"""Parse nmap -oX output into normalized Findings + a host inventory.

Uses python-libnmap, which tolerates truncated scans (missing </nmaprun>).
Emits one 'open-port' finding per open service, plus a finding per
vuln-relevant NSE script result.
"""

from __future__ import annotations

import re
from pathlib import Path

from libnmap.parser import NmapParser, NmapParserException

from ..state import Finding
from .base import ParserError, truncate_evidence

# NSE script ids (exact) we treat as vuln-relevant findings.
# Use exact IDs to avoid catching informational scripts like ssl-cert or ssl-date.
VULN_SCRIPTS = {
    "ssl-heartbleed", "ssl-poodle", "ssl-dh-params", "ssl-ccs-injection",
    "ssl-logjam", "ssl-poodle",
    "http-default-accounts", "http-shellshock", "http-csrf",
    "http-vuln-cve2014-3704",
    "ftp-anon",
    "mysql-empty-password", "mysql-vuln-cve2012-2122",
    "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-cve-2017-7494",
    "smb-vuln-ms10-054", "smb-vuln-ms10-061",
}
# Also match any script whose id starts with these prefixes (catch future vulns).
VULN_SCRIPT_PREFIXES = (
    "vuln-", "http-vuln-", "smb-vuln-", "ssl-vuln-",
)

# Map script ids to a finding_type; fallback is "nse-<id>".
SCRIPT_TYPE = {
    "ssl-heartbleed": "outdated-software",
    "ssl-poodle": "weak-crypto",
    "ssl-dh-params": "weak-crypto",
    "ssl-ccs-injection": "weak-crypto",
    "ssl-logjam": "weak-crypto",
    "http-default-accounts": "default-credentials",
    "ftp-anon": "anonymous-access",
    "http-shellshock": "rce",
    "http-csrf": "csrf",
    "mysql-empty-password": "default-credentials",
    "mysql-vuln-cve2012-2122": "auth-bypass",
    "smb-vuln-ms17-010": "rce",
    "smb-vuln-ms08-067": "rce",
    "smb-vuln-cve-2017-7494": "rce",
    "smb-vuln-ms10-054": "rce",
    "smb-vuln-ms10-061": "rce",
    "http-vuln-cve2014-3704": "sqli",
}


def _is_vuln_script(script_id: str) -> bool:
    return script_id in VULN_SCRIPTS or any(
        script_id.startswith(p) for p in VULN_SCRIPT_PREFIXES
    )


def _close_truncated(data: str) -> str:
    """Append the closing tags an interrupted scan is missing.

    Handles the common 'scan killed mid-run' case where the XML ends after a
    complete element but before its parents are closed. We close any still-open
    port/ports/host/runstats and the root, in nesting order.
    """
    suffix = ""
    # Order matters: innermost first.
    for tag in ("service", "port", "ports", "os", "host", "runstats"):
        opens = data.count(f"<{tag} ") + data.count(f"<{tag}>")
        closes = data.count(f"</{tag}>")
        # A self-closed <service .../> counts as open+closed; approximate by
        # only closing tags that are genuinely unbalanced and not self-closed.
        selfclosed = len(re.findall(rf"<{tag}\b[^>]*/>", data))
        if opens - selfclosed - closes > 0:
            suffix += f"</{tag}>"
    if "</nmaprun>" not in data:
        suffix += "</nmaprun>"
    return data + suffix


def _robust_parse(data: str):
    """Parse nmap XML, repairing truncation if needed. Returns report or None."""
    for attempt in (
        lambda: NmapParser.parse_fromstring(data),
        lambda: NmapParser.parse_fromstring(data, incomplete=True),
        lambda: NmapParser.parse_fromstring(_close_truncated(data)),
    ):
        try:
            return attempt()
        except (NmapParserException, Exception):
            continue
    return None


def _service_label(svc) -> str:
    parts = [svc.service or ""]
    if svc.banner:
        parts.append(svc.banner)
    return " ".join(p for p in parts if p).strip() or "unknown"


def parse_nmap(path: str | Path) -> list[Finding]:
    path = Path(path)
    data = path.read_text(errors="replace")
    report = _robust_parse(data)
    if report is None:
        raise ParserError("nmap XML unparseable even after truncation repair")

    findings: list[Finding] = []
    counter = 0

    for host in report.hosts:
        if not host.is_up():
            continue
        ip = host.address
        for svc in host.services:
            if svc.state != "open":
                continue
            counter += 1
            cpes = [c.cpestring for c in svc.cpelist] if svc.cpelist else []
            ev, trunc = truncate_evidence(
                f"{svc.port}/{svc.protocol} open {_service_label(svc)}"
            )
            findings.append(
                Finding(
                    id=f"RAW-{counter:03d}",
                    source_tool="nmap",
                    host=ip,
                    port=svc.port,
                    protocol=svc.protocol,
                    service=_service_label(svc),
                    finding_type="open-port",
                    name=f"Open {svc.service or 'service'} on port {svc.port}",
                    evidence=ev,
                    evidence_truncated=trunc,
                    references=cpes,
                    dedup_key=f"{ip}:{svc.port}:open-port:",
                )
            )

            # NSE script results attached to this service.
            for script in svc.scripts_results or []:
                sid = script.get("id", "")
                if not _is_vuln_script(sid):
                    continue
                counter += 1
                output = script.get("output", "").strip()
                ev, trunc = truncate_evidence(output)
                ftype = SCRIPT_TYPE.get(sid, f"nse-{sid}")
                findings.append(
                    Finding(
                        id=f"RAW-{counter:03d}",
                        source_tool="nmap",
                        host=ip,
                        port=svc.port,
                        protocol=svc.protocol,
                        service=_service_label(svc),
                        finding_type=ftype,
                        name=f"NSE {sid} on port {svc.port}",
                        description_raw=f"nmap NSE script '{sid}' result",
                        evidence=ev,
                        evidence_truncated=trunc,
                        dedup_key=f"{ip}:{svc.port}:{ftype}:{sid}",
                    )
                )
    return findings


def extract_hosts(path: str | Path) -> dict[str, dict]:
    """Build the host inventory dict used by correlation/report.

    Returns {ip: {hostnames: [...], os: str|None, open_ports: [...]}}.
    """
    path = Path(path)
    data = path.read_text(errors="replace")
    report = _robust_parse(data)
    if report is None:
        return {}

    hosts: dict[str, dict] = {}
    for host in report.hosts:
        if not host.is_up():
            continue
        os_name = None
        try:
            matches = host.os_match_probabilities()
            best = max(matches, key=lambda m: int(m.accuracy), default=None)
            if best and int(best.accuracy) >= 85:
                os_name = best.name
        except Exception:
            os_name = None
        hosts[host.address] = {
            "hostnames": [h for h in host.hostnames] if host.hostnames else [],
            "os": os_name,
            "open_ports": [
                {
                    "port": s.port,
                    "proto": s.protocol,
                    "service": s.service,
                    "version": s.banner,
                }
                for s in host.services
                if s.state == "open"
            ],
        }
    return hosts
