"""Parse OWASP ZAP alert XML exports into normalized Findings.

Uses defusedxml — ZAP output is attacker-adjacent data.
Supports ZAP 2.x/2.14+ OWASPZAPReport schema.

Risk code: 0=Informational, 1=Low, 2=Medium, 3=High.
Confidence: 0=False Positive, 1=Low, 2=Medium, 3=High, 4=Confirmed.
Finding type is derived from CWE ID first, then alert name keywords.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml.ElementTree import ParseError, parse

from ..state import Finding
from .base import ParserError, truncate_evidence

_RISKCODE_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
}

_CONFIDENCE_MAP = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
}

# CWE ID (string) -> finding_type. More-specific first.
_CWE_TO_TYPE: dict[str, str] = {
    "89": "sqli",
    "78": "os-command-injection",
    "94": "ssti",
    "611": "xxe",
    "918": "ssrf",
    "22": "path-traversal",
    "23": "path-traversal",
    "98": "lfi",
    "601": "open-redirect",
    "352": "csrf",
    "79": "xss-reflected",    # refined below if "stored" in name
    "80": "xss-stored",
    "87": "xss-stored",
    "434": "unrestricted-file-upload",
    "502": "deserialization",
    "639": "idor",
    "285": "idor",
    "287": "auth-bypass",
    "306": "anonymous-access",
    "200": "info-disclosure",
    "201": "info-disclosure",
    "209": "info-disclosure",
    "319": "sensitive-data-exposure",
    "311": "sensitive-data-exposure",
    "326": "weak-crypto",
    "327": "weak-crypto",
    "328": "weak-crypto",
    "693": "missing-security-headers",
    "16": "cors-misconfiguration",
    "942": "cors-misconfiguration",
    "1021": "clickjacking",
    "548": "directory-listing",
    "1104": "outdated-software",
    "1035": "outdated-software",
}

# Name keyword fallback when CWE is absent or unmapped.
_NAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sql\s*inject"), "sqli"),
    (re.compile(r"stored.xss|stored.cross"), "xss-stored"),
    (re.compile(r"reflected.xss|cross.site.script|xss"), "xss-reflected"),
    (re.compile(r"csrf|anti.csrf|cross.site.request"), "csrf"),
    (re.compile(r"path.travers|directory.travers"), "path-traversal"),
    (re.compile(r"lfi|local.file"), "lfi"),
    (re.compile(r"ssrf|server.side.request"), "ssrf"),
    (re.compile(r"xxe|xml.external"), "xxe"),
    (re.compile(r"open.redirect"), "open-redirect"),
    (re.compile(r"clickjack"), "clickjacking"),
    (re.compile(r"cors"), "cors-misconfiguration"),
    (re.compile(r"csp|content.security.policy|x.frame|security.header|missing.header"), "missing-security-headers"),
    (re.compile(r"directory.listing|directory.brows"), "directory-listing"),
    (re.compile(r"information.disclos|info.leak|server.version|banner"), "info-disclosure"),
    (re.compile(r"sensitive.data|cleartext"), "sensitive-data-exposure"),
    (re.compile(r"outdated|deprecated|end.of.life"), "outdated-software"),
    (re.compile(r"weak.cipher|ssl|tls"), "weak-crypto"),
    (re.compile(r"file.upload|unrestricted.upload"), "unrestricted-file-upload"),
    (re.compile(r"default.cred|weak.pass"), "default-credentials"),
]


def _finding_type(cwe_id: str, alert_name: str) -> str:
    ft = _CWE_TO_TYPE.get(cwe_id.strip())
    if ft:
        # Refine CWE-79 if the name makes clear it's stored.
        if ft == "xss-reflected" and re.search(r"stored|persist", alert_name.lower()):
            return "xss-stored"
        return ft
    name_lower = alert_name.lower()
    for pat, ftype in _NAME_PATTERNS:
        if pat.search(name_lower):
            return ftype
    return "web-issue"


def _extract_host_port(site_elem) -> tuple[str, int, str]:
    """Return (host, port, scheme) from a <site> element."""
    host = site_elem.get("host", "")
    port_str = site_elem.get("port", "80")
    ssl = site_elem.get("ssl", "false").lower() == "true"
    try:
        port = int(port_str)
    except ValueError:
        port = 443 if ssl else 80
    scheme = "https" if ssl else "http"
    return host, port, scheme


def parse_zap(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        tree = parse(str(path))
    except ParseError as exc:
        raise ParserError(f"ZAP XML unparseable: {exc}") from exc
    except Exception as exc:
        raise ParserError(f"ZAP XML rejected: {exc}") from exc

    root = tree.getroot()
    if root.tag != "OWASPZAPReport":
        raise ParserError(f"Not a ZAP report (root=<{root.tag}>)")

    findings: list[Finding] = []
    counter = 0

    for site in root.findall("site"):
        host, port, scheme = _extract_host_port(site)
        base_url = f"{scheme}://{host}:{port}"

        for alert in site.findall("alerts/alertitem"):
            try:
                alert_name = (alert.findtext("alert") or alert.findtext("name") or "").strip()
                if not alert_name:
                    continue

                riskcode = (alert.findtext("riskcode") or "0").strip()
                confidence_code = (alert.findtext("confidence") or "2").strip()
                desc = (alert.findtext("desc") or "").strip()
                solution = (alert.findtext("solution") or "").strip()
                cwe_id = (alert.findtext("cweid") or "").strip()
                plugin_id = (alert.findtext("pluginid") or "").strip()
                other_info = (alert.findtext("otherinfo") or "").strip()

                severity_raw = _RISKCODE_MAP.get(riskcode, "Informational")
                confidence = _CONFIDENCE_MAP.get(confidence_code, "Medium")
                ftype = _finding_type(cwe_id, alert_name)

                refs: list[str] = []
                if cwe_id:
                    refs.append(f"CWE-{cwe_id}")
                wasc = (alert.findtext("wascid") or "").strip()
                if wasc:
                    refs.append(f"WASC-{wasc}")

                # Build evidence from instances — use first instance request details.
                instances_elem = alert.find("instances")
                instance_list = instances_elem.findall("instance") if instances_elem is not None else []

                ev_parts = []
                param = None
                url = None
                first_path = None

                for inst in instance_list[:3]:  # cap at 3 instances in evidence
                    uri = (inst.findtext("uri") or "").strip()
                    method = (inst.findtext("method") or "GET").strip()
                    inst_param = (inst.findtext("param") or "").strip()
                    attack = (inst.findtext("attack") or "").strip()
                    evidence_text = (inst.findtext("evidence") or "").strip()

                    if uri and not url:
                        url = uri
                        try:
                            parsed = urlsplit(uri)
                            first_path = parsed.path.rstrip("/").lower() or "/"
                        except Exception:
                            first_path = "/"
                    if inst_param and not param:
                        param = inst_param

                    inst_ev = f"{method} {uri}"
                    if attack:
                        inst_ev += f"\nAttack: {attack[:200]}"
                    if evidence_text:
                        inst_ev += f"\nEvidence: {evidence_text[:200]}"
                    ev_parts.append(inst_ev)

                if other_info:
                    ev_parts.append(f"Other info: {other_info[:500]}")

                evidence, trunc = truncate_evidence("\n\n".join(ev_parts))

                # Dedup key: host:port:ftype:path|param (consistent with burp pattern).
                norm_loc = first_path or "/"
                if param:
                    norm_loc += f"|{param.lower()}"

                # Count distinct instances for the 'instances' field.
                instance_count = max(1, len(instance_list))

                counter += 1
                findings.append(
                    Finding(
                        id=f"RAW-{counter:03d}",
                        source_tool="zap",
                        host=host,
                        port=port,
                        url=url or base_url,
                        parameter=param or None,
                        finding_type=ftype,
                        name=alert_name,
                        severity_raw=severity_raw,
                        confidence=confidence,
                        description_raw=desc,
                        evidence=evidence,
                        evidence_truncated=trunc,
                        references=refs,
                        instances=instance_count,
                        dedup_key=f"{host}:{port}:{ftype}:{norm_loc}",
                    )
                )
            except Exception:
                continue

    return findings
