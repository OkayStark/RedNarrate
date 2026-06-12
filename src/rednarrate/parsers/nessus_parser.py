"""Parse Nessus (.nessus) XML scan files into normalized Findings.

Uses defusedxml — Nessus output is attacker-adjacent data.
Supports Nessus 6+ (NessusClientData_v2 schema).

Severity mapping: 0=Informational, 1=Low, 2=Medium, 3=High, 4=Critical.
The cvss3_vector element is recorded but the score is NOT trusted — the
scoring agent recomputes via cvss.CVSS3 (invariant #4).
"""

from __future__ import annotations

import re
from pathlib import Path

from defusedxml.ElementTree import ParseError, parse

from ..state import Finding
from .base import ParserError, truncate_evidence

# Nessus integer severity -> display label.
_SEVERITY_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

# Keyword patterns against the lower-cased pluginName -> finding_type.
# Order matters: more-specific patterns first.
_NAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sql\s*inject"), "sqli"),
    (re.compile(r"command\s*inject|code\s*inject|shell\s*inject"), "os-command-injection"),
    (re.compile(r"ms17.010|eternalblue|wannacry"), "rce"),
    (re.compile(r"ms08.067|netapi"), "rce"),
    (re.compile(r"shellshock|bash\s*inject"), "rce"),
    (re.compile(r"smb.{0,10}vuln|ms\d{2}-\d{3}.*exec"), "rce"),
    (re.compile(r"heartbleed"), "outdated-software"),
    (re.compile(r"poodle|sslv2|sslv3|ssl.version.2|ssl.version.3|drown"), "weak-crypto"),
    (re.compile(r"weak.{0,8}cipher|rc4|export.cipher|null.cipher|ssl.{0,8}cipher"), "ssl-weak-cipher"),
    (re.compile(r"ssl.{0,10}cert|certificate.expir|expired.cert|self.signed"), "ssl-issue"),
    (re.compile(r"tls.*version|ssl.*protocol|tlsv1\b"), "ssl-issue"),
    (re.compile(r"stored.cross|stored.xss"), "xss-stored"),
    (re.compile(r"cross.site.script|xss|reflected.xss"), "xss-reflected"),
    (re.compile(r"csrf|cross.site.request.forgery"), "csrf"),
    (re.compile(r"xml.external|xxe"), "xxe"),
    (re.compile(r"server.side.request|ssrf"), "ssrf"),
    (re.compile(r"path.travers|directory.travers"), "path-traversal"),
    (re.compile(r"local.file.inclus|lfi"), "lfi"),
    (re.compile(r"open.redirect"), "open-redirect"),
    (re.compile(r"clickjack"), "clickjacking"),
    (re.compile(r"deserializ|unserializ"), "deserialization"),
    (re.compile(r"template.inject|ssti"), "ssti"),
    (re.compile(r"anonymous.{0,8}ftp|ftp.{0,8}anon"), "anonymous-access"),
    (re.compile(r"anonymous.{0,8}ldap|anonymous.{0,8}access"), "anonymous-access"),
    (re.compile(r"default.{0,8}cred|default.{0,8}password|weak.{0,8}password"), "default-credentials"),
    (re.compile(r"brute.force"), "default-credentials"),
    (re.compile(r"mysql.empty.password"), "default-credentials"),
    (re.compile(r"privilege.escal"), "privilege-escalation"),
    (re.compile(r"idor|insecure.direct.object"), "idor"),
    (re.compile(r"directory.listing|directory.index|index.of.{0,20}apache"), "directory-listing"),
    (re.compile(r"cors"), "cors-misconfiguration"),
    (re.compile(r"missing.{0,10}header|security.header|x.frame|content.security.policy"), "missing-security-headers"),
    (re.compile(r"cleartext|plain.?text.protocol|unencrypt|sensitive.data"), "sensitive-data-exposure"),
    (re.compile(r"file.upload|unrestricted.upload"), "unrestricted-file-upload"),
    (re.compile(r"information.disclos|info.leak|banner.grab|server.version|service.detect"), "info-disclosure"),
    (re.compile(r"outdated|end.of.life|\beol\b|unsupported|deprecated|patch"), "outdated-software"),
]


def _finding_type(plugin_name: str, plugin_family: str) -> str:
    name_lower = plugin_name.lower()
    for pat, ftype in _NAME_PATTERNS:
        if pat.search(name_lower):
            return ftype
    # Plugin-family fallback.
    family_lower = plugin_family.lower()
    if "denial" in family_lower:
        return "dos"
    if "web" in family_lower or "cgi" in family_lower:
        return "web-issue"
    return "info-disclosure"


def _tags(host_elem) -> dict[str, str]:
    """Extract <tag name="...">value</tag> pairs from a ReportHost element."""
    return {
        t.get("name", ""): (t.text or "").strip()
        for t in host_elem.findall("HostProperties/tag")
    }


def parse_nessus(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        tree = parse(str(path))
    except ParseError as exc:
        raise ParserError(f"Nessus XML unparseable: {exc}") from exc
    except Exception as exc:
        raise ParserError(f"Nessus XML rejected: {exc}") from exc

    root = tree.getroot()
    if root.tag != "NessusClientData_v2":
        raise ParserError(f"Not a Nessus export (root=<{root.tag}>)")

    findings: list[Finding] = []
    counter = 0

    for report in root.findall("Report"):
        for host_elem in report.findall("ReportHost"):
            host_name = host_elem.get("name", "")
            tags = _tags(host_elem)
            host_ip = tags.get("host-ip") or host_name
            hostname = tags.get("host-fqdn") or tags.get("host-rdns") or ""

            for item in host_elem.findall("ReportItem"):
                try:
                    plugin_id = item.get("pluginID", "")
                    plugin_name = item.get("pluginName", "Unnamed plugin")
                    plugin_family = item.get("pluginFamily", "")
                    sev_int = item.get("severity", "0")
                    port_str = item.get("port", "0")
                    svc_name = item.get("svc_name", "")
                    protocol = item.get("protocol", "tcp")

                    severity_raw = _SEVERITY_MAP.get(sev_int, "Informational")
                    port = int(port_str) if port_str.isdigit() else None

                    synopsis = (item.findtext("synopsis") or "").strip()
                    description = (item.findtext("description") or "").strip()
                    plugin_output = (item.findtext("plugin_output") or "").strip()

                    cves = [e.text.strip() for e in item.findall("cve") if e.text]
                    refs = cves + [
                        e.text.strip() for e in item.findall("xref") if e.text
                        and e.text.strip().startswith("CWE:")
                    ]
                    # Normalize CWE xrefs to "CWE-NNN" format.
                    refs = [r.replace("CWE:", "CWE-") if r.startswith("CWE:") else r for r in refs]

                    ev_parts = []
                    if plugin_output:
                        ev_parts.append(plugin_output[:2000])
                    elif synopsis:
                        ev_parts.append(synopsis[:500])
                    evidence, trunc = truncate_evidence("\n\n".join(ev_parts))

                    ftype = _finding_type(plugin_name, plugin_family)
                    counter += 1
                    findings.append(
                        Finding(
                            id=f"RAW-{counter:03d}",
                            source_tool="nessus",
                            host=host_ip,
                            port=port if port and port > 0 else None,
                            protocol=protocol,
                            service=svc_name or None,
                            finding_type=ftype,
                            name=plugin_name,
                            severity_raw=severity_raw,
                            description_raw=description or synopsis,
                            evidence=evidence,
                            evidence_truncated=trunc,
                            references=refs,
                            dedup_key=f"{host_ip}:{port}:{ftype}:{plugin_id}",
                        )
                    )
                except Exception:
                    continue

    return findings
