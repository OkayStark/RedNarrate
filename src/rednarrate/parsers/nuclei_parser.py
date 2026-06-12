"""Parse Nuclei JSONL output into normalized Findings.

Nuclei writes one JSON object per line to its -o output file (JSONL format).
Each entry contains template metadata (id, severity, tags, CWE/CVE ids)
and match details (matched-at URL, host, raw request/response).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from ..state import Finding
from .base import ParserError, truncate_evidence

MAX_NUCLEI_BYTES = 10 * 1024 * 1024  # 10 MB cap

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "unknown": "Informational",
}

# Tag / template-id keywords → finding_type. Order: most-specific first.
_TAG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sqli|sql-injection|sql_injection"), "sqli"),
    (re.compile(r"rce|remote-code|remote_code"), "rce"),
    (re.compile(r"ssti|template-inject"), "ssti"),
    (re.compile(r"command-inject|cmd-inject|os-inject"), "os-command-injection"),
    (re.compile(r"ssrf"), "ssrf"),
    (re.compile(r"xxe"), "xxe"),
    (re.compile(r"lfi|local-file|local_file"), "lfi"),
    (re.compile(r"path-travers|directory-travers"), "path-traversal"),
    (re.compile(r"open-redirect"), "open-redirect"),
    (re.compile(r"stored-xss|xss-stored"), "xss-stored"),
    (re.compile(r"xss|cross-site-script"), "xss-reflected"),
    (re.compile(r"csrf"), "csrf"),
    (re.compile(r"idor"), "idor"),
    (re.compile(r"auth-bypass|authentication-bypass"), "auth-bypass"),
    (re.compile(r"default-login|default-cred"), "default-credentials"),
    (re.compile(r"cors"), "cors-misconfiguration"),
    (re.compile(r"deserialization|unsafe-deserializ"), "deserialization"),
    (re.compile(r"file-upload|unrestricted-upload"), "unrestricted-file-upload"),
    (re.compile(r"privilege-escal"), "privilege-escalation"),
    (re.compile(r"exposed-panel|admin-panel|login-panel"), "sensitive-data-exposure"),
    (re.compile(r"exposure|sensitive"), "sensitive-data-exposure"),
    (re.compile(r"cve-\d{4}"), "outdated-software"),
    (re.compile(r"weak-cipher|ssl-weak|tls-weak"), "ssl-weak-cipher"),
    (re.compile(r"ssl|tls|certificate"), "ssl-issue"),
    (re.compile(r"missing-header|security-header"), "missing-security-headers"),
    (re.compile(r"misconfig|misconfiguration"), "info-disclosure"),
    (re.compile(r"info|disclosure|leak|tech-detect|detect"), "info-disclosure"),
]


def _finding_type(tags: list[str], template_id: str) -> str:
    combined = " ".join(tags + [template_id]).lower()
    for pat, ftype in _TAG_PATTERNS:
        if pat.search(combined):
            return ftype
    return "info-disclosure"


def _host_port(matched_at: str, host_field: str) -> tuple[str, int | None]:
    for candidate in (matched_at, host_field):
        if not candidate:
            continue
        try:
            url = candidate if "://" in candidate else f"https://{candidate}"
            p = urlsplit(url)
            h = p.hostname or ""
            port = p.port or (443 if p.scheme == "https" else 80)
            if h:
                return h, port
        except Exception:
            continue
    return host_field or matched_at, None


def parse_nuclei(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        data = path.read_text(errors="replace")[:MAX_NUCLEI_BYTES]
    except OSError as exc:
        raise ParserError(f"Cannot read nuclei output: {exc}") from exc

    findings: list[Finding] = []
    counter = 0
    parseable = 0

    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Only count as a parseable nuclei line if it has a template-id.
        template_id = obj.get("template-id", "")
        if not template_id:
            continue
        parseable += 1

        try:
            info = obj.get("info", {})
            name = (info.get("name") or template_id or "Nuclei finding").strip()
            severity_str = str(info.get("severity", "info")).lower()

            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            classification = info.get("classification") or {}
            cve_raw = classification.get("cve-id") or []
            cwe_raw = classification.get("cwe-id") or []
            if isinstance(cve_raw, str):
                cve_raw = [cve_raw]
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]

            refs: list[str] = []
            for cve in cve_raw:
                if cve:
                    refs.append(cve.upper())
            for cwe in cwe_raw:
                if cwe:
                    # "cwe-89" -> "CWE-89"
                    normalized = re.sub(r"(?i)cwe[-:]?(\d+)", r"CWE-\1", str(cwe))
                    refs.append(normalized)

            matched_at = (obj.get("matched-at") or "").strip()
            host_field = (obj.get("host") or "").strip()
            ip = (obj.get("ip") or "").strip()

            resolved_host, port = _host_port(matched_at, ip or host_field)

            request = (obj.get("request") or "").strip()
            response = (obj.get("response") or "").strip()
            extracted = obj.get("extracted-results") or []

            ev_parts: list[str] = []
            if matched_at:
                ev_parts.append(f"Matched: {matched_at}")
            if extracted:
                ev_parts.append(f"Extracted: {list(extracted)[:5]}")
            if request:
                ev_parts.append("--- REQUEST ---\n" + request[:1500])
            if response:
                ev_parts.append("--- RESPONSE ---\n" + response[:1500])
            evidence, trunc = truncate_evidence("\n\n".join(ev_parts))

            ftype = _finding_type(tags, template_id)

            try:
                url_parts = urlsplit(matched_at if "://" in matched_at else f"https://{matched_at}")
                norm_path = url_parts.path.rstrip("/").lower() or "/"
            except Exception:
                norm_path = "/"

            counter += 1
            findings.append(
                Finding(
                    id=f"RAW-{counter:03d}",
                    source_tool="nuclei",
                    host=resolved_host,
                    port=port,
                    url=matched_at or None,
                    finding_type=ftype,
                    name=name,
                    severity_raw=_SEVERITY_MAP.get(severity_str, "Informational"),
                    description_raw=(info.get("description") or "").strip(),
                    evidence=evidence,
                    evidence_truncated=trunc,
                    references=refs,
                    dedup_key=f"{resolved_host}:{port}:{ftype}:{template_id}:{norm_path}",
                )
            )
        except Exception:
            continue

    if not findings and parseable == 0:
        raise ParserError("Nuclei output: no parseable JSONL lines found")

    return findings
