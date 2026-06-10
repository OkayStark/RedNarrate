"""Parse SQLMap console logs into normalized Findings.

SQLMap has no structured output; we regex the timestamped console log.
A clean run (no injection) is a valid result -> returns [].
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from ..state import Finding
from .base import ParserError, truncate_evidence

MAX_LOG_BYTES = 10 * 1024 * 1024  # don't read unbounded logs

TARGET_RE = re.compile(
    r"(?:testing connection to the target URL|starting)\s+['\"]?(https?://\S+?)['\"]?\s*$",
    re.M,
)
URL_OPT_RE = re.compile(r"-u\s+['\"]?(https?://\S+?)['\"]?(?:\s|$)")
INJECTION_RE = re.compile(
    r"(GET|POST|Cookie|URI|\(custom\) (?:GET|POST))\s+parameter\s+'(.+?)'\s+is\s+'(.+?)'\s+injectable"
)
DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")
DB_RE = re.compile(r"fetching tables for database:?\s*'(.+?)'")
DUMP_RE = re.compile(r"table '(.+?)' dumped to (?:CSV|JSON) file '(.+?)'")
ANY_INJECTABLE = re.compile(r"is\s+'.+?'\s+injectable")


def _find_target(text: str) -> str | None:
    m = URL_OPT_RE.search(text) or TARGET_RE.search(text)
    return m.group(1) if m else None


def parse_sqlmap(path: str | Path) -> list[Finding]:
    path = Path(path)
    # Read at most MAX_LOG_BYTES without slurping the whole file into memory;
    # injection results appear early in the log.
    with path.open("r", errors="replace") as fh:
        data = fh.read(MAX_LOG_BYTES)

    if "[INFO]" not in data and "[CRITICAL]" not in data and "[WARNING]" not in data:
        raise ParserError("Does not look like a sqlmap console log")

    lines = data.splitlines()
    target = _find_target(data)
    if not target:
        # No usable target and no injection markers -> not a sqlmap target log.
        if not ANY_INJECTABLE.search(data):
            raise ParserError("No sqlmap target URL or injection result found")
        target = "unknown-target"

    parts = urlsplit(target if "://" in target else f"http://{target}")
    host = parts.hostname or target
    port = parts.port or (443 if parts.scheme == "https" else 80)
    url = f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.netloc else target

    dbms = None
    m = DBMS_RE.search(data)
    if m:
        dbms = m.group(1).strip()
    dumped = DUMP_RE.findall(data)
    databases = DB_RE.findall(data)

    # Collect injection results, keyed by (method, parameter) so multiple
    # techniques on one parameter merge into a single finding.
    by_param: dict[tuple[str, str], dict] = {}
    for i, line in enumerate(lines):
        im = INJECTION_RE.search(line)
        if not im:
            continue
        method, param, technique = im.group(1), im.group(2), im.group(3)
        key = (method, param)
        entry = by_param.setdefault(
            key, {"techniques": [], "context": []}
        )
        entry["techniques"].append(technique)
        ctx = lines[max(0, i - 1): i + 2]
        entry["context"].extend(ctx)

    findings: list[Finding] = []
    counter = 0
    for (method, param), entry in by_param.items():
        counter += 1
        techniques = ", ".join(dict.fromkeys(entry["techniques"]))
        ev_lines = list(dict.fromkeys(entry["context"]))
        if dbms:
            ev_lines.append(f"back-end DBMS: {dbms}")
        if databases:
            ev_lines.append("databases: " + ", ".join(sorted(set(databases))))
        if dumped:
            ev_lines.append(
                "DATA EXFILTRATED — tables dumped: "
                + ", ".join(t for t, _ in dumped)
            )
        evidence, trunc = truncate_evidence("\n".join(ev_lines))
        norm_loc = (parts.path.rstrip("/").lower() or "/") + f"|{param.lower()}"

        findings.append(
            Finding(
                id=f"RAW-{counter:03d}",
                source_tool="sqlmap",
                host=host,
                port=port,
                url=url,
                parameter=param,
                finding_type="sqli",
                name=f"SQL injection ({techniques}) — {method} '{param}'",
                severity_raw="High",
                confidence="Certain",
                description_raw=f"sqlmap confirmed {method} parameter '{param}' injectable",
                evidence=evidence,
                evidence_truncated=trunc,
                references=["CWE-89"],
                dedup_key=f"{host}:{port}:sqli:{norm_loc}",
            )
        )

    return findings
