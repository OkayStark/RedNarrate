"""Parse directory brute-force output from ffuf and gobuster.

Supports three sub-formats (auto-detected):
  - ffuf JSON  (has top-level "commandline" + "results" keys)
  - gobuster JSON  (array of objects with "Found"/"path" + "Status"/"status")
  - gobuster text  (lines matching "/path (Status: NNN) [Size: NNN]")

Rather than generating one finding per discovered path (which would flood the
report for large wordlists), findings are grouped by security category:
  - "Accessible administration interface" (any admin-like path found)
  - "Sensitive files accessible" (backup/config/source files)
  - "Directory enumeration" summary (all 200/301 paths, informational)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from ..state import Finding
from .base import ParserError, truncate_evidence

# Patterns that indicate an administration interface.
_ADMIN_RE = re.compile(
    r"/(admin|administrator|wp-admin|phpmyadmin|manager|management|"
    r"console|dashboard|cpanel|plesk|webmin|panel|control|backend|"
    r"adminer|dbadmin|sqlmanager|myadmin)(/|$)",
    re.IGNORECASE,
)

# Patterns for backup/config/source-code files.
_SENSITIVE_RE = re.compile(
    r"(\.(bak|old|backup|sql|dump|tar\.gz|tgz|zip|gz|7z|rar|orig|save|swp|"
    r"db|sqlite|log|cfg|conf|ini|env|properties|pem|key|p12|pfx|crt|cer)$"
    r"|web\.config|config\.php|settings\.php|database\.php|wp-config\.php"
    r"|application\.properties|\.git/|\.svn/|\.hg/|\.DS_Store"
    r"|/backup|/backups|/dump)",
    re.IGNORECASE,
)

_GOBUSTER_TEXT_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\]"
)


def _interesting_status(status: int) -> bool:
    return status in (200, 201, 204, 301, 302, 307, 308, 401, 403)


def _parse_ffuf(data: str) -> list[tuple[str, int, int]]:
    """Return list of (url, status_code, size) from ffuf JSON."""
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ParserError(f"ffuf JSON invalid: {exc}") from exc
    results = obj.get("results") or []
    out = []
    for r in results:
        url = r.get("url", "")
        status = r.get("status", 0)
        size = r.get("length", 0)
        if url and _interesting_status(status):
            out.append((url, int(status), int(size)))
    return out


def _parse_gobuster_json(data: str) -> list[tuple[str, int, int]]:
    """Return list of (path_or_url, status, size) from gobuster JSON array."""
    try:
        arr = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ParserError(f"gobuster JSON invalid: {exc}") from exc
    if not isinstance(arr, list):
        raise ParserError("gobuster JSON: expected top-level array")
    out = []
    for item in arr:
        path = item.get("Found") or item.get("path") or item.get("url") or ""
        status = item.get("Status") or item.get("status") or 0
        size = item.get("Size") or item.get("size") or 0
        if path and _interesting_status(int(status)):
            out.append((path, int(status), int(size)))
    return out


def _parse_gobuster_text(data: str) -> list[tuple[str, int, int]]:
    """Return list of (path, status, size) from gobuster text output."""
    out = []
    for line in data.splitlines():
        m = _GOBUSTER_TEXT_RE.match(line.strip())
        if m:
            status = int(m.group("status"))
            if _interesting_status(status):
                out.append((m.group("path"), status, int(m.group("size"))))
    return out


def _detect_subformat(raw: str, suffix: str) -> str:
    """Return 'ffuf', 'gobuster-json', or 'gobuster-text'."""
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if "commandline" in obj and "results" in obj:
                return "ffuf"
        except json.JSONDecodeError:
            pass
    if stripped.startswith("["):
        try:
            arr = json.loads(stripped)
            if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                first = arr[0]
                if any(k in first for k in ("Found", "path", "url", "Status", "status")):
                    return "gobuster-json"
        except json.JSONDecodeError:
            pass
    if _GOBUSTER_TEXT_RE.search(raw):
        return "gobuster-text"
    # Gobuster run that produced zero results (banner line present, no paths yet).
    if re.search(r"(?im)^Gobuster\b|^={4,}.*$", raw[:500]):
        return "gobuster-text"
    raise ParserError("dirbrute: cannot identify sub-format (not ffuf JSON / gobuster JSON / gobuster text)")


def _base_url_from_results(results: list[tuple[str, int, int]], path: Path) -> tuple[str, str, int]:
    """Guess base host and port from the result URLs/paths."""
    for url, _, _ in results:
        if "://" in url:
            try:
                p = urlsplit(url)
                host = p.hostname or ""
                port = p.port or (443 if p.scheme == "https" else 80)
                return host, url.rsplit("/", 1)[0], port
            except Exception:
                continue
    # Paths only (gobuster text) — use filename as hint.
    return path.stem, "", 80


def parse_dirbrute(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        raw = path.read_text(errors="replace")[:5 * 1024 * 1024]  # 5 MB cap
    except OSError as exc:
        raise ParserError(f"Cannot read dirbrute output: {exc}") from exc

    subformat = _detect_subformat(raw, path.suffix.lower())

    if subformat == "ffuf":
        results = _parse_ffuf(raw)
    elif subformat == "gobuster-json":
        results = _parse_gobuster_json(raw)
    else:
        results = _parse_gobuster_text(raw)

    if not results:
        return []  # nothing accessible — no findings, not an error

    host, _base, port = _base_url_from_results(results, path)
    tool_label = "ffuf" if subformat == "ffuf" else "gobuster"

    # --- categorise results ---
    admin_paths: list[str] = []
    sensitive_paths: list[str] = []
    all_paths: list[str] = []

    for url_or_path, status, size in results:
        label = f"{url_or_path} [{status}] ({size}B)"
        all_paths.append(label)
        if _ADMIN_RE.search(url_or_path):
            admin_paths.append(label)
        elif _SENSITIVE_RE.search(url_or_path):
            sensitive_paths.append(label)

    findings: list[Finding] = []
    counter = 0

    def _make_finding(ftype, name, sev, paths_list, dedup_slug):
        nonlocal counter
        ev, trunc = truncate_evidence("\n".join(paths_list))
        counter += 1
        return Finding(
            id=f"RAW-{counter:03d}",
            source_tool=tool_label,
            host=host,
            port=port if port else None,
            finding_type=ftype,
            name=name,
            severity_raw=sev,
            description_raw=(
                f"{len(paths_list)} path(s) matching this category were "
                f"accessible on {host}."
            ),
            evidence=ev,
            evidence_truncated=trunc,
            dedup_key=f"{host}:{port}:{ftype}:{dedup_slug}",
        )

    if admin_paths:
        findings.append(_make_finding(
            "sensitive-data-exposure",
            "Accessible Administration Interface",
            "High",
            admin_paths,
            "admin-interface",
        ))

    if sensitive_paths:
        findings.append(_make_finding(
            "sensitive-data-exposure",
            "Sensitive Files Accessible",
            "High",
            sensitive_paths,
            "sensitive-files",
        ))

    # Informational summary of all accessible paths.
    findings.append(_make_finding(
        "directory-listing",
        f"Directory Enumeration — {len(results)} accessible path(s) found",
        "Informational",
        all_paths[:200],  # cap list in evidence
        "enumeration-summary",
    ))

    return findings
