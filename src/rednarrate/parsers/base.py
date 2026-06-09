"""Tool detection and shared parser utilities.

Parsers are LLM-free and deterministic. Each raises ParserError on a file it
cannot handle so the ingestion agent can skip-and-warn rather than crash.
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_EVIDENCE = 4096  # bytes of evidence stored per finding (PROJECT_PLAN §3.1)


class ParserError(Exception):
    """A file could not be parsed as its claimed tool format."""


# ── evidence hygiene (CLAUDE.md invariant 6) ────────────────────────
# Redact secrets BEFORE evidence is stored or rendered, so credentials from
# attacker-adjacent tool output never reach the database, logs, or report.

# Sensitive HTTP headers: replace the whole value after the colon.
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^([ \t]*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|"
    r"X-Api-Key|Api-Key|X-Auth-Token|Authentication)[ \t]*:[ \t]*).*$"
)

# Standalone secret/token patterns that may appear in dumps or response bodies.
_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),       # Anthropic keys
    re.compile(r"sk-[A-Za-z0-9]{20,}"),              # OpenAI-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{36}"),              # GitHub PAT
    re.compile(r"glpat-[A-Za-z0-9_\-]{20}"),         # GitLab PAT
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
]


def sanitize_evidence(text: str) -> str:
    """Strip credentials/secrets and null bytes from evidence text.

    Redacts Authorization/Cookie/Set-Cookie header values and common API-key /
    token shapes. SQLite cannot store NUL bytes cleanly, so those are removed too.
    """
    if not text:
        return text
    text = text.replace("\x00", "")
    text = _SENSITIVE_HEADER_RE.sub(r"\1[REDACTED]", text)
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def truncate_evidence(text: str, limit: int = MAX_EVIDENCE) -> tuple[str, bool]:
    """Sanitize, then bound evidence length. Returns (text, was_truncated)."""
    text = sanitize_evidence(text)
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n[... evidence truncated ...]", True


def detect_tool(path: str | Path) -> str | None:
    """Best-effort sniff of which tool produced a file.

    Returns one of: "nmap" | "burp" | "sqlmap" | "nessus" | "zap" |
    "nuclei" | "ffuf" | "gobuster" | "wpscan" | None.
    Cheap header inspection only — the parser is the real validator.
    """
    import json as _json

    p = Path(path)
    suffix = p.suffix.lower()
    try:
        head = p.read_text(errors="replace")[:3000]
    except OSError:
        return None

    # ── XML-based tools ─────────────────────────────────────────────
    if "<nmaprun" in head:
        return "nmap"
    if "<issues" in head or "burpVersion" in head:
        return "burp"
    if "NessusClientData_v2" in head:
        return "nessus"
    if "<OWASPZAPReport" in head:
        return "zap"
    if suffix in (".xml", ".nessus"):
        if "nmaprun" in head:
            return "nmap"
        if "NessusClientData_v2" in head:
            return "nessus"
        if "OWASPZAPReport" in head:
            return "zap"
        if "issue" in head.lower() and "burp" in head.lower():
            return "burp"

    # ── sqlmap console logs ─────────────────────────────────────────
    if re.search(r"\[\d{2}:\d{2}:\d{2}\]\s*\[(INFO|WARNING|CRITICAL|ERROR|DEBUG)\]", head):
        return "sqlmap"
    if suffix in (".log", ".txt") and "sqlmap" in head.lower():
        return "sqlmap"

    # Fast string checks before expensive JSON parsing.
    if '"target_url"' in head and '"interesting_findings"' in head:
        return "wpscan"
    # ffuf JSON can be large (many results); check key fields before parsing.
    if '"commandline"' in head and '"results"' in head:
        return "ffuf"

    # ── JSON-based tools: inspect structure ─────────────────────────
    if suffix in (".json", ".jsonl") or head.lstrip().startswith(("{", "[")):
        stripped = head.strip()

        # Nuclei JSONL: first non-empty line is a JSON object with "template-id".
        for line in head.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") and '"template-id"' in line:
                return "nuclei"
            break  # only check first non-empty line for JSONL

        # Parse the head as JSON for object-level inspection.
        try:
            snippet = stripped[:2000]
            obj = _json.loads(snippet) if suffix != ".jsonl" else None
        except (_json.JSONDecodeError, Exception):
            obj = None

        if isinstance(obj, dict):
            # WPScan JSON: has "target_url" at top level.
            if "target_url" in obj:
                return "wpscan"

        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            # gobuster JSON array.
            first = obj[0]
            if any(k in first for k in ("Found", "path", "Status", "status")):
                return "gobuster"

    # ── gobuster text output ────────────────────────────────────────
    if re.search(r"^/\S+\s+\(Status:\s*\d+\)\s+\[Size:\s*\d+\]", head, re.MULTILINE):
        return "gobuster"

    return None


# Tools that accept multiple files per run (multi-subnet nmap scans, etc.)
MULTI_FILE_TOOLS = {"nmap", "nuclei", "ffuf", "gobuster"}


def collect_inputs(directory: str | Path) -> tuple[dict[str, list[str]], list[str]]:
    """Scan a directory and map each detected tool to its file(s).

    Returns ({tool: [path, ...]}, notes).
    Tools in MULTI_FILE_TOOLS accumulate all matching files; all others
    keep the first match and note duplicates.
    """
    directory = Path(directory)
    inputs: dict[str, list[str]] = {}
    notes: list[str] = []
    if not directory.exists():
        return inputs, [f"Input path {directory} does not exist"]
    files = sorted(directory.iterdir()) if directory.is_dir() else [directory]
    for path in files:
        if not path.is_file():
            continue
        tool = detect_tool(path)
        if not tool:
            notes.append(f"Skipped unrecognized file: {path.name}")
            continue
        if tool not in inputs:
            inputs[tool] = []
        elif tool not in MULTI_FILE_TOOLS:
            notes.append(
                f"Multiple {tool} files; using {Path(inputs[tool][0]).name}, "
                f"ignoring {path.name}"
            )
            continue
        inputs[tool].append(str(path))
    return inputs, notes


def parse_file(path: str | Path, tool: str | None = None) -> list:
    """Dispatch one file to the right parser. Imports locally to avoid cycles."""
    tool = tool or detect_tool(path)
    if tool == "nmap":
        from .nmap_parser import parse_nmap

        return parse_nmap(path)
    if tool == "burp":
        from .burp_parser import parse_burp

        return parse_burp(path)
    if tool == "sqlmap":
        from .sqlmap_parser import parse_sqlmap

        return parse_sqlmap(path)
    if tool == "nessus":
        from .nessus_parser import parse_nessus

        return parse_nessus(path)
    if tool == "zap":
        from .zap_parser import parse_zap

        return parse_zap(path)
    if tool == "nuclei":
        from .nuclei_parser import parse_nuclei

        return parse_nuclei(path)
    if tool in ("ffuf", "gobuster"):
        from .dirbrute_parser import parse_dirbrute

        return parse_dirbrute(path)
    if tool == "wpscan":
        from .wpscan_parser import parse_wpscan

        return parse_wpscan(path)
    raise ParserError(f"Could not determine tool format for {path}")
