"""Parse Burp Suite issue XML into normalized Findings.

Uses defusedxml — Burp output is attacker-adjacent data and stock ElementTree
is vulnerable to XXE / entity-expansion. Do not replace with xml.etree.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml.ElementTree import ParseError, parse

from ..state import Finding
from .base import ParserError, truncate_evidence

# Burp issue 'type' integer -> normalized finding_type. Extend as needed.
BURP_TYPE = {
    "2097920": "sqli",
    "2097408": "xss-reflected",
    "2097424": "xss-stored",
    "5243392": "info-disclosure",
    "2098944": "os-command-injection",
    "3146240": "csrf",
    "5244416": "directory-listing",
    "8389632": "clickjacking",
    "2099456": "xxe",
    "5243648": "ssl-issue",
    "16777472": "open-redirect",
}

_PARAM_RE = re.compile(r"[Pp]arameter:?\s*(\S+)")


def _finding_type(issue_type: str, name: str) -> str:
    if issue_type in BURP_TYPE:
        return BURP_TYPE[issue_type]
    # Fallback: slugify the issue name.
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "web-issue"


def _decode(node) -> str:
    if node is None:
        return ""
    text = node.text or ""
    if node.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return f"[base64 decode failed]\n{text}"
    return text


def _port_for(url: str, host_elem_text: str) -> tuple[int | None, str | None]:
    """Return (port, full_url_base) from the issue's host URL."""
    base = host_elem_text or url
    parts = urlsplit(base if "://" in base else f"http://{base}")
    if parts.port:
        port = parts.port
    else:
        port = 443 if parts.scheme == "https" else 80
    return port, f"{parts.scheme}://{parts.netloc}"


def parse_burp(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        tree = parse(str(path))
    except ParseError as exc:
        raise ParserError(f"Burp XML unparseable: {exc}") from exc
    except Exception as exc:  # XXE / entity-expansion defenses raise here
        raise ParserError(f"Burp XML rejected (possible XXE): {exc}") from exc

    root = tree.getroot()
    if root.tag != "issues":
        raise ParserError(f"Not a Burp issues export (root=<{root.tag}>)")

    findings: list[Finding] = []
    counter = 0
    for issue in root.findall("issue"):
        try:
            counter += 1
            name = (issue.findtext("name") or "Unnamed issue").strip()
            itype = (issue.findtext("type") or "").strip()
            severity = (issue.findtext("severity") or "Information").strip()
            confidence = (issue.findtext("confidence") or "").strip()
            host_elem = issue.find("host")
            host_url = (host_elem.text if host_elem is not None else "") or ""
            host_ip = host_elem.get("ip") if host_elem is not None else None
            path_text = (issue.findtext("path") or "").strip()
            location = (issue.findtext("location") or "").strip()
            detail = (issue.findtext("issueDetail") or "").strip()
            background = (issue.findtext("issueBackground") or "").strip()

            port, url_base = _port_for(host_url, host_url)
            full_url = f"{url_base}{path_text}" if url_base else (host_url + path_text)
            host = host_ip or urlsplit(host_url if "://" in host_url else f"http://{host_url}").hostname or host_url

            pm = _PARAM_RE.search(location) or _PARAM_RE.search(detail)
            parameter = pm.group(1) if pm else None

            # Evidence: detail text + first request/response (decoded, capped 2KB each).
            req = issue.find(".//request")
            resp = issue.find(".//response")
            ev_parts = []
            if detail:
                ev_parts.append(detail[:1500])
            if req is not None:
                ev_parts.append("--- REQUEST ---\n" + _decode(req)[:2000])
            if resp is not None:
                ev_parts.append("--- RESPONSE ---\n" + _decode(resp)[:2000])
            evidence, trunc = truncate_evidence("\n\n".join(ev_parts))

            ftype = _finding_type(itype, name)
            norm_loc = (urlsplit(full_url).path.rstrip("/").lower() or "/")
            if parameter:
                norm_loc += f"|{parameter.lower()}"

            findings.append(
                Finding(
                    id=f"RAW-{counter:03d}",
                    source_tool="burp",
                    host=host,
                    port=port,
                    url=full_url or None,
                    parameter=parameter,
                    finding_type=ftype,
                    name=name,
                    severity_raw=severity,
                    confidence=confidence,
                    description_raw=background,
                    evidence=evidence,
                    evidence_truncated=trunc,
                    dedup_key=f"{host}:{port}:{ftype}:{norm_loc}",
                )
            )
        except Exception:
            # One broken issue must not kill the whole export.
            continue

    return findings
