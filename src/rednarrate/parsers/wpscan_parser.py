"""Parse WPScan --format json output into normalized Findings.

Generates findings for:
  - WordPress core version vulnerabilities
  - Plugin vulnerabilities (one finding per plugin with CVE refs)
  - Theme vulnerabilities
  - Interesting findings (readme, xmlrpc enabled, user enumeration)

The WPScan JSON schema is the output of `wpscan --url <target> --format json`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from ..state import Finding
from .base import ParserError, truncate_evidence


def _host_port(target_url: str) -> tuple[str, int]:
    try:
        p = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
        return p.hostname or target_url, p.port or (443 if p.scheme == "https" else 80)
    except Exception:
        return target_url, 443


def _refs_from_vuln(vuln: dict) -> list[str]:
    refs_obj = vuln.get("references") or {}
    out: list[str] = []
    for cve in refs_obj.get("cve") or []:
        if cve:
            num = re.sub(r"[^\d]", "", str(cve))
            out.append(f"CVE-{num}" if num else str(cve).upper())
    for url in (refs_obj.get("url") or [])[:3]:
        if url:
            out.append(url)
    return out


def _vuln_finding(counter: int, host: str, port: int, url: str,
                  ftype: str, name: str, vuln: dict,
                  severity_raw: str = "High") -> Finding:
    title = (vuln.get("title") or name).strip()
    fixed_in = vuln.get("fixed_in")
    refs = _refs_from_vuln(vuln)

    ev_parts = [f"Vulnerability: {title}"]
    if fixed_in:
        ev_parts.append(f"Fixed in version: {fixed_in}")
    if refs:
        ev_parts.append("References: " + ", ".join(refs[:5]))
    evidence, trunc = truncate_evidence("\n".join(ev_parts))

    return Finding(
        id=f"RAW-{counter:03d}",
        source_tool="wpscan",
        host=host,
        port=port,
        url=url,
        finding_type=ftype,
        name=name,
        severity_raw=severity_raw,
        description_raw=title,
        evidence=evidence,
        evidence_truncated=trunc,
        references=refs,
        dedup_key=f"{host}:{port}:{ftype}:{re.sub(r'[^a-z0-9]', '-', title.lower())[:60]}",
    )


def parse_wpscan(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        raw = path.read_text(errors="replace")
    except OSError as exc:
        raise ParserError(f"Cannot read WPScan output: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParserError(f"WPScan output is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "target_url" not in data:
        raise ParserError("Not a WPScan report (missing 'target_url')")

    target_url = data.get("target_url", "")
    host, port = _host_port(target_url)
    findings: list[Finding] = []
    counter = 0

    # ── WordPress core vulnerabilities ──────────────────────────────
    wp_ver = data.get("wordpress_version") or {}
    wp_number = wp_ver.get("number", "unknown")
    for vuln in wp_ver.get("vulnerabilities") or []:
        try:
            counter += 1
            f = _vuln_finding(
                counter, host, port, target_url,
                "outdated-software",
                f"WordPress Core {wp_number} — Vulnerability",
                vuln,
                severity_raw="High",
            )
            findings.append(f)
        except Exception:
            continue

    # ── Plugin vulnerabilities ───────────────────────────────────────
    for slug, plugin in (data.get("plugins") or {}).items():
        plugin_version = (plugin.get("version") or {}).get("number", "unknown")
        for vuln in plugin.get("vulnerabilities") or []:
            try:
                counter += 1
                f = _vuln_finding(
                    counter, host, port, target_url,
                    "outdated-software",
                    f"Plugin '{slug}' {plugin_version} — Vulnerability",
                    vuln,
                    severity_raw="High",
                )
                findings.append(f)
            except Exception:
                continue

    # ── Theme vulnerabilities ────────────────────────────────────────
    for slug, theme in (data.get("themes") or {}).items():
        theme_version = (theme.get("version") or {}).get("number", "unknown")
        for vuln in theme.get("vulnerabilities") or []:
            try:
                counter += 1
                f = _vuln_finding(
                    counter, host, port, target_url,
                    "outdated-software",
                    f"Theme '{slug}' {theme_version} — Vulnerability",
                    vuln,
                    severity_raw="Medium",
                )
                findings.append(f)
            except Exception:
                continue

    # ── Interesting findings (readme, xmlrpc, backup files, etc.) ───
    for item in data.get("interesting_findings") or []:
        try:
            itype = (item.get("type") or "").lower()
            to_s = (item.get("to_s") or item.get("url") or "").strip()
            item_url = (item.get("url") or target_url).strip()
            interesting_entries = item.get("interesting_entries") or []

            if not to_s:
                continue

            # Classify interesting finding type.
            if itype in ("xmlrpc", "xml-rpc"):
                ftype = "info-disclosure"
                name = "WordPress XML-RPC Enabled"
                sev = "Low"
            elif itype == "readme":
                ftype = "info-disclosure"
                name = "WordPress readme.html Accessible"
                sev = "Informational"
            elif itype in ("backup_db", "full_path_disclosure", "debug_log"):
                ftype = "sensitive-data-exposure"
                name = f"WordPress Sensitive File Accessible ({itype})"
                sev = "High"
            elif itype == "upload_directory_listing":
                ftype = "directory-listing"
                name = "WordPress Upload Directory Listing"
                sev = "Low"
            else:
                ftype = "info-disclosure"
                name = f"WordPress Interesting Finding — {to_s[:60]}"
                sev = "Informational"

            ev_parts = [to_s]
            if interesting_entries:
                ev_parts.extend(str(e) for e in interesting_entries[:5])
            evidence, trunc = truncate_evidence("\n".join(ev_parts))

            counter += 1
            findings.append(Finding(
                id=f"RAW-{counter:03d}",
                source_tool="wpscan",
                host=host,
                port=port,
                url=item_url,
                finding_type=ftype,
                name=name,
                severity_raw=sev,
                description_raw=to_s,
                evidence=evidence,
                evidence_truncated=trunc,
                dedup_key=f"{host}:{port}:{ftype}:{itype or to_s[:40]}",
            ))
        except Exception:
            continue

    # ── User enumeration ─────────────────────────────────────────────
    users = data.get("users") or {}
    if users:
        usernames = list(users.keys())
        ev, trunc = truncate_evidence(
            "Enumerated WordPress users:\n" + "\n".join(usernames[:50])
        )
        counter += 1
        findings.append(Finding(
            id=f"RAW-{counter:03d}",
            source_tool="wpscan",
            host=host,
            port=port,
            url=target_url,
            finding_type="info-disclosure",
            name=f"WordPress User Enumeration ({len(usernames)} user(s) identified)",
            severity_raw="Low",
            description_raw=f"WPScan identified {len(usernames)} WordPress user(s) via passive detection.",
            evidence=ev,
            evidence_truncated=trunc,
            dedup_key=f"{host}:{port}:info-disclosure:wp-user-enum",
        ))

    return findings
