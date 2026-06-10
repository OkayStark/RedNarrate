"""Ingestion agent: raw tool files -> normalized findings + host inventory.

Deterministic and LLM-free. One bad file becomes a warning, not a crash.
The only fatal condition is zero findings across all inputs.
"""

from __future__ import annotations

from ..parsers import (
    ParserError,
    parse_burp,
    parse_dirbrute,
    parse_nessus,
    parse_nmap,
    parse_nuclei,
    parse_sqlmap,
    parse_wpscan,
    parse_zap,
)
from ..parsers.nmap_parser import extract_hosts
from ..state import ScanState

_PARSERS = {
    "nmap": parse_nmap,
    "burp": parse_burp,
    "sqlmap": parse_sqlmap,
    "nessus": parse_nessus,
    "zap": parse_zap,
    "nuclei": parse_nuclei,
    "ffuf": parse_dirbrute,
    "gobuster": parse_dirbrute,
    "wpscan": parse_wpscan,
}


def ingestion_node(state: ScanState) -> dict:
    raw_inputs = state.get("raw_inputs", {})
    all_findings: list[dict] = []
    hosts: dict[str, dict] = {}
    warnings: list[str] = []
    errors: list[str] = []
    counter = 0

    for tool, raw_val in raw_inputs.items():
        # raw_inputs values are list[str]; accept bare str for backward compat.
        paths: list[str] = raw_val if isinstance(raw_val, list) else [raw_val]
        parser = _PARSERS.get(tool)
        if not parser:
            warnings.append(f"No parser for tool '{tool}'; skipped")
            continue

        for path in paths:
            try:
                findings = parser(path)
            except ParserError as exc:
                warnings.append(f"{tool} parse failed for {path}: {exc}")
                continue
            except Exception as exc:  # defensive: never let a parser bug crash the run
                warnings.append(f"{tool} unexpected error for {path}: {exc}")
                continue

            for f in findings:
                counter += 1
                f.id = f"RAW-{counter:03d}"
                all_findings.append(f.model_dump())

            if tool == "nmap":
                try:
                    hosts.update(extract_hosts(path))
                except Exception as exc:
                    warnings.append(f"Host inventory extraction failed for {path}: {exc}")

    # Merge Burp/SQLMap hosts (by URL host) into the inventory if absent.
    # Skip a host that is already a hostname alias of a known IP — adding it as
    # its own key would prevent correlation from resolving it to that IP.
    known_aliases = {
        name.lower() for h in hosts.values() for name in h.get("hostnames", [])
    }
    for f in all_findings:
        h = f.get("host")
        if not h or h in hosts or h.lower() in known_aliases:
            continue
        hosts[h] = {"hostnames": [], "os": None, "open_ports": []}
        if f.get("port"):
            hosts[h]["open_ports"].append(
                {"port": f["port"], "proto": f.get("protocol", "tcp"),
                 "service": f.get("service"), "version": None}
            )

    if not all_findings:
        errors.append(
            "No findings could be parsed from any input file. "
            "Supported formats: nmap -oX XML, Burp Suite issue XML, "
            "sqlmap console logs, Nessus .nessus XML, OWASP ZAP XML."
        )

    return {
        "parsed_findings": all_findings,
        "hosts": hosts,
        "warnings": warnings,
        "errors": errors,
        "current_step": "ingest",
    }
