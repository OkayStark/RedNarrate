"""Correlation agent: dedup across tools, merge, detect attack chains.

Identity is deterministic (canonical dedup keys) — never LLM-decided. The LLM
is used only to confirm/extend rule-detected chains and write their narratives,
and its output is validated against real finding ids.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit

from ..llm import get_llm
from ..state import AttackChain, ScanState

CONF_RANK = {"Certain": 3, "Firm": 2, "Tentative": 1}


# ── canonicalization (PROJECT_PLAN §11 Problem 1) ───────────────────


def canonical_host(raw: str, hosts: dict) -> str:
    if raw in hosts:
        return raw
    for ip, h in hosts.items():
        names = [n.lower() for n in h.get("hostnames", [])]
        if raw.lower() in names:
            return ip
    return raw.lower()


def canonical_location(url: str | None, parameter: str | None) -> str:
    if not url:
        return ""
    p = urlsplit(url if "://" in url else f"http://{url}")
    path = re.sub(r"/+$", "", p.path) or "/"
    return f"{path.lower()}|{(parameter or '').lower()}"


def dedup_key(f: dict, hosts: dict) -> str:
    port = f.get("port")
    if not port and f.get("url"):
        scheme = urlsplit(f["url"]).scheme
        port = {"https": 443, "http": 80}.get(scheme, 0)
    return (
        f"{canonical_host(f['host'], hosts)}:{port}:"
        f"{f['finding_type']}:{canonical_location(f.get('url'), f.get('parameter'))}"
    )


def _merge_bucket(bucket: list[dict]) -> dict:
    primary = max(
        bucket,
        key=lambda f: (CONF_RANK.get(f.get("confidence"), 0), len(f.get("evidence", ""))),
    )
    primary = dict(primary)
    primary["instances"] = len(bucket)
    tools = sorted({f.get("source_tool", "") for f in bucket})
    primary["source_tool"] = "+".join(t for t in tools if t)
    if len(bucket) > 1:
        joined = "\n\n--- corroborating evidence ---\n\n".join(
            f"[{f.get('source_tool')}] {f.get('evidence', '')}" for f in bucket
        )
        primary["evidence"] = joined[:4096]
    # Union references.
    refs: list[str] = []
    for f in bucket:
        for r in f.get("references", []):
            if r not in refs:
                refs.append(r)
    primary["references"] = refs
    return primary


# ── rule-based chain detection ──────────────────────────────────────


def _detect_chains(findings: list[dict]) -> list[dict]:
    chains: list[dict] = []
    by_host: dict[str, list[dict]] = {}
    for f in findings:
        by_host.setdefault(f["host"], []).append(f)

    for host, group in by_host.items():
        types = {f["finding_type"] for f in group}

        # exposure -> exploitation: open service + web vuln on same host
        web_vulns = [
            f for f in group
            if f["finding_type"] in {"sqli", "xss-reflected", "xss-stored",
                                     "os-command-injection", "rce", "default-credentials"}
        ]
        open_ports = [f for f in group if f["finding_type"] == "open-port"]
        for wv in web_vulns:
            same_port = [op for op in open_ports if op.get("port") == wv.get("port")]
            if same_port:
                chains.append({
                    "id": uuid.uuid4().hex,
                    "name": f"Exposure to exploitation on {host}:{wv.get('port')}",
                    "finding_ids": [same_port[0]["id"], wv["id"]],
                    "combined_impact": "",
                    "detected_by": "rule",
                })

        # injection -> data exfiltration: SQLi where evidence shows a dump
        for f in group:
            if f["finding_type"] == "sqli" and "EXFILTRAT" in f.get("evidence", "").upper():
                chains.append({
                    "id": uuid.uuid4().hex,
                    "name": f"SQL injection to data exfiltration on {host}",
                    "finding_ids": [f["id"]],
                    "combined_impact": "",
                    "detected_by": "rule",
                })

        # default creds -> post-auth finding on same host
        if "default-credentials" in types and len(group) > 1:
            cred = next(f for f in group if f["finding_type"] == "default-credentials")
            others = [f for f in group if f["id"] != cred["id"]
                      and f["finding_type"] != "open-port"]
            if others:
                chains.append({
                    "id": uuid.uuid4().hex,
                    "name": f"Default credentials enabling further access on {host}",
                    "finding_ids": [cred["id"]] + [others[0]["id"]],
                    "combined_impact": "",
                    "detected_by": "rule",
                })

    return chains


def _llm_refine_chains(
    findings: list[dict], candidates: list[dict], provider_ok: bool
) -> tuple[list[dict], list[str]]:
    """Confirm/extend chains and write narratives. Falls back to rules on error."""
    warnings: list[str] = []
    valid_ids = {f["id"] for f in findings}

    if not provider_ok or not findings:
        # No LLM: keep rule chains with a generic narrative.
        for c in candidates:
            c["combined_impact"] = (
                "These findings are related and, taken together, increase risk "
                "beyond their individual severities."
            )
        return candidates, warnings

    summary = "\n".join(
        f"{f['id']} | {f['finding_type']} | {f['host']}:{f.get('port', '')} | {f['name']}"
        for f in findings
    )
    cand_text = "\n".join(
        f"{c['name']} -> {', '.join(c['finding_ids'])}" for c in candidates
    ) or "(none detected by rules)"

    system = (
        "You are a senior penetration tester analyzing correlated findings. "
        "Only reference finding IDs that appear in the input. Do not invent findings."
    )
    user = (
        f"<findings>\n{summary}\n</findings>\n\n"
        f"<candidate_chains>\n{cand_text}\n</candidate_chains>\n\n"
        "Confirm or reject each candidate chain, and identify any additional chains "
        "where one finding materially enables another. For each chain output a name, "
        "the ordered finding_ids, and a 2-3 sentence combined_impact in business language."
    )

    try:
        from pydantic import BaseModel

        class _Chains(BaseModel):
            chains: list[AttackChain]

        llm = get_llm("correlation").with_structured_output(_Chains)
        result = llm.invoke([("system", system), ("human", user)])
        out: list[dict] = []
        for ch in result.chains:
            ids = [i for i in ch.finding_ids if i in valid_ids]
            if not ids:
                continue  # drop hallucinated chains
            out.append({
                "id": uuid.uuid4().hex,
                "name": ch.name,
                "finding_ids": ids,
                "combined_impact": ch.combined_impact,
                "detected_by": "rule+llm" if candidates else "llm",
            })
        if out:
            return out, warnings
        warnings.append("LLM returned no valid chains; using rule-based chains")
    except Exception as exc:
        warnings.append(f"Chain LLM call failed ({exc}); using rule-based chains")

    for c in candidates:
        c["combined_impact"] = (
            "These findings are related and together increase overall risk."
        )
    return candidates, warnings


def correlation_node(state: ScanState) -> dict:
    findings = state.get("parsed_findings", [])
    hosts = state.get("hosts", {})
    warnings: list[str] = []

    # 1. Deterministic dedup/merge by canonical key.
    buckets: dict[str, list[dict]] = {}
    for f in findings:
        key = dedup_key(f, hosts)
        f["dedup_key"] = key
        buckets.setdefault(key, []).append(f)

    correlated = [_merge_bucket(b) for b in buckets.values()]

    # 2. Cross-link related service findings (same host:port, different type).
    by_host_port: dict[tuple, list[dict]] = {}
    for f in correlated:
        by_host_port.setdefault((f["host"], f.get("port")), []).append(f)
    for group in by_host_port.values():
        if len(group) > 1:
            ids = [g["id"] for g in group]
            for g in group:
                g["host_port_ref"] = ",".join(i for i in ids if i != g["id"])

    # 3. Rule-based chains, then LLM refinement.
    candidates = _detect_chains(correlated)
    provider_ok = state.get("llm_provider") in (None, "anthropic", "ollama")
    chains, chain_warnings = _llm_refine_chains(correlated, candidates, provider_ok)
    warnings.extend(chain_warnings)

    # Mark chain members.
    chain_ids = {fid for c in chains for fid in c["finding_ids"]}
    for f in correlated:
        f["is_chain_member"] = f["id"] in chain_ids

    return {
        "correlated_findings": correlated,
        "attack_chains": chains,
        "warnings": warnings,
        "current_step": "correlate",
    }
