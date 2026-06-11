"""Report writer agent: produce report content, then render PDF + Markdown.

Per-finding narratives are RAG-augmented LLM calls with a deterministic
template fallback. Scores/severities/order are never changed here. If PDF
rendering fails, Markdown/HTML are still written so content is never lost.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ..config import get_settings
from ..llm import get_llm
from ..rag.retriever import get_context
from ..report.renderer import render_all
from ..state import FindingNarrative, ScanState

# Overall-risk rating is computed from severity counts, not asked of the LLM.
_RISK_BY_TOP = ["Critical", "High", "Medium", "Low", "Informational"]

# Reference validation: keep only recognizable CWE / OWASP / CVE ids.
_REF_RE = re.compile(r"^(CWE-\d+|A\d{1,2}:20\d{2}|OWASP[\w\s:.-]+|CVE-\d{4}-\d+)$", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)

# Leaked-template markers that must never appear in finished prose.
_ARTIFACT_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\[CLIENT\]|\[CLIENT_NAME\]", re.S)


def _valid_refs(refs: list[str]) -> list[str]:
    return [r.strip() for r in refs if r and _REF_RE.match(r.strip())]


def _validate_llm_refs(llm_refs: list[str], finding: dict) -> tuple[list[str], list[str]]:
    """Keep well-formed CWE/OWASP refs; allow a CVE only if the source tool
    already cited it. Returns (kept_refs, warnings) — fabricated CVEs are dropped.
    """
    known_cves = {r.upper() for r in finding.get("references", []) if _CVE_RE.match(r)}
    kept: list[str] = []
    warnings: list[str] = []
    for r in _valid_refs(llm_refs):
        if _CVE_RE.match(r) and r.upper() not in known_cves:
            warnings.append(
                f"{finding.get('id', '?')}: dropped unverifiable CVE reference '{r}'"
            )
            continue
        kept.append(r)
    return kept, warnings


def _strip_artifacts(text: str) -> str:
    """Remove any leaked Jinja/template placeholders from LLM prose."""
    return _ARTIFACT_RE.sub("", text or "").strip()


def _overall_risk(findings: list[dict]) -> str:
    present = {f.get("severity") for f in findings}
    for band in _RISK_BY_TOP:
        if band in present:
            return band
    return "Informational"


def _fallback_narrative(f: dict) -> FindingNarrative:
    ftype = f["finding_type"].replace("-", " ")
    return FindingNarrative(
        description=(
            f"A {ftype} issue was identified on {f['host']}"
            f"{':' + str(f['port']) if f.get('port') else ''}"
            f"{' affecting ' + f['url'] if f.get('url') else ''}. "
            f"{f.get('description_raw', '')[:300]}"
        ).strip(),
        business_impact=(
            "Successful exploitation could compromise the confidentiality, "
            "integrity, or availability of the affected asset."
        ),
        remediation_steps=[
            f"Remediate the {ftype} condition on the affected asset.",
            "Apply vendor patches and secure-configuration baselines.",
            "Re-test after remediation to confirm closure.",
        ],
        references=_valid_refs(f.get("references", [])),
    )


def _write_finding(f: dict, structured_llm) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    # Informational findings (open ports, info-only) don't need LLM narratives.
    if f.get("severity") == "Informational" or structured_llm is None:
        narrative = _fallback_narrative(f)
        ref_warnings: list[str] = []
    else:
        try:
            context = get_context(f)
            sys = (
                "You write findings for professional penetration test reports "
                "(PTES/OWASP style). Be specific to the evidence given. Never invent "
                "endpoints, parameters, or CVEs not present in the input or context."
            )
            user = (
                f"<finding>\nName: {f['name']}\nType: {f['finding_type']}\n"
                f"Severity: {f.get('severity')}  CVSS: {f.get('cvss_vector')}\n"
                f"Asset: {f['host']}:{f.get('port', '')} {f.get('url', '')} "
                f"{f.get('parameter', '')}\n"
                f"Evidence (excerpt): {f.get('evidence', '')[:1500]}\n</finding>\n\n"
                f"<reference_context>\n{context}\n</reference_context>\n\n"
                "Write description, business_impact, remediation_steps[], references[]."
            )
            narrative = structured_llm.invoke([("system", sys), ("human", user)])
        except Exception as exc:
            warnings.append(f"{f.get('id', '?')}: narrative LLM failed ({exc}); used template")
            narrative = _fallback_narrative(f)
        ref_warnings = []

    kept_refs, ref_warnings = _validate_llm_refs(narrative.references, f)
    warnings.extend(ref_warnings)

    f["description"] = _strip_artifacts(narrative.description)
    f["business_impact"] = _strip_artifacts(narrative.business_impact)
    f["remediation"] = [_strip_artifacts(s) for s in narrative.remediation_steps]
    f["report_references"] = kept_refs or _valid_refs(f.get("references", []))
    return f, warnings


def _write_exec_summary(findings: list[dict], chains: list[dict], meta: dict,
                        llm) -> dict:
    counts = Counter(f.get("severity") or "Informational" for f in findings)
    overall = _overall_risk(findings)
    stats_line = ", ".join(f"{counts.get(b, 0)} {b}" for b in _RISK_BY_TOP if counts.get(b))

    overview = (
        f"A penetration test was conducted against {meta.get('scope') or 'the in-scope assets'} "
        f"for {meta.get('client_name') or 'the client'}"
        f"{' (' + meta['engagement_dates'] + ')' if meta.get('engagement_dates') else ''}. "
        f"A total of {len(findings)} findings were identified ({stats_line})."
    )
    key_findings = [
        f"{f['id']} — {f['name']} ({f.get('severity')})"
        for f in findings[:5]
    ]
    immediate = [
        f"Address {f['id']} ({f['name']}) as a priority."
        for f in findings if f.get("severity") in {"Critical", "High"}
    ][:5]

    if llm is not None:
        try:
            sys = (
                "You write the executive summary of a penetration test report for a "
                "non-technical audience. Be concise and business-focused."
            )
            user = (
                f"Client: {meta.get('client_name')}\nScope: {meta.get('scope')}\n"
                f"Severity counts: {dict(counts)}\nOverall risk: {overall}\n"
                f"Top findings:\n" + "\n".join(key_findings) +
                f"\nAttack chains: {len(chains)}\n\n"
                "Write a 3-4 sentence engagement overview paragraph (business language). "
                "Return only the paragraph."
            )
            resp = llm.invoke([("system", sys), ("human", user)])
            text = getattr(resp, "content", None)
            if isinstance(text, str) and text.strip():
                overview = text.strip()
        except Exception:
            pass  # keep the deterministic overview

    return {
        "overview": overview,
        "overall_risk": overall,
        "key_findings": key_findings,
        "immediate_actions": immediate,
        "severity_counts": dict(counts),
    }


def _roadmap(findings: list[dict]) -> dict:
    immediate, short_term, long_term = [], [], []
    for f in findings:
        sev = f.get("severity")
        rem = f.get("remediation") or []
        line = f"{f['id']} {f['name']}: " + (rem[0] if rem else "Remediate the issue.")
        if sev in {"Critical", "High"}:
            immediate.append(line)
        elif sev == "Medium":
            short_term.append(line)
        else:
            long_term.append(line)
    return {"immediate": immediate, "short_term": short_term, "long_term": long_term}


def report_writer_node(state: ScanState) -> dict:
    settings = get_settings()
    findings = list(state.get("scored_findings", []))
    chains = state.get("attack_chains", [])
    meta = {
        "scan_id": state.get("scan_id", ""),
        "client_name": state.get("client_name", ""),
        "scope": state.get("scope", ""),
        "engagement_dates": state.get("engagement_dates", ""),
    }
    warnings: list[str] = []
    errors: list[str] = []

    structured_llm = None
    plain_llm = None
    try:
        plain_llm = get_llm("writer")
        structured_llm = plain_llm.with_structured_output(FindingNarrative)
    except Exception as exc:
        warnings.append(f"Writer LLM unavailable ({exc}); using template narratives")

    for i, f in enumerate(findings):
        findings[i], fwarn = _write_finding(dict(f), structured_llm)
        warnings.extend(fwarn)

    exec_summary = _write_exec_summary(findings, chains, meta, plain_llm)
    roadmap = _roadmap(findings)

    tools_used = sorted({
        t for f in findings for t in (f.get("source_tool") or "").split("+") if t
    })
    report_sections = {
        "exec_summary": exec_summary,
        "findings": findings,
        "chains": chains,
        "roadmap": roadmap,
        "methodology": {
            "standards": ["OWASP WSTG v4.2", "PTES", "NIST SP 800-115"],
            "tools_used": tools_used,
        },
        "hosts": state.get("hosts", {}),
        "warnings": list(state.get("warnings", [])),
    }

    # Render. Failures in PDF must not lose the Markdown/HTML content.
    out_dir = settings.output_path / (meta["scan_id"] or "scan")
    try:
        paths = render_all(report_sections, meta, out_dir)
    except Exception as exc:
        errors.append(f"Report rendering failed: {exc}")
        paths = {}

    return {
        "report_sections": report_sections,
        "report_paths": paths,
        "warnings": warnings,
        "errors": errors,
        "current_step": "write",
    }
