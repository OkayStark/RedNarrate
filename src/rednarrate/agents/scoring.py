"""CVSS scoring agent: assign each finding a validated CVSS 3.1 score.

Four layers (PROJECT_PLAN §11 Problem 2): heuristic anchor -> Literal-typed LLM
metrics -> cvss library validation/computation -> deterministic fallback, plus a
sanity-dispute flag when the LLM diverges sharply from the heuristic.
The cvss library — never the LLM — owns the numeric score.
"""

from __future__ import annotations

import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Literal

from cvss import CVSS3
from pydantic import BaseModel, Field

from ..llm import get_llm
from ..scoring.heuristics import heuristic_vector
from ..state import ScanState


class CVSSMetrics(BaseModel):
    """Type-constrained LLM output — invalid metric letters are unrepresentable."""

    AV: Literal["N", "A", "L", "P"] = Field(description="Attack Vector")
    AC: Literal["L", "H"] = Field(description="Attack Complexity")
    PR: Literal["N", "L", "H"] = Field(description="Privileges Required")
    UI: Literal["N", "R"] = Field(description="User Interaction")
    S: Literal["U", "C"] = Field(description="Scope")
    C: Literal["N", "L", "H"] = Field(description="Confidentiality impact")
    I: Literal["N", "L", "H"] = Field(description="Integrity impact")
    A: Literal["N", "L", "H"] = Field(description="Availability impact")
    deviation_rationale: str = Field(
        default="", description="One line, only if differing from the default vector"
    )


def _vector(m: CVSSMetrics) -> str:
    return (
        f"CVSS:3.1/AV:{m.AV}/AC:{m.AC}/PR:{m.PR}/UI:{m.UI}/"
        f"S:{m.S}/C:{m.C}/I:{m.I}/A:{m.A}"
    )


def _compute(vector: str) -> tuple[float, str]:
    c = CVSS3(vector)
    score = c.scores()[0]
    severity = c.severities()[0]
    # cvss lib uses "None" severity for 0.0; map to our band name.
    if severity == "None":
        severity = "Informational"
    return float(score), severity


def _score_one(f: dict, structured_llm) -> dict:
    prior = heuristic_vector(f["finding_type"])
    prior_score, _ = _compute(prior)

    # Shortcut: skip the LLM for findings that are deterministically Informational.
    # - open-port: CVSS is always 0.0 (no C/I/A), LLM adds nothing.
    # - Burp/tool-reported Information severity: tool already classified it; honour that.
    is_open_port = f["finding_type"] == "open-port"
    is_info_raw = (f.get("severity_raw") or "").lower() in {
        "information", "informational", "info"
    }
    if is_open_port or is_info_raw:
        score = 0.0 if is_open_port else _compute(prior)[0]
        f.update(cvss_vector=prior, cvss_score=score, severity="Informational")
        return f

    vector, score, severity = prior, prior_score, None
    last_err = None
    if structured_llm is not None:
        prompt_sys = (
            "You assign CVSS 3.1 base metrics. Output only the structured object. "
            "Anchor on the provided default vector; deviate only when the evidence "
            "justifies it (authentication required -> PR:L, local-only service -> AV:L)."
        )
        prompt_user = (
            f"Finding: {f['name']} ({f['finding_type']})\n"
            f"Asset: {f['host']}:{f.get('port', '')} {f.get('url', '')} "
            f"{f.get('parameter', '')}\n"
            f"Tool severity/confidence: {f.get('severity_raw')}/{f.get('confidence')}\n"
            f"Evidence (excerpt): {f.get('evidence', '')[:1500]}\n"
            f"Default vector for this class: {prior}"
        )
        msgs = [("system", prompt_sys), ("human", prompt_user)]
        for attempt in range(2):
            try:
                with ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(structured_llm.invoke, msgs)
                    m = fut.result(timeout=45)
                cand = _vector(m)
                score, severity = _compute(cand)  # raises on invalid combos
                vector = cand
                break
            except FuturesTimeout:
                last_err = Exception("LLM call timed out after 45s")
                break
            except Exception as exc:
                last_err = exc
                msgs.append(("human", f"That vector was invalid ({exc}). Retry."))
        else:
            severity = None

    if severity is None:  # LLM path exhausted -> deterministic fallback
        vector = prior
        score, severity = _compute(prior)
        if last_err:
            f.setdefault("_warnings", []).append(
                f"{f['id']}: LLM scoring failed ({last_err}); heuristic vector used"
            )

    f["score_disputed"] = abs(score - prior_score) > 3.0
    f.update(cvss_vector=vector, cvss_score=score, severity=severity)
    return f


def cvss_scoring_node(state: ScanState) -> dict:
    findings = list(state.get("correlated_findings", []))
    warnings: list[str] = []

    structured_llm = None
    try:
        structured_llm = get_llm("scoring").with_structured_output(CVSSMetrics)
    except Exception as exc:
        warnings.append(f"Scoring LLM unavailable ({exc}); using heuristic vectors")

    scored = []
    for f in findings:
        f = _score_one(dict(f), structured_llm)
        warnings.extend(f.pop("_warnings", []))
        scored.append(f)

    # Sort Critical -> Info (by score desc), then assign final VAPT ids.
    scored.sort(key=lambda x: (x.get("cvss_score") or 0.0), reverse=True)
    year = datetime.date.today().year
    id_map: dict[str, str] = {}
    for i, f in enumerate(scored, start=1):
        new_id = f"VAPT-{year}-{i:03d}"
        id_map[f["id"]] = new_id
        f["id"] = new_id

    # Remap chain references so they survive the id reassignment.
    chains = []
    for c in state.get("attack_chains", []):
        c = dict(c)
        c["finding_ids"] = [id_map.get(fid, fid) for fid in c.get("finding_ids", [])]
        chains.append(c)

    disputed = [f["id"] for f in scored if f.get("score_disputed")]
    if disputed:
        warnings.append(
            f"Score dispute (LLM vs heuristic > 3.0) flagged for: {', '.join(disputed)}"
        )

    return {
        "scored_findings": scored,
        "attack_chains": chains,
        "warnings": warnings,
        "current_step": "score",
    }
