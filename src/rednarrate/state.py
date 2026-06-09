"""The data contract between all pipeline stages.

`Finding` is the normalized unit every parser produces and every agent enriches.
`ScanState` is the LangGraph shared state — agents read upstream fields and
return partial updates for their own fields only (see CLAUDE.md invariants).
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from pydantic import BaseModel, Field

# Severity bands keyed to CVSS 3.1 score ranges (research_dump §3).
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


class Finding(BaseModel):
    """One normalized finding. Travels through ScanState as a dict (model_dump)."""

    id: str  # RAW-### at parse time, VAPT-YYYY-NNN after scoring
    source_tool: str  # "nmap" | "burp" | "sqlmap" | "burp+sqlmap"
    host: str  # IP or hostname
    port: Optional[int] = None
    protocol: str = "tcp"
    service: Optional[str] = None  # "http", "ssh OpenSSH 5.3p1"
    url: Optional[str] = None  # web findings
    parameter: Optional[str] = None  # injectable / affected parameter

    finding_type: str  # normalized class: "sqli", "xss-reflected", "open-port", ...
    name: str  # human-readable title

    severity_raw: Optional[str] = None  # tool-reported (Burp High/Medium/...)
    confidence: Optional[str] = None  # Burp Certain/Firm/Tentative; nmap conf as str
    description_raw: str = ""  # tool-provided description text

    evidence: str = ""  # decoded request/response, NSE output, log lines (<=4KB)
    evidence_truncated: bool = False
    references: list[str] = Field(default_factory=list)  # CWE/CVE/OWASP/CPE ids

    instances: int = 1  # merged-duplicate count
    host_port_ref: Optional[str] = None  # cross-link to related service finding
    dedup_key: str = ""  # canonical identity key

    # ── populated by the scoring agent ──────────────────────────────
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    score_disputed: bool = False  # LLM vs heuristic disagreed > 3.0

    # ── populated by the report writer agent ────────────────────────
    description: str = ""  # narrative description
    business_impact: str = ""
    remediation: list[str] = Field(default_factory=list)
    report_references: list[str] = Field(default_factory=list)  # validated CWE/OWASP


class FindingNarrative(BaseModel):
    """Structured output requested from the LLM per finding (report writer)."""

    description: str = Field(description="2-3 sentence instance-specific description")
    business_impact: str = Field(description="1-2 sentence business impact")
    remediation_steps: list[str] = Field(
        description="3-5 specific remediation bullets tied to the evidence"
    )
    references: list[str] = Field(
        default_factory=list, description="CWE / OWASP category ids only"
    )


class AttackChain(BaseModel):
    """One correlated attack chain."""

    id: str = ""
    name: str
    finding_ids: list[str]
    combined_impact: str
    detected_by: str = "rule"  # "rule" | "llm" | "rule+llm"


class ScanState(TypedDict, total=False):
    """LangGraph shared state. `total=False` so partial updates are valid."""

    # ── scan metadata (set before invoke) ───────────────────────────
    scan_id: str
    client_name: str
    scope: str
    engagement_dates: str
    llm_provider: str

    # ── inputs ──────────────────────────────────────────────────────
    raw_inputs: dict[str, list[str]]  # {"nmap": [path, ...], "burp": [path], ...}

    # ── ingestion output ────────────────────────────────────────────
    parsed_findings: list[dict]
    hosts: dict[str, dict]  # {ip: {hostname, os, open_ports: [...]}}

    # ── correlation output ──────────────────────────────────────────
    correlated_findings: list[dict]
    attack_chains: list[dict]

    # ── scoring output ──────────────────────────────────────────────
    scored_findings: list[dict]

    # ── report writer output ────────────────────────────────────────
    report_sections: dict
    report_paths: dict[str, str]

    # ── bookkeeping (append-only via reducers) ──────────────────────
    errors: Annotated[list[str], operator.add]
    warnings: Annotated[list[str], operator.add]
    current_step: str


def empty_state(**meta) -> ScanState:
    """Build an initial state with all collections defaulted, plus metadata."""
    state: ScanState = {
        "scan_id": meta.get("scan_id", ""),
        "client_name": meta.get("client_name", ""),
        "scope": meta.get("scope", ""),
        "engagement_dates": meta.get("engagement_dates", ""),
        "llm_provider": meta.get("llm_provider", "anthropic"),
        "raw_inputs": meta.get("raw_inputs", {}),
        "parsed_findings": [],
        "hosts": {},
        "correlated_findings": [],
        "attack_chains": [],
        "scored_findings": [],
        "report_sections": {},
        "report_paths": {},
        "errors": [],
        "warnings": [],
        "current_step": "init",
    }
    return state
