"""Scoring tests mock the LLM so no live calls happen in CI."""

import pytest

from rednarrate.agents.scoring import CVSSMetrics, cvss_scoring_node
from rednarrate.scoring.heuristics import heuristic_vector


class _FakeStructured:
    def __init__(self, metrics=None, raise_exc=False):
        self._metrics = metrics
        self._raise = raise_exc

    def invoke(self, _msgs):
        if self._raise:
            raise RuntimeError("simulated LLM failure")
        return self._metrics


class _FakeLLM:
    def __init__(self, structured):
        self._structured = structured

    def with_structured_output(self, _model):
        return self._structured


def _patch_llm(monkeypatch, structured):
    monkeypatch.setattr(
        "rednarrate.agents.scoring.get_llm", lambda role="scoring": _FakeLLM(structured)
    )


def _sqli_finding():
    return {
        "id": "RAW-001", "source_tool": "burp+sqlmap", "host": "10.0.0.5",
        "port": 443, "finding_type": "sqli", "name": "SQL injection",
        "severity_raw": "High", "confidence": "Certain", "evidence": "payload ' OR 1=1",
    }


def test_llm_metrics_validated_and_scored(monkeypatch):
    metrics = CVSSMetrics(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    _patch_llm(monkeypatch, _FakeStructured(metrics))
    out = cvss_scoring_node({"correlated_findings": [_sqli_finding()], "attack_chains": []})
    f = out["scored_findings"][0]
    assert f["cvss_score"] == 9.8
    assert f["severity"] == "Critical"
    assert f["id"].startswith("VAPT-")


def test_falls_back_to_heuristic_on_llm_failure(monkeypatch):
    _patch_llm(monkeypatch, _FakeStructured(raise_exc=True))
    out = cvss_scoring_node({"correlated_findings": [_sqli_finding()], "attack_chains": []})
    f = out["scored_findings"][0]
    # Heuristic sqli vector -> 9.8; pipeline must not crash.
    assert f["cvss_vector"] == heuristic_vector("sqli")
    assert f["cvss_score"] == 9.8


def test_information_finding_shortcut(monkeypatch):
    # Even if the LLM would say otherwise, Information stays Informational.
    metrics = CVSSMetrics(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    _patch_llm(monkeypatch, _FakeStructured(metrics))
    info = {
        "id": "RAW-9", "source_tool": "burp", "host": "h", "finding_type": "info-disclosure",
        "name": "Banner", "severity_raw": "Information", "evidence": "Server: Apache",
    }
    out = cvss_scoring_node({"correlated_findings": [info], "attack_chains": []})
    assert out["scored_findings"][0]["severity"] == "Informational"


def test_findings_sorted_and_ids_sequential(monkeypatch):
    _patch_llm(monkeypatch, _FakeStructured(raise_exc=True))  # heuristic scoring
    findings = [
        {"id": "RAW-1", "source_tool": "nmap", "host": "h", "port": 80,
         "finding_type": "open-port", "name": "open", "evidence": ""},
        {"id": "RAW-2", "source_tool": "burp", "host": "h", "port": 443,
         "finding_type": "sqli", "name": "sqli", "evidence": ""},
    ]
    out = cvss_scoring_node({"correlated_findings": findings, "attack_chains": []})
    ids = [f["id"] for f in out["scored_findings"]]
    assert ids == sorted(ids)  # VAPT-...-001 first
    # Highest score (sqli) sorts first.
    assert out["scored_findings"][0]["finding_type"] == "sqli"


def test_chain_ids_remapped(monkeypatch):
    _patch_llm(monkeypatch, _FakeStructured(raise_exc=True))
    findings = [{"id": "RAW-2", "source_tool": "burp", "host": "h", "port": 443,
                 "finding_type": "sqli", "name": "sqli", "evidence": ""}]
    chains = [{"id": "c1", "name": "x", "finding_ids": ["RAW-2"], "combined_impact": ""}]
    out = cvss_scoring_node({"correlated_findings": findings, "attack_chains": chains})
    new_id = out["scored_findings"][0]["id"]
    assert out["attack_chains"][0]["finding_ids"] == [new_id]


def test_all_heuristic_vectors_are_valid_cvss():
    """Guard rail: every default vector must parse/compute under cvss.CVSS3."""
    from cvss import CVSS3

    from rednarrate.scoring.heuristics import HEURISTICS, heuristic_vector

    for ftype in HEURISTICS:
        CVSS3(heuristic_vector(ftype))  # raises if any tail is malformed
