"""Report writer tests (Section 5). LLM disabled / mocked — no network."""

import rednarrate.config as config
from rednarrate.agents import report_writer as rw
from rednarrate.state import FindingNarrative


def _finding(**over):
    base = {
        "id": "VAPT-2026-001", "source_tool": "burp", "host": "10.0.0.5", "port": 443,
        "finding_type": "sqli", "name": "SQL injection", "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
        "evidence": "payload ' OR 1=1", "references": ["CWE-89"],
    }
    base.update(over)
    return base


def test_fallback_narrative_when_no_llm():
    f, warns = rw._write_finding(_finding(), structured_llm=None)
    assert f["description"]
    assert f["business_impact"]
    assert len(f["remediation"]) >= 1
    assert f["report_references"] == ["CWE-89"]


def test_hallucinated_cve_is_dropped():
    refs = ["CWE-89", "CVE-2099-99999", "A03:2021"]
    kept, warns = rw._validate_llm_refs(refs, _finding(references=["CWE-89"]))
    assert "CVE-2099-99999" not in kept
    assert "CWE-89" in kept
    assert any("CVE-2099-99999" in w for w in warns)


def test_known_cve_is_kept():
    f = _finding(references=["CVE-2017-0144", "CWE-89"])
    kept, warns = rw._validate_llm_refs(["CVE-2017-0144"], f)
    assert kept == ["CVE-2017-0144"]
    assert not warns


def test_template_artifacts_are_stripped():
    assert rw._strip_artifacts("Hello {{ client }} world") == "Hello  world"
    assert "[CLIENT]" not in rw._strip_artifacts("Risk to [CLIENT] systems")


def test_write_finding_strips_artifacts_from_llm_output():
    class _Structured:
        def invoke(self, _msgs):
            return FindingNarrative(
                description="Affects {{ client }} login",
                business_impact="Impacts [CLIENT].",
                remediation_steps=["Patch {{ now }}"],
                references=["CWE-89", "CVE-2099-1"],
            )

    f, warns = rw._write_finding(_finding(), _Structured())
    assert "{{" not in f["description"]
    assert "[CLIENT]" not in f["business_impact"]
    assert "{{" not in f["remediation"][0]
    assert "CVE-2099-1" not in f["report_references"]  # not in source refs -> dropped


def test_roadmap_buckets_are_deterministic():
    findings = [
        {"id": "1", "name": "a", "severity": "Critical", "remediation": ["x"]},
        {"id": "2", "name": "b", "severity": "High", "remediation": ["y"]},
        {"id": "3", "name": "c", "severity": "Medium", "remediation": ["z"]},
        {"id": "4", "name": "d", "severity": "Low", "remediation": []},
        {"id": "5", "name": "e", "severity": "Informational", "remediation": []},
    ]
    rm = rw._roadmap(findings)
    assert len(rm["immediate"]) == 2   # Critical + High
    assert len(rm["short_term"]) == 1  # Medium
    assert len(rm["long_term"]) == 2   # Low + Informational


def test_overall_risk_is_top_band_present():
    assert rw._overall_risk([{"severity": "Medium"}, {"severity": "Low"}]) == "Medium"
    assert rw._overall_risk([{"severity": "Critical"}, {"severity": "Low"}]) == "Critical"
    assert rw._overall_risk([{"severity": "Informational"}]) == "Informational"


def test_exec_summary_risk_is_deterministic_without_llm():
    es = rw._write_exec_summary(
        [{"id": "VAPT-2026-001", "name": "SQLi", "severity": "Critical"}],
        chains=[], meta={"client_name": "Acme"}, llm=None,
    )
    assert es["overall_risk"] == "Critical"
    assert es["severity_counts"]["Critical"] == 1


def test_pdf_failure_is_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNARRATE_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("REDNARRATE_DB_PATH", str(tmp_path / "t.db"))
    config._settings = None
    # Disable writer LLM and force the PDF renderer to blow up.
    monkeypatch.setattr("rednarrate.agents.report_writer.get_llm",
                        lambda role="writer": (_ for _ in ()).throw(RuntimeError("no llm")))
    monkeypatch.setattr("rednarrate.report.renderer.render_pdf",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("weasyprint down")))
    try:
        state = {
            "scan_id": "s1", "client_name": "Acme",
            "scored_findings": [_finding(severity="Critical")],
            "attack_chains": [],
        }
        out = rw.report_writer_node(state)
        assert "md" in out["report_paths"]
        assert "html" in out["report_paths"]
        assert "pdf" not in out["report_paths"]
        assert not out["errors"]  # PDF-only failure is non-fatal
    finally:
        config._settings = None
