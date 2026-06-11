"""End-to-end pipeline test with the LLM fully disabled.

Exercises ingest -> correlate -> score -> write on the sample evidence, using
heuristic scoring and template narratives (no network). PDF rendering may be
skipped if WeasyPrint's system libs are absent; md/html must still be produced.
"""

import shutil
from pathlib import Path

import pytest

import rednarrate.config as config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNARRATE_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("REDNARRATE_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("REDNARRATE_CHROMA_DIR", str(tmp_path / "chroma_absent"))
    config._settings = None  # force re-read of env
    yield tmp_path
    config._settings = None


def _disable_llm(monkeypatch):
    def boom(role="writer"):
        raise RuntimeError("LLM disabled in test")

    monkeypatch.setattr("rednarrate.agents.scoring.get_llm", boom)
    monkeypatch.setattr("rednarrate.agents.report_writer.get_llm", boom)


def test_full_pipeline(isolated, monkeypatch):
    _disable_llm(monkeypatch)
    from rednarrate.graph import run_pipeline

    evidence = isolated / "evidence"
    evidence.mkdir()
    for name in ("nmap_full.xml", "burp_full.xml", "sqlmap_injectable.log"):
        shutil.copy(FIXTURES / name, evidence / name)

    from rednarrate.parsers import collect_inputs

    inputs, _ = collect_inputs(evidence)
    assert set(inputs) == {"nmap", "burp", "sqlmap"}

    meta = {
        "client_name": "Acme Corp", "scope": "external web", "engagement_dates": "2026",
        "llm_provider": "none", "raw_inputs": inputs,
    }
    final = run_pipeline(meta, db_path=str(isolated / "t.db"), checkpoint=False)

    assert not final.get("errors"), final.get("errors")
    scored = final["scored_findings"]
    assert scored, "expected findings"
    # cross-tool SQLi merged and scored Critical
    sqli = [f for f in scored if f["finding_type"] == "sqli"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "Critical"
    assert "burp" in sqli[0]["source_tool"] and "sqlmap" in sqli[0]["source_tool"]
    # ids are final VAPT ids, severity-sorted
    assert all(f["id"].startswith("VAPT-") for f in scored)

    paths = final["report_paths"]
    assert "md" in paths and Path(paths["md"]).exists()
    assert "html" in paths and Path(paths["html"]).exists()
    md = Path(paths["md"]).read_text()
    assert "Acme Corp" in md
    assert "SQL injection" in md


def test_empty_inputs_fail_gracefully(isolated, monkeypatch):
    _disable_llm(monkeypatch)
    from rednarrate.graph import run_pipeline

    empty = isolated / "empty"
    empty.mkdir()
    (empty / "junk.txt").write_text("nothing useful here")

    from rednarrate.parsers import collect_inputs

    inputs, _ = collect_inputs(empty)
    meta = {"client_name": "X", "scope": "", "engagement_dates": "",
            "llm_provider": "none", "raw_inputs": inputs}
    final = run_pipeline(meta, db_path=str(isolated / "t.db"), checkpoint=False)
    assert final.get("errors"), "expected a fatal error when no findings parse"


def test_single_tool_subset_completes(isolated, monkeypatch):
    """nmap-only input must produce a complete report (no Burp/SQLMap needed)."""
    _disable_llm(monkeypatch)
    from rednarrate.graph import run_pipeline
    from rednarrate.parsers import collect_inputs

    evidence = isolated / "ev"
    evidence.mkdir()
    shutil.copy(FIXTURES / "nmap_full.xml", evidence / "nmap_full.xml")
    inputs, _ = collect_inputs(evidence)
    assert set(inputs) == {"nmap"}

    meta = {"client_name": "Solo", "scope": "", "engagement_dates": "",
            "llm_provider": "none", "raw_inputs": inputs}
    final = run_pipeline(meta, db_path=str(isolated / "t.db"), checkpoint=False)
    assert not final.get("errors"), final.get("errors")
    assert final["scored_findings"]
    assert "md" in final["report_paths"]


def test_sql_injection_client_name_is_safe(isolated, monkeypatch):
    """A SQLi payload as the client name must not corrupt the DB (parameterized)."""
    _disable_llm(monkeypatch)
    from rednarrate.db import repository as repo
    from rednarrate.graph import run_pipeline
    from rednarrate.parsers import collect_inputs

    evidence = isolated / "ev"
    evidence.mkdir()
    shutil.copy(FIXTURES / "nmap_full.xml", evidence / "nmap_full.xml")
    inputs, _ = collect_inputs(evidence)

    db = str(isolated / "t.db")
    meta = {"client_name": "'; DROP TABLE scans;--", "scope": "", "engagement_dates": "",
            "llm_provider": "none", "raw_inputs": inputs}
    final = run_pipeline(meta, db_path=db, checkpoint=False)
    assert not final.get("errors")
    # scans table still exists and recorded the literal payload as data
    scans = repo.list_scans(db_path=db)
    assert any(s["client_name"] == "'; DROP TABLE scans;--" for s in scans)
