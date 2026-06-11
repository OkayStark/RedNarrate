"""Database layer tests (Section 9). Plain sqlite3, isolated per-test db_path."""

from pathlib import Path

import pytest

from rednarrate.db import repository as repo

SRC = Path(__file__).resolve().parent.parent / "src" / "rednarrate"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "t.db")
    repo.init_db(path)
    return path


def _scan(db, scan_id="s1"):
    repo.create_scan({"scan_id": scan_id, "client_name": "Acme", "raw_inputs": {}}, db_path=db)
    return scan_id


def test_schema_creates_all_tables(db):
    with repo.connect(db) as conn:
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert {"scans", "findings", "attack_chains", "reports"} <= names


def test_foreign_keys_enabled(db):
    with repo.connect(db) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_findings_roundtrip_with_json_fields(db):
    sid = _scan(db)
    f = {
        "id": "VAPT-2026-001", "source_tool": "burp+sqlmap", "host": "10.0.0.5",
        "port": 443, "finding_type": "sqli", "name": "SQLi", "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
        "score_disputed": True, "description": "d", "business_impact": "b",
        "evidence": "e", "remediation": ["step1", "step2"], "references": ["CWE-89"],
        "instances": 2, "is_chain_member": True,
    }
    repo.save_findings(sid, [f], db_path=db)
    got = repo.get_findings(sid, db_path=db)[0]
    assert got["remediation"] == ["step1", "step2"]
    assert got["refs"] == ["CWE-89"]
    assert got["instances"] == 2
    assert got["score_disputed"] == 1


def test_cascade_delete_removes_children(db):
    sid = _scan(db)
    repo.save_findings(sid, [{"id": "VAPT-2026-001", "source_tool": "burp", "host": "h",
                              "finding_type": "sqli", "name": "n", "severity": "High",
                              "cvss_score": 7.0}], db_path=db)
    repo.save_chains(sid, [{"id": "c1", "name": "chain", "finding_ids": ["VAPT-2026-001"],
                            "combined_impact": "x", "detected_by": "rule"}], db_path=db)
    repo.save_report(sid, "md", "/tmp/r.md", [], db_path=db)

    with repo.connect(db) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (sid,))
    assert repo.get_findings(sid, db_path=db) == []
    assert repo.get_chains(sid, db_path=db) == []
    assert repo.get_reports(sid, db_path=db) == []


def test_invalid_status_rejected_by_check_constraint(db):
    sid = _scan(db)
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        repo.update_scan_status(sid, "not-a-real-status", db_path=db)


def test_list_scans_orders_newest_first(db):
    _scan(db, "old")
    _scan(db, "new")
    with repo.connect(db) as conn:  # make ordering deterministic
        conn.execute("UPDATE scans SET created_at='2020-01-01' WHERE id='old'")
        conn.execute("UPDATE scans SET created_at='2030-01-01' WHERE id='new'")
    ids = [s["id"] for s in repo.list_scans(db_path=db)]
    assert ids.index("new") < ids.index("old")


def test_agents_are_db_free():
    for p in (SRC / "agents").glob("*.py"):
        text = p.read_text()
        assert "import sqlite3" not in text, f"{p.name} touches sqlite3"
        assert "repository" not in text, f"{p.name} imports the DB repository"
