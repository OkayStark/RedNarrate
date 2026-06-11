"""FastAPI web UI tests (Section 13). Offline pipeline via BackgroundTasks."""

from pathlib import Path

import pytest

import rednarrate.config as config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNARRATE_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("REDNARRATE_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("REDNARRATE_CHROMA_DIR", str(tmp_path / "chroma_absent"))
    monkeypatch.chdir(tmp_path)  # uploads/ created under tmp
    config._settings = None

    from fastapi.testclient import TestClient

    from rednarrate.api.app import app

    with TestClient(app) as c:
        yield c
    config._settings = None


def test_index_renders(client):
    res = client.get("/")
    assert res.status_code == 200


def test_unknown_scan_is_404(client):
    assert client.get("/scans/doesnotexist").status_code == 404
    assert client.get("/scans/doesnotexist/report?fmt=md").status_code == 404


def test_upload_runs_pipeline_and_produces_report(client):
    files = [
        ("files", ("nmap_full.xml", (FIXTURES / "nmap_full.xml").read_bytes(), "application/xml")),
        ("files", ("sqlmap_injectable.log", (FIXTURES / "sqlmap_injectable.log").read_bytes(), "text/plain")),
    ]
    res = client.post("/scans", data={"client": "WebCorp", "scope": "x"}, files=files)
    # TestClient follows the 303 redirect to the status page.
    assert res.status_code == 200
    assert "WebCorp" in res.text


def test_oversized_upload_returns_413(client, monkeypatch):
    monkeypatch.setattr("rednarrate.api.app._MAX_UPLOAD_BYTES", 16)
    big = b"A" * 1024
    res = client.post(
        "/scans",
        data={"client": "T"},
        files=[("files", ("nmap_full.xml", big, "application/xml"))],
        follow_redirects=False,
    )
    assert res.status_code == 413
