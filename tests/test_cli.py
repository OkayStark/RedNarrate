"""CLI tests (Section 12). In-process via Typer's CliRunner, offline provider."""

import shutil
from pathlib import Path

from typer.testing import CliRunner

import rednarrate.config as config
from rednarrate.cli.main import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("REDNARRATE_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("REDNARRATE_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("REDNARRATE_CHROMA_DIR", str(tmp_path / "chroma_absent"))
    config._settings = None


def _evidence(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    for n in ("nmap_full.xml", "burp_full.xml", "sqlmap_injectable.log"):
        shutil.copy(FIXTURES / n, ev / n)
    return ev


def test_run_offline_exit_zero(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ev = _evidence(tmp_path)
    res = runner.invoke(app, ["run", str(ev), "--client", "T", "--provider", "none",
                              "--no-checkpoint"])
    config._settings = None
    assert res.exit_code == 0, res.output
    assert "Report written" in res.output


def test_run_no_inputs_exit_one(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "junk.txt").write_text("nope")
    res = runner.invoke(app, ["run", str(empty), "--provider", "none"])
    config._settings = None
    assert res.exit_code == 1


def test_list_scans_handles_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    res = runner.invoke(app, ["list-scans"])
    config._settings = None
    assert res.exit_code == 0


def test_help_lists_commands():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("run", "ingest-kb", "serve", "list-scans"):
        assert cmd in res.output
