"""Security & evidence-hygiene invariants (CLAUDE.md §6, §14).

No live calls, no network. Confirms defusedxml usage, credential redaction at
the parse boundary, that secrets never reach the DB, and .gitignore coverage.
"""

from pathlib import Path

import pytest

from rednarrate.db import repository as repo
from rednarrate.parsers.base import sanitize_evidence, truncate_evidence

SRC = Path(__file__).resolve().parent.parent / "src" / "rednarrate"
ROOT = Path(__file__).resolve().parent.parent


def test_burp_parser_uses_defusedxml():
    src = (SRC / "parsers" / "burp_parser.py").read_text()
    assert "defusedxml" in src
    # No direct stdlib ElementTree parsing of attacker-adjacent XML.
    assert "import xml.etree.ElementTree" not in src
    assert "from xml.etree" not in src


def test_no_stdlib_elementtree_in_parsers():
    for p in (SRC / "parsers").glob("*.py"):
        text = p.read_text()
        assert "from xml.etree" not in text, f"{p.name} imports stdlib ElementTree"
        assert "import xml.etree.ElementTree" not in text, p.name


@pytest.mark.parametrize(
    "secret, evidence",
    [
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"),
        ("session=abc123", "Cookie: session=abc123"),
        ("sid=deadbeef", "Set-Cookie: sid=deadbeef; HttpOnly"),
        ("AKIAIOSFODNN7EXAMPLE", "body AKIAIOSFODNN7EXAMPLE more"),
        ("ghp_" + "a" * 36, "token ghp_" + "a" * 36),
    ],
)
def test_sanitize_strips_secrets(secret, evidence):
    out = sanitize_evidence(evidence)
    assert secret not in out
    assert "[REDACTED]" in out


def test_sanitize_strips_null_bytes():
    assert "\x00" not in sanitize_evidence("a\x00b")


def test_truncate_evidence_sanitizes_at_parse_boundary():
    raw = "GET / HTTP/1.1\nAuthorization: Bearer SUPERSECRETTOKENVALUE123\n"
    text, _ = truncate_evidence(raw)
    assert "SUPERSECRETTOKENVALUE123" not in text


def test_no_credentials_reach_the_database(tmp_path):
    db = str(tmp_path / "sec.db")
    repo.init_db(db)
    meta = {"scan_id": "s1", "client_name": "C", "raw_inputs": {}}
    repo.create_scan(meta, db_path=db)

    # Evidence as it would arrive from a parser (already passed truncate_evidence).
    ev, _ = truncate_evidence("Cookie: session=topsecretsession\nAuthorization: Bearer zzzTOKENzzz")
    finding = {
        "id": "VAPT-2026-001", "source_tool": "burp", "host": "h", "port": 443,
        "finding_type": "sqli", "name": "SQLi", "severity": "Critical",
        "cvss_score": 9.8, "evidence": ev,
    }
    repo.save_findings("s1", [finding], db_path=db)
    stored = repo.get_findings("s1", db_path=db)[0]["evidence"]
    assert "topsecretsession" not in stored
    assert "zzzTOKENzzz" not in stored
    assert "[REDACTED]" in stored


def test_gitignore_covers_sensitive_artifacts():
    gi = (ROOT / ".gitignore").read_text()
    for needed in (".env", "*.db", "output/", "chroma_db/"):
        assert needed in gi, f".gitignore missing {needed}"
