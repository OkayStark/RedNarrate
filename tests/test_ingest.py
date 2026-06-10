"""RAG ingestion tests (Section 7). No model download — error paths raise
before embeddings load; _vuln_class is pure path classification."""

from pathlib import Path

import pytest

from rednarrate.rag.ingest import _vuln_class, build_knowledge_base


def test_vuln_class_maps_known_fragments():
    assert _vuln_class(Path("wstg/sql_injection.md")) == "sqli"
    assert _vuln_class(Path("a/command_injection.md")) == "os-command-injection"
    assert _vuln_class(Path("x/stored_xss.md")) == "xss-stored"
    assert _vuln_class(Path("x/reflected_xss.md")) == "xss-reflected"
    assert _vuln_class(Path("x/csrf_notes.txt")) == "csrf"
    assert _vuln_class(Path("x/xxe_external.md")) == "xxe"
    assert _vuln_class(Path("x/idor.md")) == "idor"


def test_vuln_class_defaults_to_general():
    assert _vuln_class(Path("misc/random_topic.md")) == "general"


def test_missing_knowledge_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_knowledge_base(knowledge_dir=str(tmp_path / "absent"),
                             chroma_dir=str(tmp_path / "chroma"))


def test_empty_corpus_raises(tmp_path):
    kdir = tmp_path / "knowledge"
    kdir.mkdir()
    (kdir / "notes.pdf").write_bytes(b"%PDF-ignored")  # non .md/.txt
    with pytest.raises(ValueError, match="No .md/.txt"):
        build_knowledge_base(knowledge_dir=str(kdir), chroma_dir=str(tmp_path / "chroma"))
