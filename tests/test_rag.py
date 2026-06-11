"""RAG retrieval tests (Section 7). Cold-start must never fail or hit the network."""

import rednarrate.config as config
from rednarrate.rag import retriever
from rednarrate.rag.fallback import GENERIC_CONTEXT, STATIC_CONTEXT, static_context
from rednarrate.scoring.heuristics import HEURISTICS


def test_cold_start_returns_static_context(tmp_path, monkeypatch):
    # Point Chroma at a non-existent dir -> store is None -> static fallback.
    monkeypatch.setenv("REDNARRATE_CHROMA_DIR", str(tmp_path / "absent"))
    config._settings = None
    retriever.reset_store_cache()
    try:
        ctx = retriever.get_context({"finding_type": "sqli", "name": "SQL injection"})
        assert isinstance(ctx, str) and ctx.strip()
        assert "SQL injection" in ctx or "parameterized" in ctx
    finally:
        config._settings = None
        retriever.reset_store_cache()


def test_static_context_specific_and_generic():
    assert "SQL injection" in static_context("sqli")
    assert static_context("totally-unknown-type") == GENERIC_CONTEXT


def test_static_context_covers_core_finding_types():
    # Every type with a heuristic vector should resolve to usable, non-empty text.
    for ftype in HEURISTICS:
        ctx = static_context(ftype)
        assert isinstance(ctx, str) and ctx.strip()


def test_generic_context_is_nonempty():
    assert GENERIC_CONTEXT.strip()
    assert len(STATIC_CONTEXT) >= 10
