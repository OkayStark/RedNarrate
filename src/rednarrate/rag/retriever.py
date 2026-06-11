"""RAG retrieval for the report writer, with a hard cold-start guarantee.

If the Chroma store is missing or empty, get_context falls back to compiled-in
static context — the pipeline must never fail for lack of RAG setup.
"""

from __future__ import annotations

from functools import lru_cache

from ..config import get_settings
from .fallback import static_context

COLLECTION = "pentest_knowledge"


@lru_cache(maxsize=1)
def _store():
    """Open the persisted Chroma collection, or None if unavailable/empty."""
    settings = get_settings()
    chroma_dir = settings.chroma_path
    if not chroma_dir.exists():
        return None
    try:
        from langchain_chroma import Chroma
        from langchain_huggingface import HuggingFaceEmbeddings

        embeddings = HuggingFaceEmbeddings(model_name=settings.embedding_model)
        store = Chroma(
            collection_name=COLLECTION,
            embedding_function=embeddings,
            persist_directory=str(chroma_dir),
        )
        # Empty collection -> treat as cold start.
        try:
            if store._collection.count() == 0:
                return None
        except Exception:
            pass
        return store
    except Exception:
        return None


def reset_store_cache() -> None:
    _store.cache_clear()


def get_context(finding: dict, k: int = 3) -> str:
    """Return reference context for a finding. Always returns usable text."""
    ftype = finding.get("finding_type", "")
    store = _store()
    if store is None:
        return static_context(ftype)

    query = f"{finding.get('name', '')} {ftype} description impact remediation"
    try:
        docs = store.similarity_search(query, k=k, filter={"vuln_class": ftype})
        if len(docs) < k:
            extra = store.similarity_search(query, k=k - len(docs))
            seen = {d.page_content for d in docs}
            docs += [d for d in extra if d.page_content not in seen]
        if docs:
            return "\n---\n".join(d.page_content for d in docs)
    except Exception:
        pass
    return static_context(ftype)
