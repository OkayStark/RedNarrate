"""Build the RAG knowledge base from the `knowledge/` corpus.

Run once via `rednarrate ingest-kb`. Walks knowledge/, chunks markdown/text
respecting headers, tags each chunk with a vuln_class derived from its path,
embeds locally, and persists to Chroma. One collection: `pentest_knowledge`.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..config import get_settings

COLLECTION = "pentest_knowledge"

# Map WSTG / file-name fragments to our finding_type vocabulary.
_CLASS_HINTS = [
    (r"sql[_-]?inj", "sqli"),
    (r"command[_-]?inj", "os-command-injection"),
    (r"reflected.*cross|cross.*reflected|reflected_xss", "xss-reflected"),
    (r"stored.*cross|stored_xss", "xss-stored"),
    (r"cross[_-]?site[_-]?scripting|xss", "xss-reflected"),
    (r"cross[_-]?site[_-]?request|csrf", "csrf"),
    (r"default[_-]?cred|weak[_-]?cred", "default-credentials"),
    (r"information[_-]?disclos|info[_-]?leak", "info-disclosure"),
    (r"directory[_-]?listing|directory[_-]?brows", "directory-listing"),
    (r"ssl|tls|transport[_-]?layer", "ssl-issue"),
    (r"xxe|xml[_-]?external", "xxe"),
    (r"idor|insecure[_-]?direct", "idor"),
    (r"open[_-]?redirect", "open-redirect"),
    (r"clickjack", "clickjacking"),
    (r"outdated|known[_-]?vuln|components", "outdated-software"),
]


def _vuln_class(path: Path) -> str:
    name = str(path).lower()
    for pattern, cls in _CLASS_HINTS:
        if re.search(pattern, name):
            return cls
    return "general"


def build_knowledge_base(knowledge_dir: str | None = None,
                         chroma_dir: str | None = None) -> int:
    """Chunk + embed + persist. Returns number of chunks indexed."""
    from langchain_chroma import Chroma
    from langchain_core.documents import Document
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    settings = get_settings()
    kdir = Path(knowledge_dir or settings.knowledge_dir)
    cdir = chroma_dir or settings.chroma_dir

    if not kdir.exists():
        raise FileNotFoundError(
            f"Knowledge directory {kdir} not found. Run scripts/fetch_knowledge.sh first."
        )

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        separators=["\n## ", "\n### ", "\n\n", "\n", " "],
    )

    docs: list[Document] = []
    for path in kdir.rglob("*"):
        if path.suffix.lower() not in (".md", ".txt") or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        source = path.relative_to(kdir).parts[0] if path.relative_to(kdir).parts else "general"
        vuln_class = _vuln_class(path)
        for chunk in splitter.split_text(text):
            if not chunk.strip():
                continue
            docs.append(Document(
                page_content=chunk,
                metadata={"source": source, "vuln_class": vuln_class,
                          "file": str(path.relative_to(kdir))},
            ))

    if not docs:
        raise ValueError(f"No .md/.txt documents found under {kdir}")

    embeddings = HuggingFaceEmbeddings(model_name=settings.embedding_model)
    store = Chroma(
        collection_name=COLLECTION,
        embedding_function=embeddings,
        persist_directory=cdir,
    )
    store.add_documents(docs)
    return len(docs)
