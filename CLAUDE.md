# CLAUDE.md — RedNarrate

## Project Summary

RedNarrate is an AI-powered pentest evidence triage and report generation tool. A pentester points it at a folder containing raw tool outputs (nmap `-oX` XML, Burp Suite issue XML, SQLMap console logs). A LangGraph pipeline parses them into normalized findings, deduplicates and correlates across tools, assigns validated CVSS 3.1 scores, and writes a complete client-ready VAPT report as PDF + Markdown.

Solo-developer project, 6-week MVP. Full plan: `PROJECT_PLAN.md`. Research notes: `research_dump.md`.

## Architecture

Sequential LangGraph pipeline over a shared `ScanState` TypedDict (`src/rednarrate/state.py`):

```
Ingestion → Correlation → CVSS Scoring → Report Writer → END
   (no LLM)   (1 LLM call)  (1 call/finding)  (1 call/finding + 1)
```

- Each agent is a function `node(state: ScanState) -> dict` in `src/rednarrate/agents/`, returning **partial state updates only**.
- Conditional edges route to END when `state["errors"]` is non-empty. Nodes never raise out of the graph — they append to `errors` (fatal) or `warnings` (non-fatal).
- Checkpointing: LangGraph `SqliteSaver`, `thread_id = scan_id`.
- Persistence (SQLite, `src/rednarrate/db/`) happens at pipeline boundaries, not inside agents — agents stay DB-free and unit-testable.
- Two frontends call the same graph: Typer CLI (`src/rednarrate/cli/main.py`) and FastAPI (`src/rednarrate/api/`).

## Agent Responsibilities (and limits)

| Agent | Does | Does NOT |
|---|---|---|
| `ingestion.py` | Dispatch files to parsers, normalize to `Finding`, build host inventory, compute `dedup_key` | Call LLMs, dedupe, assign severity |
| `correlation.py` | Deterministic dedup/merge by canonical `dedup_key`, cross-tool enrichment (e.g. Burp+SQLMap SQLi merge), rule-based attack chains, one LLM call to confirm chains and write chain narratives | Score, write report prose |
| `scoring.py` | Heuristic prior vector → LLM proposes CVSS 3.1 base metrics (structured output) → `cvss` library computes score → retry once → heuristic fallback. Assigns final `VAPT-YYYY-NNN` IDs in severity order | Trust an LLM-stated numeric score, change finding identity |
| `report_writer.py` | RAG-augmented per-finding narratives, exec summary, deterministic roadmap buckets, then render PDF/MD via `report/renderer.py` | Change scores/severities/order; do layout (renderer's job) |

## Key Design Decisions (and why)

1. **Finding identity is deterministic, never LLM-decided.** Dedup/merge happens only on exact canonical `dedup_key` equality (host resolved via nmap inventory, URL path normalized, parameter lowercased). Wrong merges hide findings; the bias is to under-merge with `host_port_ref` cross-links.
2. **The `cvss` library is the source of truth for scores.** The LLM only proposes the 8 base metrics as `Literal`-typed pydantic fields, anchored on a heuristic table (`scoring/heuristics.py`). Every vector is validated and computed by `cvss.CVSS3`. Disagreement > 3.0 vs the heuristic sets `score_disputed`.
3. **defusedxml for all XML parsing.** Burp/nmap output is attacker-adjacent data; stock ElementTree is XXE/entity-expansion vulnerable. Never replace defusedxml with plain `xml.etree`.
4. **Two LLM providers via `llm.py` factory:** Anthropic API (quality; Opus-class for the writer, Haiku-class for scoring) and Ollama Llama 3.1 8B (offline/air-gapped — a hard product constraint). All agent code must work with both; never hardcode a provider or model string in an agent.
5. **RAG is one Chroma collection (`pentest_knowledge`)** with `vuln_class` metadata filtering, embeddings via local `all-MiniLM-L6-v2` (no Ollama dependency for embeddings). Empty store falls back to static context in `rag/retriever.py` — the pipeline must work with zero RAG setup.
6. **Evidence is sanitized before layout:** truncated to ~4KB at parse time, long lines hard-wrapped in `prepare_evidence()` before reaching templates. WeasyPrint pagination depends on this.
7. **Markdown and PDF render from the same context dict** (`report_sections` + scan metadata) through parallel Jinja2 templates. If PDF rendering fails, Markdown/HTML are still written — content is never lost to a layout error.
8. **No ORM, no Celery, no React.** stdlib sqlite3 + repository module; FastAPI BackgroundTasks; server-rendered HTML. Scope discipline is the point.

## Current Build Status

Update this section as weeks complete (see PROJECT_PLAN.md §9 for definitions of done):

- [x] Week 1 — skeleton, models, DB, nmap+Burp parsers + fixtures
- [x] Week 2 — sqlmap parser, graph shell, ingestion agent, CLI `run`
- [x] Week 3 — correlation + scoring agents, heuristics table, mocked-LLM tests
- [x] Week 4 — RAG ingest/retrieve, report writer, Markdown output
- [x] Week 5 — HTML/CSS templates, WeasyPrint PDF, FastAPI upload UI
- [x] Week 6 — e2e tests + evidence sanitization done; Ollama offline pass & README demo GIF pending

**Status note (addendum audit complete):** 253 tests passing at 86% coverage. Parser
support expanded to 8 tools: nmap, Burp, SQLMap, Nessus, ZAP, Nuclei, dirbrute
(ffuf/gobuster), WPScan. Multi-file support added (MULTI_FILE_TOOLS constant). All new
parsers are LLM-free, DB-free, use defusedxml for XML, and are covered by fixture-based
tests including XXE payloads, multi-host/multi-site, malformed inputs, and edge cases.
HEURISTICS table has 35 types with validated CVSS 3.1 vectors; all types have specific
static_context entries. Evidence sanitization (auth headers, API keys) verified for all
new parsers. Remaining: validate live Anthropic/Ollama LLM paths, run `ingest-kb`
against a real corpus, and confirm WeasyPrint PDF rendering with system libraries.

> Dev note: validated on Python 3.11 (.venv). `from __future__ import annotations` kept
> for compatibility but the project runs natively on 3.11+.

## Do Not Break (invariants)

1. **State contract:** agents return partial updates; never mutate fields owned by an upstream agent; `errors`/`warnings` are append-only (reducer-annotated). Adding a `ScanState` field requires updating `state.py` and this file.
2. **Pipeline always completes or fails explicitly.** Any single file, finding, or LLM call failing must degrade (warning + fallback), not crash the run. The only fatal path is zero parseable findings.
3. **Never trust LLM output unvalidated:** CVSS vectors go through `cvss.CVSS3`; chain `finding_ids` are filtered against real IDs; references are checked against the known-ID list; structured outputs use pydantic models with `Literal` fields where possible.
4. **`defusedxml` stays.** Do not "simplify" to `xml.etree.ElementTree` direct usage.
5. **Offline mode is a feature, not a fallback.** Changes must not introduce hard network dependencies at runtime (embeddings model and knowledge base are fetched once at setup; cloud LLM is optional).
6. **Evidence hygiene:** stored/rendered evidence is truncated and (Week 6+) stripped of auth headers/cookies. Never log or persist full credentials from tool output.
7. **Parsers are LLM-free and fixture-tested.** New parser behavior requires a fixture file in `tests/fixtures/` reproducing it, including a malformed variant.
8. **Don't add input formats, output formats, or UI surfaces to MVP** — that's the v1.1 cut line (PROJECT_PLAN.md §10).

## Conventions

- Python 3.11+, pydantic v2, type hints everywhere; `pytest` for everything; mock LLMs in tests (no live API calls in CI).
- Run tests: `pytest`. Run pipeline: `rednarrate run data/samples --client "Demo Corp"`. Build KB: `rednarrate ingest-kb`. Web UI: `rednarrate serve`.
- Secrets only via `.env` (`ANTHROPIC_API_KEY`, `REDNARRATE_LLM_PROVIDER`); never committed.
