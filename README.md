# RedNarrate

AI-powered pentest evidence triage and VAPT report generation. Point it at a folder of raw tool outputs (nmap XML, Burp issue XML, SQLMap logs) and get back a complete, client-ready report (PDF + Markdown).

```
Ingestion → Correlation → CVSS Scoring → Report Writer → Report
```

A LangGraph pipeline parses each tool's output into normalized findings, deduplicates and correlates them across tools, assigns library-validated CVSS 3.1 scores, and writes professional report prose with RAG over OWASP WSTG / PTES / curated remediation content.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env        # then add your ANTHROPIC_API_KEY
```

WeasyPrint needs system libraries (pango, cairo, gdk-pixbuf). On macOS: `brew install pango`. On Debian/Ubuntu: `apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0`.

## Try it in 60 seconds (no API key)

```bash
rednarrate run data/samples --client "Demo Corp" --provider none
```

`--provider none` skips every LLM call and uses deterministic heuristics + templates, so it runs with no `ANTHROPIC_API_KEY` and no Ollama. You get a correct, severity-sorted report (with a cross-tool Burp+SQLMap SQLi merge and CVSS scores) in `output/<scan_id>/`. Add a real provider later for narrative prose.

## Use

```bash
# Build the RAG knowledge base (once; optional — pipeline falls back to static context)
./scripts/fetch_knowledge.sh
rednarrate ingest-kb

# Run the pipeline on a folder of evidence
rednarrate run data/samples --client "Acme Corp" --scope "External web app" \
    --dates "2026-06-01 to 2026-06-05"

# List past scans
rednarrate list-scans

# Web UI (upload → status → download)
rednarrate serve            # http://localhost:8000
```

Reports land in `output/<scan_id>/report.pdf` and `report.md`.

## Offline / air-gapped

Set `REDNARRATE_LLM_PROVIDER=ollama` in `.env` and run `ollama pull llama3.1:8b`. Embeddings (`all-MiniLM-L6-v2`) are downloaded once at first use and cached locally; after that, no network is required.

## Develop

```bash
pytest
```

See `PROJECT_PLAN.md` for the full design and `CLAUDE.md` for architecture invariants.
