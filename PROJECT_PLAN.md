# RedNarrate — Implementation-Ready Project Plan

**Version:** 1.0 · **Date:** 2026-06-11 · **Target:** Working MVP in 6 weeks, solo developer

AI-powered pentest evidence triage and report generation. Ingests raw nmap XML / Burp XML / SQLMap logs → LangGraph pipeline (Ingest → Correlate → Score → Write) → client-ready VAPT report (PDF + Markdown).

---

## 1. Final Tech Stack

> **Version pinning policy:** Install the packages below, verify the smoke test passes, then `pip freeze > requirements.lock` and pin exact versions. The table gives the compatibility constraint to put in `pyproject.toml`; the lock file is what you actually install from. This avoids both stale pins and surprise breakage mid-project.

| Component | Package | Pin | Purpose | Why this over alternatives |
|---|---|---|---|---|
| Agent framework | `langgraph` | `~=` minor at install | 4-node sequential pipeline with shared state, conditional error routing, SQLite checkpointing | CrewAI/AutoGen are conversation-oriented; LangGraph's typed-state DAG is exactly the shape of this pipeline and you already know it |
| LLM glue | `langchain-core` | match langgraph's requirement | Prompt templates, `with_structured_output`, runnables | Already implied by langgraph; don't add `langchain` (the meta-package) — you don't need chains/agents from it |
| LLM (cloud) | `langchain-anthropic` + `anthropic` | latest | Claude API backend | Best instruction-following for report prose. **Models:** `claude-opus-4-8` ($5/$25 per MTok) for Report Writer narrative quality; `claude-haiku-4-5` ($1/$5) for the per-finding CVSS scoring loop where volume is high and the task is constrained. Both support structured outputs. A full 20-finding report costs roughly $0.15–0.50 — within a $0-infra budget using free API credits or a few dollars |
| LLM (local/offline) | `langchain-ollama` + Ollama daemon + `llama3.1:8b` | latest | Air-gapped operation after setup | Free, runs on a laptop, good enough for scoring; report prose will be noticeably worse — that's the accepted offline tradeoff |
| nmap parser | `python-libnmap` | `~=0.7` | Parse nmap `-oX` output incl. partial/truncated scans | Handles missing `</nmaprun>`, extraports, multi-address hosts that hand-rolled ElementTree code gets wrong |
| Burp parser | stdlib `xml.etree.ElementTree` **via** `defusedxml` | `defusedxml~=0.7` | Parse Burp issue XML | Structure is flat and simple; no dependency needed beyond **defusedxml — non-negotiable: you are parsing attacker-adjacent XML, and stock ElementTree is vulnerable to entity-expansion (billion-laughs) and related attacks** |
| SQLMap parser | custom regex (stdlib `re`) | — | Parse console log | SQLMap has no structured output; regex over the log is the only portable option (session.sqlite parsing is v1.1) |
| CVSS | `cvss` (RedHatProductSecurity) | `~=3.x` | Validate vector strings, compute scores | Most maintained; CVSS 3.1 + severity bands; the LLM proposes metrics, this library is the source of truth for the number |
| Vector store | `chromadb` + `langchain-chroma` | `~=0.5` / latest | Persistent local RAG store | Zero-server, file-backed, you used it in PatchWeave. FAISS lacks metadata filtering; Qdrant needs a server |
| Embeddings | `sentence-transformers` (`all-MiniLM-L6-v2`) | `~=3.x` | Local embeddings for RAG | Fully offline with no daemon dependency (Ollama `nomic-embed-text` is the alternative, but it couples RAG to a running Ollama process — keep embeddings independent so cloud-LLM mode doesn't need Ollama at all) |
| PDF | `weasyprint` | `~=62` | HTML/CSS → PDF | Pure Python, real CSS paged-media support (`@page`, headers/footers, page breaks). ReportLab is canvas-level overkill; Playwright drags in Chromium |
| Templates | `jinja2` | `~=3.1` | HTML + Markdown report templates | One data model, two render targets; industry standard |
| Database | stdlib `sqlite3` | — | Scans/findings/chains/reports persistence | Zero-config, single file, portable to air-gapped boxes. No ORM — the schema is 4 tables; SQLAlchemy is ceremony you don't have time for |
| Web framework | `fastapi` + `uvicorn` + `python-multipart` + `jinja2` | `~=0.115` / latest | Upload UI + job status + download | You know it; `python-multipart` required for file uploads; server-rendered HTML, no React |
| CLI | `typer` + `rich` | `~=0.12` / `~=13` | `rednarrate run ./evidence/` | Typer = type-hint-driven CLI in 30 lines; rich gives progress bars/tables pentesters expect in a terminal |
| Validation | `pydantic` | v2 (`~=2.x`) | Finding model, LLM structured outputs, API schemas | One model class serves parser output, LLM output validation, and FastAPI |
| Config | `python-dotenv` | `~=1.0` | `.env` for API keys / provider switch | Standard |
| Testing | `pytest` + `pytest-cov` | `~=8.x` | Parser unit tests against fixture files | Default choice; fixture-file pattern fits parser testing perfectly |

**Explicit non-choices:** no Celery/Redis (FastAPI `BackgroundTasks` is enough for one user), no Docker requirement for MVP (it's a `pip install` Python app; `docker-compose.yml` is provided but optional), no Postgres, no React.

---

## 2. Complete Directory & File Structure

```
RedNarrate/
├── CLAUDE.md                        # Claude Code session context (deliverable 12)
├── PROJECT_PLAN.md                  # this file
├── README.md
├── pyproject.toml                   # package metadata + deps (constraints)
├── requirements.lock                # pip freeze output — exact pins
├── .env.example
├── .gitignore                       # chroma_db/, *.db, output/, .env
├── docker-compose.yml               # optional: app + ollama services
│
├── data/
│   └── samples/                     # demo inputs (checked in)
│       ├── nmap_scanme.xml
│       ├── burp_juiceshop.xml
│       └── sqlmap_dvwa.log
│
├── knowledge/                       # RAG source corpus (downloaded by script)
│   ├── wstg/                        # OWASP WSTG markdown (git sparse clone)
│   ├── ptes/                        # PTES reporting/technical pages (scraped md)
│   ├── remediation/                 # hand-curated remediation snippets (md)
│   └── sample_reports/              # extracted findings text from public reports
│
├── src/rednarrate/
│   ├── __init__.py
│   ├── config.py                    # Settings (pydantic-settings or dataclass over env)
│   ├── state.py                     # ScanState TypedDict + Finding pydantic model
│   ├── graph.py                     # StateGraph wiring, conditional edges, checkpointer
│   ├── llm.py                       # get_llm(role) factory: anthropic|ollama per role
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── ingestion.py             # ingestion_node(state) -> state
│   │   ├── correlation.py           # correlation_node(state) -> state
│   │   ├── scoring.py               # cvss_scoring_node(state) -> state
│   │   └── report_writer.py         # report_writer_node(state) -> state
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base.py                  # detect_tool(path) -> str; ParserError
│   │   ├── nmap_parser.py           # parse_nmap(path) -> list[Finding]
│   │   ├── burp_parser.py           # parse_burp(path) -> list[Finding]
│   │   └── sqlmap_parser.py         # parse_sqlmap(path) -> list[Finding]
│   │
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── heuristics.py            # finding_type -> default CVSS vector table (LLM fallback)
│   │
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── ingest.py                # build_knowledge_base(): chunk + embed + persist
│   │   └── retriever.py             # get_context(finding) -> str (with cold-start fallback)
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── schema.sql               # full DDL (section 6)
│   │   └── repository.py            # init_db, save_scan, save_findings, save_report, queries
│   │
│   ├── report/
│   │   ├── __init__.py
│   │   └── renderer.py              # render_html, render_pdf, render_markdown
│   │
│   ├── templates/
│   │   ├── report.html.j2           # master HTML template
│   │   ├── report.md.j2             # parallel Markdown template
│   │   ├── styles.css               # paged-media CSS
│   │   └── partials/
│   │       ├── cover.html.j2
│   │       ├── exec_summary.html.j2
│   │       ├── findings_table.html.j2
│   │       ├── finding_detail.html.j2
│   │       ├── attack_chains.html.j2
│   │       └── roadmap.html.j2
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py                  # typer app: run / ingest-kb / serve / list-scans
│   │
│   └── api/
│       ├── __init__.py
│       ├── app.py                   # FastAPI factory, mounts static, includes routes
│       ├── routes.py                # POST /scans (upload), GET /scans/{id}, GET /scans/{id}/report
│       ├── templates/               # web UI (server-rendered)
│       │   ├── index.html
│       │   └── scan_status.html
│       └── static/
│           └── ui.css
│
├── scripts/
│   └── fetch_knowledge.sh           # downloads WSTG/PTES/sample reports into knowledge/
│
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── nmap_full.xml            # complete scan
    │   ├── nmap_truncated.xml       # missing </nmaprun>
    │   ├── nmap_empty_host.xml
    │   ├── burp_full.xml
    │   ├── burp_no_b64.xml          # requests not base64-encoded
    │   ├── burp_malformed.xml
    │   ├── sqlmap_injectable.log
    │   └── sqlmap_clean.log         # no injection found
    ├── test_nmap_parser.py
    ├── test_burp_parser.py
    ├── test_sqlmap_parser.py
    ├── test_correlation.py          # dedup + chain detection, no LLM needed
    ├── test_scoring.py              # vector validation + heuristic fallback (mock LLM)
    ├── test_renderer.py             # template renders without error on fixture findings
    └── test_pipeline_e2e.py         # full graph on samples/ with mocked LLM
```

Entry points (in `pyproject.toml`): `rednarrate = rednarrate.cli.main:app`.

---

## 3. Agent Specs

All four agents are LangGraph nodes with signature `def node(state: ScanState) -> dict` (return partial state updates — LangGraph merges them). Errors append to `state["errors"]` / `state["warnings"]`; a node never raises out of the graph.

### 3.1 Ingestion Agent (`agents/ingestion.py`)

**Responsibility:** Turn raw tool-output files into a normalized `list[Finding]` plus a host inventory. **Does NOT:** dedupe across tools, assign severity beyond what the tool reported, call any LLM.

**Reads:** `raw_inputs` (dict of `{tool_name: file_path}` — or a directory the CLI pre-expanded via `parsers.base.detect_tool`).
**Writes:** `parsed_findings`, `hosts`, `warnings`, `errors`, `current_step`.

**Logic:**
1. For each `(tool, path)` in `raw_inputs`: dispatch to `parse_nmap` / `parse_burp` / `parse_sqlmap`.
2. Each parser returns `list[Finding]` (schema in section 5). Catch `ParserError` per file — one bad file must not kill the run; record a warning and continue.
3. Build `hosts`: `{ip: {hostname, os, open_ports: [{port, proto, service, version}]}}` from nmap data (Burp/SQLMap hosts merged in by URL host).
4. Assign provisional sequential IDs (`RAW-001…`) and compute each finding's `dedup_key` (section 5).
5. If **zero** findings parsed from **all** files → push to `errors` (graph routes to END with a failure report).

**LLM:** No. Pure deterministic parsing — keeping the ingestion layer LLM-free makes it testable and trustworthy.

**Failure modes:**
| Mode | Handling |
|---|---|
| File unreadable / wrong format | `ParserError` → warning, skip file |
| Truncated nmap XML | libnmap `incomplete=True` parse; warn "partial scan" |
| Burp XML with XXE payload (it's attacker-adjacent data) | `defusedxml` raises → warning, skip file |
| Huge evidence blobs (full HTTP responses) | Truncate stored evidence to 4 KB per finding at parse time, keep a `evidence_truncated` flag |

**Token cost:** 0.

### 3.2 Correlation Agent (`agents/correlation.py`)

**Responsibility:** Deduplicate findings across tools, group findings per host, detect attack chains. **Does NOT:** score, write prose for the report body (chain *narratives* are the one LLM output here).

**Reads:** `parsed_findings`, `hosts`.
**Writes:** `correlated_findings` (deduped, enriched), `attack_chains`, `warnings`, `current_step`.

**Logic:**
1. **Deterministic dedup (no LLM):** bucket by `dedup_key` = `(host, port, finding_type, normalized_location)`. When nmap "port 80 open / http" and Burp "SQL injection at host:80/login" share a host:port, they are *not* merged — different `finding_type` — but get a shared `host_port_ref` so the report can say "see also".
   - Same-type collisions (e.g. Burp reports SQLi on `/login?user` twice with different payloads) → merge: keep highest confidence, concatenate evidence (capped), record `instances: n`.
2. **Cross-tool enrichment:** SQLMap SQLi finding on a URL that Burp also flagged as SQLi → merge into one finding with `source_tool: "burp+sqlmap"`, evidence from both. This is the headline demo moment — one finding, two tools' evidence.
3. **Rule-based chain candidates (no LLM):** apply a small rule table, e.g.:
   - open service (nmap) → web vuln (Burp) on same host:port ⇒ "exposure → exploitation" chain
   - SQLi (any tool) + credential/table dump (SQLMap dump artifacts) ⇒ "injection → data exfiltration" chain
   - default-cred / auth-bypass finding + any post-auth finding on same host ⇒ chain
4. **LLM pass (one call):** send the compact finding summary list (id, type, host, port, one-line desc — *not* evidence) and the rule-detected candidates; ask the LLM to (a) confirm/reject candidates, (b) propose missed chains **only using provided finding IDs**, (c) write a 2-3 sentence combined-impact narrative per chain. Structured output: `list[AttackChain]` (pydantic).
5. Validate LLM output: every `finding_id` it references must exist; drop hallucinated IDs with a warning. Rule-detected chains survive even if the LLM call fails.

**LLM:** Yes — one call. Prompt skeleton:

```
SYSTEM: You are a senior penetration tester analyzing correlated findings.
Only reference finding IDs that appear in the input. Do not invent findings.

USER:
<hosts>{host inventory}</hosts>
<findings>{id | type | host:port | name — one line each}</findings>
<candidate_chains>{rule-detected chains}</candidate_chains>

Confirm or reject each candidate chain. Identify any additional chains where
one finding materially enables another. For each chain output: name,
ordered finding_ids, combined_impact (2-3 sentences, business language).
```

**Failure modes:** LLM timeout/refusal → keep rule-based chains, warn. LLM hallucinates IDs → filtered in step 5. Zero chains → fine; report omits the section.

**Token cost:** ~1.5–3K input + ~500 output. On Haiku 4.5: ~$0.005/run. Negligible.

### 3.3 CVSS Scoring Agent (`agents/scoring.py`)

**Responsibility:** Assign each correlated finding a CVSS 3.1 vector, score, and severity band. **Does NOT:** write report prose, re-correlate.

**Reads:** `correlated_findings`.
**Writes:** `scored_findings` (sorted by score desc), `warnings`, `current_step`.

**Logic (per finding):**
1. **Tool-given shortcut:** if Burp severity is `Information` → score 0.0/Info immediately, skip LLM (saves ~40% of calls on real Burp exports).
2. **Heuristic prior:** look up `finding_type` in `scoring/heuristics.py` (table of ~25 common types → default vector, e.g. `sqli → AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). This is both the LLM's anchor and the fallback.
3. **LLM call (structured output, Haiku-class model):** give finding name/type/evidence-snippet + heuristic prior; ask for the 8 base metrics **as enum fields** plus a one-line justification per metric that deviates from the prior. Pydantic model with `Literal` types per metric makes invalid letters impossible.
4. **Validate & compute:** assemble vector string → `cvss.CVSS3(vector)`. The *library* computes the score and severity — never trust an LLM-stated number.
5. **Retry once** on validation error with the error message appended; on second failure use the heuristic vector and warn.
6. Sort findings Critical→Info; assign final IDs `VAPT-<YYYY>-NNN` in severity order.

**LLM:** Yes — one call per non-Info finding. Prompt skeleton:

```
SYSTEM: You assign CVSS 3.1 base metrics. Output only the structured object.
Anchor on the provided default vector; deviate only when the evidence
justifies it (e.g. authentication required → PR:L, local-only service → AV:L).

USER:
Finding: {name} ({finding_type})
Asset: {host}:{port} {url} {parameter}
Tool severity/confidence: {severity_raw}/{confidence}
Evidence (excerpt): {evidence[:1500]}
Default vector for this class: {heuristic_vector}
```

**Failure modes:** invalid metric combo → retry-then-fallback (step 5); LLM degrades a Critical absurdly (e.g. RCE scored 2.1) → sanity rule: if |llm_score − heuristic_score| > 3.0, flag `score_disputed: true` and keep both in the DB for human review; rate limits → SDK auto-retry, then fallback.

**Token cost:** ~700 in / ~250 out per finding. 20 findings ≈ 14K/5K tokens ≈ **$0.04 on Haiku 4.5**, ~$0.19 on Opus 4.8. Use Haiku here.

### 3.4 Report Writer Agent (`agents/report_writer.py`)

**Responsibility:** Produce all report *content* (exec summary, per-finding narratives, remediation, roadmap buckets) as structured data, then call the renderer for PDF + MD. **Does NOT:** change scores or severities, re-order findings, do layout (renderer's job).

**Reads:** `scored_findings`, `attack_chains`, `hosts`, scan metadata (`client_name`, `scope`, dates).
**Writes:** `report_sections`, `report_paths`, `errors`, `current_step`.

**Logic:**
1. **Per-finding narrative (one LLM call each, RAG-augmented):**
   - `rag.retriever.get_context(finding)` → top-3 chunks (filtered by `vuln_class` metadata when it matches, see section 7).
   - LLM produces structured `FindingNarrative`: `description` (2-3 sentences, instance-specific), `business_impact` (1-2 sentences), `remediation_steps` (3-5 bullets, specific to the evidence — "parameterize the `username` parameter in /login", not "use prepared statements" alone), `references` (CWE/OWASP — validated against a known-ID list, hallucinated CVEs dropped).
2. **Exec summary (one call):** input = findings table summary + chains + overall stats; output = engagement overview para, overall risk rating (computed deterministically from severity counts, LLM just words it), 3-5 key-findings bullets in business language, immediate actions.
3. **Roadmap (no LLM):** deterministic bucketing — Critical/High → 0-7 days, Medium → 30 days, Low/Info → quarter. Remediation lines reuse step-1 output.
4. Assemble `report_sections`, call `report.renderer` → write `output/<scan_id>/report.pdf` + `report.md`, save rows to `reports` table.
5. If PDF rendering throws (WeasyPrint env issue), still write Markdown + HTML and warn — never lose the content because of layout.

**LLM:** Yes — N+1 calls. Per-finding prompt skeleton:

```
SYSTEM: You write findings for professional penetration test reports
(PTES/OWASP style). Be specific to the evidence given. Never invent
endpoints, parameters, or CVEs not present in the input or context.

USER:
<finding>{name, type, severity, cvss_vector, asset, parameter, evidence excerpt}</finding>
<reference_context>{RAG chunks}</reference_context>
Write: description, business_impact, remediation_steps[], references[].
```

**Failure modes:** one finding's call fails → template-based fallback text from the heuristics table ("A {type} issue was identified on {asset}…"), warn, continue — the report always completes; RAG store empty → static fallback context (section 7); LLM echoes RAG content verbatim including template placeholders → post-check for `{{`/`[CLIENT]` artifacts.

**Token cost (the expensive node):** per finding ~1.8K in (incl. RAG) / ~450 out; exec summary ~2.5K/700. 20 findings on **Opus 4.8** ≈ 39K in / 10K out ≈ **$0.45**. On Haiku: ~$0.09 but flatter prose. Recommended split: Opus 4.8 (or Sonnet 4.6) for the writer, Haiku for scoring — total ≈ **$0.50 per full report**. Local Llama 3.1 8B: $0, lower quality, acceptable for demos.

---

## 4. ScanState Schema (`state.py`)

This is the contract between all agents. `Finding` is a pydantic model (section 5); in state it travels as `dict` (`model_dump()`) so the state stays JSON-serializable for the SQLite checkpointer.

```python
from typing import TypedDict, Optional
from typing_extensions import Annotated
import operator

class ScanState(TypedDict):
    # ── scan metadata (set by CLI/API before invoke) ───────────────────
    scan_id: str                # uuid4 hex; thread_id for checkpointing
    client_name: str            # cover page / exec summary
    scope: str                  # free-text tested-scope description
    engagement_dates: str       # "2026-06-01 to 2026-06-05"
    llm_provider: str           # "anthropic" | "ollama" — read by llm.get_llm()

    # ── inputs ─────────────────────────────────────────────────────────
    raw_inputs: dict[str, str]  # {"nmap": "/path/scan.xml", "burp": ..., "sqlmap": ...}

    # ── ingestion output ───────────────────────────────────────────────
    parsed_findings: list[dict]     # Finding dicts, provisional RAW-### ids
    hosts: dict[str, dict]          # {ip: {hostname, os, open_ports: [...]}}

    # ── correlation output ─────────────────────────────────────────────
    correlated_findings: list[dict] # deduped/merged Findings (instances, host_port_ref set)
    attack_chains: list[dict]       # {id, name, finding_ids[], combined_impact}

    # ── scoring output ─────────────────────────────────────────────────
    scored_findings: list[dict]     # + cvss_vector, cvss_score, severity,
                                    #   final VAPT-YYYY-NNN ids, severity-sorted

    # ── report writer output ───────────────────────────────────────────
    report_sections: dict           # {exec_summary: {...}, findings: [FindingNarrative...],
                                    #  roadmap: {...}, methodology: {...}}
    report_paths: dict[str, str]    # {"pdf": ..., "md": ..., "html": ...}

    # ── bookkeeping (append-only via reducers) ─────────────────────────
    errors: Annotated[list[str], operator.add]    # fatal: graph routes to END
    warnings: Annotated[list[str], operator.add]  # non-fatal: printed + appendix
    current_step: str               # "ingest"|"correlate"|"score"|"write"|"done"|"failed"
```

Invariants: agents only **add** their own fields and never mutate upstream fields; `errors` non-empty after a node ⇒ conditional edge to END; every list field defaults to `[]` in the initial state built by the CLI.

---

## 5. Parsing Strategy Per Tool

### The normalized `Finding` model (pydantic, in `state.py`)

```python
class Finding(BaseModel):
    id: str                      # RAW-### then VAPT-YYYY-NNN after scoring
    source_tool: str             # "nmap" | "burp" | "sqlmap" | "burp+sqlmap"
    host: str                    # IP or hostname
    port: Optional[int] = None
    protocol: str = "tcp"
    service: Optional[str] = None        # "http", "ssh OpenSSH 5.3p1"
    url: Optional[str] = None            # web findings
    parameter: Optional[str] = None      # injectable/affected param
    finding_type: str            # normalized: "sqli","xss-reflected","open-port",
                                 # "outdated-software","info-disclosure",... (enum-ish str)
    name: str                    # human title
    severity_raw: Optional[str] = None   # tool-reported (Burp High/Medium/...)
    confidence: Optional[str] = None     # Burp Certain/Firm/Tentative; nmap conf 1-10 as str
    description_raw: str = ""    # tool-provided description (issueBackground etc.)
    evidence: str = ""           # decoded request/response excerpt, NSE output, log lines (≤4KB)
    evidence_truncated: bool = False
    references: list[str] = []   # CWE/CVE/OWASP ids found in tool output (CPE-derived for nmap)
    instances: int = 1           # merged duplicate count
    host_port_ref: Optional[str] = None  # link key to related service finding
    dedup_key: str = ""          # f"{host}:{port}:{finding_type}:{norm_location}"
```

`norm_location` = URL path lowercased, query stripped, trailing slash stripped + parameter name — so `/login?u=a` and `/login?u=b` collide (same finding), `/login` vs `/admin` don't.

### 5.1 nmap — `parse_nmap(path: str | Path) -> list[Finding]`

```python
def parse_nmap(path: Path) -> list[Finding]: ...
```

1. `NmapParser.parse_fromfile(path)`; on `NmapParserException`, retry `NmapParser.parse_fromstring(data, incomplete=True)` for truncated scans; if both fail → `ParserError`.
2. For each up host: collect IPv4 (`host.address`), hostnames, best OS match (`host.os_match_probabilities()`, keep accuracy ≥ 85).
3. For each **open** service: emit one `open-port` Finding (`severity_raw=None` — scoring decides; most land Info/Low). Capture `service.banner` into `service`, CPEs into `references`.
4. NSE scripts: for each `script` result on a port, if script id ∈ vuln-relevant set (`vuln*`, `*-vuln-*`, `ssl-*`, `http-default-accounts`, `smb-os-discovery`…) emit a separate Finding with `finding_type` mapped from script id (fallback `nse-{script_id}`), full script output (≤4KB) as evidence.
5. Build the host inventory dict as a side product (returned via a second function `extract_hosts(report)` or attached by the agent).

Edge cases: hosts with MAC+IPv4 → take IPv4; `extraports` ignored (not individually listed); zero up hosts → return `[]` with warning, not an error.

**Sample in → out (abbreviated):**
```xml
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="5.3p1"><cpe>cpe:/a:openbsd:openssh:5.3p1</cpe></service></port>
```
```python
Finding(id="RAW-001", source_tool="nmap", host="74.207.244.221", port=22,
        service="ssh OpenSSH 5.3p1", finding_type="open-port",
        name="Open SSH service (OpenSSH 5.3p1)",
        evidence="22/tcp open ssh OpenSSH 5.3p1 (protocol 2.0)",
        references=["cpe:/a:openbsd:openssh:5.3p1"],
        dedup_key="74.207.244.221:22:open-port:")
```

### 5.2 Burp — `parse_burp(path: str | Path) -> list[Finding]`

```python
def parse_burp(path: Path) -> list[Finding]: ...
```

1. `defusedxml.ElementTree.parse(path)` (XXE-safe). Root must be `<issues>` else `ParserError`.
2. Per `<issue>`: `name`, `type` (int), `severity`, `confidence`, `path`, `location` (extract parameter via regex `Parameter:\s*(\S+)` when present), `issueDetail`, `issueBackground`.
3. Host: `<host>` element — `ip` attribute for `host`, element text (URL) for scheme/hostname; `url = host_url + path`; port from URL scheme (443/80) or explicit `:port`.
4. Request/response: first `<requestresponse>`; if `base64="true"` → `base64.b64decode(...).decode("utf-8", errors="replace")`; else use raw text. Evidence = first 2KB of request + first 2KB of response.
5. `finding_type`: map Burp `type` int via a small dict (2097920→`sqli`, 2097408→`xss-reflected`, 5243392→`info-disclosure`, …); fallback: slugified `name`.
6. Skip nothing by severity — `Information` issues are kept (scoring shortcut handles them).

Malformed handling: missing `<requestresponses>` → evidence from `issueDetail` only; undecodable base64 → keep raw with warning flag in evidence header; per-issue try/except so one broken issue doesn't kill the export.

**Sample in → out:**
```xml
<issue><name>SQL injection</name><host ip="10.0.0.5">https://target.com</host>
<path>/login</path><location>Parameter: username</location>
<severity>High</severity><confidence>Certain</confidence>...</issue>
```
```python
Finding(id="RAW-007", source_tool="burp", host="10.0.0.5", port=443,
        url="https://target.com/login", parameter="username",
        finding_type="sqli", name="SQL injection",
        severity_raw="High", confidence="Certain",
        evidence="POST /login HTTP/1.1\nHost: target.com\nusername=' OR 1=1--...",
        dedup_key="10.0.0.5:443:sqli:/login|username")
```

### 5.3 SQLMap — `parse_sqlmap(path: str | Path) -> list[Finding]`

```python
def parse_sqlmap(path: Path) -> list[Finding]: ...
```

Regex set (module constants, each with a unit test):
```python
TARGET_RE    = re.compile(r"(?:starting|testing) (?:URL|connection to) ['\"]?(\S+?)['\"]?$", re.M)
URL_OPT_RE   = re.compile(r"-u\s+['\"]?(https?://\S+?)['\"]?(?:\s|$)")   # from echoed cmdline
INJECTION_RE = re.compile(r"(GET|POST|Cookie|URI) parameter '(.+?)' is '(.+?)' injectable")
DBMS_RE      = re.compile(r"back-end DBMS:\s*(.+)")
DB_RE        = re.compile(r"fetching tables for database:?\s*'(.+?)'")
DUMP_RE      = re.compile(r"table '(.+?)' dumped to CSV file '(.+?)'")
CRED_HINT_RE = re.compile(r"(password|passwd|hash)", re.I)
```

1. Read the log line-by-line (logs can be large; never `read()` whole file unbounded — cap at 10 MB with warning).
2. Establish target URL/host from `TARGET_RE`/`URL_OPT_RE` (first match wins). No target found → `ParserError` ("not a sqlmap log?").
3. Each `INJECTION_RE` match → one `sqli` Finding per (method, parameter); multiple techniques on the same parameter merge into one Finding with techniques listed in evidence.
4. Enrich the finding(s): DBMS string, databases enumerated, tables dumped (and flag `data-exfiltrated` in evidence if `DUMP_RE` hits; severity implications picked up by scoring via evidence text).
5. Evidence = the matched lines ± 1 line of context, joined (≤4KB).
6. Clean log (CRITICAL "not injectable", no matches) → `[]`, no error — a clean run is a valid result.

**Sample in → out:**
```
[10:24:30] [INFO] GET parameter 'id' is 'AND boolean-based blind' injectable
[10:24:40] [INFO] back-end DBMS: MySQL >= 5.0
```
```python
Finding(id="RAW-012", source_tool="sqlmap", host="testphp.vulnweb.com", port=80,
        url="http://testphp.vulnweb.com/artists.php", parameter="id",
        finding_type="sqli", name="SQL injection (boolean-based blind) — GET 'id'",
        evidence="[10:24:30] [INFO] GET parameter 'id' is 'AND boolean-based blind' injectable\n[10:24:40] [INFO] back-end DBMS: MySQL >= 5.0",
        dedup_key="testphp.vulnweb.com:80:sqli:/artists.php|id")
```

Note how the Burp and SQLMap examples produce **identical dedup_key shape** — that's what makes cross-tool merge in the Correlation agent a dict lookup, not an AI problem.

---

## 6. Database Schema (`db/schema.sql`)

Relationships: one **scan** → many **findings**; one scan → many **attack_chains**, each referencing an ordered list of finding IDs (JSON array — a join table is overkill for read-only chains at this scale); one scan → many **reports** (re-renders create new rows, old files kept).

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,            -- uuid4 hex
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_name     TEXT NOT NULL,
    scope           TEXT,
    engagement_dates TEXT,
    nmap_file       TEXT,                        -- original input paths (nullable each)
    burp_file       TEXT,
    sqlmap_file     TEXT,
    llm_provider    TEXT NOT NULL DEFAULT 'anthropic',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','ingesting','correlating',
                                      'scoring','writing','complete','failed')),
    error_summary   TEXT                         -- populated when status='failed'
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT NOT NULL,               -- VAPT-2026-001
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_tool     TEXT NOT NULL,               -- nmap/burp/sqlmap/burp+sqlmap
    host            TEXT NOT NULL,
    port            INTEGER,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT,
    url             TEXT,
    parameter       TEXT,
    finding_type    TEXT NOT NULL,               -- sqli/xss-reflected/open-port/...
    name            TEXT NOT NULL,
    severity        TEXT CHECK (severity IN ('Critical','High','Medium','Low','Informational')),
    cvss_vector     TEXT,                        -- CVSS:3.1/AV:N/...
    cvss_score      REAL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    score_disputed  INTEGER NOT NULL DEFAULT 0,  -- LLM vs heuristic disagreed > 3.0
    confidence      TEXT,
    description     TEXT,                        -- LLM narrative
    business_impact TEXT,
    evidence        TEXT,                        -- truncated raw evidence
    remediation     TEXT,                        -- JSON array of step strings
    refs            TEXT,                        -- JSON array of CWE/OWASP/CVE ids
    instances       INTEGER NOT NULL DEFAULT 1,
    is_chain_member INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              TEXT PRIMARY KEY,            -- uuid4 hex
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    chain_name      TEXT NOT NULL,               -- "SQLi to credential exfiltration"
    finding_ids     TEXT NOT NULL,               -- JSON array, in attack order
    combined_impact TEXT,                        -- LLM narrative
    detected_by     TEXT NOT NULL DEFAULT 'rule' CHECK (detected_by IN ('rule','llm','rule+llm'))
);

CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,            -- uuid4 hex
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    format          TEXT NOT NULL CHECK (format IN ('pdf','md','html')),
    file_path       TEXT NOT NULL,
    finding_count   INTEGER NOT NULL,
    severity_counts TEXT,                        -- JSON {"Critical":1,"High":3,...}
    llm_model       TEXT                         -- model used for the writer, for provenance
);

-- Indexes: every access path the app actually has
CREATE INDEX IF NOT EXISTS idx_findings_scan        ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity    ON findings(scan_id, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_host        ON findings(scan_id, host, port);
CREATE INDEX IF NOT EXISTS idx_findings_type        ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_chains_scan          ON attack_chains(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan         ON reports(scan_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created        ON scans(created_at DESC);
```

`repository.py` exposes: `init_db()`, `create_scan()`, `update_scan_status()`, `save_findings(scan_id, findings)`, `save_chains()`, `save_report()`, `get_scan()`, `list_scans()`, `get_findings(scan_id)`. The graph writes to the DB at the END node (and on failure) — agents themselves stay DB-free so they're unit-testable.

---

## 7. RAG Setup

### Corpus & sources (`scripts/fetch_knowledge.sh`)

| Source | Get it | Into |
|---|---|---|
| OWASP WSTG v4.2 (markdown per test case) | `git clone --depth 1 https://github.com/OWASP/wstg.git` → copy `document/4-Web_Application_Security_Testing/` | `knowledge/wstg/` |
| PTES technical/reporting guidelines | `http://www.pentest-standard.org/index.php/Reporting` — save the Reporting + Technical Guidelines pages as markdown (manual once; site is static) | `knowledge/ptes/` |
| Public pentest reports (style exemplars) | `git clone --depth 1 https://github.com/juliocesarfort/public-pentesting-reports.git` — pick ~10 readable reports, extract findings sections to text (`pdftotext`) | `knowledge/sample_reports/` |
| CWE top-25 + OWASP Top 10 descriptions | `https://owasp.org/Top10/` pages + `https://cwe.mitre.org/data/definitions/<id>.html` for the ~30 CWEs your finding types map to — save as md | `knowledge/remediation/` |
| Hand-curated remediation snippets | You write ~25 short md files, one per `finding_type` (1-2 paragraphs each). **Do this — it's 3 hours of work and the single highest-leverage RAG content**, because it's exactly shaped like the retrieval query | `knowledge/remediation/` |

### Ingestion (`rag/ingest.py`) — run once via `rednarrate ingest-kb`

1. Walk `knowledge/`, load `.md`/`.txt`.
2. Split: `RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50, separators=["\n## ", "\n### ", "\n\n", "\n", " "])` (≈500 tokens; respects markdown headers).
3. Metadata per chunk: `{source: "wstg"|"ptes"|"remediation"|"sample_report", vuln_class: <finding_type or "general">, file: path, section: nearest heading}`. `vuln_class` is derived from the file/dir name (WSTG file names map cleanly: `05-Testing_for_SQL_Injection` → `sqli` via a mapping dict).
4. Embed with `HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")`, persist to `./chroma_db`.
5. **One collection**: `pentest_knowledge`. Multiple collections buy nothing here — metadata filtering does the partitioning, and one collection keeps ingest/query code trivial.

### Query strategy (`rag/retriever.py`)

```python
def get_context(finding: dict, k: int = 3) -> str:
    query = f"{finding['name']} {finding['finding_type']} description impact remediation"
    # Pass 1: prefer chunks tagged for this vuln class
    docs = store.similarity_search(query, k=k,
            filter={"vuln_class": finding["finding_type"]})
    if len(docs) < k:   # Pass 2: top up from the whole corpus
        docs += store.similarity_search(query, k=k - len(docs))
    return "\n---\n".join(d.page_content for d in docs)
```

Exec-summary call queries with `"executive summary penetration test overall risk language"` filtered to `source in (ptes, sample_report)` (Chroma `$in` filter).

### Embedding model justification

`all-MiniLM-L6-v2`: 80 MB, CPU-fast (~1ms/chunk query), fully offline once downloaded, well-known retrieval quality that's plenty for a few-thousand-chunk corpus of *thematically distinct* documents (SQLi docs vs XSS docs are easy to separate — you don't need a SOTA embedder). Cached in `~/.cache` at first run → air-gap requirement satisfied. Ollama `nomic-embed-text` is marginally better but couples RAG to the Ollama daemon; not worth it.

### Cold start / empty store fallback

`get_context()` wraps store access in try/except and checks `collection.count()`. If 0 (first run, or user never ran `ingest-kb`) → return `STATIC_CONTEXT.get(finding_type, GENERIC_CONTEXT)` from a dict in `rag/retriever.py` containing one solid paragraph per common finding type (seeded from your hand-curated remediation files — same content, compiled in). The pipeline must **never** fail because the vector store is empty; it just writes slightly more generic prose and logs a warning telling the user to run `rednarrate ingest-kb`.

---

## 8. Report Template Structure

### HTML (`templates/report.html.j2` + partials)

```
report.html.j2
├── <head> — inline styles.css (WeasyPrint reads it via <style> or link)
├── {% include "partials/cover.html.j2" %}
│     vars: client_name, report_title, report_date, classification ("CONFIDENTIAL"),
│           tester_name, version
├── TOC — generated <ul> from findings list (WeasyPrint resolves internal #anchors;
│         page numbers via target-counter() in CSS)
├── {% include "partials/exec_summary.html.j2" %}
│     vars: exec.overview, exec.overall_risk (+ severity class), exec.key_findings[],
│           exec.immediate_actions[], severity_counts (rendered as a colored bar table)
├── Scope & Methodology (inline section)
│     vars: scope, engagement_dates, methodology_standards[] (static list:
│           OWASP WSTG v4.2, PTES, NIST SP 800-115), tools_used[] (derived from
│           which inputs were present), exclusions
├── {% include "partials/findings_table.html.j2" %}
│     loop: findings → | id | name | severity badge | cvss_score | asset | status |
├── {% if attack_chains %}{% include "partials/attack_chains.html.j2" %}{% endif %}
│     loop: chains → name, ordered finding links, combined_impact, arrow diagram (pure CSS)
├── Detailed Findings
│     {% for f in findings %}{% include "partials/finding_detail.html.j2" %}{% endfor %}
│     vars per finding: id, name, severity, cvss_score, cvss_vector (monospace),
│           asset line (host:port / url / parameter), description, evidence (<pre>),
│           business_impact, remediation[] (ol), references[] (links), instances note
├── {% include "partials/roadmap.html.j2" %}
│     vars: roadmap.immediate[], roadmap.short_term[], roadmap.long_term[]
└── Appendices: input file manifest, warnings list, methodology detail, glossary
```

All template variables come from one dict: `render(meta=..., exec=..., findings=[...], chains=[...], roadmap=..., warnings=[...])` — the renderer accepts exactly `state["report_sections"]` plus scan metadata.

### CSS approach (`styles.css`)

```css
/* ── palette ───────────────────────────────────────────── */
:root {
  --critical:#7f1d1d; --high:#c2410c; --medium:#b45309;
  --low:#1d4ed8;     --info:#52525b;
  --ink:#1c1917; --muted:#57534e; --rule:#e7e5e4; --accent:#0f172a;
}
body { font-family: "Helvetica Neue", Arial, sans-serif; color: var(--ink);
       font-size: 10.5pt; line-height: 1.45; }
h1,h2 { font-weight: 700; color: var(--accent); }
code, pre, .cvss-vector { font-family: "Menlo","DejaVu Sans Mono",monospace; font-size: 8.5pt; }

.badge { display:inline-block; padding:2px 10px; border-radius:3px;
         color:#fff; font-weight:700; font-size:9pt; }
.badge.Critical{background:var(--critical)} .badge.High{background:var(--high)}
.badge.Medium{background:var(--medium)}     .badge.Low{background:var(--low)}
.badge.Informational{background:var(--info)}

/* ── paged media ───────────────────────────────────────── */
@page {
  size: A4; margin: 22mm 18mm 20mm 18mm;
  @top-left  { content: "RedNarrate — Penetration Test Report"; font-size:8pt; color:var(--muted); }
  @top-right { content: "CONFIDENTIAL"; font-size:8pt; color:var(--critical); }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size:8pt; }
}
@page cover { margin:0; @top-left{content:none} @top-right{content:none} @bottom-right{content:none} }
.cover { page: cover; }                     /* cover gets its own page context */

section.finding { page-break-inside: avoid; }   /* keep short findings whole */
section.finding.long { page-break-inside: auto; }  /* renderer adds .long when evidence > ~1.5KB */
h2 { page-break-after: avoid; }                 /* never orphan a heading */
.cover, .exec-summary, .findings-table { page-break-after: always; }
pre.evidence { white-space: pre-wrap; word-break: break-all;   /* raw HTTP wraps, never overflows */
               background:#fafaf9; border:1px solid var(--rule); padding:6pt; max-width:100%; }
table { width:100%; border-collapse:collapse; }
thead { display: table-header-group; }          /* repeat header row across page breaks */
tr { page-break-inside: avoid; }
```

Key WeasyPrint mechanics used: `@page` margin boxes for running header/footer with page counters; named page (`page: cover`) so the cover has no header/footer; `target-counter(attr(href), page)` in the TOC for real page numbers; `thead { display: table-header-group }` for the findings table spanning pages.

### Markdown (`report.md.j2`)

Parallel structure, same context dict — no separate data path:

```
# Penetration Test Report — {{ meta.client_name }}
> CONFIDENTIAL · {{ meta.report_date }} · v{{ meta.version }}

## Executive Summary          ← overview, **Overall Risk: {{ exec.overall_risk }}**, bullets
## Scope & Methodology
## Findings Summary           ← GFM table: | ID | Finding | Severity | CVSS | Asset |
## Attack Chains              ← {% if chains %} numbered, "F1 → F2 → F3" notation
## Detailed Findings          ← ### {{ f.id }} — {{ f.name }} [{{ f.severity }} | {{ f.cvss_score }}]
                                 fenced code block for evidence, bullet remediation
## Remediation Roadmap        ← three subsections by window
## Appendix
```

Markdown is the diff-able, git-trackable artifact; PDF is the client deliverable; HTML (the pre-WeasyPrint render) is kept too — it's free and useful for the web UI preview.

---

## 9. Week-by-Week 6-Week Build Plan

### Week 1 — Skeleton + Parsers (the foundation everything sits on)
- [ ] Repo init, `pyproject.toml`, package layout, `pytest` wired, `.env.example`, CLAUDE.md committed
- [ ] `Finding` + `ScanState` models; `db/schema.sql` + `repository.py` with init/save/get
- [ ] `parse_nmap` + `parse_burp` complete with fixtures (incl. truncated/malformed cases)
- [ ] Collect real fixture files: scanme.nmap.org scan, Burp Community export against OWASP Juice Shop, sqlmap run against DVWA/testphp.vulnweb.com
- **Demoable:** `pytest` green; a script prints normalized findings from real nmap+Burp files.
- **Done =** both parsers pass all fixture tests including malformed inputs; findings land in SQLite.

### Week 2 — SQLMap parser + LangGraph pipeline shell
- [ ] `parse_sqlmap` + fixtures
- [ ] `graph.py`: 4 nodes wired (correlation/scoring/writer as pass-through stubs), conditional error edges, SQLite checkpointer
- [ ] Ingestion agent complete (dispatch, host inventory, dedup_key computation)
- [ ] Typer CLI: `rednarrate run <dir> --client "Acme"` → runs graph → prints findings table via rich
- **Demoable:** drop 3 real files in a folder, one command, see a severity-less findings table in the terminal.
- **Done =** end-to-end graph executes on `data/samples/` without LLM, state checkpointed, scan row + findings in DB.

### Week 3 — Correlation + CVSS Scoring (the intelligence)
- [ ] `llm.py` provider factory (anthropic / ollama, per-role model selection)
- [ ] Correlation agent: deterministic dedup + cross-tool merge + rule-based chains; then the single LLM chain-confirmation call (structured output)
- [ ] `scoring/heuristics.py` table (~25 finding types → vectors)
- [ ] Scoring agent: heuristic → LLM structured metrics → `cvss` lib validation → retry → fallback; sanity-dispute flag
- [ ] Unit tests with mocked LLM for both agents
- **Demoable:** terminal table now shows merged Burp+SQLMap SQLi finding with CVSS 9.8 Critical, severity-sorted; chains printed.
- **Done =** scoring never crashes on LLM garbage (fallback proven by test); dedup merges the cross-tool SQLi in the sample set.

### Week 4 — RAG + Report Writer
- [ ] `fetch_knowledge.sh`; write the ~25 hand-curated remediation snippets
- [ ] `rag/ingest.py` + `retriever.py` incl. cold-start static fallback; `rednarrate ingest-kb`
- [ ] Report Writer agent: per-finding narrative calls, exec summary call, deterministic roadmap, reference validation
- [ ] Markdown template + renderer first (fast iteration, no layout fights)
- **Demoable:** full pipeline → complete professional **Markdown** report from real evidence.
- **Done =** report.md contains all sections; a finding call failing produces fallback text not a crash; RAG-less run still completes.

### Week 5 — PDF + Web UI
- [ ] `report.html.j2` + partials + `styles.css`; WeasyPrint rendering; fight pagination *this week, not week 6*
- [ ] FastAPI: upload form (multi-file), `BackgroundTasks` runs graph, status page polls scan status, download links for PDF/MD
- [ ] `rednarrate serve` command
- **Demoable:** browser: drag 3 files → wait → download a styled PDF with cover, badges, page numbers.
- **Done =** PDF renders correctly with 1 finding and with 40 findings (pagination stress fixture); web round-trip works.

### Week 6 — Hardening, offline mode, polish
- [ ] Ollama end-to-end pass; fix local-model prompt issues (smaller context, stricter output coaxing)
- [ ] `test_pipeline_e2e.py` with mocked LLM in CI; error-path tests (empty dir, all-malformed files)
- [ ] Evidence sanitization pass (strip auth headers/cookies from stored evidence — pentest data hygiene)
- [ ] README with demo GIF, sample report PDF committed, CLAUDE.md build-status updated
- [ ] Buffer: this week absorbs the inevitable Week-5 spillover
- **Demoable:** the placement demo — offline laptop, 90-second folder-to-PDF run.
- **Done =** both providers work; CI green; README lets a stranger run it in 5 minutes.

---

## 10. MVP vs v1.1 Cut Line

| Feature | MVP | v1.1 | Rationale |
|---|---|---|---|
| nmap XML / Burp XML / SQLMap log parsing | ✅ | | Core promise |
| Metasploit `db_export` XML parsing | | ✅ | 4th parser adds breadth, not depth |
| Nessus/.nessus, Nuclei JSON | | ✅ | Same |
| Cross-tool dedup + merge | ✅ | | The differentiator |
| Rule-based + LLM attack chains | ✅ | | Differentiator; rules make it reliable |
| LLM CVSS 3.1 + library validation | ✅ | | Core |
| CVSS 4.0 | | ✅ | 3.1 is still what clients expect |
| EPSS / KEV enrichment (needs internet) | | ✅ | Breaks the offline constraint |
| RAG over WSTG/PTES/curated snippets | ✅ | | Core to narrative quality |
| RAG over *user's own past reports* (style learning) | | ✅ | Needs corpus mgmt UX |
| PDF (WeasyPrint) + Markdown output | ✅ | | Core deliverable |
| DOCX output | | ✅ | Clients ask; python-docx is a separate layout battle |
| Customizable report branding/themes | | ✅ | One good default theme for MVP |
| CLI (`run`, `ingest-kb`, `serve`, `list-scans`) | ✅ | | Primary interface |
| FastAPI web UI (upload→status→download) | ✅ | | "optional web UI" is in the deliverable; keep it minimal |
| Auth/multi-user on web UI | | ✅ | Localhost single-user for MVP |
| Finding edit/override UI before render | | ✅ | Big UX surface; MVP = re-run or edit the MD |
| Cloud (Anthropic) + local (Ollama) LLM | ✅ | | Offline is a hard constraint |
| Screenshot/image evidence embedding | | ✅ | Layout + upload complexity |
| Multi-scan trend comparison ("fixed since last test") | | ✅ | Needs stable cross-scan finding identity |
| Docker compose | ✅ (file provided, untested path acceptable) | polish in v1.1 | Nice for demos, not load-bearing |
| LangGraph checkpoint resume (`--resume`) | ✅ (free with SqliteSaver) | richer resume UX in v1.1 | Cheap insurance for long LLM runs |

Ruthless rule applied: anything that adds a new *input format*, a new *output format*, or a new *UI surface* is v1.1. MVP = the pipeline, deep not wide.

---

## 11. The 3 Hardest Technical Problems

### Problem 1 — Cross-tool identity: when are two findings the same finding?

**Why hard:** nmap speaks in `ip:port:service`, Burp in `URL + parameter + issue-type int`, SQLMap in `URL + parameter + technique`. The same SQLi appears as Burp issue 2097920 at `https://target.com/login` (host ip 10.0.0.5) and as sqlmap "POST parameter 'username' is injectable" at `http://10.0.0.5/login`. Naive string matching fails on hostname-vs-IP, scheme/port defaults, trailing slashes, query strings, and parameter-name case. Over-merge and you hide findings (report integrity disaster); under-merge and the report lists the same vuln 3 times (looks amateur — the exact thing RedNarrate exists to avoid).

**Solution:** canonicalize *before* comparing; merge only on exact canonical equality; never let an LLM decide identity (it's non-deterministic and unauditable).

```python
def canonical_host(raw: str, hosts: dict) -> str:
    """Resolve hostname↔IP using the nmap-derived inventory; prefer IP."""
    if raw in hosts: return raw                       # already an IP we know
    for ip, h in hosts.items():
        if raw.lower() in (n.lower() for n in h["hostnames"]): return ip
    return raw.lower()                                # unknown — keep as-is

def canonical_location(url: str | None, parameter: str | None) -> str:
    if not url: return ""
    p = urlsplit(url)
    path = re.sub(r"/+$", "", p.path) or "/"
    return f"{path.lower()}|{(parameter or '').lower()}"

def dedup_key(f: Finding, hosts: dict) -> str:
    port = f.port or {"https": 443, "http": 80}.get(urlsplit(f.url or "").scheme, 0)
    return f"{canonical_host(f.host, hosts)}:{port}:{f.finding_type}:{canonical_location(f.url, f.parameter)}"

def merge_bucket(bucket: list[Finding]) -> Finding:
    primary = max(bucket, key=lambda f: (CONF_RANK.get(f.confidence, 0), len(f.evidence)))
    primary.instances = len(bucket)
    primary.source_tool = "+".join(sorted({f.source_tool for f in bucket}))
    primary.evidence = "\n\n--- corroborating evidence ---\n\n".join(
        f"[{f.source_tool}] {f.evidence}" for f in bucket)[:4096]
    return primary
```

The two unsolved ambiguities (vhost A and vhost B on one IP; same param vulnerable via GET *and* POST) are deliberately resolved toward **under-merging** with a `host_port_ref` cross-link — a "see also VAPT-2026-004" line in the report is correct and cheap; a wrong merge is not.

### Problem 2 — Making LLM CVSS scoring trustworthy

**Why hard:** A report's credibility lives and dies on its scores. LLMs produce plausible-but-wrong metrics (PR:N on an authenticated-only endpoint), occasionally malformed vectors, and free-text drift. You also can't hand-write rules for everything, or you've built a worse Nessus. And the local-model path (Llama 8B) is *much* sloppier than Claude — the same code must survive both.

**Solution:** constrain → validate → bound → fall back. Four independent layers, each catching what the previous can't.

```python
class CVSSMetrics(BaseModel):                       # Layer 1: type-constrained output
    AV: Literal["N","A","L","P"]; AC: Literal["L","H"]
    PR: Literal["N","L","H"];     UI: Literal["N","R"]
    S:  Literal["U","C"]
    C:  Literal["N","L","H"]; I: Literal["N","L","H"]; A: Literal["N","L","H"]
    deviation_rationale: str = ""                   # only when differing from the prior

def score_finding(f: dict, llm) -> dict:
    prior = HEURISTICS.get(f["finding_type"], DEFAULT_VECTOR)   # Layer 0: anchor
    structured = llm.with_structured_output(CVSSMetrics)
    for attempt in range(2):                        # Layer 2: validate w/ real library
        try:
            m = structured.invoke(scoring_prompt(f, prior))
            vec = f"CVSS:3.1/AV:{m.AV}/AC:{m.AC}/PR:{m.PR}/UI:{m.UI}/S:{m.S}/C:{m.C}/I:{m.I}/A:{m.A}"
            c = CVSS3(vec)                          # raises on anything invalid
            score, severity = c.scores()[0], c.severities()[0]
            break
        except Exception as e:
            last_err = e
    else:                                           # Layer 3: deterministic fallback
        c = CVSS3(prior); score, severity = c.scores()[0], c.severities()[0]
        vec = prior
        f["warnings"] = f"LLM scoring failed ({last_err}); heuristic vector used"
    # Layer 4: sanity bound vs the prior — big disagreement = human review flag
    prior_score = CVSS3(prior).scores()[0]
    f["score_disputed"] = abs(score - prior_score) > 3.0
    f.update(cvss_vector=vec, cvss_score=score, severity=severity)
    return f
```

Key insight: the LLM's job is shrunk from "score this" to "adjust this default given this evidence" — a constrained-editing task LLMs are reliable at, with `Literal` types making syntactically invalid output unrepresentable, the `cvss` library owning the math, and the heuristic table guaranteeing a defensible answer exists even if the LLM never responds.

### Problem 3 — Professional PDF pagination with hostile content

**Why hard:** Evidence is raw HTTP — 300-char unbroken base64 lines that overflow page width; findings vary from 5 lines to 3 pages; naive `page-break-inside: avoid` on a 3-page finding creates a blank page then an overflow; headings orphan at page bottoms; the findings table splits without its header. WeasyPrint silently produces ugly output rather than erroring, so you only see problems by eyeballing PDFs — slow feedback, and it always eats more time than planned (hence scheduled for Week 5 with Week 6 buffer).

**Solution:** (a) sanitize content *before* layout, (b) conditional break policy by measured size, (c) a pagination stress fixture rendered in tests.

```python
MAX_EVIDENCE_LINE = 120
def prepare_evidence(raw: str, limit: int = 3000) -> str:
    """Make evidence layout-safe BEFORE it reaches the template."""
    out = []
    for line in raw.splitlines():
        while len(line) > MAX_EVIDENCE_LINE:                  # hard-wrap unbroken runs
            out.append(line[:MAX_EVIDENCE_LINE] + " ↩")  # ↩ continuation marker
            line = line[MAX_EVIDENCE_LINE:]
        out.append(line)
    text = "\n".join(out)
    if len(text) > limit:
        text = text[:limit] + f"\n[... {len(raw)-limit} bytes truncated — full evidence in appendix manifest]"
    return text

def break_class(finding: dict) -> str:           # renderer sets template class
    return "long" if len(finding["evidence"]) > 1500 or len(finding["description"]) > 1200 else ""
```

```css
section.finding        { page-break-inside: avoid; }   /* short: keep whole */
section.finding.long   { page-break-inside: auto; }    /* long: let it flow */
section.finding.long .finding-header { page-break-after: avoid; } /* but header stays with body */
pre.evidence { white-space: pre-wrap; word-break: break-all; }
h2, h3 { page-break-after: avoid; }
thead  { display: table-header-group; }
```

```python
def test_pagination_stress(tmp_path):            # regression net: render, don't eyeball
    findings = make_findings(n=40, evidence_sizes=[10, 500, 3000, 8000])
    pdf = render_pdf(report_context(findings), tmp_path / "stress.pdf")
    doc = fitz.open(pdf)                          # pypdf/pymupdf: cheap asserts
    assert doc.page_count > 10
    assert not any(page.get_text().strip() == "" for page in doc)   # no blank pages
```

The test won't catch every aesthetic issue, but it catches the catastrophic ones (blank pages, render exceptions, runaway page counts) on every commit — which is what keeps Week 5 from becoming Week 5-and-6.

---

## 12. CLAUDE.md

Written to the project root as `CLAUDE.md` (see that file). Contents: project summary, pipeline architecture, agent responsibilities, key design decisions with rationale, build-status checklist, and the "do not break" invariants.
