"""LangGraph pipeline wiring.

Ingestion -> Correlation -> CVSS Scoring -> Report Writer -> END, with a
conditional edge after each node that routes to END (failure) when errors
accumulate. Persistence to SQLite happens at the boundaries (run_pipeline),
not inside agents.
"""

from __future__ import annotations

import uuid
from typing import Optional

from langgraph.graph import END, START, StateGraph

from .agents import (
    correlation_node,
    cvss_scoring_node,
    ingestion_node,
    report_writer_node,
)
from .db import repository as repo
from .state import ScanState, empty_state


def _route(next_node: str):
    """Build a conditional-edge router: go to END if errors, else next_node."""

    def router(state: ScanState) -> str:
        return "fail" if state.get("errors") else "ok"

    return router


def build_graph(checkpointer=None):
    builder = StateGraph(ScanState)
    builder.add_node("ingest", ingestion_node)
    builder.add_node("correlate", correlation_node)
    builder.add_node("score", cvss_scoring_node)
    builder.add_node("write", report_writer_node)

    builder.add_edge(START, "ingest")
    builder.add_conditional_edges("ingest", _route("correlate"),
                                  {"ok": "correlate", "fail": END})
    builder.add_conditional_edges("correlate", _route("score"),
                                  {"ok": "score", "fail": END})
    builder.add_conditional_edges("score", _route("write"),
                                  {"ok": "write", "fail": END})
    builder.add_edge("write", END)

    return builder.compile(checkpointer=checkpointer)


# Status names the graph transitions through, for the scans table.
_STEP_STATUS = {
    "ingest": "ingesting",
    "correlate": "correlating",
    "score": "scoring",
    "write": "writing",
}


def run_pipeline(
    meta: dict,
    db_path: Optional[str] = None,
    checkpoint: bool = True,
    progress=None,
) -> ScanState:
    """End-to-end run: persist the scan, invoke the graph, persist results.

    `meta` carries scan_id (optional), client_name, scope, engagement_dates,
    llm_provider, raw_inputs. `progress(step)` is an optional callback.
    """
    repo.init_db(db_path)
    scan_id = meta.get("scan_id") or uuid.uuid4().hex
    meta["scan_id"] = scan_id
    repo.create_scan(meta, db_path)

    state = empty_state(**meta)

    checkpointer = None
    cm = None
    if checkpoint:
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver
        except ImportError:
            SqliteSaver = None  # type: ignore[assignment,misc]
        if SqliteSaver is None:
            import warnings
            warnings.warn(
                "langgraph-checkpoint-sqlite not installed; running without checkpointing.",
                stacklevel=2,
            )
        else:
            cm = SqliteSaver.from_conn_string(db_path or "rednarrate_checkpoints.db")
            checkpointer = cm.__enter__()

    try:
        graph = build_graph(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": scan_id}}

        final: ScanState = state
        for event in graph.stream(state, config=config, stream_mode="values"):
            final = event
            step = final.get("current_step")
            if step in _STEP_STATUS:
                repo.update_scan_status(scan_id, _STEP_STATUS[step], db_path=db_path)
                if progress:
                    progress(step)
    finally:
        if cm is not None:
            cm.__exit__(None, None, None)

    # Persist results.
    if final.get("errors"):
        repo.update_scan_status(
            scan_id, "failed", error_summary="; ".join(final["errors"]), db_path=db_path
        )
    else:
        scored = final.get("scored_findings", [])
        repo.save_findings(scan_id, scored, db_path=db_path)
        repo.save_chains(scan_id, final.get("attack_chains", []), db_path=db_path)
        from .config import get_settings

        s = get_settings()
        model = {
            "anthropic": s.writer_model,
            "ollama": s.ollama_model,
        }.get(s.llm_provider, "none (templates)")
        for fmt, path in final.get("report_paths", {}).items():
            repo.save_report(scan_id, fmt, path, scored, llm_model=model, db_path=db_path)
        repo.update_scan_status(scan_id, "complete", db_path=db_path)

    return final
