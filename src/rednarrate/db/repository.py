"""SQLite persistence. Plain stdlib sqlite3 — the schema is four tables.

The graph writes here at pipeline boundaries; agents stay DB-free so they're
unit-testable. All JSON-typed columns are (de)serialized at this boundary.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from ..config import get_settings

_SCHEMA = Path(__file__).with_name("schema.sql")


@contextmanager
def connect(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or get_settings().db_path
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables/indexes if absent. Idempotent."""
    with connect(db_path) as conn:
        conn.executescript(_SCHEMA.read_text())


# ── scans ───────────────────────────────────────────────────────────


def _first_path(val) -> str | None:
    """Return first path string from a str or list[str] raw_inputs value."""
    if val is None:
        return None
    if isinstance(val, list):
        return val[0] if val else None
    return str(val)


def create_scan(meta: dict, db_path: Optional[str] = None) -> str:
    scan_id = meta.get("scan_id") or uuid.uuid4().hex
    raw = meta.get("raw_inputs", {})
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO scans
               (id, client_name, scope, engagement_dates,
                nmap_file, burp_file, sqlmap_file, llm_provider, status)
               VALUES (?,?,?,?,?,?,?,?, 'pending')""",
            (
                scan_id,
                meta.get("client_name", ""),
                meta.get("scope", ""),
                meta.get("engagement_dates", ""),
                _first_path(raw.get("nmap")),
                _first_path(raw.get("burp")),
                _first_path(raw.get("sqlmap")),
                meta.get("llm_provider", "anthropic"),
            ),
        )
    return scan_id


def update_scan_status(
    scan_id: str, status: str, error_summary: str | None = None,
    db_path: Optional[str] = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE scans SET status = ?, error_summary = ? WHERE id = ?",
            (status, error_summary, scan_id),
        )


def get_scan(scan_id: str, db_path: Optional[str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(limit: int = 50, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── findings ────────────────────────────────────────────────────────


def save_findings(
    scan_id: str, findings: list[dict], db_path: Optional[str] = None
) -> None:
    """Replace this scan's findings with the given list."""
    with connect(db_path) as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.executemany(
            """INSERT INTO findings
               (id, scan_id, source_tool, host, port, protocol, service, url,
                parameter, finding_type, name, severity, cvss_vector, cvss_score,
                score_disputed, confidence, description, business_impact, evidence,
                remediation, refs, instances, is_chain_member)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    f["id"], scan_id, f.get("source_tool", ""), f.get("host", ""),
                    f.get("port"), f.get("protocol", "tcp"), f.get("service"),
                    f.get("url"), f.get("parameter"), f.get("finding_type", ""),
                    f.get("name", ""), f.get("severity"), f.get("cvss_vector"),
                    f.get("cvss_score"), int(f.get("score_disputed", False)),
                    f.get("confidence"), f.get("description", ""),
                    f.get("business_impact", ""), f.get("evidence", ""),
                    json.dumps(f.get("remediation", [])),
                    json.dumps(f.get("report_references") or f.get("references", [])),
                    f.get("instances", 1), int(f.get("is_chain_member", False)),
                )
                for f in findings
            ],
        )


def get_findings(scan_id: str, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC",
            (scan_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["remediation"] = json.loads(d.get("remediation") or "[]")
        d["refs"] = json.loads(d.get("refs") or "[]")
        out.append(d)
    return out


# ── attack chains ───────────────────────────────────────────────────


def save_chains(
    scan_id: str, chains: list[dict], db_path: Optional[str] = None
) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM attack_chains WHERE scan_id = ?", (scan_id,))
        conn.executemany(
            """INSERT INTO attack_chains
               (id, scan_id, chain_name, finding_ids, combined_impact, detected_by)
               VALUES (?,?,?,?,?,?)""",
            [
                (
                    c.get("id") or uuid.uuid4().hex, scan_id,
                    c.get("name") or c.get("chain_name", ""),
                    json.dumps(c.get("finding_ids", [])),
                    c.get("combined_impact", ""),
                    c.get("detected_by", "rule"),
                )
                for c in chains
            ],
        )


def get_chains(scan_id: str, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM attack_chains WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["finding_ids"] = json.loads(d.get("finding_ids") or "[]")
        out.append(d)
    return out


# ── reports ─────────────────────────────────────────────────────────


def save_report(
    scan_id: str, fmt: str, file_path: str, findings: list[dict],
    llm_model: str = "", db_path: Optional[str] = None,
) -> str:
    report_id = uuid.uuid4().hex
    counts = Counter(f.get("severity") or "Informational" for f in findings)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO reports
               (id, scan_id, format, file_path, finding_count, severity_counts, llm_model)
               VALUES (?,?,?,?,?,?,?)""",
            (report_id, scan_id, fmt, file_path, len(findings),
             json.dumps(dict(counts)), llm_model),
        )
    return report_id


def get_reports(scan_id: str, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE scan_id = ? ORDER BY created_at DESC",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]
