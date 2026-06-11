"""FastAPI web UI: upload evidence -> background pipeline -> download report.

Single-user, localhost. Uses BackgroundTasks (no Celery) per the MVP scope.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB per file (oversized -> 413)

from ..config import get_settings
from ..db import repository as repo
from ..parsers import collect_inputs

_HERE = Path(__file__).resolve().parent
app = FastAPI(title="RedNarrate")
templates = Jinja2Templates(directory=str(_HERE / "templates"))
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

_UPLOAD_ROOT = Path("uploads")


@app.on_event("startup")
def _startup():
    repo.init_db(get_settings().db_path)
    _UPLOAD_ROOT.mkdir(exist_ok=True)


def _run_job(scan_id: str, meta: dict, db_path: str):
    from ..graph import run_pipeline

    try:
        run_pipeline(meta, db_path=db_path, checkpoint=True)
    except Exception as exc:
        repo.update_scan_status(scan_id, "failed", error_summary=str(exc), db_path=db_path)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    settings = get_settings()
    scans = repo.list_scans(20, db_path=settings.db_path)
    return templates.TemplateResponse(request, "index.html", {"scans": scans})


@app.post("/scans")
async def create_scan(
    background: BackgroundTasks,
    client: str = Form("Client"),
    scope: str = Form(""),
    dates: str = Form(""),
    files: list[UploadFile] = None,  # noqa: B008
):
    settings = get_settings()
    scan_id = uuid.uuid4().hex
    job_dir = _UPLOAD_ROOT / scan_id
    job_dir.mkdir(parents=True, exist_ok=True)

    for uf in files or []:
        if not uf.filename:
            continue
        dest = job_dir / Path(uf.filename).name
        written = 0
        with dest.open("wb") as fh:
            while chunk := uf.file.read(1024 * 1024):
                written += len(chunk)
                if written > _MAX_UPLOAD_BYTES:
                    fh.close()
                    shutil.rmtree(job_dir, ignore_errors=True)
                    return JSONResponse(
                        {"error": f"{uf.filename} exceeds {_MAX_UPLOAD_BYTES} byte limit"},
                        status_code=413,
                    )
                fh.write(chunk)

    inputs, _notes = collect_inputs(job_dir)
    meta = {
        "scan_id": scan_id,
        "client_name": client,
        "scope": scope,
        "engagement_dates": dates,
        "llm_provider": settings.llm_provider,
        "raw_inputs": inputs,
    }
    repo.create_scan(meta, db_path=settings.db_path)
    background.add_task(_run_job, scan_id, meta, settings.db_path)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_status(request: Request, scan_id: str):
    settings = get_settings()
    scan = repo.get_scan(scan_id, db_path=settings.db_path)
    if not scan:
        return HTMLResponse("Scan not found", status_code=404)
    findings = repo.get_findings(scan_id, db_path=settings.db_path)
    reports = repo.get_reports(scan_id, db_path=settings.db_path)
    return templates.TemplateResponse(
        request,
        "scan_status.html",
        {"scan": scan, "findings": findings, "reports": reports},
    )


@app.get("/scans/{scan_id}/report")
def download_report(scan_id: str, fmt: str = "pdf"):
    settings = get_settings()
    reports = repo.get_reports(scan_id, db_path=settings.db_path)
    match = next((r for r in reports if r["format"] == fmt), None)
    if not match or not Path(match["file_path"]).exists():
        return HTMLResponse("Report not available", status_code=404)
    media = {"pdf": "application/pdf", "md": "text/markdown", "html": "text/html"}
    return FileResponse(
        match["file_path"],
        media_type=media.get(fmt, "application/octet-stream"),
        filename=f"report_{scan_id[:8]}.{fmt}",
    )
