"""Render report_sections to HTML, PDF, and Markdown from one context dict.

Evidence is made layout-safe BEFORE templating (long lines wrapped, capped) so
WeasyPrint pagination behaves (PROJECT_PLAN §11 Problem 3). PDF failure never
loses the Markdown/HTML output.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..parsers.base import sanitize_evidence

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
MAX_EVIDENCE_LINE = 120


def _autoescape(template_name: str | None) -> bool:
    """Escape HTML/XML templates; never escape Markdown (entities would leak)."""
    if not template_name:
        return False
    return ".html" in template_name or ".xml" in template_name


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=_autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


def prepare_evidence(raw: str, limit: int = 3000) -> str:
    """Hard-wrap unbroken runs and cap length so evidence can't overflow a page.

    Also re-runs credential sanitization as a defense-in-depth layer, so secrets
    never reach the rendered report even if evidence arrives from another path.
    """
    if not raw:
        return ""
    raw = sanitize_evidence(raw)
    out = []
    for line in raw.splitlines():
        while len(line) > MAX_EVIDENCE_LINE:
            out.append(line[:MAX_EVIDENCE_LINE] + " ↩")
            line = line[MAX_EVIDENCE_LINE:]
        out.append(line)
    text = "\n".join(out)
    if len(text) > limit:
        text = text[:limit] + f"\n[... {len(raw) - limit} bytes truncated ...]"
    return text


def break_class(finding: dict) -> str:
    """Long findings flow across pages; short ones stay whole."""
    if len(finding.get("evidence", "")) > 1500 or len(finding.get("description", "")) > 1200:
        return "long"
    return ""


def _build_context(sections: dict, meta: dict) -> dict:
    findings = []
    for f in sections.get("findings", []):
        f = dict(f)
        f["evidence_display"] = prepare_evidence(f.get("evidence", ""))
        f["break_class"] = break_class(f)
        findings.append(f)
    return {
        "meta": {
            "client_name": meta.get("client_name") or "Client",
            "scope": meta.get("scope") or "Not specified",
            "engagement_dates": meta.get("engagement_dates") or "Not specified",
            "report_date": datetime.date.today().isoformat(),
            "report_title": "Penetration Test Report",
            "classification": "CONFIDENTIAL",
            "version": "1.0",
        },
        "exec": sections.get("exec_summary", {}),
        "findings": findings,
        "chains": sections.get("chains", []),
        "roadmap": sections.get("roadmap", {}),
        "methodology": sections.get("methodology", {}),
        "hosts": sections.get("hosts", {}),
        "warnings": sections.get("warnings", []),
        "severity_counts": sections.get("exec_summary", {}).get("severity_counts", {}),
    }


def render_html(sections: dict, meta: dict) -> str:
    return _env().get_template("report.html.j2").render(**_build_context(sections, meta))


def render_markdown(sections: dict, meta: dict) -> str:
    return _env().get_template("report.md.j2").render(**_build_context(sections, meta))


def render_pdf(html: str, out_path: Path) -> Path:
    from weasyprint import HTML

    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(str(out_path))
    return out_path


def render_all(sections: dict, meta: dict, out_dir: Path) -> dict[str, str]:
    """Write md + html always, pdf if possible. Returns {fmt: path}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    md = render_markdown(sections, meta)
    md_path = out_dir / "report.md"
    md_path.write_text(md)
    paths["md"] = str(md_path)

    html = render_html(sections, meta)
    html_path = out_dir / "report.html"
    html_path.write_text(html)
    paths["html"] = str(html_path)

    try:
        pdf_path = render_pdf(html, out_dir / "report.pdf")
        paths["pdf"] = str(pdf_path)
    except Exception:
        # PDF (WeasyPrint system-lib) failure must not lose md/html.
        pass

    return paths
