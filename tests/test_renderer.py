from rednarrate.report.renderer import (
    break_class,
    prepare_evidence,
    render_html,
    render_markdown,
)


def _sections():
    findings = [
        {"id": "VAPT-2026-001", "name": "SQL injection", "severity": "Critical",
         "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "host": "10.0.0.5", "port": 443, "parameter": "username", "source_tool": "burp+sqlmap",
         "description": "A SQL injection issue was identified.", "business_impact": "Data exposure.",
         "evidence": "POST /login\nusername=' OR 1=1--", "remediation": ["Use prepared statements."],
         "report_references": ["CWE-89"], "instances": 2},
        {"id": "VAPT-2026-002", "name": "Open SSH service", "severity": "Informational",
         "cvss_score": 0.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
         "host": "10.0.0.5", "port": 22, "source_tool": "nmap",
         "description": "An open SSH port.", "evidence": "22/tcp open ssh", "remediation": []},
    ]
    return {
        "exec_summary": {"overview": "An assessment was performed.", "overall_risk": "Critical",
                         "key_findings": ["VAPT-2026-001 — SQL injection (Critical)"],
                         "immediate_actions": ["Fix VAPT-2026-001"],
                         "severity_counts": {"Critical": 1, "Informational": 1}},
        "findings": findings,
        "chains": [{"name": "SQLi to exfiltration", "finding_ids": ["VAPT-2026-001"],
                    "combined_impact": "Leads to data loss."}],
        "roadmap": {"immediate": ["VAPT-2026-001: prepared statements"],
                    "short_term": [], "long_term": ["VAPT-2026-002: restrict access"]},
        "methodology": {"standards": ["OWASP WSTG v4.2"], "tools_used": ["burp", "nmap", "sqlmap"]},
        "hosts": {"10.0.0.5": {"hostnames": ["target.com"], "os": "Linux",
                               "open_ports": [{"port": 22}, {"port": 443}]}},
        "warnings": ["one note"],
    }


_META = {"client_name": "Acme", "scope": "web", "engagement_dates": "2026", "scan_id": "x"}


def test_html_renders():
    html = render_html(_sections(), _META)
    assert "SQL injection" in html
    assert "VAPT-2026-001" in html
    assert "Critical" in html


def test_markdown_renders():
    md = render_markdown(_sections(), _META)
    assert "# Penetration Test Report" in md
    assert "| ID | Finding |" in md
    assert "SQLi to exfiltration" in md


def test_prepare_evidence_wraps_long_lines():
    raw = "A" * 400
    out = prepare_evidence(raw)
    assert all(len(line) <= 130 for line in out.splitlines())


def test_break_class():
    assert break_class({"evidence": "x" * 2000, "description": ""}) == "long"
    assert break_class({"evidence": "short", "description": "short"}) == ""


def test_prepare_evidence_truncates_large_blobs():
    out = prepare_evidence("Z" * 10000, limit=3000)
    assert len(out) <= 3000 + 60  # plus the truncation marker
    assert "truncated" in out


def test_severity_badge_classes_present():
    from rednarrate.report.renderer import render_html
    findings = [
        {"id": f"VAPT-2026-00{i}", "name": f"F{i}", "severity": sev, "cvss_score": s,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "host": "h",
         "port": 80, "description": "d", "business_impact": "b", "evidence": "e",
         "remediation": [], "report_references": []}
        for i, (sev, s) in enumerate(
            [("Critical", 9.8), ("High", 7.5), ("Medium", 5.0), ("Low", 3.0),
             ("Informational", 0.0)], start=1)
    ]
    sec = _sections()
    sec["findings"] = findings
    html = render_html(sec, _META)
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        assert f"badge {sev}" in html


def test_zero_chains_section_omitted():
    sec = _sections()
    sec["chains"] = []
    md = render_markdown(sec, _META)
    assert "## Attack Chains" not in md


def test_disputed_score_marked_in_markdown():
    sec = _sections()
    sec["findings"][0]["score_disputed"] = True
    md = render_markdown(sec, _META)
    assert "flagged for review" in md


def test_client_name_is_html_escaped():
    md_meta = dict(_META, client_name="<script>alert(1)</script>")
    html = render_html(_sections(), md_meta)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


import pytest

try:
    import weasyprint  # noqa: F401
    _WEASY = True
except Exception:
    _WEASY = False


@pytest.mark.skipif(not _WEASY, reason="weasyprint not installed")
def test_pagination_stress(tmp_path):
    """40 findings across a range of evidence sizes must render to a multi-page
    PDF without raising."""
    import fitz  # pymupdf
    from rednarrate.report.renderer import render_all

    sizes = [10, 500, 3000, 8000]
    findings = []
    for i in range(40):
        ev = "lorem ipsum " * (sizes[i % len(sizes)] // 12)
        findings.append({
            "id": f"VAPT-2026-{i+1:03d}", "name": f"Finding {i+1}",
            "severity": ["Critical", "High", "Medium", "Low", "Informational"][i % 5],
            "cvss_score": 7.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "host": "10.0.0.5", "port": 443, "description": "desc " * 50,
            "business_impact": "impact", "evidence": ev, "remediation": ["fix it"],
            "report_references": ["CWE-89"],
        })
    sec = _sections()
    sec["findings"] = findings
    paths = render_all(sec, _META, tmp_path)
    assert "md" in paths and "html" in paths
    assert "pdf" in paths, "PDF should render when weasyprint is available"
    doc = fitz.open(paths["pdf"])
    assert doc.page_count > 5
    doc.close()
