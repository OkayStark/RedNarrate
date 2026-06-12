"""Tests for Nuclei, dirbrute (ffuf/gobuster), WPScan parsers + multi-file support."""

from pathlib import Path

import pytest

from rednarrate.parsers.base import ParserError, collect_inputs, detect_tool
from rednarrate.parsers.dirbrute_parser import parse_dirbrute
from rednarrate.parsers.nuclei_parser import parse_nuclei
from rednarrate.parsers.wpscan_parser import parse_wpscan

FIXTURES = Path(__file__).parent / "fixtures"


# ── Nuclei ───────────────────────────────────────────────────────────

class TestNucleiParser:
    def test_parses_findings(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        assert len(findings) >= 4  # 5 lines - 1 invalid JSON = 4 valid

    def test_severity_mapping(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        sev_map = {f.finding_type: f.severity_raw for f in findings}
        assert "Critical" in sev_map.values()
        assert "High" in sev_map.values()

    def test_sqli_finding_type(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        sqli = [f for f in findings if f.finding_type == "sqli"]
        assert sqli, "sqli finding expected from sqli-error-based template"

    def test_cve_in_references(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        cve_findings = [f for f in findings if any("CVE-" in r for r in f.references)]
        assert cve_findings, "Expected CVE reference from CVE-2021-41773 template"

    def test_cwe_normalized(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        sqli = next(f for f in findings if f.finding_type == "sqli")
        assert "CWE-89" in sqli.references

    def test_host_extracted(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        for f in findings:
            assert f.host  # every finding must have a host

    def test_source_tool_is_nuclei(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        assert all(f.source_tool == "nuclei" for f in findings)

    def test_url_set(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        sqli = next(f for f in findings if f.finding_type == "sqli")
        assert sqli.url and "target.com" in sqli.url

    def test_evidence_contains_request(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        sqli = next(f for f in findings if f.finding_type == "sqli")
        assert "REQUEST" in sqli.evidence or "Matched" in sqli.evidence

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        with pytest.raises(ParserError, match="no parseable JSONL"):
            parse_nuclei(f)

    def test_invalid_json_lines_skipped(self, tmp_path):
        f = tmp_path / "bad.jsonl"
        f.write_text('{"template-id":"t1","info":{"name":"A","severity":"info"},"matched-at":"http://x.com/"}\nnot-json\n')
        findings = parse_nuclei(f)
        assert len(findings) == 1  # only the valid line

    def test_cors_finding_type(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        cors = [f for f in findings if f.finding_type == "cors-misconfiguration"]
        assert cors


# ── ffuf (dirbrute) ──────────────────────────────────────────────────

class TestFfufParser:
    def test_parses_findings(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        assert findings

    def test_admin_path_detected(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        admin = [f for f in findings if "Administration" in f.name or "Admin" in f.name]
        assert admin, "Expected admin-panel finding for /admin path"

    def test_sensitive_file_detected(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        sensitive = [f for f in findings if "Sensitive" in f.name]
        assert sensitive, "Expected sensitive-files finding for backup.sql"

    def test_summary_finding_present(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        summary = [f for f in findings if "Enumeration" in f.name]
        assert summary

    def test_finding_types(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        ftypes = {f.finding_type for f in findings}
        assert "sensitive-data-exposure" in ftypes
        assert "directory-listing" in ftypes

    def test_source_tool_is_ffuf(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        assert all(f.source_tool == "ffuf" for f in findings)

    def test_host_extracted_from_url(self):
        findings = parse_dirbrute(FIXTURES / "ffuf_sample.json")
        for f in findings:
            assert f.host


# ── gobuster text (dirbrute) ─────────────────────────────────────────

class TestGobusterTextParser:
    def test_parses_findings(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.txt")
        assert findings

    def test_admin_detected(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.txt")
        admin = [f for f in findings if "Administration" in f.name or "Admin" in f.name]
        assert admin

    def test_sensitive_files_detected(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.txt")
        sensitive = [f for f in findings if "Sensitive" in f.name]
        assert sensitive  # .env and backup.zip are both sensitive

    def test_source_tool_is_gobuster(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.txt")
        assert all(f.source_tool == "gobuster" for f in findings)

    def test_empty_results_returns_no_findings(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("Gobuster v3.6 by OJ Reeves\n===============\nStarting gobuster\n")
        findings = parse_dirbrute(f)
        assert findings == []

    def test_unknown_format_raises(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("hello world\nno gobuster here\n")
        with pytest.raises(ParserError, match="cannot identify sub-format"):
            parse_dirbrute(f)


# ── WPScan ───────────────────────────────────────────────────────────

class TestWpScanParser:
    def test_parses_findings(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        assert findings

    def test_wordpress_core_vuln(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        core = [f for f in findings if "Core" in f.name]
        assert core

    def test_plugin_vuln(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        plugin = [f for f in findings if "contact-form-7" in f.name]
        assert plugin

    def test_cve_in_plugin_refs(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        plugin = next(f for f in findings if "contact-form-7" in f.name)
        assert any("CVE" in r or "2024" in r for r in plugin.references)

    def test_interesting_findings(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        interesting = [f for f in findings if "readme" in f.name.lower() or "XML-RPC" in f.name]
        assert interesting

    def test_user_enumeration(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        user_enum = [f for f in findings if "User Enumeration" in f.name]
        assert user_enum
        assert "admin" in user_enum[0].evidence or "2 user" in user_enum[0].name

    def test_source_tool_is_wpscan(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        assert all(f.source_tool == "wpscan" for f in findings)

    def test_host_extracted(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        for f in findings:
            assert f.host == "target.com"

    def test_malformed_raises(self):
        with pytest.raises(ParserError, match="missing 'target_url'"):
            parse_wpscan(FIXTURES / "wpscan_malformed.json")

    def test_invalid_json_raises(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json{{{")
        with pytest.raises(ParserError, match="not valid JSON"):
            parse_wpscan(f)


# ── detect_tool ──────────────────────────────────────────────────────

class TestDetectToolNewTools:
    def test_detects_nuclei(self):
        assert detect_tool(FIXTURES / "nuclei_sample.jsonl") == "nuclei"

    def test_detects_ffuf(self):
        assert detect_tool(FIXTURES / "ffuf_sample.json") == "ffuf"

    def test_detects_gobuster_text(self):
        assert detect_tool(FIXTURES / "gobuster_sample.txt") == "gobuster"

    def test_detects_wpscan(self):
        assert detect_tool(FIXTURES / "wpscan_sample.json") == "wpscan"


# ── Multi-file collect_inputs ─────────────────────────────────────────

class TestMultiFileCollectInputs:
    def test_multiple_nmap_files_both_collected(self, tmp_path):
        import shutil
        (tmp_path / "scan1.xml").write_bytes((FIXTURES / "nmap_full.xml").read_bytes())
        (tmp_path / "scan2.xml").write_bytes((FIXTURES / "nmap_empty_host.xml").read_bytes())
        inputs, notes = collect_inputs(tmp_path)
        assert "nmap" in inputs
        assert len(inputs["nmap"]) == 2
        # No "ignoring" note because nmap is a multi-file tool.
        assert not any("ignoring" in n for n in notes)

    def test_multiple_burp_files_only_first_kept(self, tmp_path):
        (tmp_path / "burp1.xml").write_bytes((FIXTURES / "burp_full.xml").read_bytes())
        (tmp_path / "burp2.xml").write_bytes((FIXTURES / "burp_no_b64.xml").read_bytes())
        inputs, notes = collect_inputs(tmp_path)
        assert len(inputs["burp"]) == 1
        assert any("ignoring" in n for n in notes)

    def test_values_are_lists(self, tmp_path):
        import shutil
        shutil.copy(FIXTURES / "nmap_full.xml", tmp_path / "nmap.xml")
        inputs, _ = collect_inputs(tmp_path)
        assert isinstance(inputs["nmap"], list)
        assert len(inputs["nmap"]) == 1

    def test_mixed_tools_each_collected(self, tmp_path):
        import shutil
        shutil.copy(FIXTURES / "nmap_full.xml", tmp_path / "scan.xml")
        shutil.copy(FIXTURES / "burp_full.xml", tmp_path / "burp.xml")
        shutil.copy(FIXTURES / "sqlmap_injectable.log", tmp_path / "sqlmap.log")
        inputs, _ = collect_inputs(tmp_path)
        assert set(inputs.keys()) == {"nmap", "burp", "sqlmap"}
        for v in inputs.values():
            assert isinstance(v, list) and len(v) == 1

    def test_existing_e2e_test_compat(self, tmp_path):
        """set(inputs) == {"nmap"} still works with list values."""
        import shutil
        shutil.copy(FIXTURES / "nmap_full.xml", tmp_path / "scan.xml")
        inputs, _ = collect_inputs(tmp_path)
        assert set(inputs) == {"nmap"}
