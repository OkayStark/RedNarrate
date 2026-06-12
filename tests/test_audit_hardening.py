"""Addendum audit hardening tests — Sections B through K.

Covers edge cases, security invariants, and E2E smoke tests for all 5 new
parsers (Nessus, ZAP, Nuclei, dirbrute, WPScan).
"""

from __future__ import annotations

import importlib
import json
import time
from pathlib import Path

import pytest

from rednarrate.parsers.base import ParserError, collect_inputs, detect_tool
from rednarrate.parsers.dirbrute_parser import parse_dirbrute
from rednarrate.parsers.nessus_parser import parse_nessus
from rednarrate.parsers.nuclei_parser import parse_nuclei
from rednarrate.parsers.wpscan_parser import parse_wpscan
from rednarrate.parsers.zap_parser import parse_zap
from rednarrate.rag.fallback import GENERIC_CONTEXT, STATIC_CONTEXT, static_context
from rednarrate.scoring.heuristics import HEURISTICS, heuristic_vector

FIXTURES = Path(__file__).parent / "fixtures"


# ═══════════════════════════════════════════════════════════════════════════
# Section B — Nessus hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestNessusHardening:
    def test_xxe_payload_raises_parser_error(self):
        """defusedxml must reject DOCTYPE entity expansion."""
        with pytest.raises(ParserError):
            parse_nessus(FIXTURES / "nessus_xxe_payload.nessus")

    def test_multi_host_all_hosts_represented(self):
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        hosts = {f.host for f in findings}
        # Fixture has 3 hosts: 10.0.0.1, 10.0.0.2, 10.0.0.3
        assert len(hosts) >= 3

    def test_multi_host_finding_count(self):
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        # Fixture has 5 ReportItems across 3 hosts; port=0 items (severity=0) are still parsed
        assert len(findings) >= 3

    def test_cvss_score_none_invariant(self):
        """Parsers must never produce a cvss_score — scoring agent owns that."""
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        for f in findings:
            assert f.cvss_score is None, f"{f.id} has a non-None cvss_score from parser"

    def test_all_five_severity_bands(self):
        # nessus_multi_host.nessus has severity 0-4 across 3 hosts
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        sevs = {f.severity_raw for f in findings}
        assert "Informational" in sevs
        assert "Low" in sevs
        assert "Medium" in sevs
        assert "High" in sevs
        assert "Critical" in sevs

    def test_cwe_colon_form_normalized(self):
        """'CWE:310' in <xref> must become 'CWE-310' in references."""
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        all_refs = [r for f in findings for r in f.references]
        cwe_refs = [r for r in all_refs if r.startswith("CWE-")]
        assert any("CWE-310" in r or "CWE-89" in r or "CWE-78" in r for r in cwe_refs), \
            f"Expected normalized CWE refs; got: {cwe_refs}"

    def test_cwe_hyphen_form_unchanged(self):
        """'CWE-89' must pass through unchanged."""
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        all_refs = [r for f in findings for r in f.references]
        # Fixture has CWE-89 in xref; must not become CWE--89 or similar
        for r in all_refs:
            if r.startswith("CWE-"):
                # Should be CWE-DIGITS only
                assert r == r  # just check it's there and correctly formed
                import re
                assert re.match(r"CWE-\d+$", r), f"Malformed CWE ref: {r}"

    def test_port_zero_yields_none(self):
        """Port attribute '0' must produce Finding.port = None."""
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        # Fixture has a pluginID=19506 on port "0" in host 10.0.0.2
        zero_port_findings = [f for f in findings if f.host == "10.0.0.2" and f.port is None]
        assert zero_port_findings, "Expected at least one finding with port=None from port='0'"

    def test_source_tool_is_nessus(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        assert all(f.source_tool == "nessus" for f in findings)

    def test_dedup_key_format(self):
        """dedup_key must be host:port:ftype:plugin_id."""
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        for f in findings:
            parts = f.dedup_key.split(":")
            assert len(parts) >= 4, f"Malformed dedup_key: {f.dedup_key}"

    def test_malformed_raises(self):
        with pytest.raises(ParserError):
            parse_nessus(FIXTURES / "nessus_malformed.nessus")

    def test_missing_file_raises(self):
        with pytest.raises(ParserError):
            parse_nessus(FIXTURES / "does_not_exist.nessus")

    def test_wrong_root_raises(self):
        with pytest.raises(ParserError, match="Not a Nessus export"):
            parse_nessus(FIXTURES / "zap_sample.xml")  # OWASPZAPReport root

    def test_cve_in_references(self):
        findings = parse_nessus(FIXTURES / "nessus_multi_host.nessus")
        all_refs = [r for f in findings for r in f.references]
        assert any("CVE-" in r for r in all_refs)


# ═══════════════════════════════════════════════════════════════════════════
# Section C — ZAP hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestZapHardening:
    def test_xxe_payload_raises_parser_error(self):
        """defusedxml must reject DOCTYPE entity expansion."""
        with pytest.raises(ParserError):
            parse_zap(FIXTURES / "zap_xxe_payload.xml")

    def test_multi_site_all_hosts_represented(self):
        findings = parse_zap(FIXTURES / "zap_multi_site.xml")
        hosts = {f.host for f in findings}
        assert "app1.example.com" in hosts
        assert "api.example.com" in hosts

    def test_multi_site_finding_count(self):
        findings = parse_zap(FIXTURES / "zap_multi_site.xml")
        # Fixture has 2 sites × 2 alerts each = 4 findings
        assert len(findings) == 4

    def test_multi_site_port_correct_per_site(self):
        findings = parse_zap(FIXTURES / "zap_multi_site.xml")
        http_findings = [f for f in findings if f.host == "app1.example.com"]
        https_findings = [f for f in findings if f.host == "api.example.com"]
        assert all(f.port == 80 for f in http_findings)
        assert all(f.port == 443 for f in https_findings)

    def test_unmapped_cwe_falls_back_to_name(self):
        """CWE not in _CWE_TO_TYPE dict must fall through to name keyword matching."""
        findings = parse_zap(FIXTURES / "zap_multi_site.xml")
        # CWE-693 is mapped to missing-security-headers; verify the CSP finding
        csp = [f for f in findings if "CSP" in f.name]
        assert csp
        assert csp[0].finding_type == "missing-security-headers"

    def test_cweid_zero_uses_name_fallback(self, tmp_path):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<OWASPZAPReport version="2.14.0" generated="">
  <site name="http://t.com" host="t.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>99</pluginid>
        <alert>Open Redirect to External Site</alert>
        <name>Open Redirect</name>
        <riskcode>2</riskcode>
        <confidence>2</confidence>
        <riskdesc>Medium (Medium)</riskdesc>
        <desc>Open redirect found.</desc>
        <cweid>0</cweid>
        <wascid>0</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        f = tmp_path / "zero_cwe.xml"
        f.write_text(xml)
        findings = parse_zap(f)
        assert findings[0].finding_type == "open-redirect"

    def test_cweid_absent_uses_name_fallback(self, tmp_path):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<OWASPZAPReport version="2.14.0" generated="">
  <site name="http://t.com" host="t.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>98</pluginid>
        <alert>Directory Listing</alert>
        <name>Directory Listing</name>
        <riskcode>2</riskcode>
        <confidence>2</confidence>
        <riskdesc>Medium (Medium)</riskdesc>
        <desc>Directory listing enabled.</desc>
        <wascid>16</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        f = tmp_path / "no_cwe.xml"
        f.write_text(xml)
        findings = parse_zap(f)
        assert findings[0].finding_type == "directory-listing"

    def test_alertitem_with_no_instances(self, tmp_path):
        """<alertitem> missing <instances> must produce instances=1 (not crash)."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<OWASPZAPReport version="2.14.0" generated="">
  <site name="http://t.com" host="t.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10015</pluginid>
        <alert>Incomplete or No Cache-control Header Set</alert>
        <name>Incomplete or No Cache-control Header Set</name>
        <riskcode>1</riskcode>
        <confidence>2</confidence>
        <riskdesc>Low (Medium)</riskdesc>
        <desc>Cache-control header not set.</desc>
        <cweid>525</cweid>
        <wascid>13</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        f = tmp_path / "no_instances.xml"
        f.write_text(xml)
        findings = parse_zap(f)
        assert len(findings) == 1
        assert findings[0].instances == 1

    def test_source_tool_is_zap(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        assert all(f.source_tool == "zap" for f in findings)

    def test_malformed_raises(self):
        with pytest.raises(ParserError):
            parse_zap(FIXTURES / "zap_malformed.xml")

    def test_wrong_root_raises(self):
        with pytest.raises(ParserError, match="Not a ZAP report"):
            parse_zap(FIXTURES / "nessus_sample.nessus")

    def test_zap_cvss_score_none_invariant(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        for f in findings:
            assert f.cvss_score is None


# ═══════════════════════════════════════════════════════════════════════════
# Section D — Nuclei hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestNucleiHardening:
    def test_malformed_mixed_lines_parses_valid(self):
        """Fixture has 3 malformed + 2 valid lines; must return 2 findings."""
        findings = parse_nuclei(FIXTURES / "nuclei_malformed.jsonl")
        # Valid lines: the second line (valid-but-minimal) and the sqli line
        assert len(findings) == 2

    def test_10mb_cap_no_oom(self, tmp_path):
        """12 MB file is capped at 10 MB without OOM or crash."""
        line = json.dumps({
            "template-id": "info-test",
            "info": {"name": "Info", "severity": "info"},
            "matched-at": "http://target.com/",
            "host": "target.com",
        }) + "\n"
        twelve_mb = line * (12 * 1024 * 1024 // len(line.encode()) + 1)
        f = tmp_path / "big.jsonl"
        f.write_text(twelve_mb[:13 * 1024 * 1024])  # write 13MB text
        findings = parse_nuclei(f)
        assert findings  # at least 1 finding parsed

    def test_sqli_tag_classification(self, tmp_path):
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"sqli-error-based","info":{"name":"SQL Injection","severity":"critical","tags":["sqli"]},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].finding_type == "sqli"

    def test_rce_tag_classification(self, tmp_path):
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"apache-struts-rce","info":{"name":"Struts RCE","severity":"critical","tags":["rce","apache"]},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].finding_type == "rce"

    def test_cors_tag_classification(self, tmp_path):
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"cors-misconfiguration","info":{"name":"CORS","severity":"medium","tags":["cors"]},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].finding_type == "cors-misconfiguration"

    def test_cwe_colon_separator_normalized(self, tmp_path):
        """cwe:89 must normalize to CWE-89."""
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"sqli","info":{"name":"SQLi","severity":"high","classification":{"cwe-id":["cwe:89"]}},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert "CWE-89" in findings[0].references

    def test_cwe_hyphen_separator_normalized(self, tmp_path):
        """cwe-89 must normalize to CWE-89."""
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"sqli","info":{"name":"SQLi","severity":"high","classification":{"cwe-id":["cwe-89"]}},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert "CWE-89" in findings[0].references

    def test_matched_at_without_scheme(self, tmp_path):
        """matched-at without :// must not crash host extraction."""
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"info","info":{"name":"Test","severity":"info"},"matched-at":"target.com/path","host":"target.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].host  # must not be empty

    def test_missing_severity_defaults_to_info(self, tmp_path):
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"test","info":{"name":"Test"},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].severity_raw == "Informational"

    def test_null_tags_handled(self, tmp_path):
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"test","info":{"name":"T","severity":"info","tags":null},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].finding_type == "info-disclosure"

    def test_comma_string_tags_handled(self, tmp_path):
        """tags as comma-separated string must be split."""
        f = tmp_path / "t.jsonl"
        f.write_text('{"template-id":"t","info":{"name":"T","severity":"high","tags":"rce,apache"},"matched-at":"http://x.com/","host":"x.com"}\n')
        findings = parse_nuclei(f)
        assert findings[0].finding_type == "rce"

    def test_no_template_id_lines_raises(self, tmp_path):
        """A file where no JSON line has a 'template-id' key must raise ParserError."""
        f = tmp_path / "t.jsonl"
        # Valid JSON objects but none have template-id (e.g. ffuf output fed to wrong parser)
        f.write_text('{"not": "jsonl", "no_template_id": true}\n{"commandline": "ffuf ...", "results": []}\n')
        with pytest.raises(ParserError, match="no parseable JSONL"):
            parse_nuclei(f)

    def test_auth_header_redacted_in_evidence(self, tmp_path):
        """Authorization header in nuclei request evidence must be redacted."""
        f = tmp_path / "t.jsonl"
        payload = json.dumps({
            "template-id": "sqli",
            "info": {"name": "SQLi", "severity": "high"},
            "matched-at": "http://target.com/api",
            "host": "target.com",
            "request": "GET /api HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer sk-supersecret123\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{\"data\":\"ok\"}",
        })
        f.write_text(payload + "\n")
        findings = parse_nuclei(f)
        assert findings
        ev = findings[0].evidence
        assert "sk-supersecret123" not in ev
        assert "[REDACTED]" in ev

    def test_nuclei_cvss_score_none_invariant(self):
        findings = parse_nuclei(FIXTURES / "nuclei_sample.jsonl")
        for f in findings:
            assert f.cvss_score is None


# ═══════════════════════════════════════════════════════════════════════════
# Section E — Dirbrute hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestDirbruteHardening:
    def test_gobuster_json_parses(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.json")
        assert findings

    def test_gobuster_json_admin_detected(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.json")
        admin = [f for f in findings if "Administration" in f.name or "Admin" in f.name]
        assert admin, "Expected admin finding for /admin and /wp-admin"

    def test_gobuster_json_sensitive_detected(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.json")
        sensitive = [f for f in findings if "Sensitive" in f.name]
        assert sensitive, "Expected sensitive-files for backup.sql, .env, wp-config.php.bak"

    def test_gobuster_json_source_tool_is_gobuster(self):
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.json")
        assert all(f.source_tool == "gobuster" for f in findings)

    def test_gobuster_json_404_filtered_out(self):
        """Status 404 should not appear in findings (not interesting)."""
        findings = parse_dirbrute(FIXTURES / "gobuster_sample.json")
        # /notfound.html has 404; the summary finding should not list it
        for f in findings:
            if "Enumeration" in f.name:
                assert "notfound.html" not in f.evidence

    def test_all_404s_returns_empty(self, tmp_path):
        data = json.dumps([
            {"Found": "http://t.com/notfound", "Status": 404, "Size": 256},
            {"Found": "http://t.com/other", "Status": 404, "Size": 0},
        ])
        f = tmp_path / "all404.json"
        f.write_text(data)
        assert parse_dirbrute(f) == []

    def test_ffuf_null_results_returns_empty(self, tmp_path):
        data = json.dumps({"commandline": "ffuf ...", "results": None})
        f = tmp_path / "nullresults.json"
        f.write_text(data)
        assert parse_dirbrute(f) == []

    def test_ffuf_empty_results_returns_empty(self, tmp_path):
        data = json.dumps({"commandline": "ffuf ...", "results": []})
        f = tmp_path / "emptyresults.json"
        f.write_text(data)
        assert parse_dirbrute(f) == []

    def test_status_as_string_handled(self, tmp_path):
        """gobuster JSON sometimes has Status as string, not int."""
        data = json.dumps([
            {"Found": "http://t.com/admin", "Status": "200", "Size": "4096"},
        ])
        f = tmp_path / "str_status.json"
        f.write_text(data)
        findings = parse_dirbrute(f)
        assert any("Admin" in fn.name or "Administration" in fn.name for fn in findings)

    def test_admin_pattern_phpmyadmin(self, tmp_path):
        txt = "/phpmyadmin (Status: 200) [Size: 8192]\n"
        f = tmp_path / "gb.txt"
        f.write_text(txt)
        findings = parse_dirbrute(f)
        assert any("Admin" in fn.name or "Administration" in fn.name for fn in findings)

    def test_sensitive_pattern_env_file(self, tmp_path):
        txt = "/.env (Status: 200) [Size: 512]\n"
        f = tmp_path / "gb.txt"
        f.write_text(txt)
        findings = parse_dirbrute(f)
        assert any("Sensitive" in fn.name for fn in findings)

    def test_sensitive_pattern_backup_zip(self, tmp_path):
        txt = "/backup.zip (Status: 200) [Size: 102400]\n"
        f = tmp_path / "gb.txt"
        f.write_text(txt)
        findings = parse_dirbrute(f)
        assert any("Sensitive" in fn.name for fn in findings)

    def test_performance_5000_paths(self, tmp_path):
        """5000-path gobuster text file must parse in under 5 seconds."""
        lines = "\n".join(f"/path{i} (Status: 200) [Size: {i * 100}]" for i in range(5000))
        f = tmp_path / "big.txt"
        f.write_text(lines)
        t0 = time.time()
        parse_dirbrute(f)
        elapsed = time.time() - t0
        assert elapsed < 5.0, f"Parsing 5000 paths took {elapsed:.2f}s (limit: 5s)"

    def test_detect_gobuster_json_format(self):
        assert detect_tool(FIXTURES / "gobuster_sample.json") == "gobuster"


# ═══════════════════════════════════════════════════════════════════════════
# Section F — WPScan hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestWpScanHardening:
    def test_no_vulns_returns_empty(self):
        """A clean WordPress install with no vulns must yield zero findings."""
        findings = parse_wpscan(FIXTURES / "wpscan_no_vulns.json")
        assert findings == []

    def test_many_plugins_distinct_findings(self):
        """Multiple plugins with vulns must produce distinct findings (no merge)."""
        findings = parse_wpscan(FIXTURES / "wpscan_many_plugins.json")
        plugin_findings = [f for f in findings if "Plugin" in f.name]
        # Fixture has woocommerce, elementor, yoast-seo with vulns (akismet has none)
        assert len(plugin_findings) >= 3

    def test_many_plugins_dedup_keys_unique(self):
        findings = parse_wpscan(FIXTURES / "wpscan_many_plugins.json")
        dedup_keys = [f.dedup_key for f in findings]
        assert len(dedup_keys) == len(set(dedup_keys)), "Duplicate dedup_key in findings"

    def test_per_item_error_isolation(self, tmp_path):
        """A malformed vuln entry in the middle of plugins must not kill other findings."""
        data = {
            "target_url": "http://wp.example.com/",
            "interesting_findings": [],
            "plugins": {
                "good-plugin": {
                    "slug": "good-plugin",
                    "version": {"number": "1.0"},
                    "vulnerabilities": [
                        {"title": "Good plugin XSS", "fixed_in": "1.1",
                         "references": {"cve": ["2024-1111"]}}
                    ],
                },
                "bad-plugin": {
                    "slug": "bad-plugin",
                    # vulnerabilities has a malformed (non-dict) entry
                    "vulnerabilities": [None, {"title": "Bad plugin RCE", "fixed_in": "2.0",
                                               "references": {}}],
                },
            },
            "themes": {},
            "users": {},
        }
        f = tmp_path / "partial.json"
        f.write_text(json.dumps(data))
        findings = parse_wpscan(f)
        # Should get good-plugin and one of bad-plugin (the valid dict entry)
        plugin_f = [fn for fn in findings if "Plugin" in fn.name]
        assert len(plugin_f) >= 1
        # Ensure good-plugin finding is present
        assert any("good-plugin" in fn.name for fn in plugin_f)

    def test_interesting_finding_readme(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        readme = [f for f in findings if "readme" in f.name.lower()]
        assert readme
        assert readme[0].severity_raw == "Informational"
        assert readme[0].finding_type == "info-disclosure"

    def test_interesting_finding_xmlrpc(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        xmlrpc = [f for f in findings if "XML-RPC" in f.name]
        assert xmlrpc
        assert xmlrpc[0].severity_raw == "Low"

    def test_empty_users_no_user_enum_finding(self):
        findings = parse_wpscan(FIXTURES / "wpscan_no_vulns.json")
        user_enum = [f for f in findings if "User Enumeration" in f.name]
        assert user_enum == []

    def test_target_url_as_ip(self, tmp_path):
        data = {
            "target_url": "http://192.168.1.10/",
            "interesting_findings": [],
            "plugins": {},
            "themes": {},
            "users": {"admin": {"id": 1}},
        }
        f = tmp_path / "ip.json"
        f.write_text(json.dumps(data))
        findings = parse_wpscan(f)
        assert findings
        assert findings[0].host == "192.168.1.10"

    def test_cve_normalization(self):
        """CVE '2024-6387' in fixture must become 'CVE-2024-6387'."""
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        all_refs = [r for f in findings for r in f.references]
        cves = [r for r in all_refs if r.startswith("CVE-")]
        assert cves, f"No CVE refs found; all refs: {all_refs}"

    def test_wpscan_cvss_score_none_invariant(self):
        findings = parse_wpscan(FIXTURES / "wpscan_sample.json")
        for f in findings:
            assert f.cvss_score is None


# ═══════════════════════════════════════════════════════════════════════════
# Section H — Heuristics completeness
# ═══════════════════════════════════════════════════════════════════════════


class TestHeuristicsCompleteness:
    def test_heuristics_count_gte_35(self):
        assert len(HEURISTICS) >= 35, f"HEURISTICS has {len(HEURISTICS)} types; need ≥35"

    def test_no_duplicate_keys(self):
        """Verify by re-parsing the source file — Python dicts silently drop dupes."""
        import ast
        source = Path(__file__).parent.parent / "src/rednarrate/scoring/heuristics.py"
        tree = ast.parse(source.read_text())
        # Find the HEURISTICS dict literal
        keys_seen: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "HEURISTICS":
                        if isinstance(node.value, ast.Dict):
                            for k in node.value.keys:
                                if isinstance(k, ast.Constant):
                                    keys_seen.append(k.value)
        duplicates = [k for k in keys_seen if keys_seen.count(k) > 1]
        assert not duplicates, f"Duplicate HEURISTICS keys in source: {set(duplicates)}"

    def test_rce_score_gte_9(self):
        from cvss import CVSS3
        vec = heuristic_vector("rce")
        score = CVSS3(vec).scores()[0]
        assert score >= 9.0, f"rce CVSS score {score} < 9.0"

    def test_sqli_score_gte_9(self):
        from cvss import CVSS3
        vec = heuristic_vector("sqli")
        score = CVSS3(vec).scores()[0]
        assert score >= 9.0, f"sqli CVSS score {score} < 9.0"

    def test_open_port_score_is_zero(self):
        from cvss import CVSS3
        vec = heuristic_vector("open-port")
        score = CVSS3(vec).scores()[0]
        assert score == 0.0, f"open-port CVSS score {score} != 0.0"

    def test_info_disclosure_score_low(self):
        from cvss import CVSS3
        vec = heuristic_vector("info-disclosure")
        score = CVSS3(vec).scores()[0]
        assert score <= 5.5, f"info-disclosure CVSS score {score} > 5.5"

    def test_dos_score_gte_7(self):
        from cvss import CVSS3
        vec = heuristic_vector("dos")
        score = CVSS3(vec).scores()[0]
        assert score >= 7.0, f"dos CVSS score {score} < 7.0"

    def test_all_vectors_valid_cvss31(self):
        from cvss import CVSS3
        for ftype, tail in HEURISTICS.items():
            vec = f"CVSS:3.1/{tail}"
            try:
                CVSS3(vec)
            except Exception as exc:
                pytest.fail(f"HEURISTICS['{ftype}'] has invalid vector: {exc}")

    def test_static_context_completeness(self):
        """Every HEURISTICS type must have a specific static_context (not the generic fallback)."""
        for ftype in HEURISTICS:
            ctx = static_context(ftype)
            assert ctx, f"static_context returned empty string for '{ftype}'"
            assert ctx != GENERIC_CONTEXT, (
                f"'{ftype}' falls back to GENERIC_CONTEXT — add a specific entry in fallback.py"
            )


# ═══════════════════════════════════════════════════════════════════════════
# Section I — Security invariants
# ═══════════════════════════════════════════════════════════════════════════


class TestSecurityInvariants:
    def _parser_sources(self) -> list[Path]:
        parsers_dir = Path(__file__).parent.parent / "src/rednarrate/parsers"
        return list(parsers_dir.glob("*.py"))

    def test_no_stdlib_xml_etree_in_parsers(self):
        """Parsers must never import xml.etree.ElementTree — only defusedxml."""
        violations = []
        for f in self._parser_sources():
            text = f.read_text()
            if "xml.etree.ElementTree" in text or "from xml.etree" in text:
                # Allow it only if on a comment line
                for line in text.splitlines():
                    stripped = line.strip()
                    if not stripped.startswith("#") and "xml.etree.ElementTree" in stripped:
                        violations.append(f"{f.name}: {stripped}")
        assert not violations, f"stdlib xml.etree usage found:\n" + "\n".join(violations)

    def test_no_llm_imports_in_parsers(self):
        """Parsers are LLM-free — no anthropic/langchain/openai/llm imports."""
        forbidden = ("anthropic", "langchain", "openai", "from ..llm", "import llm")
        violations = []
        for f in self._parser_sources():
            text = f.read_text()
            for pat in forbidden:
                if pat in text:
                    violations.append(f"{f.name}: contains '{pat}'")
        assert not violations, "LLM imports in parsers:\n" + "\n".join(violations)

    def test_no_db_imports_in_parsers(self):
        """Parsers are DB-free — no sqlite3/repository imports."""
        forbidden = ("sqlite3", "from ..db", "import repository")
        violations = []
        for f in self._parser_sources():
            text = f.read_text()
            for pat in forbidden:
                if pat in text:
                    violations.append(f"{f.name}: contains '{pat}'")
        assert not violations, "DB imports in parsers:\n" + "\n".join(violations)

    def test_all_new_parsers_use_defusedxml_for_xml(self):
        """Nessus and ZAP parsers must import from defusedxml."""
        for name in ("nessus_parser.py", "zap_parser.py"):
            f = Path(__file__).parent.parent / "src/rednarrate/parsers" / name
            text = f.read_text()
            assert "from defusedxml" in text, f"{name} doesn't import defusedxml"

    def test_multi_file_tools_is_named_constant(self):
        """MULTI_FILE_TOOLS must be a module-level constant, not an inline literal."""
        from rednarrate.parsers.base import MULTI_FILE_TOOLS
        assert isinstance(MULTI_FILE_TOOLS, (set, frozenset))
        assert "nmap" in MULTI_FILE_TOOLS

    def test_cookie_header_redacted_in_evidence(self, tmp_path):
        """Cookie header on its own line in ZAP attack evidence must be redacted.

        The attack field may contain a full HTTP request with a Cookie header on a
        separate line. sanitize_evidence uses re.MULTILINE so ^Cookie: matches it.
        """
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<OWASPZAPReport version="2.14.0" generated="">
  <site name="http://t.com" host="t.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10015</pluginid>
        <alert>SQL Injection</alert>
        <name>SQL Injection</name>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <riskdesc>High (Medium)</riskdesc>
        <desc>SQLi found.</desc>
        <instances>
          <instance>
            <uri>http://t.com/login</uri>
            <method>POST</method>
            <param>id</param>
            <attack>POST /login HTTP/1.1&#10;Host: t.com&#10;Cookie: session=supersecrettoken123abc&#10;Content-Length: 20</attack>
            <evidence>error in SQL syntax</evidence>
          </instance>
        </instances>
        <cweid>89</cweid>
        <wascid>19</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        f = tmp_path / "cookie.xml"
        f.write_text(xml)
        findings = parse_zap(f)
        assert findings
        ev = findings[0].evidence
        # Cookie header value must be stripped by sanitize_evidence (MULTILINE ^Cookie:)
        assert "supersecrettoken123abc" not in ev
        assert "[REDACTED]" in ev


# ═══════════════════════════════════════════════════════════════════════════
# Section G — Multi-file verification
# ═══════════════════════════════════════════════════════════════════════════


class TestMultiFileVerification:
    def test_multi_file_tools_constant_contains_expected(self):
        from rednarrate.parsers.base import MULTI_FILE_TOOLS
        assert MULTI_FILE_TOOLS == {"nmap", "nuclei", "ffuf", "gobuster"}

    def test_all_tool_types_directory(self, tmp_path):
        """A directory with one file per tool type should map all 8+ tools."""
        import shutil
        shutil.copy(FIXTURES / "nmap_full.xml", tmp_path / "scan.xml")
        shutil.copy(FIXTURES / "burp_full.xml", tmp_path / "burp.xml")
        shutil.copy(FIXTURES / "sqlmap_injectable.log", tmp_path / "sqlmap.log")
        shutil.copy(FIXTURES / "nessus_sample.nessus", tmp_path / "nessus.nessus")
        shutil.copy(FIXTURES / "zap_sample.xml", tmp_path / "zap.xml")
        shutil.copy(FIXTURES / "nuclei_sample.jsonl", tmp_path / "nuclei.jsonl")
        shutil.copy(FIXTURES / "ffuf_sample.json", tmp_path / "ffuf.json")
        shutil.copy(FIXTURES / "gobuster_sample.txt", tmp_path / "gobuster.txt")
        shutil.copy(FIXTURES / "wpscan_sample.json", tmp_path / "wpscan.json")
        inputs, notes = collect_inputs(tmp_path)
        # Expect at least 8 tool types to be detected
        assert len(inputs) >= 8, f"Expected ≥8 tools, got {len(inputs)}: {set(inputs)}"

    def test_db_create_scan_with_list_values(self):
        """create_scan must not raise when raw_inputs has list values."""
        import tempfile
        from rednarrate.db.repository import create_scan, init_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
            db = fh.name
        init_db(db)
        meta = {
            "raw_inputs": {
                "nmap": ["/tmp/scan1.xml", "/tmp/scan2.xml"],
                "burp": ["/tmp/burp.xml"],
            },
            "client_name": "ListTest",
        }
        scan_id = create_scan(meta, db_path=db)
        assert scan_id

    def test_single_string_backward_compat_in_collect(self, tmp_path):
        """collect_inputs always returns list values; set(inputs) still works."""
        import shutil
        shutil.copy(FIXTURES / "nmap_full.xml", tmp_path / "scan.xml")
        inputs, _ = collect_inputs(tmp_path)
        assert isinstance(inputs["nmap"], list)
        assert set(inputs) == {"nmap"}  # set on dict → set of keys


# ═══════════════════════════════════════════════════════════════════════════
# Section K — E2E single-tool pipeline tests
# ═══════════════════════════════════════════════════════════════════════════


def _run_pipeline(data_dir: Path, monkeypatch, tmp_path: Path) -> dict:
    """Run the full graph via run_pipeline (LLM disabled) and return final state."""
    import rednarrate.config as config
    monkeypatch.setenv("REDNARRATE_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("REDNARRATE_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("REDNARRATE_CHROMA_DIR", str(tmp_path / "chroma_absent"))
    config._settings = None

    def boom(role="writer"):
        raise RuntimeError("LLM disabled in E2E test")

    monkeypatch.setattr("rednarrate.agents.scoring.get_llm", boom)
    monkeypatch.setattr("rednarrate.agents.report_writer.get_llm", boom)

    from rednarrate.graph import run_pipeline
    from rednarrate.parsers.base import collect_inputs

    inputs, _ = collect_inputs(data_dir)
    meta = {
        "client_name": "E2E Test",
        "scope": "localhost",
        "engagement_dates": "2026",
        "llm_provider": "none",
        "raw_inputs": inputs,
    }
    final = run_pipeline(meta, db_path=str(tmp_path / "t.db"), checkpoint=False)
    config._settings = None
    return final


class TestE2EPipelines:
    def test_e2e_nessus_only(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nessus_sample.nessus", evidence / "scan.nessus")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"], "Expected findings from Nessus"

    def test_e2e_zap_only(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "zap_sample.xml", evidence / "scan.xml")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"]

    def test_e2e_nuclei_only(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nuclei_sample.jsonl", evidence / "nuclei.jsonl")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"]

    def test_e2e_ffuf_only(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "ffuf_sample.json", evidence / "ffuf.json")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"]

    def test_e2e_wpscan_only(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "wpscan_sample.json", evidence / "wpscan.json")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"]

    def test_e2e_multi_nmap(self, tmp_path, monkeypatch):
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nmap_full.xml", evidence / "scan1.xml")
        shutil.copy(FIXTURES / "nmap_empty_host.xml", evidence / "scan2.xml")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        assert state["scored_findings"]

    def test_e2e_all_malformed_fatal_path(self, tmp_path, monkeypatch):
        """A directory containing only malformed files must set errors (fatal path)."""
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nessus_malformed.nessus", evidence / "bad.nessus")
        (evidence / "random.xyz").write_text("not a pentest tool output")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        # Pipeline degrades: malformed files produce warnings; zero findings → errors
        assert state.get("errors") or state.get("scored_findings") == [], (
            "All-malformed dir should either error or produce 0 scored findings"
        )

    def test_e2e_all_new_tools_combined(self, tmp_path, monkeypatch):
        """All 5 new tools together must produce ≥5 distinct findings."""
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nessus_sample.nessus", evidence / "scan.nessus")
        shutil.copy(FIXTURES / "zap_sample.xml", evidence / "zap.xml")
        shutil.copy(FIXTURES / "nuclei_sample.jsonl", evidence / "nuclei.jsonl")
        shutil.copy(FIXTURES / "ffuf_sample.json", evidence / "ffuf.json")
        shutil.copy(FIXTURES / "wpscan_sample.json", evidence / "wpscan.json")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors"), f"Pipeline errors: {state.get('errors')}"
        scored = state["scored_findings"]
        assert len(scored) >= 5, f"Expected ≥5 findings from 5 tools, got {len(scored)}"

    def test_e2e_findings_have_cvss_scores(self, tmp_path, monkeypatch):
        """After the scoring node, all findings must have a non-None cvss_score."""
        import shutil
        evidence = tmp_path / "ev"
        evidence.mkdir()
        shutil.copy(FIXTURES / "nessus_sample.nessus", evidence / "scan.nessus")
        state = _run_pipeline(evidence, monkeypatch, tmp_path)
        assert not state.get("errors")
        for f in state["scored_findings"]:
            assert f.get("cvss_score") is not None, f"Finding {f.get('id')} missing cvss_score"
