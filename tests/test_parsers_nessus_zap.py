"""Tests for Nessus and ZAP parsers (fixture-based, LLM-free)."""

from pathlib import Path

import pytest

from rednarrate.parsers.base import ParserError, detect_tool
from rednarrate.parsers.nessus_parser import parse_nessus
from rednarrate.parsers.zap_parser import parse_zap

FIXTURES = Path(__file__).parent / "fixtures"


# ── Nessus ───────────────────────────────────────────────────────────


class TestNessusParser:
    def test_parses_findings(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        assert len(findings) == 4  # 3 vuln items + 1 info item

    def test_severity_mapping(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        sev_map = {f.finding_type: f.severity_raw for f in findings}
        assert sev_map.get("weak-crypto") == "High"        # severity=3
        assert sev_map.get("anonymous-access") == "Medium"  # severity=2
        assert sev_map.get("default-credentials") == "Critical"  # severity=4

    def test_finding_type_detection(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        ftypes = {f.finding_type for f in findings}
        assert "weak-crypto" in ftypes          # SSL poodle detection
        assert "anonymous-access" in ftypes     # FTP anon
        assert "default-credentials" in ftypes  # MySQL empty password

    def test_cve_refs_extracted(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        ssl_finding = next(f for f in findings if f.finding_type == "weak-crypto")
        assert "CVE-2014-3566" in ssl_finding.references

    def test_cwe_xref_normalized(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        ftp_finding = next(f for f in findings if f.finding_type == "anonymous-access")
        assert "CWE-306" in ftp_finding.references

    def test_host_and_port(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        for f in findings:
            assert f.host == "192.168.10.20"

    def test_dedup_key_format(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        for f in findings:
            assert f.dedup_key.startswith("192.168.10.20:")

    def test_evidence_populated(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        ssl_finding = next(f for f in findings if f.finding_type == "weak-crypto")
        assert "SSLv3" in ssl_finding.evidence

    def test_source_tool_is_nessus(self):
        findings = parse_nessus(FIXTURES / "nessus_sample.nessus")
        assert all(f.source_tool == "nessus" for f in findings)

    def test_malformed_raises_parser_error(self):
        with pytest.raises(ParserError):
            parse_nessus(FIXTURES / "nessus_malformed.nessus")

    def test_wrong_root_raises(self, tmp_path):
        f = tmp_path / "bad.nessus"
        f.write_text('<?xml version="1.0"?><root><child/></root>')
        with pytest.raises(ParserError, match="Not a Nessus"):
            parse_nessus(f)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises((ParserError, FileNotFoundError, OSError)):
            parse_nessus(tmp_path / "absent.nessus")


# ── ZAP ──────────────────────────────────────────────────────────────


class TestZapParser:
    def test_parses_findings(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        assert len(findings) == 4

    def test_severity_mapping(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        sev_map = {f.name: f.severity_raw for f in findings}
        assert sev_map["Cross Site Scripting (Reflected)"] == "High"
        assert sev_map["Absence of Anti-CSRF Tokens"] == "Medium"
        assert sev_map["Loosely Scoped Cookie"] == "Informational"

    def test_finding_type_from_cwe(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        ftypes = {f.finding_type for f in findings}
        assert "xss-reflected" in ftypes   # CWE-79
        assert "csrf" in ftypes            # CWE-352
        assert "missing-security-headers" in ftypes  # CWE-693

    def test_cwe_in_references(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        xss = next(f for f in findings if f.finding_type == "xss-reflected")
        assert "CWE-79" in xss.references

    def test_param_extracted(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        xss = next(f for f in findings if f.finding_type == "xss-reflected")
        assert xss.parameter == "q"

    def test_url_extracted(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        xss = next(f for f in findings if f.finding_type == "xss-reflected")
        assert xss.url and "target.com" in xss.url

    def test_instance_count(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        csp = next(f for f in findings if f.finding_type == "missing-security-headers")
        assert csp.instances == 2

    def test_host_and_port(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        for f in findings:
            assert f.host == "target.com"
            assert f.port == 443

    def test_dedup_key_format(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        for f in findings:
            assert f.dedup_key.startswith("target.com:443:")

    def test_evidence_contains_attack(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        xss = next(f for f in findings if f.finding_type == "xss-reflected")
        assert "alert(1)" in xss.evidence

    def test_source_tool_is_zap(self):
        findings = parse_zap(FIXTURES / "zap_sample.xml")
        assert all(f.source_tool == "zap" for f in findings)

    def test_malformed_raises_parser_error(self):
        with pytest.raises(ParserError):
            parse_zap(FIXTURES / "zap_malformed.xml")

    def test_wrong_root_raises(self, tmp_path):
        f = tmp_path / "bad.xml"
        f.write_text('<?xml version="1.0"?><root><child/></root>')
        with pytest.raises(ParserError, match="Not a ZAP"):
            parse_zap(f)


# ── detect_tool ──────────────────────────────────────────────────────


class TestDetectTool:
    def test_detects_nessus(self):
        assert detect_tool(FIXTURES / "nessus_sample.nessus") == "nessus"

    def test_detects_zap(self):
        assert detect_tool(FIXTURES / "zap_sample.xml") == "zap"

    def test_detects_nmap(self):
        assert detect_tool(FIXTURES / "nmap_full.xml") == "nmap"

    def test_detects_burp(self):
        assert detect_tool(FIXTURES / "burp_full.xml") == "burp"

    def test_detects_sqlmap(self):
        assert detect_tool(FIXTURES / "sqlmap_injectable.log") == "sqlmap"

    def test_unknown_returns_none(self, tmp_path):
        f = tmp_path / "junk.csv"
        f.write_text("col1,col2\nval1,val2")
        assert detect_tool(f) is None


# ── new heuristic types are valid CVSS3 ──────────────────────────────


def test_new_heuristic_types_valid():
    from cvss import CVSS3
    from rednarrate.scoring.heuristics import HEURISTICS, heuristic_vector

    for ft in ("unrestricted-file-upload", "ssti", "privilege-escalation", "web-issue", "dos"):
        assert ft in HEURISTICS, f"{ft} missing from HEURISTICS"
        CVSS3(heuristic_vector(ft))  # raises if malformed


# ── new static context entries ────────────────────────────────────────


def test_new_static_context_entries():
    from rednarrate.rag.fallback import static_context
    for ft in ("unrestricted-file-upload", "ssti", "privilege-escalation", "web-issue", "dos"):
        ctx = static_context(ft)
        assert isinstance(ctx, str) and len(ctx) > 50, f"thin context for {ft}"
