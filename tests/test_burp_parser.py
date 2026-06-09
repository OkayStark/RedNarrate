from rednarrate.parsers import ParserError
from rednarrate.parsers.burp_parser import parse_burp


def test_parses_sqli_issue(fx):
    findings = parse_burp(fx("burp_full.xml"))
    sqli = next(f for f in findings if f.finding_type == "sqli")
    assert sqli.host == "10.0.0.5"
    assert sqli.port == 443
    assert sqli.parameter == "username"
    assert sqli.severity_raw == "High"
    assert sqli.confidence == "Certain"
    assert "/login" in sqli.dedup_key


def test_decodes_base64_request(fx):
    findings = parse_burp(fx("burp_full.xml"))
    sqli = next(f for f in findings if f.finding_type == "sqli")
    # base64 request decodes to text containing the HTTP verb.
    assert "POST" in sqli.evidence


def test_information_issue_kept(fx):
    findings = parse_burp(fx("burp_full.xml"))
    info = [f for f in findings if (f.severity_raw or "").lower() == "information"]
    assert info, "Information-severity issues must be retained for the scoring shortcut"


def test_type_mapping(fx):
    findings = parse_burp(fx("burp_full.xml"))
    types = {f.finding_type for f in findings}
    assert "sqli" in types
    assert "xss-reflected" in types


def test_plain_request_no_b64(fx):
    findings = parse_burp(fx("burp_no_b64.xml"))
    cmd = next(f for f in findings if f.finding_type == "os-command-injection")
    assert cmd.parameter == "host"
    assert "uid=" in cmd.evidence


def test_malformed_raises(fx):
    try:
        parse_burp(fx("burp_malformed.xml"))
    except ParserError:
        return
    raise AssertionError("expected ParserError on malformed Burp XML")
