from rednarrate.parsers import ParserError
from rednarrate.parsers.sqlmap_parser import parse_sqlmap


def test_parses_injection(fx):
    findings = parse_sqlmap(fx("sqlmap_injectable.log"))
    assert len(findings) == 1  # multiple techniques on one param -> one finding
    f = findings[0]
    assert f.finding_type == "sqli"
    assert f.parameter == "username"
    assert f.host == "target.com"
    assert f.port == 443
    assert "CWE-89" in f.references


def test_captures_dbms_and_exfil(fx):
    f = parse_sqlmap(fx("sqlmap_injectable.log"))[0]
    assert "MySQL" in f.evidence
    assert "EXFILTRAT" in f.evidence.upper()  # table dump detected


def test_techniques_merged(fx):
    f = parse_sqlmap(fx("sqlmap_injectable.log"))[0]
    # boolean, error, and time-based all on 'username' -> mentioned together
    assert "boolean-based" in f.name or "boolean" in f.evidence.lower()


def test_clean_run_is_empty(fx):
    findings = parse_sqlmap(fx("sqlmap_clean.log"))
    assert findings == []


def test_non_sqlmap_raises(tmp_path):
    bad = tmp_path / "x.log"
    bad.write_text("just some random text without sqlmap markers")
    try:
        parse_sqlmap(bad)
    except ParserError:
        return
    raise AssertionError("expected ParserError on non-sqlmap log")
