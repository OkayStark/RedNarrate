from rednarrate.parsers import ParserError
from rednarrate.parsers.nmap_parser import extract_hosts, parse_nmap


def test_parses_open_services(fx):
    findings = parse_nmap(fx("nmap_full.xml"))
    open_ports = [f for f in findings if f.finding_type == "open-port"]
    assert {f.port for f in open_ports} == {22, 80, 443}
    ssh = next(f for f in open_ports if f.port == 22)
    assert ssh.source_tool == "nmap"
    assert ssh.host == "10.0.0.5"
    assert any("openssh" in r.lower() for r in ssh.references)


def test_emits_nse_vuln_finding(fx):
    findings = parse_nmap(fx("nmap_full.xml"))
    poodle = [f for f in findings if "poodle" in f.finding_type or "poodle" in f.name.lower()]
    assert poodle, "expected an ssl-poodle finding from the NSE script"


def test_truncated_scan_still_parses(fx):
    # Missing closing tags — libnmap incomplete parse should still yield services.
    findings = parse_nmap(fx("nmap_truncated.xml"))
    assert any(f.port == 21 for f in findings)


def test_down_host_yields_no_findings(fx):
    findings = parse_nmap(fx("nmap_empty_host.xml"))
    assert findings == []


def test_host_inventory(fx):
    hosts = extract_hosts(fx("nmap_full.xml"))
    assert "10.0.0.5" in hosts
    assert "target.com" in hosts["10.0.0.5"]["hostnames"]
    ports = {p["port"] for p in hosts["10.0.0.5"]["open_ports"]}
    assert {22, 80, 443} <= ports


def test_garbage_raises(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("not xml at all")
    try:
        parse_nmap(bad)
    except ParserError:
        return
    raise AssertionError("expected ParserError on non-nmap input")
