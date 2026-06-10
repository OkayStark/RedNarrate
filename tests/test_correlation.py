"""Correlation tests run with the LLM disabled (llm_provider not in the cloud/
ollama set) so they exercise only the deterministic dedup + rule-chain paths."""

from rednarrate.agents.correlation import correlation_node, dedup_key
from rednarrate.parsers.burp_parser import parse_burp
from rednarrate.parsers.nmap_parser import extract_hosts, parse_nmap
from rednarrate.parsers.sqlmap_parser import parse_sqlmap


def _state(fx):
    findings = []
    for f in parse_nmap(fx("nmap_full.xml")):
        findings.append(f.model_dump())
    for f in parse_burp(fx("burp_full.xml")):
        findings.append(f.model_dump())
    for f in parse_sqlmap(fx("sqlmap_injectable.log")):
        findings.append(f.model_dump())
    return {
        "parsed_findings": findings,
        "hosts": extract_hosts(fx("nmap_full.xml")),
        "llm_provider": "none",  # disable the chain LLM call
    }


def test_cross_tool_sqli_merge(fx):
    out = correlation_node(_state(fx))
    sqli = [f for f in out["correlated_findings"] if f["finding_type"] == "sqli"]
    # Burp (10.0.0.5:443) and sqlmap (target.com->10.0.0.5:443) collapse to one.
    assert len(sqli) == 1
    merged = sqli[0]
    assert "burp" in merged["source_tool"] and "sqlmap" in merged["source_tool"]
    assert merged["instances"] == 2


def test_dedup_key_resolves_hostname_to_ip(fx):
    hosts = extract_hosts(fx("nmap_full.xml"))
    burp_sqli = next(
        f.model_dump() for f in parse_burp(fx("burp_full.xml")) if f.finding_type == "sqli"
    )
    sqlmap_sqli = parse_sqlmap(fx("sqlmap_injectable.log"))[0].model_dump()
    assert dedup_key(burp_sqli, hosts) == dedup_key(sqlmap_sqli, hosts)


def test_rule_chain_exposure_to_exploitation(fx):
    out = correlation_node(_state(fx))
    chains = out["attack_chains"]
    assert chains, "expected at least one rule-based chain"
    # The SQLi-with-dump should produce an exfiltration chain.
    assert any("exfiltrat" in c["name"].lower() for c in chains)


def test_chain_members_marked(fx):
    out = correlation_node(_state(fx))
    chain_ids = {fid for c in out["attack_chains"] for fid in c["finding_ids"]}
    for f in out["correlated_findings"]:
        assert f["is_chain_member"] == (f["id"] in chain_ids)
