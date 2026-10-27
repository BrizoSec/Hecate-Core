"""Deterministic DNS and network IOC rules, built from supplied indicators alone.

Both DNS rules in the 25 Sep review were rejected (the model matched '.com' and
'.xyz'), so hunts with supplied C2 domains had no DNS coverage; the model's
network rule used 1 of 8 supplied domains and missed the apex it pointed at.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import patch

import yaml

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _pysigma_problem,
    network_selectors,
)


def _rules(indicators: Dict[str, List[str]], platforms: List[str] | None = None) -> Dict[str, Any]:
    """{category: parsed rule} for the deterministic rules only."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with (
        patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})),
        patch.object(agent, "_get_provider") as provider,
    ):
        provider.return_value.provider_name = "test"
        result = agent.execute(
            SigmaGenerationInput(
                hypothesis="h",
                hunt_id="H-0012",
                platforms=platforms if platforms is not None else ["Windows"],
                indicators=indicators,
                logsources=["process_creation"],
            )
        )
    rules = [r for r in (result.data.rules if result.data else []) if "source intelligence" in r.title]
    return {r.logsource_category: yaml.safe_load(r.rule_yaml) for r in rules}


class TestNetworkSelectors:
    def test_both_providers_spellings(self) -> None:
        addresses, names, suffixes = network_selectors(
            {
                "IPv4": ["104.225.153.141"],
                "ip-dst|port": ["74.48.66.73|443"],
                "domain": ["Readonline365.com"],
                "hostname": ["p3.981666.xyz"],
                "URL": ["https://onlineview365.com/propi.msi"],
            }
        )
        assert addresses == ["104.225.153.141", "74.48.66.73"]
        assert names == ["readonline365.com", "p3.981666.xyz", "onlineview365.com"]
        # Only registrable domains get a subdomain suffix; hostnames stay exact.
        assert suffixes == [".readonline365.com"]

    def test_private_and_malformed_values_are_dropped(self) -> None:
        addresses, names, _ = network_selectors(
            {"ip-dst": ["10.0.0.5", "192.168.1.1", "not-an-ip"], "domain": ["no_tld", "-bad-.com"]}
        )
        assert addresses == [] and names == []

    def test_a_url_on_a_bare_address_is_an_address(self) -> None:
        addresses, names, _ = network_selectors({"url": ["http://45.9.148.10:8080/gate.php"]})
        assert addresses == ["45.9.148.10"] and names == []

    def test_domain_ip_pairs_contribute_both(self) -> None:
        addresses, names, _ = network_selectors({"domain|ip": ["evil-cdn.net|45.9.148.10"]})
        assert addresses == ["45.9.148.10"] and names == ["evil-cdn.net"]


def test_darkme_domains_get_dns_and_network_rules() -> None:
    """H-0012: eight domains and two URLs, none of which reached a DNS rule."""
    rules = _rules(
        {
            "domain": ["readonline365.com", "onlineview365.com"],
            "URL": ["https://readonline365.com/view/image.png"],
        }
    )
    dns = rules["dns_query"]["detection"]
    assert dns["selection_exact"]["QueryName"] == ["readonline365.com", "onlineview365.com"]
    assert dns["selection_subdomain"]["QueryName|endswith"] == [".readonline365.com", ".onlineview365.com"]
    assert dns["condition"] == "1 of selection_*"
    net = rules["network_connection"]["detection"]
    # The apex itself is matched: the model's `endswith .readonline365.com` was not.
    assert "readonline365.com" in net["selection_host"]["DestinationHostname"]
    assert rules["network_connection"]["level"] == "high"


def test_kapibala_addresses_and_host() -> None:
    rules = _rules(
        {"IPv4": ["104.225.153.141", "74.48.66.73", "172.245.247.21"], "hostname": ["p3.981666.xyz"]},
        platforms=["Linux"],
    )
    net = rules["network_connection"]
    assert net["detection"]["selection_address"]["DestinationIp"] == [
        "104.225.153.141",
        "74.48.66.73",
        "172.245.247.21",
    ]
    assert net["logsource"]["product"] == "linux"
    assert "selection_subdomain" not in rules["dns_query"]["detection"]  # hostname: exact only
    assert "subdomain" not in rules["dns_query"]["description"]  # and the description says so


def test_every_rule_is_valid_sigma_and_carries_the_hunt() -> None:
    rules = _rules({"IPv4": ["104.225.153.141"], "domain": ["pipicka.xyz"], "md5": ["a" * 32]})
    assert set(rules) == {"process_creation", "dns_query", "network_connection"}
    for rule in rules.values():
        assert rule["hunt_id"] == "H-0012"
        assert _pysigma_problem(yaml.safe_dump(rule)) is None


def test_no_network_indicators_means_no_network_rules() -> None:
    assert _rules({"md5": ["a" * 32]}).keys() == {"process_creation"}
    assert _rules({"ip-dst": ["10.0.0.5"]}) == {}


def test_dual_use_network_binding_prevents_bare_sweeps() -> None:
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with (
        patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})),
        patch.object(agent, "_get_provider") as provider,
    ):
        provider.return_value.provider_name = "test"
        result = agent.execute(
            SigmaGenerationInput(
                hypothesis="Threat actor exfiltrates data using svchost_sync.exe to S3",
                hunt_id="H-0808",
                threat_intel="Living-off-the-Cloud exfiltration: svchost_sync.exe copy to s3.us-east-1.amazonaws.com",
                platforms=["Windows"],
                indicators={
                    "ipv4": ["194.26.29.112", "52.216.148.130"],
                    "domain": ["evil-c2.net", "s3.us-east-1.amazonaws.com"],
                },
                logsources=["process_creation"],
            )
        )
    assert result.success is True
    rules = [yaml.safe_load(r.rule_yaml) for r in (result.data.rules if result.data else [])]

    # DNS rule matches only direct C2, never dual-use S3
    dns_rules = [r for r in rules if r.get("logsource", {}).get("category") == "dns_query"]
    assert len(dns_rules) == 1
    dns_det = dns_rules[0]["detection"]
    assert "evil-c2.net" in dns_det["selection_exact"]["QueryName"]
    assert "s3.us-east-1.amazonaws.com" not in str(dns_det)

    # Network connection rules: one bare sweep for direct C2, one process-bound for S3
    net_rules = [r for r in rules if r.get("logsource", {}).get("category") == "network_connection"]
    assert len(net_rules) == 2

    bare_net = next(r for r in net_rules if "Dual-Use" not in r["title"])
    dual_net = next(r for r in net_rules if "Dual-Use" in r["title"])

    # Bare sweep has only direct C2
    assert "194.26.29.112" in bare_net["detection"]["selection_address"]["DestinationIp"]
    assert "52.216.148.130" not in str(bare_net["detection"])
    assert "s3.us-east-1.amazonaws.com" not in str(bare_net["detection"])

    # Dual-use rule has process binding and matches S3 indicators
    assert "52.216.148.130" in dual_net["detection"]["selection_dest_ip"]["DestinationIp"]
    assert "s3.us-east-1.amazonaws.com" in dual_net["detection"]["selection_dest_host"]["DestinationHostname"]
    assert "selection_process" in dual_net["detection"]
    assert "\\svchost_sync.exe" in dual_net["detection"]["selection_process"]["Image|endswith"]
    assert "(1 of selection_dest_*) and selection_process" in dual_net["detection"]["condition"]



def test_a_dual_use_set_of_url_paths_yields_no_connection_rule() -> None:
    """H-0830's typed dual-use indicators were four URL paths; the rule kept a
    condition naming selection_dest_* with no selection behind it."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    paths = ["/logon/LogonPoint/tmindex.html", "/vpn/index.html"]
    with (
        patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})),
        patch.object(agent, "_get_provider") as provider,
    ):
        provider.return_value.provider_name = "test"
        result = agent.execute(
            SigmaGenerationInput(
                hypothesis="h",
                hunt_id="H-0013",
                platforms=["Network Devices"],
                indicators={"ipv4": ["209.141.43.95"], "url": paths},
                indicator_records=[
                    {"value": "209.141.43.95", "type": "ipv4", "role": "download", "status": "active"},
                    *({"value": p, "type": "url", "role": "dual_use", "status": "active"} for p in paths),
                ],
                logsources=["process_creation"],
            )
        )
    rules = [yaml.safe_load(r.rule_yaml) for r in (result.data.rules if result.data else [])]
    assert not [r for r in rules if "Dual-Use" in r["title"]]
    for rule in rules:
        names = {k for k in rule["detection"] if k != "condition"}
        if "selection_dest_*" in rule["detection"]["condition"]:
            assert any(n.startswith("selection_dest_") for n in names)
        assert not any(p in str(rule["detection"]) for p in paths)


def test_attack_sources_get_inbound_rules_not_the_outbound_sweep() -> None:
    """H-0830: the report's exploitation "Source IPs" were swept as outbound destinations."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with (
        patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})),
        patch.object(agent, "_get_provider") as provider,
    ):
        provider.return_value.provider_name = "test"
        result = agent.execute(
            SigmaGenerationInput(
                hypothesis="h",
                hunt_id="H-0014",
                platforms=["Network Devices"],
                indicators={"ipv4": ["45.153.212.101", "209.141.43.95"]},
                indicator_records=[
                    {"value": "45.153.212.101", "type": "ipv4", "role": "inbound", "status": "active"},
                    {"value": "209.141.43.95", "type": "ipv4", "role": "download", "status": "active"},
                ],
                logsources=["process_creation"],
            )
        )
    rules = {r.title: yaml.safe_load(r.rule_yaml) for r in (result.data.rules if result.data else [])}
    web = rules["Web request from an address the source names as an attack source"]
    assert web["logsource"] == {"category": "webserver"}
    assert web["detection"]["selection"] == {"c-ip": ["45.153.212.101"]}
    accepted = rules["Inbound connection from an address the source names as an attack source"]
    assert accepted["detection"]["selection"] == {"SourceIp": ["45.153.212.101"], "Initiated": "false"}
    outbound = rules["Connection to an address or host named in the source intelligence"]
    assert "45.153.212.101" not in str(outbound["detection"])
    assert "209.141.43.95" in str(outbound["detection"])
