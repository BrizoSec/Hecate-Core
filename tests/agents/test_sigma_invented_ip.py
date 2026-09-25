"""An exact IPv4 address in a rule must come from the intelligence."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _invented_ip_problem,
)

SUPPLIED = {"IPv4": ["166.88.134.62", "23.27.13.135"], "domain": ["pipicka.xyz"]}


def _sel(value: Any, field: str = "DestinationIp") -> Dict[str, Any]:
    return {"selection": {field: value}, "condition": "selection"}


@pytest.mark.parametrize("invented", ["1.2.3.4", "8.8.8.8", "203.0.113.99", "10.0.0.5"])
def test_an_address_no_intel_named_is_rejected(invented: str) -> None:
    """1.2.3.4 reached a live phishing hunt; 8.8.8.8 a DNS-exfiltration one."""
    problem = _invented_ip_problem(_sel(invented), SUPPLIED, [])
    assert problem is not None and invented in problem


def test_a_supplied_indicator_passes() -> None:
    assert _invented_ip_problem(_sel(["166.88.134.62", "23.27.13.135"]), SUPPLIED, []) is None


def test_one_invented_address_among_real_ones_is_still_rejected() -> None:
    assert _invented_ip_problem(_sel(["166.88.134.62", "1.2.3.4"]), SUPPLIED, []) is not None


def test_an_address_the_drafts_observables_name_passes() -> None:
    """Grounded research can surface a C2 address the CTI summary lacked."""
    observables = ["Outbound connections to 45.9.148.10 on port 443"]
    assert _invented_ip_problem(_sel("45.9.148.10"), {}, observables) is None


def test_an_observable_must_name_the_whole_address() -> None:
    """45.9.148.1 is not vouched for by an observable naming 45.9.148.10."""
    observables = ["Outbound connections to 45.9.148.10"]
    assert _invented_ip_problem(_sel("45.9.148.1"), {}, observables) is not None


def test_an_address_with_a_port_is_judged_by_its_address() -> None:
    assert _invented_ip_problem(_sel("166.88.134.62:443"), SUPPLIED, []) is None
    assert _invented_ip_problem(_sel("1.2.3.4:443"), SUPPLIED, []) is not None


def test_an_exclusion_filter_is_not_judged() -> None:
    detection = {
        "selection": {"DestinationIp": "166.88.134.62"},
        "filter": {"SourceIp": "127.0.0.1"},
        "condition": "selection and not filter",
    }
    assert _invented_ip_problem(detection, SUPPLIED, []) is None


@pytest.mark.parametrize("behavioural", ["192.168.", "10.0.0.0/8", ".133", "443"])
def test_prefixes_ranges_and_non_addresses_pass(behavioural: str) -> None:
    assert _invented_ip_problem(_sel(behavioural), SUPPLIED, []) is None


def test_the_full_build_rejects_it_with_a_reason() -> None:
    raw = {
        "logsource_category": "network_connection",
        "title": "C2 beacon",
        "detection": {"selection": {"DestinationIp": "1.2.3.4"}, "condition": "selection"},
    }
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    rule, problem = agent._build_rule(
        raw,
        SigmaGenerationInput(hypothesis="phishing", hunt_id="H-0009", platforms=["Windows"], indicators={}),
    )
    assert rule is None
    assert problem is not None and "network_connection" in problem and "1.2.3.4" in problem
