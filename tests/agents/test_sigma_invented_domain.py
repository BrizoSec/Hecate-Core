"""An exact domain in a rule must come from the intelligence."""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _invented_domain_problem,
    _registered_name,
)

SUPPLIED = {"domain": ["pipicka.xyz", "grenight.com"], "hostname": ["api.grenight.com"]}


def _sel(value: Any, field: str = "QueryName") -> Dict[str, Any]:
    return {"selection": {field: value}, "condition": "selection"}


def _problem(value: Any, field: str = "QueryName", context: List[str] | None = None) -> Any:
    return _invented_domain_problem(_sel(value, field), SUPPLIED, context or [])


@pytest.mark.parametrize("invented", ["malicious-c2.net", "update-server.com", "evil.example.org"])
def test_a_domain_nothing_names_is_rejected(invented: str) -> None:
    problem = _problem(invented)
    assert problem is not None and invented in problem


def test_a_supplied_domain_passes_in_any_host_field() -> None:
    assert _problem("pipicka.xyz") is None
    assert _problem("api.grenight.com", field="DestinationHostname") is None


def test_a_suffix_idiom_is_judged_on_the_domain() -> None:
    """H-0012's rule: DestinationHostname|endswith .grenight.com."""
    assert _problem(".grenight.com", field="DestinationHostname|endswith") is None
    assert _problem("*.evil-cdn.net", field="QueryName|endswith") is not None


def test_a_real_service_the_intel_names_passes() -> None:
    """A Telegram-controlled backdoor hunting api.telegram.org is behaviour,
    not an invented indicator, even though the CTI never spells the host."""
    context = ["Adversaries use a Telegram-based backdoor for command and control"]
    assert _problem("api.telegram.org", field="DestinationHostname", context=context) is None
    assert _problem("api.telegram.org", field="DestinationHostname") is not None


def test_a_registered_name_must_be_a_whole_word() -> None:
    """'gram' in 'Telegram' does not vouch for gram.example-cdn.net."""
    assert _problem("x.gram.net", context=["Telegram-based backdoor"]) is not None


def test_url_fields_are_judged_by_their_host() -> None:
    assert _problem("https://pipicka.xyz/gate.php", field="c-uri") is None
    assert _problem("http://payload-host.net/x.exe", field="c-uri") is not None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("TargetFilename|endswith", "update.bin"),  # filename, not a host field
        ("Image|endswith", "\\\\svchost.exe"),
        ("QueryName|endswith", ".xyz"),  # bare TLD: the fragment check's job
        ("QueryName", "localhost"),  # single label, not a domain
    ],
)
def test_non_domains_and_non_host_fields_pass(field: str, value: str) -> None:
    assert _problem(value, field=field) is None


def test_an_exclusion_filter_is_not_judged() -> None:
    detection = {
        "selection": {"QueryName": "pipicka.xyz"},
        "filter": {"QueryName|endswith": ".microsoft.com"},
        "condition": "selection and not filter",
    }
    assert _invented_domain_problem(detection, SUPPLIED, []) is None


@pytest.mark.parametrize(
    ("domain", "name"),
    [("api.telegram.org", "telegram"), ("www.example.co.uk", "example"), ("pipicka.xyz", "pipicka")],
)
def test_registered_name(domain: str, name: str) -> None:
    assert _registered_name(domain) == name


def test_the_full_build_rejects_it_and_the_hypothesis_counts_as_context() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)

    def build(host: str, hypothesis: str) -> Any:
        raw = {
            "logsource_category": "dns_query",
            "title": "C2 lookup",
            "detection": {"selection": {"QueryName": host}, "condition": "selection"},
        }
        return agent._build_rule(raw, SigmaGenerationInput(hypothesis=hypothesis, hunt_id="H-0013", platforms=["Windows"]))

    rule, problem = build("malicious-c2.net", "Adversaries tunnel data over DNS")
    assert rule is None and problem is not None and "malicious-c2.net" in problem
    rule, problem = build("api.telegram.org", "Adversaries use Telegram for C2")
    assert problem is None and rule is not None
