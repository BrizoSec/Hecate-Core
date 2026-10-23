"""Rules that fit what an appliance can log.

H-0830 (NetScaler RCE via User-Agent log poisoning) could only be drafted for
process_creation and file_event: webserver was not a category the model could
write, T1190 mapped to network_connection and process_creation, and nothing
dropped host-sensor categories for a hunt scoped to an appliance that runs no
EDR. Its dual-use rule also shipped a condition naming selections it did not
have.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import yaml

from hecate_agent.agents.llm.sigma_generator import (
    VALID_LOGSOURCE_CATEGORIES,
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _platform_consistent_logsources,
    _pysigma_problem,
    applicable_logsources,
)
from hecate_agent.core.sigma_semantics import semantic_problem

_APPLIANCE_TECHNIQUES = ["T1190", "T1505.003", "T1059.004"]


def test_exploitation_and_web_shells_map_to_web_logs() -> None:
    assert "webserver" in applicable_logsources(["T1190"], [])
    assert "webserver" in applicable_logsources(["T1505.003"], [])


def test_an_appliance_only_hunt_drops_host_sensor_log_sources() -> None:
    logsources = applicable_logsources(_APPLIANCE_TECHNIQUES, ["ipv4"])
    assert _platform_consistent_logsources(logsources, ["Network Devices"]) == ["network_connection", "webserver"]


def test_a_hunt_that_also_covers_hosts_keeps_them() -> None:
    logsources = applicable_logsources(_APPLIANCE_TECHNIQUES, ["ipv4"])
    kept = _platform_consistent_logsources(logsources, ["Network Devices", "Linux"])
    assert {"process_creation", "file_event"} <= set(kept)


def test_an_appliance_hunt_with_nothing_left_falls_back_to_web_logs() -> None:
    assert _platform_consistent_logsources(["process_creation"], ["Network Devices"]) == ["webserver"]


def test_the_model_can_write_a_webserver_rule() -> None:
    assert "webserver" in VALID_LOGSOURCE_CATEGORIES
    raw = {
        "logsource_category": "webserver",
        "title": "Base64 payload staged in the User-Agent of a gateway login request",
        "level": "high",
        "detection": {
            "selection": {"cs-uri-stem|endswith": "/logon/LogonPoint/tmindex.html", "cs-user-agent|startswith": "INDEX:"},
            "condition": "selection",
        },
        "falsepositives": ["Unknown"],
    }
    inp = SigmaGenerationInput(hypothesis="h", techniques=["T1190"], platforms=["Network Devices"])
    rule, problem = SigmaGeneratorAgent(llm_enabled=False)._build_rule(raw, inp)
    assert problem is None, problem
    assert yaml.safe_load(rule.rule_yaml)["logsource"] == {"category": "webserver"}  # type: ignore[union-attr]
    assert _pysigma_problem(rule.rule_yaml) is None  # type: ignore[union-attr]


def test_a_host_artifact_rule_on_an_appliance_hunt_says_it_needs_device_access() -> None:
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with (
        patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})),
        patch.object(agent, "_get_provider") as provider,
    ):
        provider.return_value.provider_name = "test"
        result = agent.execute(
            SigmaGenerationInput(
                hypothesis="h",
                hunt_id="H-0015",
                platforms=["Network Devices"],
                indicators={"sha256": ["a" * 64]},
                logsources=["process_creation"],
            )
        )
    host_rules = [yaml.safe_load(r.rule_yaml) for r in result.data.rules if r.logsource_category == "process_creation"]  # type: ignore[union-attr]
    assert host_rules
    assert all("forensic check on the device" in r["description"] for r in host_rules)


def test_a_condition_naming_a_missing_selection_is_rejected() -> None:
    detection = {
        "filter_legit": {"Image|endswith": ["\\chrome.exe"]},
        "condition": "(1 of selection_dest_*) and not filter_legit",
    }
    problem = semantic_problem(detection, "network_connection")
    assert problem is not None and "selection_dest_*" in problem
