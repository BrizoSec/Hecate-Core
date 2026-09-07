"""Tests for athf.agents.llm.sigma_generator - Sigma rule drafting for hunts."""

import json
from unittest.mock import patch

import yaml

from athf.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    applicable_logsources,
)

# The technique list and indicator types of the reference event (MISP 476,
# Lotus Blossom / Chrysalis) -- the case that motivated this agent.
CHRYSALIS_TECHNIQUES = [
    "T1005", "T1027.007", "T1041", "T1059.003", "T1070.004", "T1071.001",
    "T1083", "T1105", "T1106", "T1140", "T1204.002", "T1543.003",
    "T1547.001", "T1574.002", "T1620",
]
CHRYSALIS_INDICATOR_TYPES = ["filename", "hostname", "ip-dst", "url"]


def _agent() -> SigmaGeneratorAgent:
    return SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)


def _input(**overrides) -> SigmaGenerationInput:
    base = {
        "hypothesis": "Adversaries side-load a DLL and beacon to C2",
        "hunt_id": "H-0612",
        "techniques": ["T1059.003"],
        "platforms": ["Windows"],
    }
    base.update(overrides)
    return SigmaGenerationInput(**base)


def _rule(**overrides) -> dict:
    rule = {
        "logsource_category": "process_creation",
        "title": "Masquerading svchost outside System32",
        "description": "Detects svchost.exe running from an unexpected path",
        "techniques": ["T1059.003"],
        "detection": {
            "selection": {"Image|endswith": "\\svchost.exe"},
            "filter": {"Image|startswith": "C:\\Windows\\System32"},
            "condition": "selection and not filter",
        },
        "falsepositives": ["Patch tooling staging binaries"],
        "level": "high",
    }
    rule.update(overrides)
    return rule


# --- Log source derivation -------------------------------------------------


def test_derives_every_logsource_the_source_intel_supports():
    """The bug this agent exists to fix: the hunt was scoped to process
    telemetry alone while the CTI carried C2 URLs, hostnames and file paths."""
    sources = applicable_logsources(CHRYSALIS_TECHNIQUES, CHRYSALIS_INDICATOR_TYPES)
    assert "network_connection" in sources
    assert "dns_query" in sources
    assert "file_event" in sources
    assert "registry_event" in sources
    assert "process_creation" in sources


def test_subtechnique_inherits_parent_mapping():
    assert applicable_logsources(["T1059.003"]) == ["process_creation"]


def test_indicator_types_alone_imply_logsources():
    """Techniques can be absent; indicator types are still direct evidence."""
    assert "network_connection" in applicable_logsources([], ["ip-dst"])
    assert "registry_event" in applicable_logsources([], ["regkey"])


def test_empty_input_falls_back_rather_than_generating_nothing():
    assert applicable_logsources([], []) == ["process_creation"]


def test_derivation_is_stable_and_sorted():
    a = applicable_logsources(CHRYSALIS_TECHNIQUES, CHRYSALIS_INDICATOR_TYPES)
    b = applicable_logsources(list(reversed(CHRYSALIS_TECHNIQUES)), CHRYSALIS_INDICATOR_TYPES)
    assert a == b == sorted(a)


# --- Rule rendering --------------------------------------------------------


def test_valid_rule_renders_parseable_sigma_yaml():
    rule, problem = _agent()._build_rule(_rule(), _input())
    assert problem is None
    doc = yaml.safe_load(rule.rule_yaml)
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}
    assert doc["detection"]["condition"] == "selection and not filter"
    assert doc["status"] == "experimental"
    assert doc["tags"] == ["attack.t1059.003"]
    assert doc["related"] == [{"id": "H-0612", "type": "derived"}]


def test_multi_platform_hunt_does_not_pin_a_product():
    """Pinning product: windows on a cross-platform hunt silently stops the
    rule matching everything else."""
    rule, _ = _agent()._build_rule(_rule(), _input(platforms=["Windows", "Linux"]))
    assert yaml.safe_load(rule.rule_yaml)["logsource"] == {"category": "process_creation"}


def test_rule_id_is_unique_per_rule():
    a, _ = _agent()._build_rule(_rule(), _input())
    b, _ = _agent()._build_rule(_rule(), _input())
    assert yaml.safe_load(a.rule_yaml)["id"] != yaml.safe_load(b.rule_yaml)["id"]


def test_filename_is_derived_and_filesystem_safe():
    rule, _ = _agent()._build_rule(_rule(title="C2 beacon: api.wiresguard.com/v1"), _input())
    assert rule.filename.startswith("process_creation__")
    assert rule.filename.endswith(".yml")
    assert "/" not in rule.filename


# --- Validation ------------------------------------------------------------


def test_rejects_condition_naming_an_undefined_selection():
    """Still valid YAML and still looks like a rule -- pySigma only rejects
    it much later, after the hunt has been reviewed around it."""
    bad = _rule(detection={"selection": {"Image": "x"}, "condition": "selection and not filter"})
    rule, problem = _agent()._build_rule(bad, _input())
    assert rule is None
    assert "undefined selection" in problem


def test_accepts_wildcard_condition_when_a_selection_matches_the_stem():
    ok = _rule(
        detection={
            "selection_cmd": {"Image": "a"},
            "selection_net": {"Image": "b"},
            "condition": "1 of selection_*",
        }
    )
    rule, problem = _agent()._build_rule(ok, _input())
    assert problem is None and rule is not None


def test_rejects_unknown_logsource_category():
    rule, problem = _agent()._build_rule(_rule(logsource_category="telepathy"), _input())
    assert rule is None
    assert "unknown logsource_category" in problem


def test_rejects_detection_with_no_selection_blocks():
    rule, problem = _agent()._build_rule(_rule(detection={"condition": "selection"}), _input())
    assert rule is None
    assert "no selection blocks" in problem


def test_rejects_empty_title():
    rule, problem = _agent()._build_rule(_rule(title="   "), _input())
    assert rule is None
    assert "title is empty" in problem


def test_invalid_level_falls_back_rather_than_failing():
    rule, problem = _agent()._build_rule(_rule(level="catastrophic"), _input())
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["level"] == "medium"


def test_missing_falsepositives_gets_an_honest_placeholder():
    rule, _ = _agent()._build_rule(_rule(falsepositives=[]), _input())
    fps = yaml.safe_load(rule.rule_yaml)["falsepositives"]
    assert fps and "Unknown" in fps[0]


def test_rule_techniques_keep_subtechnique_precision():
    """The hunt lost T1059.003 -> T1059; tags must not repeat that."""
    rule, _ = _agent()._build_rule(_rule(techniques=["attack.T1059.003"]), _input())
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1059.003"]


def test_rule_falls_back_to_hunt_techniques_when_model_tags_nothing():
    rule, _ = _agent()._build_rule(
        _rule(techniques=[]), _input(techniques=["T1071.001", "T1041"])
    )
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1041", "attack.t1071.001"]


# --- execute() -------------------------------------------------------------


def test_execute_returns_failure_without_an_llm():
    agent = SigmaGeneratorAgent(llm_enabled=False)
    result = agent.execute(_input())
    assert result.success is False
    assert "requires an LLM" in result.error
    # The derivation is deterministic, so it is still reported on failure.
    assert result.data.logsources_considered == ["process_creation"]


def test_execute_drops_invalid_rules_but_keeps_valid_ones():
    payload = json.dumps(
        {"rules": [_rule(), _rule(logsource_category="nonsense", title="bad")]}
    )
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(
        agent, "_get_provider"
    ) as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input())
    assert result.success is True
    assert len(result.data.rules) == 1
    assert any("nonsense" in r for r in result.data.rejected)


def test_execute_fails_when_every_rule_is_invalid():
    """Silently succeeding with zero rules would leave the hunt looking as
    though queries had been generated."""
    payload = json.dumps({"rules": [_rule(logsource_category="nonsense")]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload):
        result = agent.execute(_input())
    assert result.success is False
    assert "failed validation" in result.error


def test_execute_warns_about_uncovered_logsources():
    payload = json.dumps({"rules": [_rule()]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(
        agent, "_get_provider"
    ) as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=["process_creation", "dns_query"]))
    assert result.success is True
    assert any("dns_query" in w for w in result.warnings)


# --- Detection normalisation ----------------------------------------------


def test_infers_condition_for_a_single_selection_block():
    """Observed on every rule of a real 14B run: detection is emitted with
    one selection and no condition. With one block the intended condition
    has exactly one possible value."""
    raw = _rule(detection={"selection": {"QueryName|contains": ["api.wiresguard.com"]}})
    rule, problem = _agent()._build_rule(raw, _input())
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection"


def test_infers_condition_using_the_actual_block_name():
    raw = _rule(detection={"beacon_traffic": {"DestinationHostname": "x"}})
    rule, _ = _agent()._build_rule(raw, _input())
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "beacon_traffic"


def test_refuses_to_invent_an_operator_between_multiple_blocks():
    """Wiring two unlabelled blocks together as AND would be guessing at
    logic nobody wrote, and the rule would look reviewed."""
    raw = _rule(detection={"selection": {"a": "b"}, "filter": {"c": "d"}})
    rule, problem = _agent()._build_rule(raw, _input())
    assert rule is None
    assert "unknowable" in problem


def test_moves_a_top_level_condition_into_detection():
    raw = _rule(detection={"selection": {"a": "b"}, "filter": {"c": "d"}})
    raw["condition"] = "selection and not filter"
    rule, problem = _agent()._build_rule(raw, _input())
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection and not filter"


def test_drops_a_technique_tag_the_source_never_asserted():
    """A real run tagged a rule T1047.002, which does not exist."""
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1047.002"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    tags = yaml.safe_load(rule.rule_yaml)["tags"]
    assert "attack.t1047.002" not in tags
    assert tags == ["attack.t1071.001", "attack.t1574.002"]


def test_keeps_a_technique_tag_the_source_did_assert():
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1071.001"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]


def test_technique_fallback_narrows_to_the_rules_own_logsource():
    """A DLL side-loading rule was tagged with all fifteen techniques the
    event carried -- exfiltration and registry persistence included --
    because every model-proposed tag had been rejected."""
    rule, _ = _agent()._build_rule(
        _rule(logsource_category="image_load", techniques=["T9999"]),
        _input(techniques=CHRYSALIS_TECHNIQUES),
    )
    tags = yaml.safe_load(rule.rule_yaml)["tags"]
    # T1574 (hijack execution flow) and T1620 (reflective load) are observable
    # in image_load; exfiltration over C2 is not.
    assert "attack.t1574.002" in tags
    assert "attack.t1041" not in tags
    assert len(tags) < len(CHRYSALIS_TECHNIQUES)


def test_technique_fallback_keeps_everything_when_logsource_maps_nothing():
    rule, _ = _agent()._build_rule(
        _rule(logsource_category="process_creation", techniques=["T9999"]),
        _input(techniques=["T1071.001"]),
    )
    # T1071 is not a process_creation technique, so narrowing yields nothing
    # and the supplied list stands rather than the rule going untagged.
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]
