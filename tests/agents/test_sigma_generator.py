"""Tests for hecate_agent.agents.llm.sigma_generator - Sigma rule drafting for hunts."""

import importlib.util
import json
import logging
import sys
from typing import Any, Dict
from unittest.mock import patch

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _placeholder_problem,
    _pysigma_problem,
    applicable_logsources,
)

# The technique list and indicator types of the reference event (MISP 476,
# Lotus Blossom / Chrysalis) -- the case that motivated this agent.
CHRYSALIS_TECHNIQUES = [
    "T1005",
    "T1027.007",
    "T1041",
    "T1059.003",
    "T1070.004",
    "T1071.001",
    "T1083",
    "T1105",
    "T1106",
    "T1140",
    "T1204.002",
    "T1543.003",
    "T1547.001",
    "T1574.002",
    "T1620",
]
CHRYSALIS_INDICATOR_TYPES = ["filename", "hostname", "ip-dst", "url"]


def _agent() -> SigmaGeneratorAgent:
    return SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)


def _input(**overrides: Any) -> SigmaGenerationInput:
    base: Dict[str, Any] = {
        "hypothesis": "Adversaries side-load a DLL and beacon to C2",
        "hunt_id": "H-0612",
        "techniques": ["T1059.003"],
        "platforms": ["Windows"],
    }
    base.update(overrides)
    return SigmaGenerationInput(**base)


def _rule(**overrides: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
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
    assert rule is not None
    assert problem is None
    doc = yaml.safe_load(rule.rule_yaml)
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}
    assert doc["detection"]["condition"] == "selection and not filter"
    assert doc["status"] == "experimental"
    assert doc["tags"] == ["attack.t1059.003"]
    # The hunt link is a custom key, not Sigma's `related:`. That field
    # relates a rule to other Sigma rules and its id must be a UUID, so a
    # hunt id there made every rule unparseable.
    assert doc["hunt_id"] == "H-0612"
    assert "related" not in doc


def test_multi_platform_hunt_does_not_pin_a_product():
    """Pinning product: windows on a cross-platform hunt silently stops the
    rule matching everything else."""
    rule, _ = _agent()._build_rule(_rule(), _input(platforms=["Windows", "Linux"]))
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["logsource"] == {"category": "process_creation"}


def test_rule_id_is_unique_per_rule():
    a, _ = _agent()._build_rule(_rule(), _input())
    assert a is not None
    b, _ = _agent()._build_rule(_rule(), _input())
    assert b is not None
    assert yaml.safe_load(a.rule_yaml)["id"] != yaml.safe_load(b.rule_yaml)["id"]


def test_filename_is_derived_and_filesystem_safe():
    rule, _ = _agent()._build_rule(_rule(title="C2 beacon: api.wiresguard.com/v1"), _input())
    assert rule is not None
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
    assert problem is not None and "undefined selection" in problem


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
    assert problem is not None and "unknown logsource_category" in problem


def test_rejects_detection_with_no_selection_blocks():
    rule, problem = _agent()._build_rule(_rule(detection={"condition": "selection"}), _input())
    assert rule is None
    assert problem is not None and "no selection blocks" in problem


def test_rejects_empty_title():
    rule, problem = _agent()._build_rule(_rule(title="   "), _input())
    assert rule is None
    assert problem is not None and "title is empty" in problem


def test_invalid_level_falls_back_rather_than_failing():
    rule, problem = _agent()._build_rule(_rule(level="catastrophic"), _input())
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["level"] == "medium"


def test_missing_falsepositives_gets_an_honest_placeholder():
    rule, _ = _agent()._build_rule(_rule(falsepositives=[]), _input())
    assert rule is not None
    fps = yaml.safe_load(rule.rule_yaml)["falsepositives"]
    assert fps and "Unknown" in fps[0]


def test_rule_techniques_keep_subtechnique_precision():
    """The hunt lost T1059.003 -> T1059; tags must not repeat that."""
    rule, _ = _agent()._build_rule(_rule(techniques=["attack.T1059.003"]), _input())
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1059.003"]


def test_rule_falls_back_to_hunt_techniques_when_model_tags_nothing():
    rule, _ = _agent()._build_rule(_rule(techniques=[]), _input(techniques=["T1071.001", "T1041"]))
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1041", "attack.t1071.001"]


# --- execute() -------------------------------------------------------------


def test_execute_returns_failure_without_an_llm():
    agent = SigmaGeneratorAgent(llm_enabled=False)
    result = agent.execute(_input())
    assert result.success is False
    assert result.error is not None and "requires an LLM" in result.error
    # The derivation is deterministic, so it is still reported on failure.
    assert result.data is not None
    assert result.data.logsources_considered == ["process_creation"]


def test_execute_drops_invalid_rules_but_keeps_valid_ones():
    payload = json.dumps({"rules": [_rule(), _rule(logsource_category="nonsense", title="bad")]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input())
    assert result.success is True
    assert result.data is not None
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
    assert result.error is not None and "no log source produced a valid rule" in result.error


def test_execute_warns_about_uncovered_logsources():
    payload = json.dumps({"rules": [_rule()]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
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
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection"


def test_infers_condition_using_the_actual_block_name():
    raw = _rule(detection={"beacon_traffic": {"DestinationHostname": "x"}})
    rule, _ = _agent()._build_rule(raw, _input())
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "beacon_traffic"


def test_refuses_to_invent_an_operator_between_multiple_blocks():
    """Wiring two unlabelled blocks together as AND would be guessing at
    logic nobody wrote, and the rule would look reviewed."""
    raw = _rule(detection={"selection": {"a": "b"}, "filter": {"c": "d"}})
    rule, problem = _agent()._build_rule(raw, _input())
    assert rule is None
    assert problem is not None and "unknowable" in problem


def test_moves_a_top_level_condition_into_detection():
    raw = _rule(detection={"selection": {"a": "b"}, "filter": {"c": "d"}})
    raw["condition"] = "selection and not filter"
    rule, problem = _agent()._build_rule(raw, _input())
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection and not filter"


def test_drops_a_technique_tag_the_source_never_asserted():
    """A real run tagged a rule T1047.002, which does not exist."""
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1047.002"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    assert rule is not None
    tags = yaml.safe_load(rule.rule_yaml)["tags"]
    assert "attack.t1047.002" not in tags
    assert tags == ["attack.t1071.001", "attack.t1574.002"]


def test_keeps_a_technique_tag_the_source_did_assert():
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1071.001"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]


def test_technique_fallback_narrows_to_the_rules_own_logsource():
    """A DLL side-loading rule was tagged with all fifteen techniques the
    event carried -- exfiltration and registry persistence included --
    because every model-proposed tag had been rejected."""
    rule, _ = _agent()._build_rule(
        _rule(logsource_category="image_load", techniques=["T9999"]),
        _input(techniques=CHRYSALIS_TECHNIQUES),
    )
    assert rule is not None
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
    assert rule is not None
    # T1071 is not a process_creation technique, so narrowing yields nothing
    # and the supplied list stands rather than the rule going untagged.
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]


# --- One call per log source (V1) ------------------------------------------


def test_one_llm_call_is_made_per_log_source():
    """The combined prompt asked for six rules in one response, which on a
    4096-token context lost every rule when the reply truncated."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    sources = ["process_creation", "network_connection", "dns_query"]
    calls = []

    def fake(prompt, *a, **k):
        calls.append(prompt)
        category = next(c for c in sources if f"and no other:\n    {c}" in prompt)
        return json.dumps({"rules": [_rule(logsource_category=category, title=f"{category} rule")]})

    with patch.object(agent, "_call_llm_with_retry", side_effect=fake), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=sources))

    assert len(calls) == 3
    assert result.metadata["llm_calls"] == 3
    assert {r.logsource_category for r in result.data.rules} == set(sources)


def test_each_prompt_names_only_its_own_log_source():
    """Offering another category's fields invites a borrowed field name, which
    matches nothing and fails silently at conversion."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    prompt = agent._build_prompt(_input(), "dns_query")
    assert "QueryName" in prompt
    assert "CommandLine" not in prompt
    assert "TargetObject" not in prompt


def test_one_log_source_failing_does_not_lose_the_others():
    """The point of splitting: a timeout costs one rule, not all of them."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    sources = ["process_creation", "network_connection"]

    def fake(prompt, *a, **k):
        if "network_connection" in prompt:
            raise TimeoutError("model timed out")
        return json.dumps({"rules": [_rule(logsource_category="process_creation")]})

    with patch.object(agent, "_call_llm_with_retry", side_effect=fake), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=sources))

    assert result.success is True
    assert [r.logsource_category for r in result.data.rules] == ["process_creation"]
    assert any("network_connection" in r for r in result.data.rejected)
    assert any("network_connection" in w for w in result.warnings)


def test_a_rule_for_the_wrong_category_is_rejected_not_relabelled():
    """Relabelling would file process telemetry under DNS."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    payload = json.dumps({"rules": [_rule(logsource_category="process_creation")]})

    with patch.object(agent, "_call_llm_with_retry", return_value=payload):
        result = agent.execute(_input(logsources=["dns_query"]))

    assert result.success is False
    assert any("returned a process_creation rule instead" in r for r in result.data.rejected)


def test_a_malformed_sibling_is_reported_even_when_a_good_rule_survives():
    agent = SigmaGeneratorAgent(llm_enabled=True)
    payload = json.dumps({"rules": [_rule(), _rule(logsource_category="nonsense", title="bad")]})

    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=["process_creation"]))

    assert result.success is True
    assert len(result.data.rules) == 1
    assert any("nonsense" in r for r in result.data.rejected)


# --- Placeholder detection values are rejected (G6) -------------------------


class TestPlaceholderGuard:
    """8 of 25 rules drafted before this guard matched on scaffolding rather
    than an observable. They are valid Sigma and pass every structural check,
    so nothing else stopped them: they reached the operator looking exactly
    like real rules and matched nothing."""

    @staticmethod
    def _det(field, value):
        return {"selection": {field: value}, "condition": "selection"}

    @pytest.mark.parametrize(
        "value,fragment",
        [
            (".exe -c bad_command", "bad_command"),
            ("known-good-script.exe", "known-good"),
            ("known-good-file-name", "known-good"),
            ("ms-office-known-good-command", "known-good"),
            (".c2.example.com", "example.com"),
            ("%appdata%\\malicious", "malicious"),
            ("\\malicious-ai-tool.exe", "malicious"),
        ],
    )
    def test_placeholder_values_are_rejected(self, value, fragment):
        problem = _placeholder_problem(self._det("CommandLine|contains", value), {})
        assert problem is not None
        assert fragment in problem

    def test_the_prompts_own_example_values_are_rejected(self):
        """The model echoes this module's prompt back; "known-good" came from
        our own example block."""
        assert _placeholder_problem(self._det("FieldName|endswith", "value"), {}) is not None

    def test_an_impossible_ipv4_is_rejected(self):
        """123.456.789 cannot match anything -- it was invented, not observed."""
        problem = _placeholder_problem(self._det("DestinationIp|contains", "123.456.789"), {})
        assert "not a valid IPv4" in problem

    def test_a_partial_ip_prefix_is_a_legitimate_contains_idiom(self):
        assert _placeholder_problem(self._det("DestinationIp|contains", "192.168."), {}) is None

    def test_an_empty_value_is_rejected(self):
        assert "empty" in _placeholder_problem(self._det("TargetFilename|endswith", ""), {})

    @pytest.mark.parametrize(
        "value",
        [
            "\\powershell.exe",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ".element.tw",
            "207e0d47c4e5493ef7313eb1faeb1c6195923c89f263e548609a6838dd91ec0c",
        ],
    )
    def test_real_observables_are_kept(self, value):
        assert _placeholder_problem(self._det("Image|endswith", value), {}) is None

    def test_a_value_the_cti_supplied_is_never_rejected(self):
        """If the intelligence really names it, that is an observable, and the
        guard must not second-guess the evidence."""
        det = self._det("QueryName", "malicious-update.example.com")
        assert _placeholder_problem(det, {}) is not None
        assert _placeholder_problem(det, {"hostname": ["malicious-update.example.com"]}) is None

    def test_nested_list_values_are_walked(self):
        det = {"selection": {"CommandLine|contains": ["legit.exe", "bad_command"]}, "condition": "selection"}
        assert _placeholder_problem(det, {}) is not None

    def test_the_condition_string_is_not_scanned_as_a_value(self):
        det = {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection and not filter"}
        assert _placeholder_problem(det, {}) is None

    @pytest.mark.parametrize("value", ["signed_binary_path", "target_process_name", "bad_command"])
    def test_a_bare_snake_case_identifier_describes_a_value_rather_than_being_one(self, value):
        """No denylist covers what the model invents fresh. A live run produced
        "signed_binary_path" past the known-placeholder list."""
        assert _placeholder_problem(self._det("Image|contains", value), {}) is not None

    @pytest.mark.parametrize("value", ["\\powershell.exe", "192.168.", ".element.tw", "--type=renderer", "-RunKey", "80"])
    def test_real_values_carry_a_separator_and_survive(self, value):
        """A path has a slash, a domain a dot, a flag a dash -- that is what
        separates them from a snake_case description."""
        assert _placeholder_problem(self._det("Image|contains", value), {}) is None


# --- Rendered rules are validated as Sigma, not just as YAML ---------------


@pytest.mark.skipif(
    importlib.util.find_spec("sigma") is None,
    reason="pysigma not installed; these assert on its parse results",
)
class TestPySigmaValidation:
    """The structural checks say whether a rule is coherent; they say nothing
    about whether it is Sigma. Three rules in the live corpus were valid YAML,
    passed every check, and could never match anything."""

    VALID = (
        "title: T\n"
        "id: 5f0b1d5a-1c9e-4a4e-9a1e-2c3d4e5f6a7b\n"
        "status: experimental\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image|endswith: \\cmd.exe\n  condition: selection\n"
        "level: medium\n"
    )

    def test_a_valid_rule_passes(self):
        assert _pysigma_problem(self.VALID) is None

    def test_a_query_dsl_operator_is_rejected(self):
        """H-0007 emitted a MongoDB-style `$or:` key, which Sigma reads as a
        field named `$or` and never matches."""
        bad = self.VALID.replace(
            "  selection:\n    Image|endswith: \\cmd.exe\n",
            "  selection:\n    $or:\n    - Image|endswith: \\cmd.exe\n",
        )
        assert "not valid Sigma" in _pysigma_problem(bad)

    def test_an_unknown_modifier_is_rejected(self):
        """H-0005 used `|in`, which is not a Sigma modifier."""
        bad = self.VALID.replace("Image|endswith:", "Image|in:")
        problem = _pysigma_problem(bad)
        assert problem and "modifier" in problem.lower()

    def test_an_empty_detection_is_rejected(self):
        bad = self.VALID.replace(
            "detection:\n  selection:\n    Image|endswith: \\cmd.exe\n  condition: selection\n",
            "detection:\n  selection: {}\n  condition: selection\n",
        )
        assert _pysigma_problem(bad) is not None

    def test_a_hunt_id_field_does_not_break_parsing(self):
        """Regression: the hunt link used to go in Sigma's `related:`, whose
        id must be a UUID. That made all 17 rules in the corpus unparseable."""
        assert _pysigma_problem(self.VALID + "hunt_id: H-0007\n") is None

    def test_a_related_block_with_a_hunt_id_would_be_rejected(self):
        """Pins the bug itself, so the old shape cannot quietly come back."""
        bad = self.VALID + "related:\n- id: H-0007\n  type: derived\n"
        assert _pysigma_problem(bad) is not None


# These two must run even without pysigma -- they are the guard against it
# passing everything silently, which is the whole failure mode.
def test_a_missing_pysigma_warns_rather_than_passing_silently(monkeypatch, caplog):
    """A validator that silently accepts everything is worse than none."""
    import hecate_agent.agents.llm.sigma_generator as sg

    monkeypatch.setattr(sg, "_PYSIGMA_WARNED", False)
    monkeypatch.setitem(sys.modules, "sigma.collection", None)
    with caplog.at_level(logging.WARNING):
        assert sg._pysigma_problem("anything") is None
    assert "not being validated" in caplog.text.lower()


def test_the_missing_pysigma_warning_is_emitted_once(monkeypatch, caplog):
    import hecate_agent.agents.llm.sigma_generator as sg

    monkeypatch.setattr(sg, "_PYSIGMA_WARNED", False)
    monkeypatch.setitem(sys.modules, "sigma.collection", None)
    with caplog.at_level(logging.WARNING):
        sg._pysigma_problem("a")
        sg._pysigma_problem("b")
    assert caplog.text.lower().count("not being validated") == 1
