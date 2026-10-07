"""The deterministic hash-IOC rule: built from the intel's hashes, no model."""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import patch

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _pysigma_problem,
    hash_selectors,
)

MD5 = "d8bf355a198fb5db3ea65cfdfcdfbd19"
SHA256 = "b7443b0ab48d2f5786d1b6f3a580f02621e9ae5a3877ee3a44e01df13d984328"
SHA1 = "a" * 40


def _input(**overrides: Any) -> SigmaGenerationInput:
    base: Dict[str, Any] = {
        "hypothesis": "Adversaries run a masquerading RAT",
        "hunt_id": "H-0010",
        "techniques": ["T1059.001"],
        "platforms": ["Windows"],
        "logsources": ["file_event"],
    }
    base.update(overrides)
    return SigmaGenerationInput(**base)


def _hash_rule(result: Any) -> Dict[str, Any]:
    rules = [r for r in result.data.rules if "file hash" in r.title]
    assert len(rules) == 1
    return yaml.safe_load(rules[0].rule_yaml)  # type: ignore


class TestHashSelectors:
    def test_both_providers_spellings_are_understood(self) -> None:
        selectors = hash_selectors(
            {"FileHash-MD5": [MD5], "sha256": [SHA256], "FileHash-SHA1": [SHA1]}
        )
        assert selectors == [f"MD5={MD5}", f"SHA256={SHA256}", f"SHA1={SHA1}"]

    def test_malformed_values_are_dropped_not_repaired(self) -> None:
        """A truncated hash matches nothing and would read as coverage."""
        assert hash_selectors({"md5": [MD5[:-1], "z" * 32, MD5.upper()]}) == [f"MD5={MD5}"]

    def test_non_hash_indicators_are_ignored(self) -> None:
        assert hash_selectors({"IPv4": ["10.0.0.1"], "domain": ["evil.example"]}) == []

    def test_duplicates_collapse(self) -> None:
        assert hash_selectors({"md5": [MD5], "FileHash-MD5": [MD5]}) == [f"MD5={MD5}"]


def test_hashes_get_a_rule_even_when_every_model_rule_is_rejected() -> None:
    """The live cycle that motivated this: ten hashes, the model's file_event
    rule matched only '.ps1' and was rejected, and no rule used a hash."""
    payload = json.dumps(
        {
            "rules": [
                {
                    "logsource_category": "file_event",
                    "title": "PowerShell script dropped",
                    "detection": {
                        "selection": {"TargetFilename|endswith": ".ps1"},
                        "condition": "selection",
                    },
                }
            ]
        }
    )
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(
        agent, "_get_provider"
    ) as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(indicators={"FileHash-MD5": [MD5], "FileHash-SHA256": [SHA256]}))

    assert result.success is True
    assert any(".ps1" in r for r in result.data.rejected)  # type: ignore
    rule = _hash_rule(result)
    assert rule["logsource"] == {"category": "process_creation", "product": "windows"}
    assert rule["detection"]["selection"]["Hashes|contains"] == [f"MD5={MD5}", f"SHA256={SHA256}"]
    assert rule["level"] == "high"
    assert rule["hunt_id"] == "H-0010"
    assert _pysigma_problem(yaml.safe_dump(rule)) is None


def test_no_hashes_means_no_hash_rule() -> None:
    payload = json.dumps({"rules": []})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload):
        result = agent.execute(_input(indicators={"IPv4": ["10.0.0.1"]}))
    assert result.success is False
    assert not any("file hash" in r.title for r in (result.data.rules if result.data else []))


@pytest.mark.parametrize("platforms", [["Linux"], []])
def test_logsource_follows_the_hunt_platform(platforms: list) -> None:
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=json.dumps({"rules": []})), patch.object(
        agent, "_get_provider"
    ) as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(platforms=platforms, indicators={"md5": [MD5]}))
    rule = _hash_rule(result)
    assert rule["logsource"]["category"] == "process_creation"
    assert rule["logsource"].get("product") != "windows"
