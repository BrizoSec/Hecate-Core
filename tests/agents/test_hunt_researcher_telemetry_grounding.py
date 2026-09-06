"""Tests for skill 3's anti-fabrication guardrails, added after a review of
generated research documents found two related failures in the telemetry
mapping section:

1. The prompt asked for OCSF fields "with population rates if known" and its
   JSON example showed "field1 (X% populated): description". Nothing ever
   measures this environment -- knowledge/environment.md ships with the
   coverage figures unfilled -- so every rate the model emitted was invented
   while reading as a measurement (e.g. "event_id:1001 (95% populated)").
2. The prompt demanded "4-6 specific OCSF fields" unconditionally. Given a
   source with no adversary behavior in it (a bare ThreatFox indicator list),
   the only concrete material left in context was the environment profile's
   generic event-ID list, so the model filled the quota by writing about
   those instead -- R-0002 mapped RDP lateral-movement telemetry (4624/4625,
   psexec.exe, logon_type 10) into a document about domains and file hashes,
   and the synthesis section then built a phishing hypothesis on top of it.

Both are prompt-level: the quota and the rate-shaped example are what
produced the output, so these tests pin the instructions themselves.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from athf.agents.llm.hunt_researcher import (
    _NO_TELEMETRY_KEY_FINDING,
    HuntResearcherAgent,
    _no_telemetry_mapped,
)
from athf.core.llm_provider import LLMProvider, LLMResponse


class _Provider(LLMProvider):
    """Captures prompts and returns a caller-supplied response shape."""

    def __init__(self, response_json: Optional[Dict[str, Any]] = None):
        self.prompts: List[str] = []
        self.response_json = response_json or {"summary": "ok", "key_findings": ["process.name: description"]}
        self.model = "fake-model"

    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        self.prompts.append(messages[0]["content"])
        return LLMResponse(
            text=json.dumps(self.response_json),
            input_tokens=10,
            output_tokens=10,
            model=self.model,
            duration_ms=1,
            cost_usd=0.0,
        )


def _telemetry_prompt() -> str:
    provider = _Provider()
    agent = HuntResearcherAgent(llm_enabled=True, provider=provider)
    agent._llm_map_telemetry(
        topic="ThreatFox IOCs for 2026-08-10",
        technique=None,
        ocsf_schema="{}",
        environment_data="Key Event IDs: 4624 - Successful logon, 4625 - Failed logon",
    )
    return provider.prompts[0]


@pytest.mark.unit
class TestPromptForbidsFabricatedRates:
    def test_prompt_does_not_ask_for_population_rates(self) -> None:
        prompt = _telemetry_prompt()

        assert "population rates if known" not in prompt
        assert "(X% populated)" not in prompt

    def test_prompt_explicitly_forbids_percentages(self) -> None:
        prompt = _telemetry_prompt()

        assert "Do not state field population rates or percentages" in prompt


@pytest.mark.unit
class TestPromptAllowsAnEmptyMapping:
    def test_prompt_does_not_demand_a_minimum_field_quota(self) -> None:
        """The "4-6 specific OCSF fields" demand is what forced the model to
        invent fields for a source that described no behavior."""
        prompt = _telemetry_prompt()

        assert "4-6 specific OCSF fields" not in prompt

    def test_prompt_states_an_empty_list_is_a_valid_answer(self) -> None:
        prompt = _telemetry_prompt()

        assert "return an empty key_findings list" in prompt
        assert "Do not substitute generic, example or typical attacker behavior" in prompt

    def test_prompt_warns_against_inferring_behavior_from_the_environment(self) -> None:
        """The environment profile says what telemetry exists, not what an
        adversary did -- R-0002's RDP content came from reading it as the
        latter."""
        prompt = _telemetry_prompt()

        assert "not evidence of adversary behavior" in prompt


@pytest.mark.unit
class TestEmptyMappingIsRenderedAsAVisibleGap:
    def test_empty_key_findings_becomes_an_explicit_marker(self) -> None:
        provider = _Provider({"summary": "No behavior to map.", "key_findings": []})
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        output = agent._skill_3_telemetry_mapping("ThreatFox IOCs for 2026-08-10", None)

        assert output.key_findings == [_NO_TELEMETRY_KEY_FINDING]
        assert _no_telemetry_mapped(output.key_findings)

    def test_empty_mapping_does_not_claim_schema_backed_confidence(self) -> None:
        provider = _Provider({"summary": "No behavior to map.", "key_findings": []})
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        output = agent._skill_3_telemetry_mapping("ThreatFox IOCs for 2026-08-10", None)

        assert output.confidence == 0.2

    def test_a_real_mapping_is_left_alone(self) -> None:
        provider = _Provider({"summary": "ok", "key_findings": ["process.name: launches the loader"]})
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        output = agent._skill_3_telemetry_mapping("Aeternum blockchain C2", None)

        assert output.key_findings == ["process.name: launches the loader"]
        assert not _no_telemetry_mapped(output.key_findings)
        assert output.confidence > 0.2
