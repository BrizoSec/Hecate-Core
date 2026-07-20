"""Tests for HuntResearcherAgent's confidence-on-failure, data-source
extraction, and synthesis parsing, added while fixing bugs found in a
comprehensive review:

1. Skill confidence scores were computed purely from whether web-search
   sources existed, never from whether the LLM call underlying that skill
   actually succeeded -- a failed call whose "summary" is literally
   "... (LLM error: ...)" could still report 0.8-0.95 confidence.
2. _extract_data_sources ignored its `telemetry` parameter entirely and
   returned an identical hardcoded dict for every research document.
3. _extract_hypothesis/_extract_gaps only matched an exact literal
   "hypothesis:"/"gap:" prefix, silently dropping the hypothesis/gaps
   whenever the model phrased them differently (e.g. bolded, or
   "Recommended Hypothesis:").
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from athf.agents.llm.hunt_researcher import (
    _LLM_ERROR_KEY_FINDING,
    HuntResearcherAgent,
    ResearchSkillOutput,
    _llm_call_failed,
)
from athf.core.llm_provider import LLMProvider, LLMResponse


class FailingProvider(LLMProvider):
    """Every call raises -- simulates a dead/unreachable/erroring LLM."""

    @property
    def provider_name(self) -> str:
        return "failing"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        raise ConnectionError("simulated LLM failure")


class CannedProvider(LLMProvider):
    """Always returns the same canned JSON response."""

    def __init__(self, response_json: Optional[Dict[str, Any]] = None):
        self.response_json = response_json or {"summary": "ok", "key_findings": ["finding1"]}
        self.model = "fake-model"

    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        import json

        return LLMResponse(
            text=json.dumps(self.response_json),
            input_tokens=10,
            output_tokens=10,
            model=self.model,
            duration_ms=1,
            cost_usd=0.0,
        )


@pytest.mark.unit
class TestLlmCallFailed:
    def test_detects_the_error_sentinel(self) -> None:
        assert _llm_call_failed([_LLM_ERROR_KEY_FINDING]) is True

    def test_real_findings_are_not_flagged_as_failed(self) -> None:
        assert _llm_call_failed(["a real finding", "another one"]) is False
        assert _llm_call_failed([]) is False


@pytest.mark.unit
class TestConfidenceReflectsLlmFailure:
    def test_skill_1_confidence_is_low_when_llm_call_fails(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=FailingProvider())
        result = agent._skill_1_system_research(topic="LSASS dumping", search_depth="basic")
        assert _LLM_ERROR_KEY_FINDING in result.key_findings
        assert result.confidence <= 0.1

    def test_skill_1_confidence_is_normal_when_llm_call_succeeds(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CannedProvider())
        result = agent._skill_1_system_research(topic="LSASS dumping", search_depth="basic")
        assert result.confidence >= 0.5

    def test_skill_2_confidence_is_low_when_llm_call_fails(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=FailingProvider())
        result = agent._skill_2_adversary_tradecraft(
            topic="LSASS dumping", technique=None, search_depth="basic", web_search_enabled=False
        )
        assert _LLM_ERROR_KEY_FINDING in result.key_findings
        assert result.confidence <= 0.1

    def test_skill_3_confidence_is_low_when_llm_call_fails(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=FailingProvider())
        result = agent._skill_3_telemetry_mapping(topic="LSASS dumping", technique=None)
        assert _LLM_ERROR_KEY_FINDING in result.key_findings
        assert result.confidence <= 0.1

    def test_skill_5_confidence_is_low_when_llm_call_fails(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=FailingProvider())
        fake_skill = ResearchSkillOutput(
            skill_name="system_research", summary="s", key_findings=["f"], sources=[], confidence=0.5
        )
        result = agent._skill_5_synthesis(topic="LSASS dumping", technique=None, skills=[fake_skill])
        assert _LLM_ERROR_KEY_FINDING in result.key_findings
        assert result.confidence <= 0.1


@pytest.mark.unit
class TestExtractDataSources:
    def test_derives_availability_from_telemetry_text_not_a_fixed_stub(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        telemetry_with_network = ResearchSkillOutput(
            skill_name="telemetry_mapping",
            summary="Network connections are captured via network.connection_info fields.",
            key_findings=["dst_endpoint.ip is well populated"],
            sources=[],
            confidence=0.9,
        )
        telemetry_without_network = ResearchSkillOutput(
            skill_name="telemetry_mapping",
            summary="Only process execution telemetry is relevant here.",
            key_findings=["process.name and command_line are populated"],
            sources=[],
            confidence=0.9,
        )

        with_network = agent._extract_data_sources(telemetry_with_network)
        without_network = agent._extract_data_sources(telemetry_without_network)

        # The two calls must actually differ based on their input -- the old
        # code returned the identical hardcoded dict regardless of input.
        assert with_network != without_network
        assert with_network["network_connections"] is True
        assert without_network["network_connections"] is False
        assert without_network["process_execution"] is True

    def test_returns_all_false_when_telemetry_skill_itself_failed(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        failed_telemetry = ResearchSkillOutput(
            skill_name="telemetry_mapping",
            summary="Telemetry mapping for X (LLM error: boom)",
            key_findings=[_LLM_ERROR_KEY_FINDING],
            sources=[],
            confidence=0.1,
        )

        result = agent._extract_data_sources(failed_telemetry)

        assert all(v is False for v in result.values())


def _synthesis(key_findings: List[str]) -> ResearchSkillOutput:
    return ResearchSkillOutput(
        skill_name="synthesis", summary="s", key_findings=key_findings, sources=[], confidence=0.8
    )


@pytest.mark.unit
class TestExtractHypothesis:
    def test_matches_the_prompts_own_exact_wording(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["Hypothesis: Adversaries use macros to drop payloads."])
        assert agent._extract_hypothesis(synthesis) == "Adversaries use macros to drop payloads."

    def test_matches_bolded_and_recommended_phrasing(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["**Recommended Hypothesis:** Adversaries abuse OAuth grants for persistence."])
        assert agent._extract_hypothesis(synthesis) == "Adversaries abuse OAuth grants for persistence."

    def test_matches_hunt_hypothesis_phrasing(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["Hunt Hypothesis: Adversaries dump LSASS via comsvcs.dll."])
        assert agent._extract_hypothesis(synthesis) == "Adversaries dump LSASS via comsvcs.dll."

    def test_returns_none_and_warns_when_nothing_matches(self, caplog: pytest.LogCaptureFixture) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["Some finding with no recognizable label at all."])

        with caplog.at_level("WARNING"):
            result = agent._extract_hypothesis(synthesis)

        assert result is None
        assert "Could not extract" in caplog.text

    def test_does_not_warn_when_the_llm_call_itself_failed(self, caplog: pytest.LogCaptureFixture) -> None:
        """No hypothesis to extract because synthesis failed is a different,
        already-logged situation -- don't pile a second, redundant warning
        on top of it."""
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis([_LLM_ERROR_KEY_FINDING])

        with caplog.at_level("WARNING"):
            result = agent._extract_hypothesis(synthesis)

        assert result is None
        assert "Could not extract" not in caplog.text


@pytest.mark.unit
class TestExtractGaps:
    def test_matches_the_prompts_own_exact_wording(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["Gap: No visibility into macro execution telemetry."])
        assert agent._extract_gaps(synthesis) == ["No visibility into macro execution telemetry."]

    def test_matches_bolded_and_variant_phrasing(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(
            [
                "**Knowledge Gap:** Limited data on adversary infrastructure.",
                "Coverage Gap: No EDR on legacy Windows Server 2012 hosts.",
            ]
        )
        assert agent._extract_gaps(synthesis) == [
            "Limited data on adversary infrastructure.",
            "No EDR on legacy Windows Server 2012 hosts.",
        ]

    def test_returns_empty_list_when_nothing_matches(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(["Some finding with no recognizable label at all."])
        assert agent._extract_gaps(synthesis) == []

    def test_ignores_non_gap_findings_mixed_in(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        synthesis = _synthesis(
            [
                "Hypothesis: Adversaries use macros to drop payloads.",
                "Gap: No macro execution telemetry.",
                "Focus: Prioritize Office process ancestry.",
            ]
        )
        assert agent._extract_gaps(synthesis) == ["No macro execution telemetry."]
