"""Tests for step 1 of the hypothesis prompt -- "is this actually a threat
report?" -- and the low sampling temperature that makes the answer stable.

An RSS item from a security vendor's research blog ("13 million tool calls:
auditing every AI coding agent action with Elastic Agent") produced a hunt
draft asserting "Adversaries use evasion techniques to circumvent Elastic
Agent's monitoring capabilities", mapped to T1052 (Exfiltration Over Physical
Medium). The post describes defensive instrumentation; no adversary appears in
it anywhere.

The is_threat_report guardrail already existed and simply misfired. Two causes:

1. Step 1's examples covered vendor marketing, compliance announcements and
   feature releases, but not defensive engineering content -- telemetry
   pipelines, detection queries and hunting guidance are security-technical
   and read as threat-adjacent, and the publisher is a security vendor.
2. The classification was sampled at the provider's creative default, so the
   same input produced different verdicts run to run. Measured against that
   post: 0/5 correct before the wording change, 2/5 after it, and 5/5 once
   the call also dropped to temperature 0.2. Real threat reports stayed
   correctly classified in every configuration (3/3 on two separate ones).
"""

import json
from typing import Any, Dict, List, Optional

import pytest

from athf.agents.llm.hypothesis_generator import HypothesisGenerationInput, HypothesisGeneratorAgent
from athf.core.llm_provider import LLMProvider, LLMResponse

_RESPONSE = {
    "hypothesis": "Adversaries use credential dumping to steal hashes on Windows endpoints",
    "justification": "Common post-exploitation technique",
    "mitre_techniques": ["T1003.001"],
    "data_sources": ["EDR telemetry"],
    "expected_observables": ["LSASS memory access"],
    "known_false_positives": ["AV scanners"],
    "time_range_suggestion": "7 days",
}


class _RecordingProvider(LLMProvider):
    """Records the kwargs each completion was called with."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.model = "fake-model"

    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        self.calls.append({"prompt": messages[0]["content"], "temperature": temperature})
        return LLMResponse(
            text=json.dumps(_RESPONSE),
            input_tokens=10,
            output_tokens=10,
            model=self.model,
            duration_ms=1,
            cost_usd=0.0,
        )


def _run(intel: str = "Some threat intel") -> _RecordingProvider:
    provider = _RecordingProvider()
    agent = HypothesisGeneratorAgent(llm_enabled=True, provider=provider)
    agent.execute(HypothesisGenerationInput(threat_intel=intel, past_hunts=[], environment={}))
    return provider


@pytest.mark.unit
class TestStepOneCoversDefensiveContent:
    def test_prompt_names_defensive_engineering_content(self) -> None:
        prompt = _run().calls[0]["prompt"]

        assert "defensive engineering content" in prompt
        assert "what a *defender* does" in prompt

    def test_prompt_says_the_publisher_is_not_the_test(self) -> None:
        """The post came from a security vendor's research blog, which is
        exactly why "who published it" cannot be the deciding factor."""
        prompt = _run().calls[0]["prompt"]

        assert "the publisher is not the test" in prompt

    def test_prompt_still_covers_the_original_marketing_case(self) -> None:
        prompt = _run().calls[0]["prompt"]

        assert "is marketing, not a threat report" in prompt


@pytest.mark.unit
class TestClassificationIsSampledDeterministically:
    def test_generation_uses_a_low_temperature(self) -> None:
        provider = _run()

        assert provider.calls[0]["temperature"] == 0.2

    def test_every_retry_attempt_keeps_the_low_temperature(self) -> None:
        """The retry loop rebuilds the prompt; it must not silently fall back
        to the provider default on attempts 2+."""

        class _BadJsonThenGood(_RecordingProvider):
            def complete(
                self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7
            ) -> LLMResponse:
                self.calls.append({"prompt": messages[0]["content"], "temperature": temperature})
                text = "not json" if len(self.calls) == 1 else json.dumps(_RESPONSE)
                return LLMResponse(
                    text=text, input_tokens=1, output_tokens=1, model="fake", duration_ms=1, cost_usd=0.0
                )

        provider = _BadJsonThenGood()
        agent = HypothesisGeneratorAgent(llm_enabled=True, provider=provider)
        agent.execute(HypothesisGenerationInput(threat_intel="intel", past_hunts=[], environment={}))

        assert len(provider.calls) >= 2
        assert all(call["temperature"] == 0.2 for call in provider.calls)


@pytest.mark.unit
class TestBaseAgentTemperaturePassthrough:
    def test_temperature_is_omitted_when_not_requested(self) -> None:
        """Agents that don't opt in must keep the provider's own default,
        rather than having one hardcoded underneath them."""
        from athf.agents.llm.hunt_researcher import HuntResearcherAgent

        provider = _RecordingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)
        agent._call_llm("prompt")

        assert provider.calls[0]["temperature"] == 0.7

    def test_explicit_temperature_is_forwarded(self) -> None:
        from athf.agents.llm.hunt_researcher import HuntResearcherAgent

        provider = _RecordingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)
        agent._call_llm("prompt", temperature=0.1)

        assert provider.calls[0]["temperature"] == 0.1
