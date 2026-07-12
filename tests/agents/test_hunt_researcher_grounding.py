"""Tests for HuntResearcherAgent's STIX technique-grounding.

Cold recall (asking a model "what is T1003.001?") measured ~30% accuracy via
`athf eval`; handing the model MITRE's own technique name/description instead
of asking it to recall them raised that to 100% on the same model. These
tests cover the fix that applies that finding to the research prompts.

Full HuntResearcherAgent coverage (web search, related-work correlation,
etc.) is a pre-existing gap unrelated to this change and out of scope here.
"""

import json
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from athf.agents.llm.hunt_researcher import HuntResearcherAgent
from athf.core.llm_provider import LLMProvider, LLMResponse


class CapturingProvider(LLMProvider):
    """Records every prompt it's called with and returns canned JSON."""

    def __init__(self, response_json: Optional[Dict[str, Any]] = None):
        self.prompts: List[str] = []
        self.response_json = response_json or {"summary": "ok", "key_findings": ["finding1"]}
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


FAKE_TECHNIQUE_INFO = {
    "id": "T1053.005",
    "name": "Scheduled Task",
    "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling.",
}


@pytest.mark.unit
class TestTechniqueGrounding:
    def test_returns_empty_string_for_none(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        assert agent._technique_grounding(None) == ""

    def test_returns_empty_string_when_not_found(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        with patch("athf.core.attack_matrix.get_technique", return_value=None):
            assert agent._technique_grounding("T9999.999") == ""

    def test_returns_empty_string_on_lookup_error(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        with patch("athf.core.attack_matrix.get_technique", side_effect=RuntimeError("stix unavailable")):
            assert agent._technique_grounding("T1003.001") == ""

    def test_formats_found_technique(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        with patch("athf.core.attack_matrix.get_technique", return_value=FAKE_TECHNIQUE_INFO):
            grounding = agent._technique_grounding("T1053.005")

        assert "T1053.005" in grounding
        assert "Scheduled Task" in grounding
        assert "Windows Task Scheduler" in grounding

    def test_truncates_long_descriptions(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False)
        long_info = {**FAKE_TECHNIQUE_INFO, "description": "x" * 2000}
        with patch("athf.core.attack_matrix.get_technique", return_value=long_info):
            grounding = agent._technique_grounding("T1053.005")

        assert len(grounding) < 600


@pytest.mark.unit
class TestGroundingWiredIntoPrompts:
    def test_tradecraft_prompt_includes_grounding(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        with patch("athf.core.attack_matrix.get_technique", return_value=FAKE_TECHNIQUE_INFO):
            agent._llm_summarize_tradecraft(
                topic="Scheduled task abuse", technique="T1053.005", sources=[], search_results=None
            )

        assert len(provider.prompts) == 1
        assert "Scheduled Task" in provider.prompts[0]
        assert "Windows Task Scheduler" in provider.prompts[0]

    def test_telemetry_prompt_includes_grounding(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        with patch("athf.core.attack_matrix.get_technique", return_value=FAKE_TECHNIQUE_INFO):
            agent._llm_map_telemetry(
                topic="Scheduled task abuse",
                technique="T1053.005",
                ocsf_schema="{}",
                environment_data="{}",
            )

        assert "Scheduled Task" in provider.prompts[0]

    def test_synthesis_prompt_includes_grounding(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        with patch("athf.core.attack_matrix.get_technique", return_value=FAKE_TECHNIQUE_INFO):
            agent._llm_synthesize(topic="Scheduled task abuse", technique="T1053.005", skills=[])

        assert "Scheduled Task" in provider.prompts[0]

    def test_no_technique_means_no_grounding_block_and_no_crash(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        agent._llm_summarize_tradecraft(
            topic="General topic", technique=None, sources=[], search_results=None
        )

        assert "MITRE ATT&CK ground truth" not in provider.prompts[0]

    def test_missing_stix_data_degrades_gracefully(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        with patch("athf.core.attack_matrix.get_technique", return_value=None):
            summary, findings = agent._llm_summarize_tradecraft(
                topic="Unknown technique", technique="T9999.999", sources=[], search_results=None
            )

        # No grounding available, but the call must still succeed normally.
        assert summary == "ok"
        assert findings == ["finding1"]
        assert "MITRE ATT&CK ground truth" not in provider.prompts[0]
