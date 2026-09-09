"""Tests for HuntResearcherAgent's anti-hallucination instruction on the
system-research/adversary-tradecraft LLM summarization prompts.

Web search snippets are truncated to 200 chars each (barely more than a
headline) -- asking for "4-6 key findings about attack methods, tools used,
and indicators" from a handful of title+200-char fragments pressures the
model to invent plausible-sounding specifics to fill the gap. A real,
observed case (research doc topic: a Talos report quoting a captured
attacker<->AI-agent prompt log, title "Keep going, bro. You've got this!")
fabricated an unrelated claim ("malware embeds this phrase to manipulate
victims") that wasn't supported by any of the provided sources.

The "flag uncertain claims with [UNCERTAIN]" instruction used to only appear
in the zero-sources fallback context string, so it never applied to a case
like the one above where thin-but-nonzero sources existed. These tests cover
making that instruction unconditional.

Also covers the source-quality-weighing sentence added alongside it: a
generic tutorial/explainer domain (oxfordhomestudy.com, a "how does AI
work?" tutoring-site blog) got cited as a research source because it was
topically relevant to an otherwise-vague CTI topic. web_search.py's
EXCLUDE_DOMAINS handles known social-media/tracker domains at the API level,
but can't anticipate every generic content-mill site -- this instruction
asks the model to weigh source authority itself instead.

Full HuntResearcherAgent coverage (web search, related-work correlation,
etc.) is a pre-existing gap unrelated to this change and out of scope here
-- see the same note in test_hunt_researcher_grounding.py.
"""

import json
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from hecate_agent.agents.llm.hunt_researcher import _GROUNDING_INSTRUCTION, HuntResearcherAgent
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse


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


@pytest.mark.unit
class TestTradecraftAntiHallucination:
    def test_instruction_present_with_real_sources(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        with patch("hecate_agent.core.attack_matrix.get_technique", return_value=None):
            agent._llm_summarize_tradecraft(
                topic="Keep going, bro",
                technique=None,
                sources=[{"title": "Some catchy headline", "url": "https://example.com", "snippet": "thin snippet"}],
                search_results=None,
            )

        assert _GROUNDING_INSTRUCTION in provider.prompts[0]

    def test_instruction_present_with_zero_sources(self) -> None:
        # This is the exact gap that let R-0005's fabrication through: the
        # old code only put a grounding instruction in the zero-sources
        # fallback text. Confirm the unconditional instruction is there too,
        # regardless of what the fallback context text also says.
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        agent._llm_summarize_tradecraft(topic="Obscure topic", technique=None, sources=[], search_results=None)

        assert _GROUNDING_INSTRUCTION in provider.prompts[0]


@pytest.mark.unit
class TestSystemResearchAntiHallucination:
    def test_instruction_present_with_real_sources(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        agent._llm_summarize_system_research(
            topic="Some system",
            sources=[{"title": "Some doc", "url": "https://example.com", "snippet": "thin snippet"}],
            search_results=None,
        )

        assert _GROUNDING_INSTRUCTION in provider.prompts[0]

    def test_instruction_present_with_zero_sources(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        agent._llm_summarize_system_research(topic="Obscure topic", sources=[], search_results=None)

        assert _GROUNDING_INSTRUCTION in provider.prompts[0]


@pytest.mark.unit
class TestSourceQualityWeighing:
    """_GROUNDING_INSTRUCTION also tells the model to discount low-authority
    sources (personal blogs, generic tutorials) even when topically relevant
    -- the EXCLUDE_DOMAINS blocklist in web_search.py only catches known
    social-media/tracker domains, not the long tail of content-mill sites.
    """

    def test_instruction_mentions_source_quality(self) -> None:
        assert "source quality" in _GROUNDING_INSTRUCTION
        assert "low-authority" in _GROUNDING_INSTRUCTION

    def test_tradecraft_prompt_includes_source_quality_guidance(self) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)

        agent._llm_summarize_tradecraft(
            topic="Some topic",
            technique=None,
            sources=[{"title": "How Does AI Work? Explained Simply", "url": "https://example.com", "snippet": "..."}],
            search_results=None,
        )

        assert "source quality" in provider.prompts[0]
        assert "low-authority" in provider.prompts[0]
