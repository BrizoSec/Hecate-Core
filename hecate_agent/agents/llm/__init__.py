"""LLM-powered agents for Hecate.

These agents use a model-agnostic provider abstraction supporting
Claude, GPT, Gemini, Ollama, and any OpenAI-compatible endpoint.
All LLM agents have fallback to deterministic methods when LLM is disabled.
"""

from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput, ResearchOutput, ResearchSkillOutput
from hecate_agent.agents.llm.hypothesis_generator import (
    HypothesisGenerationInput,
    HypothesisGenerationOutput,
    HypothesisGeneratorAgent,
    ResearchContext,
)
from hecate_agent.agents.llm.pivot_suggester import PivotInput, PivotOutput, PivotSuggesterAgent, PivotSuggestion

__all__ = [
    "HypothesisGeneratorAgent",
    "HypothesisGenerationInput",
    "HypothesisGenerationOutput",
    "ResearchContext",
    "HuntResearcherAgent",
    "ResearchInput",
    "ResearchOutput",
    "ResearchSkillOutput",
    "PivotSuggesterAgent",
    "PivotInput",
    "PivotOutput",
    "PivotSuggestion",
]
