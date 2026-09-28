"""Why a research run has no web searches: the note that marks source-only research."""

import pytest

from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> HuntResearcherAgent:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    return HuntResearcherAgent(llm_enabled=False)


def test_not_requested(agent: HuntResearcherAgent) -> None:
    assert agent._web_search_note(requested=False) == "web search not requested for this item"


def test_no_key(agent: HuntResearcherAgent) -> None:
    assert agent._web_search_note(requested=True) == "no TAVILY_API_KEY configured"


def test_a_failed_search_is_named(agent: HuntResearcherAgent) -> None:
    agent.tavily_api_key = "tvly-test"
    agent._note_search_failure(RuntimeError("403 exceeds your plan's set usage limit"))
    assert agent._web_search_note(requested=True) == "web search failed: RuntimeError: 403 exceeds your plan's set usage limit"


def test_an_unavailable_client_is_named(agent: HuntResearcherAgent, monkeypatch: pytest.MonkeyPatch) -> None:
    import hecate_agent.core.web_search as web_search

    def broken(*args, **kwargs):
        raise ImportError("tavily-python not installed")

    agent.tavily_api_key = "tvly-test"
    monkeypatch.setattr(web_search, "TavilySearchClient", broken)
    assert agent._get_search_client() is None
    assert agent._web_search_note(requested=True).startswith("search client unavailable: tavily-python not installed")


def test_no_note_once_a_search_succeeded(agent: HuntResearcherAgent) -> None:
    agent._web_searches = 2
    assert agent._web_search_note(requested=True) == ""
