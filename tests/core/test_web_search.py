"""Tests for TavilySearchClient's relevance-score filtering and the removal
of the include_domains restriction on search_system_internals/
search_adversary_tradecraft.

Full TavilySearchClient coverage (query construction, error handling, etc.)
is a pre-existing gap unrelated to this change and out of scope here -- see
the same note in tests/agents/test_hunt_researcher_grounding.py. This file
only covers the new min_score filtering behavior and the specific domain-
restriction removal, both added after measuring real search results: a
domain-restricted query for a narrow malware topic returned mostly
irrelevant filler (score 0.09-0.26) padding out a couple of genuinely
relevant hits, while the same query unrestricted stayed relevant throughout
(score 0.45-0.82).
"""

from unittest.mock import MagicMock, patch

import pytest

from athf.core.web_search import TavilySearchClient


def _raw_result(title: str, url: str, score: float) -> dict:
    return {"title": title, "url": url, "content": "snippet", "score": score}


@pytest.fixture
def client() -> TavilySearchClient:
    return TavilySearchClient(api_key="fake-key")


@pytest.mark.unit
class TestMinScoreFiltering:
    def test_results_below_min_score_are_dropped(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {
            "results": [
                _raw_result("Relevant", "https://good.example/a", 0.82),
                _raw_result("Borderline", "https://good.example/b", 0.45),
                _raw_result("Irrelevant", "https://bad.example/c", 0.26),
                _raw_result("Also irrelevant", "https://bad.example/d", 0.09),
            ],
            "answer": None,
            "images": [],
        }
        with patch.object(client, "_get_client", return_value=fake_tavily):
            response = client.search("some topic", search_depth="advanced")

        urls = [r.url for r in response.results]
        assert urls == ["https://good.example/a", "https://good.example/b"]

    def test_default_min_score_is_0_3(self, client: TavilySearchClient) -> None:
        assert TavilySearchClient.MIN_RELEVANCE_SCORE == 0.3

    def test_min_score_override_is_respected(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {
            "results": [_raw_result("Kept", "https://x.example/a", 0.2)],
            "answer": None,
            "images": [],
        }
        with patch.object(client, "_get_client", return_value=fake_tavily):
            response = client.search("some topic", min_score=0.1)

        assert len(response.results) == 1

    def test_no_results_survive_min_score_returns_empty_not_error(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {
            "results": [_raw_result("Too weak", "https://x.example/a", 0.05)],
            "answer": None,
            "images": [],
        }
        with patch.object(client, "_get_client", return_value=fake_tavily):
            response = client.search("some topic")

        assert response.results == []


@pytest.mark.unit
class TestNoDomainRestrictionOnResearchSkills:
    def test_search_system_internals_does_not_restrict_domains(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_system_internals("ValleyRAT")

        assert "include_domains" not in fake_tavily.search.call_args.kwargs

    def test_search_adversary_tradecraft_does_not_restrict_domains(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_adversary_tradecraft("ValleyRAT")

        assert "include_domains" not in fake_tavily.search.call_args.kwargs
