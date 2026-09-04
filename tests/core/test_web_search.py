"""Tests for TavilySearchClient: relevance-score filtering, the removal of
the include_domains restriction on search_system_internals/
search_adversary_tradecraft, and general client construction/query-building
coverage for the rest of the module.

The min_score filtering and domain-restriction-removal tests were added
after measuring real search results: a domain-restricted query for a narrow
malware topic returned mostly irrelevant filler (score 0.09-0.26) padding
out a couple of genuinely relevant hits, while the same query unrestricted
stayed relevant throughout (score 0.45-0.82).
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


@pytest.mark.unit
class TestExcludeDomainsOnResearchSkills:
    """EXCLUDE_DOMAINS blocks social-media reposts (e.g. the same Hacker News
    article cited 5x over Facebook/LinkedIn/X/Threads/Reddit in one real
    research doc) and URL-tracker tools (e.g. grabify.org cited as a
    "source"). Applied at the API level via Tavily's exclude_domains, unlike
    the removed include_domains allowlist this is a small, low-maintenance
    blocklist of categories that are never a legitimate primary citation
    regardless of topic.
    """

    def test_search_system_internals_excludes_known_junk_domains(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_system_internals("ValleyRAT")

        excluded = fake_tavily.search.call_args.kwargs["exclude_domains"]
        assert "reddit.com" in excluded
        assert "grabify.org" in excluded

    def test_search_adversary_tradecraft_excludes_known_junk_domains(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_adversary_tradecraft("ValleyRAT")

        excluded = fake_tavily.search.call_args.kwargs["exclude_domains"]
        assert "facebook.com" in excluded
        assert "linkedin.com" in excluded

    def test_search_adversary_tradecraft_includes_technique_in_query(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_adversary_tradecraft("ValleyRAT", technique="T1574.001")

        assert "T1574.001" in fake_tavily.search.call_args.kwargs["query"]


@pytest.mark.unit
class TestClientConstruction:
    def test_raises_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        with pytest.raises(ValueError, match="TAVILY_API_KEY"):
            TavilySearchClient(api_key=None)

    def test_uses_env_var_when_no_explicit_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-from-env")
        client = TavilySearchClient(api_key=None)
        assert client.api_key == "tvly-from-env"

    def test_get_client_constructs_and_caches_tavily_client(self, client: TavilySearchClient) -> None:
        fake_tavily_module = MagicMock()
        fake_instance = MagicMock()
        fake_tavily_module.TavilyClient.return_value = fake_instance

        with patch.dict("sys.modules", {"tavily": fake_tavily_module}):
            first = client._get_client()
            second = client._get_client()

        fake_tavily_module.TavilyClient.assert_called_once_with(api_key="fake-key")
        assert first is fake_instance
        assert second is fake_instance  # cached, not re-constructed

    def test_get_client_raises_helpful_error_when_package_missing(self, client: TavilySearchClient) -> None:
        with patch.dict("sys.modules", {"tavily": None}):
            with pytest.raises(ImportError, match="pip install tavily-python"):
                client._get_client()


@pytest.mark.unit
class TestSearchIncludeDomains:
    def test_include_domains_passed_through_when_set(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search("some query", include_domains=["example.com"])

        assert fake_tavily.search.call_args.kwargs["include_domains"] == ["example.com"]

    def test_include_domains_omitted_when_not_set(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search("some query")

        assert "include_domains" not in fake_tavily.search.call_args.kwargs


@pytest.mark.unit
class TestDeadCodeSearchMethods:
    """search_threat_intel/search_detection_methods aren't called by the
    research pipeline (see hunt_researcher.py's skills 1/2, which use
    search_system_internals/search_adversary_tradecraft instead) but remain
    part of the class's public surface -- covering their query construction
    to catch accidental breakage.
    """

    def test_search_threat_intel_builds_expected_query(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_threat_intel("credential dumping", technique="T1003.001")

        query = fake_tavily.search.call_args.kwargs["query"]
        assert "credential dumping" in query
        assert "T1003.001" in query
        assert fake_tavily.search.call_args.kwargs["include_domains"] == TavilySearchClient.SECURITY_DOMAINS

    def test_search_threat_intel_without_technique(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_threat_intel("credential dumping")

        assert fake_tavily.search.call_args.kwargs["query"] == "credential dumping threat hunting detection"

    def test_search_detection_methods_builds_expected_query(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_detection_methods("LSASS access", technique="T1003.001")

        query = fake_tavily.search.call_args.kwargs["query"]
        assert "LSASS access" in query
        assert "T1003.001" in query
        assert "sigma-hq.github.io" in fake_tavily.search.call_args.kwargs["include_domains"]

    def test_search_detection_methods_without_technique(self, client: TavilySearchClient) -> None:
        fake_tavily = MagicMock()
        fake_tavily.search.return_value = {"results": [], "answer": None, "images": []}
        with patch.object(client, "_get_client", return_value=fake_tavily):
            client.search_detection_methods("LSASS access")

        assert fake_tavily.search.call_args.kwargs["query"] == "LSASS access detection rule query sigma"


@pytest.mark.unit
class TestCreateSearchClient:
    def test_returns_none_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        from athf.core.web_search import create_search_client

        assert create_search_client(api_key=None) is None

    def test_returns_client_with_api_key(self) -> None:
        from athf.core.web_search import create_search_client

        result = create_search_client(api_key="fake-key")
        assert isinstance(result, TavilySearchClient)
        assert result.api_key == "fake-key"
