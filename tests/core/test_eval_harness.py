"""Tests for athf.core.eval_harness - known-answer model spot checks."""

from typing import Dict, List, Optional
from unittest.mock import patch

import pytest

from athf.core.eval_harness import FIXTURES, Fixture, build_grounded_fixtures, run_eval
from athf.core.llm_provider import LLMProvider, LLMResponse


class FakeProvider(LLMProvider):
    """Returns a fixed or per-prompt-keyed response instead of calling a real model."""

    def __init__(self, responses: Optional[Dict[str, str]] = None, default: str = "", model: str = "fake-model"):
        self.responses = responses or {}
        self.default = default
        self.model = model

    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        prompt = messages[0]["content"]
        text = self.responses.get(prompt, self.default)
        return LLMResponse(text=text, input_tokens=10, output_tokens=10, model=self.model, duration_ms=1, cost_usd=0.0)


class FailingProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        raise ConnectionError("simulated failure")


LSASS_FIXTURE = Fixture(
    id="T1003.001",
    category="mitre-technique",
    prompt="What is T1003.001?",
    keywords=["lsass"],
)

MULTI_KEYWORD_FIXTURE = Fixture(
    id="T1566.001",
    category="mitre-technique",
    prompt="What is T1566.001?",
    keywords=["spearphishing", "attachment"],
    match_mode="all",
)


@pytest.mark.unit
def test_run_eval_passes_on_matching_keyword() -> None:
    provider = FakeProvider(responses={LSASS_FIXTURE.prompt: "This dumps LSASS memory."})
    report = run_eval(provider, fixtures=[LSASS_FIXTURE])
    assert report.passed_count == 1
    assert report.score == 1.0
    assert report.results[0].passed


@pytest.mark.unit
def test_run_eval_fails_on_hallucinated_answer() -> None:
    provider = FakeProvider(responses={LSASS_FIXTURE.prompt: "System Information Discovery."})
    report = run_eval(provider, fixtures=[LSASS_FIXTURE])
    assert report.passed_count == 0
    assert report.score == 0.0
    assert not report.results[0].passed


@pytest.mark.unit
def test_run_eval_case_insensitive() -> None:
    provider = FakeProvider(responses={LSASS_FIXTURE.prompt: "This targets LSASS.EXE memory."})
    report = run_eval(provider, fixtures=[LSASS_FIXTURE])
    assert report.results[0].passed


@pytest.mark.unit
def test_run_eval_all_match_mode_requires_every_keyword() -> None:
    provider = FakeProvider(responses={MULTI_KEYWORD_FIXTURE.prompt: "This is a spearphishing technique."})
    report = run_eval(provider, fixtures=[MULTI_KEYWORD_FIXTURE])
    # "attachment" is missing, so an "all" match_mode fixture must fail
    assert not report.results[0].passed


@pytest.mark.unit
def test_run_eval_all_match_mode_passes_with_every_keyword() -> None:
    provider = FakeProvider(
        responses={MULTI_KEYWORD_FIXTURE.prompt: "Spearphishing via a malicious attachment."}
    )
    report = run_eval(provider, fixtures=[MULTI_KEYWORD_FIXTURE])
    assert report.results[0].passed


@pytest.mark.unit
def test_run_eval_isolates_a_single_fixture_error() -> None:
    provider = FailingProvider()
    report = run_eval(provider, fixtures=[LSASS_FIXTURE, MULTI_KEYWORD_FIXTURE])
    assert report.total_count == 2
    assert report.passed_count == 0
    assert all(r.error == "simulated failure" for r in report.results)


@pytest.mark.unit
def test_eval_report_to_dict_is_json_serializable() -> None:
    import json

    provider = FakeProvider(responses={LSASS_FIXTURE.prompt: "LSASS memory dumping."})
    report = run_eval(provider, fixtures=[LSASS_FIXTURE])
    # Must not raise — this is what the CLI's --output json path relies on.
    serialized = json.dumps(report.to_dict())
    parsed = json.loads(serialized)
    assert parsed["passed"] == 1
    assert parsed["total"] == 1


@pytest.mark.unit
def test_default_fixtures_are_well_formed() -> None:
    assert len(FIXTURES) > 0
    ids = [f.id for f in FIXTURES]
    assert len(ids) == len(set(ids)), "fixture ids must be unique"
    for fixture in FIXTURES:
        assert fixture.prompt.strip()
        assert len(fixture.keywords) > 0


# ---------------------------------------------------------------------------
# build_grounded_fixtures
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_grounded_fixture_embeds_stix_description() -> None:
    fake_info = {
        "id": "T1003.001",
        "name": "LSASS Memory",
        "description": "Adversaries dump LSASS process memory to harvest credentials.",
    }
    with patch("athf.core.attack_matrix.get_technique", return_value=fake_info):
        grounded = build_grounded_fixtures([LSASS_FIXTURE])

    assert len(grounded) == 1
    fixture = grounded[0]
    assert fixture.id == "T1003.001-grounded"
    assert fixture.category == "mitre-technique-grounded"
    assert "LSASS Memory" in fixture.prompt
    assert "harvest credentials" in fixture.prompt
    assert fixture.keywords == LSASS_FIXTURE.keywords


@pytest.mark.unit
def test_grounded_fixtures_skip_missing_stix_data() -> None:
    with patch("athf.core.attack_matrix.get_technique", return_value=None):
        grounded = build_grounded_fixtures([LSASS_FIXTURE])

    assert grounded == []


@pytest.mark.unit
def test_grounded_fixtures_exclude_non_technique_categories() -> None:
    concept_fixture = Fixture(
        id="lolbin", category="concept", prompt="What is a LOLBin?", keywords=["living off the land"]
    )
    fake_info = {"id": "T1003.001", "name": "LSASS Memory", "description": "..."}
    with patch("athf.core.attack_matrix.get_technique", return_value=fake_info):
        grounded = build_grounded_fixtures([LSASS_FIXTURE, concept_fixture])

    # Only the mitre-technique fixture should produce a grounded variant.
    assert len(grounded) == 1
    assert grounded[0].id == "T1003.001-grounded"


@pytest.mark.unit
def test_grounded_fixtures_preserve_match_mode() -> None:
    fake_info = {"id": "T1566.001", "name": "Spearphishing Attachment", "description": "Phishing via attachment."}
    with patch("athf.core.attack_matrix.get_technique", return_value=fake_info):
        grounded = build_grounded_fixtures([MULTI_KEYWORD_FIXTURE])

    assert grounded[0].match_mode == "all"
    assert grounded[0].keywords == MULTI_KEYWORD_FIXTURE.keywords


@pytest.mark.unit
def test_grounded_fixtures_default_to_module_fixtures_when_none_given() -> None:
    fake_info = {"id": "x", "name": "x", "description": "x"}
    with patch("athf.core.attack_matrix.get_technique", return_value=fake_info):
        grounded = build_grounded_fixtures()

    mitre_technique_count = sum(1 for f in FIXTURES if f.category == "mitre-technique")
    assert len(grounded) == mitre_technique_count
