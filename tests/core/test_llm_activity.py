"""The live call log: what a provider call leaves behind while a run is in progress."""

from pathlib import Path
from typing import Any, Dict, List

import pytest

from hecate_agent.core import llm_activity
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse


class _Provider(LLMProvider):
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        if self.fail:
            raise RuntimeError("timed out")
        return LLMResponse(text="ok", input_tokens=1200, output_tokens=80, model="local/model", duration_ms=1500, cost_usd=0.0)

    @property
    def provider_name(self) -> str:
        return "fake"


def _summary(path: Path) -> Dict[str, Any]:
    return llm_activity.summarize_calls(path.read_text().splitlines())


def test_each_call_is_logged_as_it_starts_and_as_it_ends(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    _Provider().complete([])
    _Provider().complete([])
    summary = _summary(log)
    assert summary["llm_calls"] == 2 and summary["in_flight"] == 0 and summary["failed"] == 0
    assert summary["input_tokens"] == 2400 and summary["output_tokens"] == 160
    assert summary["models"] == ["local/model"]


def test_a_call_that_has_not_returned_is_in_flight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    _Provider().complete([])
    seen: List[Dict[str, Any]] = []

    class Slow(_Provider):
        def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
            seen.append(_summary(log))
            return super().complete(messages, max_tokens, temperature)

    Slow().complete([])
    assert seen[0]["llm_calls"] == 1 and seen[0]["in_flight"] == 1
    # The inherited call is one call, however many classes it passes through.
    assert _summary(log)["llm_calls"] == 2


def test_a_failed_call_is_not_left_in_flight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_activity.CALL_LOG_ENV, str(log))
    with pytest.raises(RuntimeError):
        _Provider(fail=True).complete([])
    summary = _summary(log)
    assert summary["failed"] == 1 and summary["in_flight"] == 0 and summary["llm_calls"] == 0


def test_nothing_is_written_unless_a_call_log_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(llm_activity.CALL_LOG_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    _Provider().complete([])
    assert list(tmp_path.iterdir()) == []
    assert llm_activity.summarize_calls([]) == {}
