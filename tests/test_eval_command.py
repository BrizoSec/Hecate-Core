"""Tests for the `athf eval` CLI command."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from athf.commands.eval import eval_cmd
from athf.core.eval_harness import EvalReport, Fixture, FixtureResult


@pytest.fixture
def runner():
    return CliRunner()


def _fake_report() -> EvalReport:
    fixture = Fixture(id="T1003.001", category="mitre-technique", prompt="p", keywords=["lsass"])
    report = EvalReport(provider_name="ollama", model="qwen2.5:14b-instruct-q4_K_M")
    report.results.append(
        FixtureResult(fixture=fixture, passed=True, response_text="LSASS memory dumping.", duration_ms=1500)
    )
    return report


class TestEvalCommand:
    def test_table_output_shows_score(self, runner: CliRunner) -> None:
        with (
            patch("athf.core.llm_provider.create_provider", return_value=MagicMock()),
            patch("athf.core.eval_harness.run_eval", return_value=_fake_report()),
        ):
            result = runner.invoke(eval_cmd, [])

        assert result.exit_code == 0
        assert "Score: 1/1" in result.output
        assert "T1003.001" in result.output

    def test_json_output_is_valid_json(self, runner: CliRunner) -> None:
        with (
            patch("athf.core.llm_provider.create_provider", return_value=MagicMock()),
            patch("athf.core.eval_harness.run_eval", return_value=_fake_report()),
        ):
            result = runner.invoke(eval_cmd, ["--output", "json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["passed"] == 1
        assert parsed["total"] == 1

    def test_provider_and_model_overrides_are_passed_through(self, runner: CliRunner) -> None:
        with (
            patch("athf.core.llm_provider.create_provider", return_value=MagicMock()) as mock_create,
            patch("athf.core.eval_harness.run_eval", return_value=_fake_report()),
        ):
            runner.invoke(eval_cmd, ["--provider", "ollama", "--model", "qwen2.5:14b-instruct-q4_K_M"])

        mock_create.assert_called_once_with({"provider": "ollama", "model": "qwen2.5:14b-instruct-q4_K_M"})

    def test_no_overrides_passes_none_to_create_provider(self, runner: CliRunner) -> None:
        with (
            patch("athf.core.llm_provider.create_provider", return_value=MagicMock()) as mock_create,
            patch("athf.core.eval_harness.run_eval", return_value=_fake_report()),
        ):
            runner.invoke(eval_cmd, [])

        mock_create.assert_called_once_with(None)

    def test_provider_creation_failure_aborts_cleanly(self, runner: CliRunner) -> None:
        with patch("athf.core.llm_provider.create_provider", side_effect=RuntimeError("no provider configured")):
            result = runner.invoke(eval_cmd, [])

        assert result.exit_code != 0
        assert "no provider configured" in result.output

    def test_failed_fixtures_are_listed(self, runner: CliRunner) -> None:
        fixture = Fixture(id="T1003.001", category="mitre-technique", prompt="p", keywords=["lsass"])
        report = EvalReport(provider_name="ollama", model="qwen2.5:7b")
        report.results.append(
            FixtureResult(
                fixture=fixture, passed=False, response_text="System Information Discovery.", duration_ms=500
            )
        )
        with (
            patch("athf.core.llm_provider.create_provider", return_value=MagicMock()),
            patch("athf.core.eval_harness.run_eval", return_value=report),
        ):
            result = runner.invoke(eval_cmd, [])

        assert "Failed fixtures" in result.output
        assert "T1003.001" in result.output
