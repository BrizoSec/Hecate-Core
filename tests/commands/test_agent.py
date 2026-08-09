"""Tests for athf.commands.agent -- specifically the hypothesis-generator display
function, which had zero direct coverage despite carrying real conditional
logic (ABLE scoping, low-confidence-source banner)."""

import io

import pytest
from rich.console import Console

from athf.agents.base import AgentResult
from athf.agents.llm.hypothesis_generator import HypothesisGenerationOutput
from athf.commands import agent as agent_cmd


def _capture(result: AgentResult) -> str:
    """Render _display_hypothesis_generator_result to a plain-text buffer."""
    buf = io.StringIO()
    original_console = agent_cmd.console
    agent_cmd.console = Console(file=buf, width=100, force_terminal=False)
    try:
        agent_cmd._display_hypothesis_generator_result(result)
    finally:
        agent_cmd.console = original_console
    return buf.getvalue()


def _make_output(**overrides) -> HypothesisGenerationOutput:
    defaults = dict(
        hypothesis="Adversaries use credential dumping to steal hashes",
        justification="Common post-exploitation technique",
        mitre_techniques=["T1003.001"],
        data_sources=["EDR telemetry"],
        expected_observables=["LSASS memory access"],
        known_false_positives=["AV scanning LSASS"],
        time_range_suggestion="7 days",
    )
    defaults.update(overrides)
    return HypothesisGenerationOutput(**defaults)


@pytest.mark.unit
class TestDisplayHypothesisGeneratorResult:
    def test_shows_error_and_returns_early_on_failure(self):
        result = AgentResult(success=False, data=None, error="LLM timed out")
        output = _capture(result)

        assert "LLM timed out" in output
        assert "Hypothesis:" not in output

    def test_shows_core_fields(self):
        result = AgentResult(success=True, data=_make_output(), error=None)
        output = _capture(result)

        assert "Adversaries use credential dumping to steal hashes" in output
        assert "Common post-exploitation technique" in output
        assert "T1003.001" in output
        assert "EDR telemetry" in output
        assert "LSASS memory access" in output
        assert "AV scanning LSASS" in output
        assert "7 days" in output

    def test_shows_able_fields_when_present(self):
        data = _make_output(
            actor="Generic post-exploitation toolkit",
            behavior="Direct syscalls to bypass userland EDR hooks",
            location="Windows domain-joined endpoints",
            evidence="EDR process telemetry - process.name",
        )
        result = AgentResult(success=True, data=data, error=None)
        output = _capture(result)

        assert "Actor:" in output
        assert "Generic post-exploitation toolkit" in output
        assert "Behavior:" in output
        assert "Direct syscalls to bypass userland EDR hooks" in output
        assert "Location:" in output
        assert "Windows domain-joined endpoints" in output
        assert "Evidence:" in output
        assert "EDR process telemetry - process.name" in output

    def test_omits_able_fields_when_empty(self):
        """Default HypothesisGenerationOutput leaves ABLE fields empty --
        each section header must be omitted entirely, not printed with a
        blank value (which would also break a caller line-parsing this
        output, since an empty prose section is indistinguishable from a
        section that was never opened)."""
        result = AgentResult(success=True, data=_make_output(), error=None)
        output = _capture(result)

        assert "Actor:" not in output
        assert "Behavior:" not in output
        assert "Location:" not in output
        assert "Evidence:" not in output

    def test_shows_low_confidence_banner_when_flagged(self):
        data = _make_output(
            is_threat_report=False,
            low_confidence_reason="Source is a vendor compliance announcement, not an incident report.",
        )
        result = AgentResult(success=True, data=data, error=None)
        output = _capture(result)

        assert "Low Confidence Source:" in output
        assert "Source is a vendor compliance announcement, not an incident report." in output

    def test_low_confidence_banner_has_fallback_text_when_reason_empty(self):
        """is_threat_report=False with no reason string still must not
        render a blank/missing explanation."""
        data = _make_output(is_threat_report=False, low_confidence_reason="")
        result = AgentResult(success=True, data=data, error=None)
        output = _capture(result)

        assert "Low Confidence Source:" in output
        assert "does not appear to describe observed adversary behavior" in output

    def test_omits_low_confidence_banner_when_threat_report_true(self):
        """Default HypothesisGenerationOutput has is_threat_report=True --
        must not show the banner at all."""
        result = AgentResult(success=True, data=_make_output(), error=None)
        output = _capture(result)

        assert "Low Confidence Source:" not in output

    def test_shows_warnings_when_present(self):
        result = AgentResult(
            success=True,
            data=_make_output(),
            error=None,
            warnings=["Removed 1 unrecognised ATT&CK ID(s): T9999.999"],
        )
        output = _capture(result)

        assert "Warnings:" in output
        assert "T9999.999" in output


class TestDisplayPivotResult:
    """Tests for _display_pivot_result."""

    def test_shows_finding_summary(self):
        from click.testing import CliRunner
        from athf.commands.agent import agent
        from athf.agents.llm.pivot_suggester import PivotOutput, PivotSuggestion
        from athf.agents.base import AgentResult

        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "athf.agents.llm.pivot_suggester.PivotSuggesterAgent.execute"
        ) as mock_exec:
            mock_exec.return_value = AgentResult(
                success=True,
                data=PivotOutput(
                    finding_summary="PowerShell spawned by Word.",
                    technique_matches=["T1566.001"],
                    pivots=[
                        PivotSuggestion(
                            query="Check network connections from powershell.exe",
                            rationale="C2 beaconing",
                            data_source="EDR",
                            priority=1,
                        )
                    ],
                    past_hunt_references=["H-0012"],
                ),
                metadata={"duration_ms": 10},
            )
            runner = CliRunner()
            result = runner.invoke(
                agent,
                ["run", "pivot-suggester", "--finding",
                 '{"process": "powershell.exe", "parent": "winword.exe"}', "--no-llm"],
            )

        assert result.exit_code == 0
        assert "powershell.exe" in result.output or "Pivot" in result.output

    def test_missing_finding_shows_error(self):
        from click.testing import CliRunner
        from athf.commands.agent import agent

        runner = CliRunner()
        result = runner.invoke(agent, ["run", "pivot-suggester"])
        assert result.exit_code != 0 or "finding" in result.output.lower() or "error" in result.output.lower()

    def test_heuristic_mode_runs_without_llm(self):
        from click.testing import CliRunner
        from athf.commands.agent import agent

        runner = CliRunner()
        result = runner.invoke(
            agent,
            ["run", "pivot-suggester", "--no-llm",
             "--finding", '{"process": "cmd.exe", "parent": "explorer.exe"}'],
        )
        assert result.exit_code == 0
        assert "cmd.exe" in result.output or "Pivot" in result.output

    def test_pivot_suggester_listed_in_agent_list(self):
        from click.testing import CliRunner
        from athf.commands.agent import agent

        runner = CliRunner()
        result = runner.invoke(agent, ["list"])
        assert result.exit_code == 0
        assert "pivot-suggester" in result.output

    def test_pivot_suggester_info_shows_capabilities(self):
        from click.testing import CliRunner
        from athf.commands.agent import agent

        runner = CliRunner()
        result = runner.invoke(agent, ["info", "pivot-suggester"])
        assert result.exit_code == 0
        assert "pivot" in result.output.lower()
        assert "finding" in result.output.lower()
