"""Coverage for athf.commands.agent's `list`/`info` commands, the `run`
command's dispatch to each of the three agents (hypothesis-generator,
hunt-researcher, pivot-suggester), and the two display functions
(_display_pivot_result, _display_research_result) that had zero coverage
before this. _display_hypothesis_generator_result already has dedicated
tests in test_agent.py; this file doesn't duplicate those.
"""

from __future__ import annotations

import importlib
import io
import json
from typing import Any

import pytest
from click.testing import CliRunner
from rich.console import Console

from athf.agents.base import AgentResult
from athf.agents.llm.hunt_researcher import ResearchOutput, ResearchSkillOutput
from athf.agents.llm.pivot_suggester import PivotOutput, PivotSuggestion

# athf/commands/__init__.py does `from athf.commands.agent import agent`,
# shadowing the submodule reference the same way it does for `research` --
# see the note in test_research.py.
agent_cmd = importlib.import_module("athf.commands.agent")
agent = agent_cmd.agent


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    original_console = agent_cmd.console
    agent_cmd.console = Console(file=buf, width=120, force_terminal=False)
    try:
        fn(*args, **kwargs)
    finally:
        agent_cmd.console = original_console
    return buf.getvalue()


@pytest.mark.unit
class TestListCommand:
    def test_lists_registered_agents(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["list"])
        assert result.exit_code == 0
        assert "hypothesis-generator" in result.output
        assert "hunt-researcher" in result.output
        assert "pivot-suggester" in result.output


@pytest.mark.unit
class TestInfoCommand:
    def test_unknown_agent_aborts_and_lists_available(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["info", "not-a-real-agent"])
        assert result.exit_code != 0
        assert "not found" in result.output
        assert "hypothesis-generator" in result.output

    def test_known_agent_shows_details(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["info", "hypothesis-generator"])
        assert result.exit_code == 0
        assert "Capabilities:" in result.output
        assert "Usage:" in result.output

    def test_research_skills_shown_when_present(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["info", "hunt-researcher"])
        assert result.exit_code == 0
        assert "Research Skills:" in result.output


def _fake_hypothesis_agent(success: bool = True, error: str | None = None) -> Any:
    from athf.agents.llm.hypothesis_generator import HypothesisGenerationOutput

    data = (
        HypothesisGenerationOutput(
            hypothesis="Adversaries dump credentials",
            justification="Common technique",
            mitre_techniques=["T1003.001"],
            data_sources=["EDR"],
            expected_observables=["lsass access"],
            known_false_positives=["AV scan"],
            time_range_suggestion="7 days",
        )
        if success
        else None
    )
    result = AgentResult(success=success, data=data, error=error, warnings=[], metadata={"duration_ms": 1000})
    fake = type("FakeAgent", (), {"execute": lambda self, input_data: result})()
    return fake


@pytest.mark.unit
class TestRunHypothesisGenerator:
    def test_requires_threat_intel(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["run", "hypothesis-generator"])
        assert result.exit_code != 0
        assert "--threat-intel required" in result.output

    def test_success_displays_result(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )

        result = runner.invoke(agent, ["run", "hypothesis-generator", "--threat-intel", "APT29 credential theft"])

        assert result.exit_code == 0, result.output
        assert "Hypothesis generated successfully" in result.output

    def test_json_output_format(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )

        result = runner.invoke(
            agent, ["run", "hypothesis-generator", "--threat-intel", "APT29", "--output-format", "json"]
        )

        assert result.exit_code == 0, result.output
        json.loads(result.output)

    def test_agent_execution_error_aborts(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)

        def _raise(llm_enabled):
            raise RuntimeError("provider unavailable")

        monkeypatch.setattr("athf.agents.llm.HypothesisGeneratorAgent", _raise)

        result = runner.invoke(agent, ["run", "hypothesis-generator", "--threat-intel", "APT29"])

        assert result.exit_code != 0
        assert "provider unavailable" in result.output

    def test_research_option_loads_context_when_found(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.get_research",
            lambda self, research_id: {"research_id": research_id},
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.extract_research_context",
            lambda self, doc: {"topic": "fake"},
        )

        result = runner.invoke(
            agent, ["run", "hypothesis-generator", "--threat-intel", "APT29", "--research", "R-0001"]
        )

        assert "Loaded research context from R-0001" in result.output

    def test_research_option_warns_when_not_found(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.get_research", lambda self, research_id: None
        )

        result = runner.invoke(
            agent, ["run", "hypothesis-generator", "--threat-intel", "APT29", "--research", "R-9999"]
        )

        assert "not found" in result.output

    def test_technique_option_auto_discovers_research(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.find_by_technique",
            lambda self, technique: {"frontmatter": {"research_id": "R-0042"}},
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.extract_research_context",
            lambda self, doc: {"topic": "fake"},
        )

        result = runner.invoke(
            agent, ["run", "hypothesis-generator", "--threat-intel", "APT29", "--technique", "T1003.001"]
        )

        assert "Auto-discovered research R-0042 for T1003.001" in result.output

    def test_research_context_load_error_warns_not_aborts(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.get_research",
            lambda self, research_id: (_ for _ in ()).throw(RuntimeError("db locked")),
        )

        result = runner.invoke(
            agent, ["run", "hypothesis-generator", "--threat-intel", "APT29", "--research", "R-0001"]
        )

        assert result.exit_code == 0, result.output
        assert "Could not load research context" in result.output

    def test_environment_md_read_error_degrades_gracefully(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "athf.agents.llm.HypothesisGeneratorAgent", lambda llm_enabled: _fake_hypothesis_agent()
        )
        (tmp_path / "knowledge").mkdir()
        bad_file = tmp_path / "knowledge" / "environment.md"
        bad_file.write_text("data")
        monkeypatch.setattr("pathlib.Path.read_text", lambda self, **kw: (_ for _ in ()).throw(OSError("permission denied")))

        result = runner.invoke(agent, ["run", "hypothesis-generator", "--threat-intel", "APT29"])

        assert result.exit_code == 0, result.output  # degrades to environment={}, doesn't crash

    def test_import_error_shows_install_hints(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)

        def _raise(llm_enabled):
            raise ImportError("no LLM provider installed")

        monkeypatch.setattr("athf.agents.llm.HypothesisGeneratorAgent", _raise)

        result = runner.invoke(agent, ["run", "hypothesis-generator", "--threat-intel", "APT29"])

        assert result.exit_code != 0
        assert "Install an LLM provider" in result.output
        assert "pip install 'athf[litellm]'" in result.output

    def test_environment_md_loaded_when_present(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        captured = {}

        def _capturing_execute(self, input_data):
            captured["environment"] = input_data.environment
            return AgentResult(success=True, data=_fake_hypothesis_agent().execute(None).data, error=None, warnings=[], metadata={})

        (tmp_path / "knowledge").mkdir()
        (tmp_path / "knowledge" / "environment.md").write_text("# Our environment\nSplunk + CrowdStrike")

        from athf.agents.llm.hypothesis_generator import HypothesisGeneratorAgent

        monkeypatch.setattr(HypothesisGeneratorAgent, "execute", _capturing_execute)
        monkeypatch.setattr("athf.agents.llm.HypothesisGeneratorAgent", HypothesisGeneratorAgent)

        runner.invoke(agent, ["run", "hypothesis-generator", "--threat-intel", "APT29"])

        assert "environment_md" in captured["environment"]
        assert "Splunk" in captured["environment"]["environment_md"]


def _make_research_output(**overrides) -> ResearchOutput:
    def _skill(name: str) -> ResearchSkillOutput:
        return ResearchSkillOutput(skill_name=name, summary=f"{name} summary", key_findings=["f1"], sources=[], confidence=0.8)

    defaults = dict(
        research_id="R-0099",
        topic="ValleyRAT",
        mitre_techniques=["T1574.001"],
        system_research=_skill("system_research"),
        adversary_tradecraft=_skill("adversary_tradecraft"),
        telemetry_mapping=_skill("telemetry_mapping"),
        related_work=_skill("related_work"),
        synthesis=_skill("synthesis"),
        recommended_hypothesis="Adversaries do X",
        gaps_identified=["a gap"],
        total_duration_ms=60000,
        web_searches_performed=2,
        llm_calls=4,
        total_cost_usd=0.01,
    )
    defaults.update(overrides)
    return ResearchOutput(**defaults)


@pytest.mark.unit
class TestRunHuntResearcher:
    def test_requires_topic(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["run", "hunt-researcher"])
        assert result.exit_code != 0
        assert "--topic required" in result.output

    def test_success_displays_result(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=True, data=_make_research_output(), error=None, warnings=[], metadata={})},
        )()
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "hunt-researcher", "--topic", "ValleyRAT", "--technique", "T1574.001"])

        assert result.exit_code == 0, result.output
        assert "Research Complete: R-0099" in result.output

    def test_failure_aborts(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=False, data=None, error="search timed out", warnings=[], metadata={})},
        )()
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "hunt-researcher", "--topic", "ValleyRAT"])

        assert result.exit_code != 0
        assert "search timed out" in result.output

    def test_import_error_shows_install_hints(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(llm_enabled):
            raise ImportError("tavily-python not installed")

        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", _raise)

        result = runner.invoke(agent, ["run", "hunt-researcher", "--topic", "ValleyRAT"])

        assert result.exit_code != 0
        assert "Install an LLM provider" in result.output
        assert "pip install tavily-python" in result.output

    def test_json_output_format(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=True, data=_make_research_output(), error=None, warnings=[], metadata={"x": 1})},
        )()
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "hunt-researcher", "--topic", "ValleyRAT", "--output-format", "json"])

        assert result.exit_code == 0, result.output
        # A progress banner (Starting Research/Topic/Depth) prints before the
        # JSON payload even in --output-format json, same pattern
        # hecate-runner's athf_client.py has to parse around for `research
        # new`.
        start = result.output.find("{")
        json.loads(result.output[start:])


@pytest.mark.unit
class TestRunPivotSuggester:
    def test_requires_finding(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["run", "pivot-suggester"])
        assert result.exit_code != 0
        assert "--finding required" in result.output

    def test_success_displays_result(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        data = PivotOutput(
            finding_summary="Suspicious PowerShell execution",
            technique_matches=["T1059.001"],
            pivots=[
                PivotSuggestion(query="search parent=powershell.exe", rationale="check origin", data_source="EDR", priority=1, technique_hint="T1059.001"),
                PivotSuggestion(query="search network dst=*", rationale="check C2", data_source="Zeek", priority=2),
            ],
            past_hunt_references=["H-0001"],
        )
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=True, data=data, error=None, warnings=[], metadata={"mode": "llm"})},
        )()
        monkeypatch.setattr("athf.agents.llm.pivot_suggester.PivotSuggesterAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "pivot-suggester", "--finding", '{"process": "powershell.exe"}'])

        assert result.exit_code == 0, result.output
        assert "Pivot Analysis" in result.output
        assert "T1059.001" in result.output
        assert "H-0001" in result.output

    def test_heuristic_mode_shows_note(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        data = PivotOutput(finding_summary="A finding", pivots=[])
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=True, data=data, error=None, warnings=[], metadata={"mode": "heuristic"})},
        )()
        monkeypatch.setattr("athf.agents.llm.pivot_suggester.PivotSuggesterAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "pivot-suggester", "--finding", "some finding text"])

        assert "heuristic mode" in result.output

    def test_failure_aborts(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=False, data=None, error="LLM error", warnings=[], metadata={})},
        )()
        monkeypatch.setattr("athf.agents.llm.pivot_suggester.PivotSuggesterAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "pivot-suggester", "--finding", "x"])

        assert result.exit_code != 0
        assert "LLM error" in result.output

    def test_import_error_shows_install_hints(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(llm_enabled):
            raise ImportError("no provider")

        monkeypatch.setattr("athf.agents.llm.pivot_suggester.PivotSuggesterAgent", _raise)

        result = runner.invoke(agent, ["run", "pivot-suggester", "--finding", "x"])

        assert result.exit_code != 0
        assert "Install an LLM provider" in result.output

    def test_json_output_format(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        data = PivotOutput(finding_summary="A finding", pivots=[])
        fake = type(
            "FakeAgent",
            (),
            {"execute": lambda self, input_data: AgentResult(success=True, data=data, error=None, warnings=[], metadata={})},
        )()
        monkeypatch.setattr("athf.agents.llm.pivot_suggester.PivotSuggesterAgent", lambda llm_enabled: fake)

        result = runner.invoke(agent, ["run", "pivot-suggester", "--finding", "x", "--output-format", "json"])

        assert result.exit_code == 0, result.output
        json.loads(result.output)


@pytest.mark.unit
class TestRunUnknownAgent:
    def test_unknown_agent_name_aborts(self, runner: CliRunner) -> None:
        result = runner.invoke(agent, ["run", "not-a-real-agent", "--threat-intel", "x"])
        assert result.exit_code != 0
        assert "Unknown agent" in result.output
        assert "hypothesis-generator" in result.output


@pytest.mark.unit
class TestDisplayResearchResult:
    def test_error_result_shows_error_and_returns(self) -> None:
        result = AgentResult(success=False, data=None, error="boom", warnings=[], metadata={})
        text = _capture(agent_cmd._display_research_result, result)
        assert "Agent Error: boom" in text

    def test_success_shows_summary_and_next_steps(self) -> None:
        result = AgentResult(success=True, data=_make_research_output(), error=None, warnings=[], metadata={})
        text = _capture(agent_cmd._display_research_result, result)

        assert "Research Complete: R-0099" in text
        assert "Recommended Hypothesis:" in text
        assert "Gaps Identified:" in text
        assert "athf research view R-0099" in text

    def test_omits_hypothesis_and_gaps_when_absent(self) -> None:
        output = _make_research_output(recommended_hypothesis=None, gaps_identified=[])
        result = AgentResult(success=True, data=output, error=None, warnings=[], metadata={})
        text = _capture(agent_cmd._display_research_result, result)

        assert "Recommended Hypothesis:" not in text
        assert "Gaps Identified:" not in text
