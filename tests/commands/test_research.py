"""Tests for athf.commands.research -- this module had essentially zero
direct coverage (11.59%) despite `research new` being the command this
session's Tavily-grounding/EXCLUDE_DOMAINS/linked_hunts fixes all revolve
around, and despite carrying the exact linked_hunts extraction logic (the
Finding-2/3 fix's counterpart on the Core side) and the `sources` field this
session added to _display_json_output's related_work block.

Follows the existing conventions in this test tree: CliRunner against real
Click commands + a real ResearchManager working in a chdir'd tmp_path
(matching tests/commands/test_commands.py), and a StringIO console swap for
the two display functions that print directly to the module-level `console`
(matching tests/commands/test_agent.py).
"""

from __future__ import annotations

import importlib
import io
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from rich.console import Console

from athf.agents.base import AgentResult
from athf.agents.llm.hunt_researcher import ResearchOutput, ResearchSkillOutput

# athf/commands/__init__.py does `from athf.commands.research import
# research`, which re-exports the click Group under the *same* name and
# shadows the athf.commands.research *submodule* reference on the package
# object -- `from athf.commands import research` would silently get the
# Group, not the module with _display_json_output etc. on it.
# importlib.import_module goes through sys.modules directly, sidestepping
# that shadowing.
research_cmd = importlib.import_module("athf.commands.research")
research = research_cmd.research  # the click Group, for CliRunner.invoke


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def workspace(tmp_path: Path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    (tmp_path / "research").mkdir()
    yield tmp_path
    os.chdir(old_cwd)


def _skill(name: str, sources: list | None = None, key_findings: list | None = None) -> ResearchSkillOutput:
    return ResearchSkillOutput(
        skill_name=name,
        summary=f"{name} summary",
        key_findings=key_findings if key_findings is not None else [f"{name} finding"],
        sources=sources or [],
        confidence=0.8,
        duration_ms=1000,
    )


def _make_output(**overrides) -> ResearchOutput:
    defaults = dict(
        research_id="R-0099",
        topic="ValleyRAT is spreading disguised as adware",
        mitre_techniques=["T1574.001"],
        system_research=_skill("system_research", sources=[{"title": "Src A", "url": "https://a.example"}]),
        adversary_tradecraft=_skill("adversary_tradecraft"),
        telemetry_mapping=_skill("telemetry_mapping"),
        related_work=_skill(
            "related_work",
            sources=[{"title": "H-0001: Related", "url": "hunts/H-0001.md", "snippet": "..."}],
        ),
        synthesis=_skill("synthesis", key_findings=["Hypothesis: Adversaries do X", "Gap: coverage gap here"]),
        recommended_hypothesis="Adversaries do X",
        data_source_availability={"process_execution": True, "network_connections": False},
        estimated_hunt_complexity="high",
        gaps_identified=["coverage gap here"],
        total_duration_ms=150_000,
        web_searches_performed=2,
        llm_calls=4,
        total_cost_usd=0.01,
    )
    defaults.update(overrides)
    return ResearchOutput(**defaults)


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    original_console = research_cmd.console
    research_cmd.console = Console(file=buf, width=120, force_terminal=False)
    try:
        fn(*args, **kwargs)
    finally:
        research_cmd.console = original_console
    return buf.getvalue()


@pytest.mark.unit
class TestDisplayJsonOutput:
    def test_related_work_includes_sources_field(self) -> None:
        # The exact fix from this session: related_work used to omit
        # "sources" from the JSON output entirely (unlike system_research/
        # adversary_tradecraft, which always had it), so hecate-runner had
        # no structured way to recover related hunt IDs from `--output json`.
        output = _make_output()
        text = _capture(research_cmd._display_json_output, output)
        data = json.loads(text)

        assert data["related_work"]["sources"] == [{"title": "H-0001: Related", "url": "hunts/H-0001.md", "snippet": "..."}]

    def test_all_top_level_fields_present(self) -> None:
        output = _make_output()
        data = json.loads(_capture(research_cmd._display_json_output, output))

        assert data["research_id"] == "R-0099"
        assert data["recommended_hypothesis"] == "Adversaries do X"
        assert data["metrics"]["web_searches"] == 2
        assert data["metrics"]["llm_calls"] == 4


@pytest.mark.unit
class TestGenerateResearchMarkdown:
    def test_includes_all_five_skill_sections(self) -> None:
        md = research_cmd._generate_research_markdown(_make_output())

        assert "## 1. System Research: How It Works" in md
        assert "## 2. Adversary Tradecraft: Attack Techniques" in md
        assert "## 3. Telemetry Mapping: OCSF Fields" in md
        assert "## 4. Related Work: Past Hunts" in md
        assert "## 5. Research Synthesis" in md

    def test_includes_sources_as_markdown_links(self) -> None:
        md = research_cmd._generate_research_markdown(_make_output())
        assert "[Src A](https://a.example)" in md

    def test_omits_sources_heading_when_skill_has_none(self) -> None:
        output = _make_output(adversary_tradecraft=_skill("adversary_tradecraft", sources=[]))
        md = research_cmd._generate_research_markdown(output)
        # Section 2 has no sources -- its own "### Sources" heading must be
        # absent even though skill 1 (which does have one) still has one.
        section_2 = md.split("## 2. Adversary Tradecraft")[1].split("## 3.")[0]
        assert "### Sources" not in section_2

    def test_includes_recommended_hypothesis_and_gaps(self) -> None:
        md = research_cmd._generate_research_markdown(_make_output())
        assert "> Adversaries do X" in md
        assert "- coverage gap here" in md

    def test_omits_hypothesis_section_when_none(self) -> None:
        output = _make_output(recommended_hypothesis=None, gaps_identified=[])
        md = research_cmd._generate_research_markdown(output)
        assert "### Recommended Hypothesis" not in md
        assert "### Gaps Identified" not in md

    def test_includes_cost_and_duration_metrics(self) -> None:
        md = research_cmd._generate_research_markdown(_make_output())
        assert "Web Searches: 2" in md
        assert "LLM Calls: 4" in md
        assert "$0.0100" in md

    def test_minimal_output_omits_all_optional_sections(self) -> None:
        # No mitre_techniques, no sources anywhere, no related-work findings
        # -- every `if ...:` guard in the generator should take its false
        # branch without raising.
        output = _make_output(
            mitre_techniques=[],
            system_research=_skill("system_research", sources=[]),
            related_work=_skill("related_work", sources=[], key_findings=[]),
        )
        md = research_cmd._generate_research_markdown(output)

        assert "**MITRE ATT&CK:**" not in md
        assert "### Related Hunts" not in md


@pytest.mark.unit
class TestDisplayResearchSummary:
    def test_shows_key_fields(self) -> None:
        text = _capture(research_cmd._display_research_summary, _make_output(), Path("research/R-0099.md"))

        assert "Research Complete: R-0099" in text
        assert "Recommended Hypothesis:" in text
        assert "Adversaries do X" in text
        assert "Gaps Identified:" in text
        assert "athf research view R-0099" in text

    def test_omits_hypothesis_and_gaps_when_absent(self) -> None:
        output = _make_output(recommended_hypothesis=None, gaps_identified=[])
        text = _capture(research_cmd._display_research_summary, output, Path("research/R-0099.md"))

        assert "Recommended Hypothesis:" not in text
        assert "Gaps Identified:" not in text


@pytest.mark.unit
class TestNewCommand:
    def test_creates_research_file_and_prints_summary(
        self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=_make_output(), error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        result = runner.invoke(research, ["new", "--topic", "ValleyRAT"])

        assert result.exit_code == 0, result.output
        assert (workspace / "research" / "R-0099.md").exists()
        assert "Research Complete" in result.output

    def test_linked_hunts_extracted_from_related_work_sources(
        self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=_make_output(), error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        runner.invoke(research, ["new", "--topic", "ValleyRAT"])

        content = (workspace / "research" / "R-0099.md").read_text()
        assert "linked_hunts:\n- H-0001" in content or "linked_hunts: [H-0001]" in content or "- H-0001" in content

    def test_json_output_format(self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=_make_output(), error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        result = runner.invoke(research, ["new", "--topic", "ValleyRAT", "--output", "json"])

        assert result.exit_code == 0, result.output
        # Output has a progress banner before the JSON, same as hecate-runner's
        # athf_client.py has to parse around -- just confirm the JSON object
        # is present and parses.
        start = result.output.find("{")
        json.loads(result.output[start:])

    def test_agent_failure_aborts_with_error(self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=False, data=None, error="LLM timed out", warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        result = runner.invoke(research, ["new", "--topic", "ValleyRAT"])

        assert result.exit_code != 0
        assert "LLM timed out" in result.output
        assert not (workspace / "research" / "R-0099.md").exists()

    def test_success_but_no_data_aborts(self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Defensive branch: success=True but data=None shouldn't happen in
        # practice, but the command guards against it rather than crashing
        # on `output.research_id` against None.
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=None, error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        result = runner.invoke(research, ["new", "--topic", "ValleyRAT"])

        assert result.exit_code != 0
        assert "No output data" in result.output

    def test_technique_option_is_echoed(self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=_make_output(), error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        result = runner.invoke(research, ["new", "--topic", "ValleyRAT", "--technique", "T1574.001"])

        assert "Technique:" in result.output
        assert "T1574.001" in result.output

    def test_source_url_not_matching_hunt_pattern_is_skipped(
        self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        output = _make_output(
            related_work=_skill("related_work", sources=[{"title": "Not a hunt", "url": "research/R-0002.md"}])
        )
        fake_agent = MagicMock()
        fake_agent.execute.return_value = AgentResult(success=True, data=output, error=None, warnings=[], metadata={})
        monkeypatch.setattr("athf.agents.llm.hunt_researcher.HuntResearcherAgent", lambda llm_enabled: fake_agent)

        runner.invoke(research, ["new", "--topic", "ValleyRAT"])

        content = (workspace / "research" / "R-0099.md").read_text()
        assert "linked_hunts: []" in content


@pytest.mark.unit
class TestListCommand:
    def test_no_research_shows_message(self, runner: CliRunner, workspace: Path) -> None:
        result = runner.invoke(research, ["list"])
        assert result.exit_code == 0
        assert "No research documents found" in result.output

    def test_lists_created_research(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        manager = ResearchManager()
        manager.create_research_file(
            research_id="R-0001",
            topic="Test topic",
            content="body",
            frontmatter={"mitre_techniques": ["T1003.001"], "total_cost_usd": 0.01},
        )

        result = runner.invoke(research, ["list"])

        assert result.exit_code == 0
        assert "R-0001" in result.output
        assert "Test topic" in result.output

    def test_json_output_format(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="Test topic", content="body", frontmatter={}
        )

        result = runner.invoke(research, ["list", "--output", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["research_id"] == "R-0001"

    def test_more_than_two_techniques_are_truncated_with_ellipsis(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001",
            topic="Test topic",
            content="body",
            frontmatter={"mitre_techniques": ["T1003.001", "T1055", "T1574.001"]},
        )

        result = runner.invoke(research, ["list"])

        assert "T1003.001, T1055..." in result.output


@pytest.mark.unit
class TestViewCommand:
    def test_not_found_aborts(self, runner: CliRunner, workspace: Path) -> None:
        result = runner.invoke(research, ["view", "R-9999"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_view_markdown(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="Test topic", content="# body content", frontmatter={}
        )

        result = runner.invoke(research, ["view", "R-0001"])

        assert result.exit_code == 0
        assert "body content" in result.output

    def test_view_json(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="Test topic", content="# body content", frontmatter={}
        )

        result = runner.invoke(research, ["view", "R-0001", "--output", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["research_id"] == "R-0001"

    def test_missing_file_path_in_research_data_shows_error(
        self, runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "athf.core.research_manager.ResearchManager.get_research",
            lambda self, research_id: {"research_id": research_id},  # no "file_path" key
        )

        result = runner.invoke(research, ["view", "R-0001"])

        assert "Research file not found" in result.output


@pytest.mark.unit
class TestSearchCommand:
    def test_no_matches_shows_message(self, runner: CliRunner, workspace: Path) -> None:
        result = runner.invoke(research, ["search", "nonexistent-topic-xyz"])
        assert result.exit_code == 0
        assert "No research documents found matching" in result.output

    def test_finds_matching_research(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="ValleyRAT adware campaign", content="body", frontmatter={}
        )

        result = runner.invoke(research, ["search", "ValleyRAT"])

        assert result.exit_code == 0
        assert "R-0001" in result.output

    def test_json_output_format(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="ValleyRAT adware campaign", content="body", frontmatter={}
        )

        result = runner.invoke(research, ["search", "ValleyRAT", "--output", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["research_id"] == "R-0001"


@pytest.mark.unit
class TestStatsCommand:
    def test_empty_stats(self, runner: CliRunner, workspace: Path) -> None:
        result = runner.invoke(research, ["stats"])
        assert result.exit_code == 0
        assert "Total Research: 0" in result.output

    def test_json_output_format(self, runner: CliRunner, workspace: Path) -> None:
        result = runner.invoke(research, ["stats", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total_research" in data

    def test_by_status_breakdown_shown_when_present(self, runner: CliRunner, workspace: Path) -> None:
        from athf.core.research_manager import ResearchManager

        ResearchManager().create_research_file(
            research_id="R-0001", topic="Test topic", content="body", frontmatter={"status": "completed"}
        )

        result = runner.invoke(research, ["stats"])

        assert "By Status:" in result.output
        assert "completed: 1" in result.output
