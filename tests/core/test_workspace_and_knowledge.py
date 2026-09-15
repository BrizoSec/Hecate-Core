"""Knowledge files must reach the model regardless of working directory.

Every loader used to resolve `Path.cwd() / "knowledge" / ...`. The
orchestrator happens to set `cwd` to the workspace, so that worked for it --
but it made correctness depend on every caller doing the same, and any caller
that did not got a silent "not found" rather than an error.
"""

import os

import pytest

from hecate_agent.agents.llm.hypothesis_generator import HypothesisGeneratorAgent
from hecate_agent.core.hunting_knowledge import (
    HYPOTHESIS_SECTIONS,
    is_enabled,
    PIVOT_SECTIONS,
    load_sections,
)
from hecate_agent.core.workspace import knowledge_file, workspace_root

KB = """# Hunting Brain

## Section 1: Hypothesis Generation Knowledge

### Patterns
Section one body.

## Section 2: Behavioral Models

### Mapping
Section two body.

## Section 3: Pivot Logic

### Chains
Section three body.

## Section 5: Framework Mental Models

### Pyramid
Section five body.
"""


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: t\n")
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "hunting-knowledge.md").write_text(KB)
    (tmp_path / "knowledge" / "environment.md").write_text("estate")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    return tmp_path


class TestWorkspaceResolution:
    def test_resolves_from_the_env_var_not_the_cwd(self, workspace, tmp_path, monkeypatch):
        elsewhere = tmp_path.parent / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        monkeypatch.chdir(elsewhere)
        assert workspace_root() == workspace
        assert knowledge_file("environment.md").read_text() == "estate"

    def test_walks_up_from_cwd_when_no_env_var(self, workspace, monkeypatch):
        monkeypatch.delenv("HECATE_WORKSPACE", raising=False)
        nested = workspace / "hunts" / "2026"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        assert workspace_root() == workspace

    def test_falls_back_to_cwd_rather_than_raising(self, tmp_path, monkeypatch):
        """A missing workspace should degrade the prompt, not kill a cycle."""
        monkeypatch.delenv("HECATE_WORKSPACE", raising=False)
        monkeypatch.chdir(tmp_path)
        assert workspace_root() == tmp_path

    def test_a_nonexistent_env_path_is_ignored(self, workspace, monkeypatch):
        monkeypatch.setenv("HECATE_WORKSPACE", "/no/such/dir")
        assert workspace_root() != "/no/such/dir"


class TestHuntingKnowledge:
    def test_selects_only_the_requested_sections(self, workspace):
        body = load_sections(HYPOTHESIS_SECTIONS, 10_000)
        assert "Section 1" in body and "Section 2" in body and "Section 5" in body
        assert "Section 3" not in body

    def test_pivot_stage_gets_its_own_section(self, workspace):
        body = load_sections(PIVOT_SECTIONS, 10_000)
        assert "Section 3" in body
        assert "Section 1" not in body

    def test_a_missing_file_yields_nothing_rather_than_a_placeholder(self, tmp_path, monkeypatch):
        """The prompt omits the block entirely; it must not tell the model
        about knowledge it was not given."""
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
        assert load_sections(HYPOTHESIS_SECTIONS, 10_000) == ""

    def test_the_budget_is_respected(self, workspace):
        assert len(load_sections(HYPOTHESIS_SECTIONS, 1200)) <= 1400

    def test_truncation_is_declared(self, workspace):
        assert "excerpted" in load_sections(HYPOTHESIS_SECTIONS, 900)

    def test_a_complete_slice_is_not_labelled_partial(self, workspace):
        assert "excerpted" not in load_sections(PIVOT_SECTIONS, 50_000)

    def test_unknown_section_numbers_are_skipped(self, workspace):
        assert load_sections((99,), 10_000) == ""


class TestPromptDoesNotShipCopyableExamples:
    """H-0001 was scoped to Windows for a Linux Redis compromise because the
    model copied "Windows domain-joined endpoints" straight out of the
    prompt's Location example. ClickHouse reached 5 of 8 hunts the same way."""

    @staticmethod
    def _prompt_text() -> str:
        import inspect

        from hecate_agent.agents.llm import hypothesis_generator

        return inspect.getsource(hypothesis_generator)

    def test_the_location_example_is_gone(self):
        assert "Windows domain-joined endpoints" not in self._prompt_text()

    def test_the_data_source_example_is_gone(self):
        assert "ClickHouse nocsf_unified_events" not in self._prompt_text()

    def test_the_model_is_told_not_to_copy_placeholders(self):
        assert "copying it" in self._prompt_text()


class TestKnowledgeInjectionIsGated:
    """Wiring the knowledge base in is correct; injecting it at the
    hypothesis stage measurably degraded output, so it ships off. Given Linux
    Redis cryptomining CTI the model returned a PowerShell hypothesis, having
    copied 'Good: "PowerShell downloads from temp directories..."' out of the
    tradecraft it was handed."""

    def test_it_is_off_by_default(self, workspace, monkeypatch):
        monkeypatch.delenv("HECATE_HUNTING_KNOWLEDGE", raising=False)
        assert is_enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_it_can_be_switched_on(self, monkeypatch, value):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", value)
        assert is_enabled() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "  "])
    def test_other_values_leave_it_off(self, monkeypatch, value):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", value)
        assert is_enabled() is False

    def test_the_prompt_omits_the_block_when_off(self, workspace, monkeypatch):
        monkeypatch.delenv("HECATE_HUNTING_KNOWLEDGE", raising=False)
        assert HypothesisGeneratorAgent._build_hunting_knowledge_section() == ""

    def test_the_prompt_includes_it_when_on(self, workspace, monkeypatch):
        monkeypatch.setenv("HECATE_HUNTING_KNOWLEDGE", "1")
        section = HypothesisGeneratorAgent._build_hunting_knowledge_section()
        assert "Hunting Tradecraft" in section
        assert "Section 1" in section
