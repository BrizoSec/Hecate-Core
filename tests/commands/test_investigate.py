"""Tests for the investigate CLI commands."""

import os

import pytest
import yaml
from click.testing import CliRunner

from hecate_agent.commands.investigate import investigate


@pytest.fixture()
def runner():
    """Click test runner."""
    return CliRunner()


@pytest.fixture()
def workspace(tmp_path):
    """Change cwd to a temp workspace with an investigations/ dir."""
    old = os.getcwd()
    os.chdir(tmp_path)
    (tmp_path / "investigations").mkdir()
    (tmp_path / "hunts").mkdir()
    yield tmp_path
    os.chdir(old)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_INVESTIGATION_CONTENT = """\
---
investigation_id: {inv_id}
title: {title}
date: "2026-01-01"
investigator: Tester
type: exploratory
tags:
- powershell
data_sources:
- EDR
related_hunts: []
---

## LEARN: Context & Background

Some context about {title}.

## KEEP: Findings & Next Steps

Some findings here.
"""


def _write_investigation(investigations_dir, inv_id="I-0001", title="Test Investigation"):
    f = investigations_dir / f"{inv_id}.md"
    f.write_text(VALID_INVESTIGATION_CONTENT.format(inv_id=inv_id, title=title))
    return f


# ---------------------------------------------------------------------------
# `investigate new`
# ---------------------------------------------------------------------------


class TestInvestigateNew:
    """Tests for `hecate-agent investigate new`."""

    def test_new_non_interactive_creates_file(self, runner, workspace):
        result = runner.invoke(investigate, ["new", "--title", "PowerShell Triage", "--non-interactive"])

        assert result.exit_code == 0
        assert (workspace / "investigations" / "I-0001.md").exists()

    def test_new_non_interactive_file_contains_title(self, runner, workspace):
        runner.invoke(investigate, ["new", "--title", "My Hunt", "--non-interactive"])

        content = (workspace / "investigations" / "I-0001.md").read_text()
        assert "My Hunt" in content

    def test_new_non_interactive_missing_title_shows_error(self, runner, workspace):
        result = runner.invoke(investigate, ["new", "--non-interactive"])

        assert result.exit_code == 0  # CLI returns 0 but prints error
        assert "required" in result.output.lower() or "error" in result.output.lower()
        assert not (workspace / "investigations" / "I-0001.md").exists()

    def test_new_non_interactive_with_type(self, runner, workspace):
        runner.invoke(
            investigate,
            ["new", "--title", "Alert Triage", "--type", "finding", "--non-interactive"],
        )

        content = (workspace / "investigations" / "I-0001.md").read_text()
        assert "finding" in content

    def test_new_non_interactive_with_tags(self, runner, workspace):
        runner.invoke(
            investigate,
            ["new", "--title", "T", "--tags", "powershell,alert", "--non-interactive"],
        )

        content = (workspace / "investigations" / "I-0001.md").read_text()
        assert "powershell" in content
        assert "alert" in content

    def test_new_non_interactive_with_data_source(self, runner, workspace):
        runner.invoke(
            investigate,
            ["new", "--title", "T", "--data-source", "EDR", "--non-interactive"],
        )

        content = (workspace / "investigations" / "I-0001.md").read_text()
        assert "EDR" in content

    def test_new_non_interactive_with_related_hunt(self, runner, workspace):
        runner.invoke(
            investigate,
            ["new", "--title", "T", "--related-hunt", "H-0013", "--non-interactive"],
        )

        content = (workspace / "investigations" / "I-0001.md").read_text()
        assert "H-0013" in content

    def test_new_sequential_ids(self, runner, workspace):
        runner.invoke(investigate, ["new", "--title", "First", "--non-interactive"])
        runner.invoke(investigate, ["new", "--title", "Second", "--non-interactive"])

        assert (workspace / "investigations" / "I-0001.md").exists()
        assert (workspace / "investigations" / "I-0002.md").exists()

    def test_new_output_confirms_creation(self, runner, workspace):
        result = runner.invoke(investigate, ["new", "--title", "My Inv", "--non-interactive"])

        assert "I-0001" in result.output


# ---------------------------------------------------------------------------
# `investigate list`
# ---------------------------------------------------------------------------


class TestInvestigateList:
    """Tests for `hecate-agent investigate list`."""

    def test_list_empty_shows_no_investigations_message(self, runner, workspace):
        result = runner.invoke(investigate, ["list"])

        assert result.exit_code == 0
        assert "no investigations" in result.output.lower()

    def test_list_shows_created_investigation(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list"])

        assert result.exit_code == 0
        assert "I-0001" in result.output

    def test_list_filter_by_type_match(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--type", "exploratory"])

        assert result.exit_code == 0
        assert "I-0001" in result.output

    def test_list_filter_by_type_no_match(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--type", "finding"])

        assert result.exit_code == 0
        assert "no investigations" in result.output.lower()

    def test_list_filter_by_tags_match(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--tags", "powershell"])

        assert result.exit_code == 0
        assert "I-0001" in result.output

    def test_list_filter_by_tags_no_match(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--tags", "kerberos"])

        assert result.exit_code == 0
        assert "no investigations" in result.output.lower()

    def test_list_json_output(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--output", "json"])

        assert result.exit_code == 0
        assert "I-0001" in result.output
        # JSON should have curly braces
        assert "{" in result.output

    def test_list_yaml_output(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["list", "--output", "yaml"])

        assert result.exit_code == 0
        assert "investigation_id" in result.output


# ---------------------------------------------------------------------------
# `investigate search`
# ---------------------------------------------------------------------------


class TestInvestigateSearch:
    """Tests for `hecate-agent investigate search`."""

    def test_search_empty_dir_shows_message(self, runner, workspace):
        result = runner.invoke(investigate, ["search", "powershell"])

        assert result.exit_code == 0
        assert "no investigation" in result.output.lower()

    def test_search_finds_match(self, runner, workspace):
        _write_investigation(workspace / "investigations", title="PowerShell Triage")

        result = runner.invoke(investigate, ["search", "PowerShell"])

        assert result.exit_code == 0
        assert "I-0001" in result.output

    def test_search_case_insensitive(self, runner, workspace):
        _write_investigation(workspace / "investigations", title="Kerberoasting Hunt")

        result = runner.invoke(investigate, ["search", "kerberoasting"])

        assert result.exit_code == 0
        assert "I-0001" in result.output

    def test_search_no_match_shows_message(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["search", "xyzzy_not_present"])

        assert result.exit_code == 0
        assert "no matches" in result.output.lower()

    def test_search_shows_count(self, runner, workspace):
        _write_investigation(workspace / "investigations", "I-0001", "Context here")
        _write_investigation(workspace / "investigations", "I-0002", "Context also here")

        result = runner.invoke(investigate, ["search", "context"])

        assert result.exit_code == 0
        assert "2" in result.output


# ---------------------------------------------------------------------------
# `investigate validate`
# ---------------------------------------------------------------------------


class TestInvestigateValidate:
    """Tests for `hecate-agent investigate validate`."""

    def test_validate_invalid_id_format(self, runner, workspace):
        result = runner.invoke(investigate, ["validate", "BAD-ID"])

        assert result.exit_code == 0
        assert "invalid" in result.output.lower()

    def test_validate_file_not_found(self, runner, workspace):
        result = runner.invoke(investigate, ["validate", "I-0099"])

        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_validate_valid_investigation(self, runner, workspace):
        _write_investigation(workspace / "investigations")

        result = runner.invoke(investigate, ["validate", "I-0001"])

        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_invalid_investigation(self, runner, workspace):
        bad = workspace / "investigations" / "I-0001.md"
        bad.write_text("---\ninvestigation_id: I-0001\n---\n\nmissing title and date\n")

        result = runner.invoke(investigate, ["validate", "I-0001"])

        assert result.exit_code == 0
        # Should report errors
        assert "error" in result.output.lower() or "title" in result.output.lower()


# ---------------------------------------------------------------------------
# `investigate promote`
# ---------------------------------------------------------------------------


class TestInvestigatePromote:
    """Characterisation tests for `hecate-agent investigate promote`.

    Written to pin current behaviour before the command is restructured: it
    carries a complexity of 16 in a module that had no test coverage at all,
    so a refactor had nothing to check it against.
    """

    def _promote(self, runner, inv_id="I-0001", extra=None):
        args = ["promote", inv_id, "--technique", "T1059.001", "--non-interactive"]
        return runner.invoke(investigate, args + (extra or []))

    # --- Guard rails ---------------------------------------------------

    def test_rejects_a_malformed_investigation_id(self, runner, workspace):
        result = runner.invoke(investigate, ["promote", "nonsense", "--non-interactive"])
        assert "Invalid investigation ID format" in result.output
        assert not list((workspace / "hunts").rglob("H-*.md"))

    def test_reports_a_missing_investigation(self, runner, workspace):
        result = self._promote(runner, "I-0404")
        assert "not found" in result.output
        assert not list((workspace / "hunts").rglob("H-*.md"))

    def test_non_interactive_requires_a_technique(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        result = runner.invoke(investigate, ["promote", "I-0001", "--non-interactive"])
        assert "--technique required" in result.output
        assert not list((workspace / "hunts").rglob("H-*.md"))

    def test_unparseable_investigation_does_not_create_a_hunt(self, runner, workspace):
        (workspace / "investigations" / "I-0001.md").write_text("---\n: : not yaml : :\n---\n")
        self._promote(runner)
        assert not list((workspace / "hunts").rglob("H-*.md"))

    # --- Happy path ----------------------------------------------------

    def test_creates_a_hunt_file(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        result = self._promote(runner)
        assert result.exit_code == 0
        assert len(list((workspace / "hunts").rglob("H-*.md"))) == 1

    def test_hunt_carries_the_investigation_metadata(self, runner, workspace):
        _write_investigation(workspace / "investigations", title="PowerShell Triage")
        self._promote(runner)

        hunt = next((workspace / "hunts").rglob("H-*.md"))
        frontmatter = yaml.safe_load(hunt.read_text().split("---")[1])
        assert frontmatter["title"] == "PowerShell Triage"
        assert frontmatter["hunter"] == "Tester"
        assert frontmatter["spawned_from"] == "I-0001"
        assert frontmatter["techniques"] == ["T1059.001"]
        assert frontmatter["data_sources"] == ["EDR"]
        assert frontmatter["tags"] == ["powershell"]

    def test_counters_start_at_zero(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        self._promote(runner)
        hunt = next((workspace / "hunts").rglob("H-*.md"))
        frontmatter = yaml.safe_load(hunt.read_text().split("---")[1])
        assert frontmatter["findings_count"] == 0
        assert frontmatter["true_positives"] == 0
        assert frontmatter["false_positives"] == 0

    def test_tactics_and_platforms_pass_through(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        self._promote(runner, extra=["--tactic", "execution", "--platform", "Windows"])

        hunt = next((workspace / "hunts").rglob("H-*.md"))
        frontmatter = yaml.safe_load(hunt.read_text().split("---")[1])
        assert frontmatter["tactics"] == ["execution"]
        assert frontmatter["platform"] == ["Windows"]

    def test_status_defaults_to_in_progress_and_is_overridable(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        self._promote(runner)
        hunt = next((workspace / "hunts").rglob("H-*.md"))
        assert yaml.safe_load(hunt.read_text().split("---")[1])["status"] == "in-progress"

    def test_status_override(self, runner, workspace):
        _write_investigation(workspace / "investigations")
        self._promote(runner, extra=["--status", "planning"])
        hunt = next((workspace / "hunts").rglob("H-*.md"))
        assert yaml.safe_load(hunt.read_text().split("---")[1])["status"] == "planning"

    def test_investigation_body_is_carried_into_the_hunt(self, runner, workspace):
        _write_investigation(workspace / "investigations", title="Carried Body")
        self._promote(runner)
        hunt = next((workspace / "hunts").rglob("H-*.md"))
        assert "Some context about Carried Body" in hunt.read_text()

    # --- Back-references on the investigation ---------------------------

    def test_investigation_records_the_new_hunt(self, runner, workspace):
        inv = _write_investigation(workspace / "investigations")
        self._promote(runner)

        hunt_id = next((workspace / "hunts").rglob("H-*.md")).stem
        frontmatter = yaml.safe_load(inv.read_text().split("---")[1])
        assert frontmatter["related_hunts"] == [hunt_id]

    def test_investigation_gets_a_promotion_note(self, runner, workspace):
        inv = _write_investigation(workspace / "investigations")
        self._promote(runner)
        hunt_id = next((workspace / "hunts").rglob("H-*.md")).stem
        assert f"**Promoted to Hunt:** {hunt_id}" in inv.read_text()

    def test_a_null_related_hunts_field_is_handled(self, runner, workspace):
        """`related_hunts:` with no value parses as None, not a list."""
        inv = workspace / "investigations" / "I-0001.md"
        inv.write_text(
            VALID_INVESTIGATION_CONTENT.format(inv_id="I-0001", title="T").replace("related_hunts: []", "related_hunts:")
        )
        self._promote(runner)
        hunt_id = next((workspace / "hunts").rglob("H-*.md")).stem
        assert yaml.safe_load(inv.read_text().split("---")[1])["related_hunts"] == [hunt_id]

    # --- Interactive mode ----------------------------------------------

    def test_interactive_mode_prompts_for_metadata(self, runner, workspace, monkeypatch):
        _write_investigation(workspace / "investigations")
        answers = iter(["T1078", "credential-access", "Linux", "planning"])
        monkeypatch.setattr("hecate_agent.commands._investigate_lifecycle.Prompt.ask", lambda *a, **k: next(answers))

        result = runner.invoke(investigate, ["promote", "I-0001"])
        assert result.exit_code == 0

        hunt = next((workspace / "hunts").rglob("H-*.md"))
        frontmatter = yaml.safe_load(hunt.read_text().split("---")[1])
        assert frontmatter["techniques"] == ["T1078"]
        assert frontmatter["tactics"] == ["credential-access"]
        assert frontmatter["platform"] == ["Linux"]
        assert frontmatter["status"] == "planning"
