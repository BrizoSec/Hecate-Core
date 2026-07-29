"""Tests for the investigate CLI commands."""

import os

import pytest
from click.testing import CliRunner

from athf.commands.investigate import investigate


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
    """Tests for `athf investigate new`."""

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
    """Tests for `athf investigate list`."""

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
    """Tests for `athf investigate search`."""

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
    """Tests for `athf investigate validate`."""

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
