"""
Tests for ATHF CLI commands using actual implementation.
"""

import os

import pytest
import yaml
from click.testing import CliRunner

from athf.commands.hunt import hunt
from athf.commands.init import init


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace for testing."""
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(old_cwd)


class TestInitCommand:
    """Test suite for athf init command."""

    def test_init_creates_structure_non_interactive(self, runner, temp_workspace):
        """Test that init creates the correct directory structure in non-interactive mode."""
        result = runner.invoke(init, ["--non-interactive"])

        assert result.exit_code == 0
        assert (temp_workspace / "hunts").exists()
        assert (temp_workspace / "queries").exists()
        assert (temp_workspace / "runs").exists()
        assert (temp_workspace / "templates").exists()
        assert (temp_workspace / "knowledge").exists()
        assert (temp_workspace / "prompts").exists()
        assert (temp_workspace / "integrations").exists()
        assert (temp_workspace / "docs").exists()

    def test_init_creates_config_file(self, runner, temp_workspace):
        """Test that init creates a valid config file."""
        result = runner.invoke(init, ["--non-interactive"])

        assert result.exit_code == 0
        config_path = temp_workspace / "config" / ".athfconfig.yaml"
        assert config_path.exists()

        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        assert "hunt_prefix" in config
        assert "siem" in config
        assert "edr" in config
        assert config["hunt_prefix"] == "H-"

    def test_init_creates_agents_file(self, runner, temp_workspace):
        """Test that init creates AGENTS.md."""
        result = runner.invoke(init, ["--non-interactive"])

        assert result.exit_code == 0
        agents_path = temp_workspace / "AGENTS.md"
        assert agents_path.exists()

        content = agents_path.read_text()
        assert "Data Sources" in content
        assert "Technology Stack" in content

    def test_init_creates_hunt_template(self, runner, temp_workspace):
        """Test that init creates hunt template."""
        result = runner.invoke(init, ["--non-interactive"])

        assert result.exit_code == 0
        template_path = temp_workspace / "templates" / "HUNT_LOCK.md"
        assert template_path.exists()

        content = template_path.read_text()
        assert "## LEARN" in content
        assert "## OBSERVE" in content
        assert "## CHECK" in content
        assert "## KEEP" in content

    def test_init_with_custom_path(self, runner, tmp_path):
        """Test init with custom path."""
        custom_path = tmp_path / "custom_workspace"
        custom_path.mkdir()

        result = runner.invoke(init, ["--path", str(custom_path), "--non-interactive"])

        assert result.exit_code == 0
        assert (custom_path / "hunts").exists()
        assert (custom_path / "config" / ".athfconfig.yaml").exists()


class TestHuntNewCommand:
    """Test suite for athf hunt new command."""

    def test_hunt_new_non_interactive(self, runner, temp_workspace):
        """Test creating a new hunt in non-interactive mode."""
        # First initialize
        runner.invoke(init, ["--non-interactive"])

        # Create hunt
        result = runner.invoke(
            hunt,
            [
                "new",
                "--technique",
                "T1003.001",
                "--title",
                "LSASS Memory Dumping",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--data-source",
                "EDR",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0
        # Extract created hunt ID from output (init may copy sample hunts)
        import re

        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"Could not find hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        # Check hunt file was created (search recursively for hierarchical structure)
        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1, f"Expected 1 hunt file, found {len(hunt_files)}"
        hunt_file = hunt_files[0]

        content = hunt_file.read_text()
        assert f"hunt_id: {hunt_id}" in content
        assert "LSASS Memory Dumping" in content
        assert "T1003.001" in content
        assert "## LEARN" in content

    def test_hunt_new_missing_title_non_interactive(self, runner, temp_workspace):
        """Test that hunt new fails without title in non-interactive mode."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["new", "--technique", "T1003.001", "--non-interactive"])

        assert result.exit_code == 0  # Click doesn't exit with error, just prints message
        assert "Error" in result.output or "required" in result.output.lower()

    def test_hunt_new_increments_id(self, runner, temp_workspace):
        """Test that hunt IDs increment correctly."""
        import re

        runner.invoke(init, ["--non-interactive"])

        # Create first hunt
        result1 = runner.invoke(hunt, ["new", "--title", "First Hunt", "--non-interactive"])
        match1 = re.search(r"Created (H-\d+)", result1.output)
        assert match1, f"Could not find hunt ID in output: {result1.output}"
        hunt_id_1 = match1.group(1)
        num1 = int(hunt_id_1.split("-")[1])

        # Create second hunt
        result2 = runner.invoke(hunt, ["new", "--title", "Second Hunt", "--non-interactive"])
        match2 = re.search(r"Created (H-\d+)", result2.output)
        assert match2, f"Could not find hunt ID in output: {result2.output}"
        hunt_id_2 = match2.group(1)
        num2 = int(hunt_id_2.split("-")[1])

        # Second hunt should have ID incremented by 1
        assert num2 == num1 + 1, f"Expected {hunt_id_2} to be one more than {hunt_id_1}"

    def test_hunt_new_auto_derives_tactic_from_technique(self, runner, temp_workspace, monkeypatch):
        """When --tactic is omitted, tactic should be auto-derived from --technique
        via the ATT&CK provider. With STIX data, T1003.001 must yield
        credential-access (NOT the legacy hardcoded "collection" default).

        Patches `get_technique` so the test runs without a STIX cache.
        """
        import re

        # Patch the provider lookup used by hunt.py. We patch on the
        # module object directly because `athf.commands.hunt` has a
        # click Group named `hunt` that shadows attribute-style lookup.
        import sys

        hunt_mod = sys.modules["athf.commands.hunt"]

        def fake_get_technique(tid):
            if tid == "T1003.001":
                return {
                    "id": "T1003.001",
                    "name": "LSASS Memory",
                    "tactic_shortnames": ["credential-access"],
                }
            return None

        monkeypatch.setattr(hunt_mod, "get_technique", fake_get_technique)

        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Auto-tactic Hunt",
                "--technique",
                "T1003.001",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0, result.output
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"Could not find hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1
        content = hunt_files[0].read_text()

        assert "credential-access" in content, (
            "Expected auto-derived tactic 'credential-access' in hunt frontmatter; " "got hunt content:\n" + content
        )
        # Make sure we did NOT regress to the legacy hardcoded default.
        assert "tactics: [collection]" not in content
        assert "tactics:\n- collection" not in content

    def test_hunt_new_falls_back_when_technique_unknown(self, runner, temp_workspace, monkeypatch):
        """If the provider can't resolve the technique (e.g. fallback provider in
        use), the legacy default of 'collection' is preserved so existing
        behavior is unchanged for users without STIX data."""
        import re

        import sys

        hunt_mod = sys.modules["athf.commands.hunt"]
        monkeypatch.setattr(hunt_mod, "get_technique", lambda _tid: None)

        runner.invoke(init, ["--non-interactive"])
        result = runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Fallback Default Hunt",
                "--technique",
                "T1003.001",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0, result.output
        match = re.search(r"Created (H-\d+)", result.output)
        assert match
        hunt_id = match.group(1)
        content = next((temp_workspace / "hunts").rglob(f"{hunt_id}.md")).read_text()
        assert "tactics: [collection]" in content or "tactics:\n- collection" in content

    def test_hunt_new_with_multiple_tactics(self, runner, temp_workspace):
        """Test creating hunt with multiple tactics."""
        import re

        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Multi-Tactic Hunt",
                "--tactic",
                "persistence",
                "--tactic",
                "privilege-escalation",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0
        # Extract created hunt ID from output
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"Could not find hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        # Search recursively for hunt file in hierarchical structure
        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1, f"Expected 1 hunt file, found {len(hunt_files)}"
        hunt_file = hunt_files[0]
        content = hunt_file.read_text()
        assert "persistence" in content
        assert "privilege-escalation" in content

    def test_hunt_new_with_rich_content(self, runner, temp_workspace):
        """Test creating hunt with rich content parameters (hypothesis, threat-context, ABLE framework)."""
        import re

        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Rich Content Hunt",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--data-source",
                "Sysmon",
                "--hypothesis",
                "Adversaries dump LSASS memory to extract credentials",
                "--threat-context",
                "APT29 and ransomware groups commonly use this technique",
                "--actor",
                "APT29, Ransomware operators",
                "--behavior",
                "Process access to lsass.exe with PROCESS_VM_READ",
                "--location",
                "Windows endpoints, Domain Controllers",
                "--evidence",
                "Sysmon Event ID 10, EDR process access events",
                "--hunter",
                "Test Hunter",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0
        # Extract created hunt ID from output
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"Could not find hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        # Search recursively for hunt file in hierarchical structure
        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1, f"Expected 1 hunt file, found {len(hunt_files)}"
        hunt_file = hunt_files[0]
        content = hunt_file.read_text()

        # Verify YAML frontmatter
        assert f"hunt_id: {hunt_id}" in content
        assert "hunter: Test Hunter" in content

        # Verify hypothesis is populated
        assert "Adversaries dump LSASS memory to extract credentials" in content

        # Verify threat context is populated
        assert "APT29 and ransomware groups commonly use this technique" in content

        # Verify ABLE framework fields are populated
        assert "APT29, Ransomware operators" in content
        assert "Process access to lsass.exe with PROCESS_VM_READ" in content
        assert "Windows endpoints, Domain Controllers" in content
        assert "Sysmon Event ID 10, EDR process access events" in content

        # Verify it's not using default placeholders
        assert "[What behavior are you looking for?" not in content
        assert "[What threat actor/malware/TTP motivates this hunt?]" not in content
        assert "[Threat actor or malware family]" not in content


class TestHuntOutputPath:
    """Ensure hunt files land in hunts/{year}/{quarter}/, never in hunts/production/."""

    def test_hunt_new_path_is_year_quarter(self, runner, temp_workspace):
        """Production hunts must be written to hunts/{year}/{quarter}/, not hunts/production/."""
        import re
        from datetime import datetime

        runner.invoke(init, ["--non-interactive"])
        result = runner.invoke(hunt, ["new", "--title", "Path Check Hunt", "--non-interactive"])

        assert result.exit_code == 0
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"No hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1, f"Expected exactly 1 hunt file, found {len(hunt_files)}"
        hunt_file = hunt_files[0]

        parts = hunt_file.relative_to(temp_workspace / "hunts").parts
        # Must be exactly (year, quarter, filename) — no 'production' prefix
        assert len(parts) == 3, f"Expected hunts/YYYY/QN/H-XXXX.md, got hunts/{'/'.join(parts)}"
        year_part, quarter_part, _ = parts
        assert year_part == str(datetime.now().year), f"Expected year {datetime.now().year}, got {year_part}"
        assert re.match(r"Q[1-4]", quarter_part), f"Expected Q1-Q4, got {quarter_part}"

    def test_hunt_new_never_creates_production_directory(self, runner, temp_workspace):
        """The word 'production' must not appear in any part of a new hunt's file path."""
        import re

        runner.invoke(init, ["--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Anti-Production Hunt", "--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Anti-Production Hunt 2", "--non-interactive"])

        hunt_files = list((temp_workspace / "hunts").rglob("H-*.md"))
        for f in hunt_files:
            assert "production" not in f.parts, (
                f"Hunt file landed in a 'production' directory: {f}\n"
                "get_hunt_directory() must return hunts/YYYY/QN/, not hunts/production/YYYY/QN/"
            )

    def test_hunt_new_test_flag_creates_in_test_path(self, runner, temp_workspace):
        """Hunts created with --test must land in hunts/test/{year}/{quarter}/."""
        import re
        from datetime import datetime

        runner.invoke(init, ["--non-interactive"])
        result = runner.invoke(hunt, ["new", "--title", "Test-Flag Hunt", "--test", "--non-interactive"])

        assert result.exit_code == 0
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"No hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        hunt_files = list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))
        assert len(hunt_files) == 1
        hunt_file = hunt_files[0]

        parts = hunt_file.relative_to(temp_workspace / "hunts").parts
        assert parts[0] == "test", f"Expected hunts/test/YYYY/QN/, got hunts/{'/'.join(parts)}"
        assert parts[1] == str(datetime.now().year)
        assert re.match(r"Q[1-4]", parts[2])

    def test_promote_rejects_non_test_hunt(self, runner, temp_workspace):
        """promote must reject a hunt that is not in a test/ directory."""
        import re

        runner.invoke(init, ["--non-interactive"])
        result = runner.invoke(hunt, ["new", "--title", "Regular Hunt", "--non-interactive"])
        match = re.search(r"Created (H-\d+)", result.output)
        hunt_id = match.group(1)

        promote_result = runner.invoke(hunt, ["promote", hunt_id, "--yes"])
        assert "not in a test directory" in promote_result.output, (
            f"Expected 'not in a test directory' message, got: {promote_result.output}"
        )
        # File must not have moved
        assert len(list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))) == 1


class TestHuntNewBaselineCommand:
    """Test suite for athf hunt new-baseline command."""

    def test_requires_title_in_non_interactive_mode(self, runner, temp_workspace):
        """Test that --title is required for non-interactive baseline creation."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["new-baseline", "--non-interactive"])

        assert result.exit_code != 0 or "required" in result.output.lower()

    def test_creates_baseline_hunt_with_hunt_type(self, runner, temp_workspace):
        """Test that a baseline hunt is created with hunt_type: baseline and no hypothesis."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(
            hunt,
            [
                "new-baseline",
                "--title",
                "Parent-Child Process Baseline",
                "--dimension",
                "parent_process -> child_process pairs",
                "--platform",
                "Windows",
                "--data-source",
                "EDR",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 0
        assert "Created" in result.output

        hunt_files = list((temp_workspace / "hunts").rglob("H-*.md"))
        matching = [f for f in hunt_files if "Parent-Child" in f.read_text(encoding="utf-8")]
        assert len(matching) == 1

        content = matching[0].read_text(encoding="utf-8")
        assert "hunt_type: baseline" in content
        assert "dimension: parent_process -> child_process pairs" in content
        assert "Hypothesis Statement" not in content
        assert "## LEARN: Prepare the Baseline" in content

    def test_shares_hunt_id_sequence_with_regular_hunts(self, runner, temp_workspace):
        """Baseline hunts use the same H-XXXX counter as hypothesis-driven hunts,
        not a separate ID space."""
        runner.invoke(init, ["--non-interactive"])
        first = runner.invoke(hunt, ["new", "--title", "Regular Hunt", "--non-interactive"])
        second = runner.invoke(
            hunt,
            ["new-baseline", "--title", "Baseline Hunt", "--dimension", "test dimension", "--non-interactive"],
        )

        import re

        first_id = re.search(r"Created (H-\d+):", first.output).group(1)
        second_id = re.search(r"Created (H-\d+):", second.output).group(1)

        assert int(second_id.split("-")[1]) == int(first_id.split("-")[1]) + 1


class TestHuntListCommand:
    """Test suite for athf hunt list command."""

    def setup_test_hunts(self, runner, temp_workspace):
        """Helper to create test hunts."""
        runner.invoke(init, ["--non-interactive"])

        # Create hunt 1
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Test Hunt 1",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--non-interactive",
            ],
        )

        # Create hunt 2
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Test Hunt 2",
                "--technique",
                "T1053.003",
                "--tactic",
                "persistence",
                "--platform",
                "Linux",
                "--non-interactive",
            ],
        )

    def test_hunt_list_all(self, runner, temp_workspace):
        """Test listing all hunts (uses JSON output for reliable assertions)."""
        self.setup_test_hunts(runner, temp_workspace)

        result = runner.invoke(hunt, ["list", "--output", "json"])

        assert result.exit_code == 0
        assert "Test Hunt 1" in result.output
        assert "Test Hunt 2" in result.output

    def test_hunt_list_table_has_date(self, runner, temp_workspace):
        """Test that table output includes a Date column header."""
        self.setup_test_hunts(runner, temp_workspace)

        result = runner.invoke(hunt, ["list"])

        assert result.exit_code == 0
        assert "Date" in result.output

    def test_hunt_list_filter_by_status(self, runner, temp_workspace):
        """Test filtering hunts by status (uses JSON output for reliable assertions)."""
        self.setup_test_hunts(runner, temp_workspace)

        result = runner.invoke(hunt, ["list", "--status", "planning", "--output", "json"])

        assert result.exit_code == 0
        assert "Test Hunt 1" in result.output or "Test Hunt 2" in result.output

    def test_hunt_list_filter_by_technique(self, runner, temp_workspace):
        """Test filtering hunts by technique (uses JSON output for reliable assertions)."""
        self.setup_test_hunts(runner, temp_workspace)

        result = runner.invoke(hunt, ["list", "--technique", "T1003.001", "--output", "json"])

        assert result.exit_code == 0
        assert "T1003.001" in result.output

    def test_hunt_list_json_output(self, runner, temp_workspace):
        """Test JSON output format."""
        self.setup_test_hunts(runner, temp_workspace)

        result = runner.invoke(hunt, ["list", "--output", "json"])

        assert result.exit_code == 0
        assert '"hunt_id"' in result.output or "hunt_id" in result.output

    def test_hunt_list_filter_by_type(self, runner, temp_workspace):
        """Test filtering by hunt type separates baseline from hypothesis-driven hunts."""
        import json

        self.setup_test_hunts(runner, temp_workspace)
        # init seeds a few bundled example hunts on top of the two created by
        # setup_test_hunts, so assert an invariant (baseline + hypothesis-driven
        # == everything) rather than a magic total count.
        all_result = runner.invoke(hunt, ["list", "--output", "json"])
        all_hunts = json.loads(all_result.output)

        runner.invoke(
            hunt,
            ["new-baseline", "--title", "Process Baseline", "--dimension", "parent-child pairs", "--non-interactive"],
        )

        baseline_result = runner.invoke(hunt, ["list", "--type", "baseline", "--output", "json"])
        baseline_hunts = json.loads(baseline_result.output)
        assert len(baseline_hunts) == 1
        assert baseline_hunts[0]["title"] == "Process Baseline"

        hypothesis_result = runner.invoke(hunt, ["list", "--type", "hypothesis-driven", "--output", "json"])
        hypothesis_hunts = json.loads(hypothesis_result.output)
        assert all(h["title"] != "Process Baseline" for h in hypothesis_hunts)
        assert len(hypothesis_hunts) == len(all_hunts)  # unchanged -- baseline hunt didn't exist yet

    def test_hunt_list_empty(self, runner, temp_workspace):
        """Test list with no user-created hunts (sample hunts may exist)."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["list"])

        # init may copy sample hunts, so this test just checks the command works
        # If no sample hunts exist, we'll see "No hunts found"
        # If sample hunts exist, we'll see the hunt catalog
        assert result.exit_code == 0
        assert "No hunts found" in result.output or "Hunt Catalog" in result.output or "H-" in result.output


class TestHuntValidateCommand:
    """Test suite for athf hunt validate command."""

    def test_validate_all_hunts(self, runner, temp_workspace):
        """Test validating all hunts."""
        runner.invoke(init, ["--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["validate"])

        assert result.exit_code == 0

    def test_validate_specific_hunt(self, runner, temp_workspace):
        """Test validating a specific hunt."""
        runner.invoke(init, ["--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["validate", "H-0001"])

        assert result.exit_code == 0

    def test_validate_nonexistent_hunt(self, runner, temp_workspace):
        """Test validating a hunt that doesn't exist."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["validate", "H-9999"])

        assert result.exit_code == 0  # Command runs but shows error message
        assert "not found" in result.output.lower()


class TestHuntStatsCommand:
    """Test suite for athf hunt stats command."""

    def test_hunt_stats_empty(self, runner, temp_workspace):
        """Test stats with no hunts."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["stats"])

        assert result.exit_code == 0
        assert "Statistics" in result.output or "stats" in result.output.lower()

    def test_hunt_stats_with_hunts(self, runner, temp_workspace):
        """Test stats with hunts created."""
        runner.invoke(init, ["--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["stats"])

        assert result.exit_code == 0
        assert "Total Hunts" in result.output or "total" in result.output.lower()


class TestHuntSearchCommand:
    """Test suite for athf hunt search command."""

    def test_hunt_search(self, runner, temp_workspace):
        """Test searching for hunts."""
        runner.invoke(init, ["--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Kerberoasting Detection", "--technique", "T1558.003", "--non-interactive"])

        result = runner.invoke(hunt, ["search", "Kerberoasting"])

        assert result.exit_code == 0

    def test_hunt_search_no_results(self, runner, temp_workspace):
        """Test search with no results."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["search", "nonexistent"])

        assert result.exit_code == 0
        assert "No hunts found" in result.output or "found" in result.output.lower()


class TestHuntCoverageCommand:
    """Test suite for athf hunt coverage command."""

    def test_hunt_coverage(self, runner, temp_workspace):
        """Test ATT&CK coverage command."""
        runner.invoke(init, ["--non-interactive"])
        runner.invoke(
            hunt,
            ["new", "--title", "Test Hunt", "--technique", "T1003.001", "--tactic", "credential-access", "--non-interactive"],
        )

        result = runner.invoke(hunt, ["coverage"])

        assert result.exit_code == 0

    def test_hunt_coverage_empty(self, runner, temp_workspace):
        """Test coverage with no hunts."""
        runner.invoke(init, ["--non-interactive"])

        result = runner.invoke(hunt, ["coverage"])

        assert result.exit_code == 0


class TestHuntBriefCommand:
    """Test suite for athf hunt brief command."""

    FILLED_KEEP_HUNT = """---
hunt_id: H-9001
title: LSASS Memory Dumping via comsvcs.dll
status: completed
date: 2025-12-02
hunter: Test Hunter
techniques: [T1003.001]
tactics: [credential-access]
platform: [Windows]
data_sources: [windows-event-logs]
true_positives: 2
false_positives: 5
tags: [lsass, credential-dumping]
---

# H-9001: LSASS Memory Dumping via comsvcs.dll

## LEARN: Prepare the Hunt

### Hypothesis Statement

Adversaries use rundll32.exe with comsvcs.dll MiniDump to dump LSASS memory
for offline credential extraction.

### Threat Context

[What threat actor/malware/TTP motivates this hunt?]

## OBSERVE: Expected Behaviors

Expected behaviors placeholder.

## CHECK: Execute & Analyze

Query iteration detail that should not appear in a stakeholder brief.

## KEEP: Findings & Response

### Executive Summary

Two endpoints were confirmed compromised via LSASS dumping disguised as a
troubleshooting utility. Both were isolated and credentials rotated.

### Findings

| **Finding** | **Ticket** | **Description** |
|-------------|-----------|-----------------|
| True Positive | JIRA-101 | rundll32 dumping LSASS on WKS-042 |
| False Positive | N/A | EDR agent scanning lsass.exe |

**True Positives:** 2
**False Positives:** 5

### Detection Logic

**Automation Opportunity:**

Yes -- proposed as a Sigma rule for rundll32 + comsvcs.dll + MiniDump.

### Lessons Learned

**What Worked Well:**
- Internal hunter notes that should not appear in the brief.

### Follow-up Actions

- [ ] Rotate credentials on affected hosts
- [ ] Submit Sigma rule for review

### Follow-up Hunts

- Hunt for other LOLBins used for credential access
"""

    def _write_hunt_file(self, tmp_path, content: str, hunt_id: str = "H-9001") -> None:
        hunt_dir = tmp_path / "hunts" / "production" / "2025" / "Q4"
        hunt_dir.mkdir(parents=True, exist_ok=True)
        (hunt_dir / f"{hunt_id}.md").write_text(content)

    def test_brief_invalid_hunt_id(self, runner, temp_workspace):
        """Test brief with a malformed hunt ID."""
        result = runner.invoke(hunt, ["brief", "not-a-hunt-id"])

        assert result.exit_code != 0

    def test_brief_nonexistent_hunt(self, runner, temp_workspace):
        """Test brief for a hunt ID that doesn't exist."""
        result = runner.invoke(hunt, ["brief", "H-9999"])

        assert result.exit_code != 0

    def test_brief_omits_unfilled_placeholder_sections(self, runner, temp_workspace):
        """A freshly created hunt has only its hypothesis filled in -- everything
        still templated (Summary, Findings, Detection, Follow-up) should be
        left out of the brief rather than shown as literal placeholder text."""
        import re

        runner.invoke(init, ["--non-interactive"])
        # init seeds a few bundled example hunts (H-0001..H-0003), so the
        # hunt created here won't actually land on H-0001 -- pull the real ID
        # out of the creation command's own success message rather than
        # assuming.
        new_result = runner.invoke(
            hunt,
            ["new", "--title", "Test Hunt", "--hypothesis", "Adversaries abuse X to achieve Y.", "--non-interactive"],
        )
        hunt_id = re.search(r"Created (H-\d+):", new_result.output).group(1)

        result = runner.invoke(hunt, ["brief", hunt_id])

        assert result.exit_code == 0
        assert "Adversaries abuse X to achieve Y." in result.output
        assert "## Summary" not in result.output
        assert "## Detection & Automation" not in result.output
        assert "[" not in result.output.split("## Findings")[0]  # no raw template brackets before Findings

    def test_brief_includes_filled_keep_section(self, runner, temp_workspace):
        """A completed hunt's brief should surface Summary/Findings/Detection/
        Follow-up, using frontmatter TP/FP counts, while dropping internal-only
        content (query iteration detail, Lessons Learned)."""
        self._write_hunt_file(temp_workspace, self.FILLED_KEEP_HUNT)

        result = runner.invoke(hunt, ["brief", "H-9001"])

        assert result.exit_code == 0
        assert "H-9001" in result.output
        assert "comsvcs.dll MiniDump" in result.output
        assert "Two endpoints were confirmed compromised" in result.output
        assert "rundll32 dumping LSASS on WKS-042" in result.output
        assert "**True Positives:** 2" in result.output
        assert "**False Positives:** 5" in result.output
        assert "Sigma rule for rundll32" in result.output
        assert "Rotate credentials on affected hosts" in result.output
        # Internal-only content must not leak into a stakeholder brief
        assert "Query iteration detail" not in result.output
        assert "Internal hunter notes" not in result.output
        # Findings table's own restated TP/FP lines are redundant with the header stat line
        assert result.output.count("**True Positives:**") == 1

    def test_brief_output_file(self, runner, temp_workspace):
        """Test writing the brief to a file instead of stdout."""
        self._write_hunt_file(temp_workspace, self.FILLED_KEEP_HUNT)
        output_path = temp_workspace / "brief.md"

        result = runner.invoke(hunt, ["brief", "H-9001", "--output", str(output_path)])

        assert result.exit_code == 0
        assert output_path.exists()
        assert "Two endpoints were confirmed compromised" in output_path.read_text()

    FILLED_BASELINE_HUNT = """---
hunt_id: H-9002
title: Parent-Child Process Baseline
hunt_type: baseline
status: completed
date: 2025-12-02
hunter: Test Hunter
dimension: parent_process -> child_process pairs
true_positives: 0
false_positives: 0
tags: [baseline]
---

# H-9002: Parent-Child Process Baseline

## LEARN: Prepare the Baseline

### Baseline Objective

Establish normal parent-child process chains across the Windows fleet before
hunting for LOLBin abuse.

## OBSERVE: Expected Normal

### Hypothesized Normal Range

[Best guess, before running anything, at what "normal" will look like]

## CHECK: Characterize & Analyze

### Results: What Normal Actually Looks Like

winword.exe -> splwow64.exe accounts for 40% of Office-spawned children.
No instances of winword.exe -> powershell.exe were observed in 30 days.

## KEEP: Candidate Anomalies & Follow-up

### Candidate Anomalies

| **Anomaly** | **Rarity/Deviation** | **Worth a Hypothesis-Driven Hunt?** |
|-------------|----------------------|--------------------------------------|
| winword.exe spawning powershell.exe | Seen once, on WKS-014 | Yes |

**Candidate Anomalies Found:** 1

### Spawned Hunts

H-9003 was created to investigate the winword.exe -> powershell.exe anomaly.

### Lessons Learned

**What Worked Well:**
- Internal hunter notes that should not appear in the brief.
"""

    def test_brief_baseline_hunt_uses_baseline_sections(self, runner, temp_workspace):
        """A baseline hunt's brief should surface Baseline Objective, established
        normal, and candidate anomalies/spawned hunts -- not Hypothesis/Findings/
        Detection & Automation, which don't apply to a hunt with no hypothesis."""
        self._write_hunt_file(temp_workspace, self.FILLED_BASELINE_HUNT, hunt_id="H-9002")

        result = runner.invoke(hunt, ["brief", "H-9002"])

        assert result.exit_code == 0
        assert "Baseline (EDA)" in result.output
        assert "parent_process -> child_process pairs" in result.output
        assert "## Baseline Objective" in result.output
        assert "Establish normal parent-child process chains" in result.output
        assert "## What Normal Looks Like" in result.output
        assert "winword.exe -> splwow64.exe accounts for 40%" in result.output
        assert "## Candidate Anomalies" in result.output
        assert "winword.exe spawning powershell.exe" in result.output
        assert "## Spawned Hunts" in result.output
        assert "H-9003 was created" in result.output
        # Hypothesis-driven-only sections must not appear on a baseline hunt
        assert "## Hypothesis" not in result.output
        assert "## Findings" not in result.output
        assert "## Detection & Automation" not in result.output
        # Internal-only content still excluded
        assert "Internal hunter notes" not in result.output

    def test_brief_fresh_baseline_hunt_omits_placeholder_anomaly_table(self, runner, temp_workspace):
        """Regression test: a freshly-created (still-templated) baseline hunt's
        placeholder anomaly row was leaking into the brief because the
        '**Candidate Anomalies Found:** 0' stat line wasn't stripped before the
        unfilled-section check -- its presence (real bold text, no brackets)
        made the whole placeholder table look "filled" to _is_unfilled."""
        runner.invoke(init, ["--non-interactive"])
        new_result = runner.invoke(
            hunt,
            [
                "new-baseline",
                "--title",
                "Fresh Baseline",
                "--dimension",
                "test dimension",
                "--non-interactive",
            ],
        )
        import re

        hunt_id = re.search(r"Created (H-\d+):", new_result.output).group(1)

        result = runner.invoke(hunt, ["brief", hunt_id])

        assert result.exit_code == 0
        assert "None identified yet." in result.output
        assert "[Description]" not in result.output
        assert "Candidate Anomalies Found" not in result.output


class TestCLIIntegration:
    """Integration tests for CLI workflows."""

    def test_full_workflow(self, runner, temp_workspace):
        """Test complete workflow: init -> new -> validate -> list -> stats."""
        import re

        # Step 1: Initialize
        result = runner.invoke(init, ["--non-interactive"])
        assert result.exit_code == 0

        # Step 2: Create new hunt
        result = runner.invoke(
            hunt,
            [
                "new",
                "--technique",
                "T1003.001",
                "--title",
                "LSASS Memory Dumping",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0
        # Extract created hunt ID from output
        match = re.search(r"Created (H-\d+)", result.output)
        assert match, f"Could not find hunt ID in output: {result.output}"
        hunt_id = match.group(1)

        # Step 3: Validate
        result = runner.invoke(hunt, ["validate", hunt_id])
        assert result.exit_code == 0

        # Step 4: List hunts (JSON for reliable assertion)
        result = runner.invoke(hunt, ["list", "--output", "json"])
        assert result.exit_code == 0
        assert hunt_id in result.output

        # Step 5: Show stats
        result = runner.invoke(hunt, ["stats"])
        assert result.exit_code == 0

        # Step 6: Search
        result = runner.invoke(hunt, ["search", "LSASS"])
        assert result.exit_code == 0

    def test_multiple_hunts_workflow(self, runner, temp_workspace):
        """Test workflow with multiple hunts."""
        runner.invoke(init, ["--non-interactive"])

        # Create 3 hunts
        for i in range(1, 4):
            result = runner.invoke(hunt, ["new", "--title", f"Hunt {i}", "--technique", f"T100{i}.001", "--non-interactive"])
            assert result.exit_code == 0

        # List should show all 3 (JSON for reliable assertion)
        result = runner.invoke(hunt, ["list", "--output", "json"])
        assert result.exit_code == 0
        assert "H-0001" in result.output
        assert "H-0002" in result.output
        assert "H-0003" in result.output


class TestCLIErrorHandling:
    """Test suite for CLI error handling."""

    def test_hunt_commands_without_init(self, runner, temp_workspace):
        """Test that hunt commands handle missing initialization gracefully."""
        # Try to create hunt without init
        result = runner.invoke(hunt, ["new", "--title", "Test", "--non-interactive"])

        # Should still work, creating directories as needed
        assert result.exit_code == 0 or "error" in result.output.lower()

    def test_init_twice(self, runner, temp_workspace):
        """Test running init twice."""
        # First init
        result1 = runner.invoke(init, ["--non-interactive"])
        assert result1.exit_code == 0

        # Second init should ask for confirmation (but we're non-interactive)
        # In non-interactive mode, it might skip or proceed
        result2 = runner.invoke(init, ["--non-interactive"])
        # Should handle gracefully
        assert result2.exit_code == 0 or "already" in result2.output.lower()


# Run tests with: pytest tests/test_commands.py -v
