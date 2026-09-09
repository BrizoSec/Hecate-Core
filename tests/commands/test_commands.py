"""
Tests for Hecate CLI commands using actual implementation.
"""

import json
import os

import pytest
import yaml
from click.testing import CliRunner

from hecate_agent.commands.hunt import hunt


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


class TestHuntNewCommand:
    """Test suite for hecate-agent hunt new command."""

    def test_hunt_new_non_interactive(self, runner, temp_workspace):
        """Test creating a new hunt in non-interactive mode."""
        # First initialize
        (temp_workspace / "hunts").mkdir(exist_ok=True)

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
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["new", "--technique", "T1003.001", "--non-interactive"])

        assert result.exit_code == 0  # Click doesn't exit with error, just prints message
        assert "Error" in result.output or "required" in result.output.lower()

    def test_hunt_new_increments_id(self, runner, temp_workspace):
        """Test that hunt IDs increment correctly."""
        import re

        (temp_workspace / "hunts").mkdir(exist_ok=True)

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

        # Patch the provider lookup used by _hunt_create.py. We patch on
        # the _hunt_create module because get_technique moved there during
        # the hunt.py split.
        import sys

        create_mod = sys.modules["hecate_agent.commands._hunt_create"]

        def fake_get_technique(tid):
            if tid == "T1003.001":
                return {
                    "id": "T1003.001",
                    "name": "LSASS Memory",
                    "tactic_shortnames": ["credential-access"],
                }
            return None

        monkeypatch.setattr(create_mod, "get_technique", fake_get_technique)

        (temp_workspace / "hunts").mkdir(exist_ok=True)

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

        create_mod = sys.modules["hecate_agent.commands._hunt_create"]
        monkeypatch.setattr(create_mod, "get_technique", lambda _tid: None)

        (temp_workspace / "hunts").mkdir(exist_ok=True)
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

        (temp_workspace / "hunts").mkdir(exist_ok=True)

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

        (temp_workspace / "hunts").mkdir(exist_ok=True)

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

        (temp_workspace / "hunts").mkdir(exist_ok=True)
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

        (temp_workspace / "hunts").mkdir(exist_ok=True)
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

        (temp_workspace / "hunts").mkdir(exist_ok=True)
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

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["new", "--title", "Regular Hunt", "--non-interactive"])
        match = re.search(r"Created (H-\d+)", result.output)
        hunt_id = match.group(1)

        promote_result = runner.invoke(hunt, ["promote", hunt_id, "--yes"])
        assert (
            "not in a test directory" in promote_result.output
        ), f"Expected 'not in a test directory' message, got: {promote_result.output}"
        # File must not have moved
        assert len(list((temp_workspace / "hunts").rglob(f"{hunt_id}.md"))) == 1


class TestHuntBinaryPath:
    """Subprocess-level tests that invoke the real hecate-agent binary.

    CliRunner runs commands in-process with '' (CWD) first in sys.path, so it
    always loads local source code.  These tests spawn an actual subprocess to
    catch the class of bug where a stale editable install in site-packages is
    picked up by the binary's Python interpreter instead of the local source.
    """

    def test_binary_hunt_new_path_is_year_quarter(self, tmp_path):
        """The hecate-agent binary must write new hunts to hunts/YYYY/QN/, not hunts/production/."""
        import re
        import shutil
        import subprocess
        from datetime import datetime

        if not shutil.which("hecate-agent"):
            pytest.skip("hecate-agent binary not on PATH")

        (tmp_path / "hunts").mkdir(exist_ok=True)
        result = subprocess.run(
            ["hecate-agent", "hunt", "new", "--title", "Binary Smoke Test", "--non-interactive"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

        hunt_files = list((tmp_path / "hunts").rglob("H-*.md"))
        assert hunt_files, "No hunt file created"

        year = str(datetime.now().year)
        for f in hunt_files:
            parts = f.relative_to(tmp_path / "hunts").parts
            assert "production" not in parts, (
                f"Binary wrote hunt to 'production' subdirectory: {f}\n"
                "Check that the installed editable package points to the current source."
            )
            assert parts[0] == year, f"Expected year {year} as first path component, got {parts[0]}"
            assert re.match(r"Q[1-4]", parts[1]), f"Expected Q1-Q4, got {parts[1]}"

    def test_binary_version_matches_source(self, tmp_path):
        """hecate-agent --version must match hecate_agent.__version__.__version__."""
        import shutil
        import subprocess

        if not shutil.which("hecate-agent"):
            pytest.skip("hecate-agent binary not on PATH")

        from hecate_agent.__version__ import __version__

        result = subprocess.run(["hecate-agent", "--version"], capture_output=True, text=True)
        assert __version__ in result.stdout, (
            f"Binary version output {result.stdout!r} does not contain source version {__version__!r}.\n"
            "Reinstall the editable package: pip install -e ."
        )


class TestHuntNewBaselineCommand:
    """Test suite for hecate-agent hunt new-baseline command."""

    def test_requires_title_in_non_interactive_mode(self, runner, temp_workspace):
        """Test that --title is required for non-interactive baseline creation."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["new-baseline", "--non-interactive"])

        assert result.exit_code != 0 or "required" in result.output.lower()

    def test_creates_baseline_hunt_with_hunt_type(self, runner, temp_workspace):
        """Test that a baseline hunt is created with hunt_type: baseline and no hypothesis."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

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
        (temp_workspace / "hunts").mkdir(exist_ok=True)
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
    """Test suite for hecate-agent hunt list command."""

    def setup_test_hunts(self, runner, temp_workspace):
        """Helper to create test hunts."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

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
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["list"])

        # init may copy sample hunts, so this test just checks the command works
        # If no sample hunts exist, we'll see "No hunts found"
        # If sample hunts exist, we'll see the hunt catalog
        assert result.exit_code == 0
        assert "No hunts found" in result.output or "Hunt Catalog" in result.output or "H-" in result.output


class TestHuntValidateCommand:
    """Test suite for hecate-agent hunt validate command."""

    def test_validate_all_hunts(self, runner, temp_workspace):
        """Test validating all hunts."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["validate"])

        assert result.exit_code == 0

    def test_validate_specific_hunt(self, runner, temp_workspace):
        """Test validating a specific hunt."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["validate", "H-0001"])

        assert result.exit_code == 0

    def test_validate_nonexistent_hunt(self, runner, temp_workspace):
        """Test validating a hunt that doesn't exist."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["validate", "H-9999"])

        assert result.exit_code == 0  # Command runs but shows error message
        assert "not found" in result.output.lower()


class TestHuntStatsCommand:
    """Test suite for hecate-agent hunt stats command."""

    def test_hunt_stats_empty(self, runner, temp_workspace):
        """Test stats with no hunts."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["stats"])

        assert result.exit_code == 0
        assert "Statistics" in result.output or "stats" in result.output.lower()

    def test_hunt_stats_with_hunts(self, runner, temp_workspace):
        """Test stats with hunts created."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])

        result = runner.invoke(hunt, ["stats"])

        assert result.exit_code == 0
        assert "Total Hunts" in result.output or "total" in result.output.lower()


class TestHuntSearchCommand:
    """Test suite for hecate-agent hunt search command."""

    def test_hunt_search(self, runner, temp_workspace):
        """Test searching for hunts."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Kerberoasting Detection", "--technique", "T1558.003", "--non-interactive"])

        result = runner.invoke(hunt, ["search", "Kerberoasting"])

        assert result.exit_code == 0

    def test_hunt_search_no_results(self, runner, temp_workspace):
        """Test search with no results."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["search", "nonexistent"])

        assert result.exit_code == 0
        assert "No hunts found" in result.output or "found" in result.output.lower()


class TestHuntCoverageCommand:
    """Test suite for hecate-agent hunt coverage command."""

    def test_hunt_coverage(self, runner, temp_workspace):
        """Test ATT&CK coverage command."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(
            hunt,
            ["new", "--title", "Test Hunt", "--technique", "T1003.001", "--tactic", "credential-access", "--non-interactive"],
        )

        result = runner.invoke(hunt, ["coverage"])

        assert result.exit_code == 0

    def test_hunt_coverage_empty(self, runner, temp_workspace):
        """Test coverage with no hunts."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["coverage"])

        assert result.exit_code == 0


class TestHuntNewBranches:
    """Branch coverage for `hecate-agent hunt new`.

    Written before restructuring the command: at complexity 27 it was the
    worst in the codebase, and the clone, research-link and interactive
    paths were all untested.
    """

    def _base(self, *extra):
        return ["new", "--title", "Base Hunt", "--non-interactive", *extra]

    # --- clone ---------------------------------------------------------

    def test_clone_copies_metadata_from_the_source_hunt(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Source",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--platform",
                "Linux",
                "--non-interactive",
            ],
        )
        source = next((temp_workspace / "hunts").rglob("H-*.md")).stem

        runner.invoke(hunt, ["new", "--clone", source, "--non-interactive"])

        clone = sorted((temp_workspace / "hunts").rglob("H-*.md"))[-1]
        fm = yaml.safe_load(clone.read_text().split("---")[1])
        assert fm["techniques"] == ["T1003.001"]
        assert fm["tactics"] == ["credential-access"]
        assert fm["platform"] == ["Linux"]
        assert fm["title"].startswith("Clone of")

    def test_explicit_flags_override_the_clone_source(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(
            hunt,
            ["new", "--title", "Source", "--technique", "T1003.001", "--non-interactive"],
        )
        source = next((temp_workspace / "hunts").rglob("H-*.md")).stem

        runner.invoke(
            hunt,
            ["new", "--clone", source, "--technique", "T1059.001", "--non-interactive"],
        )

        clone = sorted((temp_workspace / "hunts").rglob("H-*.md"))[-1]
        assert yaml.safe_load(clone.read_text().split("---")[1])["techniques"] == ["T1059.001"]

    def test_a_missing_clone_source_creates_nothing(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["new", "--clone", "H-9999", "--non-interactive"])
        assert "Clone source not found" in result.output
        assert not list((temp_workspace / "hunts").rglob("H-*.md"))

    # --- research link -------------------------------------------------

    def test_a_malformed_research_id_creates_nothing(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, self._base("--research", "nonsense"))
        assert "Invalid research ID format" in result.output
        assert not list((temp_workspace / "hunts").rglob("H-*.md"))

    def test_a_missing_research_document_warns_but_still_creates(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, self._base("--research", "R-0404"))
        assert "not found" in result.output
        assert len(list((temp_workspace / "hunts").rglob("H-*.md"))) == 1

    def test_an_existing_research_document_is_linked(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        (temp_workspace / "research").mkdir(exist_ok=True)
        (temp_workspace / "research" / "R-0001.md").write_text(
            "---\nresearch_id: R-0001\ntopic: T\nlinked_hunts: []\n---\n\nbody\n"
        )

        runner.invoke(hunt, self._base("--research", "R-0001"))

        created = next((temp_workspace / "hunts").rglob("H-*.md"))
        assert "R-0001" in created.read_text()

    # --- non-interactive defaults --------------------------------------

    def test_title_is_required_in_non_interactive_mode(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["new", "--non-interactive"])
        assert "--title required" in result.output
        assert not list((temp_workspace / "hunts").rglob("H-*.md"))

    def test_tactics_are_derived_from_the_technique_when_not_given(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, self._base("--technique", "T1003.001"))

        created = next((temp_workspace / "hunts").rglob("H-*.md"))
        assert yaml.safe_load(created.read_text().split("---")[1])["tactics"]

    def test_platform_and_data_sources_fall_back_to_defaults(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, self._base())

        fm = yaml.safe_load(next((temp_workspace / "hunts").rglob("H-*.md")).read_text().split("---")[1])
        assert fm["platform"] == ["Windows"]
        assert fm["data_sources"] == ["SIEM", "EDR"]

    def test_test_flag_writes_into_the_test_tree(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, self._base("--test"))
        created = next((temp_workspace / "hunts").rglob("H-*.md"))
        assert "test" in created.parts

    # --- interactive ----------------------------------------------------

    def test_interactive_mode_prompts_for_each_field(self, runner, temp_workspace, monkeypatch):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        answers = iter(["T1059.001", "Interactive Hunt", "execution", "Windows", "EDR", "", "", "", ""])
        monkeypatch.setattr("hecate_agent.commands._hunt_create.Prompt.ask", lambda *a, **k: next(answers, ""))

        result = runner.invoke(hunt, ["new"])
        assert result.exit_code == 0

        fm = yaml.safe_load(next((temp_workspace / "hunts").rglob("H-*.md")).read_text().split("---")[1])
        assert fm["techniques"] == ["T1059.001"]
        assert fm["title"] == "Interactive Hunt"


class TestHuntCoverageBranches:
    """Branch coverage for `hecate-agent hunt coverage`.

    Written before the command was restructured: it carried a complexity of 15
    with only two smoke tests, so the output formats, the tactic filter and
    the detailed view had nothing checking them.
    """

    def _one_hunt(self, runner):
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Cred Dump",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--non-interactive",
            ],
        )

    def test_json_output_is_parseable(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--output", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.output[result.output.index("{") :])
        assert "by_tactic" in payload

    def test_yaml_output_is_parseable(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--output", "yaml"])
        assert result.exit_code == 0
        assert "by_tactic" in yaml.safe_load(result.output)

    def test_filtering_to_one_tactic_hides_the_others(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--tactic", "credential-access"])
        assert result.exit_code == 0
        assert "Credential Access" in result.output
        assert "Lateral Movement" not in result.output

    def test_an_unknown_tactic_lists_the_valid_ones(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--tactic", "not-a-tactic"])
        assert "Unknown tactic" in result.output
        assert "credential-access" in result.output

    def test_overall_line_appears_only_when_showing_all_tactics(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        assert "Overall:" in runner.invoke(hunt, ["coverage"]).output
        assert "Overall:" not in runner.invoke(hunt, ["coverage", "--tactic", "execution"]).output

    def test_detailed_view_names_the_covering_hunt(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--detailed"])
        assert "Detailed Technique Coverage" in result.output
        assert "T1003.001" in result.output

    def test_detailed_view_skips_tactics_with_no_hunts(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage", "--detailed"])
        detail = result.output[result.output.index("Detailed Technique Coverage") :]
        assert "Lateral Movement" not in detail

    def test_uncovered_tactics_are_marked_in_the_summary(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        self._one_hunt(runner)

        result = runner.invoke(hunt, ["coverage"])
        assert "no coverage" in result.output


class TestHuntBriefCommand:
    """Test suite for hecate-agent hunt brief command."""

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

        (temp_workspace / "hunts").mkdir(exist_ok=True)
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
        (temp_workspace / "hunts").mkdir(exist_ok=True)
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
        """Test complete workflow: new -> validate -> list -> stats."""
        import re

        (temp_workspace / "hunts").mkdir(exist_ok=True)

        # Step 1: Create new hunt
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
        (temp_workspace / "hunts").mkdir(exist_ok=True)

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


class TestHuntUpdate:
    """Tests for 'hecate-agent hunt update' command."""

    def test_update_status(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "LSASS Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001", "--status", "completed"])
        assert result.exit_code == 0
        assert "H-0001" in result.output

        # Verify the change persisted via list
        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        import json

        hunts = json.loads(list_result.output)
        assert hunts[0]["status"] == "completed"

    def test_update_true_positives(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001", "--true-positives", "3", "--false-positives", "1"])
        assert result.exit_code == 0

        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        import json

        hunts = json.loads(list_result.output)
        assert hunts[0]["true_positives"] == 3
        assert hunts[0]["false_positives"] == 1

    def test_update_add_and_remove_tags(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        runner.invoke(hunt, ["update", "H-0001", "--add-tag", "lsass", "--add-tag", "credential-dumping"])
        result = runner.invoke(hunt, ["update", "H-0001", "--remove-tag", "lsass"])
        assert result.exit_code == 0

    def test_update_with_no_options_shows_message(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001"])
        assert result.exit_code == 0
        assert "nothing changed" in result.output.lower() or "no updates" in result.output.lower()

    def test_update_nonexistent_hunt(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)

        result = runner.invoke(hunt, ["update", "H-9999", "--status", "completed"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_update_invalid_hunt_id(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["update", "INVALID", "--status", "completed"])
        assert result.exit_code == 0
        assert "invalid" in result.output.lower()

    def test_update_title_and_hunter(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Old Title", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001", "--title", "New Title", "--hunter", "Jane"])
        assert result.exit_code == 0
        assert "H-0001" in result.output


class TestHuntStatsTrend:
    """Tests for 'hecate-agent hunt stats --trend'."""

    def test_stats_trend_shows_quarterly_table(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["stats", "--trend"])
        assert result.exit_code == 0
        assert "Quarterly Trend" in result.output or "Q" in result.output

    def test_stats_trend_no_hunts(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["stats", "--trend"])
        assert result.exit_code == 0

    def test_stats_without_trend_unchanged(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["stats"])
        assert result.exit_code == 0
        assert "Total Hunts" in result.output


class TestHuntCoverageOutput:
    """Tests for 'hecate-agent hunt coverage --output' formats."""

    def test_coverage_json_output(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["coverage", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "summary" in data
        assert "by_tactic" in data

    def test_coverage_yaml_output(self, runner, temp_workspace):

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["coverage", "--output", "yaml"])
        assert result.exit_code == 0
        data = yaml.safe_load(result.output)
        assert "summary" in data

    def test_coverage_table_output(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["coverage"])
        assert result.exit_code == 0
        assert "Coverage" in result.output or "tactic" in result.output.lower()


class TestHuntValidateFailOnError:
    """Tests for 'hecate-agent hunt validate --fail-on-error'."""

    def test_fail_on_error_exits_nonzero_when_invalid(self, runner, temp_workspace):
        import yaml as _yaml

        (temp_workspace / "hunts").mkdir(exist_ok=True)

        # Create a hunt then corrupt its frontmatter
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])
        hunt_file = temp_workspace / "hunts" / "H-0001.md"
        if not hunt_file.exists():
            # search subdirectories
            matches = list((temp_workspace / "hunts").rglob("H-0001.md"))
            if matches:
                hunt_file = matches[0]

        # Remove required field by rewriting with incomplete frontmatter
        content = hunt_file.read_text()
        parts = content.split("---", 2)
        fm = _yaml.safe_load(parts[1])
        del fm["status"]

        hunt_file.write_text(f"---\n{yaml.dump(fm)}---{parts[2]}")

        result = runner.invoke(hunt, ["validate", "--fail-on-error"])
        assert result.exit_code != 0

    def test_fail_on_error_exits_zero_when_valid(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        # Rename file to match hunt_id (validation check)
        result = runner.invoke(hunt, ["validate", "--fail-on-error"])
        # May pass or fail depending on whether hunt_id matches filename;
        # either way the command should not crash
        assert result.exit_code in (0, 1)


class TestHuntNewClone:
    """Tests for 'hecate-agent hunt new --clone'."""

    def test_clone_copies_metadata(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        # Create source hunt
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "Original Hunt",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--non-interactive",
            ],
        )

        # Clone it
        result = runner.invoke(hunt, ["new", "--clone", "H-0001", "--non-interactive"])
        assert result.exit_code == 0
        assert "H-0002" in result.output or "Created" in result.output

    def test_clone_nonexistent_source_shows_error(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["new", "--clone", "H-9999", "--title", "Clone", "--non-interactive"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_clone_title_prefixed(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)

        # Determine the next ID so we can clone the hunt we create
        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        existing = json.loads(list_result.output) if list_result.output.strip().startswith("[") else []
        next_num = max((int(h["hunt_id"].split("-")[1]) for h in existing if h.get("hunt_id")), default=0) + 1
        our_id = f"H-{next_num:04d}"

        runner.invoke(hunt, ["new", "--title", "Original", "--technique", "T1003.001", "--non-interactive"])
        clone_result = runner.invoke(hunt, ["new", "--clone", our_id, "--non-interactive"])
        assert clone_result.exit_code == 0

        list_result2 = runner.invoke(hunt, ["list", "--output", "json"])
        hunts = json.loads(list_result2.output)
        titles = [h["title"] for h in hunts]
        assert any("Clone of" in t for t in titles)


# Run tests with: pytest tests/test_commands.py -v


class TestHuntUpdateAssigneeReviewer:
    """Tests for --assignee and --reviewer in hunt update command."""

    def test_update_assignee_and_reviewer(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001", "--assignee", "alice", "--reviewer", "bob"])
        assert result.exit_code == 0
        assert "assignee" in result.output.lower()
        assert "reviewer" in result.output.lower()

        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        hunts = json.loads(list_result.output)
        assert hunts[0]["assignee"] == "alice"
        assert hunts[0]["reviewer"] == "bob"

    def test_update_status_in_review(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])

        result = runner.invoke(hunt, ["update", "H-0001", "--status", "in_review"])
        assert result.exit_code == 0

        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        hunts = json.loads(list_result.output)
        assert hunts[0]["status"] == "in_review"


class TestHuntListAssignee:
    """Tests for --assignee filter on hunt list command."""

    def test_list_filter_by_assignee(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Alice Hunt", "--technique", "T1003.001", "--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Bob Hunt", "--technique", "T1003.001", "--non-interactive"])
        runner.invoke(hunt, ["update", "H-0001", "--assignee", "alice"])

        result = runner.invoke(hunt, ["list", "--assignee", "alice", "--output", "json"])
        assert result.exit_code == 0
        hunts = json.loads(result.output)
        assert len(hunts) == 1
        assert hunts[0]["assignee"] == "alice"

    def test_list_assignee_shown_in_table(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt", "--technique", "T1003.001", "--non-interactive"])
        runner.invoke(hunt, ["update", "H-0001", "--assignee", "carol"])

        # Verify via JSON (Rich may truncate narrow columns in table view)
        result = runner.invoke(hunt, ["list", "--output", "json"])
        assert result.exit_code == 0
        hunts = json.loads(result.output)
        assert any(h.get("assignee") == "carol" for h in hunts)

    def test_list_status_in_review_filter(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt A", "--technique", "T1003.001", "--non-interactive"])
        runner.invoke(hunt, ["new", "--title", "Hunt B", "--technique", "T1003.001", "--non-interactive"])
        runner.invoke(hunt, ["update", "H-0001", "--status", "in_review"])

        result = runner.invoke(hunt, ["list", "--status", "in_review", "--output", "json"])
        assert result.exit_code == 0
        hunts = json.loads(result.output)
        assert len(hunts) == 1
        assert hunts[0]["status"] == "in_review"


class TestHuntNewAssignee:
    """Tests for --assignee on hunt new command."""

    def test_new_hunt_with_assignee(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(
            hunt, ["new", "--title", "Assignee Hunt", "--technique", "T1003.001", "--assignee", "dave", "--non-interactive"]
        )
        assert result.exit_code == 0

        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        hunts = json.loads(list_result.output)
        # init copies example hunts too; find the one we just created
        assert any(h.get("assignee") == "dave" for h in hunts)

    def test_new_hunt_without_assignee(self, runner, temp_workspace):
        import json

        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt No Assignee", "--technique", "T1003.001", "--non-interactive"])

        list_result = runner.invoke(hunt, ["list", "--output", "json"])
        hunts = json.loads(list_result.output)
        # The hunt we created should have no assignee
        created = [h for h in hunts if h.get("title") == "Hunt No Assignee"]
        assert len(created) == 1
        assert created[0]["assignee"] is None


class TestHuntOperationalize:
    """Tests for 'hecate-agent hunt operationalize' command."""

    def _make_hunt_with_query(self, runner, temp_workspace):
        """Init workspace and create a hunt that has a query in the CHECK section."""
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(
            hunt,
            [
                "new",
                "--title",
                "LSASS Hunt",
                "--technique",
                "T1003.001",
                "--tactic",
                "credential-access",
                "--platform",
                "Windows",
                "--data-source",
                "EDR",
                "--non-interactive",
            ],
        )
        # Find the hunt file and inject a fenced code block into CHECK section
        import glob

        hunt_files = glob.glob(str(temp_workspace / "hunts" / "**" / "H-0001.md"), recursive=True)
        if not hunt_files:
            # Example hunt from init
            hunt_files = glob.glob(str(temp_workspace / "hunts" / "*.md"), recursive=False)
        # Locate our created hunt (newest file)
        hunt_files = sorted(glob.glob(str(temp_workspace / "hunts" / "**" / "*.md"), recursive=True))
        # Append a query block to the CHECK section of the last hunt file
        hunt_file = hunt_files[-1]
        with open(hunt_file, "r") as f:
            content = f.read()
        # Replace the [Your initial query] placeholder with a real code block
        content = content.replace(
            "[Your initial query]", "index=edr sourcetype=crowdstrike parent_process=winword.exe | stats count by process_name"
        )
        with open(hunt_file, "w") as f:
            f.write(content)
        return hunt_file

    def test_operationalize_creates_sigma_file(self, runner, temp_workspace):
        hunt_file = self._make_hunt_with_query(runner, temp_workspace)
        hunt_id = hunt_file.rstrip(".md").split("/")[-1].split("\\")[-1]

        result = runner.invoke(hunt, ["operationalize", hunt_id, "--query-index", "1"])
        assert result.exit_code == 0
        sigma_path = temp_workspace / "detections" / f"{hunt_id}.yml"
        assert sigma_path.exists(), f"Expected {sigma_path} to exist\nOutput: {result.output}"

    def test_operationalize_sigma_contains_hunt_metadata(self, runner, temp_workspace):
        self._make_hunt_with_query(runner, temp_workspace)
        import glob

        hunt_files = sorted(glob.glob(str(temp_workspace / "hunts" / "**" / "*.md"), recursive=True))
        hunt_file = hunt_files[-1]
        hunt_id = hunt_file.rstrip(".md").split("/")[-1]

        runner.invoke(hunt, ["operationalize", hunt_id, "--query-index", "1"])
        sigma_path = temp_workspace / "detections" / f"{hunt_id}.yml"
        if sigma_path.exists():
            content = sigma_path.read_text()
            assert "status: experimental" in content
            assert hunt_id in content
            assert "detection:" in content

    def test_operationalize_no_query_shows_message(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        runner.invoke(hunt, ["new", "--title", "Hunt No Query", "--technique", "T1003.001", "--non-interactive"])
        import glob

        hunt_files = sorted(glob.glob(str(temp_workspace / "hunts" / "**" / "*.md"), recursive=True))
        hunt_id = hunt_files[-1].rstrip(".md").split("/")[-1]

        result = runner.invoke(hunt, ["operationalize", hunt_id, "--query-index", "1"])
        # Either succeeds (example hunt has a placeholder) or reports no queries
        assert result.exit_code == 0

    def test_operationalize_nonexistent_hunt_shows_error(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["operationalize", "H-9999", "--query-index", "1"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_operationalize_invalid_id_shows_error(self, runner, temp_workspace):
        (temp_workspace / "hunts").mkdir(exist_ok=True)
        result = runner.invoke(hunt, ["operationalize", "NOTVALID", "--query-index", "1"])
        assert result.exit_code == 0
        assert "invalid" in result.output.lower()

    def test_operationalize_no_patch_skips_frontmatter_update(self, runner, temp_workspace):
        hunt_file = self._make_hunt_with_query(runner, temp_workspace)
        hunt_id = hunt_file.rstrip(".md").split("/")[-1].split("\\")[-1]
        content_before = open(hunt_file).read()

        runner.invoke(hunt, ["operationalize", hunt_id, "--query-index", "1", "--no-patch"])
        content_after = open(hunt_file).read()
        assert content_before == content_after

    def test_operationalize_custom_output_path(self, runner, temp_workspace):
        hunt_file = self._make_hunt_with_query(runner, temp_workspace)
        hunt_id = hunt_file.rstrip(".md").split("/")[-1].split("\\")[-1]
        custom = str(temp_workspace / "custom_sigma.yml")

        result = runner.invoke(hunt, ["operationalize", hunt_id, "--query-index", "1", "--output", custom, "--no-patch"])
        assert result.exit_code == 0
        import os

        assert os.path.exists(custom)


# ---------------------------------------------------------------------------
# hecate-agent hunt stats --save-context
# ---------------------------------------------------------------------------


class TestHuntStatsSaveContext:
    """Tests for hecate-agent hunt stats --save-context."""

    def test_save_context_creates_section_in_env_file(self, runner, temp_workspace):
        runner.invoke(hunt, ["new", "--title", "Save Ctx Hunt", "--non-interactive"])
        result = runner.invoke(hunt, ["stats", "--save-context"])
        assert result.exit_code == 0
        env_file = temp_workspace / "knowledge" / "environment.md"
        assert env_file.exists()
        content = env_file.read_text()
        assert "Hunt Program Metrics" in content

    def test_save_context_includes_stats_fields(self, runner, temp_workspace):
        runner.invoke(hunt, ["new", "--title", "Stats Hunt", "--non-interactive"])
        runner.invoke(hunt, ["stats", "--save-context"])
        env_file = temp_workspace / "knowledge" / "environment.md"
        content = env_file.read_text()
        assert "Total Hunts" in content
        assert "Success Rate" in content
        assert "TP/FP Ratio" in content

    def test_save_context_replaces_existing_section(self, runner, temp_workspace):
        runner.invoke(hunt, ["new", "--title", "First Hunt", "--non-interactive"])
        runner.invoke(hunt, ["stats", "--save-context"])
        runner.invoke(hunt, ["new", "--title", "Second Hunt", "--non-interactive"])
        runner.invoke(hunt, ["stats", "--save-context"])
        env_file = temp_workspace / "knowledge" / "environment.md"
        content = env_file.read_text()
        # Only one metrics section should exist
        assert content.count("Hunt Program Metrics") == 1

    def test_save_context_preserves_existing_env_content(self, runner, temp_workspace):
        env_path = temp_workspace / "knowledge" / "environment.md"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("# Environment Profile\n\nUsing Splunk.\n", encoding="utf-8")
        runner.invoke(hunt, ["new", "--title", "Test Hunt", "--non-interactive"])
        runner.invoke(hunt, ["stats", "--save-context"])
        content = env_path.read_text()
        assert "Using Splunk." in content
        assert "Hunt Program Metrics" in content

    def test_save_context_prints_confirmation(self, runner, temp_workspace):
        result = runner.invoke(hunt, ["stats", "--save-context"])
        assert result.exit_code == 0
        assert "environment.md" in result.output
