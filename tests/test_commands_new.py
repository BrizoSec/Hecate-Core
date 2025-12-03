"""
Tests for ATHF CLI commands using real implementations.
"""
import pytest
import tempfile
import shutil
from pathlib import Path
from click.testing import CliRunner
from athf.cli import cli
from athf.core.hunt_manager import HuntManager


class TestInitCommand:
    """Test suite for athf init command."""

    def test_init_creates_directory_structure(self, temp_dir):
        """Test that init creates all required directories."""
        runner = CliRunner()
        result = runner.invoke(cli, ['init', '--directory', str(temp_dir), '--non-interactive'])

        assert result.exit_code == 0
        assert (temp_dir / 'hunts').exists()
        assert (temp_dir / 'queries').exists()
        assert (temp_dir / 'runs').exists()
        assert (temp_dir / 'templates').exists()

    def test_init_creates_config_files(self, temp_dir):
        """Test that init creates configuration files."""
        runner = CliRunner()
        result = runner.invoke(cli, ['init', '--directory', str(temp_dir), '--non-interactive'])

        assert result.exit_code == 0
        assert (temp_dir / '.athfconfig.yaml').exists()
        assert (temp_dir / 'AGENTS.md').exists()
        assert (temp_dir / 'templates' / 'HUNT_LOCK.md').exists()

    def test_init_with_custom_siem_edr(self, temp_dir):
        """Test init with custom SIEM and EDR platforms."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'init',
            '--directory', str(temp_dir),
            '--siem', 'elastic',
            '--edr', 'sentinelone',
            '--non-interactive'
        ])

        assert result.exit_code == 0
        config_content = (temp_dir / '.athfconfig.yaml').read_text()
        assert 'elastic' in config_content
        assert 'sentinelone' in config_content


class TestHuntNewCommand:
    """Test suite for athf hunt new command."""

    def test_hunt_new_creates_file(self, athf_workspace):
        """Test creating a new hunt."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'new',
            '--technique', 'T1003.001',
            '--title', 'Test LSASS Dumping',
            '--workspace', str(athf_workspace)
        ])

        assert result.exit_code == 0
        assert (athf_workspace / 'hunts' / 'H-0001.md').exists()

    def test_hunt_new_with_invalid_technique(self, athf_workspace):
        """Test error handling for invalid technique format."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'new',
            '--technique', 'INVALID',
            '--title', 'Test Hunt',
            '--workspace', str(athf_workspace)
        ])

        assert result.exit_code != 0
        assert 'Invalid technique format' in result.output

    def test_hunt_new_increments_id(self, athf_workspace):
        """Test that hunt IDs increment correctly."""
        runner = CliRunner()

        # Create first hunt
        result1 = runner.invoke(cli, [
            'hunt', 'new',
            '--technique', 'T1003.001',
            '--title', 'First Hunt',
            '--workspace', str(athf_workspace)
        ])
        assert result1.exit_code == 0

        # Create second hunt
        result2 = runner.invoke(cli, [
            'hunt', 'new',
            '--technique', 'T1558.003',
            '--title', 'Second Hunt',
            '--workspace', str(athf_workspace)
        ])
        assert result2.exit_code == 0

        assert (athf_workspace / 'hunts' / 'H-0001.md').exists()
        assert (athf_workspace / 'hunts' / 'H-0002.md').exists()

    def test_hunt_new_with_metadata(self, athf_workspace):
        """Test creating hunt with additional metadata."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'new',
            '--technique', 'T1003.001',
            '--title', 'LSASS Dumping Detection',
            '--tactic', 'credential-access',
            '--platform', 'windows',
            '--data-source', 'windows-event-logs',
            '--workspace', str(athf_workspace)
        ])

        assert result.exit_code == 0
        hunt_content = (athf_workspace / 'hunts' / 'H-0001.md').read_text()
        assert 'credential-access' in hunt_content
        assert 'windows' in hunt_content
        assert 'windows-event-logs' in hunt_content


class TestHuntListCommand:
    """Test suite for athf hunt list command."""

    def test_hunt_list_empty_workspace(self, athf_workspace):
        """Test listing hunts in empty workspace."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'list',
            '--workspace', str(athf_workspace)
        ])

        assert result.exit_code == 0
        assert 'No hunts found' in result.output

    def test_hunt_list_shows_hunts(self, athf_workspace_with_hunts):
        """Test listing hunts."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'list',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0
        assert 'H-0001' in result.output

    def test_hunt_list_filter_by_status(self, athf_workspace_with_hunts):
        """Test filtering hunts by status."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'list',
            '--status', 'completed',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0

    def test_hunt_list_json_output(self, athf_workspace_with_hunts):
        """Test JSON output format."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'list',
            '--format', 'json',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0
        assert 'hunt_id' in result.output


class TestHuntValidateCommand:
    """Test suite for athf hunt validate command."""

    def test_validate_valid_hunt(self, athf_workspace_with_hunts):
        """Test validating a valid hunt."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'validate',
            '--hunt-id', 'H-0001',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0
        assert 'Valid' in result.output

    def test_validate_all_hunts(self, athf_workspace_with_hunts):
        """Test validating all hunts."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'validate',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0


class TestHuntStatsCommand:
    """Test suite for athf hunt stats command."""

    def test_stats_shows_coverage(self, athf_workspace_with_hunts):
        """Test displaying hunt statistics."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'stats',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0
        assert 'Total Hunts' in result.output
        assert 'Techniques Covered' in result.output


class TestHuntSearchCommand:
    """Test suite for athf hunt search command."""

    def test_search_finds_hunts(self, athf_workspace_with_hunts):
        """Test searching for hunts by keyword."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'search', 'LSASS',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0

    def test_search_no_results(self, athf_workspace_with_hunts):
        """Test search with no matching results."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            'hunt', 'search', 'nonexistent-keyword-xyz',
            '--workspace', str(athf_workspace_with_hunts)
        ])

        assert result.exit_code == 0
        assert 'No hunts found' in result.output


# Run tests with: pytest tests/test_commands_new.py -v
