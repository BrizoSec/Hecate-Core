"""Tests for env command."""

import pytest
from click.testing import CliRunner

from athf.commands.env import env


class TestEnvCommand:
    """Tests for env command."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    def test_env_info_shows_info(self, runner):
        """Test that env info shows environment information."""
        result = runner.invoke(env, ["info"])

        assert result.exit_code == 0
        # Should show either environment info or missing venv message
        assert "Virtual Environment Info" in result.output or "No .venv directory found" in result.output

    def test_env_activate_shows_command(self, runner):
        """Test that env activate shows activation command."""
        result = runner.invoke(env, ["activate"])

        # Exit code 1 when no venv exists (click.Abort), 0 when venv exists
        assert result.exit_code in (0, 1)
        # Should show activation command or setup instructions
        assert "source" in result.output or "athf env setup" in result.output or "No .venv directory found" in result.output

    def test_env_deactivate_shows_command(self, runner):
        """Test that env deactivate shows deactivation command."""
        result = runner.invoke(env, ["deactivate"])

        assert result.exit_code == 0
        # Should show deactivation command
        assert "deactivate" in result.output

    def test_env_check_runs_successfully(self, runner):
        """env check should run without crashing and print a checklist."""
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert "Python" in result.output
        assert "athf" in result.output

    def test_env_check_reports_scikit_learn(self, runner):
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert "scikit-learn" in result.output

    def test_env_check_reports_litellm(self, runner):
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert "litellm" in result.output

    def test_env_check_reports_mitreattack(self, runner):
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert "mitreattack" in result.output

    def test_env_check_reports_config_file(self, runner, tmp_path, monkeypatch):
        """env check should mention .athfconfig.yaml status."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert ".athfconfig.yaml" in result.output

    def test_env_check_reports_environment_md(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(env, ["check"])
        assert result.exit_code == 0
        assert "environment.md" in result.output

    # Note: We don't test actual setup/clean operations in unit tests
    # as they modify the filesystem and require subprocess execution.
    # These are better tested in integration tests or manually.
