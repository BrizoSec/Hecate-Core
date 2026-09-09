"""Tests for the Splunk CLI commands.

Characterisation coverage for `hecate-agent splunk search`, written before the command
is restructured: it carried a complexity of 14 in a module at 21% coverage, so
a refactor had almost nothing to check it against.

No Splunk is contacted — `get_client` is the seam, and every test replaces it
with a fake whose calls are recorded.
"""

import importlib
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

# Imported as a module rather than `from hecate_agent.commands import splunk`: the
# package re-exports the Click group under that same name, so the plain
# import (and monkeypatch's dotted-path form) resolves to the group, which
# has no `get_client` attribute to patch.
splunk_cli = importlib.import_module("hecate_agent.commands.splunk")
get_client = splunk_cli.get_client
splunk = splunk_cli.splunk

RESULTS = [
    {"_time": "2026-01-01T00:00:00", "user": "alice", "action": "login"},
    {"_time": "2026-01-01T00:01:00", "user": "bob", "status": "403"},
]


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def fake_client(monkeypatch):
    """Replace get_client with a recording double."""
    client = MagicMock()
    client.search.return_value = RESULTS
    client.search_async.return_value = RESULTS
    monkeypatch.setattr(splunk_cli, "get_client", lambda *a, **k: client)
    return client


# --- Credential resolution -------------------------------------------------


class TestGetClient:
    def test_reads_credentials_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("SPLUNK_HOST", "splunk.example.test")
        monkeypatch.setenv("SPLUNK_TOKEN", "token-from-env")
        # SplunkClient normalises the host into a management-port URL.
        assert get_client(None, None, None).base_url == "https://splunk.example.test:8089"

    def test_cli_arguments_win_over_the_environment(self, monkeypatch):
        monkeypatch.setenv("SPLUNK_HOST", "from-env")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        assert get_client("from-cli", "t", None).base_url == "https://from-cli:8089"

    def test_missing_credentials_are_a_usage_error(self, monkeypatch):
        monkeypatch.delenv("SPLUNK_HOST", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        with pytest.raises(Exception) as excinfo:
            get_client(None, None, None)
        assert "credentials required" in str(excinfo.value).lower()

    def test_verify_ssl_is_read_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("SPLUNK_VERIFY_SSL", "false")
        assert get_client(None, None, None).verify_ssl is False


# --- search ----------------------------------------------------------------


class TestSplunkSearch:
    def test_runs_a_oneshot_search_by_default(self, runner, fake_client):
        result = runner.invoke(splunk, ["search", "index=main error"])
        assert result.exit_code == 0
        fake_client.search.assert_called_once()
        fake_client.search_async.assert_not_called()

    def test_async_flag_switches_to_the_async_api(self, runner, fake_client):
        result = runner.invoke(splunk, ["search", "index=main", "--async-search"])
        assert result.exit_code == 0
        fake_client.search_async.assert_called_once()
        fake_client.search.assert_not_called()

    def test_time_range_and_count_reach_the_client(self, runner, fake_client):
        runner.invoke(
            splunk,
            ["search", "index=main", "--earliest", "-7d", "--latest", "-1h", "--count", "5"],
        )
        kwargs = fake_client.search.call_args.kwargs
        assert kwargs["earliest_time"] == "-7d"
        assert kwargs["latest_time"] == "-1h"
        assert kwargs["max_count"] == 5

    def test_max_wait_reaches_the_async_client(self, runner, fake_client):
        runner.invoke(splunk, ["search", "index=main", "--async-search", "--max-wait", "600"])
        assert fake_client.search_async.call_args.kwargs["max_wait"] == 600

    def test_empty_results_are_reported_rather_than_tabulated(self, runner, fake_client):
        fake_client.search.return_value = []
        result = runner.invoke(splunk, ["search", "index=main"])
        assert result.exit_code == 0
        assert "No results found" in result.output

    # --- output formats ---------------------------------------------

    def test_json_output_is_parseable(self, runner, fake_client):
        import json

        result = runner.invoke(splunk, ["search", "index=main", "--format", "json"])
        payload = json.loads(result.output[result.output.index("[") :])
        assert payload == RESULTS

    def test_table_output_includes_every_field_across_results(self, runner, fake_client):
        """Results are heterogeneous — the union of keys becomes the columns."""
        result = runner.invoke(splunk, ["search", "index=main", "--format", "table"])
        assert "user" in result.output
        assert "action" in result.output
        assert "status" in result.output

    def test_raw_output_lists_events_individually(self, runner, fake_client):
        result = runner.invoke(splunk, ["search", "index=main", "--format", "raw"])
        assert "Event 1:" in result.output
        assert "Event 2:" in result.output

    # --- failure modes ----------------------------------------------

    def test_a_timeout_suggests_async_and_aborts(self, runner, fake_client):
        fake_client.search.side_effect = TimeoutError("took too long")
        result = runner.invoke(splunk, ["search", "index=main"])
        assert result.exit_code != 0
        assert "Timeout" in result.output
        assert "--async-search" in result.output

    def test_any_other_failure_aborts_with_the_message(self, runner, fake_client):
        fake_client.search.side_effect = RuntimeError("connection refused")
        result = runner.invoke(splunk, ["search", "index=main"])
        assert result.exit_code != 0
        assert "connection refused" in result.output
