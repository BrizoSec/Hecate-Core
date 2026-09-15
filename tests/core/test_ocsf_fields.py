"""Field-name validation for generated telemetry mappings.

Loading `OCSF_SCHEMA_REFERENCE.md` into the prompt was not enough. With the
reference in place the model still produced `process.execution.command_line`,
`file.file_name` and `network.tcp.connection.remote_address` -- dotted,
lowercase and entirely fictional. The fix is to check the output, the same
answer the Sigma validator gave for rules that were valid YAML and
meaningless Sigma.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hecate_agent.agents.llm.hunt_researcher import _flag_invented_fields
from hecate_agent.core.ocsf_fields import (
    canonical_paths,
    clear_cache,
    invalid_fields,
    is_ocsf_field,
    suggest,
)

#: Verbatim from a live research document generated with the reference loaded.
OBSERVED_INVENTIONS = [
    "process.execution.command_line",
    "file.file_name",
    "process.creation.create_time",
    "network.tcp.connection.remote_address",
    "network.http.request.uri",
    "file.malware.family",
]

REAL = ["process.name", "process.cmd_line", "actor.user.name", "dst_endpoint.ip", "file.path"]


@pytest.fixture(autouse=True)
def _workspace(monkeypatch):
    """Pin the workspace so an exported HECATE_WORKSPACE cannot redirect the
    reference lookup."""
    monkeypatch.setenv("HECATE_WORKSPACE", str(Path(__file__).resolve().parents[2]))
    clear_cache()
    yield
    clear_cache()


class TestCanonicalSet:
    def test_it_is_built_from_the_reference(self):
        assert len(canonical_paths()) > 50

    def test_event_positions_are_included(self):
        """`network_endpoint` never appears under that name in an event."""
        assert is_ocsf_field("dst_endpoint.ip")
        assert is_ocsf_field("src_endpoint.port")

    def test_nested_positions_are_included(self):
        assert is_ocsf_field("actor.user.name")
        assert is_ocsf_field("process.parent_process.name")

    def test_a_missing_reference_disables_checking_rather_than_failing_everything(self, tmp_path, monkeypatch):
        """With no dictionary, reporting every field invalid is worse than
        not checking."""
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
        clear_cache()
        assert invalid_fields(OBSERVED_INVENTIONS) == []


class TestValidation:
    @pytest.mark.parametrize("name", OBSERVED_INVENTIONS)
    def test_the_observed_inventions_are_rejected(self, name):
        assert is_ocsf_field(name) is False

    @pytest.mark.parametrize("name", REAL)
    def test_real_fields_are_accepted(self, name):
        assert is_ocsf_field(name) is True

    def test_case_and_backticks_are_tolerated(self):
        assert is_ocsf_field("`Process.Name`")

    def test_invalid_fields_reports_only_the_bad_ones(self):
        assert invalid_fields(REAL + OBSERVED_INVENTIONS) == OBSERVED_INVENTIONS


class TestSuggestions:
    def test_a_near_miss_is_corrected(self):
        assert suggest("process.execution.command_line") == "process.cmd_line"

    def test_the_most_direct_path_wins(self):
        """`process.file.created_time` is a different field about a different
        thing, so the shallower one is the better guess."""
        assert suggest("process.creation.create_time") == "process.created_time"

    def test_no_suggestion_when_nothing_is_close(self):
        assert suggest("network.tcp.connection.remote_address") is None
        assert suggest("file.malware.family") is None

    def test_a_valid_field_needs_no_suggestion(self):
        assert suggest("process.name") is None


class TestFindingsAreFlagged:
    def test_an_invented_field_is_marked_in_place(self):
        out = _flag_invented_fields(["process.execution.command_line: what it captures"])
        assert "NOT AN OCSF FIELD" in out[0]
        assert "did you mean process.cmd_line?" in out[0]
        assert "what it captures" in out[0], "the description must survive"

    def test_a_real_field_is_left_alone(self):
        assert _flag_invented_fields(["process.cmd_line: fine"]) == ["process.cmd_line: fine"]

    def test_findings_are_flagged_not_dropped(self):
        """Silently removing them would leave a section that looks merely
        empty, hiding that the model invented something."""
        assert len(_flag_invented_fields(OBSERVED_INVENTIONS_AS_FINDINGS)) == len(
            OBSERVED_INVENTIONS_AS_FINDINGS
        )

    def test_prose_without_a_field_is_untouched(self):
        line = "Telemetry mapping requires an LLM for detailed analysis"
        assert _flag_invented_fields([line]) == [line]

    def test_a_bare_word_is_not_treated_as_a_field(self):
        line = "Summary: nothing to map here"
        assert _flag_invented_fields([line]) == [line]


OBSERVED_INVENTIONS_AS_FINDINGS = [f"{n}: description" for n in OBSERVED_INVENTIONS]
