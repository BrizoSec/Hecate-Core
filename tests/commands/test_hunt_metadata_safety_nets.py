"""Tests for the two metadata safety nets added after a review of
auto-generated drafts.

`hecate-agent hunt validate` reported "Hunt is valid!" for drafts carrying
`platform: []`, `tactics: []` and `techniques: []` -- validate() hard-fails
only on hunt_id/title/status/date. Four drafts passed validation while
`hecate-agent hunt coverage` reported "no coverage" for every tactic, because the
fields it reads were empty. And there was no way to fix them: `hunt update`
covered status/title/hunter/counts/tags but not techniques, tactics or
platform, so AGENTS.md's "never manually construct YAML frontmatter" rule
could not be followed for exactly the fields most likely to need correcting.

The gaps are reported as warnings rather than errors: a draft awaiting human
review is legitimately incomplete, and promoting them would fail every draft
and break `--fail-on-error` in CI.
"""

import os

import pytest
import yaml
from click.testing import CliRunner

from hecate_agent.commands.hunt import hunt
from hecate_agent.core.hunt_parser import HuntParser, validate_hunt_file_with_warnings


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_workspace(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    (tmp_path / "hunts").mkdir(exist_ok=True)
    yield tmp_path
    os.chdir(old_cwd)


def _write_hunt(tmp_path, **frontmatter):
    """Write a minimal structurally-valid hunt with the given frontmatter."""
    fm = {
        "hunt_id": "H-0001",
        "title": "Test hunt",
        "status": "planning",
        "date": "2026-09-06",
        "hunter": "Tester",
        "platform": ["Windows"],
        "tactics": ["execution"],
        "techniques": ["T1059"],
        "data_sources": ["Splunk"],
    }
    fm.update(frontmatter)
    body = "\n".join(
        [
            "# H-0001: Test hunt",
            "## LEARN: Prepare the Hunt",
            "text",
            "## OBSERVE: Expected Behaviors",
            "text",
            "## CHECK: Execute & Analyze",
            "text",
            "## KEEP: Findings & Response",
            "text",
        ]
    )
    path = tmp_path / "hunts" / "H-0001.md"
    path.write_text("---\n{}---\n\n{}\n".format(yaml.dump(fm, sort_keys=False), body), encoding="utf-8")
    return path


@pytest.mark.unit
class TestValidatorSurfacesEmptyRequiredFields:
    def test_empty_fields_produce_warnings(self, tmp_path):
        (tmp_path / "hunts").mkdir()
        path = _write_hunt(tmp_path, platform=[], tactics=[], techniques=[])

        parser = HuntParser(path)
        parser.parse()
        warnings = parser.collect_warnings()

        assert any("platform" in w for w in warnings)
        assert any("tactics" in w for w in warnings)
        assert any("techniques" in w for w in warnings)

    def test_populated_fields_produce_no_warnings(self, tmp_path):
        (tmp_path / "hunts").mkdir()
        path = _write_hunt(tmp_path)

        parser = HuntParser(path)
        parser.parse()

        assert parser.collect_warnings() == []

    def test_missing_field_is_reported_as_missing(self, tmp_path):
        (tmp_path / "hunts").mkdir()
        path = _write_hunt(tmp_path)
        raw = path.read_text(encoding="utf-8").replace("data_sources:\n- Splunk\n", "")
        path.write_text(raw, encoding="utf-8")

        parser = HuntParser(path)
        parser.parse()

        assert any("Missing recommended frontmatter field: data_sources" in w for w in parser.collect_warnings())

    def test_warnings_never_make_a_hunt_invalid(self, tmp_path):
        """A draft awaiting review must not fail --fail-on-error in CI."""
        (tmp_path / "hunts").mkdir()
        path = _write_hunt(tmp_path, platform=[], tactics=[], techniques=[])

        is_valid, errors, warnings = validate_hunt_file_with_warnings(path)

        assert is_valid is True
        assert errors == []
        assert len(warnings) == 3

    def test_cli_reports_the_gaps(self, runner, temp_workspace):
        _write_hunt(temp_workspace, platform=[], tactics=[], techniques=[])

        result = runner.invoke(hunt, ["validate", "H-0001"])

        assert result.exit_code == 0
        assert "Hunt is valid!" in result.output
        assert "Metadata gaps" in result.output


@pytest.mark.unit
class TestUpdateCanSetAttackMetadata:
    def test_sets_techniques_tactics_and_platform(self, runner, temp_workspace):
        _write_hunt(temp_workspace, platform=[], tactics=[], techniques=[])

        result = runner.invoke(
            hunt,
            ["update", "H-0001", "--technique", "T1071", "--tactic", "command-and-control", "--platform", "Windows"],
        )
        assert result.exit_code == 0

        fm = yaml.safe_load((temp_workspace / "hunts" / "H-0001.md").read_text().split("---", 2)[1])
        assert fm["techniques"] == ["T1071"]
        assert fm["tactics"] == ["command-and-control"]
        assert fm["platform"] == ["Windows"]

    def test_repeated_flags_replace_rather_than_append(self, runner, temp_workspace):
        _write_hunt(temp_workspace, techniques=["T1091"])

        runner.invoke(hunt, ["update", "H-0001", "--technique", "T1102", "--technique", "T1071"])

        fm = yaml.safe_load((temp_workspace / "hunts" / "H-0001.md").read_text().split("---", 2)[1])
        assert fm["techniques"] == ["T1102", "T1071"]

    def test_unknown_tactic_is_rejected_without_writing(self, runner, temp_workspace):
        _write_hunt(temp_workspace, tactics=["execution"])

        result = runner.invoke(hunt, ["update", "H-0001", "--tactic", "not-a-tactic"])

        assert "Unknown MITRE tactic" in result.output
        fm = yaml.safe_load((temp_workspace / "hunts" / "H-0001.md").read_text().split("---", 2)[1])
        assert fm["tactics"] == ["execution"]

    def test_unknown_technique_is_rejected_without_writing(self, runner, temp_workspace):
        """Guarded on STIX: without mitreattack-python installed there is no
        per-technique data to check against, so the command intentionally lets
        the value through rather than rejecting every ID."""
        from hecate_agent.core.attack_matrix import is_using_stix

        if not is_using_stix():
            pytest.skip("technique validation requires STIX data (pip install 'hecate-agent[attack]')")

        _write_hunt(temp_workspace, techniques=["T1059"])

        result = runner.invoke(hunt, ["update", "H-0001", "--technique", "T9999"])

        assert "Unknown MITRE technique" in result.output
        fm = yaml.safe_load((temp_workspace / "hunts" / "H-0001.md").read_text().split("---", 2)[1])
        assert fm["techniques"] == ["T1059"]

    def test_update_preserves_frontmatter_formatting(self, runner, temp_workspace):
        """An update should patch the requested field, not reformat every
        other one -- lists stay inline and a long title stays on one line."""
        long_title = "DRAFT - " + "a very long hunt title that would otherwise be wrapped onto a continuation line"
        _write_hunt(temp_workspace, title=long_title, platform=[])

        runner.invoke(hunt, ["update", "H-0001", "--platform", "Windows"])

        raw = (temp_workspace / "hunts" / "H-0001.md").read_text()
        assert "platform: [Windows]" in raw
        assert "title: {}".format(long_title) in raw

        fm = yaml.safe_load(raw.split("---", 2)[1])
        assert fm["title"] == long_title
