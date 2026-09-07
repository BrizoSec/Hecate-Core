"""Regressions for two formatting/resolution defects found while reviewing
generated research documents.

1. ResearchManager.link_hunt_to_research patched frontmatter with a DOTALL
   regex that matched up to the next key and then re-appended a newline, so
   every call left a stray blank line behind:

       linked_hunts: ['H-0002']
       <blank>
       web_searches: 0

   `athf hunt new --research R-XXXX` runs this on every hunt created from a
   research doc, so the blank lines accumulated one per link.

2. _get_stix_cache_dir resolved the workspace-local cache from Path.cwd()
   while its docstring said "{workspace}". A caller that declares
   ATHF_WORKSPACE and runs from elsewhere silently got a different cache
   directory than the workspace it asked for.
"""

from pathlib import Path

import pytest
import yaml

from athf.core.attack_matrix import _get_stix_cache_dir
from athf.core.research_manager import ResearchManager

_FRONTMATTER = {
    "research_id": "R-0001",
    "topic": "Test topic",
    "status": "completed",
    "linked_hunts": [],
    "web_searches": 0,
    "data_source_availability": {"process_execution": True, "file_operations": False},
}


def _write_research(research_dir, **overrides):
    fm = dict(_FRONTMATTER)
    fm.update(overrides)
    research_dir.mkdir(parents=True, exist_ok=True)
    path = research_dir / "R-0001.md"
    path.write_text(
        "---\n{}---\n\n# R-0001: Test topic\n\nBody text.\n".format(yaml.dump(fm, sort_keys=False)),
        encoding="utf-8",
    )
    return path


@pytest.mark.unit
class TestLinkHuntToResearch:
    def test_link_adds_the_hunt(self, tmp_path):
        path = _write_research(tmp_path / "research")

        assert ResearchManager(research_dir=tmp_path / "research").link_hunt_to_research("R-0001", "H-0007") is True

        fm = yaml.safe_load(path.read_text().split("---", 2)[1])
        assert fm["linked_hunts"] == ["H-0007"]

    def test_link_leaves_no_blank_line_behind(self, tmp_path):
        path = _write_research(tmp_path / "research")
        manager = ResearchManager(research_dir=tmp_path / "research")

        manager.link_hunt_to_research("R-0001", "H-0007")

        frontmatter_text = path.read_text().split("---", 2)[1]
        assert "\n\n" not in frontmatter_text

    def test_repeated_links_do_not_accumulate_blank_lines(self, tmp_path):
        """The original regex added one blank line per call, so this is the
        shape the bug actually took in a workspace over time."""
        path = _write_research(tmp_path / "research")
        manager = ResearchManager(research_dir=tmp_path / "research")

        for hunt_id in ("H-0007", "H-0008", "H-0009"):
            manager.link_hunt_to_research("R-0001", hunt_id)

        frontmatter_text = path.read_text().split("---", 2)[1]
        assert "\n\n" not in frontmatter_text

        fm = yaml.safe_load(frontmatter_text)
        assert fm["linked_hunts"] == ["H-0007", "H-0008", "H-0009"]

    def test_linking_the_same_hunt_twice_is_idempotent(self, tmp_path):
        path = _write_research(tmp_path / "research")
        manager = ResearchManager(research_dir=tmp_path / "research")

        manager.link_hunt_to_research("R-0001", "H-0007")
        assert manager.link_hunt_to_research("R-0001", "H-0007") is True

        fm = yaml.safe_load(path.read_text().split("---", 2)[1])
        assert fm["linked_hunts"] == ["H-0007"]

    def test_body_is_preserved(self, tmp_path):
        path = _write_research(tmp_path / "research")

        ResearchManager(research_dir=tmp_path / "research").link_hunt_to_research("R-0001", "H-0007")

        assert "# R-0001: Test topic" in path.read_text()
        assert "Body text." in path.read_text()

    def test_unknown_research_id_returns_false(self, tmp_path):
        _write_research(tmp_path / "research")

        assert ResearchManager(research_dir=tmp_path / "research").link_hunt_to_research("R-9999", "H-0007") is False


@pytest.mark.unit
class TestStixCacheDirResolution:
    def test_declared_workspace_wins_over_cwd(self, tmp_path, monkeypatch):
        workspace = tmp_path / "ws"
        workspace.mkdir()
        (workspace / ".athfconfig.yaml").write_text("workspace_name: test\n", encoding="utf-8")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()

        monkeypatch.delenv("ATHF_STIX_CACHE", raising=False)
        monkeypatch.setenv("ATHF_WORKSPACE", str(workspace))
        monkeypatch.chdir(elsewhere)

        assert _get_stix_cache_dir() == workspace / ".athf" / "stix-data"

    def test_cwd_is_used_when_no_workspace_declared(self, tmp_path, monkeypatch):
        workspace = tmp_path / "ws"
        workspace.mkdir()
        (workspace / ".athfconfig.yaml").write_text("workspace_name: test\n", encoding="utf-8")

        monkeypatch.delenv("ATHF_STIX_CACHE", raising=False)
        monkeypatch.delenv("ATHF_WORKSPACE", raising=False)
        monkeypatch.chdir(workspace)

        assert _get_stix_cache_dir() == workspace / ".athf" / "stix-data"

    def test_explicit_cache_env_still_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATHF_STIX_CACHE", str(tmp_path / "explicit"))
        monkeypatch.setenv("ATHF_WORKSPACE", str(tmp_path))

        assert _get_stix_cache_dir() == tmp_path / "explicit"

    def test_falls_back_to_global_without_a_workspace_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ATHF_STIX_CACHE", raising=False)
        monkeypatch.delenv("ATHF_WORKSPACE", raising=False)
        monkeypatch.chdir(tmp_path)

        assert _get_stix_cache_dir() == Path.home() / ".athf" / "stix-data"


def test_research_link_command_writes_the_back_link(tmp_path, monkeypatch):
    """The runner writes hunt files itself (it needs the ID-allocation lock),
    so `athf hunt new --research` never runs and the research document was
    left reporting linked_hunts: [] while the hunt named it in spawned_from.
    """
    from click.testing import CliRunner

    from athf.commands.research import research

    research_dir = tmp_path / "research"
    _write_research(research_dir)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(research, ["link", "R-0001", "--hunt", "H-0612"])
    assert result.exit_code == 0, result.output

    fm = yaml.safe_load((research_dir / "R-0001.md").read_text().split("---")[1])
    assert fm["linked_hunts"] == ["H-0612"]


def test_research_link_command_is_idempotent(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from athf.commands.research import research

    research_dir = tmp_path / "research"
    _write_research(research_dir)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    runner.invoke(research, ["link", "R-0001", "--hunt", "H-0612"])
    result = runner.invoke(research, ["link", "R-0001", "--hunt", "H-0612"])
    assert result.exit_code == 0

    fm = yaml.safe_load((research_dir / "R-0001.md").read_text().split("---")[1])
    assert fm["linked_hunts"] == ["H-0612"]


def test_research_link_command_fails_loudly_on_an_unknown_id(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from athf.commands.research import research

    _write_research(tmp_path / "research")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(research, ["link", "R-9999", "--hunt", "H-0612"])
    assert result.exit_code != 0
