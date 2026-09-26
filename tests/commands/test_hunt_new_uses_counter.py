"""`hunt new` and its siblings take IDs from the counter the orchestrator and Hecate-Runner share."""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from hecate_agent.commands.hunt import hunt


@pytest.fixture()
def workspace(tmp_path):
    old = os.getcwd()
    os.chdir(tmp_path)
    (tmp_path / "hunts").mkdir()
    yield tmp_path
    os.chdir(old)


def _counter(ws: Path) -> str:
    return (ws / "hunts" / ".hunt_id_counter").read_text().strip()


def _created(ws: Path) -> list:
    return sorted(p.stem for p in (ws / "hunts").rglob("H-*.md"))


def test_hunt_new_continues_from_the_counter_not_the_highest_file(workspace):
    """The Runner reserved H-0040 but has not written it yet; the CLI must not reuse it."""
    (workspace / "hunts" / ".hunt_id_counter").write_text("40\n")
    result = CliRunner().invoke(hunt, ["new", "--title", "Kerberoasting", "--non-interactive"])
    assert result.exit_code == 0, result.output
    assert "H-0041" in result.output
    assert _created(workspace) == ["H-0041"]
    assert _counter(workspace) == "41"


def test_baseline_and_model_assisted_share_the_same_sequence(workspace):
    runner = CliRunner()
    runner.invoke(hunt, ["new", "--title", "One", "--non-interactive"])
    runner.invoke(hunt, ["new-baseline", "--title", "Two", "--non-interactive"])
    runner.invoke(hunt, ["new-model-assisted", "--title", "Three", "--non-interactive"])
    assert _created(workspace) == ["H-0001", "H-0002", "H-0003"]
    assert _counter(workspace) == "3"


def test_an_abandoned_hunt_new_spends_no_id(workspace):
    """Allocation happens after the prompts, so a run that stops early leaves the counter alone."""
    result = CliRunner().invoke(hunt, ["new-baseline", "--non-interactive"])  # no --title: stops
    assert "required" in result.output
    assert not (workspace / "hunts" / ".hunt_id_counter").exists()
    CliRunner().invoke(hunt, ["new", "--title", "Next", "--non-interactive"])
    assert _created(workspace) == ["H-0001"]


def test_a_custom_prefix_keeps_the_scan_based_id(workspace):
    from hecate_agent.core.hunt_manager import HuntManager

    manager = HuntManager(hunts_dir=workspace / "hunts")
    assert manager.allocate_hunt_id(prefix="TH-") == "TH-0001"
    assert not (workspace / "hunts" / ".hunt_id_counter").exists()
