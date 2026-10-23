"""Tests for hecate-agent demo init command."""

from pathlib import Path
from click.testing import CliRunner

from hecate_agent.commands.demo import demo
from hecate_agent.core.hunt_manager import HuntManager
from hecate_agent.core.hunt_parser import parse_hunt_file


def test_demo_init_creates_files(tmp_path: Path):
    """hecate-agent demo init creates a complete example hunt in a new workspace."""
    runner = CliRunner()
    result = runner.invoke(demo, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Hecate Demo Workspace Initialized" in result.output

    # Check directories exist
    assert (tmp_path / "research").exists()
    assert (tmp_path / "queries").exists()
    assert (tmp_path / "detections").exists()

    # Check files created
    research_file = tmp_path / "research" / "R-0001.md"
    spl_file = tmp_path / "queries" / "H-0001-lsass-dumping.spl"
    kql_file = tmp_path / "queries" / "H-0001-lsass-dumping.kql"
    sigma_file = tmp_path / "detections" / "H-0001.yml"

    assert research_file.exists()
    assert spl_file.exists()
    assert kql_file.exists()
    assert sigma_file.exists()

    # Find the hunt file recursively in hunts/
    hm = HuntManager(hunts_dir=tmp_path / "hunts")
    hunts = hm.find_all_hunt_files()
    assert len(hunts) == 1
    hunt_file = hunts[0]
    assert hunt_file.name == "H-0001.md"

    # Verify hunt file parses properly
    data = parse_hunt_file(hunt_file)
    assert data["frontmatter"]["id"] == "H-0001"
    assert "T1003.001" in data["frontmatter"]["techniques"]
    assert "credential-access" in data["frontmatter"]["tactics"]
    assert "learn" in data["lock_sections"]
    assert "observe" in data["lock_sections"]
    assert "check" in data["lock_sections"]
    assert "keep" in data["lock_sections"]


def test_demo_init_skips_without_force(tmp_path: Path):
    """Running demo init twice without --force skips existing files."""
    runner = CliRunner()
    result1 = runner.invoke(demo, ["init", "--path", str(tmp_path)])
    assert result1.exit_code == 0

    result2 = runner.invoke(demo, ["init", "--path", str(tmp_path)])
    assert result2.exit_code == 0
    assert "Existing files kept" in result2.output


def test_demo_init_overwrites_with_force(tmp_path: Path):
    """Running demo init with --force overwrites modified files."""
    runner = CliRunner()
    runner.invoke(demo, ["init", "--path", str(tmp_path)])

    spl_file = tmp_path / "queries" / "H-0001-lsass-dumping.spl"
    spl_file.write_text("custom query")

    result = runner.invoke(demo, ["init", "--path", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "H-0001-lsass-dumping.spl" in result.output
    assert spl_file.read_text() != "custom query"
