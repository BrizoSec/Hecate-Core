"""Hunt ID allocation, in step with Hecate-Runner's counter protocol."""

import subprocess
from pathlib import Path

from hecate_agent.core import hunt_ids


def _hunts(tmp_path: Path) -> Path:
    hunts = tmp_path / "hunts"
    (hunts / "2026" / "Q3").mkdir(parents=True)
    return hunts


def test_the_counter_is_the_high_water_mark(tmp_path):
    hunts = _hunts(tmp_path)
    (hunts / ".hunt_id_counter").write_text("20\n")
    (hunts / "2026" / "Q3" / "H-0005.md").write_text("x")
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0021"
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0022"
    assert (hunts / ".hunt_id_counter").read_text() == "22\n"


def test_hunts_on_disk_and_query_dirs_are_floors(tmp_path):
    hunts = _hunts(tmp_path)
    (hunts / ".hunt_id_counter").write_text("3\n")
    (hunts / "2026" / "Q3" / "H-0010.md").write_text("x")
    (tmp_path / "queries" / "H-0015").mkdir(parents=True)
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0016"


def test_h0000_on_disk_does_not_confuse_numbering(tmp_path):
    hunts = _hunts(tmp_path)
    (hunts / "2026" / "Q3" / "H-0000.md").write_text("x")
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0001"


def test_git_history_seeds_a_missing_counter(tmp_path):
    hunts = _hunts(tmp_path)
    old = hunts / "2026" / "Q3" / "H-0030.md"
    old.write_text("x")
    git = ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git[:3], "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "x"], check=True)
    old.unlink()
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0031"


def test_a_corrupt_counter_falls_back_to_the_floors(tmp_path):
    hunts = _hunts(tmp_path)
    (hunts / ".hunt_id_counter").write_text("not a number")
    (hunts / "2026" / "Q3" / "H-0007.md").write_text("x")
    assert hunt_ids.allocate_hunt_id(hunts) == "H-0008"
