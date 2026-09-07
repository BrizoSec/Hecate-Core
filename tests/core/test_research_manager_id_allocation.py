"""Tests for ResearchManager research ID allocation.

Allocation used to be a pure scan of research/, so clearing the directory --
the normal cleanup here is to commit the documents and remove them -- reset
numbering to R-0001 and reissued IDs that already named a different document
in git history. Drafts reference their grounding as `spawned_from: R-XXXX`,
so a reused ID also repoints that link at the wrong research.
"""

import json
import subprocess
from pathlib import Path

from athf.core.research_manager import ResearchManager


def _write_research(research_dir: Path, research_id: str) -> None:
    """Write a minimal but structurally valid research file directly to disk."""
    content = f"""---
research_id: {research_id}
topic: Test topic for {research_id}
status: completed
depth: basic
duration_minutes: 1.0
linked_hunts: []
created_date: '2026-01-01'
---

# {research_id}: Research

## 1. System Research: How It Works

### Summary
Test content.
"""
    research_dir.mkdir(parents=True, exist_ok=True)
    (research_dir / f"{research_id}.md").write_text(content)


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_next_id_in_empty_directory(tmp_path: Path) -> None:
    manager = ResearchManager(tmp_path / "research")
    assert manager.get_next_research_id() == "R-0001"


def test_next_id_finds_max_on_disk(tmp_path: Path) -> None:
    research_dir = tmp_path / "research"
    for research_id in ("R-0003", "R-0011", "R-0007"):
        _write_research(research_dir, research_id)
    assert ResearchManager(research_dir).get_next_research_id() == "R-0012"


def test_next_id_persists_across_an_emptied_directory(tmp_path: Path) -> None:
    """Regression test for research ID reuse: the counter has to outlive the
    directory being emptied by the commit-then-clean cleanup."""
    research_dir = tmp_path / "research"
    manager = ResearchManager(research_dir)

    for expected in ("R-0001", "R-0002", "R-0003"):
        research_id = manager.get_next_research_id()
        assert research_id == expected
        _write_research(research_dir, research_id)

    # Simulate the cleanup: every document committed away, directory emptied.
    for doc in list(research_dir.glob("R-*.md")):
        doc.unlink()
    assert not list(research_dir.glob("R-*.md"))

    assert manager.get_next_research_id() == "R-0004"


def test_next_id_prefers_on_disk_max_over_a_stale_counter(tmp_path: Path) -> None:
    """A document added by hand (or by a version predating the counter) sits
    above the counter's value; it must not be clobbered."""
    research_dir = tmp_path / "research"
    _write_research(research_dir, "R-0042")
    (research_dir / ".research_id_counter").write_text(json.dumps({"R-": 3}))
    assert ResearchManager(research_dir).get_next_research_id() == "R-0043"


def test_next_id_survives_a_corrupted_counter(tmp_path: Path) -> None:
    """A truncated or hand-edited counter falls back to the on-disk floor
    rather than failing allocation."""
    research_dir = tmp_path / "research"
    _write_research(research_dir, "R-0008")
    (research_dir / ".research_id_counter").write_text("{not json")
    assert ResearchManager(research_dir).get_next_research_id() == "R-0009"


def test_counters_are_tracked_per_prefix(tmp_path: Path) -> None:
    """A custom prefix must not inherit or overwrite the default prefix's
    high-water mark."""
    research_dir = tmp_path / "research"
    manager = ResearchManager(research_dir)

    assert manager.get_next_research_id() == "R-0001"
    assert manager.get_next_research_id() == "R-0002"
    assert manager.get_next_research_id(prefix="X-") == "X-0001"
    assert manager.get_next_research_id() == "R-0003"

    counters = json.loads((research_dir / ".research_id_counter").read_text())
    assert counters == {"R-": 3, "X-": 1}


def test_next_id_seeds_from_git_history_on_first_run(tmp_path: Path) -> None:
    """First allocation after the counter was introduced resumes past every
    document git remembers, including ones already deleted from disk."""
    workspace = tmp_path / "workspace"
    research_dir = workspace / "research"
    research_dir.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)

    for research_id in ("R-0017", "R-0029", "R-0602"):
        _write_research(research_dir, research_id)
    _git("add", "-A", cwd=workspace)
    _git("commit", "-qm", "research", cwd=workspace)

    # The cleanup commit: documents removed from disk, retained in history.
    for doc in list(research_dir.glob("R-*.md")):
        doc.unlink()
    _git("add", "-A", cwd=workspace)
    _git("commit", "-qm", "cleanup", cwd=workspace)

    assert ResearchManager(research_dir).get_next_research_id() == "R-0603"


def test_next_id_outside_a_git_repo_uses_on_disk_max(tmp_path: Path) -> None:
    """A non-git workspace (or a machine without git) still allocates; the
    seed is best-effort and must not fail allocation."""
    research_dir = tmp_path / "research"
    _write_research(research_dir, "R-0004")
    assert ResearchManager(research_dir).get_next_research_id() == "R-0005"


def test_counter_file_is_readable_like_the_rest_of_the_workspace(tmp_path: Path) -> None:
    """The counter used to inherit mkstemp's owner-only 0o600, unlike every
    other file the workspace holds."""
    research_dir = tmp_path / "research"
    ResearchManager(research_dir).get_next_research_id()
    plain = research_dir / "reference.txt"
    plain.write_text("x")
    counter = research_dir / ".research_id_counter"
    assert counter.stat().st_mode & 0o777 == plain.stat().st_mode & 0o777
