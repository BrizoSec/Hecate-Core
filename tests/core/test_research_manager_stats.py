"""Tests for ResearchManager.calculate_stats(), specifically linked-hunt counting."""

from pathlib import Path

import pytest

from athf.core.research_manager import ResearchManager


def _write_research(
    research_dir: Path,
    research_id: str,
    *,
    linked_hunts: list | None = None,
) -> None:
    """Write a minimal but structurally valid research file directly to disk."""
    linked_hunts_line = f"linked_hunts: {linked_hunts!r}".replace("'", "") if linked_hunts is not None else "linked_hunts: []"
    content = f"""---
research_id: {research_id}
topic: Test topic for {research_id}
status: completed
depth: basic
duration_minutes: 1.0
{linked_hunts_line}
created_date: '2026-01-01'
---

# {research_id}: Research

## 1. System Research: How It Works

### Summary
Test content.
"""
    (research_dir / f"{research_id}.md").write_text(content)


def _write_hunt(
    hunts_dir: Path,
    hunt_id: str,
    *,
    spawned_from: str | None = None,
) -> None:
    """Write a minimal but structurally valid hunt file directly to disk."""
    spawned_from_line = f"spawned_from: {spawned_from}\n" if spawned_from else ""
    content = f"""---
hunt_id: {hunt_id}
title: Test Hunt {hunt_id}
status: planning
date: 2026-01-01
{spawned_from_line}true_positives: 0
false_positives: 0
---

## LEARN: Prepare the Hunt

Content.

## OBSERVE: Expected Behaviors

Content.

## CHECK: Execute & Analyze

Content.

## KEEP: Findings & Response

Content.
"""
    (hunts_dir / f"{hunt_id}.md").write_text(content)


@pytest.mark.unit
class TestCalculateStatsLinkedHunts:
    """Regression coverage: `linked_hunts` frontmatter and a hunt's
    `spawned_from` are meant to be inverses of each other, but nothing
    keeps them in sync -- a hunt creator that only sets `spawned_from`
    (never writes back to the research doc) used to make `calculate_stats`
    undercount real linkage. `total_linked_hunts` must reflect hunts
    discovered via `spawned_from` even when `linked_hunts` was never
    updated."""

    def test_hunt_linked_only_via_spawned_from_is_counted(self, tmp_path):
        research_dir = tmp_path / "research"
        hunts_dir = tmp_path / "hunts"
        research_dir.mkdir()
        hunts_dir.mkdir()

        _write_research(research_dir, "R-0001")  # linked_hunts: [] -- never written back
        _write_hunt(hunts_dir, "H-0001", spawned_from="R-0001")

        stats = ResearchManager(research_dir).calculate_stats()

        assert stats["total_linked_hunts"] == 1

    def test_explicit_linked_hunts_still_counted_without_a_matching_spawned_from(self, tmp_path):
        research_dir = tmp_path / "research"
        hunts_dir = tmp_path / "hunts"
        research_dir.mkdir()
        hunts_dir.mkdir()

        _write_research(research_dir, "R-0001", linked_hunts=["H-9999"])
        # No hunt file for H-9999 on disk at all -- the explicit frontmatter
        # link is still honored, not just spawned_from discovery.

        stats = ResearchManager(research_dir).calculate_stats()

        assert stats["total_linked_hunts"] == 1

    def test_same_hunt_named_both_ways_is_not_double_counted(self, tmp_path):
        research_dir = tmp_path / "research"
        hunts_dir = tmp_path / "hunts"
        research_dir.mkdir()
        hunts_dir.mkdir()

        _write_research(research_dir, "R-0001", linked_hunts=["H-0001"])
        _write_hunt(hunts_dir, "H-0001", spawned_from="R-0001")

        stats = ResearchManager(research_dir).calculate_stats()

        assert stats["total_linked_hunts"] == 1

    def test_research_with_no_hunts_at_all_counts_zero(self, tmp_path):
        research_dir = tmp_path / "research"
        hunts_dir = tmp_path / "hunts"
        research_dir.mkdir()
        hunts_dir.mkdir()

        _write_research(research_dir, "R-0001")

        stats = ResearchManager(research_dir).calculate_stats()

        assert stats["total_linked_hunts"] == 0

    def test_missing_hunts_directory_does_not_raise(self, tmp_path):
        research_dir = tmp_path / "research"
        research_dir.mkdir()
        # No hunts/ dir created at all -- a bare `research/` workspace.

        _write_research(research_dir, "R-0001")

        stats = ResearchManager(research_dir).calculate_stats()

        assert stats["total_linked_hunts"] == 0
