"""Tests for athf.core.hunt_manager - hunt listing and program statistics."""

from pathlib import Path
from typing import Optional

import pytest

from athf.core.hunt_manager import HuntManager, get_hunt_directory


def _write_hunt(
    hunts_dir: Path,
    hunt_id: str,
    *,
    hunt_type: Optional[str] = None,
    status: str = "completed",
    true_positives: int = 0,
    tactics: Optional[list] = None,
    techniques: Optional[list] = None,
) -> None:
    """Write a minimal but structurally valid hunt file directly to disk."""
    hunt_type_line = f"hunt_type: {hunt_type}\n" if hunt_type else ""
    tactics_line = f"tactics: {tactics!r}\n".replace("'", "") if tactics else ""
    techniques_line = f"techniques: {techniques!r}\n" if techniques else ""
    content = f"""---
hunt_id: {hunt_id}
title: Test Hunt {hunt_id}
{hunt_type_line}status: {status}
date: 2025-12-02
{tactics_line}{techniques_line}true_positives: {true_positives}
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
class TestGetHuntDirectory:
    """Test the get_hunt_directory function."""

    def test_get_hunt_directory_production(self, monkeypatch):
        """Test that the production directory is returned."""
        from datetime import datetime
        import athf.core.hunt_manager as hm
        monkeypatch.setattr(hm, 'datetime', type('_FakeDatetime', (), {'now': staticmethod(lambda: datetime(2025, 1, 1))})())
        assert get_hunt_directory() == Path("hunts/2025/Q1")

    def test_get_hunt_directory_test(self, monkeypatch):
        """Test that the test directory is returned."""
        from datetime import datetime
        import athf.core.hunt_manager as hm
        monkeypatch.setattr(hm, 'datetime', type('_FakeDatetime', (), {'now': staticmethod(lambda: datetime(2025, 1, 1))})())
        assert get_hunt_directory(is_test=True) == Path("hunts/test/2025/Q1")


@pytest.mark.unit
class TestFindHuntFile:
    """Test the find_hunt_file function."""

    def test_find_hunt_file_invalid_id(self, tmp_path):
        """Test that an invalid hunt ID returns None."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.find_hunt_file("invalid-id") is None

    def test_find_hunt_file_not_found(self, tmp_path):
        """Test that a non-existent hunt ID returns None."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.find_hunt_file("H-9999") is None

    def test_find_hunt_file_outside_hunts_dir(self, tmp_path):
        """Test that a hunt file outside the hunts_dir is not found."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        _write_hunt(outside_dir, "H-0001")
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.find_hunt_file("H-0001") is None


@pytest.mark.unit
class TestGetNextHuntId:
    """Test the get_next_hunt_id function."""

    def test_get_next_hunt_id_no_hunts(self, tmp_path):
        """Test that the first hunt ID is correct."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.get_next_hunt_id() == "H-0001"

    def test_get_next_hunt_id_custom_prefix(self, tmp_path):
        """Test that a custom prefix is handled correctly."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.get_next_hunt_id(prefix="HUNT-") == "HUNT-0001"

    def test_get_next_hunt_id_with_existing_hunts(self, tmp_path):
        """Test that the next hunt ID is correct when hunts exist."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(hunts_dir, "H-0001")
        _write_hunt(hunts_dir, "H-0002")
        manager = HuntManager(hunts_dir=hunts_dir)
        assert manager.get_next_hunt_id() == "H-0003"


@pytest.mark.unit
class TestCalculateStats:
    """Test HuntManager.calculate_stats(), specifically baseline-hunt exclusion."""

    def test_baseline_hunts_counted_but_excluded_from_success_rate(self, tmp_path):
        """A completed baseline hunt (true_positives always 0, no hypothesis to
        confirm) must not drag down success_rate -- it should count in
        total_hunts/completed_hunts/baseline_hunts but be excluded from the
        success_rate denominator entirely."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()

        _write_hunt(hunts_dir, "H-0001", status="completed", true_positives=1)
        _write_hunt(hunts_dir, "H-0002", hunt_type="baseline", status="completed", true_positives=0)

        stats = HuntManager(hunts_dir=hunts_dir).calculate_stats()

        assert stats["total_hunts"] == 2
        assert stats["completed_hunts"] == 2
        assert stats["baseline_hunts"] == 1
        # Only H-0001 counts toward success rate; H-0002 (baseline) is excluded
        # from the denominator entirely, so this must be 100%, not 50%.
        assert stats["success_rate"] == 100.0

    def test_success_rate_zero_when_only_baseline_hunts_exist(self, tmp_path):
        """No hypothesis-driven hunts to compute a rate over -> 0.0, not a
        ZeroDivisionError and not a misleading 0% that implies failed hunts."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()

        _write_hunt(hunts_dir, "H-0001", hunt_type="baseline", status="completed", true_positives=0)

        stats = HuntManager(hunts_dir=hunts_dir).calculate_stats()

        assert stats["total_hunts"] == 1
        assert stats["baseline_hunts"] == 1
        assert stats["success_rate"] == 0.0

    def test_hunts_without_hunt_type_field_treated_as_hypothesis_driven(self, tmp_path):
        """Every hunt created before baseline hunts existed has no hunt_type
        field at all -- these must keep counting toward success_rate exactly
        as before, not be silently dropped."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()

        _write_hunt(hunts_dir, "H-0001", status="completed", true_positives=1)

        stats = HuntManager(hunts_dir=hunts_dir).calculate_stats()

        assert stats["baseline_hunts"] == 0
        assert stats["success_rate"] == 100.0


@pytest.mark.unit
class TestListHuntsTypeFilter:
    """Test HuntManager.list_hunts()'s hunt_type filter and field."""

    def test_filters_by_hunt_type(self, tmp_path):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()

        _write_hunt(hunts_dir, "H-0001", status="planning")
        _write_hunt(hunts_dir, "H-0002", hunt_type="baseline", status="planning")

        manager = HuntManager(hunts_dir=hunts_dir)

        baseline_only = manager.list_hunts(hunt_type="baseline")
        assert [h["hunt_id"] for h in baseline_only] == ["H-0002"]

        hypothesis_only = manager.list_hunts(hunt_type="hypothesis-driven")
        assert [h["hunt_id"] for h in hypothesis_only] == ["H-0001"]

    def test_hunt_type_defaults_to_hypothesis_driven_when_absent(self, tmp_path):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(hunts_dir, "H-0001", status="planning")

        hunts = HuntManager(hunts_dir=hunts_dir).list_hunts()

        assert hunts[0]["hunt_type"] == "hypothesis-driven"


@pytest.mark.unit
class TestCalculateAttackCoverage:
    """Test HuntManager.calculate_attack_coverage(), specifically technique/tactic
    misattribution -- requires real ATT&CK data (STIX cache or bundled fallback)
    to resolve technique->tactic mappings, same as the CLI itself."""

    # Minimal technique->tactic map covering exactly the techniques used in
    # the tests below. Injected via setup_method so the tests always run
    # (no dependency on a cached STIX file or optional mitreattack-python).
    _TECHNIQUE_MAP = {
        "T1053.005": {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task",
                      "tactic_shortnames": ["execution", "persistence", "privilege-escalation"]},
        "T1204":     {"id": "T1204", "name": "User Execution",
                      "tactic_shortnames": ["execution"]},
        "T1003.001": {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory",
                      "tactic_shortnames": ["credential-access"]},
    }

    def setup_method(self):
        from athf.core import attack_matrix
        from athf.core.attack_matrix import FallbackProvider

        technique_map = self._TECHNIQUE_MAP

        class _MockProvider(FallbackProvider):
            def get_technique_by_id(self, technique_id):
                return technique_map.get(technique_id.upper())

        attack_matrix.reset_provider(_MockProvider())

    def test_technique_not_credited_to_a_tactic_it_does_not_belong_to(self, tmp_path):
        """Regression test, reproduced from this repo's real H-0016: a hunt
        tagged tactics=[credential-access] with techniques=[T1053.005, T1204]
        (Persistence/Privilege-Escalation/Execution and Execution respectively
        -- neither is Credential Access) used to have BOTH techniques credited
        to credential-access coverage with no check, because the old code
        crossed every technique on a hunt with every tactic on that same hunt."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(
            hunts_dir,
            "H-0001",
            tactics=["credential-access"],
            techniques=["T1053.005", "T1204"],
        )

        coverage = HuntManager(hunts_dir=hunts_dir).calculate_attack_coverage()

        credential_access = coverage["by_tactic"]["credential-access"]
        assert credential_access["techniques"] == {}
        assert credential_access["techniques_covered"] == 0
        # The hunt is still counted as scoped to this tactic (the hunter's own
        # declared intent), even though neither technique actually belongs here.
        assert credential_access["hunt_ids"] == ["H-0001"]

    def test_technique_still_credited_to_a_tactic_it_genuinely_belongs_to(self, tmp_path):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(
            hunts_dir,
            "H-0002",
            tactics=["credential-access"],
            techniques=["T1003.001"],  # LSASS Memory -- genuinely credential-access
        )

        coverage = HuntManager(hunts_dir=hunts_dir).calculate_attack_coverage()

        credential_access = coverage["by_tactic"]["credential-access"]
        assert credential_access["techniques"] == {"T1003.001": ["H-0002"]}
        assert credential_access["techniques_covered"] == 1

    def test_technique_credited_to_every_declared_tactic_it_genuinely_belongs_to(self, tmp_path):
        """T1053.005 genuinely belongs to execution, persistence, AND
        privilege-escalation -- a hunt declaring more than one of those
        tactics should get credit in each real match, not just the first."""
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(
            hunts_dir,
            "H-0003",
            tactics=["execution", "persistence"],
            techniques=["T1053.005"],
        )

        coverage = HuntManager(hunts_dir=hunts_dir).calculate_attack_coverage()

        assert coverage["by_tactic"]["execution"]["techniques"] == {"T1053.005": ["H-0003"]}
        assert coverage["by_tactic"]["persistence"]["techniques"] == {"T1053.005": ["H-0003"]}


@pytest.mark.unit
class TestParseCache:
    """Test the class-level cache backing list_hunts()/calculate_stats()/
    calculate_attack_coverage(). Every call site constructs a *fresh*
    HuntManager (grep confirms no caller reuses one), so this has to be a
    class-level cache keyed by directory, not a per-instance one, to have
    any effect -- these tests exercise it across separate instances to
    match that real usage pattern."""

    def test_second_call_reuses_cache_without_reparsing(self, tmp_path, monkeypatch):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(hunts_dir, "H-0001", status="planning")
        _write_hunt(hunts_dir, "H-0002", status="planning")

        import athf.core.hunt_manager as hunt_manager_module

        real_parse = hunt_manager_module.parse_hunt_file_fast
        call_count = {"n": 0}

        def counting_parse(path):
            call_count["n"] += 1
            return real_parse(path)

        monkeypatch.setattr(hunt_manager_module, "parse_hunt_file_fast", counting_parse)

        HuntManager(hunts_dir=hunts_dir).list_hunts()
        assert call_count["n"] == 2  # first call: real parse, once per file

        # A brand new instance against the same (unchanged) directory --
        # matches how every real call site actually uses HuntManager.
        HuntManager(hunts_dir=hunts_dir).list_hunts()
        assert call_count["n"] == 2  # unchanged: second call served from cache

    def test_cache_invalidates_when_a_hunt_is_added(self, tmp_path):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(hunts_dir, "H-0001", status="planning")

        first = HuntManager(hunts_dir=hunts_dir).list_hunts()
        assert len(first) == 1

        _write_hunt(hunts_dir, "H-0002", status="planning")

        second = HuntManager(hunts_dir=hunts_dir).list_hunts()
        assert len(second) == 2

    def test_cache_invalidates_when_a_hunt_is_edited(self, tmp_path):
        hunts_dir = tmp_path / "hunts"
        hunts_dir.mkdir()
        _write_hunt(hunts_dir, "H-0001", status="planning")
        assert HuntManager(hunts_dir=hunts_dir).list_hunts()[0]["status"] == "planning"

        # Rewrite with a later mtime than the original write.
        import os
        import time

        time.sleep(0.01)
        _write_hunt(hunts_dir, "H-0001", status="completed")
        os.utime(hunts_dir / "H-0001.md", None)  # force a fresh mtime regardless of fs timestamp resolution

        assert HuntManager(hunts_dir=hunts_dir).list_hunts()[0]["status"] == "completed"

    def test_different_directories_do_not_share_a_cache_entry(self, tmp_path):
        dir_a = tmp_path / "a" / "hunts"
        dir_a.mkdir(parents=True)
        _write_hunt(dir_a, "H-0001", status="planning")

        dir_b = tmp_path / "b" / "hunts"
        dir_b.mkdir(parents=True)
        _write_hunt(dir_b, "H-0002", status="completed")

        assert [h["hunt_id"] for h in HuntManager(hunts_dir=dir_a).list_hunts()] == ["H-0001"]
        assert [h["hunt_id"] for h in HuntManager(hunts_dir=dir_b).list_hunts()] == ["H-0002"]