"""Tests for atomic_red_team mapping and markdown rendering."""

import pytest
from hecate_agent.core.atomic_red_team import (
    ATOMIC_TESTS_MAP,
    get_atomic_tests,
    format_atomic_tests_markdown,
)


@pytest.mark.unit
class TestAtomicRedTeam:
    def test_get_atomic_tests_curated_technique(self):
        tests = get_atomic_tests("T1003.001")
        assert len(tests) >= 1
        assert any("lsass" in t["command"].lower() for t in tests)
        assert any("Sysmon" in t["telemetry"] for t in tests)

    def test_get_atomic_tests_base_technique_fallback(self):
        # T1055 has subtechniques, but T1055 itself is mapped
        tests = get_atomic_tests("T1055.001")
        assert len(tests) >= 1
        assert "T1055" in tests[0]["test_id"]

    def test_get_atomic_tests_unmapped_technique(self):
        tests = get_atomic_tests("T9999.001")
        assert len(tests) == 1
        assert "T9999.001" in tests[0]["test_id"]
        assert "Generic" in tests[0]["test_id"]

    def test_format_atomic_tests_markdown_empty(self):
        assert format_atomic_tests_markdown([]) == ""

    def test_format_atomic_tests_markdown_renders_table(self):
        md = format_atomic_tests_markdown(["T1059.001", "T1053.005"])
        assert "### Validation Procedure (Atomic Red Team)" in md
        assert "| Technique | Test ID | Procedure / Command | Expected Telemetry |" in md
        assert "`T1059.001`" in md
        assert "`T1053.005`" in md
        assert "schtasks" in md

    def test_format_atomic_tests_markdown_escapes_pipes(self, monkeypatch):
        # Even if command or telemetry has pipes, it should escape them for markdown tables
        monkeypatch.setitem(
            ATOMIC_TESTS_MAP,
            "T9999",
            [
                {
                    "name": "Pipe Test",
                    "test_id": "ART T9999 #1",
                    "command": "cmd1 | cmd2",
                    "telemetry": "Event 1 | Event 2",
                }
            ],
        )
        md = format_atomic_tests_markdown(["T9999"])
        assert "`T9999`" in md
        assert "cmd1 \\| cmd2" in md
        assert "Event 1 \\| Event 2" in md
