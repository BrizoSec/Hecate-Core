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

    def test_get_atomic_tests_dynamic_attack_lookup(self, monkeypatch):
        # Mock get_technique to isolate unit test from external STIX dependency on CI
        monkeypatch.setattr(
            "hecate_agent.core.attack_matrix.get_technique",
            lambda tid: {
                "name": "Brute Force",
                "platforms": ["Linux", "Windows"],
                "data_sources": ["Logon Session: Logon Session Creation"],
            }
            if "T1110" in tid
            else None,
        )
        tests = get_atomic_tests("T1110")
        assert len(tests) >= 1
        assert "Brute Force" in tests[0]["name"]
        assert "Procedural" in tests[0]["test_id"]
        assert "Linux/Windows" in tests[0]["command"]
        assert "Logon Session" in tests[0]["telemetry"]

    def test_get_atomic_tests_workspace_custom_tests(self, tmp_path):
        import json

        knowledge = tmp_path / "knowledge"
        knowledge.mkdir()
        custom_file = knowledge / "atomic_tests.json"
        custom_file.write_text(
            json.dumps(
                {
                    "T9998": [
                        {
                            "name": "Custom In-House Test",
                            "test_id": "ORG-T9998-01",
                            "command": "custom_tool.exe --run",
                            "telemetry": "Custom EDR log",
                        }
                    ]
                }
            )
        )
        tests = get_atomic_tests("T9998", workspace=tmp_path)
        assert len(tests) == 1
        assert tests[0]["name"] == "Custom In-House Test"
        assert tests[0]["test_id"] == "ORG-T9998-01"
