"""Tests for ResearchManager.append_hypothesis()."""

import textwrap
from pathlib import Path

import pytest
import yaml

from athf.core.research_manager import ResearchManager, parse_research_file


SAMPLE_RESEARCH = textwrap.dedent(
    """\
    ---
    research_id: R-0042
    topic: Discovery commands post-access reconnaissance
    mitre_techniques:
    - T1016
    - T1082
    - T1087
    status: completed
    depth: advanced
    linked_hunts: []
    created_date: '2026-05-22'
    ---

    # R-0042: Research

    ## 1. System Research

    ### Summary
    Discovery commands are widely used.
    """
)


@pytest.fixture()
def research_dir(tmp_path: Path) -> Path:
    research_dir = tmp_path / "research"
    research_dir.mkdir()
    (research_dir / "R-0042.md").write_text(SAMPLE_RESEARCH, encoding="utf-8")
    return research_dir


def test_append_hypothesis_creates_section(research_dir: Path) -> None:
    rm = ResearchManager(research_dir=research_dir)

    result = rm.append_hypothesis(
        research_id="R-0042",
        hypothesis="Adversaries run native discovery commands post-access.",
        mitre_techniques=["T1016", "T1082"],
        data_sources=["EDR process telemetry"],
        justification="Reconnaissance precedes lateral movement.",
        expected_observables=["whoami", "ipconfig"],
        known_false_positives=["Admin scripts"],
        time_range_suggestion="7 days",
    )

    assert result is not None
    contents = result.read_text(encoding="utf-8")
    assert "## Generated Hypothesis" in contents
    assert "> Adversaries run native discovery commands post-access." in contents
    assert "**MITRE Techniques:** T1016, T1082" in contents
    assert "**Data Sources:** EDR process telemetry" in contents
    assert "**Time Range:** 7 days" in contents
    assert "- whoami" in contents
    assert "- Admin scripts" in contents


def test_append_hypothesis_records_frontmatter(research_dir: Path) -> None:
    rm = ResearchManager(research_dir=research_dir)

    rm.append_hypothesis(
        research_id="R-0042",
        hypothesis="Adversaries run native discovery commands post-access.",
        mitre_techniques=["T1016"],
        data_sources=["EDR"],
    )

    parsed = parse_research_file(research_dir / "R-0042.md")
    fm = parsed["frontmatter"]
    assert "generated_hypothesis" in fm
    assert fm["generated_hypothesis"]["hypothesis"].startswith("Adversaries run")
    assert fm["generated_hypothesis"]["mitre_techniques"] == ["T1016"]
    assert fm["generated_hypothesis"]["data_sources"] == ["EDR"]
    assert fm["generated_hypothesis"]["generated_at"]
    # Pre-existing frontmatter fields are preserved
    assert fm["research_id"] == "R-0042"
    assert fm["status"] == "completed"


def test_append_hypothesis_is_idempotent(research_dir: Path) -> None:
    rm = ResearchManager(research_dir=research_dir)

    rm.append_hypothesis(
        research_id="R-0042",
        hypothesis="First hypothesis.",
        mitre_techniques=["T1016"],
    )
    rm.append_hypothesis(
        research_id="R-0042",
        hypothesis="Replacement hypothesis.",
        mitre_techniques=["T1082"],
    )

    contents = (research_dir / "R-0042.md").read_text(encoding="utf-8")
    assert contents.count("## Generated Hypothesis") == 1
    assert "Replacement hypothesis." in contents
    assert "First hypothesis." not in contents


def test_append_hypothesis_unknown_id_returns_none(research_dir: Path) -> None:
    rm = ResearchManager(research_dir=research_dir)
    assert rm.append_hypothesis(research_id="R-9999", hypothesis="x") is None


def test_append_hypothesis_preserves_research_body(research_dir: Path) -> None:
    rm = ResearchManager(research_dir=research_dir)

    rm.append_hypothesis(
        research_id="R-0042",
        hypothesis="Hypothesis.",
    )

    contents = (research_dir / "R-0042.md").read_text(encoding="utf-8")
    assert "## 1. System Research" in contents
    assert "Discovery commands are widely used." in contents
