"""Tests for Threat Actor STIX profiling in HuntResearcherAgent."""

import pytest

from hecate_agent.agents.llm.hunt_researcher import (
    HuntResearcherAgent,
    ResearchInput,
)
from hecate_agent.commands.research import _generate_research_markdown


@pytest.mark.unit
def test_hunt_researcher_attaches_threat_actor_profiles():
    agent = HuntResearcherAgent(llm_enabled=False)

    input_data = ResearchInput(
        topic="Midnight Blizzard OAuth Abuse",
        source_context="Observed activity from Midnight Blizzard (APT29) abusing OAuth application tokens.",
        depth="basic",
        web_search_enabled=False,
    )

    result = agent.execute(input_data)
    assert result.success is True
    output = result.data
    assert output is not None

    # Check threat_actor_profiles
    assert len(output.threat_actor_profiles) >= 1
    apt29 = output.threat_actor_profiles[0]
    assert apt29["id"] == "G0016"
    assert apt29["name"] == "APT29"

    # Render markdown and verify sections
    md = _generate_research_markdown(output)
    assert "### Threat Actor Profiles (MITRE ATT&CK STIX)" in md
    assert "APT29 (G0016)" in md
    assert "Midnight Blizzard" in md
    assert "Known Associated Toolkits & Malware" in md or "Key Observed Techniques" in md


@pytest.mark.unit
def test_secondary_enrichment_does_not_attribute_unrelated_actors():
    agent = HuntResearcherAgent(llm_enabled=False)
    result = agent.execute(
        ResearchInput(
            topic="Cotton Sandstorm election infrastructure activity",
            source_context=(
                "Cotton Sandstorm / Emennet Pasargad.\n"
                "SECONDARY OSINT ENRICHMENT (context lead only; not source evidence):\n"
                "Related Iranian operations include APT33, APT39 and APT42."
            ),
            depth="basic",
            web_search_enabled=False,
        )
    )
    assert result.success
    assert result.data.threat_actor_profiles == []
