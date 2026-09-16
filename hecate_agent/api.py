"""Programmatic API for Hecate operations.

This module exposes Core functionalities as reusable Python functions rather 
than CLI commands, eliminating subprocess overhead and stdout-parsing 
brittleness for orchestrators like Hecate-Runner.
"""
import re
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
import json

from hecate_agent.agents.llm.hypothesis_generator import HypothesisGeneratorAgent, HypothesisGenerationInput, HypothesisGenerationOutput
from hecate_agent.agents.llm.sigma_generator import SigmaGeneratorAgent, SigmaGenerationInput, SigmaGenerationOutput
from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput, ResearchOutput
from hecate_agent.core.attack_matrix import get_technique, get_superseding_technique_id, is_using_stix
from hecate_agent.core.research_manager import ResearchManager
from hecate_agent.commands.research import _generate_research_markdown

def generate_hypothesis(
    threat_intel: str,
    research_id: Optional[str] = None,
    indicators_only: bool = False,
    workspace: Optional[Path] = None,
) -> HypothesisGenerationOutput:
    """Generate a hunt hypothesis directly via the Python API."""
    agent = HypothesisGeneratorAgent(llm_enabled=True)
    
    past_hunts: List[dict] = []
    environment = {}
    research_ctx = None

    if workspace:
        research_mgr = ResearchManager(workspace)
        if research_id:
            research_doc = research_mgr.get_research(research_id)
            if research_doc:
                research_ctx = research_mgr.extract_research_context(research_doc)
                
        env_file = workspace / "knowledge" / "environment.md"
        if env_file.exists():
            environment = {"environment_md": env_file.read_text(encoding="utf-8")}

    input_data = HypothesisGenerationInput(
        threat_intel=threat_intel,
        past_hunts=past_hunts,
        environment=environment,
        research=research_ctx,
        intel_is_indicator_only=indicators_only,
    )
    
    result = agent.execute(input_data)
    if not result.success:
        raise RuntimeError(f"Hypothesis generation failed: {result.error}")
        
    if not result.data:
        raise RuntimeError("Hypothesis generation returned no data.")
        
    return result.data


def generate_research(
    topic: str,
    technique: Optional[str] = None,
    depth: str = "basic",
    web_search_enabled: bool = True,
    workspace: Optional[Path] = None,
) -> Tuple[ResearchOutput, Path]:
    """Execute research and create the research document."""
    manager = ResearchManager(workspace) if workspace else ResearchManager()
    research_id = manager.get_next_research_id()
    
    agent = HuntResearcherAgent(llm_enabled=True)
    result = agent.execute(
        ResearchInput(
            topic=topic,
            mitre_technique=technique,
            depth=depth,
            include_past_hunts=True,
            include_telemetry_mapping=True,
            web_search_enabled=web_search_enabled,
            research_id=research_id,
        )
    )
    
    if not result.success or not result.data:
        raise RuntimeError(f"Research failed: {result.error}")
        
    output = result.data
    markdown_content = _generate_research_markdown(output)
    
    linked_hunts = []
    for source in output.related_work.sources:
        match = re.match(r"hunts/(H-\d+)\.md$", source.get("url", ""))
        if match:
            linked_hunts.append(match.group(1))
            
    frontmatter = {
        "research_id": output.research_id,
        "topic": output.topic,
        "mitre_techniques": output.mitre_techniques,
        "status": "completed",
        "depth": depth,
        "duration_minutes": round(output.total_duration_ms / 60000, 1),
        "linked_hunts": linked_hunts,
        "web_searches": output.web_searches_performed,
        "llm_calls": output.llm_calls,
        "total_cost_usd": output.total_cost_usd,
        "data_source_availability": output.data_source_availability,
        "estimated_hunt_complexity": output.estimated_hunt_complexity,
    }

    file_path = manager.create_research_file(
        research_id=output.research_id,
        topic=output.topic,
        content=markdown_content,
        frontmatter=frontmatter,
    )
    
    return output, file_path


def generate_sigma(
    payload: Dict[str, Any],
    out_dir: Optional[Path] = None,
    hunt_id: Optional[str] = None,
) -> Tuple[SigmaGenerationOutput, List[Path]]:
    """Generate Sigma rules and optionally write them to disk."""
    known = set(SigmaGenerationInput.__dataclass_fields__)
    agent_input = SigmaGenerationInput(**{k: v for k, v in payload.items() if k in known})
    if hunt_id and not agent_input.hunt_id:
        agent_input.hunt_id = hunt_id

    result = SigmaGeneratorAgent(llm_enabled=True).execute(agent_input)
    if not result.success or not result.data:
        raise RuntimeError(f"Sigma generation failed: {result.error}")

    written_paths = []
    if out_dir:
        target = Path(out_dir)
        target.mkdir(parents=True, exist_ok=True)
        for rule in result.data.rules:
            path = target / rule.filename
            path.write_text(rule.rule_yaml, encoding="utf-8")
            written_paths.append(path)
            
    return result.data, written_paths


def lookup_technique(technique_id: str) -> Dict[str, Any]:
    """Look up an ATT&CK technique by ID."""
    if not is_using_stix():
        raise RuntimeError("stix_unavailable")
        
    tech = get_technique(technique_id)
    # Provenance of this call, not a property of the technique. Writing it
    # onto `tech` mutated the STIX provider's memoized index in place, so
    # every later lookup of the superseding ID -- and every tactic listing
    # handing back the same dict -- reported it as superseded from whatever
    # revoked ID happened to be asked for first.
    superseded_from = ""
    if not tech:
        # Check for superseded IDs
        latest = get_superseding_technique_id(technique_id)
        if latest and latest != technique_id:
            tech = get_technique(latest)
            if tech:
                superseded_from = technique_id

    if not tech:
        return {"found": False}

    return {
        "found": True,
        "technique_id": tech.get("id", ""),
        "name": tech.get("name", ""),
        "description": tech.get("description", ""),
        "tactics": tech.get("tactic_shortnames", []),
        "platforms": tech.get("platforms", []),
        "data_sources": tech.get("data_sources", []),
        "is_subtechnique": tech.get("is_subtechnique", False),
        "superseded_from": superseded_from,
    }

def link_research_to_hunt(
    research_id: str,
    hunt_id: str,
    workspace: Path | None = None,
) -> bool:
    """Link a drafted hunt ID back to its originating research document.
    
    Args:
        research_id: The ID of the research document to update.
        hunt_id: The ID of the drafted hunt.
        workspace: Path to Hecate workspace. If None, uses current directory.
    """
    from hecate_agent.core.research_manager import ResearchManager
    manager = ResearchManager(workspace) if workspace else ResearchManager()
    return manager.link_hunt_to_research(research_id, hunt_id)
