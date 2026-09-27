import logging
from typing import TypedDict, Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime

from langgraph.graph import StateGraph, END
from hecate_agent.api import generate_research, generate_hypothesis, generate_sigma

logger = logging.getLogger(__name__)


class HuntState(TypedDict):
    """The shared state passed across the Hecate Multi-Agent Graph."""

    # Inputs
    topic: str
    threat_intel: str
    enrichment_summary: Optional[str]
    workspace_path: Optional[str]
    out_dir: Optional[str]
    hunt_id: Optional[str]

    # Research Output (Agent 1)
    research_id: Optional[str]
    research_path: Optional[str]
    mitre_techniques: List[str]

    # Hypothesis Output (Agent 2)
    hypothesis: Optional[str]
    justification: Optional[str]
    observables: List[str]

    # Sigma Output (Agent 3)
    sigma_yaml_files: List[str]
    sigma_rules_yaml: List[str]  # RAW YAML STRINGS for the markdown file

    # Quality gates (technique_filter, grounding_audit)
    techniques_dropped: List[str]
    techniques_wording_matched: List[str]
    technique_facts: Dict[str, Dict[str, Any]]
    grounding_section: Optional[str]
    grounding_unsupported: int
    # Set when a gate decides there is nothing worth drafting; ends the run.
    halted: Optional[str]

    # Final Output
    draft_path: Optional[str]

    # Agentic Error Tracking
    errors: List[str]


def research_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Research Agent...")
    workspace_path = state.get("workspace_path")
    workspace = Path(workspace_path) if workspace_path else None

    try:
        output, file_path = generate_research(
            topic=state["topic"],
            workspace=workspace,
            source_context=state.get("threat_intel")
        )
        return {
            "research_id": output.research_id,
            "research_path": str(file_path),
            "mitre_techniques": output.mitre_techniques,
        }
    except Exception as e:
        logger.error(f"Research failed: {e}")
        return {"errors": state.get("errors", []) + [f"Research Error: {e}"]}


def artifact_extractor_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Artifact Extractor Agent...")
    from hecate_agent.orchestrator.artifact_extractor import extract_deep_artifacts

    try:
        threat_intel = state.get("threat_intel", "")
        extracted = extract_deep_artifacts(threat_intel)

        new_intel = extracted.get("new_intel", "")
        new_obs = extracted.get("new_observables", [])

        if new_intel:
            # Append the deep scraped artifacts to the threat_intel
            threat_intel += new_intel

        current_obs = state.get("observables", [])
        # Append new observables, ensuring no duplicates
        for obs in new_obs:
            if obs not in current_obs:
                current_obs.append(obs)

        return {"threat_intel": threat_intel, "observables": current_obs}
    except Exception as e:
        logger.error(f"Artifact Extractor Agent failed: {e}")
        return {"errors": state.get("errors", []) + [f"Artifact Extraction Error: {e}"]}


def enrichment_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Enrichment Agent (VirusTotal)...")
    from hecate_agent.orchestrator.enrichment import generate_enrichment_summary

    try:
        summary = generate_enrichment_summary(state["threat_intel"])
        return {"enrichment_summary": summary}
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        return {"errors": state.get("errors", []) + [f"Enrichment Error: {e}"]}


def hypothesis_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Hypothesis Agent...")
    workspace_path = state.get("workspace_path")
    workspace = Path(workspace_path) if workspace_path else None

    try:
        output = generate_hypothesis(
            threat_intel=state["threat_intel"] + (state.get("enrichment_summary") or ""),
            research_id=state.get("research_id"),
            workspace=workspace,
        )
        return {
            "hypothesis": output.hypothesis,
            "justification": output.justification,
            "observables": output.expected_observables,
            "mitre_techniques": list(set(state.get("mitre_techniques", []) + output.mitre_techniques)),
        }
    except Exception as e:
        logger.error(f"Hypothesis failed: {e}")
        return {"errors": state.get("errors", []) + [f"Hypothesis Error: {e}"]}


def _research_text(state: HuntState) -> str:
    path = state.get("research_path")
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(f"Could not read research document {path}: {e}")
        return ""


def _lookup(technique_id: str) -> Dict[str, Any]:
    from hecate_agent.api import lookup_technique

    return lookup_technique(technique_id)


def _candidates(text: str) -> List[Tuple[str, str]]:
    from hecate_agent.core.technique_candidates import candidate_techniques

    return candidate_techniques(text)


def technique_filter_agent(state: HuntState) -> Dict[str, Any]:
    """Drop model-picked techniques no source describes; halt when nothing is left to hunt."""
    logger.info("Executing Technique Filter Agent...")
    from hecate_agent.orchestrator import quality

    try:
        decision = quality.filter_techniques(
            state.get("mitre_techniques", []),
            cti_text=state.get("threat_intel", ""),
            research_text=_research_text(state),
            lookup=_lookup,
            candidates=_candidates,
        )
    except Exception as e:
        logger.error(f"Technique filter failed: {e}")
        return {"errors": state.get("errors", []) + [f"Technique Filter Error: {e}"]}

    dropped = decision.dropped_unevidenced + [f"{t} (not in ATT&CK)" for t in decision.dropped_unknown]
    if dropped:
        logger.info(f"Dropped techniques no source supports: {dropped}")
    update: Dict[str, Any] = {
        "mitre_techniques": decision.kept,
        "techniques_dropped": dropped,
        "techniques_wording_matched": decision.wording_matched,
        "technique_facts": {tid: {"valid": fact.valid, "names": list(fact.names)} for tid, fact in decision.facts.items()},
    }
    reason = quality.park_reason(decision.kept, state.get("threat_intel", ""))
    if reason:
        logger.warning(f"Halting before drafting: {reason}")
        update["halted"] = reason
    return update


def _workspace(state: HuntState) -> Path:
    return Path(state.get("workspace_path") or ".")


def allocate_hunt_id_agent(state: HuntState) -> Dict[str, Any]:
    """Take the next hunt ID from the counter the Runner shares, unless the caller supplied one.

    Runs after human approval: the ID is burned when allocated, so allocating
    before the pause would spend one on every rejected hunt. It must precede
    the Sigma drafter, which stamps the ID into each rule.
    """
    if state.get("hunt_id"):
        return {}
    from hecate_agent.core.hunt_ids import allocate_hunt_id

    try:
        hunt_id = allocate_hunt_id(_workspace(state) / "hunts")
    except OSError as e:
        logger.error(f"Hunt ID allocation failed: {e}")
        return {"errors": state.get("errors", []) + [f"Hunt ID Allocation Error: {e}"]}
    logger.info(f"Allocated {hunt_id}")
    return {"hunt_id": hunt_id}


def sigma_drafter_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Sigma Drafter Agent...")
    out_dir_value = state.get("out_dir")
    out_dir = Path(out_dir_value) if out_dir_value else None
    hunt_id = state["hunt_id"]

    payload: Dict[str, Any] = {
        "hypothesis": state.get("hypothesis", ""),
        "justification": state.get("justification", ""),
        "techniques": state.get("mitre_techniques", []),
        "observables": state.get("observables", []),
        "hunt_id": hunt_id,
        "indicators": {},
    }

    try:
        output, paths = generate_sigma(payload=payload, out_dir=out_dir, hunt_id=hunt_id)
        return {"sigma_yaml_files": [str(p) for p in paths], "sigma_rules_yaml": [r.rule_yaml for r in output.rules]}
    except Exception as e:
        logger.error(f"Sigma Drafter failed: {e}")
        return {"errors": state.get("errors", []) + [f"Sigma Error: {e}"]}


def render_draft(state: HuntState) -> str:
    """The draft's markdown; the grounding audit reads exactly what the writer writes."""
    hunt_id = state.get("hunt_id") or "(unallocated)"
    date_str = datetime.now().strftime("%Y-%m-%d")
    content = f"""---
hunt_id: {hunt_id}
title: {state.get('topic', 'Untitled Hunt')}
status: planning
date: {date_str}
hunter: hecate langgraph (auto-generated)
techniques: {state.get('mitre_techniques', [])}
spawned_from: {state.get('research_id', 'None')}
---
# Hunt Hypothesis
{state.get('hypothesis', 'No hypothesis generated.')}

# Research Justification
{state.get('justification', 'No justification provided.')}

# Expected Observables
{chr(10).join(f"- {o}" for o in state.get('observables', []))}

# Sigma Rules
"""
    for rule_yaml in state.get("sigma_rules_yaml", []):
        content += f"\n```yaml\n{rule_yaml}\n```\n"
    return content


def grounding_audit_agent(state: HuntState) -> Dict[str, Any]:
    """Audit the draft's techniques, CVEs, entities and rule indicators against the intel and research."""
    logger.info("Executing Grounding Audit Agent...")
    from hecate_agent.orchestrator import quality
    from hecate_agent.core.grounding import TechniqueFact

    try:
        facts = {
            tid: TechniqueFact(valid=bool(f.get("valid", True)), names=tuple(f.get("names", ())))
            for tid, f in (state.get("technique_facts") or {}).items()
        }
        report, section = quality.audit(
            draft_text=render_draft(state),
            cti_text=state.get("threat_intel", ""),
            research_text=_research_text(state),
            facts=facts,
            wording_matched=state.get("techniques_wording_matched", []),
        )
    except Exception as e:
        logger.error(f"Grounding audit failed: {e}")
        return {"errors": state.get("errors", []) + [f"Grounding Audit Error: {e}"]}

    dropped = state.get("techniques_dropped") or []
    if dropped:
        section += (
            "\n> Dropped before drafting, because the model proposed them and nothing in the CTI "
            f"or research describes them: {', '.join(f'`{d}`' for d in dropped)}\n"
        )
    if report.unsupported:
        logger.warning(f"Grounding audit: {len(report.unsupported)} unsupported claim(s); MISP publishing will be skipped")
    return {"grounding_section": section, "grounding_unsupported": len(report.unsupported)}


def hunt_writer_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Hunt Writer Agent...")
    # Because we decouple from Hecate-Runner, we do a basic markdown render here.
    workspace = _workspace(state)
    hunt_id = state.get("hunt_id")
    if not hunt_id:
        return {"errors": state.get("errors", []) + ["Hunt Writer Error: no hunt ID was allocated"]}
    content = render_draft(state)
    if state.get("grounding_section"):
        content += f"\n# Grounding\n\n{state['grounding_section']}"

    out_dir = workspace / "hunts" / str(datetime.now().year) / f"Q{(datetime.now().month-1)//3+1}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{hunt_id}.md"

    # "x" refuses to replace an existing draft: every run used to overwrite H-0000.md.
    try:
        with open(out_path, "x", encoding="utf-8") as f:
            f.write(content)
    except FileExistsError:
        logger.error(f"Refusing to overwrite existing hunt {out_path}")
        return {"errors": state.get("errors", []) + [f"Hunt Writer Error: {out_path} already exists"]}

    logger.info(f"Draft hunt written to {out_path}")
    return {"draft_path": str(out_path)}


def misp_publisher_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing MISP Publisher Agent...")
    from hecate_agent.orchestrator.misp_publisher import publish_hunt_to_misp

    try:
        topic = state.get("topic", "Untitled Hunt")
        hypothesis = state.get("hypothesis") or ""
        observables = state.get("observables", [])

        result = publish_hunt_to_misp(topic, hypothesis, observables)
        logger.info(f"MISP Publisher Result: {result}")

        # We could add the event link to the errors or a new state field, but logging is fine for now
        return {}
    except Exception as e:
        logger.error(f"MISP Publish failed: {e}")
        return {"errors": state.get("errors", []) + [f"MISP Publish Error: {e}"]}


def route_errors(state: HuntState) -> str:
    if state.get("errors"):
        logger.error(f"Pipeline aborted due to agent errors: {state['errors']}")
        return END
    if state.get("halted"):
        logger.warning(f"Pipeline halted: {state['halted']}")
        return END
    return "next"


def route_publish(state: HuntState) -> str:
    """Publish to MISP only a draft whose every checkable claim traces to a source."""
    if route_errors(state) == END:
        return END
    if state.get("grounding_unsupported"):
        logger.warning("Not publishing to MISP: the draft has unsupported claims (see its Grounding section)")
        return END
    return "next"


# Build the State Graph
workflow = StateGraph(HuntState)

# Add Agent Nodes
workflow.add_node("research", research_agent)
workflow.add_node("artifact_extractor", artifact_extractor_agent)
workflow.add_node("enrichment", enrichment_agent)
workflow.add_node("hypothesis", hypothesis_agent)
workflow.add_node("technique_filter", technique_filter_agent)
workflow.add_node("allocate_hunt_id", allocate_hunt_id_agent)
workflow.add_node("sigma_drafter", sigma_drafter_agent)
workflow.add_node("grounding_audit", grounding_audit_agent)
workflow.add_node("hunt_writer", hunt_writer_agent)
workflow.add_node("misp_publisher", misp_publisher_agent)

# Set Entry Point


# Add Conditional Edges
workflow.set_entry_point("artifact_extractor")
workflow.add_conditional_edges("artifact_extractor", route_errors, {"next": "research", END: END})
workflow.add_conditional_edges("research", route_errors, {"next": "enrichment", END: END})
workflow.add_conditional_edges("enrichment", route_errors, {"next": "hypothesis", END: END})
workflow.add_conditional_edges("hypothesis", route_errors, {"next": "technique_filter", END: END})
workflow.add_conditional_edges("technique_filter", route_errors, {"next": "allocate_hunt_id", END: END})
workflow.add_conditional_edges("allocate_hunt_id", route_errors, {"next": "sigma_drafter", END: END})
workflow.add_conditional_edges("sigma_drafter", route_errors, {"next": "grounding_audit", END: END})
workflow.add_conditional_edges("grounding_audit", route_errors, {"next": "hunt_writer", END: END})
workflow.add_conditional_edges("hunt_writer", route_publish, {"next": "misp_publisher", END: END})
workflow.add_conditional_edges("misp_publisher", route_errors, {"next": END, END: END})

from langgraph.checkpoint.sqlite import SqliteSaver
import sqlite3


def compile_graph(db_path: str = "hecate_checkpoints.sqlite", require_approval: bool = True) -> Any:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    memory = SqliteSaver(conn)

    if require_approval:
        return workflow.compile(checkpointer=memory, interrupt_before=["allocate_hunt_id"])
    else:
        return workflow.compile(checkpointer=memory)


hecate_graph = compile_graph()
