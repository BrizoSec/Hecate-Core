import logging
from typing import TypedDict, Optional, List, Dict, Any
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
    mitre_techniques: List[str]
    
    # Hypothesis Output (Agent 2)
    hypothesis: Optional[str]
    justification: Optional[str]
    observables: List[str]
    
    # Sigma Output (Agent 3)
    sigma_yaml_files: List[str]
    sigma_rules_yaml: List[str] # RAW YAML STRINGS for the markdown file
    
    # Final Output
    draft_path: Optional[str]
    
    # Agentic Error Tracking
    errors: List[str]


def research_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Research Agent...")
    workspace = Path(state["workspace_path"]) if state.get("workspace_path") else None
    
    try:
        output, file_path = generate_research(
            topic=state["topic"],
            workspace=workspace,
        )
        return {
            "research_id": output.research_id,
            "mitre_techniques": output.mitre_techniques,
        }
    except Exception as e:
        logger.error(f"Research failed: {e}")
        return {"errors": state.get("errors", []) + [f"Research Error: {e}"]}



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
    workspace = Path(state["workspace_path"]) if state.get("workspace_path") else None
    
    try:
        output = generate_hypothesis(
            threat_intel=state["threat_intel"] + (state.get("enrichment_summary") or ""),
            research_id=state.get("research_id"),
            workspace=workspace
        )
        return {
            "hypothesis": output.hypothesis,
            "justification": output.justification,
            "observables": output.expected_observables,
            "mitre_techniques": list(set(state.get("mitre_techniques", []) + output.mitre_techniques))
        }
    except Exception as e:
        logger.error(f"Hypothesis failed: {e}")
        return {"errors": state.get("errors", []) + [f"Hypothesis Error: {e}"]}


def sigma_drafter_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Sigma Drafter Agent...")
    out_dir = Path(state["out_dir"]) if state.get("out_dir") else None
    hunt_id = state.get("hunt_id", "H-0000")
    
    payload = {
        "hypothesis": state.get("hypothesis", ""),
        "justification": state.get("justification", ""),
        "techniques": state.get("mitre_techniques", []),
        "observables": state.get("observables", []),
        "hunt_id": hunt_id,
        "indicators": {}
    }
    
    try:
        output, paths = generate_sigma(
            payload=payload,
            out_dir=out_dir,
            hunt_id=hunt_id
        )
        return {
            "sigma_yaml_files": [str(p) for p in paths],
            "sigma_rules_yaml": [r.rule_yaml for r in output.rules]
        }
    except Exception as e:
        logger.error(f"Sigma Drafter failed: {e}")
        return {"errors": state.get("errors", []) + [f"Sigma Error: {e}"]}


def hunt_writer_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing Hunt Writer Agent...")
    # Because we decouple from Hecate-Runner, we do a basic markdown render here.
    workspace = Path(state["workspace_path"]) if state.get("workspace_path") else Path(".")
    hunt_id = state.get("hunt_id", "H-0000")
    
    date_str = datetime.now().strftime('%Y-%m-%d')
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
        
    out_dir = workspace / "hunts" / str(datetime.now().year) / f"Q{(datetime.now().month-1)//3+1}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{hunt_id}.md"
    
    with open(out_path, "w") as f:
        f.write(content)
        
    logger.info(f"Draft hunt written to {out_path}")
    return {"draft_path": str(out_path)}



def misp_publisher_agent(state: HuntState) -> Dict[str, Any]:
    logger.info("Executing MISP Publisher Agent...")
    from hecate_agent.orchestrator.misp_publisher import publish_hunt_to_misp
    
    try:
        topic = state.get("topic", "Untitled Hunt")
        hypothesis = state.get("hypothesis", "")
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
    return "next"


# Build the State Graph
workflow = StateGraph(HuntState)

# Add Agent Nodes
workflow.add_node("research", research_agent)
workflow.add_node("enrichment", enrichment_agent)
workflow.add_node("hypothesis", hypothesis_agent)
workflow.add_node("sigma_drafter", sigma_drafter_agent)
workflow.add_node("hunt_writer", hunt_writer_agent)
workflow.add_node("misp_publisher", misp_publisher_agent)

# Set Entry Point
workflow.set_entry_point("research")

# Add Conditional Edges
workflow.add_conditional_edges("research", route_errors, {"next": "enrichment", END: END})
workflow.add_conditional_edges("enrichment", route_errors, {"next": "hypothesis", END: END})
workflow.add_conditional_edges("hypothesis", route_errors, {"next": "sigma_drafter", END: END})
workflow.add_conditional_edges("sigma_drafter", route_errors, {"next": "hunt_writer", END: END})
workflow.add_conditional_edges("hunt_writer", route_errors, {"next": "misp_publisher", END: END})
workflow.add_conditional_edges("misp_publisher", route_errors, {"next": END, END: END})

from langgraph.checkpoint.sqlite import SqliteSaver
import sqlite3

def compile_graph(db_path: str = "hecate_checkpoints.sqlite", require_approval: bool = True):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    memory = SqliteSaver(conn)
    
    if require_approval:
        return workflow.compile(checkpointer=memory, interrupt_before=["sigma_drafter"])
    else:
        return workflow.compile(checkpointer=memory)

hecate_graph = compile_graph()
