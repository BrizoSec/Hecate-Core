import logging
from typing import TypedDict, Optional, List, Dict, Any
from pathlib import Path

from langgraph.graph import StateGraph, END
from hecate_agent.api import generate_research, generate_hypothesis, generate_sigma

logger = logging.getLogger(__name__)

class HuntState(TypedDict):
    """The shared state passed across the Hecate Multi-Agent Graph."""
    # Inputs
    topic: str
    threat_intel: str
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
    
    # Sigma Output (Agent 3 + Python Auditor)
    sigma_yaml_files: List[str]
    
    # Agentic Error Tracking
    errors: List[str]


def research_agent(state: HuntState) -> Dict[str, Any]:
    """Agent 1: Performs background CTI and system research."""
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


def hypothesis_agent(state: HuntState) -> Dict[str, Any]:
    """Agent 2: Synthesizes threat intel and research into a hunt hypothesis."""
    logger.info("Executing Hypothesis Agent...")
    workspace = Path(state["workspace_path"]) if state.get("workspace_path") else None
    
    try:
        output = generate_hypothesis(
            threat_intel=state["threat_intel"],
            research_id=state["research_id"],
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
    """Agent 3: Drafts generic Sigma rules (includes internal Agentic Audit Loop)."""
    logger.info("Executing Sigma Drafter Agent...")
    out_dir = Path(state["out_dir"]) if state.get("out_dir") else None
    
    payload = {
        "hypothesis": state.get("hypothesis", ""),
        "justification": state.get("justification", ""),
        "techniques": state.get("mitre_techniques", []),
        "observables": state.get("observables", []),
        "hunt_id": state.get("hunt_id", "H-0000"),
        "indicators": {}
    }
    
    try:
        output, paths = generate_sigma(
            payload=payload,
            out_dir=out_dir,
            hunt_id=state.get("hunt_id")
        )
        return {
            "sigma_yaml_files": [str(p) for p in paths]
        }
    except Exception as e:
        logger.error(f"Sigma Drafter failed: {e}")
        return {"errors": state.get("errors", []) + [f"Sigma Error: {e}"]}


def route_errors(state: HuntState) -> str:
    """Conditional Edge: Routes flow to END if any agent encountered an unrecoverable error."""
    if state.get("errors"):
        logger.error(f"Pipeline aborted due to agent errors: {state['errors']}")
        return END
    return "next"


# Build the State Graph
workflow = StateGraph(HuntState)

# Add Agent Nodes
workflow.add_node("research", research_agent)
workflow.add_node("hypothesis", hypothesis_agent)
workflow.add_node("sigma_drafter", sigma_drafter_agent)

# Set Entry Point
workflow.set_entry_point("research")

# Add Conditional Edges
workflow.add_conditional_edges("research", route_errors, {"next": "hypothesis", END: END})
workflow.add_conditional_edges("hypothesis", route_errors, {"next": "sigma_drafter", END: END})
workflow.add_conditional_edges("sigma_drafter", route_errors, {"next": END, END: END})

# Compile the Graph
from langgraph.checkpoint.sqlite import SqliteSaver
import sqlite3

# We wrap this in a helper so you can pass your own DB connection or memory
def compile_graph(db_path: str = "hecate_checkpoints.sqlite"):
    """Compile the LangGraph with SQLite checkpointing for state persistence."""
    # We use check_same_thread=False so it works safely in async/multithreaded envs
    conn = sqlite3.connect(db_path, check_same_thread=False)
    memory = SqliteSaver(conn)
    # interrupt_before pauses the graph right before it executes the given node
    return workflow.compile(checkpointer=memory, interrupt_before=["sigma_drafter"])

# Default global instance for easy importing
hecate_graph = compile_graph()
