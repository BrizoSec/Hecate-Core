import sqlite3
from hecate_agent.orchestrator.graph import hecate_graph

config = {"configurable": {"thread_id": "HITL-Demo-001"}}

print("1. Kicking off the pipeline...")
initial_state = {
    "topic": "Suspicious PowerShell Downloads",
    "threat_intel": "Actors are using PowerShell to download payloads from pastebin.",
    "mitre_techniques": ["T1059.001"],
    "hypothesis": "Initial hypothesis that will be reviewed.",
}

# The graph will run Research and Hypothesis, then PAUSE before sigma_drafter
for event in hecate_graph.stream(initial_state, config=config):
    for key, value in event.items():
        print(f"Node '{key}' completed.")

print("\n--- PIPELINE PAUSED (Human-in-the-Loop) ---")
# Get the current state
current_state = hecate_graph.get_state(config)
print(f"Next node to execute: {current_state.next}")

if "sigma_drafter" in current_state.next:
    print("\n[Analyst Review Required]")
    print(f"Current Hypothesis: {current_state.values.get('hypothesis')}")
    
    # Human decides to edit the state!
    print("\n2. Analyst edits the hypothesis...")
    hecate_graph.update_state(
        config,
        {"hypothesis": "UPDATED BY ANALYST: Focus exclusively on Invoke-WebRequest commands."},
    )
    
    print("3. Analyst approves and resumes the pipeline...")
    # Resuming the graph by invoking with None
    for event in hecate_graph.stream(None, config=config):
        for key, value in event.items():
            print(f"Node '{key}' completed.")
            
    final_state = hecate_graph.get_state(config)
    print("\n--- PIPELINE FINISHED ---")
    print(f"Final Hypothesis used for drafting: {final_state.values.get('hypothesis')}")
