import logging
from hecate_agent.orchestrator.graph import hecate_graph

logging.basicConfig(level=logging.INFO)

print("LangGraph compiled with SQLite Checkpointer successfully!")
print("Graph nodes:", hecate_graph.nodes)
