"""Hecate CLI commands (base commands only)."""

from hecate_agent.commands.attack import attack
from hecate_agent.commands.context import context
from hecate_agent.commands.env import env
from hecate_agent.commands.hunt import hunt
from hecate_agent.commands.investigate import investigate
from hecate_agent.commands.research import research
from hecate_agent.commands.similar import similar

# Optional: Splunk integration (requires requests package)
try:
    from hecate_agent.commands.splunk import splunk
except ImportError:
    splunk = None  # type: ignore[assignment]

__all__ = [
    "attack",
    "hunt",
    "investigate",
    "research",
    "context",
    "similar",
    "env",
    "splunk",
]
