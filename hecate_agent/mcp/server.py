"""Hecate MCP Server — expose threat hunting operations as MCP tools.

Usage:
    hecate-agent mcp serve                    # auto-detect workspace
    hecate-agent mcp serve --workspace /path  # explicit workspace
    hecate-agent-mcp                          # standalone entry point
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Global workspace path — set during server startup
_workspace: Optional[Path] = None


def get_workspace() -> Path:
    """Return the current workspace path."""
    if _workspace is None:
        raise RuntimeError("Hecate MCP server not initialized. Call create_server() first.")
    return _workspace


def _json_result(data: Any) -> str:
    """Serialize a result to JSON string for MCP tool output."""
    return json.dumps(data, indent=2, default=str)


def _discover_plugin_tools() -> list:
    """Discover MCP tool registration functions from installed plugins."""
    if sys.version_info >= (3, 10):
        from importlib.metadata import entry_points

        return list(entry_points(group="hecate_agent.mcp_tools"))
    else:
        from importlib.metadata import entry_points

        return list(entry_points().get("hecate_agent.mcp_tools", []))


def create_server(workspace_path: Optional[str] = None) -> "FastMCP":  # type: ignore[name-defined]  # noqa: F821
    """Create and configure the Hecate MCP server.

    Args:
        workspace_path: Explicit workspace path (optional).

    Returns:
        Configured FastMCP server instance.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise ImportError("MCP dependencies not installed. Install with: pip install 'hecate-agent[mcp]'") from None

    from hecate_agent.mcp.utils import find_workspace, load_workspace_config

    global _workspace
    _workspace = find_workspace(workspace_path)
    load_workspace_config(_workspace)

    mcp = FastMCP(
        name="hecate",
        instructions=(
            "Hecate (Agentic Threat Hunting Framework) server. "
            "Provides threat hunting operations: search hunts, check ATT&CK coverage, "
            "find similar hunts, create new hunts, run AI-powered research, and more. "
            f"Workspace: {_workspace}"
        ),
    )

    # Register all tool modules
    from hecate_agent.mcp.tools.agent_tools import register_agent_tools
    from hecate_agent.mcp.tools.attack_tools import register_attack_tools
    from hecate_agent.mcp.tools.hunt_tools import register_hunt_tools
    from hecate_agent.mcp.tools.investigate_tools import register_investigate_tools
    from hecate_agent.mcp.tools.research_tools import register_research_tools
    from hecate_agent.mcp.tools.search_tools import register_search_tools

    register_hunt_tools(mcp)
    register_search_tools(mcp)
    register_research_tools(mcp)
    register_investigate_tools(mcp)
    register_agent_tools(mcp)
    register_attack_tools(mcp)

    for ep in _discover_plugin_tools():
        try:
            register_fn = ep.load()
            register_fn(mcp, _workspace)
            logger.info("Loaded MCP tools from plugin: %s", ep.name)
        except Exception:
            logger.warning("Failed to load MCP tools from plugin: %s", ep.name, exc_info=True)

    logger.info("Hecate MCP server initialized with workspace: %s", _workspace)
    return mcp


def reset_server() -> None:
    """Reset global server state (for testing)."""
    global _workspace
    _workspace = None


def main(workspace_path: Optional[str] = None, transport: str = "stdio", port: int = 3100) -> None:
    """Entry point for running the MCP server."""
    server = create_server(workspace_path)
    if transport in ("sse", "streamable-http"):
        server.settings.host = "0.0.0.0"
        server.settings.port = port
    server.run(transport=transport)


def cli() -> None:
    """CLI entry point for hecate-agent-mcp standalone command."""
    import argparse

    parser = argparse.ArgumentParser(description="Hecate MCP Server")
    parser.add_argument("--workspace", default=None, help="Workspace path")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"])
    parser.add_argument("--port", type=int, default=3100, help="HTTP port for SSE/HTTP transport")
    args = parser.parse_args()
    main(workspace_path=args.workspace, transport=args.transport, port=args.port)
