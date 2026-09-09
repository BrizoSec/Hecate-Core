"""MCP server CLI command."""

import click


@click.group()
def mcp() -> None:
    """MCP server for AI assistant integration."""


@mcp.command()
@click.option("--workspace", default=None, help="Explicit workspace path (auto-detected if not set)")
@click.option(
    "--transport", default="stdio", type=click.Choice(["stdio", "sse", "streamable-http"]), help="Transport protocol"
)
@click.option("--port", default=3100, type=int, help="HTTP port for SSE transport")
def serve(workspace: str, transport: str, port: int) -> None:
    """Start the Hecate MCP server.

    This exposes Hecate operations as MCP tools that AI assistants
    (Claude Code, Copilot, Cursor, etc.) can call directly.

    \b
    Stdio (default, for Claude Code):
      hecate-agent mcp serve --workspace /path/to/hunts

    \b
    HTTP (for web UI integration):
      hecate-agent mcp serve --transport streamable-http --port 3100

    \b
    Configuration for Claude Code (~/.claude/mcp-servers.json):
      {
        "hecate": {
          "command": "hecate-agent-mcp",
          "args": ["--workspace", "/path/to/hunts"]
        }
      }
    """
    try:
        from hecate_agent.mcp.server import main as mcp_main
    except ImportError:
        click.echo("Error: MCP dependencies not installed. Install with: pip install 'hecate-agent[mcp]'", err=True)
        raise SystemExit(1) from None

    mcp_main(workspace_path=workspace, transport=transport, port=port)
