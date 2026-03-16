"""Investigation management MCP tools."""

from typing import Optional

from mcp.server.fastmcp import FastMCP

from athf.mcp.server import get_workspace, _json_result


def register_investigate_tools(mcp: FastMCP) -> None:
    """Register all investigation-related MCP tools."""

    @mcp.tool(
        name="athf_investigate_list",
        description="List investigations with optional type filter (finding, exploration, triage, validation).",
    )
    def investigate_list(
        investigation_type: Optional[str] = None,
    ) -> str:
        workspace = get_workspace()
        inv_dir = workspace / "investigations"
        if not inv_dir.exists():
            return _json_result({"count": 0, "investigations": []})

        from athf.core.investigation_parser import parse_investigation_file

        results = []
        for f in sorted(inv_dir.rglob("*.md")):
            if f.name in {"README.md", "AGENTS.md"}:
                continue
            try:
                parsed = parse_investigation_file(f)
                fm = parsed.get("frontmatter", {})
                if investigation_type and fm.get("type", "").lower() != investigation_type.lower():
                    continue
                results.append({
                    "investigation_id": fm.get("investigation_id", f.stem),
                    "title": fm.get("title", ""),
                    "type": fm.get("type", ""),
                    "status": fm.get("status", ""),
                    "tags": fm.get("tags", []),
                })
            except Exception:
                continue

        return _json_result({"count": len(results), "investigations": results})

    @mcp.tool(
        name="athf_investigate_search",
        description="Full-text search across investigation files.",
    )
    def investigate_search(query: str) -> str:
        workspace = get_workspace()
        inv_dir = workspace / "investigations"
        if not inv_dir.exists():
            return _json_result({"count": 0, "results": []})

        query_lower = query.lower()
        results = []
        for f in sorted(inv_dir.rglob("*.md")):
            if f.name in {"README.md", "AGENTS.md"}:
                continue
            try:
                content = f.read_text(encoding="utf-8")
                if query_lower in content.lower():
                    from athf.core.investigation_parser import parse_investigation_file

                    parsed = parse_investigation_file(f)
                    fm = parsed.get("frontmatter", {})
                    results.append({
                        "investigation_id": fm.get("investigation_id", f.stem),
                        "title": fm.get("title", ""),
                        "type": fm.get("type", ""),
                        "status": fm.get("status", ""),
                    })
            except Exception:
                continue

        return _json_result({"count": len(results), "results": results})
