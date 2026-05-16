"""Investigation management MCP tools."""

import logging
from typing import Optional

from athf.mcp.server import get_workspace, _json_result

logger = logging.getLogger(__name__)


def register_investigate_tools(mcp: "FastMCP") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Register all investigation-related MCP tools."""

    @mcp.tool(
        name="athf_investigate_list",
        description="List investigations with optional type filter (finding, exploration, triage, validation).",
    )
    def investigate_list(
        investigation_type: Optional[str] = None,
    ) -> str:
        from athf.core.investigation_parser import parse_investigation_file

        workspace = get_workspace()
        inv_dir = workspace / "investigations"
        if not inv_dir.exists():
            return _json_result({"count": 0, "investigations": []})

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
            except Exception as e:
                logger.debug("Skipping %s: %s", f.name, e)
                continue

        return _json_result({"count": len(results), "investigations": results})

    @mcp.tool(
        name="athf_investigate_new",
        description="Create a new investigation file (I-XXXX). Returns the investigation ID and file path. Use type='finding' for detection review pivots.",
    )
    def investigate_new(
        title: str,
        investigation_type: str = "finding",
        tags: Optional[str] = None,
        data_sources: Optional[str] = None,
        related_hunts: Optional[str] = None,
        investigator: str = "Nova",
    ) -> str:
        import subprocess

        workspace = get_workspace()
        cmd = [
            "athf", "investigate", "new",
            "--title", title,
            "--type", investigation_type,
            "--investigator", investigator,
            "--non-interactive",
        ]
        if tags:
            cmd.extend(["--tags", tags])
        if data_sources:
            for ds in data_sources.split(","):
                cmd.extend(["--data-source", ds.strip()])
        if related_hunts:
            for hunt in related_hunts.split(","):
                cmd.extend(["--related-hunt", hunt.strip()])

        try:
            result = subprocess.run(
                cmd,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return _json_result({"error": result.stderr.strip() or "Investigation creation failed"})

            from athf.core.investigation_parser import get_all_investigations
            investigations = get_all_investigations(workspace / "investigations")
            if investigations:
                latest = sorted(investigations, key=lambda i: i.get("investigation_id", ""))[-1]
                return _json_result({
                    "status": "created",
                    "investigation_id": latest.get("investigation_id"),
                    "title": latest.get("title"),
                    "path": f"investigations/{latest.get('investigation_id')}.md",
                })
            return _json_result({"status": "created", "output": result.stdout.strip()})
        except subprocess.TimeoutExpired:
            return _json_result({"error": "Investigation creation timed out"})
        except Exception as e:
            return _json_result({"error": str(e)})

    @mcp.tool(
        name="athf_investigate_search",
        description="Full-text search across investigation files.",
    )
    def investigate_search(query: str) -> str:
        from athf.core.investigation_parser import parse_investigation_file

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
                    parsed = parse_investigation_file(f)
                    fm = parsed.get("frontmatter", {})
                    results.append({
                        "investigation_id": fm.get("investigation_id", f.stem),
                        "title": fm.get("title", ""),
                        "type": fm.get("type", ""),
                        "status": fm.get("status", ""),
                    })
            except Exception as e:
                logger.debug("Skipping %s: %s", f.name, e)
                continue

        return _json_result({"count": len(results), "results": results})
