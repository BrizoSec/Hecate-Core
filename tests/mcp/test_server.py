"""Tests for the Hecate MCP server creation and tool registration."""

import os
from unittest.mock import patch

import pytest

pytest.importorskip("mcp", reason="MCP optional dependency not installed")

from hecate_agent.mcp.utils import (  # noqa: E402 - must follow the importorskip guard above
    find_workspace,
    load_workspace_config,
)


class TestFindWorkspace:
    def test_explicit_path(self, tmp_path):
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        result = find_workspace(str(tmp_path))
        assert result == tmp_path

    def test_explicit_path_not_exists(self):
        with pytest.raises(FileNotFoundError, match="does not exist"):
            find_workspace("/nonexistent/path/12345")

    def test_env_var(self, tmp_path):
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        with patch.dict(os.environ, {"HECATE_WORKSPACE": str(tmp_path)}):
            result = find_workspace()
            assert result == tmp_path

    def test_explicit_path_no_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Not an Hecate workspace"):
            find_workspace(str(tmp_path))

    def test_walk_up_finds_config(self, tmp_path):
        config = tmp_path / ".hecateconfig.yaml"
        config.write_text("workspace_name: test\n")
        subdir = tmp_path / "hunts" / "2026"
        subdir.mkdir(parents=True)

        with patch("hecate_agent.mcp.utils.Path.cwd", return_value=subdir):
            result = find_workspace()
            assert result == tmp_path

    def test_walk_up_finds_config_in_config_dir(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / ".hecateconfig.yaml").write_text("workspace_name: test\n")

        with patch("hecate_agent.mcp.utils.Path.cwd", return_value=tmp_path):
            result = find_workspace()
            assert result == tmp_path

    def test_no_workspace_raises(self, tmp_path):
        with patch("hecate_agent.mcp.utils.Path.cwd", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="No Hecate workspace found"):
                find_workspace()


class TestLoadWorkspaceConfig:
    def test_loads_config(self, tmp_path):
        config = tmp_path / ".hecateconfig.yaml"
        config.write_text("workspace_name: test\nsiem: Splunk\n")
        result = load_workspace_config(tmp_path)
        assert result["workspace_name"] == "test"
        assert result["siem"] == "Splunk"

    def test_config_in_config_dir(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / ".hecateconfig.yaml").write_text("workspace_name: nested\n")
        result = load_workspace_config(tmp_path)
        assert result["workspace_name"] == "nested"

    def test_no_config(self, tmp_path):
        result = load_workspace_config(tmp_path)
        assert result == {}


class TestCreateServer:
    def test_creates_server_with_tools(self, tmp_path):
        # Create minimal workspace
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        (tmp_path / "hunts").mkdir()
        (tmp_path / "research").mkdir()
        (tmp_path / "investigations").mkdir()

        from hecate_agent.mcp.server import create_server

        server = create_server(str(tmp_path))
        assert server is not None

    def test_server_registers_all_tool_groups(self, tmp_path):
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        (tmp_path / "hunts").mkdir()
        (tmp_path / "research").mkdir()
        (tmp_path / "investigations").mkdir()

        from hecate_agent.mcp.server import create_server

        server = create_server(str(tmp_path))

        # Get registered tool names
        import asyncio

        async def get_tools():
            return await server.list_tools()

        tools = asyncio.run(get_tools())
        tool_names = [t.name for t in tools]

        # Verify key tools from each group are registered
        assert "hecate_hunt_list" in tool_names
        assert "hecate_hunt_search" in tool_names
        assert "hecate_hunt_new" in tool_names
        assert "hecate_similar" in tool_names
        assert "hecate_context" in tool_names
        assert "hecate_research_list" in tool_names
        assert "hecate_investigate_list" in tool_names
        assert "hecate_agent_run_hypothesis" in tool_names
        assert "hecate_agent_run_researcher" in tool_names


class TestPluginToolDiscovery:
    def test_discovers_plugin_mcp_tools(self, tmp_path):
        """Plugin entry points in hecate_agent.mcp_tools group get called with (mcp, workspace)."""
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        (tmp_path / "hunts").mkdir()
        (tmp_path / "research").mkdir()
        (tmp_path / "investigations").mkdir()

        call_log = []

        def fake_register(mcp, workspace):
            call_log.append({"mcp": mcp, "workspace": workspace})

        fake_ep = type("FakeEP", (), {"load": lambda self: fake_register, "name": "test-plugin"})()

        with patch("hecate_agent.mcp.server._discover_plugin_tools", return_value=[fake_ep]):
            from hecate_agent.mcp.server import create_server

            server = create_server(str(tmp_path))

        assert len(call_log) == 1
        assert call_log[0]["workspace"] == tmp_path
        assert call_log[0]["mcp"] is server

    def test_plugin_import_error_does_not_crash_server(self, tmp_path):
        """A broken plugin should log a warning, not crash the server."""
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        (tmp_path / "hunts").mkdir()
        (tmp_path / "research").mkdir()
        (tmp_path / "investigations").mkdir()

        def broken_register(mcp, workspace):
            raise ImportError("Missing dependency xyz")

        fake_ep = type("FakeEP", (), {"load": lambda self: broken_register, "name": "broken-plugin"})()

        with patch("hecate_agent.mcp.server._discover_plugin_tools", return_value=[fake_ep]):
            from hecate_agent.mcp.server import create_server

            server = create_server(str(tmp_path))

        assert server is not None

    def test_no_plugins_still_works(self, tmp_path):
        """Server works fine when no plugins define hecate_agent.mcp_tools."""
        (tmp_path / ".hecateconfig.yaml").write_text("workspace_name: test\n")
        (tmp_path / "hunts").mkdir()
        (tmp_path / "research").mkdir()
        (tmp_path / "investigations").mkdir()

        with patch("hecate_agent.mcp.server._discover_plugin_tools", return_value=[]):
            from hecate_agent.mcp.server import create_server

            server = create_server(str(tmp_path))

        import asyncio

        tools = asyncio.run(server.list_tools())
        tool_names = [t.name for t in tools]
        assert "hecate_hunt_list" in tool_names
