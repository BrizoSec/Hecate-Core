"""Tests for investigate MCP tools, in particular the investigate_new race fix."""

import json
import subprocess
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp", reason="MCP optional dependency not installed")

from athf.mcp.server import create_server


def _setup_workspace(tmp_path):
    (tmp_path / ".athfconfig.yaml").write_text("workspace_name: test\n")
    (tmp_path / "investigations").mkdir()
    return tmp_path


@pytest.fixture
def workspace(tmp_path):
    return _setup_workspace(tmp_path)


@pytest.fixture
def server(workspace):
    return create_server(str(workspace))


def _call_tool(server, tool_name, arguments=None):
    import asyncio

    async def _run():
        result = await server.call_tool(tool_name, arguments or {})
        content_list = result[0] if isinstance(result, tuple) else result
        text = content_list[0].text if content_list else ""
        return json.loads(text)

    return asyncio.run(_run())


def _mock_subprocess_run(stdout: str, returncode: int = 0):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = ""
    return result


class TestInvestigateNew:
    def test_parses_investigation_id_from_cli_stdout(self, server, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: _mock_subprocess_run("\n✅ Created I-0042: Suspicious login pattern\n"),
        )

        result = _call_tool(server, "athf_investigate_new", {"title": "Suspicious login pattern"})

        assert result["status"] == "created"
        assert result["investigation_id"] == "I-0042"
        assert result["title"] == "Suspicious login pattern"
        assert result["path"] == "investigations/I-0042.md"

    def test_does_not_return_a_different_concurrently_created_investigation(self, server, workspace, monkeypatch):
        """Regression test: the old implementation ignored the CLI's own
        stdout and instead re-scanned the investigations/ directory
        afterward, returning whichever investigation_id sorted last. Under a
        concurrent investigate_new call finishing in between our subprocess
        exiting and that re-scan running, it could return a DIFFERENT
        caller's investigation as if it were our own. Simulated here by
        having a higher-sorting investigation already on disk (as if another
        call just created it) before our own (lower-ID) subprocess call
        "completes"."""
        # A "concurrent" call already produced a higher-sorting ID on disk.
        (workspace / "investigations" / "I-9999.md").write_text(
            "---\ninvestigation_id: I-9999\ntitle: Unrelated concurrent investigation\n---\n"
        )

        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: _mock_subprocess_run("\n✅ Created I-0042: Our own investigation\n"),
        )

        result = _call_tool(server, "athf_investigate_new", {"title": "Our own investigation"})

        assert result["investigation_id"] == "I-0042"
        assert result["investigation_id"] != "I-9999"

    def test_returns_error_on_nonzero_exit(self, server, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: _mock_subprocess_run("", returncode=1),
        )

        result = _call_tool(server, "athf_investigate_new", {"title": "Bad"})

        assert "error" in result

    def test_falls_back_to_raw_output_when_stdout_unparseable(self, server, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: _mock_subprocess_run("some unexpected output format"),
        )

        result = _call_tool(server, "athf_investigate_new", {"title": "Odd"})

        assert result["status"] == "created"
        assert "investigation_id" not in result
        assert result["output"] == "some unexpected output format"
