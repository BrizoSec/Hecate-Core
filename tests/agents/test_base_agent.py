"""Tests for BaseAgent JSON parsing and resilience."""

import pytest
from hecate_agent.agents.base import LLMAgent


class DummyLLMAgent(LLMAgent[str, str]):
    def execute(self, input_data: str) -> str:
        return input_data


def test_parse_json_valid_and_markdown():
    agent = DummyLLMAgent()
    # Standard JSON
    assert agent._parse_json_response('{"key": "value"}') == {"key": "value"}

    # Markdown block
    assert agent._parse_json_response('```json\n{"key": "value"}\n```') == {"key": "value"}

    # Chatty preamble
    chatty = 'Sure! Here is the JSON you requested:\n{"key": "value"}\nHope this helps!'
    assert agent._parse_json_response(chatty) == {"key": "value"}


def test_parse_json_repairs_windows_paths_and_unc_shares():
    agent = DummyLLMAgent()
    # Raw Windows path with invalid escape \P and \U
    payload = r'{"path": "C:\Program Files\evil.exe", "description": "drops to C:\Users\Admin"}'
    parsed = agent._parse_json_response(payload)
    assert parsed["path"] == r"C:\Program Files\evil.exe"
    assert parsed["description"] == r"drops to C:\Users\Admin"

    # UNC share from Hunt 2
    unc_payload = r'{"unc": "\\145.249.109.147@80\webdav", "action": "connect"}'
    parsed_unc = agent._parse_json_response(unc_payload)
    assert parsed_unc["unc"] == r"\145.249.109.147@80\webdav"
    assert parsed_unc["action"] == "connect"


def test_parse_json_preserves_valid_escapes():
    agent = DummyLLMAgent()
    payload = r'{"newline": "line1\nline2", "tab": "col1\tcol2", "quote": "hello \"world\""}'
    parsed = agent._parse_json_response(payload)
    assert parsed["newline"] == "line1\nline2"
    assert parsed["tab"] == "col1\tcol2"
    assert parsed["quote"] == 'hello "world"'


def test_parse_json_raises_on_invalid():
    agent = DummyLLMAgent()
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        agent._parse_json_response("This has no json at all.")
