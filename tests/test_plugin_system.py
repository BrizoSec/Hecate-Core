"""Tests for the ATHF plugin system."""

import pytest
from click import Command

from athf.plugin_system import PluginRegistry


@pytest.fixture(autouse=True)
def _clean_registry():
    """Restore PluginRegistry state after each test."""
    original_agents = dict(PluginRegistry._agents)
    original_commands = dict(PluginRegistry._commands)
    yield
    PluginRegistry._agents = original_agents
    PluginRegistry._commands = original_commands


class TestPluginRegistryAgents:
    """Tests for agent registration and retrieval."""

    def test_register_and_get_agent(self):
        class FakeAgent:
            pass

        PluginRegistry.register_agent("fake-agent", FakeAgent)

        assert PluginRegistry.get_agent("fake-agent") is FakeAgent

    def test_get_unregistered_agent_returns_none(self):
        assert PluginRegistry.get_agent("nonexistent") is None

    def test_register_agent_overwrites_existing(self):
        class AgentV1:
            pass

        class AgentV2:
            pass

        PluginRegistry.register_agent("my-agent", AgentV1)
        PluginRegistry.register_agent("my-agent", AgentV2)

        assert PluginRegistry.get_agent("my-agent") is AgentV2

    def test_multiple_agents_independent(self):
        class A:
            pass

        class B:
            pass

        PluginRegistry.register_agent("agent-a", A)
        PluginRegistry.register_agent("agent-b", B)

        assert PluginRegistry.get_agent("agent-a") is A
        assert PluginRegistry.get_agent("agent-b") is B


class TestPluginRegistryCommands:
    """Tests for command registration and retrieval."""

    def test_register_and_get_command(self):
        cmd = Command("test-cmd", callback=lambda: None)
        PluginRegistry.register_command("test-cmd", cmd)

        assert PluginRegistry.get_command("test-cmd") is cmd

    def test_get_unregistered_command_returns_none(self):
        assert PluginRegistry.get_command("nonexistent") is None

    def test_register_command_overwrites_existing(self):
        cmd1 = Command("cmd", callback=lambda: None)
        cmd2 = Command("cmd", callback=lambda: None)

        PluginRegistry.register_command("my-cmd", cmd1)
        PluginRegistry.register_command("my-cmd", cmd2)

        assert PluginRegistry.get_command("my-cmd") is cmd2


class TestLoadPlugins:
    """Tests for load_plugins() auto-discovery."""

    def test_load_plugins_does_not_raise_when_no_plugins_installed(self):
        """load_plugins() must silently succeed with no entry points."""
        PluginRegistry.load_plugins()

    def test_load_plugins_can_be_called_multiple_times(self):
        PluginRegistry.load_plugins()
        PluginRegistry.load_plugins()
