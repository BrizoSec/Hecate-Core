"""Tests for offline mode handling in hecate-agent research new."""

from pathlib import Path
from click.testing import CliRunner

from hecate_agent.commands.research import research


def test_research_new_offline_mode_prompt(tmp_path: Path, monkeypatch):
    """When no LLM provider is configured, research new outputs the friendly prompt and creates the template."""
    monkeypatch.chdir(tmp_path)
    # Clear any provider env vars
    monkeypatch.setenv("HECATE_LLM_PROVIDER", "none")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    runner = CliRunner()
    result = runner.invoke(research, ["new", "--topic", "Pass-the-Hash", "--technique", "T1003.002"])

    assert result.exit_code == 0
    normalized_output = " ".join(result.output.split())
    assert (
        "AI features are not configured; you can manually fill in the research template at research/R-0001.md"
        in normalized_output
    )

    # Check template file was created
    research_file = tmp_path / "research" / "R-0001.md"
    assert research_file.exists()
    content = research_file.read_text()
    assert "topic: Pass-the-Hash" in content
    assert "T1003.002" in content
    assert "## 1. System Research: How It Works" in content
    assert "## 2. Adversary Tradecraft: Abuse Techniques" in content
    assert "## 3. Telemetry Mapping" in content
    assert "## 4. Related Work" in content
    assert "## 5. Research Synthesis: Actionable Insights" in content
