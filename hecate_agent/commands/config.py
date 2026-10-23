"""Configuration commands for Hecate."""

import os
from pathlib import Path
from typing import Dict, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

ENV_FILE_NAME = ".env"


def _read_env_file(env_path: Path) -> Dict[str, str]:
    """Parse existing .env file into key-value pairs while preserving order."""
    env_vars: Dict[str, str] = {}
    if not env_path.exists():
        return env_vars

    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                env_vars[key.strip()] = val.strip().strip("'\"")
    return env_vars


def _write_env_file(env_path: Path, updates: Dict[str, Optional[str]]) -> None:
    """Update or append keys to an existing .env file, preserving other lines and comments."""
    existing_lines = []
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            existing_lines = f.readlines()

    keys_written = set()
    new_lines = []

    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _ = stripped.split("=", 1)
            key = key.strip()
            if key in updates:
                new_val = updates[key]
                if new_val is not None:
                    new_lines.append(f"{key}={new_val}\n")
                keys_written.add(key)
                continue
        new_lines.append(line)

    # Append any remaining updates not present in existing file
    for key, val in updates.items():
        if key not in keys_written and val is not None:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{key}={val}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


@click.group(name="config")
def config() -> None:
    """Manage Hecate configuration (AI providers, integrations, and workspace settings)."""
    pass


@config.command(name="show")
def config_show() -> None:
    """Show current AI and search configuration."""
    from hecate_agent.core.llm_provider import _load_config_file, _ollama_is_running

    env_provider = os.environ.get("HECATE_LLM_PROVIDER")
    env_model = os.environ.get("HECATE_LLM_MODEL")
    file_cfg = _load_config_file()

    active_provider = env_provider or file_cfg.get("provider") or "(auto-detect)"
    active_model = env_model or file_cfg.get("model") or "(default for provider)"

    openai_key_set = bool(os.environ.get("OPENAI_API_KEY"))
    anthropic_key_set = bool(os.environ.get("ANTHROPIC_API_KEY"))
    tavily_key_set = bool(os.environ.get("TAVILY_API_KEY"))
    ollama_running = _ollama_is_running()

    table = Table(title="Hecate AI Configuration Status")
    table.add_column("Component", style="cyan")
    table.add_column("Setting / Status", style="green")
    table.add_column("Source", style="dim")

    table.add_row("Configured Provider", active_provider, "HECATE_LLM_PROVIDER / config" if env_provider else "config / auto")
    table.add_row("Configured Model", active_model, "HECATE_LLM_MODEL" if env_model else "default")
    table.add_row("OpenAI API Key", "✓ Set" if openai_key_set else "✗ Not set", "OPENAI_API_KEY")
    table.add_row("Anthropic API Key", "✓ Set" if anthropic_key_set else "✗ Not set", "ANTHROPIC_API_KEY")
    table.add_row("Local Ollama Server", "✓ Reachable" if ollama_running else "✗ Not reachable", "http://localhost:11434")
    table.add_row("Tavily Search Key", "✓ Set" if tavily_key_set else "✗ Not set (offline search)", "TAVILY_API_KEY")

    console.print()
    console.print(table)
    console.print()


@config.command(name="ai")
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["openai", "anthropic", "ollama", "litellm", "none"], case_sensitive=False),
    help="AI provider to configure.",
)
@click.option("--model", "-m", help="Model name (e.g., gpt-4o, claude-3-5-sonnet-20241022, llama3).")
@click.option("--api-key", "-k", help="API key for cloud provider.")
@click.option("--base-url", help="Base URL for local or custom endpoint (default: http://localhost:11434 for Ollama).")
@click.option("--search-key", help="Tavily API key for web search grounding.")
@click.option("--non-interactive", is_flag=True, help="Run without interactive prompts.")
def config_ai(
    provider: Optional[str],
    model: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str],
    search_key: Optional[str],
    non_interactive: bool,
) -> None:
    """Interactive wizard to configure AI providers (OpenAI / Anthropic / local Ollama).

    \\b
    Guides you through selecting a provider, model, API keys, and persistence.
    If you do not have AI configured, hunt records, LOCK documentation, stats,
    and CLI validation still work fully without AI!

    \\b
    Examples:
      # Interactive wizard
      hecate-agent config ai

      # Non-interactive configuration for Ollama
      hecate-agent config ai --provider ollama --model llama3 --non-interactive

      # Non-interactive configuration for OpenAI
      hecate-agent config ai --provider openai --model gpt-4o --api-key sk-... --non-interactive
    """
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]🧠 Hecate AI Configuration Wizard[/bold cyan]\n"
            "[dim]Configure LLM and search providers for automated research and hypothesis generation.[/dim]",
            border_style="cyan",
        )
    )

    selected_provider = provider.lower() if provider else None
    selected_model = model
    selected_api_key = api_key
    selected_base_url = base_url
    selected_search_key = search_key

    if not non_interactive and not selected_provider:
        console.print("[bold]Select an AI provider:[/bold]")
        console.print("  [cyan]1[/cyan]) OpenAI        (GPT-4o, GPT-4o-mini - requires API key)")
        console.print("  [cyan]2[/cyan]) Anthropic     (Claude 3.5 Sonnet, Claude 3 Haiku - requires API key)")
        console.print("  [cyan]3[/cyan]) Local Ollama   (100% offline & free - runs on your machine)")
        console.print("  [cyan]4[/cyan]) LiteLLM        (Multi-provider proxy / custom endpoints)")
        console.print("  [cyan]5[/cyan]) None / Offline (Disable AI; hunt records & LOCK still work)")
        console.print()

        choice = Prompt.ask("Choose provider", choices=["1", "2", "3", "4", "5"], default="3")
        provider_map = {
            "1": "openai",
            "2": "anthropic",
            "3": "ollama",
            "4": "litellm",
            "5": "none",
        }
        selected_provider = provider_map[choice]

    updates: Dict[str, Optional[str]] = {}

    if selected_provider == "none":
        console.print("\n[yellow]ℹ AI features will be disabled.[/yellow]")
        console.print("[dim]Note: Hunt records, LOCK documentation, search, and CLI validation[/dim]")
        console.print("[dim]continue to work fully. AI research and hypothesis generation will be skipped.[/dim]\n")
        updates["HECATE_LLM_PROVIDER"] = "none"
        updates["HECATE_LLM_MODEL"] = ""
    elif selected_provider == "ollama":
        if not selected_base_url and not non_interactive:
            selected_base_url = Prompt.ask("Ollama Base URL", default="http://localhost:11434")
        if not selected_model and not non_interactive:
            selected_model = Prompt.ask("Ollama Model Name", default="llama3")

        updates["HECATE_LLM_PROVIDER"] = "ollama"
        updates["HECATE_LLM_MODEL"] = selected_model or "llama3"
        updates["OLLAMA_HOST"] = selected_base_url or "http://localhost:11434"

        # Check reachability
        from hecate_agent.core.llm_provider import _ollama_is_running

        host = updates.get("OLLAMA_HOST") or "http://localhost:11434"
        if _ollama_is_running(host):
            console.print(f"[green]✓ Successfully connected to Ollama at {host}[/green]")
        else:
            console.print(
                f"[yellow]⚠ Warning: Ollama not reachable at {host}. Ensure it is running with 'ollama serve'.[/yellow]"
            )
    elif selected_provider == "openai":
        if not selected_api_key and not non_interactive:
            selected_api_key = Prompt.ask("OpenAI API Key (sk-...)", password=True)
        if not selected_model and not non_interactive:
            selected_model = Prompt.ask("Model Name", default="gpt-4o")

        updates["HECATE_LLM_PROVIDER"] = "openai"
        updates["HECATE_LLM_MODEL"] = selected_model or "gpt-4o"
        if selected_api_key:
            updates["OPENAI_API_KEY"] = selected_api_key
    elif selected_provider == "anthropic":
        if not selected_api_key and not non_interactive:
            selected_api_key = Prompt.ask("Anthropic API Key (sk-ant-...)", password=True)
        if not selected_model and not non_interactive:
            selected_model = Prompt.ask("Model Name", default="claude-3-5-sonnet-20241022")

        updates["HECATE_LLM_PROVIDER"] = "anthropic"
        updates["HECATE_LLM_MODEL"] = selected_model or "claude-3-5-sonnet-20241022"
        if selected_api_key:
            updates["ANTHROPIC_API_KEY"] = selected_api_key
    elif selected_provider == "litellm":
        if not selected_model and not non_interactive:
            selected_model = Prompt.ask("LiteLLM Model (e.g. gpt-4o, anthropic/claude-3-5-sonnet)", default="gpt-4o")
        updates["HECATE_LLM_PROVIDER"] = "litellm"
        updates["HECATE_LLM_MODEL"] = selected_model or "gpt-4o"
        if selected_api_key:
            updates["LITELLM_API_KEY"] = selected_api_key

    # Web search prompt (optional)
    if selected_provider != "none" and not non_interactive and not selected_search_key:
        if Confirm.ask("Would you like to configure Tavily API Key for grounded web research?", default=False):
            selected_search_key = Prompt.ask("Tavily API Key (tvly-...)", password=True)

    if selected_search_key:
        updates["TAVILY_API_KEY"] = selected_search_key

    # Persist to .env
    env_path = Path.cwd() / ENV_FILE_NAME
    _write_env_file(env_path, updates)

    console.print()
    console.print(f"[bold green]✓ Configuration successfully persisted to {env_path.name}[/bold green]")
    if selected_provider != "none":
        console.print(f"  Provider: [cyan]{updates.get('HECATE_LLM_PROVIDER')}[/cyan]")
        console.print(f"  Model:    [cyan]{updates.get('HECATE_LLM_MODEL')}[/cyan]")
        console.print()
        console.print("[bold]Next Steps:[/bold]")
        console.print("  • Try AI research: [cyan]hecate-agent research new --topic 'Pass-the-Hash'[/cyan]")
        console.print("  • View AI status:  [cyan]hecate-agent config show[/cyan]")
    else:
        console.print("[dim]You can re-run 'hecate-agent config ai' at any time to enable AI providers.[/dim]")
    console.print()
