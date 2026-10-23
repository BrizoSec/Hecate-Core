"""Maturity model assessment commands."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_agent.core.hunt_manager import HuntManager
from hecate_agent.core.llm_provider import _load_config_file, _ollama_is_running

console = Console()

LEVEL_NAMES = {
    0: "Level 0: Ad-hoc",
    1: "Level 1: Documented",
    2: "Level 2: Searchable",
    3: "Level 3: Generative",
    4: "Level 4: Agentic",
}

LEVEL_DESCRIPTIONS = {
    0: "Hunts exist in tickets, chats, or notes without standardized persistent documentation.",
    1: "Persistent hunt records documented using the LOCK pattern (Learn, Observe, Check, Keep).",
    2: "Structured YAML frontmatter and context files enable fast search and AI recall.",
    3: "AI assistants and MCP tools actively execute queries, conduct research, and enrich findings.",
    4: "Autonomous agents monitor threat feeds, draft hypotheses, and coordinate through shared memory.",
}


def assess_workspace_maturity(workspace_path: Optional[Path] = None) -> Dict[str, Any]:
    """Assess the maturity level of a workspace against Hecate's 5-level maturity model.

    Args:
        workspace_path: Root directory of the workspace (default: current working directory)

    Returns:
        Dict containing assessment scores, metrics, level, and concrete recommendations.
    """
    root = workspace_path or Path.cwd()
    hunts_dir = root / "hunts"
    research_dir = root / "research"
    queries_dir = root / "queries"
    agents_md = root / "AGENTS.md"
    knowledge_dir = root / "knowledge"
    mcp_config = root / ".mcp.json"

    # 1. Inspect Hunt files
    manager = HuntManager(hunts_dir=hunts_dir if hunts_dir.exists() else None)
    hunt_files = manager.find_all_hunt_files() if hunts_dir.exists() else []

    total_hunts = len(hunt_files)
    hunts_with_lock = 0
    hunts_with_frontmatter = 0
    hunts_missing_frontmatter = []

    for hf in hunt_files:
        try:
            content = hf.read_text(encoding="utf-8")
        except Exception:
            continue

        has_frontmatter = content.startswith("---") and "\n---" in content[3:]
        if has_frontmatter:
            hunts_with_frontmatter += 1
        else:
            hunts_missing_frontmatter.append(hf.name)

        lower_content = content.lower()
        has_learn = "learn" in lower_content or "# learn" in lower_content or "**learn**" in lower_content
        has_observe = "observe" in lower_content or "# observe" in lower_content or "**observe**" in lower_content
        has_check = "check" in lower_content or "# check" in lower_content or "**check**" in lower_content
        has_keep = "keep" in lower_content or "# keep" in lower_content or "**keep**" in lower_content

        if (has_learn and has_observe) or (has_check and has_keep) or (has_observe and has_check):
            hunts_with_lock += 1

    # 2. Inspect Context & Memory files
    has_agents_md = agents_md.exists()
    has_knowledge = knowledge_dir.exists() and any(knowledge_dir.glob("*.md"))

    # 3. Inspect AI & Tool configuration
    env_provider = os.environ.get("HECATE_LLM_PROVIDER")
    file_cfg = _load_config_file()
    active_provider = env_provider or file_cfg.get("provider")
    has_ai_key = bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))
    has_ollama = _ollama_is_running()
    ai_configured = bool(
        (active_provider and active_provider.lower() not in ("none", "disabled"))
        or has_ai_key
        or (active_provider == "ollama" and has_ollama)
    )

    has_mcp = mcp_config.exists()
    has_research_docs = research_dir.exists() and any(research_dir.glob("R-*.md"))
    has_query_files = queries_dir.exists() and any(queries_dir.glob("*.*"))

    # 4. Inspect Autonomous Pipeline / Level 4 indicators
    has_checkpoints = (root / "hecate_checkpoints.sqlite").exists()
    has_cti_queue = (root / "cti_queue").exists() and any((root / "cti_queue").glob("*.*"))
    has_runner_logs = (root / "logs").exists() and any((root / "logs").glob("*runner*.log"))
    has_agentic_pipeline = has_checkpoints or has_cti_queue or has_runner_logs

    # Compute Maturity Level
    recommendations: List[str] = []

    if total_hunts == 0:
        level = 0
        recommendations.append("Run 'hecate-agent demo init' to seed a complete example hunt (LSASS Credential Dumping).")
        recommendations.append("Or run 'hecate-agent hunt new' to create your first documented threat hunt.")
    elif hunts_with_lock < total_hunts or hunts_with_frontmatter < total_hunts or not (has_agents_md or has_knowledge):
        if hunts_with_lock == 0:
            level = 0
            recommendations.append("Adopt the LOCK pattern (Learn → Observe → Check → Keep) in your hunt documents.")
        else:
            level = 1
            if hunts_missing_frontmatter:
                count = len(hunts_missing_frontmatter)
                sample = ", ".join(hunts_missing_frontmatter[:3])
                suffix = "..." if count > 3 else ""
                recommendations.append(f"Add YAML frontmatter to {count} hunts ({sample}{suffix}) to reach Level 2.")
            if not has_agents_md:
                recommendations.append("Add an AGENTS.md file to define environment context, indexes, and EDR data sources.")
            if not has_knowledge:
                recommendations.append("Add domain hunting knowledge to knowledge/hunting-knowledge.md for AI assistance.")
    else:
        # We meet Level 2 criteria (structured hunts + context files)
        if not (ai_configured or has_mcp or has_research_docs):
            level = 2
            recommendations.append(
                "Configure an AI provider using 'hecate-agent config ai' (OpenAI / Anthropic / local Ollama)."
            )
            recommendations.append(
                "Start pre-hunt research with 'hecate-agent research new --topic <topic>' to reach Level 3."
            )
            recommendations.append("Connect MCP tool integrations or SIEM queries in queries/.")
        elif not has_agentic_pipeline:
            level = 3
            recommendations.append("Deploy Hecate-Runner to automatically monitor CTI feeds and draft hunts overnight.")
            recommendations.append("Use 'hecate-agent monitor' to observe automated hunt cycles in real time.")
            recommendations.append(
                "Promote validated hunts to detection rules via 'hecate-agent hunt promote --output sigma'."
            )
        else:
            level = 4
            recommendations.append(
                "Workspace operating at Level 4 (Agentic)! Continue monitoring cycles with 'hecate-agent monitor'."
            )
            recommendations.append("Review drafted hunts from CTI queue and promote validated logic to Sigma rules.")

    return {
        "level": level,
        "level_name": LEVEL_NAMES[level],
        "level_description": LEVEL_DESCRIPTIONS[level],
        "metrics": {
            "total_hunts": total_hunts,
            "hunts_with_lock": hunts_with_lock,
            "hunts_with_frontmatter": hunts_with_frontmatter,
            "hunts_missing_frontmatter_count": len(hunts_missing_frontmatter),
            "has_agents_md": has_agents_md,
            "has_knowledge": has_knowledge,
            "ai_configured": ai_configured,
            "active_provider": active_provider or "none",
            "has_mcp": has_mcp,
            "has_research_docs": has_research_docs,
            "has_query_files": has_query_files,
            "has_agentic_pipeline": has_agentic_pipeline,
        },
        "recommendations": recommendations,
    }


@click.group(name="maturity")
def maturity() -> None:
    """Assess and advance your threat hunting program maturity."""
    pass


@maturity.command(name="assess")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format: table (default) or json.",
)
@click.option(
    "--path",
    "target_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory to assess (default: current directory).",
)
def maturity_assess(output_format: str, target_dir: Optional[Path]) -> None:
    """Assess workspace maturity level against the 5-level agentic hunting model.

    \\b
    Evaluates:
      • Level 0 (Ad-hoc)    - Unstructured hunts
      • Level 1 (Documented)- Persistent LOCK hunt records
      • Level 2 (Searchable)- YAML frontmatter + AGENTS.md / knowledge context
      • Level 3 (Generative)- AI provider / MCP tool execution / research documents
      • Level 4 (Agentic)   - Autonomous pipelines / CTI ingestion / runner state

    \\b
    Examples:
      # Interactive assessment report
      hecate-agent maturity assess

      # Programmatic JSON output for CI / reporting
      hecate-agent maturity assess --format json
    """
    assessment = assess_workspace_maturity(target_dir)

    if output_format.lower() == "json":
        click.echo(json.dumps(assessment, indent=2))
        return

    level = assessment["level"]
    metrics = assessment["metrics"]
    recs = assessment["recommendations"]

    color_map = {
        0: "red",
        1: "yellow",
        2: "cyan",
        3: "blue",
        4: "green",
    }
    lvl_color = color_map.get(level, "green")

    console.print()
    console.print(
        Panel.fit(
            f"[bold {lvl_color}]🏆 Current Maturity: {assessment['level_name']}[/bold {lvl_color}]\n"
            f"[dim]{assessment['level_description']}[/dim]",
            border_style=lvl_color,
        )
    )

    table = Table(title="Maturity Criteria Assessment")
    table.add_column("Capability Dimension", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    # Row 1: Documentation (Level 1)
    lock_ok = metrics["total_hunts"] > 0 and metrics["hunts_with_lock"] == metrics["total_hunts"]
    table.add_row(
        "LOCK Hunt Records (L1)",
        (
            "[green]✓ Met[/green]"
            if lock_ok
            else ("[yellow]Partially[/yellow]" if metrics["total_hunts"] > 0 else "[red]✗ Missing[/red]")
        ),
        f"{metrics['hunts_with_lock']}/{metrics['total_hunts']} hunts have LOCK sections",
    )

    # Row 2: Searchability (Level 2)
    fm_ok = metrics["total_hunts"] > 0 and metrics["hunts_with_frontmatter"] == metrics["total_hunts"]
    table.add_row(
        "YAML Frontmatter (L2)",
        "[green]✓ Met[/green]" if fm_ok else "[yellow]Incomplete[/yellow]",
        f"{metrics['hunts_with_frontmatter']}/{metrics['total_hunts']} hunts have frontmatter",
    )

    # Row 3: Context Files (Level 2)
    ctx_ok = metrics["has_agents_md"] and metrics["has_knowledge"]
    ctx_status = (
        "[green]✓ Met[/green]"
        if ctx_ok
        else ("[yellow]Partial[/yellow]" if (metrics["has_agents_md"] or metrics["has_knowledge"]) else "[red]✗ Missing[/red]")
    )
    table.add_row(
        "Context Files (L2)",
        ctx_status,
        f"AGENTS.md: {'✓' if metrics['has_agents_md'] else '✗'}, knowledge/: {'✓' if metrics['has_knowledge'] else '✗'}",
    )

    # Row 4: AI & Execution (Level 3)
    ai_status = "[green]✓ Met[/green]" if metrics["ai_configured"] else "[dim]Not configured[/dim]"
    table.add_row(
        "AI / Tool Execution (L3)",
        ai_status,
        f"Provider: {metrics['active_provider']}, Research docs: {'✓' if metrics['has_research_docs'] else '✗'}",
    )

    # Row 5: Agentic Pipelines (Level 4)
    agentic_status = "[green]✓ Met[/green]" if metrics["has_agentic_pipeline"] else "[dim]Inactive[/dim]"
    table.add_row(
        "Autonomous Pipeline (L4)",
        agentic_status,
        (
            "Active background CTI orchestrator / checkpoints"
            if metrics["has_agentic_pipeline"]
            else "No runner activity detected"
        ),
    )

    console.print(table)
    console.print()

    console.print("[bold]Concrete Suggestions for Advancing:[/bold]")
    for r in recs:
        console.print(f"  [cyan]•[/cyan] {r}")
    console.print()
