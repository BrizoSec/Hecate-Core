"""Hunt query/display commands: list, validate, stats, search, coverage, coffee."""

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from athf.core.hunt_manager import HuntManager
from athf.core.hunt_parser import validate_hunt_file
from athf.utils.validation import validate_hunt_id

console = Console()


def _validate_single_hunt(hunt_file: Path) -> tuple:
    """Validate a single hunt file and display results.

    Returns:
        (is_valid, errors) — callers use this to avoid a second parse.
    """
    console.print(f"\n[bold]Validating {hunt_file.name}...[/bold]\n")

    is_valid, errors = validate_hunt_file(hunt_file)

    if is_valid:
        console.print("[green]Hunt is valid![/green]")
    else:
        console.print("[red]Hunt has validation errors:[/red]\n")
        for error in errors:
            console.print(f"  - {error}")

    return is_valid, errors


def _render_progress_bar(covered: int, total: int, width: int = 20) -> str:
    """Render a visual progress bar with filled and empty blocks.

    Args:
        covered: Number of covered techniques
        total: Total number of techniques
        width: Width of the progress bar in characters

    Returns:
        ASCII progress bar string using simple characters
    """
    if total == 0:
        return "·" * width

    # Cap percentage at 100% for visual display
    percentage = min(covered / total, 1.0)
    filled = int(percentage * width)
    empty = width - filled

    # Use simple characters that render reliably
    filled_char = "■"
    empty_char = "·"

    return filled_char * filled + empty_char * empty


@click.command(name="list")
@click.option("--status", help="Filter by status (planning, active, in_review, completed)")
@click.option("--tactic", help="Filter by MITRE tactic")
@click.option("--technique", help="Filter by MITRE technique (e.g., T1003.001)")
@click.option("--platform", help="Filter by platform")
@click.option("--directory", type=click.Choice(["test", "production"]), help="Filter by environment directory")
@click.option("--type", "hunt_type", type=click.Choice(["hypothesis-driven", "baseline", "model-assisted"]), help="Filter by hunt type")
@click.option("--assignee", help="Filter by assigned team member")
@click.option("--output", type=click.Choice(["table", "json", "yaml"]), default="table", help="Output format")
def list_hunts(status: str, tactic: str, technique: str, platform: str, directory: str, hunt_type: str, assignee: str, output: str) -> None:
    """List all hunts with filtering and formatting options.

    \b
    Displays hunt catalog with:
    • Hunt ID and title
    • Current status
    • Environment directory (test/production)
    • MITRE ATT&CK techniques
    • True/False positive counts

    \b
    Examples:
      # List all hunts
      athf hunt list

      # Show only completed hunts
      athf hunt list --status completed

      # Filter by tactic
      athf hunt list --tactic credential-access

      # Filter by environment directory
      athf hunt list --directory test

      # Combine filters
      athf hunt list --tactic persistence --platform Linux --directory production

      # JSON output for scripting
      athf hunt list --output json

      # Show only baseline (EDA) hunts
      athf hunt list --type baseline

    \b
    Output formats:
      • table (default): Human-readable table with colors
      • json: Machine-readable for scripts and automation
      • yaml: Structured format for configuration management

    Note: Use --output instead of --format for specifying output format.
    """
    manager = HuntManager()
    hunts = manager.list_hunts(
        status=status, tactic=tactic, technique=technique, platform=platform,
        directory=directory, hunt_type=hunt_type, assignee=assignee,
    )

    if not hunts:
        console.print("[yellow]No hunts found.[/yellow]")
        console.print("\nCreate your first hunt: [cyan]athf hunt new[/cyan]")
        return

    if output == "json":
        console.print(json.dumps(hunts, indent=2), soft_wrap=True)
        return

    if output == "yaml":
        console.print(yaml.dump(hunts, default_flow_style=False))
        return

    # Table format
    console.print(f"\n[bold]📋 Hunt Catalog ({len(hunts)} total)[/bold]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Hunt ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white", no_wrap=True, max_width=30)
    table.add_column("Date", style="dim", no_wrap=True)
    table.add_column("Status", style="yellow", no_wrap=True)
    table.add_column("Assignee", style="dim", no_wrap=True)
    table.add_column("Env", style="blue", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Technique", style="magenta", no_wrap=True)
    table.add_column("Findings", style="green", no_wrap=True)

    for hunt in hunts:
        hunt_id = hunt.get("hunt_id", "")
        title_full = hunt.get("title") or ""
        title = title_full[:30] + ("..." if len(title_full) > 30 else "")
        date_val = hunt.get("date") or "-"
        date_str = str(date_val) if date_val != "-" else "-"
        status_val = hunt.get("status", "")
        assignee_val = hunt.get("assignee") or "-"
        environment = hunt.get("environment", "-")
        env_display = environment if environment else "-"
        # Only non-hypothesis-driven types stand out here -- hypothesis-driven
        # is the overwhelmingly common case, so keep the column quiet for it.
        _ht = hunt.get("hunt_type")
        type_display = "baseline" if _ht == "baseline" else ("model-asst" if _ht == "model-assisted" else "-")
        techniques = hunt.get("techniques", [])
        technique_str = techniques[0] if techniques else "-"

        tp = hunt.get("true_positives", 0)
        fp = hunt.get("false_positives", 0)
        findings_str = f"{tp + fp} ({tp} TP)" if (tp + fp) > 0 else "-"

        table.add_row(hunt_id, title, date_str, status_val, assignee_val, env_display, type_display, technique_str, findings_str)

    console.print(table)
    console.print()


@click.command()
@click.argument("hunt_id", required=False)
@click.option("--fail-on-error", is_flag=True, help="Exit with non-zero status if any validation errors are found (useful for CI)")
def validate(hunt_id: str, fail_on_error: bool) -> None:
    """Validate hunt file structure and metadata.

    \b
    Validates:
    • YAML frontmatter syntax
    • Required metadata fields
    • LOCK section structure
    • MITRE ATT&CK technique format
    • File naming conventions

    \b
    Examples:
      # Validate specific hunt
      athf hunt validate H-0042

      # Validate all hunts
      athf hunt validate

      # CI-safe: exit non-zero on errors
      athf hunt validate --fail-on-error

    \b
    Use this to:
    • Catch formatting errors before committing
    • Ensure consistency across hunt documentation
    • Verify hunt files are AI-assistant readable
    """
    if hunt_id:
        # Validate hunt ID format
        if not validate_hunt_id(hunt_id):
            console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
            console.print("[yellow]Expected format: H-0001[/yellow]")
            return

        # Validate specific hunt - search recursively for backward compatibility
        hunts_dir = Path("hunts")
        hunt_file = hunts_dir / f"{hunt_id}.md"

        # If not found in flat structure, search recursively
        if not hunt_file.exists():
            matching_files = list(hunts_dir.rglob(f"{hunt_id}.md"))
            if not matching_files:
                console.print(f"[red]Hunt not found: {hunt_id}[/red]")
                return
            hunt_file = matching_files[0]  # Use first match

        # Validate path is within hunts directory
        try:
            hunt_file.resolve().relative_to(hunts_dir.resolve())
        except (ValueError, OSError):
            console.print("[red]Error: Invalid hunt file path[/red]")
            return

        is_valid, _ = _validate_single_hunt(hunt_file)
        if fail_on_error and not is_valid:
            import sys
            sys.exit(1)
    else:
        # Validate all hunts
        console.print("\n[bold]🔍 Validating all hunts...[/bold]\n")

        hunts_dir = Path("hunts")
        if not hunts_dir.exists():
            console.print("[yellow]No hunts directory found.[/yellow]")
            return

        hunt_files = HuntManager(hunts_dir).find_all_hunt_files()

        if not hunt_files:
            console.print("[yellow]No hunt files found.[/yellow]")
            return

        valid_count = 0
        invalid_count = 0

        for hunt_file in hunt_files:
            is_valid, errors = validate_hunt_file(hunt_file)

            if is_valid:
                valid_count += 1
                console.print(f"[green]✓[/green] {hunt_file.name}")
            else:
                invalid_count += 1
                console.print(f"[red]✗[/red] {hunt_file.name}")
                for error in errors:
                    console.print(f"    - {error}")

        console.print(f"\n[bold]Results:[/bold] {valid_count} valid, {invalid_count} invalid")
        if fail_on_error and invalid_count > 0:
            import sys
            sys.exit(1)


def _show_trend(manager: HuntManager) -> None:
    """Print a quarterly breakdown of hunt activity."""
    from collections import defaultdict

    hunts = manager.list_hunts()
    if not hunts:
        return

    quarters: dict = defaultdict(lambda: {"total": 0, "completed": 0, "true_positives": 0})

    for hunt in hunts:
        date_val = hunt.get("date")
        if not date_val:
            continue
        try:
            if hasattr(date_val, "year"):
                year, month = date_val.year, date_val.month
            else:
                parsed = datetime.strptime(str(date_val)[:10], "%Y-%m-%d")
                year, month = parsed.year, parsed.month
            quarter = f"{year} Q{(month - 1) // 3 + 1}"
        except (ValueError, AttributeError):
            continue

        quarters[quarter]["total"] += 1
        if hunt.get("status") == "completed":
            quarters[quarter]["completed"] += 1
        quarters[quarter]["true_positives"] += hunt.get("true_positives", 0)

    if not quarters:
        return

    console.print("[bold cyan]📈 Quarterly Trend[/bold cyan]\n")
    trend_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    trend_table.add_column("Quarter", style="cyan")
    trend_table.add_column("Total", justify="right")
    trend_table.add_column("Completed", justify="right")
    trend_table.add_column("True Positives", justify="right")

    for quarter in sorted(quarters.keys()):
        q = quarters[quarter]
        trend_table.add_row(quarter, str(q["total"]), str(q["completed"]), str(q["true_positives"]))

    console.print(trend_table)
    console.print()


def _save_hunt_context(stats_data: dict, manager: HuntManager) -> None:
    """Write a structured hunt-program metrics block to knowledge/environment.md.

    Appends (or replaces) a ``## Hunt Program Metrics`` section so agent runs
    inherit up-to-date context about what has been hunted, success rates, and
    covered tactics.
    """
    from athf.core.attack_matrix import get_sorted_tactics

    # Collect tactic coverage summary
    coverage_data = manager.calculate_attack_coverage()
    by_tactic = coverage_data.get("by_tactic", {})
    covered_tactics = [t for t in get_sorted_tactics() if by_tactic.get(t, {}).get("hunt_count", 0) > 0]

    # Build the metrics block
    now_str = datetime.now().strftime("%Y-%m-%d")
    tp_fp = stats_data.get("tp_fp_ratio", "N/A")
    tp_fp_str = str(tp_fp) if tp_fp != float("inf") else "∞"

    block_lines = [
        "",
        "## Hunt Program Metrics",
        "",
        f"_Auto-generated by `athf hunt stats --save-context` on {now_str}._",
        "",
        f"- **Total Hunts:** {stats_data['total_hunts']}",
        f"- **Completed Hunts:** {stats_data['completed_hunts']}",
        f"- **Baseline Hunts:** {stats_data['baseline_hunts']}",
        f"- **Model-Assisted Hunts:** {stats_data['model_assisted_hunts']}",
        f"- **True Positives:** {stats_data['true_positives']}",
        f"- **False Positives:** {stats_data['false_positives']}",
        f"- **Success Rate (hypothesis-driven):** {stats_data['success_rate']}%",
        f"- **TP/FP Ratio:** {tp_fp_str}",
        "",
        "**Covered ATT&CK Tactics:**",
    ]
    if covered_tactics:
        for t in covered_tactics:
            hunt_count = by_tactic[t].get("hunt_count", 0)
            tech_count = by_tactic[t].get("techniques_covered", 0)
            block_lines.append(f"- {t}: {hunt_count} hunt(s), {tech_count} technique(s)")
    else:
        block_lines.append("- No tactic coverage yet.")

    summary = coverage_data.get("summary", {})
    unique = summary.get("unique_techniques", 0)
    total = summary.get("total_techniques", 0)
    pct = summary.get("overall_coverage_pct", 0.0)
    block_lines.append("")
    block_lines.append(f"**Overall Technique Coverage:** {unique}/{total} ({pct:.0f}%)")
    block_lines.append("")

    metrics_block = "\n".join(block_lines)

    env_path = Path("knowledge/environment.md")
    env_path.parent.mkdir(parents=True, exist_ok=True)

    if env_path.exists():
        existing = env_path.read_text(encoding="utf-8")
        # Replace existing metrics block if present
        import re
        existing = re.sub(
            r"\n## Hunt Program Metrics\b.*?(?=\n## |\Z)",
            "",
            existing,
            flags=re.DOTALL,
        ).rstrip()
        new_content = existing + metrics_block
    else:
        new_content = f"# Environment Profile\n{metrics_block}"

    env_path.write_text(new_content, encoding="utf-8")
    console.print(f"[green]Hunt program context saved to {env_path}[/green]")


@click.command()
@click.option("--trend", is_flag=True, help="Show quarterly breakdown of hunt activity")
@click.option(
    "--save-context",
    is_flag=True,
    help="Append a hunt-program metrics block to knowledge/environment.md for agent context.",
)
def stats(trend: bool, save_context: bool) -> None:
    """Show hunt program statistics and success metrics.

    \b
    Calculates and displays:
    • Total hunts vs completed hunts
    • Total findings (True Positives + False Positives)
    • Success rate (hunts with TPs / completed hunts)
    • TP/FP ratio (quality of detections)
    • Hunt velocity metrics

    \b
    Examples:
      athf hunt stats
      athf hunt stats --trend

    \b
    Use this to:
    • Track hunting program effectiveness over time
    • Identify areas for improvement
    • Demonstrate hunting value to leadership
    • Set quarterly goals and OKRs
    """
    manager = HuntManager()
    stats_data = manager.calculate_stats()

    console.print("\n[bold cyan]📊 Hunt Program Statistics[/bold cyan]\n")

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white", justify="right")

    table.add_row("Total Hunts", str(stats_data["total_hunts"]))
    table.add_row("Completed Hunts", str(stats_data["completed_hunts"]))
    table.add_row("Baseline Hunts", str(stats_data["baseline_hunts"]))
    table.add_row("Model-Assisted Hunts", str(stats_data["model_assisted_hunts"]))
    table.add_row("Total Findings", str(stats_data["total_findings"]))
    table.add_row("True Positives", str(stats_data["true_positives"]))
    table.add_row("False Positives", str(stats_data["false_positives"]))
    table.add_row("Success Rate (hypothesis-driven)", f"{stats_data['success_rate']}%")
    table.add_row("TP/FP Ratio", str(stats_data["tp_fp_ratio"]))

    console.print(table)
    console.print()

    # Easter egg: First True Positive milestone
    if stats_data["true_positives"] == 1 and stats_data["completed_hunts"] > 0:
        console.print("[bold yellow]🎯 First True Positive Detected![/bold yellow]\n")
        console.print(
            "[italic]Every expert threat hunter started here. This confirms your hypothesis was testable, your data was sufficient, and your analytical instincts were sound. Document what worked.[/italic]\n"
        )

    if trend:
        _show_trend(manager)

    if save_context:
        _save_hunt_context(stats_data, manager)


@click.command()
@click.argument("query")
@click.option("--directory", type=click.Choice(["test", "production"]), help="Filter by environment directory")
def search(query: str, directory: str) -> None:
    """Full-text search across all hunt files.

    \b
    Searches through:
    • Hunt titles and descriptions
    • YAML frontmatter metadata
    • LOCK section content
    • Lessons learned
    • Query comments

    \b
    Examples:
      # Search for specific TTP
      athf hunt search "kerberoasting"

      # Search for technology
      athf hunt search "powershell"

      # Search by hunt ID
      athf hunt search "H-0042"

      # Search for data source
      athf hunt search "sysmon"

      # Filter by environment directory
      athf hunt search "credential" --directory test

    \b
    Use this to:
    • Avoid duplicate hunts
    • Find related past work
    • Reference lessons learned
    • Check if a TTP has been hunted before
    """
    manager = HuntManager()
    results = manager.search_hunts(query, directory=directory)

    if not results:
        console.print(f"[yellow]No hunts found matching '{query}'[/yellow]")
        return

    console.print(f"\n[bold]🔍 Search results for '{query}' ({len(results)} found)[/bold]\n")

    for result in results:
        environment = result.get("environment", "-")
        env_display = f" | Env: {environment}" if environment else ""
        console.print(f"[cyan]{result['hunt_id']}[/cyan]: {result['title']}")
        console.print(f"  Status: {result['status']}{env_display} | File: {result['file_path']}")
        console.print()


@click.command()
@click.option("--tactic", help="Filter by specific tactic (or 'all' for all tactics)")
@click.option("--detailed", is_flag=True, help="Show detailed technique coverage with hunt references")
@click.option("--output", "output_format", type=click.Choice(["table", "json", "yaml"]), default="table", help="Output format (default: table)")
def coverage(tactic: Optional[str], detailed: bool, output_format: str) -> None:
    """Show MITRE ATT&CK technique coverage across hunts.

    \b
    Analyzes and displays:
    • Hunt count per tactic across all 14 ATT&CK tactics
    • Technique count per tactic (with caveats - see note below)
    • Overall unique technique coverage across all hunts
    • Detailed technique-to-hunt mapping (with --detailed)

    \b
    Examples:
      # Show coverage overview for all tactics
      athf hunt coverage

      # Show all tactics explicitly
      athf hunt coverage --tactic all

      # Show coverage for a specific tactic
      athf hunt coverage --tactic credential-access

      # Show detailed technique mapping for execution tactic
      athf hunt coverage --tactic execution --detailed

    \b
    Note on technique counts:
      Per-tactic technique counts may include duplicates if hunts cover
      multiple tactics. The overall unique technique count (bottom) is accurate.

    \b
    Use this to:
    • Identify blind spots in your hunting program
    • Prioritize future hunt topics
    • Demonstrate coverage to stakeholders
    • Align hunting with threat intelligence priorities
    • Balance hunt portfolio across tactics

    \b
    Pro tip:
      Focus on tactics with no coverage that align with your threat model.
      Use --detailed to see which specific techniques each hunt covers.
    """
    from athf.core.attack_matrix import ATTACK_TACTICS, get_sorted_tactics

    manager = HuntManager()
    coverage_data = manager.calculate_attack_coverage()

    if not coverage_data or not coverage_data.get("by_tactic"):
        console.print("[yellow]No hunt coverage data available.[/yellow]")
        return

    if output_format == "json":
        console.print(json.dumps(coverage_data, indent=2), soft_wrap=True)
        return

    if output_format == "yaml":
        console.print(yaml.dump(coverage_data, default_flow_style=False))
        return

    summary = coverage_data["summary"]
    by_tactic = coverage_data["by_tactic"]

    # Determine which tactics to display
    tactics_to_display = []
    if tactic and tactic.lower() != "all":
        # Validate tactic exists
        if tactic not in ATTACK_TACTICS:
            console.print(f"[red]Error: Unknown tactic '{tactic}'[/red]")
            console.print("\n[bold]Valid tactics:[/bold]")
            for tactic_key in get_sorted_tactics():
                console.print(f"  • {tactic_key}")
            return
        tactics_to_display = [tactic]
    else:
        # Show all tactics
        tactics_to_display = get_sorted_tactics()

    # Display title
    if tactic and tactic.lower() != "all":
        tactic_display_name = ATTACK_TACTICS[tactic]["name"]
        console.print(f"\n[bold]MITRE ATT&CK Coverage - {tactic_display_name}[/bold]")
    else:
        console.print("\n[bold]MITRE ATT&CK Coverage[/bold]")
    console.print("─" * 60 + "\n")

    # Display selected tactics in ATT&CK order with hunt counts
    for tactic_key in tactics_to_display:
        data = by_tactic.get(tactic_key, {})
        tactic_name = ATTACK_TACTICS[tactic_key]["name"]

        hunt_count = data.get("hunt_count", 0)
        techniques_covered = data.get("techniques_covered", 0)

        # Format: "Tactic Name          2 hunts, 7 techniques"
        if hunt_count > 0:
            console.print(f"{tactic_name:<24} {hunt_count} hunts, {techniques_covered} techniques")
        else:
            console.print(f"{tactic_name:<24} [dim]no coverage[/dim]")

    # Display overall coverage only if showing all tactics
    if not tactic or tactic.lower() == "all":
        console.print(
            f"\n[bold]Overall: {summary['unique_techniques']}/{summary['total_techniques']} techniques ({summary['overall_coverage_pct']:.0f}%)[/bold]\n"
        )
    else:
        console.print()

    # Display detailed technique coverage if requested
    if detailed:
        console.print("\n[bold cyan]🔍 Detailed Technique Coverage[/bold cyan]\n")

        for tactic_key in tactics_to_display:
            data = by_tactic.get(tactic_key, {})
            if data.get("hunt_count", 0) == 0:
                continue  # Skip tactics with no hunts in detailed view

            tactic_name = ATTACK_TACTICS[tactic_key]["name"]
            console.print(
                f"\n[bold]{tactic_name}[/bold] ({data['hunt_count']} hunts, {len(data['techniques'])} unique techniques)"
            )

            # Show techniques with hunt references
            for technique, hunt_ids in sorted(data["techniques"].items()):
                hunt_refs = ", ".join(sorted(set(hunt_ids)))  # Remove duplicates and sort
                console.print(f"  • [yellow]{technique}[/yellow] - {hunt_refs}")

    console.print()


@click.command(hidden=True)
def coffee() -> None:
    """Check your caffeine levels (critical for threat hunting)."""
    now = datetime.now()
    hour = now.hour

    # Random caffeine level
    caffeine_level = random.randint(0, 100)

    # Time-aware status
    if 3 <= hour < 5:
        status = "Incident Response Mode"
        time_message = "Running on pure incident response adrenaline."
    elif 0 <= hour < 6:
        status = "Night Hunter"
        time_message = "The real threat hunting happens in the dark."
    elif 6 <= hour < 9:
        status = "Early Bird"
        time_message = "Morning hunts catch the adversaries."
    elif 18 <= hour < 24:
        status = "Evening Detective"
        time_message = "Picking up where the day shift left off."
    else:
        status = "Operational"
        time_message = "Sustainable hunting pace detected."

    # Caffeine-level specific recommendations
    if caffeine_level < 30:
        recommendation = "Consider refueling. Even the best hunters need breaks."
    elif caffeine_level > 90:
        recommendation = "Peak operational capacity. Time to chase that hypothesis."
    else:
        recommendation = time_message

    console.print("\n[bold]☕ Threat Hunter Caffeine Check[/bold]\n")
    console.print(f"Current Level: [cyan]{caffeine_level}%[/cyan]")
    console.print(f"Status: [yellow]{status}[/yellow]")
    console.print(f"Recommendation: [italic]{recommendation}[/italic]\n")

    # Random wisdom quote
    wisdom_quotes = [
        "The best hunts are fueled by curiosity, not just caffeine.",
        "Caffeine enables the hunt. Rigor validates the findings.",
        "Stay sharp, stay curious, stay caffeinated.",
        "Coffee: because threat actors don't work business hours.",
        "Fuel your hypotheses with coffee. Validate them with data.",
    ]
    console.print(f"[dim italic]{random.choice(wisdom_quotes)}[/dim italic]\n")
