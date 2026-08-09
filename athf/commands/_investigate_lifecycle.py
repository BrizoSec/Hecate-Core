"""Investigation lifecycle command: promote."""

from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.prompt import Prompt

from athf.utils.validation import validate_investigation_id

console = Console()


@click.command()
@click.argument("investigation_id")
@click.option("--technique", help="MITRE ATT&CK technique (required for hunt)")
@click.option("--tactic", multiple=True, help="MITRE tactics (can specify multiple)")
@click.option("--platform", multiple=True, help="Target platforms (can specify multiple)")
@click.option("--status", default="in-progress", help="Hunt status (default: in-progress)")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def promote(
    investigation_id: str,
    technique: Optional[str],
    tactic: Tuple[str, ...],
    platform: Tuple[str, ...],
    status: str,
    non_interactive: bool,
) -> None:
    """Promote investigation to formal hunt.

    \b
    Creates a hunt file (H-XXXX) from an investigation, adding:
    • Hunt-required metadata (tactics, techniques, platform)
    • Hunt status and tracking fields
    • Findings count and TP/FP fields (default: 0)
    • Reference to original investigation (spawned_from)

    \b
    Examples:
      # Interactive promotion (prompts for details)
      athf investigate promote I-0042

      # Non-interactive with all options
      athf investigate promote I-0042 \\
        --technique T1059.001 \\
        --tactic execution \\
        --platform Windows \\
        --non-interactive

    \b
    After promotion:
      • Hunt file created in hunts/ directory
      • Investigation remains in investigations/ directory
      • Both files cross-reference each other
    """
    from athf.core.hunt_manager import HuntManager, get_hunt_directory
    from athf.core.investigation_parser import InvestigationParser

    console.print("\n[bold cyan]Promoting investigation to hunt[/bold cyan]\n")

    if not validate_investigation_id(investigation_id):
        console.print(f"[red]Error: Invalid investigation ID format: {investigation_id}[/red]")
        console.print("[yellow]Expected format: I-0001[/yellow]")
        return

    investigations_dir = Path("investigations")
    investigation_file = investigations_dir / f"{investigation_id}.md"

    try:
        investigation_file.resolve().relative_to(investigations_dir.resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid investigation file path[/red]")
        return

    if not investigation_file.exists():
        console.print(f"[red]Error: Investigation file not found: {investigation_file}[/red]")
        return

    try:
        parser = InvestigationParser(investigation_file)
        investigation_data = parser.parse()
        inv_frontmatter = investigation_data.get("frontmatter", {})
        inv_content = investigation_data.get("content", "")
    except Exception as e:
        console.print(f"[red]Error parsing investigation file: {e}[/red]")
        return

    inv_title = inv_frontmatter.get("title", "Untitled")
    inv_investigator = inv_frontmatter.get("investigator", "Unknown")
    inv_data_sources = inv_frontmatter.get("data_sources", [])
    inv_related_hunts = inv_frontmatter.get("related_hunts", [])
    inv_tags = inv_frontmatter.get("tags", [])

    console.print(f"[bold]Investigation:[/bold] {investigation_id} - {inv_title}")

    if non_interactive:
        if not technique:
            console.print("[red]Error: --technique required in non-interactive mode[/red]")
            return
        hunt_technique = technique
        hunt_tactics = list(tactic) if tactic else []
        hunt_platforms = list(platform) if platform else []
        hunt_status = status
    else:
        console.print("\n[bold]Let's add hunt-required metadata:[/bold]")

        console.print("\n1. MITRE ATT&CK Technique (required for hunts):")
        console.print("   Examples: [cyan]T1003.001, T1059.001, T1078[/cyan]")
        hunt_technique = Prompt.ask("   Technique", default=technique or "")

        console.print("\n2. MITRE Tactics (comma-separated):")
        console.print("   Examples: [cyan]initial-access, execution, persistence, credential-access[/cyan]")
        tactics_input = Prompt.ask("   Tactics", default=",".join(tactic) if tactic else "")
        hunt_tactics = [t.strip() for t in tactics_input.split(",")] if tactics_input else []

        console.print("\n3. Target Platforms (comma-separated):")
        console.print("   Examples: [cyan]Windows, Linux, macOS, Cloud[/cyan]")
        platforms_input = Prompt.ask("   Platforms", default=",".join(platform) if platform else "")
        hunt_platforms = [p.strip() for p in platforms_input.split(",")] if platforms_input else []

        console.print("\n4. Hunt Status:")
        hunt_status = Prompt.ask(
            "   Status",
            default=status,
            choices=["planning", "in-progress", "completed", "archived"],
        )

    hunt_manager = HuntManager()
    hunt_id = hunt_manager.get_next_hunt_id()

    console.print(f"\n[bold]Hunt ID:[/bold] {hunt_id}")

    today = datetime.now().strftime("%Y-%m-%d")
    hunt_frontmatter = {
        "hunt_id": hunt_id,
        "title": inv_title,
        "status": hunt_status,
        "date": today,
        "hunter": inv_investigator,
        "platform": hunt_platforms,
        "tactics": hunt_tactics,
        "techniques": [hunt_technique],
        "data_sources": inv_data_sources,
        "related_hunts": inv_related_hunts,
        "spawned_from": investigation_id,
        "findings_count": 0,
        "true_positives": 0,
        "false_positives": 0,
        "customer_deliverables": [],
        "tags": inv_tags,
    }

    yaml_content = yaml.dump(hunt_frontmatter, default_flow_style=False, sort_keys=False)

    hunt_content = f"""---
{yaml_content}---

# {hunt_id}: {inv_title}

**Hunt Metadata**

- **Date:** {today}
- **Hunter:** {inv_investigator}
- **Status:** {hunt_status.title()}
- **Promoted From:** {investigation_id}

---

{inv_content}
"""

    hunt_dir = get_hunt_directory()
    hunt_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunt_dir / f"{hunt_id}.md"

    try:
        hunt_file.resolve().relative_to(Path("hunts").resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid hunt file path[/red]")
        return

    with open(hunt_file, "w", encoding="utf-8") as f:
        f.write(hunt_content)

    console.print(f"\n[bold green]Promoted {investigation_id} to {hunt_id}[/bold green]")

    # Update investigation's related_hunts field in frontmatter
    try:
        with open(investigation_file, "r", encoding="utf-8") as f:
            content = f.read()

        parts = content.split("---")
        if len(parts) >= 3:
            frontmatter_yaml = parts[1]
            body = "---".join(parts[2:])

            frontmatter = yaml.safe_load(frontmatter_yaml)
            if "related_hunts" not in frontmatter or frontmatter["related_hunts"] is None:
                frontmatter["related_hunts"] = []

            if hunt_id not in frontmatter["related_hunts"]:
                frontmatter["related_hunts"].append(hunt_id)

            updated_yaml = yaml.dump(frontmatter, default_flow_style=False, sort_keys=False)
            updated_content = f"---\n{updated_yaml}---{body}"

            with open(investigation_file, "w", encoding="utf-8") as f:
                f.write(updated_content)

            console.print(f"[dim]Updated {investigation_file} with hunt reference in related_hunts[/dim]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not update investigation frontmatter: {e}[/yellow]")

    promotion_note = f"\n\n---\n\n**Promoted to Hunt:** {hunt_id} on {today}\n"
    with open(investigation_file, "a", encoding="utf-8") as f:
        f.write(promotion_note)

    console.print(f"[dim]Added promotion note to {investigation_file}[/dim]")

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{hunt_file}[/cyan] to refine hunt hypothesis")
    console.print("  2. Add MITRE ATT&CK coverage if needed")
    console.print(f"  3. Validate hunt: [cyan]athf hunt validate {hunt_id}[/cyan]")
    console.print(f"  4. View hunt: [cyan]athf hunt list --status {hunt_status}[/cyan]\n")
