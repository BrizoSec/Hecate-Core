"""Investigation query/display commands: list, search, validate."""

import json
from pathlib import Path
from typing import Optional

import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from athf.core.investigation_parser import get_all_investigations, validate_investigation_file
from athf.utils.validation import validate_investigation_id

console = Console()


@click.command(name="list")
@click.option("--type", "investigation_type", help="Filter by type (finding, baseline, exploratory, other)")
@click.option("--tags", help="Filter by tags (comma-separated)")
@click.option("--output", type=click.Choice(["table", "json", "yaml"]), default="table", help="Output format")
def list_investigations(
    investigation_type: Optional[str],
    tags: Optional[str],
    output: str,
) -> None:
    """List all investigations with filtering options.

    \b
    Displays investigation catalog with:
    • Investigation ID and title
    • Type (finding, baseline, exploratory, other)
    • Tags and related hunts

    \b
    Examples:
      # List all investigations
      athf investigate list

      # Show only finding investigations
      athf investigate list --type finding

      # Filter by tags
      athf investigate list --tags alert-triage

      # JSON output for scripting
      athf investigate list --output json
    """
    investigations_dir = Path("investigations")
    investigations = get_all_investigations(investigations_dir)

    if not investigations:
        console.print("[yellow]No investigations found.[/yellow]")
        console.print("\nCreate your first investigation: [cyan]athf investigate new[/cyan]")
        return

    filtered_investigations = investigations
    if investigation_type:
        filtered_investigations = [
            inv for inv in filtered_investigations if inv.get("frontmatter", {}).get("type") == investigation_type
        ]

    if tags:
        filter_tags = {t.strip() for t in tags.split(",")}
        filtered_investigations = [
            inv for inv in filtered_investigations if filter_tags.intersection(inv.get("frontmatter", {}).get("tags", []))
        ]

    if not filtered_investigations:
        console.print("[yellow]No investigations match the filters.[/yellow]")
        return

    if output == "json":
        console.print(json.dumps(filtered_investigations, indent=2), soft_wrap=True)
        return

    if output == "yaml":
        console.print(yaml.dump(filtered_investigations, default_flow_style=False))
        return

    table = Table(title="Investigations", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Type", style="yellow")
    table.add_column("Related Hunts", style="green")
    table.add_column("Tags", style="dim")
    table.add_column("Date", style="dim")

    for investigation in filtered_investigations:
        frontmatter = investigation.get("frontmatter", {})
        inv_id = frontmatter.get("investigation_id", "N/A")
        title = frontmatter.get("title", "Untitled")
        inv_type = frontmatter.get("type", "unknown")
        inv_tags = frontmatter.get("tags", [])
        inv_related_hunts = frontmatter.get("related_hunts", [])
        date = frontmatter.get("date", "N/A")

        tags_str = ", ".join(inv_tags[:3]) if inv_tags else "-"
        if len(inv_tags) > 3:
            tags_str += f" (+{len(inv_tags) - 3})"

        related_hunts_str = ", ".join(inv_related_hunts) if inv_related_hunts else "-"

        table.add_row(inv_id, title, inv_type, related_hunts_str, tags_str, date)

    console.print(table)
    console.print(f"\n[dim]Total: {len(filtered_investigations)} investigations[/dim]")


@click.command()
@click.argument("query")
def search(query: str) -> None:
    """Search investigation files for keywords.

    \b
    Performs full-text search across all investigation files.

    \b
    Examples:
      # Search for PowerShell
      athf investigate search "PowerShell"

      # Search for customer-specific findings
      athf investigate search "customer-x"

      # Search for baseline work
      athf investigate search "baseline CloudTrail"
    """
    investigations_dir = Path("investigations")
    investigation_files = sorted(investigations_dir.glob("I-*.md"))

    if not investigation_files:
        console.print("[yellow]No investigation files found.[/yellow]")
        return

    matches = []
    for file_path in investigation_files:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            if query.lower() in content.lower():
                matches.append(file_path)

    if not matches:
        console.print(f'[yellow]No matches found for "{query}"[/yellow]')
        return

    console.print(f'\n[bold]Found {len(matches)} investigation(s) matching "{query}":[/bold]\n')

    for file_path in matches:
        investigation_id = file_path.stem
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                frontmatter_match = yaml.safe_load(content.split("---")[1])
                title = frontmatter_match.get("title", "Untitled")
        except Exception:
            title = "Untitled"

        console.print(f"[cyan]{investigation_id}[/cyan]: {title}")
        console.print(f"  [dim]{file_path}[/dim]\n")


@click.command()
@click.argument("investigation_id")
def validate(investigation_id: str) -> None:
    """Validate investigation file structure.

    \b
    Checks:
    • YAML frontmatter is valid
    • Required fields exist (investigation_id, title, date)
    • Investigation ID format (I-XXXX)
    • File name matches investigation ID

    \b
    Examples:
      # Validate a specific investigation
      athf investigate validate I-0042

      # Validate after editing
      athf investigate validate I-0001
    """
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

    is_valid, errors = validate_investigation_file(investigation_file)

    if is_valid:
        console.print(f"[bold green]{investigation_id} is valid[/bold green]")
    else:
        console.print(f"[bold red]{investigation_id} has validation errors:[/bold red]\n")
        for error in errors:
            console.print(f"  • {error}")
