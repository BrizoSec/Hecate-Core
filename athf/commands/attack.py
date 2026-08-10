"""ATT&CK data management commands."""

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import click
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from athf.core.attack_matrix import TechniqueInfo

console = Console()


@click.group()
def attack() -> None:
    """Manage MITRE ATT&CK data.

    \b
    Commands for downloading, inspecting, and querying ATT&CK
    technique data via the STIX framework.

    \b
    Quick Start:
      athf attack update       Download/refresh STIX data
      athf attack status       Show provider info and cache age
      athf attack lookup T1003 Look up technique metadata
    """


_STIX_ID_RE = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _sanitize_stix_bundle(path: Path) -> None:
    """Fix known-bad fields in the MITRE STIX bundle that cause stix2 validation errors.

    The upstream bundle sometimes ships DataComponent objects with empty
    ``x_mitre_data_source_ref`` values.  The ``stix2`` library rejects
    these because they don't match the STIX identifier format.  We
    strip those invalid entries so ``MitreAttackData`` can load the file.
    """
    with open(path, "r") as f:
        bundle = json.load(f)

    modified = False
    for obj in bundle.get("objects", []):
        ref = obj.get("x_mitre_data_source_ref")
        if ref is not None and not _STIX_ID_RE.match(ref):
            del obj["x_mitre_data_source_ref"]
            modified = True

    if modified:
        with open(path, "w") as f:
            json.dump(bundle, f)


@attack.command()
@click.option("--force", is_flag=True, help="Re-download even if cache exists")
def update(force: bool) -> None:
    """Download or refresh ATT&CK STIX data.

    Downloads the Enterprise ATT&CK STIX bundle from the official
    MITRE repository and caches it locally.

    \b
    Examples:
      athf attack update
      athf attack update --force
    """
    try:
        from mitreattack.stix20 import MitreAttackData  # noqa: F401
    except ImportError:
        console.print("[red]Error: mitreattack-python is not installed.[/red]")
        console.print("[dim]Install it with: pip install 'athf[attack]'[/dim]")
        raise click.Abort()

    from athf.core.attack_matrix import _get_stix_file_path, reset_provider

    stix_path = _get_stix_file_path()

    if stix_path.exists() and not force:
        age_days = int((time.time() - stix_path.stat().st_mtime) / 86400)
        console.print(f"[yellow]STIX data already exists (age: {age_days}d).[/yellow]")
        console.print("[dim]Use --force to re-download.[/dim]")
        return

    # Ensure cache directory exists
    stix_path.parent.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]Downloading ATT&CK Enterprise STIX data...[/cyan]")
    console.print(f"[dim]Cache location: {stix_path}[/dim]")

    _STIX_URL = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
        "/master/enterprise-attack/enterprise-attack.json"
    )

    try:
        urllib.request.urlretrieve(_STIX_URL, str(stix_path))
        _sanitize_stix_bundle(stix_path)
        # Reset provider so it picks up the new data
        reset_provider()
        console.print("[green]ATT&CK STIX data downloaded successfully.[/green]")

        # Show summary
        from athf.core.attack_matrix import get_attack_version, is_using_stix

        if is_using_stix():
            console.print(f"[dim]Version: {get_attack_version()}[/dim]")
    except Exception as e:
        console.print(f"[red]Error downloading STIX data: {e}[/red]")
        raise click.Abort()


@attack.command()
def status() -> None:
    """Show ATT&CK data provider status.

    Displays the active provider type, ATT&CK version,
    technique counts, and cache file details.

    \b
    Example:
      athf attack status
    """
    from athf.core.attack_matrix import (
        _get_stix_file_path,
        get_attack_version,
        get_sorted_tactics,
        is_using_stix,
    )

    console.print("\n[bold]ATT&CK Data Status[/bold]\n")

    provider_type = "STIX (mitreattack-python)" if is_using_stix() else "Fallback (hardcoded v14)"
    console.print(f"  [cyan]Provider:[/cyan]  {provider_type}")
    console.print(f"  [cyan]Version:[/cyan]   {get_attack_version()}")
    console.print(f"  [cyan]Tactics:[/cyan]   {len(get_sorted_tactics())}")

    # Show cache info
    stix_path = _get_stix_file_path()
    if stix_path.exists():
        size_mb = stix_path.stat().st_size / (1024 * 1024)
        age_days = int((time.time() - stix_path.stat().st_mtime) / 86400)
        console.print(f"  [cyan]Cache:[/cyan]     {stix_path}")
        console.print(f"  [cyan]Size:[/cyan]      {size_mb:.1f} MB")
        console.print(f"  [cyan]Age:[/cyan]       {age_days} days")
    else:
        console.print(f"  [cyan]Cache:[/cyan]     Not found ({stix_path})")
        console.print("[dim]  Run 'athf attack update' to download STIX data.[/dim]")

    # Check if mitreattack-python is installed
    try:
        import mitreattack  # noqa: F401
        console.print("  [cyan]Library:[/cyan]   mitreattack-python installed")
    except ImportError:
        console.print("  [cyan]Library:[/cyan]   [yellow]mitreattack-python not installed[/yellow]")
        console.print("[dim]  Install with: pip install 'athf[attack]'[/dim]")

    console.print()


def _display_technique_fields(tech: "TechniqueInfo") -> None:
    """Print technique metadata fields to the console."""
    if tech.get("url"):
        console.print(f"  [cyan]URL:[/cyan]           {tech['url']}")
    if tech.get("platforms"):
        console.print(f"  [cyan]Platforms:[/cyan]     {', '.join(tech['platforms'])}")
    if tech.get("tactic_shortnames"):
        console.print(f"  [cyan]Tactics:[/cyan]       {', '.join(tech['tactic_shortnames'])}")
    if tech.get("data_sources"):
        console.print(f"  [cyan]Data Sources:[/cyan]  {', '.join(tech['data_sources'][:5])}")
        if len(tech.get("data_sources", [])) > 5:
            console.print(f"                 [dim]... and {len(tech['data_sources']) - 5} more[/dim]")
    is_sub = tech.get("is_subtechnique", False)
    console.print(f"  [cyan]Type:[/cyan]          {'Sub-technique' if is_sub else 'Technique'}")
    if is_sub and tech.get("parent_id"):
        console.print(f"  [cyan]Parent:[/cyan]        {tech['parent_id']}")
    if tech.get("description"):
        desc = tech["description"]
        if len(desc) > 300:
            desc = desc[:300] + "..."
        console.print(f"\n  [dim]{desc}[/dim]")


@attack.command()
@click.argument("technique_id")
@click.option("--json", "as_json", is_flag=True, help="Print technique metadata as JSON instead of a formatted table.")
def lookup(technique_id: str, as_json: bool) -> None:
    """Look up an ATT&CK technique by ID.

    Shows technique metadata including name, platforms,
    data sources, tactics, and sub-techniques.

    \b
    Examples:
      athf attack lookup T1003
      athf attack lookup T1003.001
      athf attack lookup T1003.001 --json
    """
    from athf.core.attack_matrix import get_sub_techniques, get_technique, is_using_stix

    if not is_using_stix():
        if as_json:
            print(json.dumps({"error": "stix_unavailable", "technique_id": technique_id}))
        else:
            console.print("[yellow]STIX data not available. Technique lookup requires STIX.[/yellow]")
            console.print("[dim]Install and update: pip install 'athf[attack]' && athf attack update[/dim]")
        return

    tech = get_technique(technique_id)
    if tech is None:
        if as_json:
            print(json.dumps({"error": "not_found", "technique_id": technique_id}))
        else:
            console.print(f"[yellow]Technique {technique_id} not found.[/yellow]")
        return

    if as_json:
        print(
            json.dumps(
                {
                    "id": tech.get("id", ""),
                    "name": tech.get("name", ""),
                    "tactics": tech.get("tactic_shortnames", []),
                    "platforms": tech.get("platforms", []),
                    "is_subtechnique": tech.get("is_subtechnique", False),
                    "parent_id": tech.get("parent_id"),
                }
            )
        )
        return

    console.print(f"\n[bold]{tech.get('id', '')} - {tech.get('name', '')}[/bold]\n")
    _display_technique_fields(tech)

    # Show sub-techniques if this is a parent
    if not tech.get("is_subtechnique", False):
        subs = get_sub_techniques(technique_id)
        if subs:
            console.print(f"\n  [bold]Sub-techniques ({len(subs)}):[/bold]")
            for sub in subs:
                console.print(f"    {sub.get('id', '')} - {sub.get('name', '')}")

    console.print()


def _generate_gap_hunts(gaps: list, limit: int) -> None:
    """Generate draft hunt files for uncovered ATT&CK techniques.

    Iterates up to *limit* gap entries, feeds each into HypothesisGeneratorAgent
    (heuristic mode — no LLM required), and writes a draft hunt file via
    render_hunt_template().  Prints a summary of created files.
    """
    from pathlib import Path

    from athf.agents.llm.hypothesis_generator import (
        HypothesisGenerationInput,
        HypothesisGeneratorAgent,
    )
    from athf.core.hunt_manager import HuntManager
    from athf.core.template_engine import render_hunt_template

    manager = HuntManager()
    agent = HypothesisGeneratorAgent(llm_enabled=False)

    # Read environment context if available
    env_file = Path("knowledge/environment.md")
    env_text = env_file.read_text(encoding="utf-8")[:3000] if env_file.exists() else ""

    targets = gaps[:limit]
    console.print(f"\n[bold cyan]Generating {len(targets)} draft hunt file(s)…[/bold cyan]\n")

    created: list = []
    for entry in targets:
        tech_id = entry["id"]
        tech_name = entry["name"]
        tactic_key = entry["tactic"]

        threat_intel = (
            f"ATT&CK technique {tech_id} — {tech_name} "
            f"(tactic: {tactic_key}) has no existing hunt coverage. "
            f"Platforms: {', '.join(entry.get('platforms', []) or ['unknown'])}."
        )

        result = agent.execute(HypothesisGenerationInput(
            threat_intel=threat_intel,
            past_hunts=[],
            environment={"environment_summary": env_text[:500]} if env_text else {},
        ))

        if not result.is_success or result.data is None:
            console.print(f"  [yellow]⚠ Skipped {tech_id}: agent error[/yellow]")
            continue

        out = result.data
        hunt_id = manager.get_next_hunt_id()

        hunt_content = render_hunt_template(
            hunt_id=hunt_id,
            title=f"Hunt {tech_id}: {tech_name}",
            technique=tech_id,
            tactics=[tactic_key],
            platform=entry.get("platforms") or [],
            data_sources=out.data_sources,
            hypothesis=out.hypothesis,
            threat_context=f"Gap-generated from ATT&CK coverage analysis. {out.justification}",
            actor=out.actor or "",
            behavior=out.behavior or "",
            location=out.location or "",
            evidence=out.evidence or "",
        )

        hunt_dir = Path("hunts")
        hunt_dir.mkdir(parents=True, exist_ok=True)
        hunt_file = hunt_dir / f"{hunt_id}.md"
        hunt_file.write_text(hunt_content, encoding="utf-8")
        created.append((hunt_id, tech_id, tech_name))
        console.print(f"  [green]✓[/green] {hunt_id} — {tech_id}: {tech_name}")

    if created:
        console.print(f"\n[bold]Created {len(created)} draft hunt file(s).[/bold]")
        console.print("[dim]Edit each file to add queries and complete the LOCK section.[/dim]\n")
    else:
        console.print("[yellow]No hunt files were created.[/yellow]\n")


@attack.command()
@click.option("--tactic", "tactic_filter", help="Limit to one tactic (e.g., credential-access)")
@click.option("--platform", "platform_filter", help="Only show techniques for this platform")
@click.option("--no-subtechniques", "no_subs", is_flag=True, help="Exclude sub-techniques")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option(
    "--generate",
    is_flag=True,
    help="Generate draft hunt files for each uncovered technique via hypothesis-generator agent.",
)
@click.option(
    "--limit",
    type=int,
    default=5,
    show_default=True,
    help="Maximum number of hunt files to generate (used with --generate).",
)
def gap(
    tactic_filter: Optional[str],
    platform_filter: Optional[str],
    no_subs: bool,
    output_format: str,
    generate: bool,
    limit: int,
) -> None:
    """Show ATT&CK techniques not yet covered by any hunt.

    Requires STIX data (run 'athf attack update' first).

    \b
    Examples:
      # Show all uncovered techniques
      athf attack gap

      # Limit to one tactic
      athf attack gap --tactic credential-access

      # Filter by platform
      athf attack gap --tactic persistence --platform Windows

      # JSON output for scripting
      athf attack gap --output json

      # Generate draft hunt files for top 5 uncovered techniques
      athf attack gap --tactic credential-access --generate

      # Generate up to 10 draft hunts
      athf attack gap --generate --limit 10
    """
    from athf.core.attack_matrix import (
        get_sorted_tactics,
        get_techniques_for_tactic,
        is_using_stix,
    )
    from athf.core.hunt_manager import HuntManager

    if not is_using_stix():
        console.print("[yellow]STIX data not available. Gap analysis requires STIX.[/yellow]")
        console.print("[dim]Install and update: pip install 'athf[attack]' && athf attack update[/dim]")
        return

    # Build set of covered technique IDs from the hunt corpus
    manager = HuntManager()
    coverage_data = manager.calculate_attack_coverage()
    covered: set = set()
    for tactic_data in coverage_data.get("by_tactic", {}).values():
        covered.update(tactic_data.get("techniques", {}).keys())

    # Determine which tactics to inspect
    tactics = [tactic_filter] if tactic_filter else get_sorted_tactics()

    gaps: list = []
    for tactic_key in tactics:
        techs = get_techniques_for_tactic(tactic_key)
        if not techs:
            continue
        for tech in techs:
            tid = tech.get("id", "")
            if not tid or tid in covered:
                continue
            if no_subs and tech.get("is_subtechnique", False):
                continue
            if platform_filter:
                platforms = [p.lower() for p in tech.get("platforms", [])]
                if platform_filter.lower() not in platforms:
                    continue
            gaps.append({
                "tactic": tactic_key,
                "id": tid,
                "name": tech.get("name", ""),
                "is_subtechnique": tech.get("is_subtechnique", False),
                "platforms": tech.get("platforms", []),
            })

    if not gaps:
        console.print("[green]No gaps found — all techniques are covered![/green]")
        return

    if output_format == "json":
        click.echo(json.dumps(gaps, indent=2))
        return

    console.print(f"\n[bold]ATT&CK Coverage Gaps ({len(gaps)} uncovered techniques)[/bold]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Tactic", style="cyan", width=22)
    table.add_column("ID", style="yellow", width=12)
    table.add_column("Name", style="white")
    table.add_column("Sub?", style="dim", width=4)

    current_tactic = None
    for gap in gaps:
        if gap["tactic"] != current_tactic:
            current_tactic = gap["tactic"]
        sub = "Yes" if gap["is_subtechnique"] else ""
        table.add_row(gap["tactic"], gap["id"], gap["name"], sub)

    console.print(table)
    console.print()

    if generate:
        _generate_gap_hunts(gaps, limit)


@attack.command()
@click.argument("tactic_key")
def techniques(tactic_key: str) -> None:
    """List techniques for a tactic.

    Shows all techniques mapped to the specified tactic key
    (e.g., credential-access, lateral-movement).

    \b
    Examples:
      athf attack techniques credential-access
      athf attack techniques lateral-movement
    """
    from athf.core.attack_matrix import (
        get_tactic_display_name,
        get_techniques_for_tactic,
        is_using_stix,
    )

    if not is_using_stix():
        console.print("[yellow]STIX data not available. Technique listing requires STIX.[/yellow]")
        console.print("[dim]Install and update: pip install 'athf[attack]' && athf attack update[/dim]")
        return

    techs = get_techniques_for_tactic(tactic_key)
    if not techs:
        console.print(f"[yellow]No techniques found for tactic '{tactic_key}'.[/yellow]")
        console.print("[dim]Use a tactic shortname like: credential-access, lateral-movement[/dim]")
        return

    display_name = get_tactic_display_name(tactic_key)
    console.print(f"\n[bold]{display_name}[/bold] ({len(techs)} techniques)\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="white", width=12)
    table.add_column("Name", style="white")
    table.add_column("Sub?", style="dim", width=4)
    table.add_column("Platforms", style="dim")

    for tech in techs:
        is_sub = "Yes" if tech.get("is_subtechnique", False) else ""
        platforms = ", ".join(tech.get("platforms", [])[:3])
        if len(tech.get("platforms", [])) > 3:
            platforms += "..."
        table.add_row(
            tech.get("id", ""),
            tech.get("name", ""),
            is_sub,
            platforms,
        )

    console.print(table)
    console.print()
