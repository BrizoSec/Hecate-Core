"""Investigation creation command: new."""

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.prompt import Prompt

from athf.core.investigation_parser import get_next_investigation_id

console = Console()


def _render_investigation_template(
    investigation_id: str,
    title: str,
    investigator: str,
    investigation_type: str,
    tags: List[str],
    data_sources: List[str],
    related_hunts: List[str],
) -> str:
    """Render investigation template with provided values."""
    today = datetime.now().strftime("%Y-%m-%d")

    frontmatter = {
        "investigation_id": investigation_id,
        "title": title,
        "date": today,
        "investigator": investigator,
        "type": investigation_type,
        "related_hunts": related_hunts,
        "data_sources": data_sources,
        "tags": tags,
    }

    yaml_content = yaml.dump(frontmatter, default_flow_style=False, sort_keys=False)

    content = f"""---
{yaml_content}---

# {investigation_id}: {title}

**Investigation Metadata**

- **Date:** {today}
- **Investigator:** {investigator}
- **Type:** {investigation_type.title()}

---

## LEARN: Context & Background

### Investigation Context

[Why are you investigating this? What prompted the investigation?]

- **Trigger:** [Alert, customer report, anomaly, data quality check, etc.]
- **Initial Observations:** [What was initially noticed?]
- **Scope:** [What are you investigating? Time range? Specific systems?]

### Related Context

- **Related Hunts:** {', '.join(related_hunts) if related_hunts else '[None]'}
- **Past Investigations:** [Reference any related investigations]
- **Threat Intel/CTI:** [Any relevant threat intelligence or context]

---

## OBSERVE: Initial Analysis

### What You're Looking For

[Describe what patterns, behaviors, or anomalies you're investigating]

### Data Sources

- **Index/Data Source:** {', '.join(data_sources) if data_sources else '[Specify data sources]'}
- **Time Range:** [Start datetime] to [End datetime]
- **Key Fields:** [process.name, user, source_ip, etc.]

### Expected vs Observed

**Normal Behavior:**
- [What should normal activity look like?]
- [Common false positives to watch for]

**Suspicious/Anomalous Behavior:**
- [What anomalies are you seeing?]
- [What makes this suspicious or worth investigating?]

---

## CHECK: Investigation Queries & Analysis

### Initial Query

```[language: sql, kql, spl, etc.]
[Your initial investigation query]
```

**Query Results:**

- **Events Found:** [Count]
- **Time to Execute:** [X.X seconds]
- **Initial Findings:** [Brief summary of what was found]

### Refined Analysis

```[language]
[Follow-up queries or refined analysis]
```

**Additional Findings:**

- [Key observations from refined analysis]
- [Patterns or correlations discovered]
- [Anomalies identified]

### Pivots & Follow-ups

[Document any pivots you made during the investigation]

- **Pivot 1:** [What did you investigate next and why?]
- **Pivot 2:** [Additional follow-up investigation]

---

## KEEP: Findings & Next Steps

### Summary

[3-5 sentence summary of the investigation outcome]

- **Verdict:** [Benign | Suspicious | Malicious | Inconclusive | Data Quality Issue]
- **Confidence:** [High | Medium | Low]

### Key Findings

| **Finding** | **Evidence** | **Assessment** |
|-------------|-------------|----------------|
| [Finding 1] | [Supporting evidence] | [Benign/Suspicious/Malicious] |
| [Finding 2] | [Supporting evidence] | [Benign/Suspicious/Malicious] |

### Lessons Learned

**What Worked Well:**

- [Effective investigation strategies]
- [Useful queries or data sources]
- [Tools or techniques that helped]

**What Could Be Improved:**

- [Data gaps or blind spots identified]
- [Better approaches for next time]
- [Telemetry or visibility improvements needed]

### Next Steps

- [ ] [Escalate to incident response if malicious]
- [ ] [Create detection rule if repeatable pattern]
- [ ] [Promote to formal hunt if hypothesis emerges]
- [ ] [Document exceptions or false positive filters]
- [ ] [Address telemetry gaps]
- [ ] [Follow-up investigation if needed]

---

**Investigation Completed:** [Date or "Ongoing"]
**Status:** [Closed|In Progress|Escalated|Promoted to Hunt]
"""

    return content


@click.command()
@click.option("--title", help="Investigation title")
@click.option(
    "--type",
    "investigation_type",
    type=click.Choice(["finding", "baseline", "exploratory", "other"]),
    help="Investigation type",
)
@click.option("--tags", help="Comma-separated tags (e.g., alert-triage,powershell)")
@click.option("--data-source", multiple=True, help="Data sources (can specify multiple)")
@click.option("--related-hunt", multiple=True, help="Related hunt IDs (e.g., H-0013)")
@click.option("--investigator", help="Investigator name", default="ATHF")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def new(
    title: Optional[str],
    investigation_type: Optional[str],
    tags: Optional[str],
    data_source: Tuple[str, ...],
    related_hunt: Tuple[str, ...],
    investigator: Optional[str],
    non_interactive: bool,
) -> None:
    """Create a new investigation file.

    \b
    Creates an investigation file with:
    • Auto-generated investigation ID (I-XXXX format)
    • Minimal YAML frontmatter
    • Optional LOCK structure for flexible documentation

    \b
    Interactive mode (default):
      Guides you through investigation creation with prompts.
      Example: athf investigate new

    \b
    Non-interactive mode:
      Provide all details via options for scripting.
      Example: athf investigate new --title "Alert Triage" \\
               --type finding --tags alert-triage --non-interactive

    \b
    After creation:
      1. Edit investigations/I-XXXX.md to document your investigation
      2. Use LOCK pattern sections (optional/flexible)
      3. Optionally promote to hunt: athf investigate promote I-XXXX
    """
    console.print("\n[bold cyan]Creating new investigation[/bold cyan]\n")

    investigations_dir = Path("investigations")
    investigations_dir.mkdir(exist_ok=True)

    investigation_id = get_next_investigation_id(investigations_dir)
    console.print(f"[bold]Investigation ID:[/bold] {investigation_id}")

    if non_interactive:
        if not title:
            console.print("[red]Error: --title required in non-interactive mode[/red]")
            return
        inv_title = title
        inv_type = investigation_type or "exploratory"
        inv_tags = [t.strip() for t in tags.split(",")] if tags else []
        inv_data_sources = list(data_source) if data_source else []
        inv_related_hunts = list(related_hunt) if related_hunt else []
    else:
        console.print("\n[bold]Let's set up your investigation:[/bold]")

        inv_title = Prompt.ask("1. Investigation Title", default=title or "")

        console.print("\n2. Investigation Type:")
        console.print("   [cyan]finding[/cyan]     - Alert triage or specific finding investigation")
        console.print("   [cyan]baseline[/cyan]    - Data source baselining or normal behavior analysis")
        console.print("   [cyan]exploratory[/cyan] - Ad-hoc exploration or query sandbox")
        console.print("   [cyan]other[/cyan]       - Miscellaneous investigation")
        inv_type = Prompt.ask(
            "   Type",
            default=investigation_type or "exploratory",
            choices=["finding", "baseline", "exploratory", "other"],
        )

        console.print("\n3. Tags (comma-separated, optional):")
        console.print("   Examples: [cyan]alert-triage, powershell, customer-x[/cyan]")
        tags_input = Prompt.ask("   Tags", default=tags or "")
        inv_tags = [t.strip() for t in tags_input.split(",")] if tags_input else []

        console.print("\n4. Data Sources (comma-separated, optional):")
        console.print("   Examples: [cyan]ClickHouse, EDR, CloudTrail[/cyan]")
        ds_input = Prompt.ask("   Data Sources", default="")
        inv_data_sources = [ds.strip() for ds in ds_input.split(",")] if ds_input else []

        console.print("\n5. Related Hunts (comma-separated IDs, optional):")
        console.print("   Examples: [cyan]H-0013, H-0042[/cyan]")
        hunts_input = Prompt.ask("   Related Hunts", default="")
        inv_related_hunts = [h.strip() for h in hunts_input.split(",")] if hunts_input else []

    investigation_content = _render_investigation_template(
        investigation_id=investigation_id,
        title=inv_title,
        investigator=investigator or "ATHF",
        investigation_type=inv_type,
        tags=inv_tags,
        data_sources=inv_data_sources,
        related_hunts=inv_related_hunts,
    )

    investigation_file = investigations_dir / f"{investigation_id}.md"

    try:
        investigation_file.resolve().relative_to(investigations_dir.resolve())
    except (ValueError, OSError):
        console.print("[red]Error: Invalid investigation file path[/red]")
        return

    with open(investigation_file, "w", encoding="utf-8") as f:
        f.write(investigation_content)

    console.print(f"\n[bold green]Created {investigation_id}: {inv_title}[/bold green]")

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{investigation_file}[/cyan] to document your investigation")
    console.print("  2. Use LOCK pattern sections (optional/flexible)")
    console.print("  3. View all investigations: [cyan]athf investigate list[/cyan]")
    console.print(f"  4. Promote to hunt if valuable: [cyan]athf investigate promote {investigation_id}[/cyan]")
