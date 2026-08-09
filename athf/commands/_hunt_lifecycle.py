"""Hunt lifecycle commands: promote, export, brief."""

import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.prompt import Prompt

from athf.core.hunt_manager import HuntManager, get_hunt_directory
from athf.utils.validation import validate_hunt_id

console = Console()


def _load_linked_research(research_id: str, research_dir: Path) -> Optional[Dict[str, Any]]:
    """Load a linked research document by ID.

    Args:
        research_id: Research ID (e.g., R-0008)
        research_dir: Path to research directory

    Returns:
        Dict with research frontmatter and sections, or None if not found
    """
    research_file = research_dir / f"{research_id}.md"
    if not research_file.exists():
        return None

    try:
        from athf.core.research_manager import parse_research_file

        research_data = parse_research_file(research_file)
        frontmatter = research_data.get("frontmatter", {})

        return {
            "research_id": frontmatter.get("research_id"),
            "topic": frontmatter.get("topic"),
            "mitre_techniques": frontmatter.get("mitre_techniques", []),
            "status": frontmatter.get("status"),
            "depth": frontmatter.get("depth"),
            "duration_minutes": frontmatter.get("duration_minutes"),
            "data_source_availability": frontmatter.get("data_source_availability", {}),
            "estimated_hunt_complexity": frontmatter.get("estimated_hunt_complexity"),
            "created_date": frontmatter.get("created_date"),
            "sections": research_data.get("sections", {}),
            "file_path": str(research_file),
        }
    except Exception:
        return None


def _json_serializer(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def _load_sessions_for_hunt(hunt_id: str, sessions_dir: Path) -> List[Dict[str, Any]]:
    """Load all session data for a hunt from the sessions directory.

    Reads session.yaml, decisions.yaml, findings.yaml, and queries.yaml
    from each matching session directory.

    Args:
        hunt_id: Hunt ID to find sessions for (e.g., H-0027)
        sessions_dir: Path to sessions directory

    Returns:
        List of session dicts with all available data
    """
    sessions: List[Dict[str, Any]] = []

    if not sessions_dir.exists():
        return sessions

    for session_dir in sorted(sessions_dir.iterdir()):
        if not session_dir.is_dir() or session_dir.name.startswith("."):
            continue

        session_file = session_dir / "session.yaml"
        if not session_file.exists():
            continue

        try:
            with open(session_file, "r", encoding="utf-8") as f:
                session_data = yaml.safe_load(f) or {}

            if session_data.get("hunt_id") != hunt_id:
                continue

            # Load optional YAML files
            for yaml_name in ("decisions", "findings", "queries"):
                yaml_file = session_dir / f"{yaml_name}.yaml"
                if yaml_file.exists():
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        extra_data = yaml.safe_load(f) or {}
                    session_data[yaml_name] = extra_data.get(yaml_name, [])

            sessions.append(session_data)
        except Exception:
            continue

    return sessions


def _build_export_dict(
    hunt_data: Dict[str, Any],
    sessions_dir: Path,
    include_content: bool,
    no_sessions: bool,
) -> Dict[str, Any]:
    """Build the export dictionary for a single hunt.

    Args:
        hunt_data: Parsed hunt data from HuntParser
        sessions_dir: Path to sessions directory
        include_content: Whether to include raw markdown
        no_sessions: Whether to exclude sessions

    Returns:
        Dict ready for JSON serialization
    """
    frontmatter = hunt_data.get("frontmatter", {})
    hunt_id = frontmatter.get("hunt_id", "")

    export: Dict[str, Any] = {
        "hunt_id": hunt_id,
        "title": frontmatter.get("title"),
        "status": frontmatter.get("status"),
        "date": frontmatter.get("date"),
        "hunter": frontmatter.get("hunter"),
        "platform": frontmatter.get("platform", []),
        "tactics": frontmatter.get("tactics", []),
        "techniques": frontmatter.get("techniques", []),
        "data_sources": frontmatter.get("data_sources", []),
        "related_hunts": frontmatter.get("related_hunts", []),
        "spawned_from": frontmatter.get("spawned_from"),
        "findings_count": frontmatter.get("findings_count", 0),
        "true_positives": frontmatter.get("true_positives", 0),
        "false_positives": frontmatter.get("false_positives", 0),
        "events_scanned": frontmatter.get("events_scanned"),
        "tags": frontmatter.get("tags", []),
        "lock_sections": hunt_data.get("lock_sections", {}),
        "file_path": hunt_data.get("file_path"),
    }

    if include_content:
        export["content"] = hunt_data.get("content", "")

    # Load linked research document
    spawned_from = frontmatter.get("spawned_from")
    if spawned_from:
        research_dir = Path("research")
        research = _load_linked_research(spawned_from, research_dir)
        if research:
            export["research"] = research

    if not no_sessions:
        export["sessions"] = _load_sessions_for_hunt(hunt_id, sessions_dir)

    return export


def _extract_subsection(section_text: str, heading: str) -> str:
    """Extract a ``### heading`` subsection's body from a LOCK section's markdown text.

    Args:
        section_text: Raw markdown for a whole LOCK section (e.g. lock_sections["keep"]).
        heading: The ``###`` subsection heading to find (e.g. "Executive Summary").

    Returns:
        The subsection body, or empty string if the heading isn't present.
    """
    pattern = rf"###\s+{re.escape(heading)}\s*\n(.*?)(?=\n###\s+|\Z)"
    match = re.search(pattern, section_text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _is_unfilled(text: str) -> bool:
    """True if every line of a subsection is blank, a markdown table separator
    row, a bold table header row, or contains only bracketed template
    placeholders like ``[TBD]`` -- covers plain placeholder prose (Executive
    Summary) as well as placeholder table rows (``| [Type] | [Ticket] |``)
    and checklist items (``- [ ] [Action item]``), which don't fullmatch a
    single ``[...]`` span the way a simple placeholder line does.
    """
    stripped = text.strip()
    if not stripped:
        return True

    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r"[|\-:\s]+", line):  # table separator row, e.g. "|---|---|"
            continue
        if re.fullmatch(r"(\|\s*\*\*[^*]+\*\*\s*)+\|?", line):  # bold table header row
            continue
        line = re.sub(r"^-\s*\[\s?\]\s*", "", line)  # strip a leading checklist checkbox
        cells = [c.strip() for c in line.split("|") if c.strip()] or [line]
        for cell in cells:
            if not re.fullmatch(r"\[.*\]", cell, re.DOTALL):
                return False
    return True


_STAT_LINE_RE = re.compile(r"\*\*(True Positives|False Positives|Candidate Anomalies Found):\*\*")


def _strip_stat_lines(text: str) -> str:
    """Drop redundant ``**True/False Positives:**``/``**Candidate Anomalies Found:**``
    lines that are shown as their own stat line elsewhere in the brief (the
    header, for TP/FP) or would otherwise be the only "content" keeping a
    placeholder-only table from being recognized as unfilled by _is_unfilled.
    """
    kept = [line for line in text.splitlines() if not _STAT_LINE_RE.match(line.strip())]
    return "\n".join(kept).strip()


def _as_text(value: Any) -> str:
    """Coerce a frontmatter scalar field to a clean display string.

    Frontmatter fields like ``hunter`` are meant to be plain strings, but a
    stray YAML flow-sequence (``hunter: [Your Name]`` instead of a quoted
    string) parses as a one-element list -- shown as-is, that renders as the
    Python repr ``['Your Name']`` instead of the intended text.
    """
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else ""


def _build_brief_header(frontmatter: Dict[str, Any], *, hunt_type: Optional[str] = None, is_baseline: bool = False) -> List[str]:
    """Build the title/status/type line(s) common to all brief variants."""
    hunt_id = _as_text(frontmatter.get("hunt_id", ""))
    title = _as_text(frontmatter.get("title", ""))
    status = _as_text(frontmatter.get("status", ""))
    hunt_date = _as_text(frontmatter.get("date", ""))
    hunter = _as_text(frontmatter.get("hunter", ""))

    lines = [f"# Hunt Brief: {hunt_id} — {title}", ""]
    lines.append(f"**Status:** {status}  |  **Date:** {hunt_date}  |  **Hunter:** {hunter}")

    _ht = hunt_type or ("baseline" if is_baseline else None)
    if _ht == "baseline":
        dimension = _as_text(frontmatter.get("dimension", ""))
        if dimension:
            lines.append(f"**Type:** Baseline (EDA)  |  **Dimension:** {dimension}")
    elif _ht == "model-assisted":
        model_type = _as_text(frontmatter.get("model_type", ""))
        features = frontmatter.get("features", [])
        features_str = ", ".join(features) if isinstance(features, list) else _as_text(features)
        type_line = "**Type:** Model-Assisted (M-ATH)"
        if model_type:
            type_line += f"  |  **Model:** {model_type}"
        if features_str:
            type_line += f"  |  **Features:** {features_str}"
        lines.append(type_line)
    else:
        tactics = ", ".join(frontmatter.get("tactics", []) or [])
        techniques = ", ".join(frontmatter.get("techniques", []) or [])
        if tactics or techniques:
            separator = " / " if tactics and techniques else ""
            lines.append(f"**MITRE ATT&CK:** {tactics}{separator}{techniques}")

    lines.append("")
    return lines


def _build_baseline_brief_body(frontmatter: Dict[str, Any], lock_sections: Dict[str, str]) -> List[str]:
    """Build the objective/normal/anomalies/spawned-hunts body for a baseline hunt brief."""
    learn = lock_sections.get("learn", "")
    check = lock_sections.get("check", "")
    keep = lock_sections.get("keep", "")

    objective = _extract_subsection(learn, "Baseline Objective")
    established_normal = _extract_subsection(check, "Results: What Normal Actually Looks Like")
    anomalies = _strip_stat_lines(_extract_subsection(keep, "Candidate Anomalies"))
    spawned_hunts = _extract_subsection(keep, "Spawned Hunts")

    lines: List[str] = []
    if not _is_unfilled(objective):
        lines += ["## Baseline Objective", objective, ""]

    if not _is_unfilled(established_normal):
        lines += ["## What Normal Looks Like", established_normal, ""]

    lines += ["## Candidate Anomalies", ""]
    lines += [anomalies if not _is_unfilled(anomalies) else "None identified yet.", ""]

    if not _is_unfilled(spawned_hunts):
        lines += ["## Spawned Hunts", spawned_hunts, ""]

    return lines


def _build_math_brief_body(frontmatter: Dict[str, Any], lock_sections: Dict[str, str]) -> List[str]:
    """Build the objective/anomalies/leads/spawned-hunts body for a model-assisted hunt brief."""
    learn = lock_sections.get("learn", "")
    check = lock_sections.get("check", "")
    keep = lock_sections.get("keep", "")

    objective = _extract_subsection(learn, "Model Objective")
    anomalies_surfaced = _extract_subsection(check, "Results: Anomalies Surfaced")
    candidate_leads = _strip_stat_lines(_extract_subsection(keep, "Candidate Leads"))
    model_params = _extract_subsection(keep, "Model Parameters to Reuse")
    spawned_hunts = _extract_subsection(keep, "Spawned Hunts")

    lines: List[str] = []
    if not _is_unfilled(objective):
        lines += ["## Model Objective", objective, ""]

    if not _is_unfilled(anomalies_surfaced):
        lines += ["## Anomalies Surfaced", anomalies_surfaced, ""]

    lines += ["## Candidate Leads", ""]
    lines += [candidate_leads if not _is_unfilled(candidate_leads) else "None identified yet.", ""]

    if not _is_unfilled(model_params):
        lines += ["## Model Parameters", model_params, ""]

    if not _is_unfilled(spawned_hunts):
        lines += ["## Spawned Hunts", spawned_hunts, ""]

    return lines


def _build_hypothesis_brief_body(frontmatter: Dict[str, Any], lock_sections: Dict[str, str]) -> List[str]:
    """Build the hypothesis/summary/findings/detection body for a hypothesis-driven hunt brief."""
    learn = lock_sections.get("learn", "")
    keep = lock_sections.get("keep", "")

    true_positives = frontmatter.get("true_positives", 0)
    false_positives = frontmatter.get("false_positives", 0)
    hypothesis = _extract_subsection(learn, "Hypothesis Statement")
    exec_summary = _extract_subsection(keep, "Executive Summary")
    findings = _strip_stat_lines(_extract_subsection(keep, "Findings"))
    detection = _extract_subsection(keep, "Detection Logic")
    follow_up = _extract_subsection(keep, "Follow-up Actions")

    lines: List[str] = []
    if not _is_unfilled(hypothesis):
        lines += ["## Hypothesis", hypothesis, ""]

    if not _is_unfilled(exec_summary):
        lines += ["## Summary", exec_summary, ""]

    lines += ["## Findings", f"**True Positives:** {true_positives}  |  **False Positives:** {false_positives}", ""]
    if not _is_unfilled(findings):
        lines += [findings, ""]

    if not _is_unfilled(detection):
        lines += ["## Detection & Automation", detection, ""]

    if not _is_unfilled(follow_up):
        lines += ["## Follow-up Actions", follow_up, ""]

    return lines


def _build_brief(hunt_data: Dict[str, Any]) -> str:
    """Build a condensed, stakeholder-facing markdown brief for a hunt.

    Baseline hunts (hunt_type: baseline) have no hypothesis, so they get a
    different set of subsections -- see _build_baseline_brief_body vs.
    _build_hypothesis_brief_body. Both skip internal hunter-only detail
    (query iteration, lessons learned).

    Args:
        hunt_data: Parsed hunt data from HuntManager.get_hunt().

    Returns:
        Markdown text of the brief.
    """
    frontmatter = hunt_data.get("frontmatter", {})
    lock_sections = hunt_data.get("lock_sections", {})
    hunt_type = frontmatter.get("hunt_type")

    lines = _build_brief_header(frontmatter, hunt_type=hunt_type)
    if hunt_type == "baseline":
        lines += _build_baseline_brief_body(frontmatter, lock_sections)
    elif hunt_type == "model-assisted":
        lines += _build_math_brief_body(frontmatter, lock_sections)
    else:
        lines += _build_hypothesis_brief_body(frontmatter, lock_sections)

    return "\n".join(lines).rstrip() + "\n"


@click.command(name="update")
@click.argument("hunt_id")
@click.option("--status", help="Set status (planning, active, in_review, completed, archived)")
@click.option("--title", help="Update hunt title")
@click.option("--hunter", help="Update hunter name")
@click.option("--assignee", help="Assign the hunt to a team member")
@click.option("--reviewer", help="Set the reviewer for the hunt")
@click.option("--true-positives", "true_positives", type=int, help="Set true positives count")
@click.option("--false-positives", "false_positives", type=int, help="Set false positives count")
@click.option("--findings-count", "findings_count", type=int, help="Set findings count")
@click.option("--add-tag", "add_tags", multiple=True, help="Add tag(s) to the hunt")
@click.option("--remove-tag", "remove_tags", multiple=True, help="Remove tag(s) from the hunt")
def update_hunt(
    hunt_id: str,
    status: Optional[str],
    title: Optional[str],
    hunter: Optional[str],
    assignee: Optional[str],
    reviewer: Optional[str],
    true_positives: Optional[int],
    false_positives: Optional[int],
    findings_count: Optional[int],
    add_tags: Tuple,
    remove_tags: Tuple,
) -> None:
    """Update frontmatter fields in a hunt file.

    \b
    Patches YAML frontmatter in-place without touching the markdown body.

    \b
    Examples:
      # Mark a hunt as completed
      athf hunt update H-0042 --status completed

      # Record findings
      athf hunt update H-0042 --true-positives 3 --false-positives 1

      # Add tags
      athf hunt update H-0042 --add-tag lateral-movement --add-tag rdp

      # Combine updates
      athf hunt update H-0042 --status completed --true-positives 2 --findings-count 5
    """
    if not validate_hunt_id(hunt_id):
        console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
        return

    manager = HuntManager()
    hunt_file = manager.find_hunt_file(hunt_id)
    if not hunt_file:
        console.print(f"[red]Error: Hunt not found: {hunt_id}[/red]")
        return

    with open(hunt_file, "r", encoding="utf-8") as f:
        raw = f.read()

    # Split on the closing --- of the frontmatter
    parts = raw.split("---", 2)
    if len(parts) < 3:
        console.print(f"[red]Error: Could not parse frontmatter in {hunt_file.name}[/red]")
        return

    try:
        fm = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as e:
        console.print(f"[red]Error: Invalid YAML frontmatter: {e}[/red]")
        return

    # Apply updates
    changed: List[str] = []
    if status is not None:
        fm["status"] = status
        changed.append(f"status → {status}")
    if title is not None:
        fm["title"] = title
        changed.append(f"title → {title}")
    if hunter is not None:
        fm["hunter"] = hunter
        changed.append(f"hunter → {hunter}")
    if assignee is not None:
        fm["assignee"] = assignee
        changed.append(f"assignee → {assignee}")
    if reviewer is not None:
        fm["reviewer"] = reviewer
        changed.append(f"reviewer → {reviewer}")
    if true_positives is not None:
        fm["true_positives"] = true_positives
        changed.append(f"true_positives → {true_positives}")
    if false_positives is not None:
        fm["false_positives"] = false_positives
        changed.append(f"false_positives → {false_positives}")
    if findings_count is not None:
        fm["findings_count"] = findings_count
        changed.append(f"findings_count → {findings_count}")
    if add_tags:
        current_tags: List[str] = fm.get("tags") or []
        for tag in add_tags:
            if tag not in current_tags:
                current_tags.append(tag)
        fm["tags"] = current_tags
        changed.append(f"tags +{list(add_tags)}")
    if remove_tags:
        current_tags = fm.get("tags") or []
        fm["tags"] = [t for t in current_tags if t not in remove_tags]
        changed.append(f"tags -{list(remove_tags)}")

    if not changed:
        console.print("[yellow]No updates specified — nothing changed.[/yellow]")
        console.print("[dim]Use --status, --true-positives, --add-tag, etc.[/dim]")
        return

    new_fm = yaml.dump(fm, default_flow_style=False, sort_keys=False)
    updated = f"---\n{new_fm}---{parts[2]}"

    with open(hunt_file, "w", encoding="utf-8") as f:
        f.write(updated)

    console.print(f"\n[bold green]✅ Updated {hunt_id}[/bold green]")
    for change in changed:
        console.print(f"  [dim]{change}[/dim]")
    console.print()


def _sigma_logsource(platforms: List[str], data_sources: List[str]) -> dict:
    """Derive a best-effort Sigma logsource block from hunt metadata."""
    platform_str = " ".join(platforms).lower()
    ds_str = " ".join(data_sources).lower()

    product = "windows"
    if "linux" in platform_str:
        product = "linux"
    elif "macos" in platform_str or "mac" in platform_str:
        product = "macos"
    elif "cloud" in platform_str or "aws" in platform_str or "azure" in platform_str:
        product = "aws"  # best guess; hunter should verify

    category = "process_creation"
    if "network" in ds_str or "proxy" in ds_str or "dns" in ds_str:
        category = "network_connection"
    elif "auth" in ds_str or "logon" in ds_str or "login" in ds_str:
        category = "authentication"
    elif "file" in ds_str:
        category = "file_event"
    elif "registry" in ds_str:
        category = "registry_event"

    return {"category": category, "product": product}


def _sigma_tags(tactics: List[str], techniques: List[str]) -> List[str]:
    """Build Sigma ATT&CK tag list from hunt tactics and techniques."""
    tags: List[str] = []
    for tactic in tactics:
        tags.append(f"attack.{tactic.replace('-', '_')}")
    for technique in techniques:
        tags.append(f"attack.{technique.lower()}")
    return tags


def _extract_check_queries(check_section: str) -> List[str]:
    """Extract all fenced code blocks from a CHECK section."""
    import re
    return re.findall(r"```[^\n]*\n(.*?)```", check_section, re.DOTALL)


@click.command(name="operationalize")
@click.argument("hunt_id")
@click.option("--query-index", "query_index", type=int, default=None,
              help="Index (1-based) of the query to use when multiple are found. Skips interactive prompt.")
@click.option("--output", "output_file", type=click.Path(), default=None,
              help="Sigma rule output path (default: detections/<hunt_id>.yml)")
@click.option("--no-patch", is_flag=True,
              help="Do not update the hunt frontmatter with detection_rule path")
def operationalize(hunt_id: str, query_index: Optional[int], output_file: Optional[str], no_patch: bool) -> None:
    """Generate a Sigma detection rule stub from a completed hunt.

    \b
    Extracts the hunt query from the CHECK section and generates a Sigma
    YAML stub at detections/<hunt_id>.yml. The detection logic is preserved
    as a comment — the hunter translates it into proper Sigma field conditions.

    \b
    Examples:
      # Interactive — pick a query when multiple are found
      athf hunt operationalize H-0042

      # Non-interactive — use the first query
      athf hunt operationalize H-0042 --query-index 1

      # Custom output path
      athf hunt operationalize H-0042 --output sigma/lsass-dump.yml

    \b
    After generation:
      1. Open detections/<hunt_id>.yml
      2. Replace the placeholder detection.selection block with real Sigma conditions
      3. Validate with: sigma check detections/<hunt_id>.yml
    """
    import uuid

    from athf.core.hunt_manager import HuntManager
    from athf.core.hunt_parser import parse_hunt_file
    from athf.utils.validation import validate_hunt_id

    if not validate_hunt_id(hunt_id):
        console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
        return

    manager = HuntManager()
    hunt_file = manager.find_hunt_file(hunt_id)
    if not hunt_file:
        console.print(f"[red]Error: Hunt not found: {hunt_id}[/red]")
        return

    hunt_data = parse_hunt_file(hunt_file)
    frontmatter = hunt_data.get("frontmatter", {})
    lock_sections = hunt_data.get("lock_sections", {})

    check_section = lock_sections.get("check", "")
    queries = _extract_check_queries(check_section)
    queries = [q.strip() for q in queries if q.strip()]

    if not queries:
        console.print(f"[yellow]No fenced code blocks found in the CHECK section of {hunt_id}.[/yellow]")
        console.print("[dim]Add your final query inside a fenced code block (``` ... ```) in the CHECK section.[/dim]")
        return

    # Determine which query to use
    chosen_query: str
    if len(queries) == 1:
        chosen_query = queries[0]
        console.print(f"[dim]Using the single query found in CHECK section.[/dim]")
    elif query_index is not None:
        idx = query_index - 1
        if not (0 <= idx < len(queries)):
            console.print(f"[red]Error: --query-index {query_index} out of range (1–{len(queries)})[/red]")
            return
        chosen_query = queries[idx]
    else:
        console.print(f"\n[bold]{len(queries)} queries found in CHECK section:[/bold]\n")
        for i, q in enumerate(queries, 1):
            preview = q[:120].replace("\n", " ")
            console.print(f"  [cyan]{i}.[/cyan] {preview}{'...' if len(q) > 120 else ''}")
        console.print()
        choice = Prompt.ask("Select query to use", choices=[str(i) for i in range(1, len(queries) + 1)], default="1")
        chosen_query = queries[int(choice) - 1]

    # Build Sigma YAML
    title = frontmatter.get("title") or hunt_id
    hunter = frontmatter.get("hunter") or "unknown"
    today = datetime.now().strftime("%Y/%m/%d")
    rule_id = str(uuid.uuid4())

    tactics: List[str] = frontmatter.get("tactics") or []
    techniques: List[str] = frontmatter.get("techniques") or []
    platforms: List[str] = frontmatter.get("platform") or []
    data_sources: List[str] = frontmatter.get("data_sources") or []

    logsource = _sigma_logsource(platforms, data_sources)
    tags = _sigma_tags(tactics, techniques)

    # Indent the query as a YAML block comment
    query_comment = "\n".join(f"    #   {line}" for line in chosen_query.splitlines())

    # Build platforms/data_sources comment lines
    meta_comment = ""
    if platforms:
        meta_comment += f"    # Platform: {', '.join(platforms)}\n"
    if data_sources:
        meta_comment += f"    # Data source: {', '.join(data_sources)}\n"

    tags_yaml = "\n".join(f"  - {t}" for t in tags) if tags else "  - attack.unknown"

    sigma_yaml = f"""title: {title}
id: {rule_id}
status: experimental
description: >
  {title} - extracted from ATHF hunt {hunt_id}.
  TODO: Translate the hunt query in the detection block into proper Sigma conditions.
references:
  - 'athf://hunts/{hunt_id}'
author: {hunter}
date: {today}
tags:
{tags_yaml}
logsource:
{meta_comment}  category: {logsource['category']}
  product: {logsource['product']}
detection:
  selection:
    # TODO: Replace this placeholder with real Sigma detection conditions.
    # Hunt query extracted from {hunt_id} CHECK section:
    #
{query_comment}
    #
    # Example field conditions (delete and replace with real Sigma fields):
    Image|endswith: '\\\\example.exe'
  condition: selection
falsepositives:
  - Unknown
level: medium
"""

    # Write Sigma file
    dest = Path(output_file) if output_file else Path("detections") / f"{hunt_id}.yml"
    dest.parent.mkdir(parents=True, exist_ok=True)

    with open(dest, "w", encoding="utf-8") as f:
        f.write(sigma_yaml)

    console.print(f"\n[bold green]Sigma rule stub written to {dest}[/bold green]")
    console.print(f"  Title:    {title}")
    console.print(f"  Logsource: {logsource['product']} / {logsource['category']}")
    if tags:
        console.print(f"  Tags:     {', '.join(tags)}")
    console.print()

    # Patch hunt frontmatter unless --no-patch
    if not no_patch:
        with open(hunt_file, "r", encoding="utf-8") as f:
            raw = f.read()

        parts = raw.split("---", 2)
        if len(parts) >= 3:
            try:
                fm = yaml.safe_load(parts[1]) or {}
                fm["detection_rule"] = str(dest)
                new_fm = yaml.dump(fm, default_flow_style=False, sort_keys=False)
                with open(hunt_file, "w", encoding="utf-8") as f:
                    f.write(f"---\n{new_fm}---{parts[2]}")
                console.print(f"[dim]Updated {hunt_id} frontmatter: detection_rule → {dest}[/dim]")
            except yaml.YAMLError:
                console.print("[yellow]Warning: Could not patch hunt frontmatter (YAML parse error)[/yellow]")

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{dest}[/cyan] — replace the placeholder detection block with real Sigma conditions")
    console.print("  2. Validate: [cyan]sigma check " + str(dest) + "[/cyan]")
    console.print("  3. Convert to SIEM query: [cyan]sigma convert -t splunk " + str(dest) + "[/cyan]")
    console.print()


@click.command(name="promote")
@click.argument("hunt_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def promote_hunt(hunt_id: str, yes: bool) -> None:
    """Promote a hunt from test to production.

    \b
    Moves a hunt file from hunts/test/... to hunts/production/...
    while preserving its hunt ID and updating the file path.

    \b
    Examples:
      # Promote a test hunt to production
      athf hunt promote H-0042

      # Skip confirmation
      athf hunt promote H-0042 --yes

    \b
    After promotion:
      • Hunt file moved to production directory
      • Original test file removed
      • Hunt ID preserved (no renumbering)
    """
    import shutil

    if not validate_hunt_id(hunt_id):
        console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
        console.print("[yellow]Expected format: H-0001[/yellow]")
        return

    manager = HuntManager()
    hunt_file = manager.find_hunt_file(hunt_id)

    if not hunt_file:
        console.print(f"[red]Error: Hunt not found: {hunt_id}[/red]")
        return

    # Check hunt is in test directory
    if "test" not in hunt_file.parts:
        console.print(f"[yellow]{hunt_id} is not in a test directory: {hunt_file}[/yellow]")
        return

    # Calculate production destination
    prod_dir = get_hunt_directory(is_test=False)
    prod_file = prod_dir / f"{hunt_id}.md"

    console.print(f"\n[bold cyan]🔄 Promoting {hunt_id} to production[/bold cyan]\n")
    console.print(f"  [dim]From:[/dim] {hunt_file}")
    console.print(f"  [dim]To:  [/dim] {prod_file}\n")

    if prod_file.exists():
        console.print(f"[red]Error: Destination already exists: {prod_file}[/red]")
        return

    if not yes:
        confirm = Prompt.ask("Proceed with promotion?", choices=["y", "n"], default="y")
        if confirm != "y":
            console.print("[dim]Promotion cancelled.[/dim]")
            return

    # Move the file
    prod_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(hunt_file), str(prod_file))

    console.print(f"[bold green]✅ Promoted {hunt_id} to production[/bold green]")
    console.print(f"  [dim]{prod_file}[/dim]\n")


@click.command(name="export")
@click.argument("hunt_id", required=False)
@click.option("--all", "export_all", is_flag=True, help="Export all hunts")
@click.option("--output", "output_file", type=click.Path(), help="Write to file instead of stdout")
@click.option("--include-content", is_flag=True, help="Include raw markdown content in output")
@click.option("--no-sessions", is_flag=True, help="Exclude session data from export")
@click.option("--status", help="Filter by status when using --all (planning, active, completed)")
def export_hunt(
    hunt_id: Optional[str],
    export_all: bool,
    output_file: Optional[str],
    include_content: bool,
    no_sessions: bool,
    status: Optional[str],
) -> None:
    """Export hunt data as structured JSON.

    \b
    Exports full hunt data including frontmatter, LOCK sections,
    and associated session data (decisions, findings, queries).

    \b
    Examples:
      # Export a single hunt
      athf hunt export H-0027

      # Export all hunts
      athf hunt export --all

      # Export to file
      athf hunt export H-0027 --output hunt-0027.json

      # Export with raw markdown content
      athf hunt export H-0027 --include-content

      # Export without session data
      athf hunt export H-0027 --no-sessions

      # Export all completed hunts
      athf hunt export --all --status completed

    \b
    Use this to:
      • Feed hunt data into external tools and dashboards
      • Create machine-readable hunt reports
      • Power graph databases and analytics pipelines
      • Archive hunts in structured format
    """
    if not hunt_id and not export_all:
        console.print("[red]Error: Provide a hunt ID or use --all[/red]")
        console.print("[dim]Example: athf hunt export H-0027[/dim]")
        console.print("[dim]         athf hunt export --all[/dim]")
        raise click.Abort()

    manager = HuntManager()
    sessions_dir = Path("sessions")

    if export_all:
        hunts = manager.list_hunts(status=status)
        if not hunts:
            console.print("[yellow]No hunts found.[/yellow]")
            return

        export_data: List[Dict[str, Any]] = []
        for hunt_summary in hunts:
            hid = hunt_summary.get("hunt_id")
            if not hid:
                continue
            hunt_data = manager.get_hunt(hid)
            if not hunt_data:
                continue
            export_data.append(_build_export_dict(hunt_data, sessions_dir, include_content, no_sessions))

        result = json.dumps(export_data, indent=2, default=_json_serializer)

    else:
        if not validate_hunt_id(hunt_id):  # type: ignore[arg-type]
            console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
            console.print("[yellow]Expected format: H-0001[/yellow]")
            raise click.Abort()

        hunt_data = manager.get_hunt(hunt_id)  # type: ignore[arg-type]
        if not hunt_data:
            console.print(f"[red]Error: Hunt not found: {hunt_id}[/red]")
            raise click.Abort()

        export_dict = _build_export_dict(hunt_data, sessions_dir, include_content, no_sessions)
        result = json.dumps(export_dict, indent=2, default=_json_serializer)

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result)
            f.write("\n")
        console.print(f"[green]Exported to {output_path}[/green]")
    else:
        click.echo(result)


@click.command(name="brief")
@click.argument("hunt_id")
@click.option("--output", "output_file", type=click.Path(), help="Write to file instead of stdout")
def brief(hunt_id: str, output_file: Optional[str]) -> None:
    """Render a condensed, stakeholder-facing summary of a hunt.

    \b
    This is the PEAK framework's "Brief" step: hypothesis, executive
    summary, findings, and detection/automation outcome -- without the
    internal query-iteration or lessons-learned detail meant for the
    hunter, not the audience.

    \b
    Examples:
      athf hunt brief H-0027
      athf hunt brief H-0027 --output brief-0027.md
    """
    if not validate_hunt_id(hunt_id):
        console.print(f"[red]Error: Invalid hunt ID format: {hunt_id}[/red]")
        console.print("[dim]Example: athf hunt brief H-0027[/dim]")
        raise click.Abort()

    manager = HuntManager()
    hunt_data = manager.get_hunt(hunt_id)
    if not hunt_data:
        console.print(f"[red]Error: Hunt not found: {hunt_id}[/red]")
        raise click.Abort()

    brief_text = _build_brief(hunt_data)

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(brief_text)
        console.print(f"[green]Brief written to {output_path}[/green]")
    else:
        click.echo(brief_text)
