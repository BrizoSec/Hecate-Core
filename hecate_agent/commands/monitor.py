"""Live terminal dashboard for Hecate Runner activity and host metrics."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.core.cost_tracker import summarize_cost
from hecate_agent.core.llm_activity import summarize_calls
from hecate_agent.core.workspace import workspace_root

console = Console()

_LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ \[(\w+)\] ([\w.]+): (.*)$")
_TRAIL_RE = re.compile(r"^\[([a-f0-9]+) \+\s*([\d.]+)s\]\s+(\S+)\s+(.*)$")
_STAGES: Tuple[Tuple[str, str], ...] = (
    ("intake", "Intake"),
    ("source", "Source extraction"),
    ("research", "Research"),
    ("hypothesis", "Hypothesis"),
    ("techniques", "Technique mapping"),
    ("scope", "Platform and claims"),
    ("write", "Draft write"),
    ("sigma", "Rule generation"),
    ("review", "Review and finish"),
)


@dataclass
class TrailEvent:
    timestamp: str
    cycle_id: str
    elapsed: float
    stage: str
    message: str


@dataclass
class HostSample:
    cpu_percent: Optional[float]
    memory_used: Optional[int]
    memory_total: Optional[int]
    disks: List["DiskSample"]
    gpu_name: str = "unavailable"
    gpu_percent: Optional[float] = None
    gpu_memory_used: Optional[int] = None
    gpu_memory_total: Optional[int] = None


@dataclass
class DiskSample:
    mount: str
    used: int
    total: int


@dataclass
class RunnerStatus:
    installed: bool = False
    timer_active: bool = False
    service_state: str = "unknown"
    next_run: Optional[datetime] = None
    drafts_today: Optional[int] = None
    drafts_limit: Optional[int] = None
    research_today: Optional[int] = None
    research_limit: Optional[int] = None
    total_drafts: Optional[int] = None
    parked_items: Optional[int] = None
    #: The workspace the service writes to; the service's state says nothing about any other.
    workspace: Optional[Path] = None


class RunnerStatusSampler:
    """Read service scheduling and quota state without starting Runner work."""

    SERVICE = "hecate-runner-orchestrator.service"
    TIMER = "hecate-runner-orchestrator.timer"

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self._checked_at = 0.0
        self._cached = RunnerStatus()

    def sample(self) -> RunnerStatus:
        now = time.monotonic()
        if now - self._checked_at < 10:
            return self._cached
        self._checked_at = now
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "show",
                    self.TIMER,
                    self.SERVICE,
                    "-p",
                    "Id",
                    "-p",
                    "LoadState",
                    "-p",
                    "ActiveState",
                    "-p",
                    "WorkingDirectory",
                ],
                capture_output=True,
                check=True,
                text=True,
                timeout=1.5,
            )
        except (OSError, subprocess.SubprocessError):
            self._cached = RunnerStatus()
            return self._cached

        units: Dict[str, Dict[str, str]] = {}
        for block in result.stdout.split("\n\n"):
            values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if values.get("Id"):
                units[values["Id"]] = values
        timer = units.get(self.TIMER, {})
        service = units.get(self.SERVICE, {})
        installed = timer.get("LoadState") not in {None, "not-found"} or service.get("LoadState") not in {None, "not-found"}
        if not installed:
            self._cached = RunnerStatus()
            return self._cached

        timer_active = timer.get("ActiveState") == "active"
        next_run = self._next_timer_run() if timer_active else None
        runner_dir = Path(service.get("WorkingDirectory") or self.workspace.parent / "Hecate-Runner")
        env = _read_env_file(runner_dir / ".env")
        quota_workspace = Path(env.get("HECATE_WORKSPACE", str(self.workspace))).expanduser()
        if not quota_workspace.is_absolute():
            quota_workspace = runner_dir / quota_workspace
        state: Dict[str, Any] = {}
        try:
            state = json.loads((quota_workspace / ".orchestrator_state.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            pass
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        same_day = state.get("date") == today
        queue_dir = Path(env.get("HECATE_RUNNER_CTI_QUEUE_DIR", str(quota_workspace / "cti_queue")).strip("\"'"))
        if not queue_dir.is_absolute():
            queue_dir = runner_dir / queue_dir
        try:
            parked = len(list((queue_dir / "parked").glob("*.json")))
        except OSError:
            parked = None
        self._cached = RunnerStatus(
            installed=True,
            timer_active=timer_active,
            service_state=service.get("ActiveState", "unknown"),
            next_run=next_run,
            drafts_today=(
                int(state.get("drafts_today", 0)) if same_day and "drafts_today" in state else (0 if same_day else None)
            ),
            drafts_limit=_env_int(env, "HECATE_RUNNER_MAX_DRAFTS_PER_DAY"),
            research_today=(
                int(state.get("research_runs_today", 0))
                if same_day and "research_runs_today" in state
                else (0 if same_day else None)
            ),
            research_limit=_env_int(env, "HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY"),
            total_drafts=int(state["total_drafts_ever"]) if "total_drafts_ever" in state else None,
            parked_items=parked,
            workspace=quota_workspace,
        )
        return self._cached

    @classmethod
    def _next_timer_run(cls) -> Optional[datetime]:
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend", cls.TIMER],
                capture_output=True,
                check=True,
                text=True,
                timeout=1.5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 5 or cls.TIMER not in fields:
                continue
            try:
                scheduled = datetime.strptime(" ".join(fields[:3]), "%a %Y-%m-%d %H:%M:%S")
                return scheduled.replace(tzinfo=datetime.now().astimezone().tzinfo)
            except ValueError:
                continue
        return None


def _read_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.split("#", 1)[0].strip().strip("\"'")
    return values


def _env_int(env: Dict[str, str], key: str) -> Optional[int]:
    try:
        return int(env[key])
    except (KeyError, TypeError, ValueError):
        return None


class HostSampler:
    """Read inexpensive host metrics without requiring a monitoring package."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self._cpu_previous: Optional[Tuple[int, int]] = None
        self._gpu_last_check = 0.0
        self._gpu_cache: Dict[str, Any] = {}

    def sample(self) -> HostSample:
        cpu = self._cpu_percent()
        memory_used, memory_total = self._memory()
        disks = self._disks(self.workspace)
        if time.monotonic() - self._gpu_last_check >= 3:
            self._gpu_cache = self._gpu()
            self._gpu_last_check = time.monotonic()
        return HostSample(
            cpu_percent=cpu,
            memory_used=memory_used,
            memory_total=memory_total,
            disks=disks,
            **self._gpu_cache,
        )

    @staticmethod
    def _disks(workspace: Path) -> List[DiskSample]:
        """Collect local filesystems backing Hecate's workspace and mounted data."""
        disks: List[DiskSample] = []
        seen_devices = set()
        workspace_path = workspace.resolve()
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        except OSError:
            return disks

        for line in mounts:
            fields = line.split()
            if len(fields) < 3:
                continue
            source, target = fields[:2]
            if not source.startswith("/dev/") or source.startswith("/dev/loop"):
                continue
            # /proc/mounts encodes spaces and tabs as octal escapes.
            target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), target)
            mount_path = Path(target)
            if not (
                workspace_path == mount_path
                or workspace_path.is_relative_to(mount_path)
                or mount_path.is_relative_to(workspace_path)
            ):
                continue
            try:
                device_id = os.stat(mount_path).st_dev
                if device_id in seen_devices:
                    continue
                usage = shutil.disk_usage(mount_path)
            except OSError:
                continue
            seen_devices.add(device_id)
            label = target if target == "/" else str(mount_path)
            disks.append(DiskSample(label, usage.used, usage.total))
        return disks

    def _cpu_percent(self) -> Optional[float]:
        try:
            fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()[1:]
            values = [int(value) for value in fields]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
        except (OSError, ValueError, IndexError):
            return None
        previous = self._cpu_previous
        self._cpu_previous = (idle, total)
        if previous is None:
            return None
        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * (1 - idle_delta / total_delta)))

    @staticmethod
    def _memory() -> Tuple[Optional[int], Optional[int]]:
        try:
            values: Dict[str, int] = {}
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0]) * 1024
            total = values["MemTotal"]
            available = values.get("MemAvailable", values.get("MemFree", total))
            return max(0, total - available), total
        except (OSError, ValueError, KeyError, IndexError):
            return None, None

    @staticmethod
    def _gpu() -> Dict[str, Any]:
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                check=True,
                text=True,
                timeout=0.8,
            )
            fields = [field.strip() for field in result.stdout.splitlines()[0].split(",")]
            return {
                "gpu_name": fields[0],
                "gpu_percent": float(fields[1]),
                "gpu_memory_used": int(fields[2]) * 1024 * 1024,
                "gpu_memory_total": int(fields[3]) * 1024 * 1024,
            }
        except (OSError, subprocess.SubprocessError, ValueError, IndexError):
            return {"gpu_name": "not detected", "gpu_percent": None, "gpu_memory_used": None, "gpu_memory_total": None}


def _tail(path: Path, limit: int = 180) -> List[str]:
    """Read only the last part of an append-only log."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 160_000))
            raw = handle.read().decode("utf-8", errors="replace")
        return raw.splitlines()[-limit:]
    except OSError:
        return []


def _read_events(log_path: Path) -> List[TrailEvent]:
    events: List[TrailEvent] = []
    for line in _tail(log_path):
        match = _LOG_RE.match(line)
        if not match or match.group(3) != "hecate_runner.trail":
            continue
        trail = _TRAIL_RE.match(match.group(4))
        if not trail:
            continue
        cycle_id, elapsed, stage, message = trail.groups()
        events.append(TrailEvent(match.group(1), cycle_id, float(elapsed), stage, message))
    return events


def _read_recent_error(log_path: Path) -> str:
    error_block = []
    in_error = False
    
    for line in _tail(log_path, limit=300):
        match = _LOG_RE.match(line)
        if match:
            level = match.group(2)
            if level in {"ERROR", "CRITICAL"}:
                in_error = True
                error_block = [line]
            else:
                in_error = False
        else:
            if in_error or error_block:
                error_block.append(line)
                
    return "\n".join(error_block[-20:]) if error_block else ""

def _latest_metrics(metrics_path: Path) -> Dict[str, Any]:
    lines = _tail(metrics_path, limit=2000)
    aggregate = {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "estimated_cost_usd": 0.0,
        "completed_cycles": 0,
    }
    latest_val = {}
    for line in lines:
        try:
            val = json.loads(line)
            if isinstance(val, dict) and isinstance(val.get("stages"), list):
                aggregate["completed_cycles"] += 1
                latest_val = val
                for stage in val["stages"]:
                    if isinstance(stage, dict):
                        aggregate["llm_calls"] += int(stage.get("llm_calls") or 0)
                        aggregate["input_tokens"] += int(stage.get("input_tokens") or 0)
                        aggregate["output_tokens"] += int(stage.get("output_tokens") or 0)
                        aggregate["estimated_cost_usd"] += float(stage.get("estimated_cost_usd") or 0.0)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    latest_val["aggregate"] = aggregate
    return latest_val


def _bytes(value: Optional[int]) -> str:
    if value is None:
        return "n/a"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "n/a"


def _bar(value: Optional[float], width: int = 22) -> Text:
    if value is None:
        return Text("[ telemetry unavailable ]", style="dim")
    value = max(0.0, min(100.0, value))
    full = round(width * value / 100)
    color = "bright_magenta" if value >= 85 else "bright_cyan"
    return Text("█" * full + "░" * (width - full) + f" {value:5.1f}%", style=color)


def _resource_panel(title: str, value: Optional[float], detail: str = "") -> Panel:
    body = Group(_bar(value), Text(detail or " ", style="dim"))
    return Panel(body, title=f"[bold bright_cyan]{title}[/]", border_style="bright_magenta", box=box.ROUNDED)


#: With no service to ask, a cycle whose log has been quiet this long is taken as stopped.
#: One model call can run for many minutes without logging, so this cannot be short.
_QUIET_SECONDS = 30 * 60
#: Stages that log a line when they begin; every other stage logs only when it is finished.
_SELF_STARTING = frozenset({"research", "hypothesis", "sigma"})


def _parse_time(timestamp: str) -> Optional[datetime]:
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _pipeline_state(
    events: List[TrailEvent], service_running: Optional[bool] = None, now: Optional[datetime] = None
) -> Tuple[Optional[TrailEvent], bool, Optional[float]]:
    """(latest event, whether its cycle is running, seconds the cycle has taken).

    ``service_running`` is the Runner service's own state when it works on the
    monitored workspace: a crashed cycle then reads as stopped at once, not
    after the log has been quiet for half an hour. ``None`` (no service, or a
    different workspace such as a replay's) falls back to log freshness.
    """
    if not events:
        return None, False, None
    now = now or datetime.now()
    latest = events[-1]
    current_events = [event for event in events if event.cycle_id == latest.cycle_id]
    last_update = _parse_time(latest.timestamp)
    fresh = last_update is not None and (now - last_update).total_seconds() < _QUIET_SECONDS
    active = latest.stage != "done" and (fresh if service_running is None else service_running)
    logged = max((event.elapsed for event in current_events), default=latest.elapsed)
    # A stage logs when it ends, so the log's own clock stops at the last line:
    # ten minutes into source extraction it still read "elapsed 4s".
    started = _parse_time(current_events[0].timestamp)
    if active and started is not None:
        elapsed = max(logged, (now - started).total_seconds() + current_events[0].elapsed)
    else:
        elapsed = logged
    return latest, active, elapsed


def _stage_in_progress(events: List[TrailEvent]) -> int:
    """Index in ``_STAGES`` of the stage the latest cycle is working on, or -1 with no events.

    Most stages log one line, when they finish, so the stage named on the
    latest line is the one just completed and the work in hand is the next.
    Research, the hypothesis and rule generation also log when they begin and
    are in progress until their "done" line; source extraction logs "starting"
    and is in progress until its next line.
    """
    if not events:
        return -1
    cycle = [event for event in events if event.cycle_id == events[-1].cycle_id]
    drafting_started = any(event.stage.startswith("sigma") or event.stage == "write" for event in cycle)
    furthest = -1
    for event in cycle:
        if event.stage == "done":
            return len(_STAGES) - 1
        # Grounding is logged twice: before the draft is written and after the rules.
        order = _stage_order("scope" if event.stage == "grounding" and not drafting_started else event.stage)
        if order < 0:
            continue
        key = _STAGES[order][0]
        if event.stage == "source":
            # Source extraction logs "starting" and then one line when it is finished.
            finished = not event.message.startswith("starting")
        else:
            finished = key not in _SELF_STARTING or re.search(r"\bdone\b", event.message) is not None
        furthest = max(furthest, min(order + 1, len(_STAGES) - 1) if finished else order)
    return furthest


def _stage_table(current: Optional[TrailEvent], active: bool, stale: bool, in_progress: Optional[int] = None) -> Table:
    table = Table(box=None, expand=True, padding=(0, 1))
    table.add_column("STATE", width=8)
    table.add_column("PIPELINE STAGE", ratio=1)
    current_order = in_progress if in_progress is not None else (_stage_order(current.stage) if current else -1)
    for index, (key, label) in enumerate(_STAGES):
        if current and current.stage == "done":
            state, style = "DONE", "bright_green"
        elif index < current_order:
            state, style = "DONE", "bright_green"
        elif index == current_order:
            if stale:
                state, style = "STALE", "bold bright_red"
            else:
                state, style = ("ACTIVE", "bold bright_magenta") if active else ("DONE", "bright_green")
        else:
            state, style = "WAIT", "dim"
        table.add_row(Text(state, style=style), Text(label, style=style if state != "WAIT" else "white"))
    return table


def _stage_order(stage: str) -> int:
    aliases = {
        "start": "intake",
        "route": "intake",
        "guidance": "source",
        "triage": "intake",
        "quota": "intake",
        "claims": "scope",
        "grounding": "review",
    }
    normalized = aliases.get(stage, stage)
    if normalized.startswith("technique"):
        normalized = "techniques"
    if normalized.startswith("hypothesis"):
        normalized = "hypothesis"
    if normalized.startswith("sigma"):
        normalized = "sigma"
    return next((index for index, (key, _) in enumerate(_STAGES) if key == normalized), -1)



_STAGE_COLORS = {
    "intake": "dim white",
    "source": "cyan",
    "research": "yellow",
    "hypothesis": "magenta",
    "techniques": "blue",
    "scope": "bright_white",
    "write": "bright_cyan",
    "sigma": "bright_yellow",
    "review": "bright_green"
}

def _get_stage_color(stage: str) -> str:
    return _STAGE_COLORS.get(stage.lower(), "white")

#: An event's message may wrap onto this many lines before it is cut.
_LINES_PER_EVENT = 2


def _recent_events(events: List[TrailEvent], rows: int, width: int) -> List[Tuple[TrailEvent, str]]:
    """The newest events that fit in ``rows`` lines of ``width`` characters, oldest first.

    A panel clips what overflows it from the bottom, which is where the newest
    lines are: eight long events in a short panel hid the cycle's "done" line.
    So the events are chosen to fit, newest first, and long messages are cut.
    """
    width = max(20, width)
    chosen: List[Tuple[TrailEvent, str]] = []
    used = 0
    for event in reversed(events):
        # Wrapped here, not by the table: its own wrapping can take a third line.
        lines = textwrap.wrap(event.message, width=width, max_lines=_LINES_PER_EVENT, placeholder="…") or [""]
        if chosen and used + len(lines) > rows:
            break
        chosen.append((event, "\n".join(lines)))
        used += len(lines)
    return chosen[::-1]


def _activity_table(events: List[TrailEvent], rows: int = 8, width: int = 100) -> Table:
    table = Table(box=None, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("TIME", width=10, style="dim")
    table.add_column("STAGE", width=10)
    table.add_column("ACTIVITY", ratio=1, overflow="ellipsis", no_wrap=True)
    for event, message in _recent_events(events, rows, width):
        color = _get_stage_color(event.stage)
        table.add_row(event.timestamp[-8:], f"[{color}]{event.stage[:10]}[/]", message)
    if not events:
        table.add_row("--:--:--", "[dim white]idle[/]", "Waiting for Runner events in logs/orchestrator.log")
    return table


def _calculate_llm_metrics(llm_stages: List[Dict[str, Any]]) -> Tuple[int, int, int, List[str], str]:
    calls = sum(int(stage.get("llm_calls") or 0) for stage in llm_stages)
    input_tokens = sum(int(stage.get("input_tokens") or 0) for stage in llm_stages)
    output_tokens = sum(int(stage.get("output_tokens") or 0) for stage in llm_stages)
    models = sorted({model for stage in llm_stages for model in (stage.get("models") or [])})
    known_costs = [float(stage.get("estimated_cost_usd") or 0.0) for stage in llm_stages if stage.get("estimated_cost_usd") is not None]
    if known_costs and len(known_costs) == len(llm_stages):
        cost_text = f"${sum(known_costs):.4f} reported estimate"
    elif known_costs:
        cost_text = f"${sum(known_costs):.4f} partial estimate"
    else:
        cost_text = "unknown"
    return calls, input_tokens, output_tokens, models, cost_text


def _build_summary_table(
    compact: bool, calls: int, input_tokens: int, output_tokens: int, cost_text: str,
    search_count: str, models: List[str], workspace: Optional[Path],
    usage_note: str, has_stages: bool, stage_line: str = "", narrow: bool = False
) -> Table:
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=10, min_width=10, no_wrap=True)
    table.add_column("value", style="bright_white", ratio=1, overflow="ellipsis", no_wrap=True)
    if narrow:
        _narrow_usage_rows(
            table,
            f"{calls} calls" if has_stages else "no usage recorded",
            f"{input_tokens:,} in / {output_tokens:,} out" if has_stages else "—",
            cost_text,
            ", ".join(models) or "not reported",
            search_count,
            stage_line,
            usage_note,
            workspace,
        )
    elif compact:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no completed metrics"
        table.add_row("LLM", llm_summary)
        table.add_row("Cost", cost_text)
        table.add_row("Tavily", f"{search_count} searches")
        table.add_row("Model", ", ".join(models) or "not reported")
        table.add_row("Keys", _credential_summary(workspace))
    else:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no usage recorded"
        _usage_rows(
            table,
            f"{llm_summary} · cost {cost_text}",
            f"{', '.join(models) or 'not reported'} · Tavily searches: {search_count}",
            stage_line,
            f"{usage_note} · {_credential_summary(workspace)}",
        )
    return table


def _narrow_usage_rows(
    table: Table, llm: str, tokens: str, cost: str, model: str, searches: str, by_stage: str, status: str,
    workspace: Optional[Path],
) -> None:
    """The usage rows for a column a third of the screen wide: one fact a row."""
    table.add_row("LLM", llm)
    table.add_row("Tokens", tokens)
    table.add_row("Cost", cost)
    table.add_row("Model", model)
    table.add_row("Tavily", f"{searches} searches" if searches.isdigit() else f"searches {searches}")
    first, _, second = by_stage.partition("\n")
    table.add_row("By stage", first)
    table.add_row("", second)
    table.add_row("Status", status)
    table.add_row("Keys", _credential_summary(workspace))


#: Rows of the usage panel in a side column, with its border.
_NARROW_USAGE_PANEL_HEIGHT = 11


def _usage_rows(table: Table, llm: str, model: str, by_stage: str, status: str) -> None:
    """The full layout's four usage rows: the panel is this tall and no taller."""
    table.add_row("LLM", llm)
    table.add_row("Model", model)
    table.add_row("By stage", by_stage)
    table.add_row("Status", status)


#: Rows of the usage panel in the full layout, with its border.
_USAGE_PANEL_HEIGHT = 6


def _stage_line(llm_stages: List[Dict[str, Any]], tokens: bool = True) -> str:
    """Each stage's calls, and its tokens where there is room, on one line; the cycle total is the LLM row."""
    parts = []
    for stage in llm_stages:
        if stage.get("stage") == "cycle":
            continue
        part = f"{str(stage.get('stage', 'unknown')).removesuffix('_generation').removesuffix('_evidence')} {stage.get('llm_calls') or 0}"
        if tokens:
            part += f" ({int(stage.get('input_tokens') or 0):,}/{int(stage.get('output_tokens') or 0):,})"
        parts.append(part)
    if not parts:
        return "none recorded"
    if tokens:
        return " · ".join(parts) + "  (calls, tokens in/out)"
    half = (len(parts) + 1) // 2  # two rows in a narrow column
    return " · ".join(parts[:half]) + "\n" + (" · ".join(parts[half:]) + " calls").strip()


def _usage_panel(
    metrics: Dict[str, Any],
    current: Optional[TrailEvent],
    active: bool,
    events: List[TrailEvent],
    compact: bool = False,
    workspace: Optional[Path] = None,
    live: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
    narrow: bool = False,
) -> Panel:
    if active and current and live:
        # The running cycle's own calls, not the totals of the last one to finish.
        return _live_usage_panel(live, current, events, compact, workspace, now or datetime.now(), narrow)
    
    stages = metrics.get("stages") or []
    llm_stages = [stage for stage in stages if isinstance(stage, dict) and stage.get("llm_calls") is not None]
    calls, input_tokens, output_tokens, models, cost_text = _calculate_llm_metrics(llm_stages)
    search_count = _search_count(current, events)
    
    if active and current and current.stage in {"source", "research", "hypothesis", "sigma"}:
        usage_note = "Live token totals are written when the cycle ends."
    elif not metrics:
        usage_note = "No completed cycle metrics found yet."
    else:
        usage_note = f"Last cycle {metrics.get('cycle_id', 'unknown')} · {metrics.get('outcome', 'unknown')}"

    table = _build_summary_table(
        compact, calls, input_tokens, output_tokens, cost_text,
        search_count, models, workspace, usage_note, bool(llm_stages), _stage_line(llm_stages, tokens=not narrow), narrow
    )
    return Panel(table, title="[bold bright_cyan]LLM / API TELEMETRY[/]", border_style="bright_magenta", box=box.ROUNDED)


def _search_count(current: Optional[TrailEvent], events: List[TrailEvent]) -> str:
    if current:
        for event in reversed(events):
            if event.cycle_id != current.cycle_id or event.stage != "research":
                continue
            searches = re.search(r"(\d+) web search\(es\)", event.message)
            if searches:
                return searches.group(1)
            break
    return "pending"


def _live_usage(call_log: Path) -> Dict[str, Any]:
    """The running cycle's provider calls so far; empty when the Runner keeps no call log."""
    return summarize_calls(_tail(call_log, limit=2000))


def _live_usage_panel(
    live: Dict[str, Any],
    current: TrailEvent,
    events: List[TrailEvent],
    compact: bool,
    workspace: Optional[Path],
    now: datetime,
    narrow: bool = False,
) -> Panel:
    calls, in_flight, failed = live["llm_calls"], live["in_flight"], live["failed"]
    call_text = f"{calls} done"
    if in_flight:
        waited = _duration(max(0.0, now.timestamp() - live["last_start"]))
        call_text += f" · {in_flight} in flight ({waited})" if narrow else f" · {in_flight} in flight (latest sent {waited} ago)"
    if failed:
        call_text += f" · {failed} failed"
    cost, basis = summarize_cost(live["models"], calls, live["input_tokens"], live["output_tokens"], live["cost_usd"])
    cost_text = "unknown" if cost is None else f"${cost:.4f} so far"
    if cost is None and calls:
        cost_text = basis.split(":")[0]
    models = ", ".join(live["models"]) or "not reported yet"
    search_count = _search_count(current, events)
    if live["last_end"]:
        last = f"last reply {datetime.fromtimestamp(live['last_end']):%H:%M:%S}"
    else:
        last = "no reply yet"
    usage_note = f"Live · cycle {current.cycle_id} so far · {last}"

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=10, min_width=10, no_wrap=True)
    table.add_column("value", style="bright_white", ratio=1, overflow="ellipsis", no_wrap=True)
    if narrow:
        _narrow_usage_rows(
            table,
            call_text,
            f"{live['input_tokens']:,} in / {live['output_tokens']:,} out",
            cost_text,
            models,
            search_count,
            "written when the cycle ends",
            usage_note,
            workspace,
        )
    elif compact:
        table.add_row("LLM", f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out")
        table.add_row("Cost", cost_text)
        table.add_row("Tavily", f"{search_count} searches")
        table.add_row("Model", models)
        table.add_row("Keys", _credential_summary(workspace))
    else:
        _usage_rows(
            table,
            f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out · cost {cost_text}",
            f"{models} · Tavily searches: {search_count}",
            "written when the cycle ends",
            f"{usage_note} · {_credential_summary(workspace)}",
        )
    return Panel(table, title="[bold bright_cyan]LLM / API TELEMETRY[/]", border_style="bright_magenta", box=box.ROUNDED)


def _credential_summary(workspace: Optional[Path] = None) -> str:
    """Show configured status only; never read or render credential values."""
    checks = (
        (
            "LLM",
            (
                "HECATE_LLM_PROVIDER",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "AWS_PROFILE",
                "OLLAMA_HOST",
            ),
        ),
        ("Tavily", ("TAVILY_API_KEY",)),
        ("OTX", ("OTX_API_KEY",)),
    )
    env_files = [workspace / ".env"] if workspace else []
    if workspace:
        env_files.append(workspace.parent / "Hecate-Runner" / ".env")
    file_keys = set()
    for env_file in env_files:
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and value.strip().strip("\"'"):
                    file_keys.add(key.strip().removeprefix("export "))
        except OSError:
            continue
    present = []
    for label, names in checks:
        is_set = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
        present.append(f"{label} {'ON' if is_set else 'OFF'}")
    return " · ".join(present)


def _compact_progress(
    current: Optional[TrailEvent], active: bool, stale: bool, in_progress: Optional[int] = None
) -> Panel:
    current_order = in_progress if in_progress is not None else (_stage_order(current.stage) if current else -1)
    labels = ("IN", "SRC", "RES", "HYP", "TEC", "SCOPE", "WRITE", "SIGMA", "REVIEW")
    parts: List[Text] = []
    for index, label in enumerate(labels):
        if current and current.stage == "done" or index < current_order:
            style, glyph = "bright_green", "✓"
        elif index == current_order:
            if stale:
                style, glyph = "bold bright_red", "!"
            else:
                style, glyph = ("bold bright_magenta", "▶") if active else ("bright_green", "✓")
        else:
            style, glyph = "dim", "·"
        parts.append(Text(glyph + label, style=style))
        if index < len(labels) - 1:
            parts.append(Text(" › ", style="dim"))
    return Panel(Text.assemble(*parts), title="[bold bright_cyan]PIPELINE[/]", border_style="bright_magenta", box=box.SIMPLE)


def _compact_resources(host: HostSample) -> Panel:
    gpu_memory = _percent(host.gpu_memory_used, host.gpu_memory_total)
    cells = (
        ("CPU", host.cpu_percent, "host"),
        ("RAM", _percent(host.memory_used, host.memory_total), f"{_bytes(host.memory_used)}/{_bytes(host.memory_total)}"),
        (
            "GPU",
            host.gpu_percent,
            f"{_bytes(host.gpu_memory_used)}/{_bytes(host.gpu_memory_total)}" if gpu_memory is not None else host.gpu_name,
        ),
    )
    table = Table(box=None, expand=True, show_header=False, padding=(0, 1))
    for _ in cells:
        table.add_column(ratio=1)
    values = []
    for name, value, detail in cells:
        percent = "n/a" if value is None else f"{value:.0f}%"
        style = "bright_magenta" if value is not None and value >= 85 else "bright_cyan"
        values.append(Text(f"{name} {percent} · {detail}", style=style))
    table.add_row(*values)
    body = Group(table, Text.assemble(("DRIVES ", "bold bright_cyan"), (_disk_summary(host, compact=True), "bright_cyan")))
    return Panel(body, border_style="bright_magenta", box=box.SIMPLE, padding=(0, 0))


def _disk_summary(host: HostSample, compact: bool = False) -> str:
    if not host.disks:
        return "no local mounted drives detected"
    entries = []
    for disk in host.disks:
        percent = 100 * disk.used / disk.total if disk.total else 0
        if compact:
            entries.append(f"{disk.mount} {percent:.0f}%")
        else:
            entries.append(f"{disk.mount} {percent:.0f}% ({_bytes(disk.used)}/{_bytes(disk.total)})")
    return "  ·  ".join(entries)


def _disk_panel(host: HostSample) -> Panel:
    table = Table(box=None, expand=True, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("MOUNT", style="bright_cyan")
    table.add_column("USED", justify="right")
    table.add_column("CAPACITY", justify="right")
    for disk in host.disks:
        percent = 100 * disk.used / disk.total if disk.total else 0
        table.add_row(disk.mount, f"{_bytes(disk.used)} ({percent:.0f}%)", _bytes(disk.total))
    if not host.disks:
        table.add_row("--", "no local drives detected", "--")
    return Panel(
        table,
        title="[bold bright_cyan]MOUNTED LOCAL DRIVES[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _backlog_observation(events: List[TrailEvent]) -> Optional[Tuple[int, str]]:
    for event in reversed(events):
        match = re.search(r"(\d+) high-signal waiting in its backlog", event.message)
        if match:
            return int(match.group(1)), event.timestamp[-8:]
    return None


def _quota_text(used: Optional[int], limit: Optional[int]) -> str:
    if used is None or limit is None:
        return "n/a"
    return f"{used}/{limit}" + (" FULL" if limit > 0 and used >= limit else "")


def _until_next_run(next_run: Optional[datetime]) -> str:
    if next_run is None:
        return "not scheduled"
    seconds = max(0, int((next_run - datetime.now().astimezone()).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{remainder}s"


def _runner_compact_summary(status: RunnerStatus, events: List[TrailEvent]) -> str:
    if not status.installed:
        return ""
    backlog = _backlog_observation(events)
    backlog_text = f"B{backlog[0]}@{backlog[1][:5]}" if backlog else "B?"
    parked_text = f"P{status.parked_items}" if status.parked_items is not None else "P?"
    service_state = (
        "running"
        if status.service_state in {"active", "activating"}
        else "idle" if status.service_state == "inactive" else status.service_state
    )
    timer_text = f"+{_until_next_run(status.next_run)}" if status.timer_active else "timer off"
    draft_quota = (
        f"{status.drafts_today}/{status.drafts_limit}"
        if status.drafts_today is not None and status.drafts_limit is not None
        else "?"
    )
    research_quota = (
        f"{status.research_today}/{status.research_limit}"
        if status.research_today is not None and status.research_limit is not None
        else "?"
    )
    return f"Runner {service_state} {timer_text} · D{draft_quota} R{research_quota} · {backlog_text} {parked_text}"


def _runner_panel(status: RunnerStatus, events: List[TrailEvent]) -> Panel:
    service_state = status.service_state.upper()
    service_style = "bright_green" if service_state in {"ACTIVE", "ACTIVATING"} else "bright_cyan"
    rows = [
        Text.assemble(
            ("SERVICE  ", "dim"),
            (service_state, service_style),
            (" · timer " + ("active" if status.timer_active else "inactive"), "bright_cyan"),
        ),
        Text.assemble(("NEXT RUN ", "dim"), (_until_next_run(status.next_run), "bright_magenta")),
        Text.assemble(
            ("QUOTA    ", "dim"),
            ("drafts " + _quota_text(status.drafts_today, status.drafts_limit), "bright_white"),
            (" · research " + _quota_text(status.research_today, status.research_limit), "bright_white"),
        ),
    ]
    backlog = _backlog_observation(events)
    if backlog:
        rows.append(
            Text.assemble(
                ("BACKLOG  ", "dim"),
                (f"{backlog[0]} high-signal waiting", "bright_cyan"),
                (f" · observed {backlog[1]}", "dim"),
            )
        )
    else:
        rows.append(Text.assemble(("BACKLOG  ", "dim"), ("not reported in recent trail", "yellow")))
    if status.parked_items is not None or status.total_drafts is not None:
        details = []
        if status.parked_items is not None:
            details.append(f"{status.parked_items} parked")
        if status.total_drafts is not None:
            details.append(f"{status.total_drafts} total drafts")
        rows.append(Text.assemble(("QUEUE    ", "dim"), (" · ".join(details), "bright_white")))
    return Panel(
        Group(*rows),
        title="[bold bright_cyan]HECATE RUNNER SERVICE[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _get_inbox_counts(workspace: Path) -> Tuple[int, int, int]:
    try:
        from hecate_agent.orchestrator.graph import hecate_graph
        import sqlite3
        db_path = workspace / "hecate_checkpoints.sqlite"
        if not db_path.exists():
            return 0, 0, 0
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT DISTINCT thread_id FROM checkpoints")
        threads = [row[0] for row in c.fetchall()]
        pending, completed, failed = 0, 0, 0
        for thread_id in threads:
            try:
                state = hecate_graph.get_state({"configurable": {"thread_id": thread_id}})
                if state.next:
                    pending += 1
                elif state.values.get("halt_reason"):
                    failed += 1
                else:
                    completed += 1
            except Exception:
                failed += 1
        return pending, completed, failed
    except Exception:
        return 0, 0, 0

def _render_dashboard(
    workspace: Path,
    events: List[TrailEvent],
    metrics: Dict[str, Any],
    host: HostSample,
    refreshed: datetime,
    runner: Optional[RunnerStatus] = None,
    recent_error: str = "",
    live: Optional[Dict[str, Any]] = None,
) -> Layout:
    runner = runner or RunnerStatus()
    latest, active, elapsed = _pipeline_state(events, _service_running(runner, workspace), refreshed)
    stale = bool(latest and not active and latest.stage != "done")
    in_progress = _stage_in_progress(events)
    working_on = _STAGES[in_progress][1] if in_progress >= 0 else "starting"
    status = "RUNNING" if active else "STALLED" if stale else "IDLE"
    cycle = latest.cycle_id if latest else "------"
    title = Text.assemble(
        (" HECATE ", "bold black on bright_cyan"),
        ("  PIPELINE MONITOR  ", "bold bright_white"),
        ("  CYBER OPS / LIVE TELEMETRY", "bright_magenta"),
        (f"     {status}", "bold bright_green" if active else "bold bright_red" if stale else "bold yellow"),
    )
    pending, completed, failed = _get_inbox_counts(workspace)
    queue_str = f"  ·  Queue: {pending} pending, {completed} completed, {failed} failed" if (pending or completed or failed) else ""

    if latest and active:
        subline = (
            f"cycle {cycle}  ·  now: {working_on}  ·  elapsed {_duration(elapsed)}"
            f"  ·  last: {latest.stage}: {latest.message[:60]}{queue_str}"
        )
    elif latest and stale:
        why = (
            "the Runner service is not running"
            if _service_running(runner, workspace) is False
            else f"no log activity for {_QUIET_SECONDS // 60}+ minutes"
        )
        subline = f"cycle {cycle}  ·  stopped in {working_on}  ·  last seen {latest.timestamp}  ·  {why}{queue_str}"
    elif latest:
        subline = f"last cycle {cycle}  ·  {latest.message[:100]}{queue_str}"
    else:
        subline = f"monitoring {workspace}  ·  waiting for a pipeline cycle{queue_str}"

    layout = Layout()
    header_panel = Panel(Group(title, Text(subline, style="dim")), border_style="bright_cyan", box=box.DOUBLE)
    compact = console.size.height < 40
    if compact:
        activity = Table(box=None, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
        activity.add_column("TIME", width=8, style="dim")
        activity.add_column("STAGE", width=9)
        activity.add_column("ACTIVITY", ratio=1, overflow="ellipsis")
        for event in events[-3:]:
            color = _get_stage_color(event.stage)
            activity.add_row(event.timestamp[-8:], f"[{color}]{event.stage[:9]}[/]", event.message)
        if not events:
            activity.add_row("--:--:--", "[dim white]idle[/]", "Waiting for Runner events")
        if recent_error and stale:
            action_panel = Panel(Text(recent_error, style="red"), title="[bold red]ERROR STREAM[/]", border_style="red", box=box.SIMPLE)
        else:
            action_panel = Panel(activity, title="[bold bright_cyan]ACTION STREAM[/]", border_style="bright_magenta", box=box.SIMPLE)
        layout.split_column(
            Layout(header_panel, name="header", size=4),
            Layout(_compact_resources(host), name="resources", size=4),
            Layout(_compact_progress(latest, active, stale, in_progress), name="progress", size=3),
            Layout(action_panel, name="activity", size=6),
            Layout(_usage_panel(metrics, latest, active, events, compact=True, workspace=workspace, live=live, now=refreshed), name="usage", size=7),
            Layout(
                Text(
                    f"Updated {refreshed:%H:%M:%S} · Ctrl-C exits"
                    + (f" · {_runner_compact_summary(runner, events)}" if runner.installed else ""),
                    style="dim",
                    overflow="ellipsis",
                ),
                name="footer",
                size=1,
            ),
        )
        return layout

    resources_height = 6 if len(host.disks) <= 1 else 5 + len(host.disks) + 3
    stages_height = len(_STAGES) + 3
    service_height = 8 if runner.installed else 0
    footer = Layout(
        Panel(
            Text(
                f"Updated {refreshed:%H:%M:%S}   ·   Ctrl-C to exit   ·   log: "
                f"{workspace / 'logs' / 'orchestrator.log'}",
                style="dim",
            ),
            border_style="bright_magenta",
            box=box.SIMPLE,
        ),
        name="footer",
        size=3,
    )
    body_height = console.size.height - 4 - resources_height - 3
    # A full-width usage panel is mostly empty to the right of its values, and
    # every row it takes is one the stream loses. With room for all three
    # panels in the left-hand column, the stream runs the full height instead.
    usage_on_left = body_height >= stages_height + service_height + _NARROW_USAGE_PANEL_HEIGHT
    usage_panel = _usage_panel(metrics, latest, active, events, workspace=workspace, live=live, now=refreshed, narrow=usage_on_left)
    if usage_on_left:
        middle_height = body_height
        layout.split_column(
            Layout(header_panel, name="header", size=4),
            Layout(name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            footer,
        )
    else:
        middle_height = body_height - _USAGE_PANEL_HEIGHT
        layout.split_column(
            Layout(header_panel, name="header", size=4),
            Layout(name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            Layout(usage_panel, name="usage", size=_USAGE_PANEL_HEIGHT),
            footer,
        )
    if len(host.disks) <= 1:
        layout["resources"].split_row(
            Layout(_resource_panel("CPU", host.cpu_percent, "host utilization"), ratio=1),
            Layout(
                _resource_panel(
                    "MEMORY",
                    _percent(host.memory_used, host.memory_total),
                    f"{_bytes(host.memory_used)} / {_bytes(host.memory_total)}",
                ),
                ratio=1,
            ),
            Layout(
                _resource_panel(
                    "GPU",
                    host.gpu_percent,
                    f"{host.gpu_name} · {_bytes(host.gpu_memory_used)} / {_bytes(host.gpu_memory_total)}",
                ),
                ratio=1,
            ),
            Layout(
                _resource_panel(
                    "HECATE FS",
                    _percent(host.disks[0].used, host.disks[0].total) if host.disks else None,
                    f"{_bytes(host.disks[0].used)} / {_bytes(host.disks[0].total)} used" if host.disks else "not detected",
                ),
                ratio=1,
            ),
        )
    else:
        layout["resources"].split_column(
            Layout(name="compute", size=5),
            Layout(_disk_panel(host), size=len(host.disks) + 3),
        )
        layout["compute"].split_row(
            Layout(_resource_panel("CPU", host.cpu_percent, "host utilization"), ratio=1),
            Layout(
                _resource_panel(
                    "MEMORY",
                    _percent(host.memory_used, host.memory_total),
                    f"{_bytes(host.memory_used)} / {_bytes(host.memory_total)}",
                ),
                ratio=1,
            ),
            Layout(
                _resource_panel(
                    "GPU",
                    host.gpu_percent,
                    f"{host.gpu_name} · {_bytes(host.gpu_memory_used)} / {_bytes(host.gpu_memory_total)}",
                ),
                ratio=1,
            ),
        )
    stages_panel = Panel(
        _stage_table(latest, active, stale, in_progress),
        title="[bold bright_cyan]PIPELINE SEQUENCE[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )
    layout["middle"].split_row(Layout(name="stages", ratio=1), Layout(name="operations", ratio=2))
    # The stage list is short and its column was half empty, so the service
    # panel sits under it when there is room and the stream gets the whole
    # right-hand column.
    service_on_left = runner.installed and middle_height >= stages_height + service_height
    stream_height = middle_height if service_on_left or not runner.installed else middle_height - service_height
    if recent_error and stale:
        main_panel = Panel(Text(recent_error, style="red"), title="[bold red]ERROR STREAM[/]", border_style="red", box=box.ROUNDED)
    else:
        main_panel = Panel(
            # Inside the panel: two border lines and the table's header; two fixed columns and the padding.
            _activity_table(events, rows=max(1, stream_height - 3), width=console.size.width * 2 // 3 - 30),
            title="[bold bright_cyan]ACTION STREAM[/]",
            border_style="bright_magenta",
            box=box.ROUNDED,
        )

    left = [Layout(stages_panel, ratio=1)]
    if service_on_left:
        left.append(Layout(_runner_panel(runner, events), size=service_height))
    if usage_on_left:
        left.append(Layout(usage_panel, size=_NARROW_USAGE_PANEL_HEIGHT))
    if len(left) > 1:
        layout["stages"].split_column(*left)
    else:
        layout["stages"].update(stages_panel)
    if runner.installed and not service_on_left:
        layout["operations"].split_column(Layout(main_panel, ratio=2), Layout(_runner_panel(runner, events), size=service_height))
    else:
        layout["operations"].update(main_panel)
    return layout


def _service_running(runner: RunnerStatus, workspace: Path) -> Optional[bool]:
    """Whether the Runner service is working, or None when it is not the one writing to ``workspace``."""
    if not runner.installed or runner.workspace is None:
        return None
    try:
        if runner.workspace.resolve() != workspace.resolve():
            return None
    except OSError:
        return None
    return runner.service_state in {"active", "activating"}


def _duration(seconds: Optional[float]) -> str:
    total = int(seconds or 0)
    minutes, secs = divmod(total, 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


def _percent(used: Optional[int], total: Optional[int]) -> Optional[float]:
    if used is None or not total:
        return None
    return max(0.0, min(100.0, used * 100 / total))


@click.command()
@click.option(
    "--workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Hecate workspace to monitor.",
)
@click.option(
    "--interval",
    type=click.FloatRange(min=0.5, max=30),
    default=1.0,
    show_default=True,
    help="Screen refresh interval in seconds.",
)
def monitor(workspace: Optional[Path], interval: float) -> None:
    """Open a live htop-style dashboard for Hecate pipeline activity."""
    root = workspace_root(workspace)
    log_path = root / "logs" / "orchestrator.log"
    metrics_path = root / "logs" / "stage_metrics.jsonl"
    call_log = root / "logs" / "llm_calls.jsonl"
    sampler = HostSampler(root)
    runner_sampler = RunnerStatusSampler(root)
    try:
        with Live(console=console, screen=True, refresh_per_second=4, transient=False) as live:
            while True:
                events = _read_events(log_path)
                recent_error = _read_recent_error(log_path)
                metrics = _latest_metrics(metrics_path)
                host = sampler.sample()
                runner = runner_sampler.sample()
                calls = _live_usage(call_log)
                live.update(
                    _render_dashboard(root, events, metrics, host, datetime.now(), runner, recent_error, calls), refresh=True
                )
                time.sleep(interval)
    except KeyboardInterrupt:
        console.show_cursor(True)
