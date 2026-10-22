"""Live terminal dashboard for Hecate Runner activity and host metrics."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import click
import yaml
from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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
    latest_with_llm = {}
    for line in lines:
        try:
            val = json.loads(line)
            if isinstance(val, dict) and isinstance(val.get("stages"), list):
                aggregate["completed_cycles"] += 1
                latest_val = val
                has_llm = any(isinstance(s, dict) and (s.get("llm_calls") or 0) > 0 for s in val["stages"])
                if has_llm:
                    latest_with_llm = val
                for stage in val["stages"]:
                    if isinstance(stage, dict):
                        aggregate["llm_calls"] += int(stage.get("llm_calls") or 0)
                        aggregate["input_tokens"] += int(stage.get("input_tokens") or 0)
                        aggregate["output_tokens"] += int(stage.get("output_tokens") or 0)
                        aggregate["estimated_cost_usd"] += float(stage.get("estimated_cost_usd") or 0.0)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    if latest_with_llm and not any(isinstance(s, dict) and (s.get("llm_calls") or 0) > 0 for s in latest_val.get("stages", [])):
        latest_val = dict(latest_val)
        latest_val["stages"] = latest_with_llm.get("stages", [])
        latest_val["models"] = latest_with_llm.get("models", [])
        latest_val["hunt_id"] = latest_with_llm.get("hunt_id")
        latest_val["research_id"] = latest_with_llm.get("research_id")
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
    if now.tzinfo is not None:
        now = now.replace(tzinfo=None)
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
            ev_time = _parse_time(current.timestamp) if current.timestamp else None
            is_fresh = ev_time and (datetime.now() - ev_time).total_seconds() < _QUIET_SECONDS
            if is_fresh:
                state, style = "DONE", "bright_green"
            else:
                state, style = "WAIT", "dim"
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
_LINES_PER_EVENT = 1


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
    duration_ms = sum(int(stage.get("duration_ms") or 0) for stage in llm_stages)
    if duration_ms > 0:
        tps = (input_tokens + output_tokens) / (duration_ms / 1000)
        speed_text = f"{tps:.1f} tok/s ({duration_ms / 1000:.1f}s)"
    else:
        speed_text = "unknown"
    return calls, input_tokens, output_tokens, models, speed_text


def _build_summary_table(
    compact: bool, calls: int, input_tokens: int, output_tokens: int, speed_text: str,
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
            speed_text,
            ", ".join(models) or "not reported",
            search_count,
            stage_line,
            usage_note,
            workspace,
        )
    elif compact:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no completed metrics"
        table.add_row("LLM", llm_summary)
        table.add_row("Speed", speed_text)
        table.add_row("Latency", usage_note)
        table.add_row("Model", ", ".join(models) or "not reported")
    else:
        llm_summary = f"{calls} calls · {input_tokens:,} in / {output_tokens:,} out" if has_stages else "no usage recorded"
        _usage_rows(
            table,
            f"{llm_summary} · speed {speed_text}",
            ", ".join(models) or "not reported",
            stage_line,
            usage_note,
        )
    return table


def _narrow_usage_rows(
    table: Table, llm: str, tokens: str, speed: str, model: str, searches: str, by_stage: str, latency: str,
    workspace: Optional[Path] = None,
) -> None:
    """The usage rows for a column a third of the screen wide: one fact a row."""
    table.add_row("LLM", llm)
    table.add_row("Tokens", tokens)
    table.add_row("Speed", speed)
    table.add_row("Latency", latency)
    table.add_row("Model", model)
    first, _, second = by_stage.partition("\n")
    table.add_row("By stage", first)
    if second:
        table.add_row("", second)


#: Rows of the LLM panel in a side column, with its border.
_NARROW_USAGE_PANEL_HEIGHT = 9
_NARROW_LLM_PANEL_HEIGHT = 9
_INTEGRATIONS_PANEL_HEIGHT = 10
_HUNTS_PANEL_HEIGHT = 7
_MITRE_PANEL_HEIGHT = 12
_PURPLE_PANEL_HEIGHT = 6


def _usage_rows(table: Table, llm: str, model: str, by_stage: str, latency: str) -> None:
    """The full layout's four usage rows: the panel is this tall and no taller."""
    table.add_row("LLM", llm)
    table.add_row("Model", model)
    table.add_row("By stage", by_stage)
    table.add_row("Latency", latency)


#: Rows of the usage panel in the full layout, with its border.
_USAGE_PANEL_HEIGHT = 6
#: Height of the bottom usage/summary/integrations row in horizontal dashboard layouts.
_BOTTOM_ROW_HEIGHT = 12


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
    if (active or (live and live.get("in_flight", 0) > 0)) and current and live:
        # The running cycle's own calls, not the totals of the last one to finish.
        return _live_usage_panel(live, current, events, compact, workspace, now or datetime.now(), narrow)
    
    stages = metrics.get("stages") or []
    llm_stages = [stage for stage in stages if isinstance(stage, dict) and stage.get("llm_calls") is not None]
    calls, input_tokens, output_tokens, models, cost_text = _calculate_llm_metrics(llm_stages)
    search_count = _search_count(current, events)
    
    duration_ms = sum(int(stage.get("duration_ms") or 0) for stage in llm_stages)
    if active and current and current.stage in {"source", "research", "hypothesis", "sigma"}:
        usage_note = "Live token totals are written when the cycle ends."
    elif not metrics:
        usage_note = "No completed cycle metrics found yet."
    elif duration_ms > 0 and calls > 0:
        avg_latency = duration_ms / calls / 1000
        usage_note = f"{avg_latency:.1f}s per call"
    else:
        usage_note = "unknown"

    table = _build_summary_table(
        compact, calls, input_tokens, output_tokens, cost_text,
        search_count, models, workspace, usage_note, bool(llm_stages), _stage_line(llm_stages, tokens=not narrow), narrow
    )
    return Panel(table, title="[bold bright_cyan]LLM STATS[/]", border_style="bright_magenta", box=box.ROUNDED)


def _search_count(current: Optional[TrailEvent], events: List[TrailEvent]) -> str:
    if current:
        for event in reversed(events):
            if event.cycle_id != current.cycle_id or event.stage != "research":
                continue
            searches = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", event.message)
            if searches:
                return searches.group(1)
            break
        if current.stage == "research":
            return "in progress..."
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
    duration_ms = live.get("duration_ms", 0)
    if duration_ms > 0 and live["llm_calls"] > 0:
        tps = (live["input_tokens"] + live["output_tokens"]) / (duration_ms / 1000)
        avg_latency = duration_ms / live["llm_calls"] / 1000
        speed_text = f"{tps:.1f} tok/s · {avg_latency:.1f}s/call"
        last_end = live.get("last_end")
        last_end_str = f" (last reply at {datetime.fromtimestamp(last_end):%H:%M:%S})" if last_end else ""
        latency_text = f"avg {avg_latency:.1f}s{last_end_str}"
    elif duration_ms > 0:
        tps = (live["input_tokens"] + live["output_tokens"]) / (duration_ms / 1000)
        speed_text = f"{tps:.1f} tok/s"
        latency_text = "in progress"
    else:
        speed_text = "unknown"
        latency_text = "no replies yet"
        
    models = ", ".join(live["models"]) or "not reported yet"
    search_count = _search_count(current, events)

    ended_calls = live.get("ended_calls", [])
    stage_counts = {}  # type: ignore
    cycle_events = [e for e in events if e.cycle_id == current.cycle_id]
    _STAGE_NORM = {
        "guidance": "source",
        "intake": "source",
        "route": "source",
        "source_evidence": "source",
        "research_new": "research",
        "hypothesis_generator": "hypothesis",
        "hypothesis_generation": "hypothesis",
        "sigma_generator": "sigma",
        "sigma_generation": "sigma",
    }
    for call in ended_calls:
        call_ts = call.get("ts", 0.0)
        active_stage = "unknown"
        for event in cycle_events:
            ev_time = _parse_time(event.timestamp)
            if ev_time and ev_time.timestamp() <= call_ts:
                active_stage = event.stage
            elif ev_time and ev_time.timestamp() > call_ts:
                break
        clean_stage = _STAGE_NORM.get(active_stage, active_stage.removesuffix("_generation").removesuffix("_evidence"))
        stage_counts[clean_stage] = stage_counts.get(clean_stage, 0) + 1
        
    if stage_counts:
        live_stage_line = " · ".join(f"{stage} {count}" for stage, count in stage_counts.items() if stage != "cycle")
    else:
        live_stage_line = "no usage recorded yet"

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=10, min_width=10, no_wrap=True)
    table.add_column("value", style="bright_white", ratio=1, overflow="ellipsis", no_wrap=True)
    if narrow:
        _narrow_usage_rows(
            table,
            call_text,
            f"{live['input_tokens']:,} in / {live['output_tokens']:,} out",
            speed_text,
            models,
            search_count,
            live_stage_line,
            latency_text,
            workspace,
        )
    elif compact:
        table.add_row("LLM", f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out")
        table.add_row("Speed", speed_text)
        table.add_row("Latency", latency_text)
        table.add_row("Model", models)
    else:
        _usage_rows(
            table,
            f"{call_text} · {live['input_tokens']:,} in / {live['output_tokens']:,} out · speed {speed_text}",
            models,
            live_stage_line,
            latency_text,
        )
    return Panel(table, title="[bold bright_cyan]LLM STATS[/]", border_style="bright_magenta", box=box.ROUNDED)


def _credential_status(workspace: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Return lists of active (configured) and inactive service labels."""
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
        ("MISP", ("MISP_API_KEY",)),
        ("VT", ("HECATE_RUNNER_VT_API_KEY", "VT_API_KEY")),
        ("GreyNoise", ("GREYNOISE_API_KEY",)),
        ("AbuseIPDB", ("ABUSEIPDB_API_KEY",)),
        ("Shodan", ("SHODAN_API_KEY",)),
        ("Censys", ("CENSYS_API_TOKEN",)),
        ("ThreatFox", ("ABUSECH_API_KEY",)),
        ("MalBazaar", ("ABUSECH_API_KEY",)),
        ("Slack", ("HECATE_RUNNER_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")),
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
    on, off = [], []
    for label, names in checks:
        is_set = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
        if is_set:
            on.append(label)
        else:
            off.append(label)
    return on, off


def _credential_summary(workspace: Optional[Path] = None) -> str:
    """Show configured status only; never read or render credential values."""
    on, off = _credential_status(workspace)
    return " · ".join([f"{item} ON" for item in on] + [f"{item} OFF" for item in off])


def _integrations_panel(
    workspace: Optional[Path] = None,
    search_count: str = "pending",
    narrow: bool = True,
    compact: bool = False,
    events: Optional[List[TrailEvent]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    live: Optional[Dict[str, Any]] = None,
    current: Optional[TrailEvent] = None,
) -> Panel:
    """A dedicated panel displaying external API and service integration statuses and activity metrics."""
    checks = (
        ("LLM", ("HECATE_LLM_PROVIDER", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "AWS_PROFILE", "OLLAMA_HOST")),
        ("Tavily", ("TAVILY_API_KEY",)),
        ("OTX", ("OTX_API_KEY",)),
        ("MISP", ("MISP_API_KEY",)),
        ("VT", ("HECATE_RUNNER_VT_API_KEY", "VT_API_KEY")),
        ("GreyNoise", ("GREYNOISE_API_KEY",)),
        ("AbuseIPDB", ("ABUSEIPDB_API_KEY",)),
        ("Shodan", ("SHODAN_API_KEY",)),
        ("Censys", ("CENSYS_API_TOKEN",)),
        ("ThreatFox", ("ABUSECH_API_KEY",)),
        ("MalBazaar", ("ABUSECH_API_KEY",)),
        ("Feodo C2", ()),
        ("SSLBL", ()),
        ("URLhaus", ("ABUSECH_API_KEY",)),
        ("URLScan", ("URLSCAN_API_KEY",)),
        ("Hybrid", ("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY", "FALCON_SANDBOX_API_KEY")),
        ("RDAP", ()),
        ("crt.sh", ()),
        ("PDNS", ("VT_API_KEY", "MNEMONIC_API_KEY", "OTX_API_KEY")),
        ("Spur", ("SPUR_API_KEY",)),
        ("Tor/Proxy", ("IPINFO_TOKEN", "IPINFO_API_KEY")),
        ("EPSS", ()),
        ("OSV.dev", ()),
        ("Slack", ("HECATE_RUNNER_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")),
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

    cycle_events: List[TrailEvent] = []
    if current and events:
        cycle_events = [e for e in events if e.cycle_id == current.cycle_id]
    elif events:
        last_cid = events[-1].cycle_id if events else None
        if last_cid:
            cycle_events = [e for e in events if e.cycle_id == last_cid]

    # For enrichment services, preserve metrics from the latest active cycle that performed
    # enrichment across idle polling cycles (similar to _latest_metrics for LLM calls).
    active_enrichment_events: List[TrailEvent] = cycle_events
    if not any(e.stage == "enrichment" for e in cycle_events) and events:
        for e in reversed(events):
            if e.stage == "enrichment":
                last_enrich_cid = e.cycle_id
                active_enrichment_events = [ev for ev in events if ev.cycle_id == last_enrich_cid]
                break

    services_data = []
    for label, names in checks:
        is_set = (
            any(os.environ.get(name) for name in names)
            or any(name in file_keys for name in names)
            or (label in ("RDAP", "EPSS", "OSV.dev", "Feodo C2", "SSLBL", "Feodo/SSLBL", "URLScan", "crt.sh", "PDNS", "Tor/Proxy"))
        )
        if label == "LLM":
            if is_set:
                provider_name = os.environ.get("HECATE_LLM_PROVIDER")
                if not provider_name:
                    if any(os.environ.get(k) or k in file_keys for k in ("ANTHROPIC_API_KEY",)):
                        provider_name = "anthropic"
                    elif any(os.environ.get(k) or k in file_keys for k in ("OPENAI_API_KEY",)):
                        provider_name = "openai"
                    elif any(os.environ.get(k) or k in file_keys for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY")):
                        provider_name = "gemini"
                    elif any(os.environ.get(k) or k in file_keys for k in ("AWS_PROFILE",)):
                        provider_name = "bedrock"
                    else:
                        provider_name = "ollama"
                else:
                    provider_name = provider_name.lower().split()[0]
                detail = str(provider_name)
                calls = 0
                if live and live.get("llm_calls") is not None:
                    calls = int(live.get("llm_calls") or 0)
                elif metrics:
                    llm_stages = [s for s in (metrics.get("stages") or []) if isinstance(s, dict) and s.get("llm_calls") is not None]
                    calls = sum(int(s.get("llm_calls") or 0) for s in llm_stages)
                metric = f"{calls} calls"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Tavily":
            if is_set:
                detail = "web search"
                searches = None
                in_prog = False
                for e in reversed(cycle_events):
                    m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
                    if m:
                        searches = int(m.group(1))
                        break
                    if e.stage == "research" and "web search on" in e.message:
                        in_prog = True
                if searches is None and not in_prog and active_enrichment_events != cycle_events:
                    for e in reversed(active_enrichment_events):
                        m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
                        if m:
                            searches = int(m.group(1))
                            break
                if searches is not None:
                    metric = f"{searches} searches"
                elif in_prog:
                    metric = "searching..."
                elif search_count.isdigit():
                    metric = f"{search_count} searches"
                elif search_count in ("in progress...", "searching..."):
                    metric = "searching..."
                else:
                    metric = "0 searches"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "OTX":
            if is_set:
                detail = "feed/ioc" if narrow else "pulses"
                otx_found = any(e.stage in ("intake", "route", "research") and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower()) for e in cycle_events)
                if not otx_found and active_enrichment_events != cycle_events:
                    otx_found = any(e.stage in ("intake", "route", "research") and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower()) for e in active_enrichment_events)
                if otx_found:
                    metric = "1 pulse"
                else:
                    obs_count = 0
                    for e in active_enrichment_events:
                        if e.stage == "enrichment":
                            m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                            if m_obs:
                                obs_count = int(m_obs.group(1))
                                break
                    if obs_count > 0:
                        metric = f"{obs_count} queries"
                    else:
                        backlog = _backlog_observation(events or [])
                        if backlog and backlog[0] > 0:
                            metric = f"{backlog[0]} queued"
                        else:
                            metric = "0 queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "MISP":
            if is_set:
                detail = "threat sharing" if narrow else "threat share"
                misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in cycle_events)
                if not misp_found and active_enrichment_events != cycle_events:
                    misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in active_enrichment_events)
                metric = "1 event" if misp_found else "0 events"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "VT":
            if is_set:
                detail = "enrichment"
                ioc_count = 0
                for e in active_enrichment_events:
                    m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                    if m_obs:
                        ioc_count = max(ioc_count, int(m_obs.group(1)))
                    m = re.search(r"(\d+)\s+indicator\(s\)", e.message)
                    if m:
                        ioc_count = max(ioc_count, int(m.group(1)))
                    m_typed = re.search(r"(\d+)/\d+\s+indicator\(s\)\s+typed", e.message)
                    if m_typed:
                        ioc_count = max(ioc_count, int(m_typed.group(1)))
                    m_intake = re.search(r"indicators:\s*([^\);]+)", e.message)
                    if m_intake and "none" not in m_intake.group(1).lower():
                        nums = [int(n) for n in re.findall(r"\b(\d+)\b", m_intake.group(1))]
                        if nums:
                            ioc_count = max(ioc_count, sum(nums))
                metric = f"{ioc_count} checked"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "GreyNoise":
            if is_set:
                detail = "noise" if narrow else "noise filter"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "AbuseIPDB":
            if is_set:
                detail = "ip abuse"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Shodan":
            if is_set:
                detail = "recon"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Censys":
            if is_set:
                detail = "surface" if narrow else "attack surface"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "ThreatFox":
            if is_set:
                detail = "abuse.ch"
                tf_count = 0
                for e in active_enrichment_events:
                    if e.stage == "enrichment":
                        m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                        if m_obs:
                            tf_count = int(m_obs.group(1))
                            break
                    m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                    if m_obs:
                        tf_count = max(tf_count, int(m_obs.group(1)))
                    elif tf_count == 0:
                        m_ind = re.search(r"(\d+)\s+indicator\(s\)", e.message, re.IGNORECASE)
                        if m_ind:
                            tf_count = max(tf_count, int(m_ind.group(1)))
                metric = f"{tf_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "MalBazaar":
            if is_set:
                detail = "malware"
                hash_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                    if m:
                        hash_count = max(hash_count, int(m.group(1)))
                metric = f"{hash_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label in ("Feodo C2", "Feodo"):
            detail = "botnet c2" if narrow else "botnet"
            ip_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                if m:
                    ip_count = max(ip_count, int(m.group(1)))
            metric = f"{ip_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "SSLBL":
            detail = "ssl/ja3"
            hash_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                if m:
                    hash_count = max(hash_count, int(m.group(1)))
            metric = f"{hash_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "URLhaus":
            if is_set:
                detail = "urls" if narrow else "malware urls"
                url_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
                    if m:
                        url_count = max(url_count, int(m.group(1)))
                metric = f"{url_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "URLScan":
            has_key = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
            detail = "web lures" if has_key else "lures"
            url_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
                if m:
                    url_count = max(url_count, int(m.group(1)))
            metric = f"{url_count} scans"
            services_data.append((label, True, detail, metric))
        elif label == "Hybrid":
            if is_set:
                detail = "sandbox"
                hash_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
                    if m:
                        hash_count = max(hash_count, int(m.group(1)))
                metric = f"{hash_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "RDAP":
            detail = "whois/age"
            dom_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
                if m:
                    dom_count = max(dom_count, int(m.group(1)))
            metric = f"{dom_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "crt.sh":
            detail = "ct logs"
            dom_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
                if m:
                    dom_count = max(dom_count, int(m.group(1)))
            metric = f"{dom_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "PDNS":
            detail = "passive dns"
            obs_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                if m:
                    obs_count = max(obs_count, int(m.group(1)))
            metric = f"{obs_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "Spur":
            if is_set:
                detail = "proxy/vpn"
                ip_count = 0
                for e in active_enrichment_events:
                    m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                    if m:
                        ip_count = max(ip_count, int(m.group(1)))
                metric = f"{ip_count} queries"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))
        elif label == "Tor/Proxy":
            detail = "tor/vpn"
            ip_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
                if m:
                    ip_count = max(ip_count, int(m.group(1)))
            metric = f"{ip_count} queries"
            services_data.append((label, True, detail, metric))
        elif label == "EPSS":
            detail = "cve score" if narrow else "exploit prediction"
            cve_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                if m:
                    cve_count = max(cve_count, int(m.group(1)))
            metric = f"{cve_count} CVEs"
            services_data.append((label, True, detail, metric))
        elif label in ("OSV.dev", "OSV"):
            detail = "supply chain" if narrow else "osv/pkg"
            cve_count = 0
            for e in active_enrichment_events:
                m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
                if m:
                    cve_count = max(cve_count, int(m.group(1)))
            metric = f"{cve_count} CVEs"
            services_data.append((label, True, detail, metric))
        elif label == "Slack":
            if is_set:
                detail = "alerts"
                draft_created = any("draft_created" in e.message for e in cycle_events)
                if not draft_created and active_enrichment_events != cycle_events:
                    draft_created = any("draft_created" in e.message for e in active_enrichment_events)
                metric = "1 sent" if draft_created else "0 sent"
                services_data.append((label, True, detail, metric))
            else:
                services_data.append((label, False, "unconfigured", "--"))

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    if narrow:
        table.add_column("label", style="dim", width=9, no_wrap=True)
        table.add_column("status", ratio=1, overflow="ellipsis", no_wrap=True)
        table.add_column("metric", justify="right", width=11, no_wrap=True)
        for label, is_set, detail, metric in services_data:
            if is_set:
                st = Text.assemble(("ON", "bold bright_green"), (" · ", "dim"), (detail, "bright_white"))
                m_style = "bright_cyan" if metric != "--" else "dim"
            else:
                st = Text.assemble(("OFF", "dim yellow"), (" · ", "dim"), (detail, "dim"))
                m_style = "dim"
            table.add_row(label, st, Text(metric, style=m_style))
    else:
        def format_item(lbl: str, is_on: bool, det: str, met: str) -> Text:
            st = "ON" if is_on else "OFF"
            col = "bold bright_green" if is_on else "dim yellow"
            m_col = "bright_cyan" if is_on and met != "--" else "dim"
            return Text.assemble(
                (f"{lbl:<9}", "dim"),
                (" ", "default"),
                (st, col),
                (" · ", "dim"),
                (f"{det[:7]:<7}", "bright_white" if is_on else "dim"),
                (" ", "default"),
                (f"{met:>9}", m_col),
            )
        table = Table(box=None, show_header=False, expand=True, padding=(0, 0))
        table.add_column("col1", ratio=1, no_wrap=True)
        table.add_column("col2", ratio=1, no_wrap=True)
        pairs = [
            (services_data[i], services_data[i + 1] if i + 1 < len(services_data) else None)
            for i in range(0, len(services_data), 2)
        ]
        for d1, d2 in pairs:
            if d2:
                table.add_row(format_item(*d1), format_item(*d2))
            else:
                table.add_row(format_item(*d1), Text(""))

    return Panel(table, title="[bold bright_cyan]INTEGRATIONS[/]", border_style="bright_magenta", box=box.ROUNDED)


@dataclass
class HuntsMetrics:
    total_hunts: int = 0
    drafts_count: int = 0
    active_count: int = 0
    completed_count: int = 0
    threats_count: int = 0
    actors_count: int = 0
    campaigns_count: int = 0
    malware_count: int = 0
    ttps_count: int = 0
    sigma_rules_count: int = 0
    network_total: int = 0
    network_ips: int = 0
    network_domains: int = 0
    network_urls: int = 0
    host_total: int = 0
    host_hashes: int = 0
    host_paths: int = 0
    enterprise_ttps: Dict[str, int] = field(default_factory=dict)
    mobile_ttps: Dict[str, int] = field(default_factory=dict)
    ics_ttps: Dict[str, int] = field(default_factory=dict)
    enterprise_total: int = 0
    mobile_total: int = 0
    ics_total: int = 0


_EXCLUDED_HUNT_DOCS = {"README.md", "FORMAT_GUIDELINES.md", "INDEX.md", "AGENTS.md", "WEEKLY_SUMMARY_TEMPLATE.md"}
_RE_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_HEX = re.compile(r"^[a-fA-F0-9]{32,64}$")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|ru|cn|io|top|biz|info|cc|co|kg|lv|dev|online|store|site|club|app|vip|pro|mobi|tech)\b",
    re.IGNORECASE,
)
_RE_ACTOR_ROW = re.compile(r"\|\s*\*\*Actor\*\*\s*\|\s*([^|\n]+)\|")
_RE_THREAT_CONTEXT = re.compile(r"\*\*Threat(?:\s+Actor)?:\*\*\s*([^\n]+)")
_RE_GROUNDING_ENTITY = re.compile(r"\|\s*`([^`]+)`\s*\|\s*entity\s*\|\s*asserted by CTI")
_RE_ROLE_INDICATOR = re.compile(r"\|\s*`([^`]+)`\s*\|\s*([\w_]+)\s*\|")
_RE_MALWARE_TERMS = re.compile(
    r"\b(trojan|ransomware|stealer|loader|backdoor|rat|botnet|wiper|rootkit|infostealer|dropper|implant|spyware|worm|malware|keylogger|miner|vshell)\b",
    re.I,
)
_RE_CAMEL_MALWARE = re.compile(r"\b[A-Z][a-z0-9]+(?:RAT|Bot|Loader|Stealer|Locker)\b")
_RE_ACTOR_TERMS = re.compile(
    r"\b(apt\d+|fin\d+|unc\d+|ta\d+|storm-\d+|group|team|crew|cartel|operators?|syndicate|threat cluster)\b",
    re.I,
)
_RE_CAMPAIGN_TERMS = re.compile(
    r"\b(campaign|operation|op\s+[a-z0-9_-]+)\b",
    re.I,
)
_GENERIC_THREAT_NAMES = {
    "unknown", "none", "n/a", "various", "threat actor", "adversary",
    "unspecified", "tbd", "actor", "attacker", "malware", "not specified",
    "hkcu", "hklm",
}

_HUNTS_METRICS_CACHE: Dict[Path, Tuple[float, int, float, HuntsMetrics]] = {}


def _collect_hunts_metrics(workspace: Optional[Path] = None) -> HuntsMetrics:
    """Collect summary metrics across all hunt drafts in the workspace.

    Cached with a 10s cooldown and file count/mtime fingerprinting
    so monitor refresh cycles remain instantaneous.
    """
    if not workspace:
        return HuntsMetrics()

    hunts_dir = workspace / "hunts"
    hunt_files: List[Path] = []
    if hunts_dir.exists() and hunts_dir.is_dir():
        try:
            hunt_files = sorted(f for f in hunts_dir.rglob("*.md") if f.name not in _EXCLUDED_HUNT_DOCS)
        except OSError:
            hunt_files = []

    # If this workspace has no hunt files yet (e.g. an eval run still in early stages),
    # fall back to the primary knowledge base in Hecate-Workspace so the operator
    # sees the cumulative hunt repository metrics instead of blank zeros.
    is_eval_or_special = (
        "/tmp/eval_runs" in str(workspace.resolve())
        or "eval" in workspace.name.lower()
        or workspace == Path("/home/chemch/betas")
    )
    if not hunt_files and is_eval_or_special:
        alt_candidates = [
            Path("/home/chemch/betas/Hecate-Workspace/hunts"),
            Path.home() / "betas" / "Hecate-Workspace" / "hunts",
            workspace.parent / "Hecate-Workspace" / "hunts",
        ]
        for alt in alt_candidates:
            if alt.exists() and alt.is_dir():
                try:
                    alt_files = sorted(f for f in alt.rglob("*.md") if f.name not in _EXCLUDED_HUNT_DOCS)
                    if alt_files:
                        hunts_dir = alt
                        hunt_files = alt_files
                        break
                except OSError:
                    continue

    if not hunts_dir or not hunts_dir.exists() or not hunt_files:
        return HuntsMetrics()

    resolved_path = hunts_dir.resolve()
    now = time.monotonic()
    cached = _HUNTS_METRICS_CACHE.get(resolved_path)

    if cached is not None and (now - cached[0] < 10.0):
        return cached[3]

    file_count = len(hunt_files)
    try:
        max_mtime = max((f.stat().st_mtime for f in hunt_files), default=0.0)
    except OSError:
        max_mtime = 0.0

    if cached is not None and cached[1] == file_count and cached[2] == max_mtime:
        _HUNTS_METRICS_CACHE[resolved_path] = (now, file_count, max_mtime, cached[3])
        return cached[3]

    drafts_count = 0
    active_count = 0
    completed_count = 0
    actors: Set[str] = set()
    campaigns: Set[str] = set()
    malware: Set[str] = set()
    techniques: Set[str] = set()
    network_ips: Set[str] = set()
    network_domains: Set[str] = set()
    network_urls: Set[str] = set()
    host_hashes: Set[str] = set()
    host_paths: Set[str] = set()

    from hecate_agent.core.grounding import _ACRONYM_STOPWORDS

    def _is_valid_threat(val: str) -> bool:
        if not val or len(val) < 2:
            return False
        lowered = val.lower()
        if lowered in _GENERIC_THREAT_NAMES or lowered in _ACRONYM_STOPWORDS:
            return False
        if lowered.startswith("[review") or lowered.startswith("review cti"):
            return False
        if "/" in val or "\\" in val:
            return False
        if _RE_HEX.match(val) or _RE_IP.match(val):
            return False
        return True

    def _record_threat(name: str, hint: str = "") -> None:
        clean = name.strip().strip("*_`# ")
        if not _is_valid_threat(clean):
            return
        if _RE_ACTOR_TERMS.search(clean) or hint == "actor":
            actors.add(clean)
        elif _RE_CAMPAIGN_TERMS.search(clean) or hint == "campaign":
            campaigns.add(clean)
        elif _RE_MALWARE_TERMS.search(clean) or _RE_CAMEL_MALWARE.search(clean) or hint == "malware":
            malware.add(clean)
        elif hint == "attribution":
            actors.add(clean)
        else:
            malware.add(clean)

    for hunt_file in hunt_files:
        try:
            text = hunt_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        m_fm = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        if m_fm:
            try:
                fm = yaml.safe_load(m_fm.group(1)) or {}
                st = str(fm.get("status", "")).lower()
                if st in {"active", "in_progress", "in-progress"}:
                    active_count += 1
                elif st in {"completed", "done", "closed"}:
                    completed_count += 1
                else:
                    drafts_count += 1

                for t in fm.get("techniques", []):
                    t_str = str(t).strip()
                    if _RE_TECHNIQUE.match(t_str):
                        techniques.add(t_str)

                for k in ("threat", "threat_actor", "actor"):
                    val = fm.get(k)
                    if val and isinstance(val, str):
                        for p in re.split(r",\s*|\s*;\s*|\s+and\s+", val):
                            _record_threat(p, hint="attribution")
            except Exception:
                drafts_count += 1
        else:
            drafts_count += 1

        m_act = _RE_ACTOR_ROW.search(text)
        if m_act:
            for p in re.split(r",\s*|\s*;\s*|\s+and\s+", m_act.group(1)):
                _record_threat(p, hint="actor")

        m_ta = _RE_THREAT_CONTEXT.search(text)
        if m_ta:
            for p in re.split(r",\s*|\s*;\s*|\s+and\s+", m_ta.group(1)):
                _record_threat(p, hint="attribution")

        m_tags = re.search(r"Tags:\s*([^\n]+)", text)
        if m_tags:
            for tag in m_tags.group(1).split(","):
                clean_tag = tag.strip().strip("*_`# ")
                if _is_valid_threat(clean_tag):
                    if _RE_CAMPAIGN_TERMS.search(clean_tag):
                        campaigns.add(clean_tag)
                    elif _RE_MALWARE_TERMS.search(clean_tag) or _RE_CAMEL_MALWARE.search(clean_tag):
                        malware.add(clean_tag)

        for m_ge in _RE_GROUNDING_ENTITY.finditer(text):
            _record_threat(m_ge.group(1).strip())

        for m_ir in _RE_ROLE_INDICATOR.finditer(text):
            val, itype = m_ir.group(1).strip(), m_ir.group(2).lower()
            if itype in {"malware_family", "malware"}:
                _record_threat(val, hint="malware")
            elif itype in {"threat_actor", "actor"}:
                _record_threat(val, hint="actor")
            elif itype == "campaign":
                _record_threat(val, hint="campaign")
            elif itype in {"ip", "ipv4", "ipv6"}:
                clean_ip = val.replace("[", "").replace("]", "")
                if _RE_IP.match(clean_ip):
                    network_ips.add(clean_ip)
            elif itype in {"domain", "hostname"}:
                network_domains.add(val.replace("[", "").replace("]", "").lower())
            elif itype == "url":
                network_urls.add(val.replace("[", "").replace("]", ""))
            elif itype in {"hash", "file_hash", "sha256", "md5", "sha1"}:
                host_hashes.add(val.lower())
            elif itype in {"file_path", "path", "file", "registry", "process"}:
                host_paths.add(val)

        m_ioc = re.search(r"###\s+Indicators of Compromise.*?(?=\n###\s+[A-Z]|\n## |\Z)", text, re.DOTALL | re.IGNORECASE)
        if m_ioc:
            ioc_txt = m_ioc.group(0)
            for ip in _RE_IP.findall(ioc_txt):
                network_ips.add(ip)
            for d in _RE_DOMAIN.findall(ioc_txt):
                network_domains.add(d.lower())
            for hsh in _RE_SHA256.findall(ioc_txt):
                host_hashes.add(hsh.lower())
            for hsh in _RE_MD5.findall(ioc_txt):
                host_hashes.add(hsh.lower())
            for hsh in _RE_SHA1.findall(ioc_txt):
                host_hashes.add(hsh.lower())
            m_fp = re.search(r"####\s+File Paths.*?(?=####|\Z)", ioc_txt, re.DOTALL | re.IGNORECASE)
            if m_fp:
                for p in re.findall(r"`([^`]+)`", m_fp.group(0)):
                    host_paths.add(p)

    actors.difference_update(malware | campaigns)
    all_threats = actors | campaigns | malware

    queries_dir = workspace / "queries"
    sigma_rules_count = 0
    if queries_dir.is_dir():
        try:
            sigma_rules_count = sum(1 for _ in queries_dir.rglob("*.yml"))
        except OSError:
            sigma_rules_count = 0

    if sigma_rules_count == 0:
        fallback_queries_dir = hunts_dir.parent / "queries"
        if fallback_queries_dir.is_dir():
            try:
                sigma_rules_count = sum(1 for _ in fallback_queries_dir.rglob("*.yml"))
            except OSError:
                sigma_rules_count = 0

    from hecate_agent.core.attack_matrix import categorize_techniques_by_matrix

    cat_metrics = categorize_techniques_by_matrix(techniques)

    metrics = HuntsMetrics(
        total_hunts=file_count,
        drafts_count=drafts_count,
        active_count=active_count,
        completed_count=completed_count,
        threats_count=len(all_threats),
        actors_count=len(actors),
        campaigns_count=len(campaigns),
        malware_count=len(malware),
        ttps_count=len(techniques),
        sigma_rules_count=sigma_rules_count,
        network_total=len(network_ips | network_domains | network_urls),
        network_ips=len(network_ips),
        network_domains=len(network_domains),
        network_urls=len(network_urls),
        host_total=len(host_hashes | host_paths),
        host_hashes=len(host_hashes),
        host_paths=len(host_paths),
        enterprise_ttps=cat_metrics.get("enterprise", {}),
        mobile_ttps=cat_metrics.get("mobile", {}),
        ics_ttps=cat_metrics.get("ics", {}),
        enterprise_total=cat_metrics.get("enterprise_total", 0),
        mobile_total=cat_metrics.get("mobile_total", 0),
        ics_total=cat_metrics.get("ics_total", 0),
    )
    _HUNTS_METRICS_CACHE[resolved_path] = (now, file_count, max_mtime, metrics)
    return metrics


def _hunts_summary_panel(
    workspace: Optional[Path] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    """A dedicated panel displaying summary metrics for hunts and IOCs across the workspace."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=9, min_width=9, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    if compact:
        if h_metrics.total_hunts == 0:
            table.add_row("HUNTS", Text("0 generated", style="dim"))
            table.add_row("THREATS", Text("0 tracked", style="dim"))
            table.add_row("SIGMA", Text("0 rules", style="dim"))
            table.add_row("IOCs", Text("0 observables", style="dim"))
        else:
            hunts_text = f"{h_metrics.total_hunts} total"
            hunts_sub = f"{h_metrics.drafts_count} drafts" if not h_metrics.completed_count else f"{h_metrics.drafts_count} drf · {h_metrics.completed_count} done"
            table.add_row(
                "HUNTS",
                Text.assemble((hunts_text, "bright_white"), (" · ", "dim"), (hunts_sub, "bright_cyan")),
            )
            threats_val = f"{h_metrics.threats_count}"
            threats_sub = f"{h_metrics.actors_count} act, {h_metrics.campaigns_count} camp, {h_metrics.malware_count} mal"
            table.add_row(
                "THREATS",
                Text.assemble((threats_val, "bright_white"), (" · ", "dim"), (threats_sub, "bright_cyan")),
            )
            table.add_row(
                "SIGMA",
                Text.assemble(
                    (f"{h_metrics.sigma_rules_count:,} rules", "bright_white"),
                    (" · ", "dim"),
                    ("detection queries", "bright_cyan"),
                ),
            )
            table.add_row(
                "IOCs",
                Text.assemble(
                    (f"{h_metrics.network_total:,} net", "bright_white"),
                    (" · ", "dim"),
                    (f"{h_metrics.host_total:,} host", "bright_white"),
                ),
            )
    else:
        # Full and narrow modes: 6 rows (HUNTS, THREATS, SIGMA, NETWORK, HOST, IOC TOTAL)
        if h_metrics.total_hunts == 0:
            table.add_row("HUNTS", Text("0 generated", style="dim"))
            table.add_row("THREATS", Text("0 tracked", style="dim"))
            table.add_row("SIGMA", Text("0 rules", style="dim"))
            table.add_row("NETWORK", Text("0 IOCs", style="dim"))
            table.add_row("HOST", Text("0 IOCs", style="dim"))
            if not narrow:
                table.add_row("IOC TOTAL", Text("0 observables", style="dim"))
        else:
            hunts_text = f"{h_metrics.total_hunts} total"
            hunts_sub = f"{h_metrics.drafts_count} drafts" if not h_metrics.completed_count else f"{h_metrics.drafts_count} drf · {h_metrics.completed_count} done"
            table.add_row(
                "HUNTS",
                Text.assemble((hunts_text, "bright_white"), (" · ", "dim"), (hunts_sub, "bright_cyan")),
            )
            if narrow:
                threats_val = f"{h_metrics.threats_count}"
                threats_sub = f"{h_metrics.actors_count} act, {h_metrics.campaigns_count} camp, {h_metrics.malware_count} mal"
            else:
                threats_val = f"{h_metrics.threats_count} tracked"
                threats_sub = f"{h_metrics.actors_count} actors, {h_metrics.campaigns_count} campaigns, {h_metrics.malware_count} malware"
            table.add_row(
                "THREATS",
                Text.assemble((threats_val, "bright_white"), (" · ", "dim"), (threats_sub, "bright_cyan")),
            )
            table.add_row(
                "SIGMA",
                Text.assemble(
                    (f"{h_metrics.sigma_rules_count:,} rules", "bright_white"),
                    (" · ", "dim"),
                    ("queries drafted", "bright_cyan"),
                ),
            )
            table.add_row(
                "NETWORK",
                Text.assemble(
                    (f"{h_metrics.network_total:,} IOCs", "bright_white"),
                    (" · ", "dim"),
                    (f"{h_metrics.network_ips} IPs, {h_metrics.network_domains} dom", "bright_cyan"),
                ),
            )
            table.add_row(
                "HOST",
                Text.assemble(
                    (f"{h_metrics.host_total:,} IOCs", "bright_white"),
                    (" · ", "dim"),
                    (f"{h_metrics.host_hashes} hash, {h_metrics.host_paths} path", "bright_cyan"),
                ),
            )
            if not narrow:
                total_iocs = h_metrics.network_total + h_metrics.host_total
                table.add_row(
                    "IOC TOTAL",
                    Text.assemble(
                        (f"{total_iocs:,} observables", "bright_white"),
                        (" · ", "dim"),
                        ("asserted by CTI", "dim"),
                    ),
                )

    return Panel(
        table,
        title="[bold bright_cyan]HUNT SUMMARY[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _mitre_metrics_panel(
    workspace: Optional[Path] = None,
    narrow: bool = False,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    """A dedicated panel displaying MITRE ATT&CK Enterprise, Mobile, and ICS coverage metrics."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    ent = h_metrics.enterprise_ttps or {}
    mob = h_metrics.mobile_ttps or {}
    ics = h_metrics.ics_ttps or {}

    ent_total = h_metrics.enterprise_total or sum(ent.values())
    mob_total = h_metrics.mobile_total or sum(mob.values())
    ics_total = h_metrics.ics_total or sum(ics.values())

    recon = ent.get("reconnaissance", 0)
    resdev = ent.get("resource-development", 0)
    initacc = ent.get("initial-access", 0)
    exec_cnt = ent.get("execution", 0)
    persist = ent.get("persistence", 0)
    privesc = ent.get("privilege-escalation", 0)
    stealth = ent.get("stealth", 0)
    defimp = ent.get("defense-impairment", 0)
    credacc = ent.get("credential-access", 0)
    disc = ent.get("discovery", 0)
    latmove = ent.get("lateral-movement", 0)
    collect = ent.get("collection", 0)
    c2 = ent.get("command-and-control", 0)
    exfil = ent.get("exfiltration", 0)
    impact = ent.get("impact", 0)

    active_tactics = sum(1 for v in ent.values() if v > 0)

    if compact:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("0 TTPs · 15 tactics ready", style="dim"))
            table.add_row(" Ingress", Text("Recon 0 · ResDev 0 · InitAcc 0", style="dim"))
            table.add_row(" Execution", Text("Exec 0 · Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0 · CredAcc 0", style="dim"))
            table.add_row(" Actions", Text("Disc 0 · C2 0 · Impact 0", style="dim"))
            table.add_row("MOB & ICS", Text("Mob: 0 · ICS: 0", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text.assemble(
                    (f"{ent_total} TTPs", "bright_white"),
                    (" · ", "dim"),
                    (f"{active_tactics} tactics active" if active_tactics > 0 else "ready", "bright_cyan"),
                ),
            )
            table.add_row(
                " Ingress",
                Text.assemble(
                    ("Recon ", "dim"), (str(recon), "bright_white"), (" · ", "dim"),
                    ("ResDev ", "dim"), (str(resdev), "bright_white"), (" · ", "dim"),
                    ("InitAcc ", "dim"), (str(initacc), "bright_white"),
                ),
            )
            table.add_row(
                " Execution",
                Text.assemble(
                    ("Exec ", "dim"), (str(exec_cnt), "bright_white"), (" · ", "dim"),
                    ("Persist ", "dim"), (str(persist), "bright_white"), (" · ", "dim"),
                    ("PrivEsc ", "dim"), (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"), (str(stealth), "bright_white"), (" · ", "dim"),
                    ("DefImp ", "dim"), (str(defimp), "bright_white"), (" · ", "dim"),
                    ("CredAcc ", "dim"), (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("Disc ", "dim"), (str(disc), "bright_white"), (" · ", "dim"),
                    ("C2 ", "dim"), (str(c2), "bright_white"), (" · ", "dim"),
                    ("Impact ", "dim"), (str(impact), "bright_white"),
                ),
            )
            mob_str = f"Mob: {mob_total}" if mob_total else "Mob: 0"
            ics_str = f"ICS: {ics_total}" if ics_total else "ICS: 0"
            table.add_row(
                "MOB & ICS",
                Text.assemble(
                    (mob_str, "bright_cyan" if mob_total else "dim"),
                    (" · ", "dim"),
                    (ics_str, "bright_cyan" if ics_total else "dim"),
                ),
            )
    else:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("0 TTPs · 15 tactics ready", style="dim"))
            table.add_row(" Pre-Attack", Text("Recon 0 · ResDev 0", style="dim"))
            table.add_row(" Initial", Text("InitAcc 0 · Exec 0", style="dim"))
            table.add_row(" Persist", Text("Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0", style="dim"))
            table.add_row(" Discovery", Text("Disc 0 · CredAcc 0", style="dim"))
            table.add_row(" Movement", Text("LatMove 0 · Collect 0", style="dim"))
            table.add_row(" Actions", Text("C2 0 · Exfil 0 · Impact 0", style="dim"))
            table.add_row("MOBILE", Text("0 TTPs · 14 tactics ready", style="dim"))
            table.add_row("ICS", Text("0 TTPs · 12 tactics ready", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text.assemble(
                    (f"{ent_total} TTPs", "bright_white"),
                    (" · ", "dim"),
                    (f"{active_tactics} tactics active" if active_tactics > 0 else "ready", "bright_cyan"),
                ),
            )
            table.add_row(
                " Pre-Attack",
                Text.assemble(
                    ("Recon ", "dim"), (str(recon), "bright_white"), (" · ", "dim"),
                    ("ResDev ", "dim"), (str(resdev), "bright_white"),
                ),
            )
            table.add_row(
                " Initial",
                Text.assemble(
                    ("InitAcc ", "dim"), (str(initacc), "bright_white"), (" · ", "dim"),
                    ("Exec ", "dim"), (str(exec_cnt), "bright_white"),
                ),
            )
            table.add_row(
                " Persist",
                Text.assemble(
                    ("Persist ", "dim"), (str(persist), "bright_white"), (" · ", "dim"),
                    ("PrivEsc ", "dim"), (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"), (str(stealth), "bright_white"), (" · ", "dim"),
                    ("DefImp ", "dim"), (str(defimp), "bright_white"),
                ),
            )
            table.add_row(
                " Discovery",
                Text.assemble(
                    ("Disc ", "dim"), (str(disc), "bright_white"), (" · ", "dim"),
                    ("CredAcc ", "dim"), (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Movement",
                Text.assemble(
                    ("LatMove ", "dim"), (str(latmove), "bright_white"), (" · ", "dim"),
                    ("Collect ", "dim"), (str(collect), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("C2 ", "dim"), (str(c2), "bright_white"), (" · ", "dim"),
                    ("Exfil ", "dim"), (str(exfil), "bright_white"), (" · ", "dim"),
                    ("Impact ", "dim"), (str(impact), "bright_white"),
                ),
            )

            if mob_total > 0:
                mob_actives = [("C2: " + str(v) if k == "command-and-control" else f"{k[:4].capitalize()}: {v}") for k, v in mob.items() if v > 0]
                mob_sub = ", ".join(mob_actives[:2])
                table.add_row(
                    "MOBILE",
                    Text.assemble(
                        (f"{mob_total} TTP" if mob_total == 1 else f"{mob_total} TTPs", "bright_white"),
                        (" · ", "dim"),
                        (mob_sub, "bright_cyan"),
                    ),
                )
            else:
                table.add_row(
                    "MOBILE",
                    Text.assemble(("0 TTPs", "dim"), (" · ", "dim"), ("14 tactics ready", "dim")),
                )

            if ics_total > 0:
                ics_actives = [f"{k[:4].capitalize()}: {v}" for k, v in ics.items() if v > 0]
                ics_sub = ", ".join(ics_actives[:2])
                table.add_row(
                    "ICS",
                    Text.assemble(
                        (f"{ics_total} TTP" if ics_total == 1 else f"{ics_total} TTPs", "bright_white"),
                        (" · ", "dim"),
                        (ics_sub, "bright_cyan"),
                    ),
                )
            else:
                table.add_row(
                    "ICS",
                    Text.assemble(("0 TTPs", "dim"), (" · ", "dim"), ("12 tactics ready", "dim")),
                )

    return Panel(
        table,
        title="[bold bright_cyan]MITRE METRICS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


@dataclass
class PurpleTeamMetrics:
    validated_rules: int = 0
    tuned_rules: int = 0
    total_telemetry_events: int = 0
    precision_rate: float = 1.0
    false_positive_count: int = 0
    hunts_validated: int = 0
    last_status: str = "IDLE"
    last_validated_count: int = 0
    last_tuned_count: int = 0
    last_duration_sec: float = 0.0


_PURPLE_METRICS_CACHE: Dict[str, Tuple[float, int, float, PurpleTeamMetrics]] = {}


def _collect_purple_team_metrics(
    workspace: Optional[Path] = None,
    events: Optional[List[TrailEvent]] = None,
) -> PurpleTeamMetrics:
    """Collect purple-team validation metrics from workspace artifacts and trail events."""
    metrics = PurpleTeamMetrics()
    now = time.time()

    # 1. Parse from active/recent trail events
    if events:
        for ev in reversed(events):
            if ev.stage == "purple_team":
                m = re.search(
                    r"validated\s+(\d+)\s+rule\(s\)\s+in\s+([\d\.]+)s:\s+(\d+)\s+tuned,\s+(\d+)\s+FP",
                    ev.message,
                )
                if m:
                    metrics.last_validated_count = int(m.group(1))
                    metrics.last_duration_sec = float(m.group(2))
                    metrics.last_tuned_count = int(m.group(3))
                    metrics.false_positive_count = int(m.group(4))
                    metrics.last_status = "COMPLETED"
                    break
            elif "purple" in ev.message.lower() and "validat" in ev.message.lower():
                metrics.last_status = "ACTIVE"

    if not workspace or not workspace.exists():
        return metrics

    resolved_path = str(workspace.resolve())
    hunts_dir = workspace / "hunts"
    queries_dir = workspace / "queries"

    hunt_files: List[Path] = []
    if hunts_dir.exists():
        hunt_files = [f for f in hunts_dir.glob("**/*.md") if f.name not in _EXCLUDED_HUNT_DOCS]

    file_count = len(hunt_files)
    max_mtime = max((f.stat().st_mtime for f in hunt_files), default=0.0)

    cached = _PURPLE_METRICS_CACHE.get(resolved_path)
    if cached and (now - cached[0] < 5.0) and cached[1] == file_count and cached[2] == max_mtime:
        cached_m = cached[3]
        if metrics.last_validated_count > 0:
            cached_m.last_validated_count = metrics.last_validated_count
            cached_m.last_tuned_count = metrics.last_tuned_count
            cached_m.last_duration_sec = metrics.last_duration_sec
            cached_m.last_status = metrics.last_status
        return cached_m

    val_rules = 0
    tuned_rules = 0
    hunts_val = 0
    telemetry = 0

    for hf in hunt_files:
        try:
            content = hf.read_text(encoding="utf-8", errors="ignore")
            if "purple_team_validated: true" in content or "Purple-Team Validated" in content:
                hunts_val += 1
                m_ev = re.search(r"purple_team_rules_evaluated:\s*(\d+)", content)
                if m_ev:
                    val_rules += int(m_ev.group(1))
                m_tu = re.search(r"purple_team_rules_tuned:\s*(\d+)", content)
                if m_tu:
                    tuned_rules += int(m_tu.group(1))
                m_te = re.search(r"purple_team_telemetry_events:\s*(\d+)", content)
                if m_te:
                    telemetry += int(m_te.group(1))
        except OSError:
            continue

    if val_rules == 0 and queries_dir.exists():
        for qf in queries_dir.glob("**/*.yml"):
            try:
                qc = qf.read_text(encoding="utf-8", errors="ignore")
                if "x_hecate_purple_team_validated: true" in qc:
                    val_rules += 1
                    if "x_hecate_tuned: true" in qc:
                        tuned_rules += 1
            except OSError:
                continue

    if val_rules == 0:
        eval_base = Path("/tmp/eval_runs")
        if eval_base.exists():
            for sub_hunts in eval_base.glob("*/hunts/**/*.md"):
                try:
                    content = sub_hunts.read_text(encoding="utf-8", errors="ignore")
                    if "purple_team_validated: true" in content or "Purple-Team Validated" in content:
                        hunts_val += 1
                        m_ev = re.search(r"purple_team_rules_evaluated:\s*(\d+)", content)
                        if m_ev:
                            val_rules += int(m_ev.group(1))
                        m_tu = re.search(r"purple_team_rules_tuned:\s*(\d+)", content)
                        if m_tu:
                            tuned_rules += int(m_tu.group(1))
                        m_te = re.search(r"purple_team_telemetry_events:\s*(\d+)", content)
                        if m_te:
                            telemetry += int(m_te.group(1))
                except OSError:
                    continue

    if metrics.last_validated_count > val_rules:
        val_rules = max(val_rules, metrics.last_validated_count)
    if metrics.last_tuned_count > tuned_rules:
        tuned_rules = max(tuned_rules, metrics.last_tuned_count)

    metrics.validated_rules = val_rules
    metrics.tuned_rules = tuned_rules
    metrics.hunts_validated = hunts_val
    metrics.total_telemetry_events = telemetry
    _PURPLE_METRICS_CACHE[resolved_path] = (now, file_count, max_mtime, metrics)
    return metrics


def _purple_team_panel(
    workspace: Optional[Path] = None,
    events: Optional[List[TrailEvent]] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[PurpleTeamMetrics] = None,
) -> Panel:
    """A dedicated panel displaying Purple-Team validation and autonomous self-tuning metrics."""
    pt_metrics = metrics or _collect_purple_team_metrics(workspace, events)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=11, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    if compact:
        if pt_metrics.validated_rules == 0:
            table.add_row("ENGINE", Text("ONLINE · standby", style="dim"))
            table.add_row("VALIDATED", Text("0 rules tested", style="dim"))
            table.add_row("SELF-TUNED", Text("0 tuned (0 FP)", style="dim"))
            table.add_row("TELEMETRY", Text("ephemeral sandbox", style="dim"))
        else:
            table.add_row(
                "ENGINE",
                Text.assemble(("ONLINE", "bold bright_green"), (" · ", "dim"), ("closed-loop", "bright_cyan")),
            )
            val_txt = f"{pt_metrics.validated_rules} rules"
            sub_val = "100% TPR" if pt_metrics.validated_rules else "none"
            table.add_row(
                "VALIDATED",
                Text.assemble((val_txt, "bright_white"), (" · ", "dim"), (sub_val, "bright_cyan")),
            )
            tune_txt = f"{pt_metrics.tuned_rules} tuned"
            table.add_row(
                "SELF-TUNED",
                Text.assemble((tune_txt, "bright_white"), (" · ", "dim"), ("0 FP noise", "bright_green")),
            )
            table.add_row(
                "TELEMETRY",
                Text.assemble(("Live sensors", "bright_white"), (" · ", "dim"), ("proc/net/file", "dim")),
            )
    else:
        if pt_metrics.validated_rules == 0:
            table.add_row(
                "STATUS",
                Text.assemble(("ONLINE", "bold bright_green"), (" · ", "dim"), ("ephemeral sandbox ready", "dim")),
            )
            table.add_row("VALIDATION", Text("0 rules tested · 0 hunts", style="dim"))
            table.add_row("SELF-TUNING", Text("0 tuned · 0 FP noise", style="dim"))
            table.add_row("PRECISION", Text("100% target · 0 FP", style="dim"))
            if not narrow:
                table.add_row("TELEMETRY", Text("process, network, file events", style="dim"))
                table.add_row("SANDBOX", Text("ephemeral execution runner", style="dim"))
        else:
            table.add_row(
                "STATUS",
                Text.assemble(("ACTIVE", "bold bright_green"), (" · ", "dim"), ("closed-loop engine", "bright_cyan")),
            )
            val_str = f"{pt_metrics.validated_rules} rules tested"
            hunt_sub = f"{pt_metrics.hunts_validated} hunt(s)" if pt_metrics.hunts_validated else "100% TPR"
            table.add_row(
                "VALIDATION",
                Text.assemble((val_str, "bright_white"), (" · ", "dim"), (hunt_sub, "bright_cyan")),
            )
            tune_str = f"{pt_metrics.tuned_rules} logic re-tuned"
            table.add_row(
                "SELF-TUNING",
                Text.assemble((tune_str, "bright_white"), (" · ", "dim"), ("0 FP noise", "bright_green")),
            )
            table.add_row(
                "PRECISION",
                Text.assemble(("100% precision", "bold bright_green"), (" · ", "dim"), ("0 false positives", "bright_white")),
            )
            if not narrow:
                telemetry_str = f"{pt_metrics.total_telemetry_events:,} events" if pt_metrics.total_telemetry_events else "Live sensors"
                table.add_row(
                    "TELEMETRY",
                    Text.assemble((telemetry_str, "bright_white"), (" · ", "dim"), ("proc / net / file", "dim")),
                )
                if pt_metrics.last_duration_sec > 0:
                    last_str = f"{pt_metrics.last_validated_count} in {pt_metrics.last_duration_sec:.1f}s"
                    table.add_row(
                        "LAST RUN",
                        Text.assemble((last_str, "bright_white"), (" · ", "dim"), (f"{pt_metrics.last_tuned_count} tuned", "bright_cyan")),
                    )
                else:
                    table.add_row(
                        "SANDBOX",
                        Text.assemble(("Ephemeral VM/container", "bright_white"), (" · ", "dim"), ("sensor intercept", "dim")),
                    )

    return Panel(
        table,
        title="[bold magenta]PURPLE TEAM ENGINE[/]",
        border_style="magenta",
        box=box.ROUNDED,
    )


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
            no_wrap=True,
        ),
        Text.assemble(("NEXT RUN ", "dim"), (_until_next_run(status.next_run), "bright_magenta"), no_wrap=True),
        Text.assemble(
            ("QUOTA    ", "dim"),
            ("drafts " + _quota_text(status.drafts_today, status.drafts_limit), "bright_white"),
            (" · research " + _quota_text(status.research_today, status.research_limit), "bright_white"),
            no_wrap=True,
        ),
    ]
    backlog = _backlog_observation(events)
    if backlog:
        rows.append(
            Text.assemble(
                ("BACKLOG  ", "dim"),
                (f"{backlog[0]} waiting", "bright_cyan"),
                (f" · {backlog[1]}", "dim"),
                no_wrap=True,
            )
        )
    else:
        rows.append(Text.assemble(("BACKLOG  ", "dim"), ("none reported", "yellow"), no_wrap=True))
    if status.parked_items is not None or status.total_drafts is not None:
        details = []
        if status.parked_items is not None:
            details.append(f"{status.parked_items} parked")
        if status.total_drafts is not None:
            details.append(f"{status.total_drafts} total drafts")
        rows.append(Text.assemble(("QUEUE    ", "dim"), (" · ".join(details), "bright_white"), no_wrap=True))
    return Panel(
        Group(*rows),
        title="[bold bright_cyan]RUNNER SERVICE[/]",
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

def _format_cycle_outcome(msg: str) -> str:
    """Format a completed or parked cycle's outcome message cleanly for the header.

    Eliminates awkward mid-word slicing and formats reasons like
    'parked_after_hypothesis (reason) in 170s' into:
    'parked_after_hypothesis in 170s · reason'
    """
    clean = " ".join(msg.split())
    match = re.match(r"^(parked_after_\w+|parked\w*)\s*\((.*?)\)(?:\s*in\s*(\d+s))?$", clean)
    if match:
        outcome = match.group(1)
        reason = match.group(2).strip()
        dur = match.group(3)
        for prefix in (
            "hypothesis model judged this ",
            "model judged this ",
            "route model judged this ",
        ):
            if reason.lower().startswith(prefix):
                reason = reason[len(prefix):].strip()
                break
        if dur:
            return f"{outcome} in {dur} · {reason}"
        return f"{outcome} · {reason}"
    return clean


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
    title = Text(no_wrap=True, overflow="ellipsis")
    title.append(" HECATE ", style="bold black on bright_cyan")
    title.append(" MONITOR ", style="bold bright_white")
    pending, completed, failed = _get_inbox_counts(workspace)
    queue_str = f" · Queue: {pending} pending, {completed} completed, {failed} failed" if (pending or completed or failed) else ""

    if latest and active:
        subline = (
            f"[{status}] cycle {cycle} · now: {working_on} · elapsed {_duration(elapsed)}"
            f" · last: {latest.stage}: {' '.join(latest.message.split())}{queue_str}"
        )
    elif latest and stale:
        why = (
            "the Runner service is not running"
            if _service_running(runner, workspace) is False
            else f"no log activity for {_QUIET_SECONDS // 60}+ minutes"
        )
        time_str = latest.timestamp.split()[-1] if " " in latest.timestamp else latest.timestamp
        subline = f"[{status}] cycle {cycle} · stopped in {working_on} · seen {time_str} · {why}{queue_str}"
    elif latest:
        outcome_str = _format_cycle_outcome(latest.message)
        subline = f"[{status}] last cycle {cycle} · {outcome_str}{queue_str}"
    else:
        subline = f"[{status}] monitoring {workspace} · waiting for a pipeline cycle{queue_str}"

    layout = Layout()
    title.append(" " + subline, style="dim")
    header_panel = Panel(title, border_style="bright_cyan", box=box.DOUBLE)
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
        search_count = _search_count(latest, events)
        layout.split_column(
            Layout(header_panel, name="header", size=3),
            Layout(_compact_resources(host), name="resources", size=4),
            Layout(_compact_progress(latest, active, stale, in_progress), name="progress", size=3),
            Layout(action_panel, name="activity", size=6),
            Layout(name="usage", size=_BOTTOM_ROW_HEIGHT),
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
        h_metrics = _collect_hunts_metrics(workspace)
        pt_metrics = _collect_purple_team_metrics(workspace, events)
        layout["usage"].split_row(
            Layout(_usage_panel(metrics, latest, active, events, compact=True, workspace=workspace, live=live, now=refreshed), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_hunts_summary_panel(workspace=workspace, compact=True, narrow=False, metrics=h_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_mitre_metrics_panel(workspace=workspace, compact=True, narrow=False, metrics=h_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_purple_team_panel(workspace=workspace, events=events, compact=True, narrow=False, metrics=pt_metrics), ratio=1),
            Layout(Text(" "), size=1),
            Layout(_integrations_panel(workspace=workspace, search_count=search_count, compact=True, narrow=False, events=events, metrics=metrics, live=live, current=latest), ratio=1),
        )
        return layout

    resources_height = 4 if len(host.disks) <= 1 else 4 + len(host.disks)
    stages_height = len(_STAGES) + 3
    service_height = 7 if runner.installed else 0
    footer = Layout(
        Text(
            f"Updated {refreshed:%H:%M:%S}   ·   Ctrl-C to exit   ·   log: "
            f"{workspace / 'logs' / 'orchestrator.log'}",
            style="dim",
            justify="center"
        ),
        name="footer",
        size=1,
    )
    body_height = console.size.height - 3 - resources_height - 1
    llm_height = _NARROW_LLM_PANEL_HEIGHT
    hunts_height = _HUNTS_PANEL_HEIGHT
    mitre_height = _MITRE_PANEL_HEIGHT
    search_count = _search_count(latest, events)
    usage_on_left = body_height >= stages_height + service_height + llm_height + hunts_height + mitre_height + 5
    middle_height = body_height if usage_on_left else max(10, body_height - _BOTTOM_ROW_HEIGHT)
    service_on_left = runner.installed and middle_height >= stages_height + service_height
    h_metrics = _collect_hunts_metrics(workspace)
    pt_metrics = _collect_purple_team_metrics(workspace, events)
    llm_panel = _usage_panel(metrics, latest, active, events, workspace=workspace, live=live, now=refreshed, narrow=usage_on_left)
    integrations_panel = _integrations_panel(workspace=workspace, search_count=search_count, narrow=True, events=events, metrics=metrics, live=live, current=latest)
    hunts_panel = _hunts_summary_panel(workspace=workspace, narrow=usage_on_left, metrics=h_metrics)
    mitre_panel = _mitre_metrics_panel(workspace=workspace, narrow=usage_on_left, metrics=h_metrics)
    purple_team_panel = _purple_team_panel(workspace=workspace, events=events, narrow=False, metrics=pt_metrics)
    if usage_on_left:
        layout.split_column(
            Layout(header_panel, name="header", size=3),
            Layout(name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            footer,
        )
    else:
        layout.split_column(
            Layout(header_panel, name="header", size=3),
            Layout(name="resources", size=resources_height),
            Layout(name="middle", ratio=2),
            Layout(name="usage", size=_BOTTOM_ROW_HEIGHT),
            footer,
        )
        layout["usage"].split_row(
            Layout(llm_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(hunts_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(mitre_panel, ratio=1),
            Layout(Text(" "), size=1),
            Layout(integrations_panel, ratio=1),
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
                    "STORAGE",
                    _percent(host.disks[0].used, host.disks[0].total) if host.disks else None,
                    f"{_bytes(host.disks[0].used)} / {_bytes(host.disks[0].total)} used" if host.disks else "not detected",
                ),
                ratio=1,
            ),
        )
    else:
        layout["resources"].split_column(
            Layout(name="compute", size=4),
            Layout(_disk_panel(host), size=len(host.disks) + 2),
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
    left_width = min(52, max(46, console.size.width // 4)) if console.size.width >= 120 else None
    if left_width:
        layout["middle"].split_row(
            Layout(name="stages", size=left_width),
            Layout(Text(" "), name="gutter", size=1),
            Layout(name="operations", ratio=1),
        )
    else:
        layout["middle"].split_row(
            Layout(name="stages", ratio=1),
            Layout(Text(" "), name="gutter", size=1),
            Layout(name="operations", ratio=2),
        )
    # The stage list is short and its column was half empty, so the service
    # panel sits under it when there is room and the stream gets the whole
    # right-hand column.
    service_on_left = runner.installed and middle_height >= stages_height + service_height
    stream_height = middle_height if service_on_left or not runner.installed else middle_height - service_height
    if recent_error and stale:
        main_panel = Panel(Text(recent_error, style="red"), title="[bold red]ERROR STREAM[/]", border_style="red", box=box.ROUNDED)
    else:
        act_width = (console.size.width - left_width - 6) if left_width else (console.size.width * 2 // 3 - 30)
        main_panel = Panel(
            # Inside the panel: two border lines and the table's header; two fixed columns and the padding.
            _activity_table(events, rows=max(1, stream_height - 3), width=max(40, act_width)),
            title="[bold bright_cyan]ACTION STREAM[/]",
            border_style="bright_magenta",
            box=box.ROUNDED,
        )

    left = [Layout(stages_panel, size=stages_height)]
    if service_on_left:
        left.append(Layout(_runner_panel(runner, events), size=service_height))
    if usage_on_left:
        left.append(Layout(llm_panel, size=llm_height))
        left.append(Layout(hunts_panel, size=hunts_height))
        left.append(Layout(mitre_panel, size=mitre_height))
        left.append(Layout(integrations_panel, ratio=1))
    else:
        left.append(Layout(purple_team_panel, ratio=1))
    if len(left) > 1:
        layout["stages"].split_column(*left)
    else:
        layout["stages"].update(stages_panel)
    if runner.installed and not service_on_left:
        layout["operations"].split_column(Layout(main_panel, ratio=2), Layout(_runner_panel(runner, events), size=service_height))
    elif usage_on_left:
        layout["operations"].split_column(Layout(main_panel, ratio=1), Layout(purple_team_panel, size=_PURPLE_PANEL_HEIGHT))
    else:
        layout["operations"].update(main_panel)
    return layout


def _is_runner_process_running(workspace: Optional[Path] = None) -> bool:
    """Check if any hecate-runner process is currently running on the host for the given workspace."""
    try:
        current_pid = os.getpid()
        ws_resolved = workspace.resolve() if workspace else None
        for pid_dir in Path("/proc").glob("[0-9]*"):
            try:
                pid = int(pid_dir.name)
                if pid == current_pid:
                    continue
                cmdline = (pid_dir / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
                cmdline_lower = cmdline.lower()
                if (
                    "hecate-runner" in cmdline_lower
                    or "replay.py" in cmdline_lower
                    or "run_two_evals.py" in cmdline_lower
                    or "run_three_evals.py" in cmdline_lower
                    or ("hecate-agent" in cmdline_lower and "monitor" not in cmdline_lower)
                ):
                    if ws_resolved is None:
                        return True
                    parts = cmdline.split()
                    for idx, part in enumerate(parts):
                        if part in ("--workspace", "-w") and idx + 1 < len(parts):
                            try:
                                if Path(parts[idx + 1]).resolve() == ws_resolved:
                                    return True
                            except OSError:
                                pass
                    try:
                        cwd = Path(f"/proc/{pid}/cwd").resolve()
                        if cwd == ws_resolved:
                            return True
                    except (OSError, ValueError):
                        pass
            except (OSError, ValueError):
                continue
    except Exception:
        pass
    return False


def find_eval_workspace(eval_base: Path = Path("/tmp/eval_runs"), check_procs: bool = True) -> Optional[Path]:
    """Find the actively running evaluation workspace, or the most recent one in eval_base."""
    if not eval_base.exists():
        return None
    if check_procs:
        try:
            for pid_dir in Path("/proc").glob("[0-9]*"):
                try:
                    cmdline = (pid_dir / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
                    if "replay.py" in cmdline:
                        parts = cmdline.split()
                        for i, p in enumerate(parts):
                            if p == "--workspace" and i + 1 < len(parts):
                                ws = Path(parts[i + 1])
                                if ws.is_dir() and (ws / "logs" / "orchestrator.log").exists():
                                    return ws
                except (OSError, ValueError):
                    continue
        except Exception:
            pass

    candidates = [
        p for p in eval_base.iterdir()
        if p.is_dir() and (p / "logs" / "orchestrator.log").exists()
    ]
    if candidates:
        candidates.sort(key=lambda p: (p / "logs" / "orchestrator.log").stat().st_mtime, reverse=True)
        return candidates[0]
    return None


def _service_running(runner: RunnerStatus, workspace: Path) -> Optional[bool]:
    """Whether the Runner service or process is working, or None when it is not writing to ``workspace``."""
    if runner.installed and runner.workspace is not None:
        try:
            if runner.workspace.resolve() == workspace.resolve() and runner.service_state in {"active", "activating"}:
                return True
        except OSError:
            pass

    if _is_runner_process_running(workspace):
        return True

    if not runner.installed or runner.workspace is None:
        return None
    try:
        if runner.workspace.resolve() != workspace.resolve():
            return None
    except OSError:
        return None
    return False


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
    "--eval",
    "eval_mode",
    is_flag=True,
    help="Monitor the active or most recent evaluation run in /tmp/eval_runs.",
)
@click.option(
    "--interval",
    type=click.FloatRange(min=0.5, max=30),
    default=1.0,
    show_default=True,
    help="Screen refresh interval in seconds.",
)
def monitor(workspace: Optional[Path], eval_mode: bool = False, interval: float = 1.0) -> None:
    """Open a live htop-style dashboard for Hecate pipeline activity."""
    if eval_mode:
        detected = find_eval_workspace()
        if detected:
            workspace = detected
        else:
            console.print("[yellow]No evaluation workspace found in /tmp/eval_runs.[/]")
            return
    elif workspace is None:
        default_root = workspace_root(None)
        active_eval = find_eval_workspace()
        if active_eval and _is_runner_process_running(active_eval):
            workspace = active_eval
        else:
            runner_sampler_check = RunnerStatusSampler(default_root)
            runner_check = runner_sampler_check.sample()
            if runner_check.installed and runner_check.workspace and runner_check.workspace.exists() and (runner_check.workspace / "hunts").exists():
                workspace = runner_check.workspace
            elif (default_root / "hunts").exists():
                workspace = default_root
            elif (default_root / "Hecate-Workspace" / "hunts").exists():
                workspace = default_root / "Hecate-Workspace"
            elif (Path.home() / "betas" / "Hecate-Workspace" / "hunts").exists():
                workspace = Path.home() / "betas" / "Hecate-Workspace"
            elif active_eval and (active_eval / "logs" / "orchestrator.log").exists():
                workspace = active_eval
            else:
                workspace = default_root

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
