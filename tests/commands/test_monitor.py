"""The pipeline monitor: what it reports about a cycle, from the Runner's trail lines."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import pytest
from rich.console import Console

from hecate_agent.commands import monitor as m

START = datetime(2026, 10, 4, 23, 39, 46)


def _events(*steps: str, cycle: str = "54ac42", at: datetime = START) -> List[m.TrailEvent]:
    """Trail events from "stage: message" strings, one second of log time apart."""
    events = []
    for index, step in enumerate(steps):
        stage, _, message = step.partition(": ")
        events.append(m.TrailEvent(f"{at + timedelta(seconds=index):%Y-%m-%d %H:%M:%S}", cycle, float(index), stage, message))
    return events


def _stage(events: List[m.TrailEvent]) -> str:
    return m._STAGES[m._stage_in_progress(events)][0]


def _host() -> m.HostSample:
    return m.HostSample(cpu_percent=50.0, memory_used=8 * 2**30, memory_total=62 * 2**30, disks=[])


def _render(events: List[m.TrailEvent], runner: Optional[m.RunnerStatus] = None, error: str = "", height: int = 30) -> str:
    m.console = Console(width=140, height=height, record=True, force_terminal=False)
    now = START + timedelta(minutes=10)
    m.console.print(m._render_dashboard(Path("/nonexistent/workspace"), events, {}, _host(), now, runner, error))
    return m.console.export_text()


# --- The stage in progress ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("steps", "working_on"),
    [
        # A stage logs when it finishes: after routing, the cycle is reading the report.
        (["start: cycle 54ac42", "intake: otx: item", "triage: pass", "quota: slot 1/5", "route: narrative"], "source"),
        (["route: narrative", "source: https://x (13497 chars) in 310s", "guidance: none"], "research"),
        # Source extraction says when it starts, and is in hand until its next line.
        (["route: narrative", "source: starting: reading https://x"], "source"),
        (["source: starting: reading https://x", "source: https://x (13497 chars) in 310s"], "research"),
        # Research, the hypothesis and rule generation log their own start and are in hand until "done".
        (["source: done reading", "research: starting: topic"], "research"),
        (["research: R-0001 done in 137s; grounding: independent"], "hypothesis"),
        (["research: R-0001 done in 137s", "hypothesis: asking the model (grounded by R-0001)"], "hypothesis"),
        (["hypothesis: done in 77s: Adversaries use"], "techniques"),
        (["write: H-0001 written", "sigma: 9 command(s) the source shows", "sigma: drafting rules"], "sigma"),
        (["sigma: rejected process_creation: condition", "sigma: done in 324s: 20 rule(s) kept"], "review"),
        (
            ["sigma: done in 324s", "review: 3 model rule(s) reviewed", "grounding: 11 asserted", "done: draft_created"],
            "review",
        ),
    ],
)
def test_the_stage_shown_is_the_one_in_hand_not_the_last_one_logged(steps: List[str], working_on: str) -> None:
    assert _stage(_events(*steps)) == working_on


def test_the_grounding_line_before_the_draft_does_not_jump_to_the_end() -> None:
    """Grounding is logged twice: once before the draft is written, once after the rules."""
    assert (
        _stage(_events("hypothesis: done in 77s", "scope: platforms Linux", "claims: audit", "grounding: 2 asserted"))
        == "write"
    )


def test_only_the_latest_cycle_counts() -> None:
    earlier = _events("sigma: done in 300s", "done: draft_created", cycle="aaaaaa")
    assert _stage([*earlier, *_events("route: narrative", cycle="bbbbbb")]) == "source"


# --- Elapsed time and running state ------------------------------------------------------------


def test_elapsed_time_is_the_wall_clock_while_a_cycle_runs() -> None:
    """Ten minutes into source extraction the log's own clock still read four seconds."""
    events = _events("start: cycle", "intake: item", "triage: pass", "quota: slot", "route: narrative")
    _, active, elapsed = m._pipeline_state(events, now=START + timedelta(minutes=10))
    assert active and elapsed == pytest.approx(600, abs=1)


def test_a_finished_cycle_keeps_the_time_it_logged() -> None:
    events = _events("route: narrative", "done: draft_created -> H-0001 in 704s")
    events[-1].elapsed = 704.3
    _, active, elapsed = m._pipeline_state(events, now=START + timedelta(hours=3))
    assert not active and elapsed == 704.3


def test_the_service_state_decides_whether_a_cycle_is_running() -> None:
    events = _events("route: narrative")
    just_now, much_later = START + timedelta(minutes=2), START + timedelta(minutes=50)
    # The service stopped: the cycle is not running, however fresh the log.
    assert m._pipeline_state(events, service_running=False, now=just_now)[1] is False
    # The service is in a long model call: still running, however quiet the log.
    assert m._pipeline_state(events, service_running=True, now=much_later)[1] is True
    # No service to ask (a replay's workspace): fall back to how recently the log changed.
    assert m._pipeline_state(events, now=just_now)[1] is True
    assert m._pipeline_state(events, now=much_later)[1] is False


def test_the_service_only_speaks_for_its_own_workspace(tmp_path: Path) -> None:
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=tmp_path)
    assert m._service_running(runner, tmp_path) is False
    assert m._service_running(runner, tmp_path / "replay") is None
    assert m._service_running(m.RunnerStatus(), tmp_path) is None


# --- Rendering ---------------------------------------------------------------------------------


@pytest.mark.parametrize("height", [30, 60])
def test_the_dashboard_renders_with_an_error_block_in_both_layouts(height: int) -> None:
    """The loop passed the recent error text to a render function that did not accept it."""
    events = _events("start: cycle", "route: narrative")
    text = _render(events, error="2026-10-04 23:40:00,000 [ERROR] x: boom", height=height)
    assert "HECATE" in text and "now: Source extraction" in text and "elapsed 10m" in text


def test_a_cycle_whose_service_has_stopped_is_reported_as_stopped() -> None:
    workspace = Path("/nonexistent/workspace")
    runner = m.RunnerStatus(installed=True, service_state="failed", workspace=workspace)
    text = _render(_events("route: narrative"), runner, error="[ERROR] boom")
    assert "STALLED" in text and "the Runner service is not running" in text and "stopped in Source extraction" in text


def test_it_renders_with_no_events_at_all() -> None:
    assert "waiting for a pipeline cycle" in _render([])


def test_source_extraction_reads_as_live_model_work_not_as_the_last_cycle() -> None:
    """The model reads the report for minutes before research starts; the last cycle's outcome is not news."""
    metrics = {"cycle_id": "e2675e", "outcome": "research_quota_reached", "stages": []}
    events = _events("route: narrative", "source: starting: reading https://x")
    m.console = Console(width=140, height=30, record=True, force_terminal=False)
    m.console.print(m._usage_panel(metrics, events[-1], True, events))
    text = m.console.export_text()
    assert "Live token totals are written when the cycle ends." in text
    assert "e2675e" not in text


def test_a_running_cycle_shows_its_own_calls_as_they_happen() -> None:
    """Minutes into a read, the panel says what has been sent and what has come back."""
    metrics = {"cycle_id": "e2675e", "outcome": "research_quota_reached", "stages": []}
    events = _events("route: narrative", "source: starting: reading https://x")
    now = START + timedelta(minutes=5)
    live = {
        "llm_calls": 2,
        "in_flight": 1,
        "failed": 0,
        "input_tokens": 12400,
        "output_tokens": 900,
        "cost_usd": 0.0,
        "models": ["ollama/qwen2.5"],
        "last_start": (now - timedelta(seconds=95)).timestamp(),
        "last_end": (now - timedelta(seconds=96)).timestamp(),
    }
    m.console = Console(width=140, height=30, record=True, force_terminal=False)
    m.console.print(m._usage_panel(metrics, events[-1], True, events, live=live, now=now))
    text = m.console.export_text()
    assert "2 done · 1 in flight" in text
    assert "12,400" in text and "900" in text
    assert "ollama/qwen2.5" in text
    assert "Live · cycle 54ac42 so far" in text
    assert "n/a" not in text and "e2675e" not in text


def test_a_finished_cycle_shows_its_recorded_totals_not_the_call_log() -> None:
    events = _events("route: narrative", "done: draft_created")
    live = {"llm_calls": 9, "in_flight": 0, "failed": 0, "input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0, "models": [], "last_start": 0.0, "last_end": 0.0}
    metrics = {"cycle_id": "54ac42", "outcome": "draft_created", "stages": [{"stage": "research", "llm_calls": 4, "input_tokens": 5000, "output_tokens": 600, "models": ["m"]}]}
    m.console = Console(width=140, height=30, record=True, force_terminal=False)
    m.console.print(m._usage_panel(metrics, events[-1], False, events, live=live))
    text = m.console.export_text()
    assert "Last cycle 54ac42 · draft_created" in text and "5,000" in text
