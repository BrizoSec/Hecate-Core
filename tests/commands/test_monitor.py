"""The pipeline monitor: what it reports about a cycle, from the Runner's trail lines."""

import json
from datetime import datetime, timedelta, timezone
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
    assert "Latency" in text and "no replies yet" in text
    assert "n/a" not in text and "e2675e" not in text


def test_a_finished_cycle_shows_its_recorded_totals_not_the_call_log() -> None:
    events = _events("route: narrative", "done: draft_created")
    live = {
        "llm_calls": 9,
        "in_flight": 0,
        "failed": 0,
        "input_tokens": 1,
        "output_tokens": 1,
        "cost_usd": 0.0,
        "models": [],
        "last_start": 0.0,
        "last_end": 0.0,
    }
    metrics = {
        "cycle_id": "54ac42",
        "outcome": "draft_created",
        "stages": [{"stage": "research", "llm_calls": 4, "input_tokens": 5000, "output_tokens": 600, "models": ["m"]}],
    }
    m.console = Console(width=140, height=30, record=True, force_terminal=False)
    m.console.print(m._usage_panel(metrics, events[-1], False, events, live=live))
    text = m.console.export_text()
    assert "4 calls" in text and "5,000" in text


# --- The action stream -------------------------------------------------------------------------


def _long_cycle(rejections: int = 12) -> List[m.TrailEvent]:
    """A finished cycle whose rule lines are long enough to wrap, as real rejections are."""
    steps = [f"sigma: rejected rule {n}: " + "the source gives no such value " * 8 for n in range(rejections)]
    return _events("route: narrative", *steps, "sigma: done in 395s: 3 rule(s) kept", "done: draft_created -> H-0001 in 844s")


@pytest.mark.parametrize("height", [40, 44, 52, 60])
def test_the_newest_line_is_always_in_the_action_stream(height: int) -> None:
    """Long lines used to push the cycle's last lines out of the bottom of the panel."""
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))
    text = _render(_long_cycle(), runner, height=height)
    assert "draft_created -> H-0001 in 844s" in text.split("ACTION STREAM", 1)[1]
    assert "RUNNER SERVICE" in text


def test_a_tall_screen_gives_the_stream_the_whole_right_column() -> None:
    """With room for them, the service and usage panels stack under the stage list, left of the stream."""
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))
    tall, short = _render(_long_cycle(40), runner, height=60), _render(_long_cycle(40), runner, height=30)
    assert tall.count("rejected rule") > short.count("rejected rule")
    for title in ("RUNNER SERVICE", "LLM STATS", "INTEGRATIONS"):
        line = next(line for line in tall.splitlines() if title in line)
        assert line.index(title) < 140 // 3
    # Too short for that, the usage panel keeps its row under the stream.
    usage = next(line for line in short.splitlines() if "INTEGRATIONS" in line)
    assert usage.index("INTEGRATIONS") > 140 // 3


def test_the_side_usage_panel_shows_every_stage() -> None:
    stages = [
        {"stage": name, "llm_calls": calls, "input_tokens": 1000, "output_tokens": 100, "models": ["local/model"]}
        for name, calls in (("source_evidence", 4), ("research", 4), ("hypothesis_generation", 1), ("sigma_generation", 16))
    ]
    events = _events("route: narrative", "done: draft_created")
    m.console = Console(width=54, record=True, force_terminal=False)
    m.console.print(
        m._usage_panel(
            {"cycle_id": "54ac42", "outcome": "draft_created", "stages": stages}, events[-1], False, events, narrow=True
        )
    )
    text = m.console.export_text()
    assert len(text.splitlines()) == m._NARROW_USAGE_PANEL_HEIGHT
    for part in ("25 calls", "source 4", "research 4", "hypothesis 1", "sigma 16"):
        assert part in text


def test_events_are_chosen_to_fit_the_rows_they_are_given() -> None:
    events = _long_cycle()
    chosen = m._recent_events(events, rows=6, width=60)
    assert chosen[-1][0] is events[-1]
    assert sum(len(message.splitlines()) for _, message in chosen) <= 6
    assert all(len(line) <= 60 for _, message in chosen for line in message.splitlines())


def test_the_usage_panel_is_four_rows_whatever_it_shows() -> None:
    """It sits under the stream, and every row it takes is one the stream loses."""
    stages = [
        {"stage": name, "llm_calls": 4, "input_tokens": 13469, "output_tokens": 2749, "models": ["local/a-long-model-name"]}
        for name in ("source_evidence", "research", "hypothesis_generation", "sigma_generation")
    ]
    metrics = {"cycle_id": "54ac42", "outcome": "draft_created", "stages": [*stages, {"stage": "cycle", "llm_calls": None}]}
    events = _events("route: narrative", "done: draft_created")
    for width in (100, 170):
        m.console = Console(width=width, record=True, force_terminal=False)
        m.console.print(m._usage_panel(metrics, events[-1], False, events))
        lines = m.console.export_text().splitlines()
        assert len(lines) == m._USAGE_PANEL_HEIGHT
        assert "16 calls" in lines[1] and "Latency" in lines[4]
        assert "source 4 (13,469/2,749)" in lines[3] and "cycle" not in lines[3]


def test_integrations_panel_shows_metrics_to_the_right_in_narrow_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    monkeypatch.setenv("OTX_API_KEY", "otx-test")
    monkeypatch.setenv("MISP_API_KEY", "misp-test")
    monkeypatch.setenv("VT_API_KEY", "vt-test")
    monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test")
    monkeypatch.setenv("CENSYS_API_TOKEN", "censys-test")
    monkeypatch.setenv("ABUSECH_API_KEY", "abusech-test")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("HECATE_RUNNER_SLACK_WEBHOOK_URL", raising=False)

    events = _events(
        'intake: otx: "Pulse report" (indicators: IPv4 1, FileHash-SHA256 7)',
        "route: narrative",
        "enrichment: 3 observable(s) (1 ip, 0 hash, 2 domain) checked via VT, GreyNoise, Shodan, Censys, ThreatFox",
        "research: R-0001 done in 30s; grounding: independent research, 2 web search(es);",
        "sigma: done in 100s: 3 rule(s) kept",
        "provenance: 14 indicator(s) across 3 rule(s)",
        "done: draft_created -> H-0001 in 200s",
    )
    metrics = {"stages": [{"stage": "source", "llm_calls": 2}, {"stage": "research", "llm_calls": 3}]}
    c = Console(width=46, record=True, force_terminal=False)
    panel = m._integrations_panel(
        workspace=tmp_path,
        narrow=True,
        events=events,
        metrics=metrics,
        current=events[-1],
    )
    c.print(panel)
    text = c.export_text()

    assert "LLM" in text and "5 calls" in text
    assert "Tavily" in text and "2 searches" in text
    assert "OTX" in text and "1 pulse" in text
    assert "MISP" in text and "0 events" in text
    assert "VT" in text and "14 checked" in text
    assert "GreyNoise" in text and "1 queries" in text
    assert "Shodan" in text and "1 queries" in text
    assert "Censys" in text and "1 queries" in text
    assert "ThreatFox" in text and "3 queries" in text
    assert "AbuseIPDB" in text and "--" in text
    assert "MalBazaar" in text and "0 queries" in text
    assert "Feodo C2" in text and "1 queries" in text
    assert "SSLBL" in text and "0 queries" in text
    assert "URLhaus" in text and "0 queries" in text
    assert "Hybrid" in text and "--" in text
    assert "RDAP" in text and "2 queries" in text
    assert "EPSS" in text and "0 CVEs" in text
    assert "OSV.dev" in text and "0 CVEs" in text
    assert "Slack" in text and "--" in text


def test_integrations_panel_shows_metrics_in_wide_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    monkeypatch.setenv("OTX_API_KEY", "otx-test")
    monkeypatch.setenv("MISP_API_KEY", "misp-test")
    monkeypatch.setenv("VT_API_KEY", "vt-test")
    monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test")
    monkeypatch.setenv("CENSYS_API_TOKEN", "censys-test")
    monkeypatch.setenv("ABUSECH_API_KEY", "abusech-test")
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/xxx")

    events = _events(
        'intake: misp: "Threat Event" (indicators: none)',
        "done: draft_created -> H-0002 in 120s",
    )
    live = {"llm_calls": 8, "in_flight": 0}
    for width in (70, 120):
        c = Console(width=width, record=True, force_terminal=False)
        panel = m._integrations_panel(
            workspace=tmp_path,
            narrow=False,
            events=events,
            live=live,
            current=events[-1],
        )
        c.print(panel)
        text = c.export_text()

        assert "8 calls" in text
        assert "1 event" in text
        assert "1 sent" in text
        assert "GreyNoise" in text and "0 queries" in text
        assert "Shodan" in text and "0 queries" in text
        assert "ThreatFox" in text and "0 queries" in text
        assert "MalBazaar" in text and "0 queries" in text
        assert "Feodo C2" in text and "0 queries" in text
        assert "SSLBL" in text and "0 queries" in text
        assert "URLhaus" in text and "0 queries" in text
        assert "Hybrid" in text and "0 queries" in text
        assert "RDAP" in text and "0 queries" in text
        assert "EPSS" in text and "0 CVEs" in text
        assert "OSV.dev" in text and "0 CVEs" in text
        assert "ready" not in text


def test_integrations_panel_preserves_enrichment_metrics_across_idle_cycles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    monkeypatch.setenv("OTX_API_KEY", "otx-test")
    monkeypatch.setenv("MISP_API_KEY", "misp-test")
    monkeypatch.setenv("VT_API_KEY", "vt-test")
    monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test")
    monkeypatch.setenv("CENSYS_API_TOKEN", "censys-test")
    monkeypatch.setenv("ABUSECH_API_KEY", "abusech-test")
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/xxx")

    # Cycle 1: active enrichment and draft creation
    active_events = _events(
        'intake: otx: "Active threat campaign" (indicators: IPv4 2, FileHash-SHA256 1)',
        "enrichment: 6 observable(s) (2 ip, 1 hash, 1 domain, 1 url, 1 cve) checked via VT, GreyNoise, AbuseIPDB, Shodan, Censys, Abuse.ch (ThreatFox, MalwareBazaar, Feodo, SSLBL, URLhaus), RDAP, EPSS, OTX",
        "research: grounding: independent research, 4 web search(es);",
        "sigma: done in 100s: 2 rule(s) kept",
        "provenance: 6 indicator(s) across 2 rule(s)",
        "done: draft_created -> H-0005 in 180s",
    )
    for ev in active_events:
        ev.cycle_id = "cycle-0001"

    # Cycle 2: idle queue poll
    idle_events = _events(
        "intake: queue empty",
        "done: no_actionable_cti (skipped 0) in 2s",
    )
    for ev in idle_events:
        ev.cycle_id = "cycle-0002"

    all_events = active_events + idle_events
    c = Console(width=46, record=True, force_terminal=False)
    panel = m._integrations_panel(
        workspace=tmp_path,
        narrow=True,
        events=all_events,
        current=idle_events[-1],
    )
    c.print(panel)
    text = c.export_text()

    # Active cycle metrics should be preserved rather than wiped to 0 queries / ready
    assert "VT" in text and "6 checked" in text
    assert "GreyNoise" in text and "2 queries" in text
    assert "Shodan" in text and "2 queries" in text
    assert "Censys" in text and "2 queries" in text
    assert "ThreatFox" in text and "6 queries" in text
    assert "MalBazaar" in text and "1 queries" in text
    assert "Feodo C2" in text and "2 queries" in text
    assert "SSLBL" in text and "1 queries" in text
    assert "URLhaus" in text and "1 queries" in text
    assert "Hybrid" in text and "1 queries" in text
    assert "RDAP" in text and "1 queries" in text
    assert "EPSS" in text and "1 CVEs" in text
    assert "OSV.dev" in text and "1 CVEs" in text
    assert "Tavily" in text and "4 searches" in text
    assert "Slack" in text and "1 sent" in text
    assert "ready" not in text


def test_format_cycle_outcome_handles_parking_and_duration() -> None:
    msg = (
        "parked_after_hypothesis (hypothesis model judged this NOT a threat report: "
        "The source is a vendor-published risk management guidance document) in 170s"
    )
    formatted = m._format_cycle_outcome(msg)
    assert formatted.startswith("parked_after_hypothesis in 170s · NOT a threat report")
    assert "vendor-published" in formatted

    draft_msg = "draft_created -> H-0800 in 617s"
    assert m._format_cycle_outcome(draft_msg) == draft_msg


def test_header_panel_does_not_abruptly_truncate_or_wrap() -> None:
    events = _events(
        "route: narrative",
        "done: parked_after_hypothesis (hypothesis model judged this NOT a threat report: The source is a vendor-published risk management guidance document) in 170s",
    )
    m.console = Console(width=160, height=48, record=True, force_terminal=False)
    m.console.print(m._render_dashboard(Path("/nonexistent/workspace"), events, {}, _host(), refreshed=datetime.now()))
    header_text = m.console.export_text().splitlines()[1]
    assert "vendor-published" in header_text
    assert "HECATE" in header_text and "MONITOR" in header_text


def test_latest_metrics_preserves_llm_stages_across_zero_call_cycles(tmp_path: Path) -> None:
    metrics_file = tmp_path / "stage_metrics.jsonl"
    cycle1 = {
        "cycle_id": "c1",
        "hunt_id": "H-0001",
        "stages": [
            {
                "stage": "research",
                "llm_calls": 3,
                "input_tokens": 1000,
                "output_tokens": 200,
                "duration_ms": 15000,
                "models": ["test-model"],
            }
        ],
    }
    # Cycle 2 is a quota check with no LLM calls
    cycle2 = {
        "cycle_id": "c2",
        "hunt_id": None,
        "stages": [{"stage": "cti_intake", "llm_calls": None}],
    }
    metrics_file.write_text(json.dumps(cycle1) + "\n" + json.dumps(cycle2) + "\n")
    latest = m._latest_metrics(metrics_file)
    assert latest["hunt_id"] == "H-0001"
    assert len(latest["stages"]) == 1
    assert latest["stages"][0]["llm_calls"] == 3


def test_collect_hunts_metrics_empty_workspace(tmp_path: Path) -> None:
    metrics = m._collect_hunts_metrics(tmp_path)
    assert metrics.total_hunts == 0
    assert metrics.threats_count == 0
    assert metrics.ttps_count == 0
    assert metrics.network_total == 0
    assert metrics.host_total == 0


def test_collect_hunts_metrics_with_hunts(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)

    hunt_text = """---
hunt_id: H-0001
title: "Test Hunt - Adversary Execution"
status: planning
date: 2026-10-18
techniques: ["T1059.001", "T1105", "T1218.011"]
---

### Threat Context
**Threat Actor:** APT28 (Fancy Bear)

### ABLE Scoping
| **Field** | **Your Input** |
|---|---|
| **Actor** | Fancy Bear |

### Grounding
| Claim | Type | Grounding |
|---|---|---|
| `X-Agent` | entity | asserted by CTI |

**Indicators by role**:
| Indicator | Type | Role | Status | Confidence | Rules |
|---|---|---|---|---|---|
| `198.51.100.1` | ip | c2 | active | high | network_connection |
| `evil-domain.com` | domain | c2 | active | high | dns_query |
| `https://evil-domain.com/payload.exe` | url | payload | active | high | network_connection |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | sha256 | payload | active | high | file_event |
| `C:\\Windows\\Temp\\malware.exe` | file_path | artifact | active | high | file_event |

### Indicators of Compromise (IoCs)
#### File Hashes (SHA-256)
- `2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae`

#### Network Observables & Infrastructure
- `203.0.113.5`
- `bad-c2.xyz`

#### File Paths & Artifacts
- `C:\\ProgramData\\updater.dll`
"""
    (hunts_dir / "H-0001.md").write_text(hunt_text, encoding="utf-8")
    # Also create an excluded doc file to verify it is ignored
    (tmp_path / "hunts" / "README.md").write_text("# Documentation", encoding="utf-8")

    metrics = m._collect_hunts_metrics(tmp_path)
    assert metrics.total_hunts == 1
    assert metrics.drafts_count == 1
    assert metrics.ttps_count == 3
    # Threats: APT28 (Fancy Bear), Fancy Bear, X-Agent
    assert metrics.threats_count >= 2
    # Network: 198.51.100.1, evil-domain.com, url, 203.0.113.5, bad-c2.xyz
    assert metrics.network_total >= 4
    assert metrics.network_ips >= 2
    assert metrics.network_domains >= 2
    # Host: hashes (2) + paths (2)
    assert metrics.host_total >= 3
    assert metrics.host_hashes >= 2
    assert metrics.host_paths >= 1

    # Verify cache returns the same instance on quick successive calls
    cached_metrics = m._collect_hunts_metrics(tmp_path)
    assert cached_metrics is metrics


def test_hunts_summary_panel_narrow_rendering(tmp_path: Path) -> None:
    mock_metrics = m.HuntsMetrics(
        total_hunts=197,
        drafts_count=197,
        threats_count=295,
        ttps_count=200,
        sigma_rules_count=1200,
        network_total=1053,
        network_ips=271,
        network_domains=532,
        host_total=1085,
        host_hashes=477,
        host_paths=608,
        actors_count=50,
        campaigns_count=10,
        malware_count=235,
    )
    c = Console(width=48, record=True, force_terminal=False)
    panel = m._hunts_summary_panel(workspace=tmp_path, narrow=True, metrics=mock_metrics)
    c.print(panel)
    text = c.export_text()

    assert "HUNT SUMMARY" in text
    assert "HUNTS" in text and "197 total" in text and "197 drafts" in text
    assert "THREATS" in text and "295" in text
    assert "50 act, 10 camp, 235 mal" in text
    assert "SIGMA" in text and "1,200 rules" in text
    assert "NETWORK" in text and "1,053 IOCs" in text and "271 IPs" in text
    assert "HOST" in text and "1,085 IOCs" in text and "477 hash" in text

    # Verify height is exactly 7 lines (5 data rows + 2 borders)
    assert len(text.splitlines()) == m._HUNTS_PANEL_HEIGHT


def test_hunts_summary_panel_wide_and_compact_rendering(tmp_path: Path) -> None:
    mock_metrics = m.HuntsMetrics(
        total_hunts=197,
        drafts_count=197,
        threats_count=295,
        actors_count=50,
        campaigns_count=10,
        malware_count=235,
        ttps_count=200,
        sigma_rules_count=1200,
        network_total=1053,
        network_ips=271,
        network_domains=532,
        host_total=1085,
        host_hashes=477,
        host_paths=608,
    )
    # Wide mode
    c = Console(width=80, record=True, force_terminal=False)
    panel = m._hunts_summary_panel(workspace=tmp_path, narrow=False, metrics=mock_metrics)
    c.print(panel)
    text_wide = c.export_text()
    assert "HUNT SUMMARY" in text_wide
    assert "197 total" in text_wide
    assert "295 tracked" in text_wide
    assert "50 actors, 10 campaigns, 235 malware" in text_wide
    assert "1,200 rules" in text_wide
    assert "1,053 IOCs" in text_wide
    assert "2,138 observables" in text_wide

    # Compact mode
    c_compact = Console(width=50, record=True, force_terminal=False)
    panel_compact = m._hunts_summary_panel(workspace=tmp_path, compact=True, metrics=mock_metrics)
    c_compact.print(panel_compact)
    text_compact = c_compact.export_text()
    assert len(text_compact.splitlines()) == m._USAGE_PANEL_HEIGHT
    assert "50 act, 10 camp, 235 mal" in text_compact


def test_mitre_metrics_panel_rendering(tmp_path: Path) -> None:
    mock_metrics = m.HuntsMetrics(
        ttps_count=225,
        enterprise_ttps={
            "reconnaissance": 6,
            "resource-development": 11,
            "initial-access": 13,
            "execution": 33,
            "persistence": 39,
            "privilege-escalation": 35,
            "stealth": 66,
            "defense-impairment": 18,
            "credential-access": 38,
            "discovery": 26,
            "lateral-movement": 16,
            "collection": 18,
            "command-and-control": 26,
            "exfiltration": 8,
            "impact": 11,
        },
        mobile_ttps={"command-and-control": 1},
        ics_ttps={},
        enterprise_total=346,
        mobile_total=1,
        ics_total=0,
    )
    # Wide mode: 10 data rows + 2 borders = 12 lines
    c_wide = Console(width=80, record=True, force_terminal=False)
    panel_wide = m._mitre_metrics_panel(workspace=tmp_path, narrow=False, metrics=mock_metrics)
    c_wide.print(panel_wide)
    text_wide = c_wide.export_text()

    assert "MITRE METRICS" in text_wide
    assert "ENTERPRISE" in text_wide and "346 TTPs" in text_wide
    assert "Recon 6" in text_wide and "ResDev 11" in text_wide
    assert "InitAcc 13" in text_wide and "Exec 33" in text_wide
    assert "Persist 39" in text_wide and "PrivEsc 35" in text_wide
    assert "Stealth 66" in text_wide and "DefImp 18" in text_wide
    assert "Disc 26" in text_wide and "CredAcc 38" in text_wide
    assert "LatMove 16" in text_wide and "Collect 18" in text_wide
    assert "C2 26" in text_wide and "Exfil 8" in text_wide and "Impact 11" in text_wide
    assert "MOBILE" in text_wide and "1 TTP" in text_wide
    assert "ICS" in text_wide and "0 TTPs" in text_wide
    assert len(text_wide.splitlines()) == m._BOTTOM_ROW_HEIGHT

    # Narrow mode: vertically broken out with 10 data rows + 2 borders = 12 lines
    c_narrow = Console(width=48, record=True, force_terminal=False)
    panel_narrow = m._mitre_metrics_panel(workspace=tmp_path, narrow=True, metrics=mock_metrics)
    c_narrow.print(panel_narrow)
    text_narrow = c_narrow.export_text()
    assert len(text_narrow.splitlines()) == m._MITRE_PANEL_HEIGHT
    assert "MOBILE" in text_narrow and "1 TTP" in text_narrow
    assert "ICS" in text_narrow and "0 TTPs" in text_narrow
    assert "Stealth 66 · DefImp 18" in text_narrow
    assert "Disc 26 · CredAcc 38" in text_narrow
    assert "LatMove 16 · Collect 18" in text_narrow

    # Compact mode: 6 data rows + 2 borders
    c_compact = Console(width=48, record=True, force_terminal=False)
    panel_compact = m._mitre_metrics_panel(workspace=tmp_path, compact=True, metrics=mock_metrics)
    c_compact.print(panel_compact)
    text_compact = c_compact.export_text()
    assert "MOB & ICS" in text_compact and "Mob: 1" in text_compact


def test_dashboard_includes_hunts_summary_in_both_layouts() -> None:
    events = _events("route: narrative", "done: draft_created")
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))

    # Tall screen (height=60): HUNT SUMMARY is stacked on the left above INTEGRATIONS
    tall = _render(events, runner, height=60)
    assert "HUNT SUMMARY" in tall
    assert "MITRE METRICS" in tall
    assert "PURPLE TEAM ENGINE" in tall
    tall_lines = tall.splitlines()
    tall_line = next(line for line in tall_lines if "HUNT SUMMARY" in line)
    assert tall_line.index("HUNT SUMMARY") < 140 // 3
    hunts_line_no = next(i for i, line_text in enumerate(tall_lines) if "HUNT SUMMARY" in line_text)
    integrations_line_no = next(i for i, line_text in enumerate(tall_lines) if "INTEGRATIONS" in line_text)
    assert hunts_line_no < integrations_line_no

    # Short screen (height=30): HUNT SUMMARY is in the bottom usage row
    short = _render(events, runner, height=30)
    assert "HUNT SUMMARY" in short
    assert "MITRE METRICS" in short
    assert "PURPLE TEAM ENGINE" in short
    short_line = next(line for line in short.splitlines() if "HUNT SUMMARY" in line)
    assert short_line.index("HUNT SUMMARY") >= 140 // 5


def test_find_eval_workspace_detects_candidate(tmp_path: Path) -> None:
    eval_dir = tmp_path / "eval_runs"
    eval_dir.mkdir()
    ws1 = eval_dir / "eval-case-1"
    (ws1 / "logs").mkdir(parents=True)
    (ws1 / "logs" / "orchestrator.log").write_text("log 1")

    ws2 = eval_dir / "eval-case-2"
    (ws2 / "logs").mkdir(parents=True)
    (ws2 / "logs" / "orchestrator.log").write_text("log 2")

    found = m.find_eval_workspace(eval_base=eval_dir, check_procs=False)
    assert found is not None
    assert found in (ws1, ws2)


def test_is_runner_process_running_detects_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    # Verify that replay.py is recognized as runner activity
    target_ws = Path("/tmp/eval_runs/test-case")
    assert not m._is_runner_process_running(target_ws)


def test_purple_team_panel_rendering() -> None:
    mock_metrics = m.PurpleTeamMetrics(
        validated_rules=12,
        tuned_rules=3,
        total_telemetry_events=450,
        precision_rate=1.0,
        false_positive_count=0,
        hunts_validated=2,
        last_status="ACTIVE",
        last_validated_count=4,
        last_tuned_count=1,
        last_duration_sec=2.5,
    )
    # Wide mode
    c_wide = Console(width=80, record=True, force_terminal=False)
    panel_wide = m._purple_team_panel(narrow=False, metrics=mock_metrics)
    c_wide.print(panel_wide)
    text_wide = c_wide.export_text()
    assert "PURPLE TEAM ENGINE" in text_wide
    assert "12 rules tested" in text_wide
    assert "3 logic re-tuned" in text_wide
    assert "100% precision" in text_wide
    assert "4 in 2.5s" in text_wide

    # Compact mode
    c_compact = Console(width=48, record=True, force_terminal=False)
    panel_compact = m._purple_team_panel(compact=True, metrics=mock_metrics)
    c_compact.print(panel_compact)
    text_compact = c_compact.export_text()
    assert "PURPLE TEAM ENGINE" in text_compact
    assert "12 rules" in text_compact
    assert "3 tuned" in text_compact


def test_collect_purple_team_metrics_from_trail_events() -> None:
    events = [
        m.TrailEvent(
            stage="purple_team",
            message="validated 8 rule(s) in 12.0s: 2 tuned, 0 FP",
            cycle_id="abcdef",
            timestamp="12:00:00",
            elapsed=12.0,
        )
    ]
    metrics = m._collect_purple_team_metrics(events=events)
    assert metrics.last_validated_count == 8
    assert metrics.last_tuned_count == 2
    assert metrics.last_duration_sec == 12.0
    assert metrics.false_positive_count == 0
    assert metrics.last_status == "COMPLETED"


def test_collect_hunts_metrics_grounding(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)

    hunt_text = """---
hunt_id: H-0002
title: "Test Grounding Hunt"
status: planning
techniques: ["T1003.001"]
---

### Grounding
*12 asserted by CTI · 0 research-only · 3 inferred · 1 unsupported*

| Claim | Type | Grounding |
|---|---|---|
| `LSASS` | entity | asserted by CTI |
"""
    (hunts_dir / "H-0002.md").write_text(hunt_text, encoding="utf-8")
    metrics = m._collect_hunts_metrics(tmp_path)
    assert metrics.grounding_asserted == 12
    assert metrics.grounding_corroborated == 0
    assert metrics.grounding_derived == 3
    assert metrics.grounding_unsupported == 1


def test_hunts_summary_panel_grounding_rendering(tmp_path: Path) -> None:
    mock_metrics = m.HuntsMetrics(
        total_hunts=10,
        drafts_count=10,
        grounding_asserted=25,
        grounding_derived=5,
        grounding_unsupported=2,
    )
    # Wide mode displays dedicated GROUNDING row
    c_wide = Console(width=80, record=True, force_terminal=False)
    panel_wide = m._hunts_summary_panel(workspace=tmp_path, narrow=False, metrics=mock_metrics)
    c_wide.print(panel_wide)
    text_wide = c_wide.export_text()
    assert "GROUNDING" in text_wide
    assert "25 asserted" in text_wide
    assert "5 derived" in text_wide
    assert "2 unsupp" in text_wide

    # Narrow mode tags HUNTS row
    c_narrow = Console(width=48, record=True, force_terminal=False)
    panel_narrow = m._hunts_summary_panel(workspace=tmp_path, narrow=True, metrics=mock_metrics)
    c_narrow.print(panel_narrow)
    text_narrow = c_narrow.export_text()
    assert "2 unsupp" in text_narrow


def test_latest_metrics_tracks_today_spend(tmp_path: Path) -> None:
    metrics_file = tmp_path / "stage_metrics.jsonl"
    today_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT12:00:00+00:00")
    yesterday_iso = "2020-01-01T12:00:00+00:00"

    cycle_today = {
        "cycle_id": "c_today",
        "started_at": today_iso,
        "stages": [{"stage": "research", "llm_calls": 2, "estimated_cost_usd": 0.35}],
    }
    cycle_old = {
        "cycle_id": "c_old",
        "started_at": yesterday_iso,
        "stages": [{"stage": "research", "llm_calls": 5, "estimated_cost_usd": 1.50}],
    }
    metrics_file.write_text(json.dumps(cycle_old) + "\n" + json.dumps(cycle_today) + "\n")
    latest = m._latest_metrics(metrics_file)
    agg = latest.get("aggregate", {})
    assert agg.get("cost_today_usd") == 0.35
    assert agg.get("calls_today") == 2
    assert agg.get("estimated_cost_usd") == 1.85


def test_runner_panel_shows_cost_provider_and_pending_queries() -> None:
    runner = m.RunnerStatus(
        installed=True,
        service_state="active",
        timer_active=True,
        drafts_today=2,
        drafts_limit=4,
        research_today=1,
        research_limit=7,
        total_drafts=15,
        parked_items=3,
        parked_reasons={"commentary": 2, "no_behavior": 1},
        pending_queries=2,
        cti_provider="multi (rss, otx)",
        cost_today=0.45,
    )
    events = [
        m.TrailEvent(
            stage="done",
            message="done: draft_created",
            cycle_id="abcdef",
            timestamp="12:00:00",
            elapsed=10.0,
        )
    ]
    c = Console(width=80, record=True, force_terminal=False)
    panel = m._runner_panel(runner, events)
    c.print(panel)
    text = c.export_text()
    assert "SERVICE" in text and "multi (rss, otx)" in text
    assert "$0.45 today" in text
    assert "2 pending" in text
    assert "3 parked (2 commentary, 1 no_behavior)" in text


def test_detection_rules_panel_rendering() -> None:
    mock_metrics = m.HuntsMetrics(
        total_hunts=832,
        sigma_rules_count=1382,
    )
    runner = m.RunnerStatus(
        query_provider="splunk",
        pending_queries=3,
    )
    c = Console(width=50, record=True, force_terminal=False)
    panel = m._detection_rules_panel(metrics=mock_metrics, runner=runner)
    c.print(panel)
    text = c.export_text()
    assert "DETECTION RULES" in text
    assert "1,382 rules" in text
    assert "832 hunts" in text
    assert "100% valid" in text
    assert "Splunk SPL" in text
    assert "SPLUNK backend" in text
    assert "3 pending" in text


def test_threat_observables_panel_rendering() -> None:
    mock_metrics = m.HuntsMetrics(
        network_total=1420,
        network_ips=680,
        network_domains=740,
        host_total=890,
        host_hashes=420,
        host_paths=470,
        threats_count=150,
        actors_count=42,
        malware_count=68,
        grounding_asserted=420,
        grounding_derived=310,
        grounding_unsupported=0,
    )
    c = Console(width=50, record=True, force_terminal=False)
    panel = m._threat_observables_panel(metrics=mock_metrics)
    c.print(panel)
    text = c.export_text()
    assert "THREAT OBSERVABLES" in text
    assert "1,420 IOCs" in text
    assert "680 IP, 740 dom" in text
    assert "890 IOCs" in text
    assert "420 hash, 470 path" in text
    assert "150 threats" in text
    assert "42 act, 68 mal" in text
    assert "420 asrt" in text
    assert "310 drv" in text
    assert "0 unsupp" in text


def test_dashboard_wide_screen_bottom_ribbon() -> None:
    events = _events("route: narrative", "done: draft_created")
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))

    # Width=200, Height=60: Very wide screen splits operations bottom into Purple Team, Detection Rules, Threat Observables
    m.console = Console(width=200, height=60, record=True, force_terminal=False)
    now = START + timedelta(minutes=10)
    m.console.print(m._render_dashboard(Path("/nonexistent/workspace"), events, {}, _host(), now, runner, ""))
    wide_text = m.console.export_text()
    assert "PURPLE TEAM ENGINE" in wide_text
    assert "DETECTION RULES" in wide_text
    assert "THREAT OBSERVABLES" in wide_text
