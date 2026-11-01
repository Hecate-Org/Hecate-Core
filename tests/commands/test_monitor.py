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
    assert "RUNNER" in text


def test_a_tall_screen_gives_the_stream_the_whole_right_column() -> None:
    """With room for them, the service and usage panels stack under the stage list, left of the stream."""
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))
    tall, short = _render(_long_cycle(40), runner, height=60), _render(_long_cycle(40), runner, height=30)
    assert tall.count("rejected rule") > short.count("rejected rule")
    for title in ("RUNNER", "LLM", "HUNTS"):
        line = next(line for line in tall.splitlines() if title in line)
        assert line.index(title) < 140 // 3
    integrations_line = next(line for line in tall.splitlines() if "INTEGRATIONS" in line)
    assert integrations_line.index("INTEGRATIONS") >= 140 // 3
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

    assert "HUNTS" in text
    assert "197 total" in text and "197 drafts" in text
    assert "THREATS" in text and "295" in text
    assert "50 act, 10 camp" in text
    assert "NETWORK" in text and "1,053 IOCs" in text and "271 IP" in text
    assert "ENDPOINT" in text and "1,085 IOCs" in text and "477 hash" in text

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
    assert "HUNTS" in text_wide
    assert "197 total" in text_wide
    assert "295 threats" in text_wide
    assert "50 act, 10 camp, 235 mal" in text_wide
    assert "1,053 IOCs" in text_wide
    assert "1,085 IOCs" in text_wide

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
        cloud_ttps={"initial-access": 2, "discovery": 1},
        containers_ttps={"execution": 1},
        mobile_ttps={"command-and-control": 1},
        ics_ttps={},
        enterprise_total=346,
        cloud_total=3,
        containers_total=1,
        mobile_total=1,
        ics_total=0,
    )
    # Wide mode: 10 data rows + 2 borders = 12 lines
    c_wide = Console(width=80, record=True, force_terminal=False)
    panel_wide = m._mitre_metrics_panel(workspace=tmp_path, narrow=False, metrics=mock_metrics)
    c_wide.print(panel_wide)
    text_wide = c_wide.export_text()

    assert "MITRE" in text_wide
    assert "ENTERPRISE" in text_wide and "(15 / 15 tactics) (346 Unique TTPs)" in text_wide
    assert "Recon 6" in text_wide and "ResDev 11" in text_wide
    assert "InitAcc 13" in text_wide and "Exec 33" in text_wide
    assert "Persist 39" in text_wide and "PrivEsc 35" in text_wide
    assert "Stealth 66" in text_wide and "DefImp 18" in text_wide
    assert "Disc 26" in text_wide and "CredAcc 38" in text_wide
    assert "LatMove 16" in text_wide and "Collect 18" in text_wide
    assert "C2 26" in text_wide and "Exfil 8" in text_wide and "Impact 11" in text_wide
    assert "CLOUD" in text_wide and "(2 / 12 tactics) (3 Unique TTPs)" in text_wide
    assert "CONTAINERS" in text_wide and "(1 / 10 tactics) (1 Unique TTPs)" in text_wide
    assert len(text_wide.splitlines()) == m._BOTTOM_ROW_HEIGHT

    # Narrow mode: vertically broken out with 10 data rows + 2 borders = 12 lines
    c_narrow = Console(width=48, record=True, force_terminal=False)
    panel_narrow = m._mitre_metrics_panel(workspace=tmp_path, narrow=True, metrics=mock_metrics)
    c_narrow.print(panel_narrow)
    text_narrow = c_narrow.export_text()
    assert len(text_narrow.splitlines()) == m._MITRE_PANEL_HEIGHT
    assert "CLOUD" in text_narrow and "(2 / 12 tactics)" in text_narrow
    assert "CONTAINERS" in text_narrow and "(1 / 10 tactics)" in text_narrow
    assert "Stealth 66 · DefImp 18" in text_narrow
    assert "Disc 26 · CredAcc 38" in text_narrow
    assert "LatMove 16 · Collect 18" in text_narrow

    # Compact mode: 6 data rows + 2 borders
    c_compact = Console(width=48, record=True, force_terminal=False)
    panel_compact = m._mitre_metrics_panel(workspace=tmp_path, compact=True, metrics=mock_metrics)
    c_compact.print(panel_compact)
    text_compact = c_compact.export_text()
    assert "CLOUD & K8S" in text_compact and "Cloud" in text_compact


def test_dashboard_includes_hunts_summary_in_both_layouts() -> None:
    events = _events("route: narrative", "done: draft_created")
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))

    # Tall screen (height=60): HUNTS is stacked on the left above INTEGRATIONS
    tall = _render(events, runner, height=60)
    assert "HUNTS" in tall
    assert "MITRE" in tall
    assert "DETECTIONS" in tall
    tall_lines = tall.splitlines()
    tall_line = next(line for line in tall_lines if "HUNTS" in line)
    assert tall_line.index("HUNTS") < 140 // 3
    hunts_line_no = next(i for i, line_text in enumerate(tall_lines) if "HUNTS" in line_text)
    integrations_line_no = next(i for i, line_text in enumerate(tall_lines) if "INTEGRATIONS" in line_text)
    assert hunts_line_no < integrations_line_no

    # Short screen (height=30): HUNTS is in the bottom usage row
    short = _render(events, runner, height=30)
    assert "HUNTS" in short
    assert "MITRE" in short
    assert "DETECTIONS" in short
    short_line = next(line for line in short.splitlines() if "HUNTS" in line)
    assert short_line.index("HUNTS") >= 140 // 6


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
    assert "VALIDATION" in text_wide
    assert "12 rules tested" in text_wide
    assert "3 logic re-tuned" in text_wide
    assert "100% precision" in text_wide
    assert "4 in 2.5s" in text_wide

    # Compact mode
    c_compact = Console(width=48, record=True, force_terminal=False)
    panel_compact = m._purple_team_panel(compact=True, metrics=mock_metrics)
    c_compact.print(panel_compact)
    text_compact = c_compact.export_text()
    assert "VALIDATION" in text_compact
    assert "12 rules" in text_compact
    assert "3 tuned" in text_compact


@pytest.mark.parametrize("own_rules", [0, 5])
def test_purple_team_metrics_do_not_import_other_evaluation_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, own_rules: int
) -> None:
    workspace = tmp_path / "public"
    (workspace / "hunts").mkdir(parents=True)
    foreign_evals = tmp_path / "other-evaluations"
    foreign_hunts = foreign_evals / "old-run/hunts"
    foreign_hunts.mkdir(parents=True)
    (foreign_hunts / "H-0001.md").write_text(
        "purple_team_validated: true\npurple_team_rules_evaluated: 37\n"
    )
    if own_rules:
        (workspace / "hunts/H-0001.md").write_text(
            f"purple_team_validated: true\npurple_team_rules_evaluated: {own_rules}\n"
        )
    monkeypatch.setattr(m, "Path", lambda path: foreign_evals if str(path) == "/tmp/eval_runs" else Path(path))
    metrics = m._collect_purple_team_metrics(workspace)
    assert metrics.validated_rules == own_rules
    assert metrics.hunts_validated == (1 if own_rules else 0)


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
    assert "FIDELITY" in text_wide
    assert "25 asrt" in text_wide
    assert "5 drv" in text_wide
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


def test_runner_panel_shows_daemon_mode() -> None:
    runner = m.RunnerStatus(
        installed=True,
        daemon_active=True,
        service_state="active",
        cti_provider="multi",
    )
    events: list[m.TrailEvent] = []
    c = Console(width=80, record=True, force_terminal=False)
    panel = m._runner_panel(runner, events)
    c.print(panel)
    text = c.export_text()
    assert "DAEMON ACTIVE" in text
    assert "continuous loop" in text or "event loop" in text
    assert "MODE" in text

    compact = m._runner_compact_summary(runner, events)
    assert "daemon (continuous)" in compact


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
    assert "DETECTIONS" in text
    assert "1,382 rules" in text
    assert "pySigma compliant" in text
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
    assert "HUNTS" in text
    assert "1,420 IOCs" in text
    assert "680 IP, 740 dom" in text
    assert "890 IOCs" in text
    assert "420 hash, 470 path" in text
    assert "150 threats" in text
    assert "42 act" in text
    assert "420 asrt" in text
    assert "310 drv" in text
    assert "0 unsupp" in text


def test_dashboard_wide_screen_bottom_ribbon() -> None:
    events = _events("route: narrative", "done: draft_created")
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))

    # Width=200, Height=60: Very wide screen splits operations bottom into Detections, Outbound, Integrations, Mitre
    m.console = Console(width=200, height=60, record=True, force_terminal=False)
    now = START + timedelta(minutes=10)
    m.console.print(m._render_dashboard(Path("/nonexistent/workspace"), events, {}, _host(), now, runner, ""))
    wide_text = m.console.export_text()
    assert "DETECTIONS" in wide_text
    assert "HUNTS" in wide_text
    assert "OUTBOUND" in wide_text


@pytest.mark.parametrize(("grid", "narrow"), [(True, True), (False, True), (False, False)])
def test_integrations_color_reachable_disabled_purple(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grid: bool, narrow: bool) -> None:
    from datetime import timedelta, timezone
    import json

    monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "multi")
    monkeypatch.setenv("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "lolbas,nuclei,cisa_advisories,cisa_ics,attack_deltas")
    monkeypatch.setenv("TAVILY_API_KEY", "configured-does-not-confirm")
    health = tmp_path / ".hecate" / "integrations"
    health.mkdir(parents=True)
    now = datetime.now(timezone.utc)
    for name, enabled, healthy, checked in [("lolbas", True, True, now), ("nuclei", True, False, now),
                                    ("gtfobins", False, True, now), ("loldrivers", False, False, now),
                                    ("attack_deltas", True, True, now - timedelta(hours=3)),
                                    ("cisa_ics", False, True, now - timedelta(hours=3))]:
        (health / f"{name}.json").write_text(json.dumps({"enabled": enabled, "healthy": healthy, "checked_at": checked.isoformat()}))
    panel = m._integrations_panel(tmp_path, grid=grid, narrow=narrow)
    console = Console(width=150, force_terminal=True, color_system="standard")
    segments = list(console.render(panel, console.options))
    def color_for(word: str) -> list[str]:
        return [str(segment.style) for segment in segments if word in segment.text]
    if grid:
        assert any("green" in style for style in color_for("LOLBAS"))
        assert any("magenta" in style for style in color_for("GTFOBins"))
        for label in ("Nuclei", "ATT&CK", "Tavily", "CISA ICS"):
            assert any("red" in style for style in color_for(label))
        assert any("grey62" in style for style in color_for("LOLDrivers"))
        assert any("grey62" in style for style in color_for("OpenCTI"))
    else:
        status_styles = [str(segment.style) for segment in segments if segment.text == "OFF"]
        assert any("magenta" in style for style in status_styles)
        assert any("red" in style for style in status_styles)
        assert any("grey62" in style for style in status_styles)
    text = "".join(segment.text for segment in segments)
    for label in ("LOLBAS", "LOLDrivers", "GTFOBins", "Nuclei", "CISA AA", "CISA CSAF", "CISA ICS", "ATT&CK"):
        assert label in text
    assert m._confirmed_integration(tmp_path, "lolbas", True)[0]
    assert m._confirmed_integration(tmp_path, "gtfobins", False) == (False, "reachable; disabled")
    assert m._confirmed_integration(tmp_path, "cisa_ics", False) == (False, "disabled")
    assert m._confirmed_integration(tmp_path, "loldrivers", False)[1] != "reachable; disabled"
    assert not m._confirmed_integration(tmp_path, "attack_deltas", True)[0]
    assert not m._confirmed_integration(tmp_path, "tavily", True)[0]


def test_all_integration_rows_fit_the_wide_grid() -> None:
    panel = m._integrations_panel(grid=True)
    console = Console(width=110)
    assert console.measure(panel).maximum <= 110
    lines = console.render_lines(panel, console.options)
    assert len(lines) <= m._BOTTOM_DETAIL_PANELS_HEIGHT


@pytest.mark.parametrize(("grid", "narrow"), [(True, True), (False, True), (False, False)])
@pytest.mark.parametrize("state", ["healthy", "failed", "stale"])
def test_misp_output_only_is_pink_only_with_recent_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grid: bool, narrow: bool, state: str) -> None:
    monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "multi")
    monkeypatch.setenv("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "rss")
    monkeypatch.setenv("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "true")
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    health = tmp_path / ".hecate/integrations"
    health.mkdir(parents=True)
    checked = datetime.now(timezone.utc) - (timedelta(hours=3) if state == "stale" else timedelta())
    (health / "misp_output.json").write_text(json.dumps({"enabled": True, "healthy": state != "failed", "checked_at": checked.isoformat()}))
    console = Console(width=150, force_terminal=True, color_system="standard")
    segments = list(console.render(m._integrations_panel(tmp_path, grid=grid, narrow=narrow), console.options))
    if grid:
        styles = [str(s.style) for s in segments if s.text.strip() == "MISP"]
    else:
        styles = [str(s.style) for s in segments if s.text == ("ON" if state == "healthy" else "OFF")]
    assert any(("#ff69b4" if state == "healthy" else "red") in style for style in styles)


@pytest.mark.parametrize("interactive", [False, True])
def test_slack_color_distinguishes_notifications_from_interactive_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interactive: bool) -> None:
    monkeypatch.setenv("SLACK_BOT_TOKEN", "configured-bot-token")
    monkeypatch.setenv("HECATE_RUNNER_SLACK_INTERACTIVE_ENABLED", str(interactive).lower())
    health = tmp_path / ".hecate/integrations"
    health.mkdir(parents=True)
    (health / "slack.json").write_text(json.dumps({"enabled": True, "healthy": True, "checked_at": datetime.now(timezone.utc).isoformat()}))
    console = Console(width=150, force_terminal=True, color_system="standard")
    segments = list(console.render(m._integrations_panel(tmp_path, grid=True), console.options))
    assert any(("green" if interactive else "#ff69b4") in str(s.style) for s in segments if s.text.strip() == "Slack")


def test_validation_reads_private_sensor_runs_and_deduplicates_hunt_results(tmp_path: Path) -> None:
    root = tmp_path / ".hecate/bas"
    (root / "runs").mkdir(parents=True)
    state = {"enabled": True, "auto_execute_live": True, "telemetry": "lab_process"}
    (root / "state.json").write_text(json.dumps(state))
    record = {
        "run_id": "run-1", "hunt_id": "H-0001", "provider": "caldera",
        "status": "verified_true_positive", "technique_id": "T1033",
        "telemetry_arrived": True, "rule_triggered": True, "sensor_events_count": 3,
        "matched_events_count": 1,
    }
    (root / "runs/one.json").write_text(json.dumps(record))
    hunts = tmp_path / "hunts"
    hunts.mkdir()
    (hunts / "H-0001.md").write_text(
        "---\nhunt_id: H-0001\nbas_status: verified_true_positive\n"
        "bas_provider: caldera\nbas_run_id: run-1\nbas_detection_triggered: true\n---\n"
    )
    metrics = m._collect_purple_team_metrics(tmp_path)
    assert metrics.bas_runs == 1 and metrics.bas_live_runs == 1
    assert metrics.bas_verified == 1 and metrics.bas_matched_events == 3
    assert metrics.bas_mode_label == "AUTO · approved Linux lab"
    assert metrics.bas_scope_label == "Local process sensor + Sigma"
    # A new runtime record invalidates the cache even when no hunt changed.
    (root / "runs/two.json").write_text(json.dumps({
        "run_id": "run-2", "status": "skipped", "reason": "No approved Linux procedure",
    }))
    metrics = m._collect_purple_team_metrics(tmp_path)
    assert metrics.bas_runs == 1 and metrics.bas_skipped == 1
    console = Console(width=100, record=True, force_terminal=False)
    console.print(m._purple_team_panel(metrics=metrics, narrow=False))
    text = console.export_text()
    assert "AUTO · approved Linux lab" in text and "Local process sensor + Sigma" in text
    assert "BAS SKIPPED" in text and "No approved Linux procedure" in text
    assert "1 rule matches" in text


def test_validation_combines_rule_replay_and_bas_outcomes(tmp_path: Path) -> None:
    hunts = tmp_path / "hunts/2026/Q4"
    hunts.mkdir(parents=True)
    records = [
        ("caldera", "verified_true_positive", "T1059", True, 5),
        ("stratus", "detection_miss", "T1530", False, 0),
        ("mock", "verified_true_positive", "T1059", True, 1),
        ("caldera", "telemetry_missing", "T1059", False, 0),
        ("caldera", "detonation_failed", "T1003", False, 0),
    ]
    for index, (provider, status, technique, triggered, hits) in enumerate(records, 1):
        text = (
            f"---\nhunt_id: H-{index:04}\nbas_provider: {provider}\nbas_status: {status}\n"
            f"bas_detection_triggered: {str(triggered).lower()}\n"
            "purple_team_validated: true\npurple_team_rules_evaluated: 2\n---\n"
            f"> - **Target Technique:** `{technique}`\n"
            f"> - **Detection Triggered:** {'Yes' if triggered else 'No'} ({hits} hit(s))\n"
            "> - **Duration:** 2.50s\n"
        )
        (hunts / f"H-{index:04}.md").write_text(text)
    metrics = m._collect_purple_team_metrics(tmp_path)
    assert metrics.validated_rules == 10 and metrics.hunts_validated == 5
    assert metrics.bas_runs == 5
    assert metrics.bas_live_runs == 4 and metrics.bas_mock_runs == 1
    assert metrics.bas_verified == 2 and metrics.bas_detection_misses == 1
    assert metrics.bas_telemetry_missing == 1 and metrics.bas_failures == 1
    assert metrics.bas_detections == 2 and metrics.bas_matched_events == 6
    assert metrics.bas_telemetry_runs == 3 and metrics.bas_techniques == 3
    console = Console(width=80, record=True, force_terminal=False)
    console.print(m._purple_team_panel(metrics=metrics, narrow=False))
    text = console.export_text()
    assert "VALIDATION" in text and "PURPLE TEAM ENGINE" not in text
    assert "5 runs · 4 live, 1 mock" in text
    assert "3 techniques · 2 detections" in text
    assert "2 verified · 1 missed" in text
    assert "1 sensor gaps · 1 failed" in text
    assert "3/5 observed · 6 events" in text


@pytest.mark.parametrize("width", [48, 60, 80])
def test_detailed_mitre_has_one_row_per_enterprise_tactic(width: int) -> None:
    metrics = m.HuntsMetrics(
        enterprise_ttps={"execution": 7, "credential-access": 3}, enterprise_total=10,
        total_hunts=2, sigma_rules_count=4, ttps_count=10,
        tactic_hunts={"enterprise": {"execution": 2}}, tactic_rules={"enterprise": {"execution": 4}},
    )
    console = Console(width=width, record=True, force_terminal=False)
    console.print(m._mitre_metrics_panel(metrics=metrics, detailed=True))
    text = console.export_text()
    assert len(text.splitlines()) == m._DETAILED_MITRE_PANEL_HEIGHT
    for label in ("Reconnaissance", "Resource Development", "Privilege Escalation", "Credential Access", "Command and Control"):
        assert label in text
    execution = next(line for line in text.splitlines() if "Execution" in line)
    assert execution.split()[2:6] == ["7", "0", "2", "4"]
    assert "TTPs" in text and "IOCs" in text and "Hunts" in text and "Rules" in text
    assert "MITRE METRICS" not in text
    if width >= 80:
        assert "10 Unique TTPs" in text
    else:
        assert "ENTERPRISE" in text
    assert "CLOUD" in text and "CONTAINERS" in text


def test_wide_dashboard_swaps_observables_and_expands_mitre(monkeypatch: pytest.MonkeyPatch) -> None:
    console = Console(width=220, height=65, record=True, force_terminal=False)
    monkeypatch.setattr(m, "console", console)
    runner = m.RunnerStatus(installed=True, service_state="inactive", workspace=Path("/nonexistent/workspace"))
    console.print(m._render_dashboard(Path("/nonexistent/workspace"), _events("done: draft_created"), {}, _host(), START, runner, ""))
    lines = console.export_text().splitlines()
    hunts = next(line for line in lines if "HUNTS" in line)
    mitre = next(line for line in lines if "MITRE" in line)
    assert hunts.index("HUNTS") < 52
    assert mitre.index("MITRE") > 120
    assert any("Resource Development" in line for line in lines)
    assert any("BREACH SIM" in line for line in lines)


@pytest.fixture
def mitre_test_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_agent.core import attack_matrix

    tactics = {"T1059.001": ["execution"], "T1059.003": ["execution"], "T1082": ["discovery"]}
    monkeypatch.setattr(
        attack_matrix, "get_technique",
        lambda technique: {"tactic_shortnames": tactics[technique]} if technique in tactics else None,
    )


def test_mitre_counts_hunts_and_sigma_rules_once_per_tactic(tmp_path: Path, mitre_test_metadata: None) -> None:
    hunts = tmp_path / "hunts/2026/Q4"
    hunts.mkdir(parents=True)
    for hunt_id, ids in (
        ("H-0001", "T1059.001, T1059.003, T1059.001"),
        ("H-0002", "T1059.001, T1082"),
    ):
        (hunts / f"{hunt_id}.md").write_text(f"---\nhunt_id: {hunt_id}\nstatus: planning\ntechniques: [{ids}]\n---\n")
    queries = tmp_path / "queries/H-0001"
    queries.mkdir(parents=True)
    for name, tags in (
        ("execution.yml", "attack.t1059.001, attack.t1059.003, attack.execution"),
        ("discovery.yaml", "attack.t1082"),
        ("tactic-only.yml", "attack.discovery, attack.discovery"),
        ("untagged.yml", ""),
    ):
        (queries / name).write_text(f"title: Example\ntags: [{tags}]\n")
    (queries / "execution.spl").write_text("tags: [attack.t1059.001]\n")
    metrics = m._collect_hunts_metrics(tmp_path)
    assert metrics.ttps_count == 3
    assert metrics.sigma_rules_count == 4
    assert metrics.tactic_hunts["enterprise"]["execution"] == 2
    assert metrics.tactic_hunts["enterprise"]["discovery"] == 1
    assert metrics.tactic_rules["enterprise"]["execution"] == 1
    assert metrics.tactic_rules["enterprise"]["discovery"] == 2
    assert metrics.matrix_hunts["enterprise"] == 2
    assert metrics.matrix_rules["enterprise"] == 3


def test_mitre_rule_counts_refresh_without_hunt_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mitre_test_metadata: None
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(m.time, "monotonic", lambda: clock[0])
    hunts = tmp_path / "hunts"
    hunts.mkdir()
    (hunts / "H-0001.md").write_text("---\nhunt_id: H-0001\ntechniques: [T1082]\n---\n")
    queries = tmp_path / "queries/H-0001"
    queries.mkdir(parents=True)
    (queries / "discovery.yml").write_text("title: Discovery\ntags: [attack.t1082]\n")
    first = m._collect_hunts_metrics(tmp_path)
    assert first.sigma_rules_count == 1
    (queries / "execution.yml").write_text("title: Execution\ntags: [attack.t1059.001]\n")
    clock[0] += 20
    second = m._collect_hunts_metrics(tmp_path)
    assert second is not first
    assert second.sigma_rules_count == 2
    assert second.tactic_rules["enterprise"]["execution"] == 1


def test_render_dashboard_tab2_hunts_and_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = Console(width=160, height=50, record=True, force_terminal=False)
    monkeypatch.setattr(m, "console", c)
    events = _events("source: reading report", "done: draft_created")
    layout = m._render_dashboard(tmp_path, events, {}, _host(), START, active_tab=2)
    c.print(layout)
    text = c.export_text()
    assert "ACTIVE & RECENT HUNTS" in text
    assert "DETECTIONS" in text
    assert "MITRE" in text
    assert "HUNTS" in text


def test_render_dashboard_tab3_feeds_and_outbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = Console(width=160, height=50, record=True, force_terminal=False)
    monkeypatch.setattr(m, "console", c)
    events = _events("source: reading report", "done: draft_created")
    layout = m._render_dashboard(tmp_path, events, {}, _host(), START, active_tab=3)
    c.print(layout)
    text = c.export_text()
    assert "INBOUND CTI FEEDS" in text
    assert "CTI INGESTION FUNNEL" in text
    assert "GITHUB PROMOTION OUTBOX" in text
    assert "MISP EXPORT OUTBOX" in text


def test_render_dashboard_tab4_bas_and_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = Console(width=160, height=50, record=True, force_terminal=False)
    monkeypatch.setattr(m, "console", c)
    events = _events("source: reading report", "done: draft_created")
    layout = m._render_dashboard(tmp_path, events, {}, _host(), START, active_tab=4)
    c.print(layout)
    text = c.export_text()
    assert "BAS CONTROLLER" in text
    assert "SENSOR & BREACH SIMULATION LOGS" in text
    assert "VALIDATION" in text


def test_activity_table_errors_only_filter() -> None:
    events = [
        m.TrailEvent("2026-10-31 01:00:00", "c1", 1.0, "source", "normal source extraction"),
        m.TrailEvent("2026-10-31 01:00:01", "c1", 2.0, "error", "connection refused by target host"),
        m.TrailEvent("2026-10-31 01:00:02", "c1", 3.0, "hypothesis", "parked: ungrounded hypothesis"),
        m.TrailEvent("2026-10-31 01:00:03", "c1", 4.0, "write", "normal draft writing"),
    ]
    c = Console(width=100, record=True, force_terminal=False)
    t_all = m._activity_table(events, rows=10, width=100, errors_only=False)
    c.print(t_all)
    text_all = c.export_text()
    assert "normal source extraction" in text_all
    assert "connection refused" in text_all
    assert "parked: ungrounded hypothesis" in text_all

    c_err = Console(width=100, record=True, force_terminal=False)
    t_err = m._activity_table(events, rows=10, width=100, errors_only=True)
    c_err.print(t_err)
    text_err = c_err.export_text()
    assert "normal source extraction" not in text_err
    assert "connection refused" in text_err
    assert "parked: ungrounded hypothesis" in text_err


def test_cooldown_countdown_calculation() -> None:
    now = datetime(2026, 10, 31, 2, 30, 0)
    event = m.TrailEvent(
        timestamp="2026-10-31 02:00:00",
        cycle_id="c1",
        elapsed=10.0,
        stage="done",
        message="cycle parked: spacing_cooldown for 2.00h / 3.00h before next hunt draft",
    )
    cooldown_str = m._get_cooldown_str([event], now)
    assert cooldown_str is not None
    assert "30m 00s" in cooldown_str
    assert "UTC" in cooldown_str


def test_runner_status_sampler_queries_outboxes(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    def missing_systemd(*args, **kwargs):
        raise FileNotFoundError("systemctl unavailable")

    monkeypatch.setattr("hecate_agent.commands.monitor_samplers.subprocess.run", missing_systemd)

    pub_dir = tmp_path / ".hecate" / "publisher"
    pub_dir.mkdir(parents=True)
    conn = sqlite3.connect(pub_dir / "promotion-outbox.sqlite3")
    conn.execute("CREATE TABLE promotions (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO promotions VALUES ('p1', 'published'), ('p2', 'published'), ('p3', 'pending')")
    conn.commit()
    conn.close()

    misp_dir = tmp_path / ".hecate" / "misp"
    misp_dir.mkdir(parents=True)
    conn = sqlite3.connect(misp_dir / "outbox.sqlite3")
    conn.execute("CREATE TABLE exports (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO exports VALUES ('e1', 'confirmed'), ('e2', 'confirmed'), ('e3', 'pending'), ('e4', 'confirmed')")
    conn.commit()
    conn.close()

    sampler = m.RunnerStatusSampler(tmp_path)
    status = sampler.sample()
    assert not status.installed
    assert status.github_confirmed_promotions == 2
    assert status.github_pending_prs == 1
    assert status.misp_confirmed_exports == 3
    assert status.misp_pending_exports == 1


def test_runner_status_sampler_tiered_caching(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    def missing_systemd(*args, **kwargs):
        raise FileNotFoundError("systemctl unavailable")

    monkeypatch.setattr("hecate_agent.commands.monitor_samplers.subprocess.run", missing_systemd)

    pub_dir = tmp_path / ".hecate" / "publisher"
    pub_dir.mkdir(parents=True)
    db_path = pub_dir / "promotion-outbox.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE promotions (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO promotions VALUES ('p1', 'published')")
    conn.commit()
    conn.close()

    sampler = m.RunnerStatusSampler(tmp_path)
    # First call samples heavy data
    status1 = sampler.sample()
    assert status1.github_confirmed_promotions == 1

    # Insert a new record into DB directly
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO promotions VALUES ('p2', 'published')")
    conn.commit()
    conn.close()

    # Immediate second call without force uses heavy cache (does not re-query SQLite)
    status2 = sampler.sample(force=False)
    assert status2.github_confirmed_promotions == 1

    # Calling with force=True refreshes heavy data
    status3 = sampler.sample(force=True)
    assert status3.github_confirmed_promotions == 2


def test_check_key_non_blocking_returns_none() -> None:
    key = m._check_key(timeout=0.0)
    assert key is None
