"""The integrations panel's footer: metrics for the integration in use."""

from rich.console import Console
from rich.layout import Layout

from hecate_agent.commands.monitor_integrations import _active_integration_lines, _integrations_panel
from hecate_agent.commands.monitor_samplers import TrailEvent

_EVENTS = [
    TrailEvent("2026-11-09 02:50:09", "c1", 976.2, "research", "starting: topic; web search on"),
    TrailEvent("2026-11-09 02:54:01", "c1", 1208.0, "sigma", "drafting rules from techniques T1190"),
    TrailEvent("2026-11-09 02:56:30", "c1", 1357.0, "sigma", "pass 1: 8 exact value(s) may match"),
]
_LIVE = {
    "llm_calls": 4,
    "in_flight": 1,
    "failed": 0,
    "input_tokens": 12_400,
    "output_tokens": 900,
    "duration_ms": 20_000,
    "cost_usd": 0.42,
    "models": ["claude-opus-5-5"],
}
_SERVICES = [("LLM", True, "anthropic", "4 calls")]


def _text(lines) -> str:
    return "\n".join(line.plain for line in lines)


def test_the_active_llm_shows_its_stage_and_call_metrics() -> None:
    text = _text(_active_integration_lines("LLM", _SERVICES, _EVENTS[-1], _EVENTS, _LIVE))
    assert "NOW  LLM · anthropic · 4 calls" in text
    assert "stage sigma · 149s in stage · 2 step(s)" in text
    assert "1 in flight · 4 done · 12.4k in / 900 out tok · avg 5.0s/call · $0.42 · claude-opus-5-5" in text
    assert "pass 1: 8 exact value(s) may match" in text


def test_with_nothing_active_it_shows_the_last_integration_used() -> None:
    text = _text(_active_integration_lines(None, _SERVICES, None, _EVENTS, None))
    assert text.startswith("LAST  LLM")
    assert "at 02:56:30" in text


def test_with_no_activity_it_says_so() -> None:
    assert _text(_active_integration_lines(None, [], None, [], None)) == "No integration in use this cycle"


def test_the_footer_fills_spare_rows_and_is_cropped_first() -> None:
    def render(height: int) -> str:
        console = Console(width=110, height=height, record=True, color_system=None)
        console.print(Layout(_integrations_panel(events=_EVENTS, live=_LIVE, current=_EVENTS[-1], grid=True)))
        return console.export_text()

    roomy, tight = render(20), render(14)
    assert "NOW  LLM" in roomy and "in flight" in roomy
    assert "NOW  LLM" not in tight
    assert "VulnCheck" in tight


def _write_calls(workspace, calls) -> None:
    import json

    logs = workspace / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "api_calls.jsonl").write_text("".join(json.dumps(c) + "\n" for c in calls))


def test_request_hosts_map_to_panel_labels() -> None:
    from hecate_agent.commands.monitor_integrations import _api_label

    env = {"MISP_URL": "https://localhost:8443", "OLLAMA_HOST": "http://127.0.0.1:11500"}
    assert _api_label("www.virustotal.com", env) == "VT"
    assert _api_label("localhost:8443", env) == "MISP"
    assert _api_label("127.0.0.1:11500", env) == "LLM"
    assert _api_label("rdap.verisign.com", env) == "RDAP"
    assert _api_label("raw.githubusercontent.com", env) is None


def test_traffic_counts_this_cycles_requests_per_integration(tmp_path) -> None:
    from hecate_agent.commands.monitor_integrations import _api_traffic

    _write_calls(
        tmp_path,
        [
            {"ts": 50.0, "method": "GET", "host": "www.virustotal.com", "status": 200},
            {"ts": 100.0, "method": "GET", "host": "www.virustotal.com", "status": 200},
            {"ts": 101.0, "method": "GET", "host": "www.virustotal.com", "status": 429},
            {"ts": 102.0, "method": "GET", "host": "www.virustotal.com", "status": 404},
            {"ts": 103.0, "method": "GET", "host": "api.shodan.io", "status": 200},
            "not json",
        ],
    )
    traffic = _api_traffic(tmp_path, since=90.0, env_values={})
    assert traffic["VT"] == {"requests": 3, "ok": 1, "errors": 1, "limited": 1, "last_ts": 102.0}
    assert traffic["Shodan"]["requests"] == 1


def test_footer_shows_requests_and_lookup_outcomes_for_the_active_service() -> None:
    events = [
        TrailEvent("2026-11-09 03:00:00", "c2", 10.0, "enrichment", "4 observable(s) (2 ip, 2 hash) sent to OSINT lookup"),
        TrailEvent("2026-11-09 03:00:30", "c2", 40.0, "enrichment", "VirusTotal: 4 checked · 2 found (1 flagged) · 2 not found"),
    ]
    traffic = {"VT": {"requests": 6, "ok": 5, "errors": 0, "limited": 1, "last_ts": 997.0}}
    text = _text(
        _active_integration_lines(None, [("VT", True, "hash/ip", "4 obs")], None, events, None, traffic, now=1000.0)
    )
    assert "NOW  VT · hash/ip · 4 obs" in text
    assert "6 req · 5 ok · 1 rate-limited · last 3s ago" in text
    assert "lookups: 4 checked · 2 found (1 flagged) · 2 not found" in text


def test_an_old_request_does_not_mark_its_integration_active() -> None:
    traffic = {"VT": {"requests": 1, "ok": 1, "errors": 0, "limited": 0, "last_ts": 900.0}}
    text = _text(_active_integration_lines(None, [], None, [], None, traffic, now=1000.0))
    assert "No integration in use" in text


def test_hosts_and_trail_names_come_from_one_registry() -> None:
    from hecate_agent.integration_registry import BY_ID, enrichment_label, label_for_host

    assert label_for_host("www.virustotal.com", {}) == "VT"
    assert label_for_host("localhost:8443", {"MISP_URL": "https://localhost:8443"}) == "MISP"
    assert label_for_host("rdap.verisign.com", {}) == "RDAP"
    assert label_for_host("raw.githubusercontent.com", {}) is None
    assert enrichment_label("VirusTotal") == "VT"
    assert enrichment_label("Passive DNS") == "PDNS"
    assert BY_ID["cisa_narrative"].cti_name == "cisa_advisories"
    assert BY_ID["misp_output"].panel == "none"


def test_enrichment_counts_travel_on_the_event_instead_of_its_wording() -> None:
    events = [
        TrailEvent(
            "2026-11-09 03:00:30",
            "c2",
            40.0,
            "enrichment",
            "wording the panel does not have to parse",
            data={"kind": "enrichment", "service": "VirusTotal", "summary": "4 checked · 2 found (1 flagged)"},
        )
    ]
    text = _text(_active_integration_lines("VT", [("VT", True, "hash/ip", "4 obs")], events[-1], events, None))
    assert "lookups: 4 checked · 2 found (1 flagged)" in text


def test_the_monitor_reads_stage_events_and_keeps_log_cycles_that_have_none(tmp_path) -> None:
    import json

    from hecate_agent.commands.monitor_samplers import _read_events

    log = tmp_path / "orchestrator.log"
    log.write_text(
        "2026-11-09 03:00:00,000 [INFO] hecate_runner.trail: [abc111 +   1.0s] sigma     from the log\n"
        "2026-11-09 03:05:00,000 [INFO] hecate_runner.trail: [def222 +   1.0s] sigma     log copy\n"
    )
    (tmp_path / "events.jsonl").write_text(
        json.dumps(
            {
                "ts": 1_762_700_000.0,
                "type": "stage",
                "cycle_id": "def222",
                "elapsed": 2.0,
                "stage": "sigma",
                "message": "from the channel",
                "data": {},
            }
        )
        + "\n"
    )
    messages = [(event.cycle_id, event.message) for event in _read_events(log)]
    assert ("abc111", "from the log") in messages
    assert ("def222", "from the channel") in messages
    assert ("def222", "log copy") not in messages
