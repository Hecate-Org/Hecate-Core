"""Per-service lookup outcomes collected while enrichment runs."""

import pytest

from hecate_agent.orchestrator import enrichment
from hecate_agent.orchestrator.enrichment import classify_enrichment_result, generate_enrichment_summary


@pytest.mark.parametrize(
    "result,outcome",
    [
        ("Malicious hits: 5 | Threat Label: mirai | Known Filenames: a", "flagged"),
        ("Malicious hits: 0 | Threat Label: Unknown | Known Filenames: ", "found"),
        ("Not found or error.", "missing"),
        ("No results on ThreatFox.", "missing"),
        ("Not listed in VulnCheck KEV (CVE-2026-1).", "missing"),
        ("OTX error: HTTP 503", "errors"),
        ("URLScan.io rate limit exceeded.", "errors"),
        ("Error querying VT: timed out", "errors"),
        ("SPUR_API_KEY not configured.", "unconfigured"),
        ("Private/internal IP address.", "skipped"),
        ("Invalid hash format 'x'.", "skipped"),
        ("Observed (malicious) | Actor: unknown", "found"),
    ],
)
def test_provider_answers_are_bucketed(result: str, outcome: str) -> None:
    assert classify_enrichment_result(result) == outcome


def test_summary_fills_per_service_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in dir(enrichment):
        if name.startswith("query_"):
            monkeypatch.setattr(enrichment, name, lambda *_a, **_k: "No record.")
    monkeypatch.setattr(enrichment, "query_vt_ip", lambda ip: "Malicious hits: 3 | Threat Label: x")
    monkeypatch.setattr(enrichment, "query_shodan_ip", lambda ip: "Shodan API error: 503")
    monkeypatch.setattr(enrichment, "query_epss_batch", lambda cves: {})
    monkeypatch.setattr(enrichment, "expand_ttps", lambda text: "")

    stats: dict = {}
    generate_enrichment_summary("C2 at 45.9.148.10 and 45.9.148.11 exploiting CVE-2026-58115", stats)

    assert stats["VirusTotal"] == {
        "checked": 2, "found": 2, "flagged": 2, "missing": 0, "errors": 0, "unconfigured": 0, "skipped": 0,
    }
    assert stats["Shodan"]["errors"] == 2
    assert stats["GreyNoise"]["missing"] == 2
    assert stats["EPSS"]["checked"] == 1
    assert stats["VulnCheck"]["checked"] == 1


def test_citations_label_each_observable_from_lookup_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in dir(enrichment):
        if name.startswith("query_"):
            monkeypatch.setattr(enrichment, name, lambda *_a, **_k: "No record.")
    monkeypatch.setattr(
        enrichment,
        "query_vt_ip",
        lambda ip: report("Malicious hits: 3 | Threat Label: x", "flagged", verdict="malicious"),
    )
    monkeypatch.setattr(enrichment, "query_shodan_ip", lambda ip: "Shodan API error: 503")
    monkeypatch.setattr(enrichment, "query_spur_ip", lambda ip: "SPUR_API_KEY not configured.")
    monkeypatch.setattr(enrichment, "query_epss_batch", lambda cves: {})
    monkeypatch.setattr(enrichment, "expand_ttps", lambda text: "")
    from hecate_agent.enrichment.result import report

    citations: list = []
    summary = generate_enrichment_summary("C2 at 45.9.148.10 exploiting CVE-2026-10001", None, citations)

    from hecate_agent.enrichment.result import render_enrichment_citations

    text = render_enrichment_citations(citations)
    assert "**ip** `45.9.148.10` — **corroborated** by VirusTotal (malicious)" in text
    assert "Not configured: Spur." in text
    assert "**cve** `CVE-2026-10001` — **uncorroborated**" in text
    assert "No record:" in text
    assert text in summary


def test_an_error_with_no_record_is_inconclusive() -> None:
    from hecate_agent.enrichment.result import render_enrichment_citations

    text = render_enrichment_citations(
        [
            {"observable": "1.2.3.4", "kind": "ip", "service": "Shodan", "outcome": "errors", "verdict": ""},
            {"observable": "1.2.3.4", "kind": "ip", "service": "GreyNoise", "outcome": "missing", "verdict": ""},
        ]
    )
    assert "**inconclusive**" in text
    assert "uncorroborated" not in text


def test_summary_without_stats_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in dir(enrichment):
        if name.startswith("query_"):
            monkeypatch.setattr(enrichment, name, lambda *_a, **_k: "No record.")
    monkeypatch.setattr(enrichment, "query_epss_batch", lambda cves: {})
    monkeypatch.setattr(enrichment, "expand_ttps", lambda text: "")
    assert "IP 45.9.148.10" in generate_enrichment_summary("C2 at 45.9.148.10")


def test_the_same_sentence_keeps_the_outcome_it_was_given() -> None:
    from hecate_agent.enrichment.result import classify_enrichment_result, report

    missing = report("Not found or error.", "missing")
    unconfigured = report("Not found or error.", "unconfigured")
    assert missing == unconfigured == "Not found or error."
    assert missing.outcome == "missing"
    assert classify_enrichment_result(unconfigured) == "unconfigured"


def test_virus_total_records_a_verdict_rather_than_leaving_it_in_the_sentence(monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_agent.enrichment.providers.virustotal import query_vt_ip
    from hecate_agent.enrichment.result import EnrichmentResult

    class _Response:
        status_code = 200

        @staticmethod
        def json():
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 4}, "asn": 1, "as_owner": "Example"}}}

    monkeypatch.setattr("hecate_agent.enrichment.providers.virustotal.httpx.get", lambda *a, **k: _Response())
    monkeypatch.setattr("hecate_agent.enrichment.providers.virustotal._setting", lambda *a, **k: "key")
    result = query_vt_ip("1.2.3.4")
    assert isinstance(result, EnrichmentResult)
    assert result.outcome == "flagged"
    assert result.verdict == "malicious"
    assert result.facts["malicious"] == 4
    assert "Malicious hits: 4" in result
