"""Tests for the report artifact extractor."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hecate_agent.orchestrator import artifact_extractor as ax

VOLEXITY = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2"
PAGE = (
    "CLEANGULP installs to %LOCALAPPDATA%\\Microsoft\\IME\\MicrosoftIME.exe and creates a "
    "scheduled task named MicrosoftIME. The fake site was hosted at 96.9.125[.]52 on "
    "chinadigitaltimes[.]top."
)


def _llm(payload: str) -> MagicMock:
    provider = MagicMock()
    provider.complete.return_value = SimpleNamespace(text=payload)
    return provider


def test_report_urls_skips_local_misp_links_and_trailing_punctuation():
    cti = f"Link: https://localhost:8443/events/view/1816\nReferences: {VOLEXITY}."
    assert ax.report_urls(cti) == [VOLEXITY]


def test_report_urls_rejects_adversary_c2_and_payload_downloads():
    cti = (
        "Malware connects to http://45.150.34.2:8080/gate.php to fetch payloads.\n"
        "Payload was hosted at http://sync-telemetry.top/payload.bin and staging at "
        "http://hub.zoom.com.kg:5173/bin/zoomMacArm.\n"
        f"Read full advisory at {VOLEXITY}."
    )
    # The adversary C2 endpoints and payload drops must be skipped; only the advisory link is kept.
    assert ax.report_urls(cti) == [VOLEXITY]


def test_only_artifacts_the_page_states_verbatim_are_kept():
    """The old mock put `update.windows-time.com` in the text; the report never names it."""
    kept, dropped = ax.verbatim_artifacts(
        [
            "%LOCALAPPDATA%\\Microsoft\\IME\\MicrosoftIME.exe",
            "MicrosoftIME",
            "96.9.125.52",
            "chinadigitaltimes.top",
            "update.windows-time.com",
        ],
        PAGE,
    )
    assert kept == [
        "%LOCALAPPDATA%\\Microsoft\\IME\\MicrosoftIME.exe",
        "MicrosoftIME",
        "96.9.125.52",
        "chinadigitaltimes.top",
    ]
    assert dropped == ["update.windows-time.com"]


def test_extraction_parses_the_models_json_and_drops_invented_artifacts(monkeypatch):
    monkeypatch.setattr(ax, "scrape_url_text", lambda url: PAGE)
    payload = (
        'Here is the result:\n{"observables": ["MicrosoftIME", "update.windows-time.com"], '
        '"summary": "A scheduled task keeps CLEANGULP running."}'
    )
    monkeypatch.setattr(ax, "create_router", lambda: _llm(payload))

    result = ax.extract_deep_artifacts(f"References: {VOLEXITY}")

    assert result["new_observables"] == ["MicrosoftIME"]
    assert "update.windows-time.com" not in result["new_intel"]
    assert "\n- MicrosoftIME\n" in result["new_intel"]
    assert "\\n" not in result["new_intel"]


def test_nothing_is_added_when_the_page_cannot_be_fetched(monkeypatch):
    monkeypatch.setattr(ax, "scrape_url_text", lambda url: "")
    provider = _llm("{}")
    monkeypatch.setattr(ax, "create_router", lambda: provider)

    assert ax.extract_deep_artifacts(f"References: {VOLEXITY}") == {"new_intel": "", "new_observables": []}
    provider.complete.assert_not_called()


@pytest.mark.parametrize("payload", ["no json here", '{"observables": "not a list"}', "{broken"])
def test_malformed_model_output_adds_nothing(monkeypatch, payload):
    monkeypatch.setattr(ax, "scrape_url_text", lambda url: PAGE)
    monkeypatch.setattr(ax, "create_router", lambda: _llm(payload))

    assert ax.extract_deep_artifacts(f"References: {VOLEXITY}")["new_observables"] == []


def test_scrape_returns_visible_text_only(monkeypatch):
    html = "<html><script>var x=1;</script><nav>menu</nav><p>schtasks /create /tn MicrosoftIME</p></html>"
    monkeypatch.setattr(ax.httpx, "get", lambda *a, **k: SimpleNamespace(status_code=200, text=html))
    assert ax.scrape_url_text(VOLEXITY) == "schtasks /create /tn MicrosoftIME"


def test_scrape_verifies_tls(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(status_code=404, text="")

    monkeypatch.setattr(ax.httpx, "get", fake_get)
    assert ax.scrape_url_text(VOLEXITY) == ""
    assert seen.get("verify", True) is True


def test_credentials_come_from_the_environment(monkeypatch):
    from hecate_agent.orchestrator import enrichment, misp_publisher

    monkeypatch.setenv("MISP_API_KEY", "from-env")
    monkeypatch.setenv("VT_API_KEY", "vt-from-env")
    assert misp_publisher._setting("MISP_API_KEY") == "from-env"
    assert enrichment._setting("VT_API_KEY") == "vt-from-env"
    for module in (enrichment, misp_publisher):
        source = Path(module.__file__).read_text(encoding="utf-8")  # type: ignore
        assert 'API_KEY = "' not in source and 'TOKEN = "' not in source


def test_defanged_artifacts_are_returned_refanged():
    """Live Volexity run: artifacts came back as `chinadigitaltimes[.]top`, unusable in a rule."""
    kept, _ = ax.verbatim_artifacts(
        ["chinadigitaltimes[.]top", "hxxps://americanprgoress[.]top/x.exe"], PAGE + " hxxps://americanprgoress[.]top/x.exe"
    )
    assert kept == ["chinadigitaltimes.top", "https://americanprgoress.top/x.exe"]
