"""Primary-source evidence and typed indicator provenance (deep-dive items #1 and #2)."""

import json
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core import source_evidence as se
from hecate_agent.core.gold_eval import load_gold, score_draft
from hecate_agent.core.provenance import (
    IndicatorRecord,
    attach_url_ports,
    merge_records,
    placements,
    records_from_cti,
    routable_indicators,
    split_host_port,
    url_parts,
)

IP = "38.207.178.192"
LOADER = "81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30"
DECODED = "c666ac4f1a1b8df7ccfe8b19705279acd8b7eb7a4d0b3802bb3465064883ab25"
GOLD = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"

PAGE = f"""The resume executable launches cmd.exe, which opens Word on the decoy.
The decoy is saved to C:\\Windows\\Temp\\resume (2).docx before Word opens it.
SNOWLIGHT connects to {IP.replace(".", "[.]", 1)}:50812, downloads 4.65 MB, XOR-decodes it with 0x99.
HIGH confidence 38.207.178[.]192:50813 HTTP staging and DOCX decoy
Go loader SHA-256 {LOADER}
Decoded SHA-256: {DECODED}
AES key and IV: YtWzxwZimsZoeMen
Classification: pan.qlam[.]cc was a historical tenant of the same IP, not a campaign IOC.
"""


def _reply(*artifacts: Dict[str, Any]) -> str:
    return "Here you go:\n" + json.dumps({"artifacts": list(artifacts)})


# --- Provenance ------------------------------------------------------------------------------


def test_url_and_host_port_parsing() -> None:
    assert split_host_port("38.207.178.192:50813") == ("38.207.178.192", 50813)
    assert split_host_port("38.207.178.192") == ("38.207.178.192", None)
    assert url_parts("hxxp://38.207.178[.]192:50813/MySQL_LOG.txt") == ("38.207.178.192", 50813, "/MySQL_LOG.txt")


def test_feed_indicators_become_untyped_records() -> None:
    records = records_from_cti({"FileHash-SHA256": [LOADER.upper()], "IPv4": [IP], "hostname": ["Pan.Qlam.cc."]})
    assert [(r.type, r.value, r.role, r.status) for r in records] == [
        ("sha256", LOADER, "unknown", "unknown"),
        ("ipv4", IP, "unknown", "unknown"),
        ("hostname", "pan.qlam.cc", "unknown", "unknown"),
    ]


def test_active_evidence_outranks_history_and_old_ports_never_scope_a_rule() -> None:
    """H-0618's IP was current on 50812/50813 and historical on 40010."""
    merged = merge_records(
        records_from_cti({"IPv4": [IP]}),
        [
            IndicatorRecord(IP, "ipv4", "historical", "historical", "medium", evidence="old", ports=[40010]),
            IndicatorRecord(IP, "ipv4", "c2", "active", "high", evidence="now", ports=[50812]),
            IndicatorRecord(IP, "ipv4", "download", "active", evidence="now", ports=[50813]),
        ],
    )
    assert len(merged) == 1
    record = merged[0]
    assert (record.status, record.role, record.ports) == ("active", "c2", [50812, 50813])


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (IndicatorRecord(LOADER, "sha256", "executable"), ["process_creation.Hashes"]),
        (IndicatorRecord(LOADER, "sha256", "unknown"), ["process_creation.Hashes"]),
        (IndicatorRecord(LOADER, "sha256", "library"), ["image_load.Hashes"]),
        (IndicatorRecord(DECODED, "sha256", "memory_only"), []),
        (IndicatorRecord(DECODED, "sha256", "archive"), []),
        (IndicatorRecord("pan.qlam.cc", "hostname", "historical", "historical"), []),
        (IndicatorRecord("pan.qlam.cc", "hostname", "staging", "historical"), []),
        (
            IndicatorRecord("evil.example", "domain", "c2", "active"),
            ["dns_query.QueryName", "network_connection.DestinationHostname"],
        ),
        (IndicatorRecord(IP, "ipv4", "c2", "active"), ["network_connection.DestinationIp"]),
        (IndicatorRecord("http://x.example/a.txt", "url", "download"), ["proxy.c-uri"]),
    ],
)
def test_placements_follow_role_and_status(record: IndicatorRecord, expected: List[str]) -> None:
    assert placements(record) == expected


def test_only_routable_indicators_reach_the_model() -> None:
    records = [
        IndicatorRecord(LOADER, "sha256", "executable"),
        IndicatorRecord(DECODED, "sha256", "memory_only"),
        IndicatorRecord("pan.qlam.cc", "hostname", "historical", "historical"),
    ]
    assert routable_indicators(records) == {"sha256": [LOADER]}


def test_url_ports_scope_their_host() -> None:
    records = [IndicatorRecord(IP, "ipv4"), IndicatorRecord(f"http://{IP}:50813/MySQL_LOG.txt", "url")]
    attach_url_ports(records)
    assert records[0].ports == [50813]


# --- Verified extraction ---------------------------------------------------------------------


def test_chunks_cover_the_whole_page_within_the_size_limit() -> None:
    page = "\n".join(f"line {i} " + "x" * 90 for i in range(400))
    chunks = se.chunk_text(page, size=5000, overlap=300)
    assert len(chunks) > 1 and all(len(c) <= 5000 for c in chunks)
    assert chunks[0] == page[: len(chunks[0])] and page.endswith(chunks[-1])


def _extract(*artifacts: Dict[str, Any]) -> se.SourceEvidence:
    return se.extract_source_evidence("https://report.example/a", page_text=PAGE, complete=lambda _m: _reply(*artifacts))


def test_values_must_appear_verbatim_and_have_the_right_shape() -> None:
    ev = _extract(
        {
            "value": "YtWzxwZimsZoeMen",
            "kind": "md5",
            "role": "unknown",
            "status": "active",
            "evidence": "AES key and IV: YtWzxwZimsZoeMen",
        },
        {"value": "10.9.9.9", "kind": "ipv4", "role": "c2", "status": "active", "evidence": ""},
        {
            "value": "cmd.exe",
            "kind": "process",
            "role": "spawned shell",
            "status": "active",
            "evidence": "The resume executable launches cmd.exe",
        },
    )
    assert [a.value for a in ev.artifacts] == ["cmd.exe"]
    assert any("not a well-formed md5" in d for d in ev.dropped)
    assert any("not found verbatim" in d for d in ev.dropped)


def test_a_role_without_a_quoted_passage_is_unknown() -> None:
    ev = _extract(
        {"value": LOADER, "kind": "sha256", "role": "executable", "status": "active", "evidence": "a loader I think"}
    )
    assert (ev.indicators[0].role, ev.indicators[0].status, ev.indicators[0].evidence) == ("unknown", "unknown", "")


def test_hash_role_comes_from_the_reports_own_label() -> None:
    """H-0618's decoded VShell was labelled executable by the model; the report says Decoded."""
    ev = _extract(
        {
            "value": DECODED,
            "kind": "sha256",
            "role": "executable",
            "status": "active",
            "evidence": f"Decoded SHA-256: {DECODED}",
        }
    )
    assert ev.indicators[0].role == "memory_only"
    assert placements(ev.indicators[0]) == []


def test_confidence_is_the_reports_label_and_ports_are_kept() -> None:
    ev = _extract(
        {
            "value": "38.207.178[.]192:50813",
            "kind": "ipv4",
            "role": "staging",
            "status": "active",
            "evidence": "HIGH confidence 38.207.178[.]192:50813 HTTP staging and DOCX decoy",
        }
    )
    record = ev.indicators[0]
    assert (record.value, record.ports, record.confidence, record.source) == (IP, [50813], "high", "https://report.example/a")


def test_a_failed_fetch_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(url: str, timeout: float = 20.0) -> str:
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(se, "fetch_page_text", boom)
    ev = se.extract_source_evidence("https://report.example/a", complete=lambda _m: _reply())
    assert ev.error.startswith("fetch failed") and not ev.artifacts


def test_feed_indicators_missed_by_the_chunk_pass_are_classified_from_their_passages() -> None:
    ev = _extract()
    records = records_from_cti({"hostname": ["pan.qlam.cc"], "IPv4": ["203.0.113.50"]})
    asked: List[str] = []

    def complete(messages: List[Dict[str, str]]) -> str:
        asked.append(messages[-1]["content"])
        return _reply(
            {
                "value": "pan.qlam.cc",
                "role": "historical",
                "status": "historical",
                "evidence": "pan.qlam[.]cc was a historical tenant of the same IP, not a campaign IOC.",
            }
        )

    classified = se.classify_feed_indicators(records, ev, complete)
    assert [(r.value, r.status) for r in classified] == [("pan.qlam.cc", "historical")]
    assert "203.0.113.50" not in asked[0]  # the source never mentions it


# --- Role-routed IOC rules -------------------------------------------------------------------


def _rules(records: List[IndicatorRecord], platforms: List[str] = ["Windows"]) -> Dict[str, Dict[str, Any]]:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    data = SigmaGenerationInput(
        hypothesis="x", hunt_id="H-0901", platforms=platforms, indicator_records=[r.to_dict() for r in records]
    )
    out = {}
    for rule, problem in agent._ioc_rules(data):
        assert problem is None, problem
        doc = yaml.safe_load(rule.rule_yaml)  # type: ignore
        out[doc["logsource"]["category"]] = doc
    return out


def test_records_route_hashes_hosts_ports_and_paths() -> None:
    rules = _rules(
        [
            IndicatorRecord(LOADER, "sha256", "executable", "active"),
            IndicatorRecord(DECODED, "sha256", "memory_only", "active"),
            IndicatorRecord(IP, "ipv4", "c2", "active", ports=[50812, 50813]),
            IndicatorRecord("pan.qlam.cc", "hostname", "historical", "historical"),
            IndicatorRecord(f"http://{IP}:50813/MySQL_LOG.txt", "url", "download", "active"),
        ]
    )
    assert set(rules) == {"process_creation", "network_connection", "proxy"}
    assert rules["process_creation"]["detection"]["selection"]["Hashes|contains"] == [f"SHA256={LOADER}"]
    network = rules["network_connection"]["detection"]
    assert {(b["DestinationIp"], b["DestinationPort"]) for k, b in network.items() if k != "condition"} == {
        (IP, 50812),
        (IP, 50813),
    }
    assert rules["proxy"]["logsource"] == {"category": "proxy"}  # proxy logs have no endpoint OS
    assert rules["proxy"]["detection"]["selection_0"] == {"cs-host": IP, "c-uri|contains": "/MySQL_LOG.txt"}


def test_without_records_the_old_placements_are_unchanged() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    data = SigmaGenerationInput(
        hypothesis="x", platforms=["Windows"], indicators={"sha256": [DECODED], "hostname": ["pan.qlam.cc"]}
    )
    categories = {r.logsource_category for r, _ in agent._ioc_rules(data) if r}
    assert categories == {"process_creation", "dns_query", "network_connection"}


_GOLD_ROLE = {
    "go-loader-executable": ("executable", "active"),
    "zip-archive": ("archive", "active"),
    "encrypted-http-response": ("network_content", "active"),
    "snowlight-shellcode-in-memory": ("memory_only", "active"),
    "encoded-vshell-stream": ("network_content", "active"),
    "decoded-vshell-in-memory": ("memory_only", "active"),
    "docx-decoy": ("document", "active"),
    "c2-staging-and-transfer": ("c2", "active"),
    "historical-passive-dns": ("historical", "historical"),
}


def test_role_routed_ioc_rules_pass_every_gold_indicator_placement(tmp_path: Path) -> None:
    """H-0618 passed 6/24 gold indicator checks; typed records must pass all of them."""
    gold = load_gold(GOLD)
    records: List[IndicatorRecord] = []
    for ind in gold["indicators"]:
        if ind["type"] == "url-path":
            records.append(IndicatorRecord(f"http://{IP}:50813/{ind['value']}", "url", "download", "active"))
            continue
        role, status = _GOLD_ROLE[ind["role"]]
        rtype = "hostname" if ind["type"] == "hostname" else ind["type"]
        records.append(
            IndicatorRecord(str(ind["value"]), rtype, role, status, ports=[50812, 50813] if rtype == "ipv4" else [])
        )

    hunt = tmp_path / "hunts" / "2026" / "Q3" / "H-0901.md"
    hunt.parent.mkdir(parents=True)
    hunt.write_text("---\nhunt_id: H-0901\nplatform: [Windows]\ntechniques: []\n---\n", encoding="utf-8")
    qdir = tmp_path / "queries" / "H-0901"
    qdir.mkdir(parents=True)
    for category, doc in _rules(records).items():
        (qdir / f"{category}.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")

    report = score_draft(gold, hunt)
    assert report.dimensions()["indicators"] == (24, 24)
    passed = {c.id for c in report.checks if c.dimension == "detections" and c.passed}
    assert {"c2-http-staging-port", "c2-raw-tcp-port", "loader-execution", "staging-url-paths"} <= passed
    assert all(c.passed for c in report.checks if c.dimension == "rule semantics")


def test_a_pages_related_content_block_is_cut() -> None:
    """The Huntress page ended with "You Might Also Like" teasers for AMOS and GhostSocks articles."""
    from hecate_agent.core.source_evidence import strip_page_furniture

    body = "Report body. " * 50
    page = f"{body}\nYou Might Also Like\nAMOS Stealer Exploits AI Trust\nGhostSocks and information stealers"
    assert strip_page_furniture(page) == body.rstrip()
    assert strip_page_furniture("Related posts\n" + body) == "Related posts\n" + body  # navigation at the top stays


@pytest.mark.parametrize(
    ("evidence", "role"),
    [
        ("5bad988affc1094f12b8b8bed659ef55b20e2988eb25441e1c1b34dd03b3eb52 Profiler/loader Bash script", "script"),
        (
            "established persistence via deploying a payload (SHA256: "
            "b43a909a01e954d6549558f2f7e9bb58e34959a0ae229f340d61091ab726bbd3) at "
            "/Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate",
            "executable",
        ),
        ("f0062f7e SHA256 Stealer executable (ARM64)", "executable"),
        ("the loader side-loads version.dll, a library it drops", "library"),
    ],
)
def test_hash_roles_from_the_reports_wording(evidence: str, role: str) -> None:
    from hecate_agent.core.source_evidence import _hash_role_from_evidence

    assert _hash_role_from_evidence(evidence, "unknown") == role


def test_a_script_hash_is_placed_in_no_process_rule() -> None:
    from hecate_agent.core.provenance import IndicatorRecord, placements

    assert placements(IndicatorRecord("a" * 64, "sha256", "script", "active")) == []


def test_a_free_text_role_must_use_the_texts_words() -> None:
    """The Huntress replay labelled osascript "decoy document path", the prompt's old example."""
    from hecate_agent.core.source_evidence import _role_supported

    assert not _role_supported("decoy document path", "prompting the victim via an osascript dialogue", "osascript")
    assert _role_supported("kill-switch marker", "Kill-switch marker %TEMP%\\log_de.log", "%TEMP%\\log_de.log")
    page = "the malware downloads a real word document from a url. it saves it as: c:\\windows\\temp\\a.docx"
    assert _role_supported(
        "decoy document path", "It saves it as: C:\\Windows\\Temp\\a.docx", "C:\\Windows\\Temp\\a.docx", page
    )


def test_evidence_that_names_no_role_leaves_the_hash_role_unknown() -> None:
    """A VShell replay's evidence was only "SHA-256: 0524..."; the model's "executable" stood for shellcode."""
    from hecate_agent.core.source_evidence import _checked, _words, normalise

    value = "0524619d2471d77aba4b7993f5ffbaa4b8be6d2c0d91e63a02943851dc4b6404"
    page = f"SNOWLIGHT shellcode SHA-256: {value}"
    raw = {"value": value, "kind": "sha256", "role": "executable", "status": "active", "evidence": f"SHA-256: {value}"}
    artifact, _ = _checked(raw, normalise(page), " ".join(_words(page)))
    assert artifact is not None and artifact.role == "unknown"


def test_the_models_usage_is_counted_across_both_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Chunk extraction and indicator typing both call the model; neither may go unreported."""
    from hecate_agent.core import llm_provider

    class Provider:
        def complete(self, messages: List[Dict[str, str]], **_kwargs: Any) -> llm_provider.LLMResponse:
            return llm_provider.LLMResponse(
                text=_reply(), input_tokens=1000, output_tokens=50, model="claude-sonnet-4-5", duration_ms=2000, cost_usd=0.01
            )

    monkeypatch.setattr(
        "hecate_agent.core.llm_router.create_router", lambda *_a, **_k: Provider()
    )
    ev = se.extract_source_evidence("https://report.example/a", page_text=PAGE)
    assert ev.usage_metadata()["llm_calls"] == ev.chunks
    se.classify_feed_indicators([IndicatorRecord(DECODED, "sha256")], ev)
    usage = ev.usage_metadata()
    assert usage["llm_calls"] == ev.chunks + 1
    assert usage["input_tokens"] == 1000 * usage["llm_calls"]
    assert usage["output_tokens"] == 50 * usage["llm_calls"]
    assert usage["llm_duration_ms"] == 2000 * usage["llm_calls"]
    assert usage["models"] == ["claude-sonnet-4-5"]


def test_a_caller_supplied_model_reports_no_usage() -> None:
    assert _extract().usage_metadata() == {}


@pytest.mark.parametrize(
    "text, value",
    [
        ("Source IPs: 45.153.212[.]101, 46.233.40[.]20", "45.153.212.101"),
        ("Exploitation attempts originated from 198.51.100.7 over two days.", "198.51.100.7"),
        ("We saw scanning from 203.0.113.9 against every exposed gateway.", "203.0.113.9"),
    ],
)
def test_where_the_attack_came_from_is_inbound(text: str, value: str) -> None:
    """H-0830 listed its exploitation "Source IPs"; typed unknown, they became
    an outbound DestinationIp sweep that could never see them."""
    assert se.network_role_from_context(text, value)[0] == "inbound"


def test_a_download_host_stays_infrastructure() -> None:
    text = "The implant was downloaded from 209.141.43[.]95 after exploitation from 45.153.212[.]101."
    assert se.network_role_from_context(text, "209.141.43.95")[0] == ""


def test_the_model_cannot_call_an_address_inbound_without_the_wording() -> None:
    """Inbound turns an address's rules around; a C2 misread as a source would lose its outbound rule."""
    from hecate_agent.core.source_evidence import _checked, _words, normalise

    page = "The beacon reached its C2 at 185.196.8.44 every 60 seconds."
    raw = {"value": "185.196.8.44", "kind": "ipv4", "role": "inbound", "status": "active", "evidence": page}
    artifact, _ = _checked(raw, normalise(page), " ".join(_words(page)))
    assert artifact is not None and artifact.role == "unknown"


def test_fetch_page_text_uses_tavily_extract(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock
    import httpx
    from hecate_agent.core.source_evidence import fetch_page_text

    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-123")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [{"url": "https://example.com/advisory", "raw_content": "Extracted threat intelligence content " * 10}]
    }

    mock_post = MagicMock(return_value=mock_resp)
    monkeypatch.setattr(httpx, "post", mock_post)
    text = fetch_page_text("https://example.com/advisory")
    assert "Extracted threat intelligence content" in text
    assert mock_post.called


@pytest.mark.parametrize("line", ['rev 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', '{"rev":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}'])
def test_a_revision_id_is_not_a_file_hash(line: str) -> None:
    """H-0018's hash rule came from Node-RED flow revision IDs."""
    value = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    assert se.non_file_passage(line, value)


def test_a_named_hash_is_still_a_file_hash() -> None:
    value = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    assert not se.non_file_passage(f"reverse_shell_sha256: {value}", value)


def test_a_github_repository_is_read_as_its_readme(monkeypatch: pytest.MonkeyPatch) -> None:
    readme = "# PoC\n\n## Detection Rules\n\n" + "Alert on POST /flows. " * 10
    calls: List[str] = []

    def fake_get(url: str, **_: Any) -> httpx.Response:
        calls.append(url)
        return httpx.Response(200, text=readme)

    monkeypatch.setattr(se.httpx, "get", fake_get)
    assert se.fetch_page_text("https://github.com/al4n4n/CVE-2026-58115") == readme.strip()
    assert calls == ["https://api.github.com/repos/al4n4n/CVE-2026-58115/readme"]
    assert se.github_readme_text("https://github.com/al4n4n/CVE-2026-58115/blob/main/x.py") == ""


def test_reference_urls_and_domains_are_excluded_from_indicators() -> None:
    from hecate_agent.core.source_evidence import is_reference_url, _checked

    # CVE, CVSS, CWE, NVD reference URLs and domains must be recognized as reference URLs
    assert is_reference_url("https://www.cve.org/CVERecord?id=CVE-2024-3400") is True
    assert is_reference_url("hxxps://www[.]cve[.]org/CVERecord?id=CVE-2024-3400") is True
    assert is_reference_url("https://www.first.org/cvss/calculator/4.0#...") is True
    assert is_reference_url("https://cwe.mitre.org/data/definitions/77.html") is True
    assert is_reference_url("https://nvd.nist.gov/vuln/detail/CVE-2024-3400") is True
    assert is_reference_url("cve.org") is True
    assert is_reference_url("www.first.org") is True

    # Matching the source report URL domain itself
    assert (
        is_reference_url(
            "https://security.paloaltonetworks.com/CVE-2024-3400",
            source_url="https://security.paloaltonetworks.com/CVE-2024-3400",
        )
        is True
    )

    # Adversary URLs and endpoints must NOT be flagged as reference URLs
    assert is_reference_url("http://198.51.100.7/beacon") is False
    assert is_reference_url("https://malicious-c2.com/payload.exe") is False
    assert is_reference_url("/ssl-vpn/hipreport.esp") is False

    # In _checked, reference URLs are rejected with an informative problem message
    artifact, problem = _checked(
        {
            "value": "hxxps://www[.]cve[.]org/CVERecord?id=CVE-2024-3400",
            "kind": "url",
            "role": "unknown",
            "status": "active",
            "evidence": "See CVE record hxxps://www[.]cve[.]org/CVERecord?id=CVE-2024-3400",
        },
        page="See CVE record hxxps://www[.]cve[.]org/CVERecord?id=CVE-2024-3400",
        page_words="See CVE record hxxps://www[.]cve[.]org/CVERecord?id=CVE-2024-3400",
    )
    assert artifact is None
    assert "reference/documentation URL" in problem

