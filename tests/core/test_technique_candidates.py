"""Deterministic ATT&CK candidates from a report's own wording."""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional

import pytest

from hecate_agent.core import attack_matrix
from hecate_agent.core.attack_matrix import FallbackProvider, TechniqueInfo
from hecate_agent.core.technique_candidates import _stem, candidate_techniques, format_candidates


def _t(tid: str, name: str, tactic: str) -> TechniqueInfo:
    return TechniqueInfo(id=tid, name=name, tactic_shortnames=[tactic])


_TECHNIQUES: Dict[str, TechniqueInfo] = {
    t["id"]: t
    for t in [
        _t("T1036", "Masquerading", "stealth"),
        _t("T1113", "Screen Capture", "collection"),
        _t("T1546.002", "Screensaver", "persistence"),
        _t("T1569.003", "Systemctl", "execution"),
        _t("T1124", "System Time Discovery", "discovery"),
        _t("T1207", "Rogue Domain Controller", "stealth"),
        _t("T1547.006", "Kernel Modules and Extensions", "persistence"),
        _t("T1583.001", "Domains", "resource-development"),
        _t("T1587.001", "Malware", "resource-development"),
        _t("T1127.001", "MSBuild", "stealth"),
        _t("T1610", "Deploy Container", "execution"),
        _t("T1204.002", "Malicious File", "execution"),
        _t("T1190", "Exploit Public-Facing Application", "initial-access"),
        _t("T1574.001", "DLL", "stealth"),
        _t("T1571", "Non-Standard Port", "command-and-control"),
        _t("T1546.005", "Trap", "persistence"),
        _t("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration"),
        _t("T1105", "Ingress Tool Transfer", "command-and-control"),
        _t("T1059.005", "Visual Basic", "execution"),
    ]
}


class _FakeMatrix(FallbackProvider):
    def get_sorted_tactic_keys(self) -> List[str]:
        return sorted({t["tactic_shortnames"][0] for t in _TECHNIQUES.values()})

    def get_technique_by_id(self, technique_id: str) -> Optional[TechniqueInfo]:
        return _TECHNIQUES.get(technique_id.upper())

    def get_techniques_for_tactic(self, tactic_key: str) -> List[TechniqueInfo]:
        return [t for t in _TECHNIQUES.values() if tactic_key in t["tactic_shortnames"]]


@pytest.fixture(autouse=True)
def fake_matrix() -> Iterator[None]:
    attack_matrix.reset_provider(_FakeMatrix())
    yield
    attack_matrix.reset_provider(None)


def _ids(text: str) -> List[str]:
    return [tid for tid, _ in candidate_techniques(text)]


def test_a_named_behavior_is_proposed() -> None:
    """H-0002: LabubaRAT "masquerades as NVIDIA software" got T1027.004."""
    ids = _ids("LabubaRAT masquerades as NVIDIA software and supports screen capture.")
    assert "T1036" in ids
    assert "T1113" in ids


def test_words_that_merely_share_a_prefix_are_not_a_match() -> None:
    """A six-letter stem let Screensaver match "screen capture" and
    Systemctl match "system"."""
    ids = _ids("Supports screen capture and system reconnaissance.")
    assert "T1546.002" not in ids
    assert "T1569.003" not in ids


def test_a_name_must_appear_as_a_phrase_not_as_scattered_words() -> None:
    """ "discovered ... time" is not System Time Discovery; "domains" and
    "remote control" are not Rogue Domain Controller (H-0007)."""
    ids = _ids(
        "Researchers discovered the system at the time. Typosquatted provider "
        "domains delivered backdoors for remote control. Go modules and Chrome extensions."
    )
    assert "T1124" not in ids
    assert "T1207" not in ids
    assert "T1547.006" not in ids


def test_pre_intrusion_tactics_are_not_matched_on_everyday_nouns() -> None:
    assert "T1587.001" not in _ids("The malware was delivered by email.")


def test_report_wording_names_a_technique_its_title_never_uses() -> None:
    ids = _ids("It abused legitimate Microsoft build utilities via MSBuild from typosquatted domains.")
    assert ids[:2] == ["T1127.001", "T1583.001"]


def test_commentary_yields_no_candidates() -> None:
    """H-0006: an opinion post about AI guardrails."""
    assert _ids("Frontier AI models are restrictive; defenders face a safety penalty.") == []


def test_unreadable_attack_data_yields_nothing_rather_than_raising() -> None:
    class Broken(_FakeMatrix):
        def get_sorted_tactic_keys(self) -> List[str]:
            raise RuntimeError("stix unavailable")

    attack_matrix.reset_provider(Broken())
    assert candidate_techniques("masquerading") == []


def test_a_shared_prefix_across_a_phrase_is_not_a_match() -> None:
    """25 Sep: "VCO deployments contain a critical vulnerability" was read as
    T1610 Deploy Container."""
    assert "T1610" not in _ids("On-premises deployments contain a critical vulnerability.")
    assert "T1610" in _ids("The actor tried to deploy containers on the cluster.")


def test_a_short_root_under_a_derivational_suffix_is_a_different_word() -> None:
    """ "portion" is not "port"; the longer roots still meet their variants."""
    assert _stem("portion") != _stem("port")
    assert _stem("obfuscation") == _stem("obfuscated")
    assert _stem("containers") == _stem("container")
    assert "T1571" in _ids("Beacons used a non-standard port for C2.")


def test_a_name_of_only_generic_words_is_never_matched() -> None:
    """ "Malicious File" put User Execution on an advisory saying "malicious
    files" about an exploit no user ran."""
    assert "T1204.002" not in _ids("Indicators include malicious files and suspicious HTTP headers.")


def test_zero_day_alone_does_not_propose_a_public_facing_exploit() -> None:
    """DarkMe "abandoned zero-day exploits"; UTA0565's 0-days were in Chrome."""
    assert "T1190" not in _ids("Previously notable for weaponizing zero-day exploits, it now phishes.")
    assert "T1190" not in _ids("Chrome and Windows 0-day exploits delivered from fake websites.")
    assert "T1190" in _ids("A remote code execution flaw in the internet-facing appliance.")


def test_dll_hijacking_is_proposed_although_its_attack_name_is_just_dll() -> None:
    assert "T1574.001" in _ids("The ClickFix campaign sideloads a malicious mscoree.dll.")
    assert "T1574.001" in _ids("Detecting DLL hijacking with Elastic Defend")


def test_a_one_word_name_that_is_an_everyday_word_is_not_matched() -> None:
    """H-0018: T1546.005 Trap for a Teams vishing campaign, on "OAuth Traps"."""
    assert "T1546.005" not in _ids("Phishing Kits, Dropbox Account Hacks, OAuth Traps")
    assert "T1036" in _ids("The loader masquerades as a Teams update.")


def test_a_name_that_is_a_thing_not_a_behaviour_is_not_matched() -> None:
    """T1213.006 Databases was proposed for a Redis cryptomining botnet: Redis is a database."""
    assert "T1213.006" not in _ids("The operator logs C2 pings to a local SQLite database on exposed Redis database servers.")
    assert "T1213.001" not in _ids("Attackers exploited a Confluence vulnerability for initial access.")
    assert "T1036" in _ids("The loader masquerades as a database backup tool.")


def test_dns_exfiltration_is_proposed() -> None:
    """H-0017, "Abusing Open Recursive DNS for Exfiltration", got T1027 alone."""
    assert "T1048.003" in _ids("Malware Sample Abusing Open Recursive DNS for Exfiltration")
    assert "T1048.003" not in _ids("DNS logs were collected for the exfiltration review.")


def test_format_candidates() -> None:
    assert format_candidates([]) is None
    assert format_candidates([("T1036", "Masquerading")]) == "  T1036: Masquerading"


def test_tool_transfer_and_explicit_visual_basic_are_proposed() -> None:
    assert "T1105" in _ids("It executes commands to download a secondary payload.")
    assert "T1059.005" not in _ids("The loader executes WScript commands from the temporary folder.")
    assert "T1059.005" in _ids("The loader executes VBScript from the temporary folder.")


def test_named_techniques_leave_out_similarity_leads(monkeypatch: pytest.MonkeyPatch) -> None:
    """H-0016: TF-IDF similarity on a Node-RED exploit README proposed RC
    Scripts and Password Managers, and the Runner kept both as "matched in the
    source's wording", shielded from the unevidenced-technique check."""
    from hecate_agent.core import technique_candidates

    monkeypatch.setattr(
        technique_candidates,
        "_semantic_matches",
        lambda text: [("T1037.004", "RC Scripts", 38), ("T1555.005", "Password Managers", 14)],
    )
    text = "A remote code execution flaw in the internet-facing appliance."
    assert "T1037.004" in _ids(text)
    named = [tid for tid, _ in technique_candidates.named_techniques(text)]
    assert named == ["T1190"]


def test_semantic_candidate_matching_with_stix() -> None:
    attack_matrix.reset_provider(None)
    try:
        from hecate_agent.core.attack_matrix import is_using_stix
        if not is_using_stix():
            pytest.skip("STIX data not installed")
        cands = [tid for tid, _ in candidate_techniques("The malware uses JavaScript embedded in compromised websites to profile the victim's system.")]
        assert "T1059.007" in cands or "T1027.006" in cands
    finally:
        attack_matrix.reset_provider(_FakeMatrix())
