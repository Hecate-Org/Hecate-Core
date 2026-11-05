"""Behaviour-to-technique mapping, gated on observed use (deep-dive item #4)."""

from pathlib import Path
from typing import Dict

import pytest
import yaml

from hecate_agent.core.technique_evidence import map_behaviours, sentence_status, sentences, technique_support

GOLD = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"


def _observed(text: str) -> Dict[str, str]:
    return {e.technique_id: e.passage for e in map_behaviours([("cti", text)]) if e.status == "observed"}


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        ("The loader checks for a sandbox and needs at least four logical processors.", "T1497.001"),
        ("It verifies a ten-second sleep timer before continuing.", "T1497.003"),
        ("The stager XOR-decodes the payload with key 0x99.", "T1140"),
        ("It downloads 4.65 MB of data from the server.", "T1105"),
        ("It executes obfuscated WScript commands to download a secondary payload.", "T1105"),
        ("WScript executing obfuscated JavaScript from temporary storage.", "T1059.007"),
        ("A Chinese-language executable disguised as a resume was sent to researchers.", "T1204.002"),
        ("The executable launches cmd.exe, which opens Word.", "T1059.003"),
        ("It connects over a raw TCP channel to the operator.", "T1095"),
        ("Frames use AES-GCM with a 12-byte nonce.", "T1573"),
        ("The loader uses HTTP staging on port 50813.", "T1071.001"),
        ("It allocates memory, copies the downloaded bytes, marks them executable, creates a thread and waits.", "T1620"),
        ("A scheduled task named MicrosoftIME keeps it running.", "T1053.005"),
        ("The payload is injected into explorer via process hollowing.", "T1055.012"),
    ],
)
def test_described_behaviour_maps_to_its_technique(sentence: str, technique: str) -> None:
    assert technique in _observed(sentence)


def test_windows_script_host_does_not_imply_visual_basic():
    assert "T1059.005" not in _observed("WScript executing obfuscated JavaScript from temporary storage.")
    assert "T1059.005" in _observed("The adversary executed a VBScript payload with wscript.exe.")


def test_a_capability_list_is_not_observed_use() -> None:
    """H-0618: T1113 came from what VShell offers, not what the intrusion did."""
    text = "The RAT provides operators with command execution, file access, screen capture and lateral movement capabilities."
    evidence = {e.technique_id: e.status for e in map_behaviours([("cti", text)])}
    assert evidence == {"T1113": "capability"}


@pytest.mark.parametrize(
    "sentence",
    [
        "Give an operator quiet access to the workstation: command execution and screen capture.",
        "Public VShell analysis documents: screenshot capture and interactive screen access.",
    ],
)
def test_purpose_and_documentation_framing_is_capability(sentence: str) -> None:
    assert sentence_status(sentence) == "capability"


def test_a_feature_list_after_enabling_is_capability() -> None:
    """H-0618 replay: independent research's feature list mapped T1113 as observed."""
    text = (
        "The final payload is a fileless VShell RAT, executed entirely in memory without persistence, "
        "enabling command execution, file access, screen capture, and lateral movement."
    )
    assert "T1113" not in _observed(text)


def test_a_negation_rules_the_behaviour_out() -> None:
    assert "T1113" not in _observed("Not observed: an operator taking a screen capture.")


def test_website_script_injection_is_not_process_injection() -> None:
    assert "T1055" not in _observed("Malicious JavaScript is injected into the website HTML.")
    assert "T1055" in _observed("The loader injects into explorer.exe.")
    assert "T1055" in _observed("The payload is injected into another process.")


def test_analyst_instruction_does_not_become_observed_run_key_persistence() -> None:
    text = "Do not infer a registry Run key from the infection marker."
    assert "T1547.001" not in _observed(text)
    assert sentence_status(text) == "context"
    assert "T1547.001" in _observed("The operator creates a Run key for persistence.")


def test_another_actors_tradecraft_is_context_not_evidence() -> None:
    text = "UAT-8302 used Windows SNOWLIGHT, government intrusions, sideloading and different malware; no lure match."
    assert map_behaviours([("primary source", text)]) == []


def test_a_bare_fileless_label_does_not_establish_reflective_loading() -> None:
    assert "T1620" not in _observed("It launches a fileless VShell RAT.")


def test_label_lines_are_not_evidence() -> None:
    text = "OTX Pulse: A fake resume installed VShell\nTags: sandbox evasion, fileless execution\nDescription: prose."
    assert _observed(text) == {}


def test_scraped_inline_elements_are_rejoined_into_sentences() -> None:
    assert sentences("The sandbox showed the executable launching\ncmd.exe\n, opening a DOCX.") == [
        "The sandbox showed the executable launching cmd.exe, opening a DOCX."
    ]


def test_an_observed_passage_outranks_a_capability_one() -> None:
    text = "VShell offers screen capture. In this intrusion the operator took a screen capture of the desktop."
    evidence = map_behaviours([("cti", text)])
    assert [(e.technique_id, e.status) for e in evidence] == [("T1113", "observed")]
    assert evidence[0].passage.startswith("In this intrusion")


def test_an_everyday_word_is_not_support_for_the_technique_it_names() -> None:
    """A model chose T1213.006 Databases for a Redis botnet and the word "database" kept it."""
    text = "The attackers compromised exposed Redis database servers and wrote a cron job to each."
    assert technique_support("T1213.006", ["Databases"], text) is None
    assert technique_support("T1056.001", ["Keylogging"], "The implant performed keylogging on each host.") is not None


def test_technique_support_by_name_reports_capability_only_mentions() -> None:
    text = "The tool offers credential dumping and keylogging to its operators."
    support = technique_support("T1056.001", ["Keylogging"], text)
    assert support is not None and support.status == "capability"
    assert technique_support("T1056.001", ["Keylogging"], "Nothing relevant here.") is None


def test_the_vshell_cti_maps_only_observed_techniques() -> None:
    """On the OTX blurb alone: six gold techniques, none forbidden, T1113 capability only."""
    gold = yaml.safe_load(GOLD.read_text(encoding="utf-8"))
    evidence = map_behaviours([("cti", gold["source"]["cti"])])
    observed = {e.technique_id for e in evidence if e.status == "observed"}
    expected = {t["id"] for t in gold["techniques"]["observed"]}
    forbidden = {t["id"] for t in gold["techniques"]["forbidden"]}
    assert observed == {"T1036", "T1105", "T1140", "T1204.002", "T1497.001", "T1497.003"}
    assert observed <= expected and not observed & forbidden
    assert {e.technique_id for e in evidence if e.status == "capability"} == {"T1113"}
    assert all(e.passage for e in evidence)


# --- macOS and Unix tradecraft (the ClickFix gold case) ---------------------------------------


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        ("The target was tricked into pasting a ClickFix command into a Mac Terminal.", "T1204.004"),
        ("The target had followed a link sent in an email message.", "T1566.002"),
        ("The file that was downloaded is a Bash script that creates a detailed profile of the system.", "T1059.004"),
        ("It runs ioreg -c IOPlatformExpertDevice -d 2 and system_profiler SPHardwareDataType.", "T1082"),
        ('It runs echo "$(whoami)" to identify the logged-in user.', "T1033"),
        ("It then deleted the command history from the Terminal.", "T1070.003"),
        ("It retrieves a file, executes it, then deletes the temporarily stored file with rm -f .x.", "T1070.004"),
        ("xattr -d com.apple.quarantine removes the Gatekeeper bit.", "T1553.001"),
        ("It creates a directory with a name that mimics the name of the legitimate process in macOS.", "T1036.005"),
        ("It ran launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist.", "T1543.001"),
        ("The attackers prompted the victim for their credentials via an osascript dialogue.", "T1056.002"),
    ],
)
def test_unix_and_macos_behaviour_maps_to_its_technique(sentence: str, technique: str) -> None:
    assert technique in _observed(sentence)


def test_a_description_of_a_legitimate_subsystem_is_context() -> None:
    """BTM "tracks ... launch agents, login items, or cron jobs": no cron job was used."""
    text = (
        "BTM is a legitimate Apple subsystem that is used to track anything that installs itself to run "
        "automatically in the background (like launch agents, login items, or cron jobs)."
    )
    assert not _observed(text)


def test_the_macos_feed_text_alone_maps_its_behaviour_without_forbidden_techniques() -> None:
    """The feed never mentions LaunchAgents ("persistence through macOS Background Task Management"); the report does."""
    gold = yaml.safe_load((GOLD.parent / "macos-clickfix-stealer.yaml").read_text(encoding="utf-8"))
    observed = {e.technique_id for e in map_behaviours([("cti", gold["source"]["cti"])]) if e.status == "observed"}
    forbidden = {t["id"] for t in gold["techniques"]["forbidden"]}
    assert {"T1204.004", "T1553.001", "T1555.001"} <= observed and not observed & forbidden


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        # H-0016, a Node-RED exploit PoC README: none of these happened on a victim.
        ("The layer ships no settings.js and the string adminAuth does not appear anywhere in the repository.", "T1059.007"),
        (
            "PCAP Live capture of a check.py + poc.py run under capture/ : 70 packets, 7 HTTP requests "
            "over 7 connections, 172.17.0.1 → 172.17.0.4:1880, no TLS.",
            "T1071.001",
        ),
        ("The exploit is delivered over HTTP to the vulnerable server.", "T1071.001"),
    ],
)
def test_a_file_name_or_plain_web_traffic_is_not_the_technique(sentence: str, technique: str) -> None:
    assert technique not in _observed(sentence)


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        ("The dropper ran wscript.exe C:\\Users\\Public\\update.js on logon.", "T1059.007"),
        ("node loader.js fetched the second stage.", "T1059.007"),
        ("The implant sends HTTP requests to its C2 every 60 seconds.", "T1071.001"),
        ("The backdoor communicates with the operator over HTTPS.", "T1071.001"),
    ],
)
def test_script_execution_and_http_c2_still_map(sentence: str, technique: str) -> None:
    assert technique in _observed(sentence)


@pytest.mark.parametrize(
    "sentence",
    [
        "# 2. Or stop the service if it is not needed systemctl disable --now node-red",
        "# 1. Enable authentication (adminAuth) following the Node-RED securing guide.",
        "We recommend that administrators disable PowerShell v2 on every host.",
    ],
)
def test_advice_to_defenders_is_not_observed_use(sentence: str) -> None:
    assert sentence_status(sentence) == "negated"


def test_a_technique_named_only_in_remediation_advice_has_no_observed_support() -> None:
    support = technique_support(
        "T1569.003", ["Systemctl"], "# 2. Or stop the service if it is not needed systemctl disable --now node-red"
    )
    assert support is not None and support.status == "capability"


def test_a_candidate_from_report_wording_has_a_passage() -> None:
    """H-0018 matched T1190 on "RCE" but showed no passage for it."""
    found = technique_support("T1190", [], "Siemens IoT2050 Node-RED unauthenticated root RCE.")
    assert found is not None and found.status == "observed"
