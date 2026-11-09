"""Sigma semantic validation (deep-dive item #5).

The rejected rules are the ones H-0618's runs actually drafted.
"""

from typing import Any, Dict, Optional

import pytest

from hecate_agent.agents.llm.sigma_generator import _or_branch_breadth_problem
from hecate_agent.core.sigma_semantics import semantic_problem


def _problem(category: str, detection: Dict[str, Any], description: str = "") -> Optional[str]:
    return semantic_problem(detection, category, description)


def test_wscript_path_must_match_expanded_telemetry():
    detection = {"selection": {"Image|endswith": r"\wscript.exe", "CommandLine|contains": r"%APPDATA%\Local\Temp"}, "condition": "selection"}
    assert "unexpanded environment variable" in (_problem("process_creation", detection) or "")
    detection["selection"]["CommandLine|contains"] = "\\Temp\\"
    assert _problem("process_creation", detection) is None


def test_cmd_can_receive_unexpanded_environment_variables():
    detection = {"selection": {"Image|endswith": r"\cmd.exe", "CommandLine|contains": r"%TEMP%\script.cmd"}, "condition": "selection"}
    assert _problem("process_creation", detection) is None


def test_registry_key_creation_is_not_value_modification():
    detection = {"selection": {"TargetObject|contains": r"\CurrentVersion\Run", "EventType": "CreateKey"}, "condition": "selection"}
    assert "CreateKey misses writes" in (_problem("registry_event", detection, "Detects Run key modifications") or "")
    assert _problem("registry_event", detection, "Detects creation of a new Run key") is None
    detection["selection"]["EventType"] = "SetValue"
    assert _problem("registry_event", detection, "Detects Run key modifications") is None


@pytest.mark.parametrize("claim", ["WScript with Obfuscated Arguments", "WScript with Obfuscated Command Line", "Obfuscated script execution"])
def test_temporary_script_path_does_not_test_obfuscated_arguments(claim):
    detection = {"selection": {"Image|endswith": r"\wscript.exe", "CommandLine|contains": "\\AppData\\Local\\Temp\\"}, "condition": "selection"}
    assert "only a script path" in (_problem("process_creation", detection, claim) or "")
    assert _problem("process_creation", detection, "WScript execution from a temporary directory") is None
    detection["selection"]["CommandLine|contains"] = ["\\Temp\\", "-EncodedCommand"]
    assert _problem("process_creation", detection, "Execution with Obfuscated Arguments") is None


def test_script_host_without_arguments_cannot_claim_argument_obfuscation():
    detection = {"selection": {"Image|endswith": r"\wscript.exe"}, "condition": "selection"}
    assert "only a script path or process" in (_problem("process_creation", detection, "Obfuscated command-line arguments") or "")


@pytest.mark.parametrize("value", ["[auth key]", "-k https://gitea.redacted.com.ar/api/v1/metrics?k=[auth", "<target>"])
def test_report_redactions_are_not_deployable_predicates(value):
    detection = {"selection": {"CommandLine|contains": value}, "condition": "selection"}
    assert "report redaction" in (_problem("process_creation", detection) or "")


@pytest.mark.parametrize("value", ["/usr/lib//", "/proc/self/exe", "/proc/net/tcp", "/proc//cmdline"])
def test_non_file_write_artifacts_do_not_become_file_creation_rules(value):
    detection = {"selection": {"TargetFilename": value}, "condition": "selection"}
    assert _problem("file_event", detection)
    if value.endswith("/"):
        detection["selection"] = {"TargetFilename|endswith": value}
        assert _problem("file_event", detection)
    if value.startswith("/proc/"):
        detection["selection"] = {"TargetFilename|contains": value}
        assert _problem("file_event", detection)
    detection["selection"] = {"TargetFilename|startswith": "/usr/lib/"}
    assert _problem("file_event", detection) is None


def test_echo_is_not_an_argument_to_nc_on_the_other_side_of_a_pipe():
    detection = {"selection": {"Image|endswith": "/nc", "CommandLine|contains": "echo"}, "condition": "selection"}
    assert "shell pipeline" in (_problem("process_creation", detection) or "")
    detection["selection"]["CommandLine|contains"] = "48931"
    assert _problem("process_creation", detection) is None


@pytest.mark.parametrize(
    ("category", "detection", "expected"),
    [
        (
            "image_load",
            {"selection": {"ImageLoaded|endswith": "\\activeds.dll", "ParentImage|endswith": "\\winword.exe"}},
            "ParentImage is not a image_load field",
        ),
        (
            "process_creation",
            {"selection": {"Image|endswith": "\\cmd.exe", "DestinationIp": "45.94.31.110"}},
            "DestinationIp is not a process_creation field",
        ),
        (
            "file_event",
            {"selection": {"TargetFilename|endswith": ".docx", "Hashes|contains": "SHA256=81c511"}},
            "Hashes is not a file_event field",
        ),
    ],
)
def test_a_field_from_another_log_source_is_rejected(category: str, detection: Dict[str, Any], expected: str) -> None:
    detection["condition"] = "selection"
    assert expected in (_problem(category, detection) or "")


def test_a_document_is_not_a_process_image() -> None:
    detection = {"selection": {"Image|contains": "MySQL_LOG.txt"}, "condition": "selection"}
    assert "never a process image" in (_problem("process_creation", detection) or "")


def test_an_api_name_is_not_a_command_line() -> None:
    detection = {
        "selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": ["Beep"]},
        "condition": "selection",
    }
    assert "API or system call" in (_problem("process_creation", detection) or "")


def test_an_api_name_inside_a_longer_argument_is_rejected() -> None:
    detection = {
        "selection": {"Image|endswith": "\\winword.exe", "CommandLine|contains": "call VirtualAlloc then"},
        "condition": "selection",
    }
    assert "API or system call" in (_problem("process_creation", detection) or "")


@pytest.mark.parametrize(
    "selection",
    [
        # PowerShell inline P/Invoke names APIs on its command line (SigmaHQ's inline Win API rule).
        {"Image|endswith": "\\powershell.exe", "CommandLine|contains": ["CreateRemoteThread", "VirtualAlloc"]},
        # No process pinned: any script host may carry it.
        {"CommandLine|contains": ["CreateRemoteThread"]},
    ],
)
def test_an_api_name_on_a_script_hosts_command_line_is_accepted(selection: Dict[str, Any]) -> None:
    detection = {
        "selection": selection,
        "filter_optional_mpcmdrun": {"Image|endswith": "\\MpCmdRun.exe"},
        "condition": "selection and not 1 of filter_optional_*",
    }
    assert _problem("process_creation", detection) is None


def test_a_sigma_escaped_wildcard_is_not_a_path() -> None:
    detection = {"selection": {"c-uri|contains": "/manifest\\?manifest=wac"}, "condition": "selection"}
    assert _problem("proxy", detection) is None


@pytest.mark.parametrize(
    ("category", "field", "value", "expected"),
    [
        ("file_event", "TargetFilename|endswith", "http://45.94.31.110:50813/resume.docx", "is a local path"),
        ("proxy", "c-uri|endswith", "C:\\Windows\\Temp\\resume.docx", "is a URL"),
        ("dns_query", "QueryName", "update.example.org/check", "holds a host name"),
    ],
)
def test_urls_and_local_paths_are_not_interchangeable(category: str, field: str, value: str, expected: str) -> None:
    detection = {"selection": {field: value}, "condition": "selection"}
    assert expected in (_problem(category, detection) or "")


def test_two_process_images_in_one_and_match_no_event() -> None:
    """Word then cmd.exe is a sequence; as one AND on Image it matches nothing."""
    detection = {
        "selection_word": {"Image|endswith": "\\winword.exe"},
        "selection_cmd": {"Image|endswith": "\\cmd.exe"},
        "condition": "selection_word and selection_cmd",
    }
    assert "same event" in (_problem("process_creation", detection) or "")


@pytest.mark.parametrize(
    "detection",
    [
        # Parent and child on one event: the single-event form of a chain.
        {"selection": {"ParentImage|endswith": "\\winword.exe", "Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        # Compatible constraints on one field.
        {
            "a": {"Image|endswith": "\\cmd.exe"},
            "b": {"Image|startswith": "C:\\Windows\\"},
            "condition": "a and b",
        },
        # An OR is not one event's AND.
        {"a": {"Image|endswith": "\\winword.exe"}, "b": {"Image|endswith": "\\cmd.exe"}, "condition": "a or b"},
        # A negated filter does not have to agree with the selection.
        {
            "selection": {"Image|endswith": "\\svchost.exe"},
            "filter": {"Image|startswith": "C:\\Windows\\System32"},
            "condition": "selection and not filter",
        },
    ],
)
def test_satisfiable_logic_is_accepted(detection: Dict[str, Any]) -> None:
    assert _problem("process_creation", detection) is None


def test_a_suffix_promise_needs_suffix_logic() -> None:
    detection = {"selection": {"QueryName": ["api.example.net"]}, "condition": "selection"}
    assert "subdomain" in (_problem("dns_query", detection, "Matches the domain and its subdomains") or "")
    detection["selection"] = {"QueryName|endswith": [".example.net"]}
    assert _problem("dns_query", detection, "Matches the domain and its subdomains") is None


def test_a_reversed_process_chain_is_rejected() -> None:
    """The source's chain was loader -> cmd.exe -> Word; the description and selection must at least agree."""
    detection = {
        "selection": {"ParentImage|endswith": "\\cmd.exe", "Image|endswith": "\\winword.exe"},
        "condition": "selection",
    }
    assert "starts cmd" in (_problem("process_creation", detection, "Detects WinWord spawning cmd.exe") or "")
    assert _problem("process_creation", detection, "Detects cmd.exe launching Word") is None
    assert _problem("process_creation", detection, "Detects WinWord spawned by cmd.exe") is None


def test_a_broad_or_branch_is_rejected_even_beside_a_specific_one() -> None:
    detection = {
        "selection_ioc": {"Hashes|contains": "SHA256=81c511aa"},
        "selection_any": {"Image|endswith": ".exe"},
        "condition": "1 of selection_*",
    }
    assert "selection_any" in (_or_branch_breadth_problem(detection) or "")
    detection["condition"] = "selection_ioc and selection_any"
    assert _or_branch_breadth_problem(detection) is None


# --- The #5 replay's model rules, which passed the first version of these checks ---

DECOY = "C:\\Windows\\Temp\\Beijing Institute of Technology_..._personal resume (2).docx"


def test_an_api_name_is_not_a_loaded_module() -> None:
    detection = {"selection": {"ImageLoaded|contains": "Beep", "Image|endswith": "\\cmd.exe"}, "condition": "selection"}
    assert "not a file or module name" in (_problem("image_load", detection) or "")


def test_a_file_name_is_not_a_dns_name() -> None:
    detection = {"selection": {"QueryName|endswith": ".txt"}, "condition": "selection"}
    assert "file name" in (_problem("dns_query", detection) or "")
    detection["selection"] = {"QueryName|endswith": ".zip"}  # a real TLD
    assert _problem("dns_query", detection) is None


def test_a_reported_elision_is_not_a_literal() -> None:
    detection = {"selection": {"CommandLine|contains": DECOY}, "condition": "selection"}
    assert "elision" in (_problem("process_creation", detection) or "")


def test_a_filter_may_not_exclude_the_threats_own_artifact() -> None:
    detection = {
        "selection": {"TargetFilename|startswith": "C:\\Windows\\Temp\\", "TargetFilename|endswith": ".docx"},
        "filter": {"TargetFilename|contains": "personal resume (2).docx"},
        "condition": "selection and not filter",
    }
    named = [f"file.path: {DECOY}"]
    assert "drop the event it hunts for" in (semantic_problem(detection, "file_event", "", named) or "")
    # A directory is judged by what it excludes: System32 is ordinary tuning,
    # but the source says the decoy is written under C:\\Windows\\Temp\\ (the A1 replay).
    detection["selection"] = {"TargetFilename|endswith": ".docx"}
    detection["filter"] = {"TargetFilename|startswith": "C:\\Windows\\System32\\"}
    assert semantic_problem(detection, "file_event", "", [DECOY]) is None
    detection["filter"] = {"TargetFilename|contains": "\\Windows\\Temp\\"}
    assert "matches" in (semantic_problem(detection, "file_event", "", [DECOY]) or "")


def test_a_port_is_not_a_module_path() -> None:
    detection = {"selection": {"ImageLoaded|contains": "50813", "Image|endswith": "\\cmd.exe"}, "condition": "selection"}
    assert "bare number" in (_problem("image_load", detection) or "")


def test_a_filter_may_not_reuse_the_threats_file_name() -> None:
    """The decoy's own name with an invented year may be the decoy."""
    detection = {
        "selection": {"TargetFilename|endswith": "_personal resume (2).docx"},
        "filter": {"TargetFilename|contains": "Beijing Institute of Technology_2023_"},
        "condition": "selection and not filter",
    }
    assert "threat's own file name" in (semantic_problem(detection, "file_event", "", [f"file.path: {DECOY}"]) or "")


def test_an_executables_hash_is_not_a_loaded_module() -> None:
    from hecate_agent.agents.llm.sigma_generator import _hash_role_problem

    loader = "81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30"
    records = [{"value": loader, "type": "sha256", "role": "executable", "status": "active"}]
    detection = {"selection": {"Hashes|contains": loader}, "condition": "selection"}
    assert "never seen in image_load" in (_hash_role_problem(detection, records, "image_load") or "")
    assert _hash_role_problem(detection, records, "process_creation") is None


def test_a_document_is_not_a_loaded_module() -> None:
    detection = {"selection": {"ImageLoaded|endswith": ".docx", "Image|endswith": "\\cmd.exe"}, "condition": "selection"}
    assert "never a loaded module" in (_problem("image_load", detection) or "")


def test_a_filter_that_repeats_the_selection_is_rejected() -> None:
    """The #6 replay's image_load rule could never fire."""
    detection = {
        "selection": {"ImageLoaded|contains": "vshell", "Image|endswith": "\\cmd.exe"},
        "filter": {"ImageLoaded|contains": "vshell"},
        "condition": "selection and not filter",
    }
    assert "never fires" in (_problem("image_load", detection) or "")
    detection["filter"] = {"ImageLoaded|contains": "C:\\Windows\\System32\\"}
    assert _problem("image_load", detection) is None


def test_a_wildcard_inside_a_value_is_wildcard_matching() -> None:
    detection = {"selection": {"TargetFilename": "C:\\Windows\\Temp\\a_*_b.docx"}, "condition": "selection"}
    assert _problem("file_event", detection, "The wildcard stands for the elided part") is None


def test_an_image_load_rule_must_say_which_module() -> None:
    """The end-to-end replay kept Image|endswith: \\cmd.exe alone: every DLL cmd.exe loads."""
    detection = {
        "selection": {"Image|endswith": "\\cmd.exe"},
        "filter": {"Image|endswith": "\\winword.exe"},
        "condition": "selection and not filter",
    }
    assert "every module that process loads" in (_problem("image_load", detection) or "")
    # A process that should never connect out is a sound rule on Image alone (SigmaHQ has a dozen).
    detection = {"selection": {"Image|endswith": "\\notepad.exe"}, "condition": "selection"}
    assert _problem("network_connection", detection) is None


def test_a_filter_may_not_exclude_a_named_unix_path() -> None:
    """The ClickFix replay's rule hunted a LaunchAgent plist and filtered out /Library/LaunchAgents/."""
    named = ["launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist"]
    detection = {
        "selection": {"TargetFilename|endswith": "/com.apple.softwareupdated.plist"},
        "filter": {"TargetFilename|contains": "/Library/LaunchAgents/"},
        "condition": "selection and not filter",
    }
    assert "matches" in (semantic_problem(detection, "file_event", "", named) or "")
    detection["filter"] = {"TargetFilename|startswith": "/System/Library/"}
    assert semantic_problem(detection, "file_event", "", named) is None


def test_a_wildcard_filter_that_matches_a_named_artifact_is_rejected() -> None:
    """The ClickFix replay filtered out /Users/*/Library/LaunchAgents/ while hunting the plist inside it."""
    named = ["launchctl bootstrap gui/501 /Users/<redacted>/Library/LaunchAgents/com.apple.softwareupdated.plist"]
    detection = {
        "selection": {"TargetFilename|endswith": "/com.apple.softwareupdated.plist"},
        "filter": {"TargetFilename|startswith": "/Users/*/Library/LaunchAgents/"},
        "condition": "selection and not filter",
    }
    assert "matches" in (semantic_problem(detection, "file_event", "", named) or "")
    detection["filter"] = {"TargetFilename|startswith": "/Users/*/Library/Application Support/"}
    assert semantic_problem(detection, "file_event", "", named) is None


def test_dual_use_destination_without_process_context_is_rejected() -> None:
    # Bare connection to S3 without process context fails
    detection = {
        "selection": {"DestinationHostname|endswith": ".amazonaws.com"},
        "condition": "selection",
    }
    problem = semantic_problem(detection, "network_connection", "Connects to S3")
    assert problem is not None
    assert "without process context" in problem

    # Bare connection to S3 IP fails
    detection_ip = {
        "selection": {"DestinationIp": "52.216.148.130"},
        "condition": "selection",
    }
    problem_ip = semantic_problem(detection_ip, "network_connection", "Connects to S3 IP")
    assert problem_ip is not None
    assert "without process context" in problem_ip


def test_dual_use_destination_with_process_binding_passes() -> None:
    # Bound to svchost_sync.exe
    detection = {
        "selection_dest": {"DestinationHostname|endswith": ".amazonaws.com"},
        "selection_process": {"Image|endswith": "\\svchost_sync.exe"},
        "condition": "selection_dest and selection_process",
    }
    assert semantic_problem(detection, "network_connection", "Sync to S3") is None


def test_dual_use_destination_with_browser_filter_passes() -> None:
    # Filter legitimate browsers
    detection = {
        "selection_dest": {"DestinationHostname|endswith": ".amazonaws.com"},
        "filter_browsers": {"Image|endswith": ["\\chrome.exe", "\\msedge.exe"]},
        "condition": "selection_dest and not filter_browsers",
    }
    assert semantic_problem(detection, "network_connection", "Sync to S3") is None


def test_repair_sigma_semantics_strips_all_modifier_on_scalar_ip() -> None:
    from hecate_agent.core.sigma_semantics import repair_sigma_semantics

    detection = {
        "selection": {"DestinationIp|all": ["194.26.29.112", "185.196.8.44"]},
        "condition": "selection",
    }
    repaired, actions = repair_sigma_semantics(detection)
    assert "DestinationIp" in repaired["selection"]
    assert "DestinationIp|all" not in repaired["selection"]
    assert repaired["selection"]["DestinationIp"] == ["194.26.29.112", "185.196.8.44"]
    assert len(actions) == 1
    assert "Stripped impossible '|all' modifier" in actions[0]
    assert semantic_problem(repaired, "network_connection") is None


def test_repair_sigma_semantics_strips_all_on_scalar_commandline_and_image() -> None:
    from hecate_agent.core.sigma_semantics import repair_sigma_semantics

    detection = {
        "selection": {
            "CommandLine|all": ["whoami.exe", "net.exe"],
            "Image|all": ["\\cmd.exe", "\\powershell.exe"],
        },
        "condition": "selection",
    }
    repaired, actions = repair_sigma_semantics(detection)
    assert "CommandLine" in repaired["selection"]
    assert "Image" in repaired["selection"]
    assert "CommandLine|all" not in repaired["selection"]
    assert "Image|all" not in repaired["selection"]
    assert len(actions) == 2


def test_repair_sigma_semantics_preserves_valid_contains_all() -> None:
    from hecate_agent.core.sigma_semantics import repair_sigma_semantics

    detection = {
        "selection": {"CommandLine|contains|all": ["certutil.exe", "-urlcache", "-f"]},
        "condition": "selection",
    }
    repaired, actions = repair_sigma_semantics(detection)
    assert "CommandLine|contains|all" in repaired["selection"]
    assert len(actions) == 0


def test_cloud_audit_and_identity_audit_categories_accepted() -> None:
    cloud_detection = {
        "selection": {
            "eventSource": "sts.amazonaws.com",
            "eventName": ["AssumeRole", "AssumeRoleWithSAML"],
        },
        "condition": "selection",
    }
    assert semantic_problem(cloud_detection, "cloud_audit") is None

    identity_detection = {
        "selection": {
            "eventName": "Consent to application",
            "appId": "00000003-0000-0000-c000-000000000000",
            "permissions|contains": ["Directory.ReadWrite.All"],
        },
        "condition": "selection",
    }
    assert semantic_problem(identity_detection, "identity_audit") is None


def test_a_shell_spawned_by_a_runtime_is_read_as_its_child() -> None:
    """H-0018 put Node-RED's /node in Image beside the /bin/sh -c it spawns."""
    from hecate_agent.core.sigma_semantics import repair_sigma_semantics

    detection = {
        "selection": {"Image|endswith": "/node", "CommandLine|contains": "/bin/sh -c"},
        "condition": "selection",
    }
    repaired, repairs = repair_sigma_semantics(detection)
    assert repaired["selection"] == {
        "ParentImage|endswith": "/node",
        "CommandLine|contains": "/bin/sh -c",
    }
    assert repairs


def test_a_runtime_rule_without_a_shell_child_is_left_alone() -> None:
    from hecate_agent.core.sigma_semantics import repair_sigma_semantics

    for detection in (
        {"selection": {"Image|endswith": "/node", "CommandLine|contains": "server.js"}, "condition": "selection"},
        {
            "a": {"Image|endswith": "/node"},
            "b": {"CommandLine|contains": "/bin/sh -c"},
            "condition": "a or b",
        },
    ):
        repaired, _ = repair_sigma_semantics(detection)
        assert "ParentImage|endswith" not in str(repaired)


def test_a_shell_spawn_rule_must_name_the_parent_as_parent_image() -> None:
    """H-0025's model rule matched the Node-RED process itself, not the shell it spawns."""
    detection = {
        "selection_node_red": {"Image|endswith": "/usr/bin/node-red"},
        "selection_shell": {"CommandLine|contains": "/bin/sh"},
        "condition": "selection_node_red and selection_shell",
    }
    problem = _problem("process_creation", detection, "Node-RED Runtime Spawning Shell for Command Execution")
    assert problem and "ParentImage" in problem

    fixed = {
        "selection": {"ParentImage|endswith": "/node", "ParentCommandLine|contains": "node-red", "Image|endswith": "/sh"},
        "condition": "selection",
    }
    assert _problem("process_creation", fixed, "Node-RED Runtime Spawning Shell") is None
    # Without a spawn claim, a program run with a shell script argument is left alone.
    assert _problem("process_creation", detection, "Node-RED started with a wrapper") is None
