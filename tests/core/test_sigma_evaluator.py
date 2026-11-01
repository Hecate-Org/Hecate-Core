"""Unit tests for the in-process Sigma Rule Evaluator (Milestone 1)."""

from pathlib import Path

import pytest

from hecate_agent.core.sigma_evaluator import (
    ConditionEvaluator,
    SigmaEvaluator,
    get_event_field,
)


def test_get_event_field_direct_and_case_insensitive() -> None:
    event = {"Image": "C:\\Windows\\System32\\cmd.exe", "commandline": "whoami"}
    found, val = get_event_field(event, "Image")
    assert found and val == "C:\\Windows\\System32\\cmd.exe"

    found, val = get_event_field(event, "image")
    assert found and val == "C:\\Windows\\System32\\cmd.exe"

    found, val = get_event_field(event, "CommandLine")
    assert found and val == "whoami"


def test_get_event_field_aliases_and_nested() -> None:
    event = {
        "process": {
            "name": "powershell.exe",
            "cmd_line": "powershell -enc AAAA",
            "parent_process": {"name": "explorer.exe"},
        },
        "dst_endpoint": {"ip": "192.168.1.50", "port": 443},
    }
    # Alias Image -> process.name
    found, val = get_event_field(event, "Image")
    assert found and val == "powershell.exe"

    # Alias CommandLine -> process.cmd_line
    found, val = get_event_field(event, "CommandLine")
    assert found and val == "powershell -enc AAAA"

    # Alias ParentImage -> process.parent_process.name
    found, val = get_event_field(event, "ParentImage")
    assert found and val == "explorer.exe"

    # Alias DestinationIp -> dst_endpoint.ip
    found, val = get_event_field(event, "DestinationIp")
    assert found and val == "192.168.1.50"


def test_condition_evaluator_boolean_logic() -> None:
    blocks = {
        "sel_1": True,
        "sel_2": False,
        "filt_1": False,
        "filt_2": True,
    }
    assert ConditionEvaluator("sel_1", blocks).evaluate() is True
    assert ConditionEvaluator("sel_2", blocks).evaluate() is False
    assert ConditionEvaluator("sel_1 and not filt_1", blocks).evaluate() is True
    assert ConditionEvaluator("sel_1 and not filt_2", blocks).evaluate() is False
    assert ConditionEvaluator("sel_1 or sel_2", blocks).evaluate() is True
    assert ConditionEvaluator("(sel_1 and sel_2) or not filt_1", blocks).evaluate() is True


def test_condition_evaluator_quantifiers() -> None:
    blocks = {
        "selection_a": True,
        "selection_b": False,
        "selection_c": True,
        "filter_noise": False,
    }
    assert ConditionEvaluator("1 of selection_*", blocks).evaluate() is True
    assert ConditionEvaluator("2 of selection_*", blocks).evaluate() is True
    assert ConditionEvaluator("3 of selection_*", blocks).evaluate() is False
    assert ConditionEvaluator("all of selection_*", blocks).evaluate() is False
    assert ConditionEvaluator("any of selection_* and not filter_noise", blocks).evaluate() is True
    assert ConditionEvaluator("1 of them", blocks).evaluate() is True
    assert ConditionEvaluator("1 of (selection_b, filter_noise)", blocks).evaluate() is False
    assert ConditionEvaluator("1 of (selection_a, selection_b)", blocks).evaluate() is True


def test_evaluator_basic_selection() -> None:
    rule_yaml = """
title: Test Basic Selection
logsource:
    category: process_creation
detection:
    selection:
        Image: 'C:\\Windows\\System32\\cmd.exe'
        CommandLine: 'cmd.exe /c whoami'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    matching_event = {
        "category": "process_creation",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    }
    non_matching_event = {
        "category": "process_creation",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir",
    }

    assert evaluator.matches(matching_event) is True
    assert evaluator.matches(non_matching_event) is False


def test_evaluator_modifiers() -> None:
    rule_yaml = """
title: Modifiers Test
logsource:
    category: process_creation
detection:
    sel_contains:
        CommandLine|contains: 'Invoke-Mimikatz'
    sel_starts:
        Image|startswith: 'C:\\Windows\\'
    sel_ends:
        Image|endswith: '\\powershell.exe'
    condition: 1 of sel_*
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev1 = {"category": "process_creation", "CommandLine": "powershell.exe -ep bypass Invoke-Mimikatz.ps1"}
    ev2 = {"category": "process_creation", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
    ev3 = {"category": "process_creation", "CommandLine": "calc.exe", "Image": "C:\\calc.exe"}

    assert evaluator.matches(ev1) is True
    assert evaluator.matches(ev2) is True
    assert evaluator.matches(ev3) is False


def test_evaluator_contains_all() -> None:
    rule_yaml = """
title: Contains All Test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '-enc'
            - 'AAAA'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    match_ev = {"CommandLine": "powershell.exe -enc AAAA123"}
    fail_ev = {"CommandLine": "powershell.exe -enc BBBB123"}  # missing AAAA

    assert evaluator.matches(match_ev) is True
    assert evaluator.matches(fail_ev) is False


def test_evaluator_cidr_and_regex() -> None:
    rule_yaml = """
title: CIDR and Regex Test
logsource:
    category: network_connection
detection:
    sel_ip:
        DestinationIp|cidr: '10.0.0.0/8'
    sel_port:
        DestinationPort|gt: 1024
    sel_host:
        DestinationHostname|re: '.*\\.evil\\.(com|org)$'
    condition: sel_ip and sel_port and sel_host
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev_pass = {
        "category": "network_connection",
        "DestinationIp": "10.50.1.20",
        "DestinationPort": 8080,
        "DestinationHostname": "c2.evil.com",
    }
    ev_fail_ip = {
        "category": "network_connection",
        "DestinationIp": "192.168.1.1",
        "DestinationPort": 8080,
        "DestinationHostname": "c2.evil.com",
    }
    ev_fail_port = {
        "category": "network_connection",
        "DestinationIp": "10.50.1.20",
        "DestinationPort": 80,  # not > 1024
        "DestinationHostname": "c2.evil.com",
    }

    assert evaluator.matches(ev_pass) is True
    assert evaluator.matches(ev_fail_ip) is False
    assert evaluator.matches(ev_fail_port) is False


def test_evaluator_numeric_comparisons() -> None:
    rule_yaml = """
title: Numeric Comparisons
detection:
    sel_gt:
        Count|gt: 10
    sel_lte:
        Count|lte: 20
    condition: sel_gt and sel_lte
"""
    evaluator = SigmaEvaluator(rule_yaml)
    assert evaluator.matches({"Count": 15}) is True
    assert evaluator.matches({"Count": 10}) is False  # not gt 10
    assert evaluator.matches({"Count": 20}) is True  # lte 20
    assert evaluator.matches({"Count": 21}) is False  # not lte 20


def test_evaluator_windash_modifier() -> None:
    rule_yaml = """
title: Windash Flag Test
detection:
    selection:
        CommandLine|contains|windash: '/c whoami'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev_slash = {"CommandLine": "cmd.exe /c whoami"}
    ev_dash = {"CommandLine": "cmd.exe -c whoami"}

    assert evaluator.matches(ev_slash) is True
    assert evaluator.matches(ev_dash) is True


def test_evaluator_wildcard_matching() -> None:
    rule_yaml = """
title: Wildcard Glob Test
detection:
    selection:
        Image: '*\\cmd.exe'
        CommandLine: '* /c *'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev_match = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c calc.exe"}
    ev_mismatch = {"Image": "C:\\Windows\\System32\\cmd.exe.bak", "CommandLine": "cmd.exe /k calc.exe"}

    assert evaluator.matches(ev_match) is True
    assert evaluator.matches(ev_mismatch) is False


def test_evaluator_list_of_hashes_in_event() -> None:
    rule_yaml = """
title: Hash Match
logsource:
    category: process_creation
detection:
    selection:
        Hashes|contains: 'SHA256=c25d4412f7f93e7de5b2aaf41747175d94cffd983ca20efbd0efcdd718b58c4d'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev = {
        "category": "process_creation",
        "Hashes": [
            "MD5=a7cc7e3cdd2f0f9210044911a483fa5d",
            "SHA256=c25d4412f7f93e7de5b2aaf41747175d94cffd983ca20efbd0efcdd718b58c4d",
        ],
    }
    assert evaluator.matches(ev) is True


def test_evaluator_filter_negation() -> None:
    rule_yaml = """
title: Filter Negation
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    filter_admin:
        User: 'NT AUTHORITY\\SYSTEM'
    condition: selection and not filter_admin
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev_user = {"category": "process_creation", "CommandLine": "whoami", "User": "attacker"}
    ev_system = {"category": "process_creation", "CommandLine": "whoami", "User": "NT AUTHORITY\\SYSTEM"}

    assert evaluator.matches(ev_user) is True
    assert evaluator.matches(ev_system) is False


def test_evaluator_list_of_mappings_or() -> None:
    rule_yaml = """
title: List of Mappings OR Test
logsource:
    category: process_creation
detection:
    selection:
        - Image|endswith: '\\cmd.exe'
          CommandLine|contains: 'whoami'
        - Image|endswith: '\\powershell.exe'
          CommandLine|contains: 'whoami'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev1 = {"category": "process_creation", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}
    ev2 = {
        "category": "process_creation",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell whoami",
    }
    ev3 = {"category": "process_creation", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c dir"}

    assert evaluator.matches(ev1) is True
    assert evaluator.matches(ev2) is True
    assert evaluator.matches(ev3) is False


def test_evaluator_null_value_handling() -> None:
    rule_yaml = """
title: Null Check
detection:
    selection:
        ParentImage: null
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    ev_null = {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": None}
    ev_missing = {"Image": "C:\\Windows\\System32\\cmd.exe"}
    ev_present = {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "explorer.exe"}

    assert evaluator.matches(ev_null) is True
    assert evaluator.matches(ev_missing) is True
    assert evaluator.matches(ev_present) is False


def test_evaluator_pysigma_rule_object() -> None:
    from sigma.collection import SigmaCollection

    rule_yaml = """
title: PySigma Rule Object Test
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    coll = SigmaCollection.from_yaml(rule_yaml)
    pysigma_rule = coll.rules[0]

    evaluator = SigmaEvaluator(pysigma_rule)
    assert evaluator.matches({"category": "process_creation", "Image": "C:\\Windows\\System32\\cmd.exe"}) is True
    assert evaluator.matches({"category": "process_creation", "Image": "C:\\Windows\\System32\\calc.exe"}) is False


def test_evaluator_real_vshell_ioc_rule() -> None:
    rule_path = Path(
        "tests/fixtures/gold/vshell-fake-resume/queries/H-0618/network_connection__connection_to_an_address_or_host_named_in_the_source_intelli.yml"
    )
    assert rule_path.exists(), f"Query fixture missing at {rule_path}"
    rule_text = rule_path.read_text()
    evaluator = SigmaEvaluator(rule_text)

    # Ground truth intrusion events from threat report
    intrusions = [
        {"category": "network_connection", "DestinationIp": "38.207.178.192", "DestinationPort": 443},
        {"category": "network_connection", "DestinationHostname": "pan.qlam.cc", "DestinationPort": 80},
        {"category": "network_connection", "DestinationHostname": "unrelated.evil.com", "DestinationPort": 80},  # missed
    ]
    # Ground truth baseline events from benign activity
    baselines = [
        {"category": "network_connection", "DestinationIp": "8.8.8.8", "DestinationPort": 53},
        {"category": "network_connection", "DestinationHostname": "microsoft.com", "DestinationPort": 443},
    ]

    report = evaluator.evaluate_stream(intrusions, baselines)
    assert report.true_positives == 2
    assert report.false_positives == 0
    assert report.false_negatives == 1
    assert report.true_negatives == 2
    assert report.precision == 1.0
    assert pytest.approx(report.recall, 0.01) == 0.67
    assert report.is_clean is True


def test_evaluator_logsource_category_aliasing() -> None:
    rule_yaml = """
title: Category Check
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: 'curl'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)

    # Linux auditd/OCSF category is process_activity
    ev_alias = {"category": "process_activity", "Image": "/usr/bin/curl"}
    ev_wrong = {"category": "network_connection", "Image": "/usr/bin/curl"}

    assert evaluator.matches(ev_alias) is True
    assert evaluator.matches(ev_wrong) is False


def test_evaluation_stream_confusion_matrix_perfect() -> None:
    rule_yaml = """
title: Detection of Fake Resume Stealer
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'fake_resume_stager.exe'
    condition: selection
"""
    intrusion_events = [
        {"category": "process_creation", "CommandLine": "cmd.exe /c fake_resume_stager.exe --install"},
        {"category": "process_creation", "CommandLine": "powershell.exe ./fake_resume_stager.exe"},
    ]
    baseline_events = [
        {"category": "process_creation", "CommandLine": "cmd.exe /c whoami"},
        {"category": "process_creation", "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
        {"category": "process_creation", "CommandLine": "notepad.exe normal.txt"},
    ]

    report = SigmaEvaluator.evaluate_rule(rule_yaml, intrusion_events, baseline_events)

    assert report.total_events == 5
    assert report.intrusion_events_count == 2
    assert report.baseline_events_count == 3
    assert report.true_positives == 2
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.true_negatives == 3
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1_score == 1.0
    assert report.is_perfect is True
    assert report.is_clean is True
    assert report.fired_on_intrusion is True
    assert len(report.triggering_events) == 2
    assert len(report.false_positive_events) == 0
    assert len(report.missed_events) == 0
    assert "PERFECT" in report.summary()


def test_evaluation_stream_confusion_matrix_with_fp_and_fn() -> None:
    rule_yaml = """
title: Overly Broad Rule
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'svchost'
    condition: selection
"""
    # 2 intrusion events, one contains svchost, one doesn't
    intrusion_events = [
        {"category": "process_creation", "CommandLine": "malware.exe -target svchost.exe"},
        {"category": "process_creation", "CommandLine": "malware.exe -target lsass.exe"},  # missed!
    ]
    # 2 baseline events, one is normal svchost (false positive!), one is explorer
    baseline_events = [
        {"category": "process_creation", "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},  # FP!
        {"category": "process_creation", "CommandLine": "C:\\Windows\\explorer.exe"},  # TN
    ]

    report = SigmaEvaluator.evaluate_rule(rule_yaml, intrusion_events, baseline_events)

    assert report.true_positives == 1
    assert report.false_positives == 1
    assert report.false_negatives == 1
    assert report.true_negatives == 1

    # Precision: 1 TP / (1 TP + 1 FP) = 0.5 (50%)
    assert report.precision == 0.5
    # Recall: 1 TP / (1 TP + 1 FN) = 0.5 (50%)
    assert report.recall == 0.5
    assert report.f1_score == 0.5
    assert report.is_perfect is False
    assert report.is_clean is False
    assert len(report.false_positive_events) == 1
    assert len(report.missed_events) == 1
    assert "NOISY" in report.summary()


def test_evaluator_evaluate_with_inline_labels() -> None:
    rule_yaml = """
title: Inline Label Evaluation
detection:
    selection:
        Image|endswith: 'malware.exe'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)
    events = [
        {"Image": "C:\\temp\\malware.exe", "_label": "intrusion"},
        {"Image": "C:\\temp\\benign.exe", "_label": "baseline"},
        {"Image": "C:\\temp\\other_threat.bat", "is_intrusion": True},  # missed!
    ]
    report = evaluator.evaluate(events)
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.false_negatives == 1
    assert report.true_negatives == 1


def test_evaluator_diagnostics_trace() -> None:
    rule_yaml = """
title: Diagnostic Trace Test
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'evil'
    condition: selection
"""
    evaluator = SigmaEvaluator(rule_yaml)
    ev_missed = {
        "category": "process_creation",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "evil script.bat",
    }
    diag = evaluator.evaluate_event(ev_missed, is_intrusion=True)
    assert diag.matched is False
    assert diag.logsource_matched is True
    assert diag.block_results["selection"] is False
    assert any("Image" in r for r in diag.reasons)


@pytest.mark.parametrize("image,expected", [("/bin/whoami", True), ("/bin/id", True), ("/bin/ls", False)])
def test_condition_list_evaluates_every_alternative(image, expected):
    rule = {"detection": {"first": {"Image": "/bin/whoami"}, "second": {"Image": "/bin/id"}, "condition": ["first", "second"]}}
    assert SigmaEvaluator(rule).matches({"Image": image}) is expected


@pytest.mark.parametrize(
    "modifier,pattern,event,expected",
    [
        ("contains", "curl*example.com", "sh -c curl https://example.com/path", True),
        ("contains", "curl*example.com", "wget https://example.com", False),
        ("startswith", "curl?https*", "curl https://example.com", True),
        ("startswith", "curl*", "sh curl https://example.com", False),
        ("endswith", "*example.?om", "curl https://example.com", True),
        ("endswith", "example.com", "curl https://example.com/path", False),
        ("contains", r"literal\*value", "literal*value", True),
        ("contains", r"literal\*value", "literalOTHERvalue", False),
        ("endswith", r"\cmd.exe", r"C:\Windows\cmd.exe", True),
    ],
)
def test_string_modifiers_preserve_sigma_wildcards(modifier, pattern, event, expected):
    rule = {"detection": {"selection": {f"CommandLine|{modifier}": pattern}, "condition": "selection"}}
    assert SigmaEvaluator(rule).matches({"CommandLine": event}) is expected


def test_non_null_needle_never_matches_none_or_missing_field():
    rule_wildcard = {"detection": {"selection": {"CommandLine": "*"}, "condition": "selection"}}
    rule_none_str = {"detection": {"selection": {"CommandLine|contains": "None"}, "condition": "selection"}}

    ev_none = {"CommandLine": None}
    ev_missing = {"OtherField": "value"}
    ev_real = {"CommandLine": "whoami"}

    assert SigmaEvaluator(rule_wildcard).matches(ev_none) is False
    assert SigmaEvaluator(rule_wildcard).matches(ev_missing) is False
    assert SigmaEvaluator(rule_wildcard).matches(ev_real) is True

    assert SigmaEvaluator(rule_none_str).matches(ev_none) is False
    assert SigmaEvaluator(rule_none_str).matches(ev_missing) is False


def test_dict_event_value_matches_on_values_not_repr_syntax():
    rule_user = {"detection": {"selection": {"User": "admin"}, "condition": "selection"}}
    rule_syntax = {"detection": {"selection": {"User|contains": "TargetUserName"}, "condition": "selection"}}

    ev_dict = {"User": {"TargetUserName": "admin", "Domain": "CORP"}}

    # Value match should succeed
    assert SigmaEvaluator(rule_user).matches(ev_dict) is True
    # Key / dictionary syntax repr match should fail
    assert SigmaEvaluator(rule_syntax).matches(ev_dict) is False

