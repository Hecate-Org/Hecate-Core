"""The single publish check over a hunt and its Sigma rules."""

from hecate_agent.core.publish_check import evaluate_hunt

_SHELL = """
title: Node starts a shell
description: the runtime spawns a shell
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /usr/bin/node
    CommandLine|contains: /bin/sh
  condition: selection
"""

_AUTH = """
title: Unauthenticated flow deploy
description: an unauthenticated client deploys a flow
logsource:
  category: webserver
  product: linux
detection:
  selection:
    cs-method: POST
    cs-uri-stem|contains: /flows
  condition: selection
"""

_CLEAN = """
title: Encoded PowerShell
description: powershell launched with an encoded command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
"""


def test_a_parent_child_rule_written_as_one_process_blocks() -> None:
    report = evaluate_hunt("", [("node shell", _SHELL)])
    assert report.verdict == "block"
    assert any(item.check == "semantics" and "ParentImage" in item.message for item in report.blocking())


def test_an_unauthenticated_claim_with_no_auth_field_blocks() -> None:
    report = evaluate_hunt("", [("deploy", _AUTH)])
    assert report.verdict == "block"
    assert any(item.check == "auth_claim" for item in report.blocking())


def test_a_specific_process_rule_passes() -> None:
    report = evaluate_hunt("No secrets here.", [("powershell", _CLEAN)])
    assert report.verdict == "pass"
    assert report.findings == []


def test_a_credential_in_the_hunt_blocks_even_without_rules() -> None:
    report = evaluate_hunt("token AKIAIOSFODNN7EXAMPLE in the notes", [])
    assert report.verdict == "block"
    assert report.blocking()[0].check == "credential"


def test_a_rule_fenced_in_the_hunt_is_checked_when_no_files_are_passed() -> None:
    report = evaluate_hunt(f"## Rule\n```yaml\n{_AUTH}```")
    assert any(item.check == "auth_claim" for item in report.blocking())


def test_a_rule_with_rejected_review_verdict_blocks() -> None:
    rejected_rule = """
title: Contradicted HTTP2 rule
description: attempts to detect network traffic despite guidance saying no signature exists
logsource:
  category: webserver
detection:
  selection:
    cs-method: GET
  condition: selection
hecate_review:
  verdict: reject
  unverified_contradiction: The rule attempts to detect exploitation through network signatures
"""
    report = evaluate_hunt("Some hunt text", [("contradicted_rule.yml", rejected_rule)])
    assert report.verdict == "block"
    blocking_checks = [item.check for item in report.blocking()]
    assert "rule_review_rejected" in blocking_checks
