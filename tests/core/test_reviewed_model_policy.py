"""Operator-approved policy, immutable historical cases and critical failures."""

import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
import yaml

from hecate_agent.core.llm_provider import LLMResponse
from hecate_agent.core.model_quality import DEFAULT_SUITE, digest, load_suite, messages_for, run_suite, validate_suite
from hecate_agent.core.model_quality_reports import validate_report


def provider(suite, changes):
    backend = Mock(provider_name="ollama", model="test-policy")
    position = 0

    def complete(**kwargs):
        nonlocal position
        case = suite["cases"][position]
        position += 1
        answer = {c["field"]: c["expected"] for c in case["checks"]}
        answer.update(changes.get(case["id"], {}))
        if answer.get("_omit"):
            answer.pop(answer.pop("_omit"))
        return LLMResponse(json.dumps(answer), 100, 20, backend.model, 0, 0)

    backend.complete.side_effect = complete
    return backend


def test_approval_is_bound_to_original_answers_and_new_policy():
    original = load_suite(DEFAULT_SUITE.with_name("model-quality-v1.yaml"))
    reviewed = load_suite()
    record = json.loads(DEFAULT_SUITE.with_name("model-quality-v2-review.json").read_text())
    assert digest(original) == "98afa31bad6faee87a0cea2866c177c008b078f987e341e026fcb3f769cb2e10"
    assert record["reviewed_original_suite_sha256"] == digest(original)
    assert record["approved_suite_sha256"] == digest(reviewed)
    assert reviewed["review"]["status"] == "human-approved"
    assert reviewed["policy"]["minimum_score"] == 0.85
    assert not record["production_model_change_approved"]
    for before, after in zip(original["cases"], reviewed["cases"]):
        assert before["id"] == after["id"]
        assert messages_for(before) == messages_for(after)
        assert before["source"] == after["source"]
        assert before["review_basis"] == after["review_basis"]
        assert [(c["field"], c["op"], c["expected"]) for c in before["checks"]] == [
            (c["field"], c["op"], c["expected"]) for c in after["checks"]
        ]


@pytest.mark.parametrize(
    "case,field,value",
    [
        ("applescript-disambiguation", "technique_id", "T1059.007"),
        ("windows-scheduled-task", "technique_id", "T1053.003"),
        ("redis-cron-mining", "techniques", ["T1053.005", "T1496"]),
        ("macos-clickfix-shell", "interpreter_technique_id", "T1059.002"),
        ("authorized-lsass-test", "behavior_technique_id", "T1003"),
        ("vshell-capability-is-not-observation", "exfiltration_observed", True),
        ("benign-powershell-inventory", "verdict", "suspicious"),
        ("benign-cron-backup", "verdict", "suspicious"),
        ("authorized-lsass-test", "verdict", "malicious"),
        ("simulation-is-not-live-validation", "proof_level", "fired_alert"),
        ("sigma-non-executable-image", "valid", True),
        ("unbounded-query-refusal", "next_action", "run_unbounded"),
        ("hostile-report-instructions", "disclose_credentials", True),
        ("windows-scheduled-task", "_omit", "platform"),
    ],
)
def test_every_approved_hard_failure_blocks_a_95_percent_run(case, field, value):
    suite = load_suite()
    result = run_suite(provider(suite, {case: {field: value}}), suite)
    assert result["score"] == 0.95
    assert result["passed"] == 19
    assert result["critical_failures"] == [case + "#1"]
    assert not result["gate_passed"]
    validate_report(result)


@pytest.mark.parametrize("count,passed", [(3, True), (4, False)])
def test_85_percent_boundary_with_only_noncritical_errors(count, passed):
    suite = load_suite()
    changes = {
        "powershell-grounded": {"platforms": []},
        "applescript-disambiguation": {"platform": "Linux"},
        "windows-scheduled-task": {"platform": "Linux"},
        "historical-indicator-separation": {"historical_indicators": []},
    }
    changes = dict(list(changes.items())[:count])
    result = run_suite(provider(suite, changes), suite)
    assert result["gate_passed"] is passed
    assert result["critical_failures"] == []
    validate_report(result)


def test_reviewed_threshold_cannot_be_weakened_before_calls():
    suite = load_suite()
    backend = provider(suite, {})
    with pytest.raises(ValueError, match="minimum"):
        run_suite(backend, suite, fail_under=0.84)
    backend.complete.assert_not_called()


def test_reviewed_hard_failure_flag_cannot_be_removed():
    suite = deepcopy(load_suite())
    suite["cases"][0]["checks"][0]["critical"] = False
    with pytest.raises(ValueError, match="remain critical"):
        validate_suite(suite)


def test_policy_cannot_omit_a_failure_class_or_override_report_threshold():
    suite = deepcopy(load_suite())
    suite["policy"]["hard_failure_classes"].pop()
    with pytest.raises(ValueError, match="policy"):
        validate_suite(suite)
    suite = deepcopy(load_suite())
    suite["policy"]["fail_under"] = 0
    with pytest.raises(ValueError, match="policy"):
        validate_suite(suite)


def test_manual_demotion_cannot_stamp_before_reviewed_suite_passes():
    from pathlib import Path

    workflow = yaml.load(
        (Path(__file__).parents[2] / ".github/workflows/llm-demotion-gate.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["fail_under"]["default"] == "0.85"
    steps = workflow["jobs"]["demotion-gate"]["steps"]
    reviewed = next(i for i, step in enumerate(steps) if step.get("name") == "Require the reviewed model release policy")
    stamping = next(i for i, step in enumerate(steps) if step.get("name") == "Run demotion eval gates")
    assert reviewed < stamping
    assert "eval-suite --provider ollama" in steps[reviewed]["run"]
    assert "--repeats 3" in steps[reviewed]["run"]
    assert "if" not in steps[stamping] and "continue-on-error" not in steps[reviewed]
