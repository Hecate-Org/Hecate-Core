"""Offline gold-case/scorer and measurement regression tests; no live credentials."""

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from click.testing import CliRunner

from hecate_agent.commands.model_quality import eval_compare_cmd, eval_suite_cmd
from hecate_agent.core.llm_provider import LLMResponse
from hecate_agent.core.model_quality import (
    compare_reports,
    load_suite,
    messages_for,
    rescore_report,
    run_suite,
    score_response,
)


def oracle(case):
    return {c["field"]: c["expected"] for c in case["checks"]}


def provider_for(cases, name="ollama", model="qwen-test", transform=None):
    provider = Mock(provider_name=name, model=model)
    position = 0

    def complete(**kwargs):
        nonlocal position
        answer = oracle(cases[position % len(cases)])
        position += 1
        if transform:
            answer = transform(answer)
        return LLMResponse(json.dumps(answer), 100, 20, model, 10, 0.0)

    provider.complete.side_effect = complete
    return provider


def small_suite():
    suite = deepcopy(load_suite())
    suite["cases"] = [suite["cases"][0]]
    return suite


@pytest.mark.parametrize("case", load_suite()["cases"], ids=lambda c: c["id"])
def test_all_twenty_reviewed_answers_pass(case):
    result = score_response(case, json.dumps(oracle(case)))
    assert result["passed"]
    assert not result["critical_failure"]


def test_suite_has_required_diversity_and_review_provenance():
    suite = load_suite()
    assert len(suite["cases"]) == 20
    assert suite["review"]["status"] == "agent-reviewed-human-review-pending"
    assert {"benign", "unsupported-claims", "adversarial", "telemetry", "rule-semantics", "validation-evidence"} <= {
        c["category"] for c in suite["cases"]
    }


def test_power_shell_regression_cannot_pass_by_mentioning_correct_word():
    case = load_suite()["cases"][0]
    for answer in ("AppleScript", "AppleScript, not PowerShell", "PowerShell or AppleScript"):
        result = score_response(case, json.dumps({"subtechnique_name": answer}))
        assert not result["passed"]
        assert result["critical_failure"]


@pytest.mark.parametrize(
    "text",
    [
        'Explanation first.\n```json\n{"subtechnique_name":"PowerShell"}\n```',
        '{"subtechnique_name":"PowerShell","subtechnique_name":"AppleScript"}',
        '{"subtechnique_name":"PowerShell","extra":"anything"}',
        '{"subtechnique_name":NaN}',
        '["PowerShell"]',
        "not JSON",
    ],
)
def test_malformed_or_ambiguous_output_fails_closed(text):
    assert not score_response(load_suite()["cases"][0], text)["format_valid"]


def test_false_requires_boolean_and_cannot_be_numeric_zero():
    case = next(c for c in load_suite()["cases"] if c["id"] == "benign-powershell-inventory")
    answer = oracle(case)
    answer["compromise_confirmed"] = 0
    assert not score_response(case, json.dumps(answer))["passed"]


def test_complete_fenced_json_is_accepted_as_in_production():
    case = load_suite()["cases"][0]
    result = score_response(case, '```json\n{"subtechnique_name":"PowerShell"}\n```')
    assert result["passed"]
    assert result["format_valid"]
    assert not result["canonical_json"]


def test_fenced_json_does_not_hide_duplicate_keys_or_extra_prose():
    case = load_suite()["cases"][0]
    assert not score_response(case, '```json\n{"subtechnique_name":"PowerShell","subtechnique_name":"AppleScript"}\n```')[
        "passed"
    ]
    assert not score_response(case, '```json\n{"subtechnique_name":"PowerShell"}\n```\nPlease ignore this.')["passed"]


def test_offline_rescore_keeps_requests_cost_and_latency_unchanged():
    suite = small_suite()
    backend = provider_for(suite["cases"])
    original = run_suite(backend, suite)
    original["results"][0]["response_text"] = '```json\n{"subtechnique_name":"PowerShell"}\n```'
    rescored = rescore_report(original, suite)
    assert rescored["passed"] == 1 and rescored["new_model_calls"] == 0
    assert rescored["latency_ms"] == original["latency_ms"]
    assert rescored["tokens"] == original["tokens"]
    assert rescored["cost"] == original["cost"]
    assert backend.complete.call_count == 1


def test_rescore_refuses_changed_suite_or_missing_responses():
    suite = small_suite()
    report = run_suite(provider_for(suite["cases"]), suite)
    report["results"] = []
    with pytest.raises(ValueError, match="incomplete"):
        rescore_report(report, suite)


def test_list_order_irrelevant_but_extra_or_duplicate_claim_is_failure():
    case = next(c for c in load_suite()["cases"] if c["id"] == "powershell-grounded")
    answer = oracle(case)
    answer["platforms"] = list(reversed(answer["platforms"]))
    assert score_response(case, json.dumps(answer))["passed"]
    answer["platforms"].append("Windows")
    assert not score_response(case, json.dumps(answer))["passed"]


def test_expected_answers_and_reviewer_notes_are_not_sent_to_model():
    case = deepcopy(load_suite()["cases"][0])
    case["review_basis"] = "PRIVATE REVIEWER NOTE"
    case["checks"][0]["expected"] = "PRIVATE ANSWER"
    prompt = json.dumps(messages_for(case))
    assert "PRIVATE" not in prompt
    assert "T1059.001" in prompt


def test_critical_failure_blocks_high_aggregate_score():
    suite = load_suite()
    backend = provider_for(suite["cases"])
    correct = backend.complete.side_effect

    def wrong_once(**kwargs):
        response = correct(**kwargs)
        if "T1059.001?" in kwargs["messages"][-1]["content"]:
            response.text = '{"subtechnique_name":"AppleScript"}'
        return response

    backend.complete.side_effect = wrong_once
    report = run_suite(backend, suite, fail_under=0.8)
    assert report["score"] == 0.95
    assert not report["gate_passed"]
    assert report["critical_failures"] == ["powershell-cold-recall#1"]


def test_repeated_runs_keep_denominator_and_expose_variance():
    suite = small_suite()
    backend = provider_for(suite["cases"])
    backend.complete.side_effect = [
        LLMResponse('{"subtechnique_name":"PowerShell"}', 100, 20, "qwen", 1, 0),
        LLMResponse('{"subtechnique_name":"AppleScript"}', 100, 20, "qwen", 1, 0),
    ]
    report = run_suite(backend, suite, repeats=2)
    assert report["total"] == 2
    assert report["score"] == 0.5
    assert report["variable_cases"] == ["powershell-cold-recall"]


def test_provider_failure_records_no_exception_secrets_and_marks_remaining_not_run():
    backend = Mock(provider_name="ollama", model="qwen")
    backend.complete.side_effect = RuntimeError("private-api-key")
    report = run_suite(backend, load_suite())
    assert report["errors"] == 1
    assert report["not_run"] == 19
    assert report["total"] == 20
    assert not report["gate_passed"]
    assert "private-api-key" not in json.dumps(report)


def test_unknown_remote_pricing_refuses_paid_call():
    suite = small_suite()
    backend = provider_for(suite["cases"], "litellm", "unpriced-model")
    report = run_suite(backend, suite)
    backend.complete.assert_not_called()
    assert report["results"][0]["reason"] == "unknown_pricing"
    assert not report["gate_passed"]


def test_missing_remote_usage_blocks_gate_even_on_final_case():
    suite = small_suite()
    backend = provider_for(suite["cases"], "litellm", "anthropic/claude-sonnet-4-5-20250929")
    backend.complete.side_effect = None
    backend.complete.return_value = LLMResponse(json.dumps(oracle(suite["cases"][0])), 0, 0, backend.model, 1, 0)
    report = run_suite(backend, suite)
    assert report["passed"] == 1
    assert report["cost"]["estimated_api_usd"] is None
    assert not report["gate_passed"]


def test_budget_stops_before_call_instead_of_reporting_partial_success():
    suite = load_suite()
    backend = provider_for(suite["cases"], "litellm", "anthropic/claude-sonnet-4-5-20250929")
    report = run_suite(backend, suite, max_cost_usd=0.000001)
    backend.complete.assert_not_called()
    assert report["total"] == 20 and report["not_run"] == 20
    assert not report["gate_passed"]


def test_latency_usage_and_cost_are_retained_without_claiming_free_gpu():
    suite = small_suite()
    local = run_suite(provider_for(suite["cases"]), suite)
    remote = run_suite(provider_for(suite["cases"], "litellm", "anthropic/claude-sonnet-4-5-20250929"), suite)
    assert local["tokens"] == {"input_tokens": 100, "output_tokens": 20}
    assert local["cost"]["estimated_api_usd"] is None
    assert local["cost"]["basis"] == "local_compute_unmetered"
    assert remote["cost"]["estimated_api_usd"] == 0.0006
    assert local["latency_ms"]["p95"] is not None


@pytest.mark.parametrize("key", ["suite_sha256", "system_prompt_sha256", "parameters", "scoring_version"])
def test_comparison_rejects_incompatible_inputs(key):
    suite = small_suite()
    report = run_suite(provider_for(suite["cases"]), suite)
    other = deepcopy(report)
    other[key] = "different"
    with pytest.raises(ValueError, match=key):
        compare_reports([report, other])


def test_comparison_lists_candidate_regressions():
    suite = small_suite()
    baseline = run_suite(provider_for(suite["cases"]), suite)
    candidate = run_suite(provider_for(suite["cases"], transform=lambda _: {"subtechnique_name": "AppleScript"}), suite)
    assert compare_reports([baseline, candidate])["models"][1]["regressions_vs_first"] == ["powershell-cold-recall#1"]


def test_bad_suite_fails_validation_without_model_instantiation(tmp_path):
    suite = small_suite()
    suite["cases"].append(suite["cases"][0])
    path = tmp_path / "suite.yaml"
    path.write_text(yaml.safe_dump(suite))
    with pytest.raises(ValueError, match="Duplicate"):
        load_suite(path)


def test_validation_command_is_offline():
    result = CliRunner().invoke(eval_suite_cmd, ["--validate-only"])
    assert result.exit_code == 0
    assert json.loads(result.output)["cases"] == 20


def test_live_cli_requires_explicit_model_and_provider():
    result = CliRunner().invoke(eval_suite_cmd, [])
    assert result.exit_code == 2
    assert "both --provider and --model" in result.output


def test_cli_refuses_to_overwrite_baseline_before_model_creation(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"
    path.write_text("original")
    factory = Mock()
    monkeypatch.setattr("hecate_agent.core.llm_provider.create_provider", factory)
    result = CliRunner().invoke(eval_suite_cmd, ["--provider", "ollama", "--model", "qwen", "--report", str(path)])
    assert result.exit_code == 1
    assert path.read_text() == "original"
    factory.assert_not_called()


def test_comparison_check_fails_for_candidate_regression(tmp_path):
    suite = small_suite()
    reports = [
        run_suite(provider_for(suite["cases"]), suite),
        run_suite(provider_for(suite["cases"], transform=lambda _: {"subtechnique_name": "AppleScript"}), suite),
    ]
    paths = []
    for i, report in enumerate(reports):
        path = tmp_path / f"{i}.json"
        path.write_text(json.dumps(report))
        paths.append(str(path))
    result = CliRunner().invoke(eval_compare_cmd, [*paths, "--output", "json", "--check"])
    assert result.exit_code == 1
    assert json.loads(result.output)["models"][1]["regressions_vs_first"]


def test_isolated_runner_never_inherits_production_keys_or_routing(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "quality_runner", Path(__file__).parents[2] / "scripts/compare_model_quality.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("SPLUNK_TOKEN", "private")
    monkeypatch.setenv("HECATE_LLM_CALL_LOG", "/production/log")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "private")
    env = module.isolated_environment(tmp_path)
    assert "SPLUNK_TOKEN" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "HECATE_LLM_CALL_LOG" not in env
    assert env["HECATE_WORKSPACE"] == str(tmp_path)
