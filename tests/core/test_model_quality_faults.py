"""Fault injection and adversarial input regressions; all providers are local fakes."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from hecate_agent.commands.model_quality import eval_compare_cmd, eval_suite_cmd
from hecate_agent.core.llm_provider import LLMResponse
from hecate_agent.core.model_quality import compare_reports, load_suite, run_suite, score_response
from hecate_agent.core.model_quality_io import MAX_REPORT_BYTES, MAX_RESPONSE_BYTES, load_report, reserve_report
from hecate_agent.core.model_quality_reports import validate_report


def backend():
    provider = Mock(provider_name="ollama", model="qwen", think=False, num_ctx=16384)
    provider.complete.return_value = LLMResponse('{"subtechnique_name":"PowerShell"}', 100, 20, "qwen", 0, 0)
    return provider


def short_suite():
    suite = load_suite()
    suite["cases"] = suite["cases"][:1]
    return suite


@pytest.mark.parametrize("text", [None, 1, True, [], {}, b"{}", " " * (MAX_RESPONSE_BYTES + 1), "\ud800"])
def test_non_text_invalid_unicode_and_oversized_outputs_fail_without_crashing(text):
    assert not score_response(short_suite()["cases"][0], text)["passed"]


@pytest.mark.parametrize(
    "expected,actual", [({"flag": False}, {"flag": 0}), ([False], [0]), ({"nested": [1]}, {"nested": [1.0]})]
)
def test_recursive_equality_preserves_types(expected, actual):
    case = short_suite()["cases"][0]
    case["checks"] = [{"field": "value", "op": "equals", "expected": expected}]
    assert not score_response(case, json.dumps({"value": actual}))["passed"]


@pytest.mark.parametrize(
    "payload", ['{"subtechnique_name":1e999}', "[" * 4000 + "]" * 4000, "```json\n{}\n```\n```json\n{}\n```"]
)
def test_exponent_overflow_deep_json_and_multiple_fences_are_rejected(payload):
    assert not score_response(short_suite()["cases"][0], payload)["format_valid"]


@pytest.mark.parametrize("mutation", ["duplicate", "drop", "gate", "score", "cost", "tokens", "duration", "category"])
def test_inconsistent_reports_cannot_approve_a_candidate(mutation):
    original = run_suite(backend(), short_suite())
    modified = deepcopy(original)
    if mutation == "duplicate":
        modified["results"].append(deepcopy(modified["results"][0]))
    elif mutation == "drop":
        modified["results"] = []
    elif mutation == "gate":
        modified["gate_passed"] = False
    elif mutation == "score":
        modified["score"] = 0.1
    elif mutation == "cost":
        modified["cost"]["known_api_subtotal_usd"] = 100
    elif mutation == "tokens":
        modified["tokens"]["input_tokens"] = 0
    elif mutation == "duration":
        modified["latency_ms"]["total"] += 1
    else:
        modified["results"][0]["category"] = "wrong"
    with pytest.raises(ValueError):
        compare_reports([original, modified])


def test_failed_baseline_does_not_block_a_better_passing_candidate(tmp_path):
    fake = backend()
    fake.complete.return_value.text = '{"subtechnique_name":"AppleScript"}'
    baseline = run_suite(fake, short_suite())
    candidate = run_suite(backend(), short_suite())
    paths = []
    for index, report in enumerate((baseline, candidate)):
        path = tmp_path / f"{index}.json"
        path.write_text(json.dumps(report))
        paths.append(str(path))
    result = CliRunner().invoke(eval_compare_cmd, [*paths, "--check", "--output", "json"])
    assert result.exit_code == 0
    assert not json.loads(result.output)["models"][0]["gate_passed"]


def test_repeated_call_coverage_cannot_be_replaced_by_duplicate_first_result():
    original = run_suite(backend(), short_suite(), repeats=2)
    modified = deepcopy(original)
    modified["results"][1] = deepcopy(modified["results"][0])
    with pytest.raises(ValueError, match="Duplicate"):
        compare_reports([original, modified])


@pytest.mark.parametrize(
    "text", ["schema: wrong\nschema: hecate-model-quality/1", "a: &a [*a]", "a: " + "[" * 1000 + "0" + "]" * 1000]
)
def test_duplicate_yaml_keys_recursive_aliases_and_deep_yaml_fail(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_suite(path)


@pytest.mark.parametrize("field,value", [("input_tokens", -1), ("output_tokens", True), ("input_tokens", float("nan"))])
def test_invalid_usage_stops_calls_and_never_appears_as_valid_metrics(field, value):
    fake = backend()
    setattr(fake.complete.return_value, field, value)
    report = run_suite(fake, load_suite())
    assert fake.complete.call_count == 1
    assert report["errors"] == 1 and report["not_run"] == 19
    assert not report["gate_passed"]
    json.dumps(report, allow_nan=False)
    validate_report(report)


def test_paid_usage_survives_an_oversized_bad_answer():
    fake = backend()
    fake.provider_name, fake.model = "litellm", "anthropic/claude-sonnet-4-5-20250929"
    fake.complete.return_value.model = fake.model
    fake.complete.return_value.text = "x" * (MAX_RESPONSE_BYTES + 1)
    report = run_suite(fake, load_suite())
    assert fake.complete.call_count == 1 and not report["gate_passed"]
    assert report["cost"]["known_api_subtotal_usd"] == 0.0006
    assert report["tokens"] == {"input_tokens": 100, "output_tokens": 20}
    validate_report(report)


def test_actual_budget_overrun_stops_subsequent_calls_and_is_recorded():
    fake = backend()
    fake.provider_name, fake.model = "litellm", "anthropic/claude-sonnet-4-5-20250929"
    fake.complete.return_value.model = fake.model
    fake.complete.return_value.input_tokens = 1_000_000
    report = run_suite(fake, load_suite(), max_cost_usd=0.05)
    assert fake.complete.call_count == 1
    assert report["cost"]["known_api_subtotal_usd"] > 0.05
    assert not report["gate_passed"] and report["not_run"] == 19


def test_invalid_report_parent_is_rejected_before_provider_creation(tmp_path, monkeypatch):
    factory = Mock()
    monkeypatch.setattr("hecate_agent.core.llm_provider.create_provider", factory)
    result = CliRunner().invoke(
        eval_suite_cmd, ["--provider", "ollama", "--model", "qwen", "--report", str(tmp_path / "missing" / "report.json")]
    )
    assert result.exit_code == 1
    factory.assert_not_called()


def test_concurrent_report_reservation_has_one_winner(tmp_path):
    path = tmp_path / "shared.json"
    barrier = threading.Barrier(8)

    def reserve(_):
        barrier.wait()
        try:
            with reserve_report(path):
                return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(8))) == 1
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_ctrl_c_keeps_failed_report_and_durable_checkpoints(tmp_path, monkeypatch):
    fake = backend()
    fake.complete.side_effect = [fake.complete.return_value, KeyboardInterrupt()]
    monkeypatch.setattr("hecate_agent.core.llm_provider.create_provider", lambda _: fake)
    path = tmp_path / "interrupted.json"
    result = CliRunner().invoke(eval_suite_cmd, ["--provider", "ollama", "--model", "qwen", "--report", str(path)])
    assert result.exit_code == 130
    report = load_report(path)
    assert report["interrupted"] and not report["gate_passed"]
    assert report["scored"] == 1 and report["not_run"] == 18
    validate_report(report)
    assert len(path.with_name(path.name + ".progress.jsonl").read_text().splitlines()) == 21


@pytest.mark.parametrize("option,value", [("--repeats", "2"), ("--fail-under", "0.5")])
def test_rescoring_does_not_silently_ignore_live_parameter_overrides(tmp_path, option, value):
    path = tmp_path / "saved.json"
    path.write_text(json.dumps(run_suite(backend(), short_suite())))
    result = CliRunner().invoke(eval_suite_cmd, ["--rescore", str(path), option, value])
    assert result.exit_code == 2


def test_report_loader_rejects_duplicate_fields_and_nonfinite_numbers(tmp_path):
    path = tmp_path / "bad.json"
    for text in ('{"gate_passed":false,"gate_passed":true}', '{"score":NaN}', '{"score":1e999}'):
        path.write_text(text)
        with pytest.raises(ValueError):
            load_report(path)


def test_report_size_limit_is_checked_before_reading_a_large_file(tmp_path):
    path = tmp_path / "large.json"
    with path.open("wb") as handle:
        handle.truncate(MAX_REPORT_BYTES + 1)
    with pytest.raises(ValueError):
        load_report(path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes only")
def test_fifo_is_rejected_without_blocking(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError):
        load_report(path)


def test_context_limit_is_checked_before_model_calls():
    fake = backend()
    fake.num_ctx = 600
    with pytest.raises(ValueError, match="context"):
        run_suite(fake, short_suite())
    fake.complete.assert_not_called()


def test_total_response_storage_limit_stops_requests(monkeypatch):
    fake = backend()
    monkeypatch.setattr(
        "hecate_agent.core.model_quality.MAX_TOTAL_RESPONSE_BYTES", len(json.dumps(fake.complete.return_value.text)) * 2 - 1
    )
    report = run_suite(fake, load_suite())
    assert fake.complete.call_count == 2
    assert report["not_run"] == 18 and not report["gate_passed"]


def test_storage_limit_accounts_for_json_escape_expansion(monkeypatch):
    fake = backend()
    fake.complete.return_value.text = "\x01" * 100
    monkeypatch.setattr("hecate_agent.core.model_quality.MAX_TOTAL_RESPONSE_BYTES", 500)
    report = run_suite(fake, load_suite())
    assert fake.complete.call_count == 1
    assert report["results"][0]["measurement_error"] == "invalid_or_oversized_response"


def test_progress_write_failure_stops_further_model_calls():
    fake = backend()
    with pytest.raises(OSError):
        run_suite(fake, load_suite(), progress=Mock(side_effect=OSError("disk full")))
    assert fake.complete.call_count == 1


def test_negative_subprocess_exit_stops_before_requesting_remote_model(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "quality_kill", Path(__file__).parents[2] / "scripts/compare_model_quality.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", ["compare_model_quality.py", "--output-root", str(tmp_path)])
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setattr(module, "local_model_metadata", lambda _: {})
    child = Mock(return_value=subprocess.CompletedProcess([], -15))
    monkeypatch.setattr(module.subprocess, "run", child)
    assert module.main() == 130
    assert child.call_count == 1
    metadata = json.loads(next(tmp_path.glob("*/run-metadata.json")).read_text())
    assert metadata["finished_at_utc"] and metadata["exit_code"] == 130
    assert "claude" not in metadata["targets"]


def test_helper_restores_process_umask_even_after_an_exception(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "quality_umask", Path(__file__).parents[2] / "scripts/compare_model_quality.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    previous = os.umask(0o027)
    expected = os.umask(0o027)  # Windows may normalize unsupported permission bits.
    try:
        monkeypatch.setattr(module, "_main", Mock(side_effect=RuntimeError("injected")))
        with pytest.raises(RuntimeError):
            module.main()
        observed = os.umask(0o027)
        assert observed == expected
    finally:
        os.umask(previous)


def test_timeout_in_comparison_helper_finishes_metadata_and_returns_failure(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "quality_helper", Path(__file__).parents[2] / "scripts/compare_model_quality.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", ["compare_model_quality.py", "--local-only", "--output-root", str(tmp_path)])
    monkeypatch.setattr(module, "local_model_metadata", lambda _: {})
    monkeypatch.setattr(module.subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("fake", 1)))
    assert module.main() == 1
    metadata = json.loads(next(tmp_path.glob("*/run-metadata.json")).read_text())
    assert metadata["finished_at_utc"] and metadata["exit_code"] == 1
    assert metadata["targets"]["qwen"]["error_type"] == "TimeoutExpired"
