"""Prompt changes must remain measurable without relabeling saved runs."""

import json
import re
from copy import deepcopy
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from hecate_agent.commands.model_quality import eval_suite_cmd
from hecate_agent.core.llm_provider import LLMResponse
from hecate_agent.core.model_quality import (
    BASELINE_SYSTEM_PROMPT,
    DEFAULT_PROMPT_PROFILE,
    PROMPT_PROFILES,
    compare_reports,
    digest,
    load_suite,
    messages_for,
    prompt_for,
    rescore_report,
    run_suite,
)


def example():
    suite = deepcopy(load_suite())
    suite["cases"] = [suite["cases"][0]]
    backend = Mock(provider_name="ollama", model="test-prompt")
    backend.complete.return_value = LLMResponse('{"subtechnique_name":"PowerShell"}', 100, 20, backend.model, 0, 0)
    return suite, backend


@pytest.mark.parametrize("profile", PROMPT_PROFILES)
def test_profile_is_sent_to_provider_and_bound_to_report(profile):
    suite, backend = example()
    report = run_suite(backend, suite, prompt_profile=profile)
    assert backend.complete.call_args.kwargs["messages"][0]["content"] == prompt_for(profile)
    assert report["prompt_profile"] == profile
    assert report["system_prompt_sha256"] == digest(prompt_for(profile))
    assert report["gate_passed"]


def test_prompt_strengthening_does_not_supply_answers_or_rewrite_tasks():
    suite = load_suite()
    for case in suite["cases"]:
        original = messages_for(case, prompt_profile="baseline-v1")
        current = messages_for(case, prompt_profile="complete-v3")
        assert original[1] == current[1]
    extra = prompt_for("complete-v3").removeprefix(BASELINE_SYSTEM_PROMPT)
    assert extra and not re.search(r"T\d{4}|AppleScript|PowerShell|JavaScript|Windows|macOS", extra)
    altered = deepcopy(suite["cases"][0])
    altered["checks"][0]["expected"] = "DO_NOT_LEAK"
    altered["review_basis"] = "DO_NOT_LEAK"
    assert "DO_NOT_LEAK" not in json.dumps(messages_for(altered, prompt_profile="complete-v3"))


def test_experiments_do_not_change_the_default_prompt():
    assert DEFAULT_PROMPT_PROFILE == "baseline-v1"
    assert messages_for(load_suite()["cases"][0])[0]["content"] == BASELINE_SYSTEM_PROMPT


def test_historical_report_without_profile_rescores_with_original_prompt():
    suite, backend = example()
    historical = run_suite(backend, suite, prompt_profile="baseline-v1")
    historical.pop("prompt_profile")  # Reports from before profiles existed.
    rescored = rescore_report(historical, suite)
    assert rescored["prompt_profile"] == "baseline-v1"
    assert rescored["system_prompt_sha256"] == historical["system_prompt_sha256"]
    assert rescored["new_model_calls"] == 0
    backend.complete.assert_called_once()


def test_changed_prompt_cannot_be_compared_or_relabelled_as_baseline():
    suite, backend = example()
    baseline = run_suite(backend, suite, prompt_profile="baseline-v1")
    candidate = run_suite(backend, suite, prompt_profile="complete-v3")
    with pytest.raises(ValueError, match="system_prompt_sha256"):
        compare_reports([baseline, candidate])
    candidate["prompt_profile"] = "baseline-v1"
    with pytest.raises(ValueError, match="system prompt"):
        rescore_report(candidate, suite)
    with pytest.raises(ValueError, match="system prompt"):
        compare_reports([candidate, candidate])


@pytest.mark.parametrize("profile", ["unknown", None, []])
def test_invalid_prompt_profile_fails_before_model_calls(profile):
    suite, backend = example()
    with pytest.raises(ValueError, match="prompt profile"):
        run_suite(backend, suite, prompt_profile=profile)
    backend.complete.assert_not_called()


def test_cli_rescore_cannot_change_prompt(tmp_path):
    suite, backend = example()
    path = tmp_path / "historical.json"
    path.write_text(json.dumps(run_suite(backend, suite, prompt_profile="baseline-v1")))
    result = CliRunner().invoke(eval_suite_cmd, ["--rescore", str(path), "--prompt-profile", "checked-v2"])
    assert result.exit_code == 2
    assert "preserves" in result.output
