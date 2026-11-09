"""Reviews are reused only for identical prompts within one generation execution."""

import json
from collections import Counter
from types import SimpleNamespace

import pytest
import yaml

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent

SOURCE = "The loader launches cmd.exe before opening Word."


def candidate(title="Masquerading svchost outside System32", category="process_creation"):
    detection = {
        "selection": {"Image|endswith": "\\svchost.exe"},
        "filter": {"Image|startswith": "C:\\Windows\\System32"},
        "condition": "selection and not filter",
    }
    if category == "file_event":
        detection = {"selection": {"TargetFilename|endswith": "\\Windows\\Temp\\agent-update.exe"}, "condition": "selection"}
    return {
        "title": title,
        "logsource_category": category,
        "detection": detection,
        "description": "Detects the observed behavior",
        "techniques": ["T1059.003"],
    }


def inputs(**changes):
    values = {
        "hypothesis": "The loader launches cmd.exe and stages an executable.",
        "threat_intel": SOURCE,
        "platforms": ["windows"],
        "techniques": ["T1059.003"],
        "logsources": ["process_creation"],
        "review_rules": True,
    }
    values.update(changes)
    return SigmaGenerationInput(**values)


@pytest.fixture
def harness(monkeypatch):
    agent = SigmaGeneratorAgent(llm_enabled=True)
    calls = []
    options = {"verdict": "keep"}
    generations = []
    monkeypatch.setattr(agent, "_build_prompt", lambda data, source: f"GENERATE:{source}")
    monkeypatch.setattr(agent, "_get_provider", lambda: SimpleNamespace(provider_name="test"))
    monkeypatch.setattr("hecate_agent.agents.base.time.sleep", lambda _: None)

    def complete(prompt, **kwargs):
        if prompt.startswith("GENERATE:"):
            calls.append(("generate", prompt))
            source = prompt.splitlines()[0].split(":", 1)[1]
            rule = generations.pop(0) if generations else candidate(category=source)
            return json.dumps({"rules": [rule]})
        if prompt.startswith("You review ONE"):
            calls.append(("review", prompt))
            if options.get("fail_first") and sum(k == "review" for k, _ in calls) == 1:
                raise TimeoutError("review unavailable")
            if options.get("invalid_first_review") and sum(k == "review" for k, _ in calls) <= 2:
                return '{"issues": ["missing verdict"]}'
            if options.get("reject_bad") and "Incorrect direction" in prompt:
                return json.dumps({"verdict": "reject", "contradiction": "reversed process chain", "quote": SOURCE})
            return json.dumps({"verdict": options["verdict"], "issues": ["analyst advice"]})
        assert prompt.startswith("You check whether"), prompt[:100]
        calls.append(("coverage", prompt))
        return '{"gaps": []}'

    monkeypatch.setattr(agent, "_call_llm", complete)
    return agent, calls, options, generations


@pytest.mark.parametrize("verdict", ["keep", "revise", "reject"])
def test_accepted_rule_is_reviewed_once_and_retains_review_notes(harness, verdict):
    agent, calls, options, _ = harness
    options["verdict"] = verdict
    result = agent.execute(inputs())
    assert result.success, result.error
    assert Counter(kind for kind, _ in calls) == {"generate": 1, "review": 1, "coverage": 1}
    document = yaml.safe_load(result.data.rules[0].rule_yaml)
    assert document["hecate_review"]["verdict"] == verdict
    assert document["hecate_review"]["issues"] == ["analyst advice"]
    # The final artifact keeps the same UUID as the artifact actually reviewed.
    review_prompt = next(prompt for kind, prompt in calls if kind == "review")
    assert document["id"] in review_prompt


def test_parallel_sources_each_get_one_review_and_share_one_coverage_check(harness):
    agent, calls, _, _ = harness
    result = agent.execute(inputs(logsources=["process_creation", "file_event"]))
    assert result.success, result.error
    assert len(result.data.rules) == 2
    assert Counter(kind for kind, _ in calls) == {"generate": 2, "review": 2, "coverage": 1}
    coverage = next(prompt for kind, prompt in calls if kind == "coverage")
    assert all(rule.title in coverage for rule in result.data.rules)


def test_verified_rejection_still_drives_regeneration(harness):
    agent, calls, options, generations = harness
    options["reject_bad"] = True
    generations.extend([candidate("Incorrect direction"), candidate("Corrected direction")])
    result = agent.execute(inputs())
    assert result.success, result.error
    assert result.data.rules[0].title == "Corrected direction"
    assert Counter(kind for kind, _ in calls) == {"generate": 2, "review": 2, "coverage": 1}
    retried_prompt = [prompt for kind, prompt in calls if kind == "generate"][1]
    assert "rejected by review" in retried_prompt
    assert SOURCE in retried_prompt


def test_repeated_rejected_candidate_stays_rejected_without_repeat_reviews(harness):
    agent, calls, options, generations = harness
    options["reject_bad"] = True
    generations.extend([candidate("Incorrect direction") for _ in range(4)])
    result = agent.execute(inputs())
    assert not result.success
    assert result.data.rules == []
    assert Counter(kind for kind, _ in calls) == {"generate": 4, "review": 1, "coverage": 1}
    assert any("reversed process chain" in reason for reason in result.data.rejected)


def test_failed_inline_review_is_retried_in_final_pass(harness):
    agent, calls, options, _ = harness
    options["fail_first"] = True
    result = agent.execute(inputs())
    assert result.success, result.error
    assert Counter(kind for kind, _ in calls) == {"generate": 1, "review": 2, "coverage": 1}
    assert yaml.safe_load(result.data.rules[0].rule_yaml)["hecate_review"]["verdict"] == "keep"


@pytest.mark.parametrize("change", ["rule", "hypothesis", "source"])
def test_reuse_requires_identical_rule_and_evidence(harness, change):
    agent, calls, _, _ = harness
    data = inputs()
    reviews = {}
    rule, problems, _ = agent._generate_for_logsource(data, "process_creation", reviews)
    assert rule is not None and not problems
    if change == "rule":
        rule.rule_yaml = rule.rule_yaml.replace("svchost.exe", "rundll32.exe")
    elif change == "hypothesis":
        data.hypothesis += " It persists using a scheduled task."
    else:
        data.threat_intel += " The source also reports a scheduled task."
    kept, _, _, _ = agent._review_rules([rule], data, reviews)
    assert len(kept) == 1
    assert Counter(kind for kind, _ in calls) == {"generate": 1, "review": 2, "coverage": 1}


def test_reviews_do_not_leak_between_hunts_on_same_agent(harness):
    agent, calls, _, _ = harness
    first = agent.execute(inputs())
    second = agent.execute(inputs())
    assert first.success and second.success
    assert Counter(kind for kind, _ in calls) == {"generate": 2, "review": 2, "coverage": 2}
    first_id = yaml.safe_load(first.data.rules[0].rule_yaml)["id"]
    second_id = yaml.safe_load(second.data.rules[0].rule_yaml)["id"]
    assert first_id != second_id


def test_review_disabled_skips_both_rule_review_and_coverage(harness):
    agent, calls, _, _ = harness
    result = agent.execute(inputs(review_rules=False))
    assert result.success, result.error
    assert Counter(kind for kind, _ in calls) == {"generate": 1}


def test_invalid_review_after_retry_exhaustion_is_not_cached(harness):
    agent, calls, options, _ = harness
    options["invalid_first_review"] = True
    result = agent.execute(inputs())
    assert result.success, result.error
    # Two invalid review replies exhaust the inline retry loop. The final pass
    # gets a fresh valid verdict, rather than silently using a default "keep".
    assert Counter(kind for kind, _ in calls) == {"generate": 1, "review": 3, "coverage": 1}
    assert yaml.safe_load(result.data.rules[0].rule_yaml)["hecate_review"]["verdict"] == "keep"
