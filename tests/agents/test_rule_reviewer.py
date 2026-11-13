"""Rule reviewer (deep-dive appendix A2): verified contradictions drop a rule; the rest is advice."""

import json
from typing import Any, Dict, List

import yaml

from hecate_agent.agents.llm.rule_reviewer import RuleReviewer, _json, validate_review, verbatim_in
from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent, SigmaRule

GUIDANCE = "Resume-themed executables launching cmd.exe and then Word"
PASSAGES = [
    "ANY.RUN showed the executable launching cmd.exe, opening a DOCX in Word",
    "Kill-switch marker %TEMP%\\log_de.log",
    GUIDANCE,
]
HYPOTHESIS = "A resume-themed loader launches cmd.exe, opens a decoy DOCX in Word, and stages VShell from 38.207.178.192."
WORD_TO_CMD = """title: Word spawning cmd
logsource: {category: process_creation}
detection:
  selection: {ParentImage|endswith: '\\\\winword.exe', Image|endswith: '\\\\cmd.exe'}
  condition: selection
"""


def _reviewer(*replies: Dict[str, Any]) -> RuleReviewer:
    queue = [json.dumps(r) for r in replies]
    return RuleReviewer(lambda prompt, validate: queue.pop(0))


def test_a_quote_must_appear_verbatim_in_a_passage() -> None:
    assert verbatim_in("launching cmd.exe, opening a DOCX in Word", PASSAGES)
    assert verbatim_in("Kill-switch marker %TEMP%\\log_de.log", PASSAGES)
    assert not verbatim_in("Word launches cmd.exe", PASSAGES)  # paraphrase
    assert not verbatim_in("cmd.exe", PASSAGES)  # too short to establish anything


def test_a_quoted_contradiction_is_verified() -> None:
    review = _reviewer(
        {"verdict": "reject", "issues": ["reversed chain"], "contradiction": "Word does not start cmd.exe", "quote": GUIDANCE}
    ).review(WORD_TO_CMD, HYPOTHESIS, PASSAGES)
    assert review.verdict == "reject" and review.verified


def test_an_unquoted_contradiction_is_not() -> None:
    review = _reviewer({"verdict": "reject", "contradiction": "the order is wrong", "quote": "Word starts the shell"}).review(
        WORD_TO_CMD, HYPOTHESIS, PASSAGES
    )
    assert review.verdict == "reject" and not review.verified


def test_only_gaps_quoted_from_the_hypothesis_or_source_are_reported() -> None:
    gaps = _reviewer(
        {
            "gaps": [
                {"behaviour": "decoy DOCX opened in Word", "quote": "opens a decoy DOCX in Word"},
                {"behaviour": "persistence via Run key", "quote": "adds a Run key for persistence"},
            ]
        }
    ).gaps([], HYPOTHESIS, PASSAGES)
    assert gaps == [{"behaviour": "decoy DOCX opened in Word", "quote": "opens a decoy DOCX in Word"}]


# --- In the generator ------------------------------------------------------------------------


def _agent(replies: List[Dict[str, Any]]) -> SigmaGeneratorAgent:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    queue = [json.dumps(r) for r in replies]
    agent._call_llm_with_retry = lambda prompt, validate, **kwargs: queue.pop(0)  # type: ignore
    return agent


def _input() -> SigmaGenerationInput:
    return SigmaGenerationInput(
        hypothesis=HYPOTHESIS,
        source_artifacts=[{"value": "cmd.exe", "kind": "process", "status": "active", "evidence": PASSAGES[0]}],
        detection_guidance=[{"id": "G1", "route": "sigma", "text": GUIDANCE}],
        review_rules=True,
    )


def _rule(title: str, origin: str = "model") -> SigmaRule:
    return SigmaRule(logsource_category="process_creation", title=title, rule_yaml=WORD_TO_CMD, origin=origin)


def test_a_verified_contradiction_drops_the_model_rule() -> None:
    agent = _agent(
        [
            {"verdict": "reject", "contradiction": "the source has cmd.exe starting Word", "quote": GUIDANCE},
            {"gaps": []},
        ]
    )
    kept, rejected, gaps, warnings = agent._review_rules([_rule("Word spawning cmd")], _input())
    assert kept == [] and gaps == [] and warnings == []
    assert rejected == [f'process_creation: reviewer: the source has cmd.exe starting Word (source: "{GUIDANCE}")']


def test_unverified_revisions_are_kept_with_an_actionable_note() -> None:
    agent = _agent(
        [
            {"verdict": "revise", "issues": ["no command-line context"], "contradiction": "maybe reversed", "quote": ""},
            {"gaps": [{"behaviour": "decoy opened in Word", "quote": "opens a decoy DOCX in Word"}]},
        ]
    )
    kept, rejected, gaps, _ = agent._review_rules([_rule("Word spawning cmd")], _input())
    assert len(kept) == 1
    assert rejected == []
    note = yaml.safe_load(kept[0].rule_yaml)["hecate_review"]
    assert note["verdict"] == "revise"
    assert note["issues"] == ["no command-line context"]
    assert gaps == [{"behaviour": "decoy opened in Word", "quote": "opens a decoy DOCX in Word"}]


def test_deterministic_rules_are_not_reviewed_and_a_failed_review_keeps_the_rule() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    calls: List[str] = []

    def failing(prompt: str, validate: Any, **kwargs: Any) -> str:
        calls.append(prompt)
        raise TimeoutError("model timed out")

    agent._call_llm_with_retry = failing  # type: ignore
    kept, rejected, gaps, warnings = agent._review_rules(
        [_rule("IOC rule", origin="deterministic"), _rule("Word spawning cmd")], _input()
    )
    assert [r.title for r in kept] == ["IOC rule", "Word spawning cmd"] and rejected == [] and gaps == []
    assert len(calls) == 2  # one review (the model rule) and one coverage check
    assert any("rule review failed for 'Word spawning cmd'" in w for w in warnings)


def test_grounded_gaps_that_sigma_cannot_see_or_rules_already_match_are_dropped() -> None:
    """All five of the A2 replay's gaps quoted the source verbatim; none was a real gap."""
    gaps = [
        {"behaviour": "XOR-decoding of downloaded payload with key 0x99", "quote": "XOR-decodes it with 0x99"},
        {
            "behaviour": "Reflective loading of the stager",
            "quote": "It reflectively runs a 1,454-byte Windows SNOWLIGHT stager",
        },
        {"behaviour": "High-signal SNOWLIGHT check-in", "quote": "High-signal SNOWLIGHT check-in: 77 33 32"},
        {"behaviour": "Kill-switch marker file", "quote": "Kill-switch marker %TEMP%\\log_de.log"},
        {"behaviour": "Staging download", "quote": "EasyConnectUpdata_Log.txt is encrypted shellcode"},
        {"behaviour": "decoy opened in Word", "quote": "opens a decoy DOCX in Word"},
    ]
    passages = [g["quote"] for g in gaps]
    rules = [
        {"title": "log_de", "description": "", "detection": "selection: {TargetFilename|endswith: '\\\\log_de.log'}"},
        {"title": "urls", "description": "", "detection": "selection: {c-uri|endswith: [/EasyConnectUpdata_Log.txt]}"},
    ]
    kept = _reviewer({"gaps": gaps}).gaps(rules, HYPOTHESIS, passages)
    assert kept == [{"behaviour": "decoy opened in Word", "quote": "opens a decoy DOCX in Word"}]


def test_platform_contradiction_is_remediated_instead_of_rejected() -> None:
    linux_rule_yaml = """title: Linux process on NetScaler
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /sh
  condition: selection
"""
    rule = SigmaRule(
        logsource_category="process_creation",
        title="Linux process on NetScaler",
        rule_yaml=linux_rule_yaml,
        origin="model",
    )
    quote = PASSAGES[0]
    agent = _agent(
        [
            {
                "verdict": "reject",
                "contradiction": "The rule specifies logsource: product: linux, but NetScaler appliances run FreeBSD, not Linux.",
                "quote": quote,
            },
            {"gaps": []},
        ]
    )
    input_data = _input()
    kept, rejected, gaps, warnings = agent._review_rules([rule], input_data)
    assert rejected == []
    assert len(kept) == 1
    doc = yaml.safe_load(kept[0].rule_yaml)
    assert doc["logsource"]["product"] == "freebsd"
    assert doc["hecate_review"]["verdict"] == "remediated"
    assert any("auto-remediated platform" in w for w in warnings)


def test_generation_keeps_unverified_review_advice() -> None:
    """Neither advisory revisions nor an invented quote can veto a valid draft."""
    for verdict in ("revise", "reject"):
        agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
        agent._build_prompt = lambda *args: "draft"  # type: ignore
        agent._build_rule = lambda *args: (_rule("Word spawning cmd"), None)  # type: ignore

        def complete(prompt: str, validate: Any, **kwargs: Any) -> str:
            if prompt == "draft":
                response = json.dumps({"rules": [{}]})
                assert validate(response) is None
                return response
            return json.dumps({"verdict": verdict, "issues": ["needs more detail"], "contradiction": "wrong order", "quote": "invented source passage"})

        agent._call_llm_with_retry = complete  # type: ignore
        rule, problems, _ = agent._generate_for_logsource(_input(), "process_creation")
        assert rule is not None
        assert problems == []


def test_json_extraction_from_markdown_code_fence_and_noise() -> None:
    # 1. Standard markdown code block
    markdown_wrapped = """Here is the review result:
```json
{
  "verdict": "keep",
  "issues": []
}
```
Hope this helps!"""
    data = _json(markdown_wrapped)
    assert data["verdict"] == "keep"
    assert validate_review(markdown_wrapped) is None

    # 2. Text with braces before and after
    noisy = """Note: {debug: 123}
```json
{
  "verdict": "reject",
  "issues": ["bad rule"]
}
```
closing {extra: true}"""
    data = _json(noisy)
    assert data["verdict"] == "reject"
    assert validate_review(noisy) is None

    # 3. Raw decode without fences but leading commentary
    commentary = 'The analysis concluded with the following payload:\n{"verdict": "keep", "issues": []}\nDone.'
    data = _json(commentary)
    assert data["verdict"] == "keep"

