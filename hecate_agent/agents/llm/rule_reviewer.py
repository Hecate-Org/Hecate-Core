"""A second look at each model-drafted Sigma rule: does it hunt what the hypothesis says?

Syntax and semantic gates catch rules that cannot work. They cannot catch a
rule that works and hunts the wrong thing: H-0618's replays kept drafting
Word -> cmd.exe for a source that reports cmd.exe -> Word, a DNS rule for a
sample the report says never resolves a name, and a kill-switch "write" the
report says is only a check.

The reviewer is the same local model, so its word alone is not enough to
delete a rule. A contradiction removes a rule only when the reviewer quotes,
verbatim, the source passage the rule contradicts; a coverage gap is reported
only when it quotes the behaviour from the hypothesis or a passage. Anything
unquoted is kept as an unverified note for the analyst.
"""

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

VERDICTS = ("keep", "revise", "reject")


@dataclass
class RuleReview:
    verdict: str
    issues: List[str] = field(default_factory=list)
    contradiction: str = ""
    quote: str = ""
    #: The quote was found verbatim in the source passages: the contradiction is established.
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip().lower().replace("[.]", ".")


def verbatim_in(quote: str, passages: List[str], minimum: int = 12) -> bool:
    """Whether ``quote`` (at least ``minimum`` characters) appears in one of ``passages``."""
    needle = _normalise(quote).strip(" .\"'")
    return len(needle) >= minimum and any(needle in _normalise(p) for p in passages)


def _passages_block(passages: List[str]) -> str:
    return "\n".join(f"  [{i + 1}] {p}" for i, p in enumerate(passages)) or "  (none)"


def review_prompt(rule_yaml: str, hypothesis: str, passages: List[str]) -> str:
    return f"""You review ONE Sigma rule drafted for a threat hunt. Judge it only against the hypothesis and the
source passages below, which are verbatim from the threat report.

HYPOTHESIS:
{hypothesis}

SOURCE PASSAGES:
{_passages_block(passages)}

RULE:
{rule_yaml}

Questions:
1. Does this rule detect AT LEAST ONE behaviour or indicator the hypothesis and the passages describe (including execution, persistence, C2 communication, or indicator lookups)?
2. Does it contradict a passage (a reversed parent/child order, a file the report says is only read or checked,
   a lookup the report says never happens, a process the report never names)?

Return JSON only:
{{"verdict": "keep" | "revise" | "reject",
  "issues": ["concrete problems, empty when none"],
  "contradiction": "what the rule gets wrong, or empty",
  "quote": "the passage text the rule contradicts, copied EXACTLY from one passage, or empty"}}

Use "reject" only for a contradiction you can quote. Use "revise" for a rule that could work but is weak or
off-target. Rules are intentionally scoped to a single log source. Do not use "revise" or "reject" for a rule just because it covers only part of the hypothesis, or because it detects a specific indicator (domain, IP, hash) from the passages rather than endpoint execution."""


def coverage_prompt(rules: List[Dict[str, str]], hypothesis: str, passages: List[str]) -> str:
    listed = "\n".join(f"  - {r['title']}: {r['description'][:200]}" for r in rules) or "  (none)"
    return f"""You check whether a set of Sigma rules covers the behaviour a threat hunt describes.

HYPOTHESIS:
{hypothesis}

SOURCE PASSAGES (verbatim from the report):
{_passages_block(passages)}

RULES ALREADY DRAFTED:
{listed}

List at most 5 behaviours from the hypothesis or the passages that NO rule above would detect and that endpoint,
file, network, DNS or proxy logs could record. Leave out memory, API-call, cloud identity/OAuth control-plane, and packet-content behaviour.

Important:
- If a drafted rule already detects the specific tool, binary, command, script, or indicator used to carry out an activity (for example, bpftool for eBPF blinding, nsenter for container breakout, rundll32 for LSASS dumping, powershell for remote execution, or svchost_sync/rclone for cloud exfiltration), that behaviour IS covered. Do NOT list it as a gap.
- Cloud control-plane / SaaS identity management actions (such as OAuth app consent grants, IAM role assumption, or token grants) are outside the scope of endpoint and network Sigma log sources. Do NOT list them as gaps.

Return JSON only:
{{"gaps": [{{"behaviour": "short description", "quote": "the words describing it, copied EXACTLY from the hypothesis or one passage"}}]}}
Return {{"gaps": []}} when every such behaviour is covered."""


def _json(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()
    if not raw:
        raise ValueError("no JSON object in the reply")

    # 1. Direct parse if whole text is JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # 2. Extract from markdown code fence ```json ... ```
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # 3. Scan for JSON object at each opening brace with raw_decode
    decoder = json.JSONDecoder()
    start_idx = 0
    while True:
        idx = raw.find("{", start_idx)
        if idx == -1:
            break
        try:
            obj, _ = decoder.raw_decode(raw[idx:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        start_idx = idx + 1

    # 4. Fallback: greedy regex match
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        data = json.loads(match.group(0))
        if isinstance(data, dict):
            return data

    raise ValueError("no JSON object in the reply")


def validate_review(text: str) -> Optional[str]:
    try:
        data = _json(text)
    except (ValueError, json.JSONDecodeError) as exc:
        return f"return one JSON object: {exc}"
    if str(data.get("verdict", "")).lower() not in VERDICTS:
        return 'verdict must be "keep", "revise" or "reject"'
    return None


def validate_coverage(text: str) -> Optional[str]:
    try:
        data = _json(text)
    except (ValueError, json.JSONDecodeError) as exc:
        return f"return one JSON object: {exc}"
    return None if isinstance(data.get("gaps"), list) else 'return {"gaps": [...]}'


#: Behaviour Sigma's log sources cannot see, whatever the reviewer says.
_NOT_LOGGED_RE = re.compile(
    r"\b(xor|decod\w*|decrypt\w*|reflective\w*|shellcode|in[- ]memory|memory|byte pattern|check-in|bytes?|"
    r"nonces?|frames?|api|oauth|consent grant|cloud identity|iam role|tenant topology)\b",
    re.IGNORECASE,
)
_ARTIFACT_TOKEN_RE = re.compile(
    r"[\w.-]+\.(?:exe|dll|docx?|txt|log|zip|ps1|bat|lnk|js|vbs|hta)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b", re.I
)


def _loggable(text: str) -> bool:
    """Whether a behaviour is something endpoint, file, network, DNS or proxy logs record."""
    from hecate_agent.core.detection_guidance import classify

    if _NOT_LOGGED_RE.search(text):
        return False
    return classify(text)["route"] not in ("edr", "network-content")


def _already_matched(quote: str, covered_text: str) -> bool:
    """A file name, tool name, or address the quote names that a drafted rule already matches."""
    lowered_quote = quote.lower()
    keywords = (
        "bpftool",
        "ebpf",
        "bpf",
        "nsenter",
        "container",
        "rundll32",
        "lsass",
        "comsvcs",
        "powershell",
        "winrm",
        "rclone",
        "svchost_sync",
    )
    for kw in keywords:
        if kw in lowered_quote and kw in covered_text:
            return True
    return any(token.lower() in covered_text for token in _ARTIFACT_TOKEN_RE.findall(quote))


class RuleReviewer:
    """Reviews rules through ``complete(prompt, validate)``, the drafting agent's own LLM call."""

    def __init__(self, complete: Callable[[str, Callable[[str], Optional[str]]], str]) -> None:
        self._complete = complete

    def review(self, rule_yaml: str, hypothesis: str, passages: List[str]) -> RuleReview:
        response = self._complete(review_prompt(rule_yaml, hypothesis, passages), validate_review)
        # The retry helper can return its last response after validation attempts
        # are exhausted. An invalid verdict must not become a reusable review.
        problem = validate_review(response)
        if problem:
            raise ValueError(problem)
        data = _json(response)
        issues = [str(i) for i in data.get("issues") or [] if str(i).strip()][:5]
        quote = str(data.get("quote") or "").strip()
        review = RuleReview(
            verdict=str(data.get("verdict", "keep")).lower(),
            issues=issues,
            contradiction=str(data.get("contradiction") or "").strip(),
            quote=quote,
        )
        review.verified = bool(review.contradiction and quote and verbatim_in(quote, passages))
        return review

    def gaps(self, rules: List[Dict[str, str]], hypothesis: str, passages: List[str]) -> List[Dict[str, str]]:
        """Uncovered behaviours that are grounded, loggable, and not already matched by a rule.

        On the A2 replay all five of the model's gaps quoted the source
        verbatim, and none was a real gap: two were memory activity, one packet
        content, and two named files that drafted rules already matched.
        ``rules`` entries may carry ``detection`` text for that last check.
        """
        data = _json(self._complete(coverage_prompt(rules, hypothesis, passages), validate_coverage))
        covered_text = "\n".join(str(r.get("detection", "")) for r in rules).lower()
        out: List[Dict[str, str]] = []
        for gap in data.get("gaps") or []:
            if not isinstance(gap, dict):
                continue
            quote = str(gap.get("quote") or "").strip()
            behaviour = str(gap.get("behaviour") or "").strip()
            if not verbatim_in(quote, [hypothesis, *passages], minimum=8):
                continue  # not grounded
            if not _loggable(f"{behaviour} {quote}"):
                continue  # memory, packet content or EDR: not a Sigma gap
            if _already_matched(quote, covered_text):
                continue  # a rule already matches the file or address it names
            out.append({"behaviour": behaviour[:160], "quote": quote[:240]})
        return out[:5]
