"""One publish decision for a finished hunt and its Sigma rules.

Generation, semantics, and the public promotion gate each check a slice of a
draft. This runs the checks that can be decided from the hunt as it will be
published, and returns one verdict: pass, review, or block.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

_FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----)"
)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # "block" stops approval; "review" is shown and does not
    message: str
    target: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class PublishReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(item.severity == "block" for item in self.findings):
            return "block"
        if self.findings:
            return "review"
        return "pass"

    def blocking(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "block"]


def fenced_sigma(hunt_text: str) -> list[tuple[str, str]]:
    """Sigma documents embedded in the hunt body, named by their title."""
    import yaml

    found: list[tuple[str, str]] = []
    for match in _FENCE_RE.finditer(hunt_text or ""):
        raw = match.group(1).strip()
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            found.append(("embedded rule", raw))
            continue
        if _is_sigma(doc):
            found.append((str(doc.get("title") or "embedded rule"), raw))
    return found


def evaluate_hunt(
    hunt_text: str, rules: list[tuple[str, str]] | None = None
) -> PublishReport:
    """Check the hunt text and its Sigma rules.

    ``rules`` is ``(name, yaml)``. When it is omitted, fenced Sigma in the hunt
    body is checked instead. Query files, when the caller has them, should be
    passed here so a rule is not judged twice.
    """
    findings: list[Finding] = []
    secret = _SECRET_RE.search(hunt_text or "")
    if secret:
        findings.append(
            Finding("credential", "block", "High-confidence credential material in the hunt text")
        )
    chosen = rules if rules is not None else fenced_sigma(hunt_text)
    for name, raw in chosen:
        findings.extend(_check_rule(name, raw))
    return PublishReport(findings)


def _is_sigma(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("detection"), dict)
        and isinstance(doc.get("logsource"), dict)
    )


def _check_rule(name: str, raw: str) -> list[Finding]:
    import yaml

    from hecate_agent.agents.llm.sigma.validators import (
        _breadth_problem,
        _field_type_problem,
        _impossible_modifier_problem,
        _library_as_process_problem,
        _modifier_in_value_problem,
        _or_branch_breadth_problem,
        _pysigma_problem,
    )
    from hecate_agent.agents.llm.sigma_generator import _unobservable_auth_claim_problem
    from hecate_agent.core.sigma_semantics import semantic_problem

    target = name or "rule"
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return [Finding("sigma_parse", "block", f"YAML did not parse: {exc}", target)]
    if not _is_sigma(doc):
        return []
    detection = doc["detection"]
    category = str((doc.get("logsource") or {}).get("category") or "")
    description = " ".join(str(doc.get(key) or "") for key in ("title", "description"))
    findings: list[Finding] = []

    def add(check: str, severity: str, message: str | None) -> None:
        if message:
            findings.append(Finding(check, severity, message[:400], target))

    add("semantics", "block", semantic_problem(detection, category, description))
    add("auth_claim", "block", _unobservable_auth_claim_problem(detection, description))
    add("field_type", "block", _field_type_problem(detection))
    add("modifier", "block", _modifier_in_value_problem(detection))
    add("modifier", "block", _impossible_modifier_problem(detection))
    add("library_as_process", "block", _library_as_process_problem(detection, category))
    add("breadth", "review", _breadth_problem(detection))
    add("breadth", "review", _or_branch_breadth_problem(detection))
    add("pysigma", "block", _pysigma_problem(raw))
    if _SECRET_RE.search(raw):
        add("credential", "block", "High-confidence credential material in the rule")
    return findings
