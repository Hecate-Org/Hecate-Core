"""One OSINT lookup's answer, as data the trail and monitor can count.

Providers return an ``EnrichmentResult``. It is a ``str`` of the sentence the
research prompt already expects, plus the outcome of the lookup, so callers
that compare or format the text keep working and callers that tally do not
have to guess from the wording.
"""

from __future__ import annotations

import re
from typing import Any

OUTCOMES = ("found", "flagged", "missing", "errors", "unconfigured", "skipped")

_UNCONFIGURED_RE = re.compile(r"(?i)not configured")
_ERROR_RE = re.compile(r"(?i)\berror\b|rate limit|\bHTTP [45]\d\d\b|timed? ?out")
_SKIPPED_RE = re.compile(r"(?i)^(invalid|private/internal)")
_MISSING_RE = re.compile(
    r"(?i)(^(?:no |not |unknown\b)|\bnot found\b|\bnot listed\b|\bnot observed\b|\bnot seen\b|\bno record\b)"
)
_VT_MALICIOUS_RE = re.compile(r"Malicious hits: (\d+)")


def classify_enrichment_result(result: str) -> str:
    """Fallback outcome for a provider that still returns a bare sentence.

    "flagged" is a subset of "found": the provider has a record and calls it
    malicious. Prefer ``report(..., outcome)`` at the return, which does not
    depend on this wording.
    """
    named = getattr(result, "outcome", None)
    if named in OUTCOMES:
        return str(named)
    text = (result or "").strip()
    if not text or _SKIPPED_RE.match(text):
        return "skipped"
    if _UNCONFIGURED_RE.search(text):
        return "unconfigured"
    if _MISSING_RE.match(text):
        return "missing"
    if _ERROR_RE.search(text):
        return "errors"
    match = _VT_MALICIOUS_RE.search(text)
    if match and int(match.group(1)) > 0:
        return "flagged"
    return "found"


class EnrichmentResult(str):
    """The prompt sentence, with the lookup's outcome attached."""

    outcome: str
    verdict: str | None
    facts: dict[str, Any]
    error: str | None
    service: str
    observable: str

    def __new__(
        cls,
        text: str,
        outcome: str = "found",
        *,
        verdict: str | None = None,
        facts: dict[str, Any] | None = None,
        error: str | None = None,
        service: str = "",
        observable: str = "",
    ) -> "EnrichmentResult":
        obj = str.__new__(cls, text)
        obj.outcome = outcome if outcome in OUTCOMES else "found"
        obj.verdict = verdict
        obj.facts = dict(facts or {})
        obj.error = error
        obj.service = service
        obj.observable = observable
        return obj


def report(
    text: Any,
    outcome: str | None = None,
    *,
    verdict: str | None = None,
    facts: dict[str, Any] | None = None,
    error: str | None = None,
    service: str = "",
    observable: str = "",
) -> EnrichmentResult:
    """Wrap a provider sentence. An explicit ``outcome`` wins over the wording."""
    if (
        isinstance(text, EnrichmentResult)
        and outcome is None
        and verdict is None
        and not facts
        and error is None
        and not service
        and not observable
    ):
        return text
    rendered = str(text)
    chosen = outcome or classify_enrichment_result(rendered)
    return EnrichmentResult(
        rendered,
        chosen,
        verdict=verdict,
        facts=facts,
        error=error,
        service=service or getattr(text, "service", ""),
        observable=observable or getattr(text, "observable", ""),
    )


def render_enrichment_citations(records: list[dict[str, Any]]) -> str:
    """Markdown labeling each observable from its lookup outcomes.

    A provider that was not configured, or that skipped the observable, is not
    a miss. ``corroborated`` means a configured provider had a record.
    ``uncorroborated`` means every configured provider that answered had none.
    ``inconclusive`` means a lookup failed and none had a record.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for row in records:
        observable = str(row.get("observable") or "")
        if not observable:
            continue
        key = (str(row.get("kind") or "observable"), observable)
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(row)
    lines = [
        line
        for key in order
        if (line := _citation_line(key[0], key[1], grouped[key]))
    ]
    if not lines:
        return ""
    return (
        "### Enrichment citations\n\n"
        "Labels come from lookup outcomes. A provider that was not configured is not a miss.\n\n"
        + "\n".join(lines)
    )


def _citation_line(kind: str, observable: str, rows: list[dict[str, Any]]) -> str:
    services: dict[str, list[str]] = {}
    verdicts: dict[str, str] = {}
    for row in rows:
        outcome = str(row.get("outcome") or "")
        if outcome == "skipped":
            continue
        service = str(row.get("service") or "provider")
        bucket = services.setdefault(outcome, [])
        if service not in bucket:
            bucket.append(service)
        if row.get("verdict"):
            verdicts[service] = str(row["verdict"])
    flagged = services.get("flagged", [])
    found = [service for service in services.get("found", []) if service not in flagged]
    missed = services.get("missing", [])
    failed = services.get("errors", [])
    unconfigured = services.get("unconfigured", [])
    corroborated = flagged + found
    if corroborated:
        cited = ", ".join(f"{service} ({verdicts[service]})" if service in verdicts else service for service in corroborated)
        label = f"**corroborated** by {cited}"
    elif missed and not failed:
        label = "**uncorroborated**"
    elif failed:
        label = "**inconclusive**"
    elif unconfigured:
        label = "**not configured**"
    else:
        return ""
    tail: list[str] = []
    if corroborated and missed:
        tail.append(f"No record: {', '.join(missed)}.")
    elif missed and not corroborated:
        tail.append(f"No record: {', '.join(missed)}.")
    if failed and corroborated:
        tail.append(f"Lookup failed: {', '.join(failed)}.")
    elif failed and not corroborated:
        tail.append(f"Lookup failed: {', '.join(failed)}.")
    if unconfigured and (corroborated or missed or failed):
        tail.append(f"Not configured: {', '.join(unconfigured)}.")
    elif unconfigured and not corroborated:
        tail.append(", ".join(unconfigured) + ".")
    return f"- **{kind}** `{observable}` — {label}" + (" " + " ".join(tail) if tail else "")

