"""Validate saved evaluation evidence before using it as a release gate."""

from __future__ import annotations

import math
import statistics
from typing import Any

from hecate_agent.core.model_quality_io import MAX_CASES, MAX_RESPONSE_BYTES, strict_equal


def _number(value: Any, minimum: float = 0) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def _integer(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def validate_report(report: Any) -> None:
    """Reject incomplete, duplicated or internally inconsistent artifacts.

    This checks consistency, not authenticity. Reports are trusted local
    artifacts, not signed attestations or a defense against an author forging
    every input and output together.
    """
    try:
        _validate_report(report)
    except (KeyError, TypeError, IndexError, AttributeError, OverflowError):
        raise ValueError("Malformed evaluation report") from None


def _validate_report(report: Any) -> None:
    if not isinstance(report, dict) or report.get("schema") != "hecate-model-quality-report/1":
        raise ValueError("Unsupported comparison report schema")
    if type(report.get("scoring_version")) is not int or report["scoring_version"] not in (1, 2, 3):
        raise ValueError("Unsupported scoring_version")
    for key in ("suite_id", "suite_sha256", "system_prompt_sha256", "provider", "model"):
        if not isinstance(report.get(key), str) or not report[key]:
            raise ValueError("Missing report identity metadata")
    params, policy = report["parameters"], report["policy"]
    repeats = params["repeats"]
    if (
        not _integer(repeats, 1)
        or repeats > 10
        or not _integer(params["max_tokens"], 1)
        or params["max_tokens"] > 4096
        or not _number(params["temperature"])
        or params["temperature"] != 0
    ):
        raise ValueError("Invalid generation parameters")
    if (
        not _number(policy["fail_under"])
        or policy["fail_under"] > 1
        or not _number(policy["max_cost_usd"])
        or policy["max_cost_usd"] <= 0
        or type(policy["critical_failures_allowed"]) is not int
        or policy["critical_failures_allowed"] != 0
    ):
        raise ValueError("Invalid quality policy")
    if "minimum_score" in policy and (not _number(policy["minimum_score"]) or policy["minimum_score"] > policy["fail_under"]):
        raise ValueError("Report threshold is below its reviewed policy minimum")
    rows = report["results"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CASES * 10:
        raise ValueError("Report has incomplete or excessive results")
    identities: set[tuple[str, int]] = set()
    case_categories: dict[str, str] = {}
    categories: dict[str, Any] = {}
    critical = []
    tokens = {"input_tokens": 0, "output_tokens": 0}
    costs = []
    durations = []
    scored = errors = not_run = passed = 0
    for row in rows:
        case, repeat, category, status = row["id"], row["repeat"], row["category"], row["status"]
        if (
            not isinstance(case, str)
            or not case
            or not _integer(repeat, 1)
            or repeat > repeats
            or not isinstance(category, str)
            or not category
            or status not in ("scored", "error", "not_run")
            or type(row["passed"]) is not bool
            or not _integer(row["duration_ms"])
        ):
            raise ValueError("Invalid result identity, status or measurement")
        if (case, repeat) in identities:
            raise ValueError("Duplicate report case/repetition")
        identities.add((case, repeat))
        if case_categories.setdefault(case, category) != category:
            raise ValueError("Case category changes between repetitions")
        bucket = categories.setdefault(category, {"passed": 0, "total": 0})
        bucket["total"] += 1
        bucket["passed"] += int(row["passed"])
        passed += int(row["passed"])
        for key in tokens:
            if not _integer(row.get(key, 0)):
                raise ValueError("Invalid token usage")
            tokens[key] += row.get(key, 0)
        cost = row.get("estimated_api_cost_usd")
        if cost is not None and not _number(cost):
            raise ValueError("Invalid API cost measurement")
        if status != "not_run":
            costs.append(cost)
            durations.append(row["duration_ms"])
        if status == "scored":
            scored += 1
            text = row["response_text"]
            if (
                not isinstance(text, str)
                or len(text) > MAX_RESPONSE_BYTES
                or len(text.encode("utf-8", errors="replace")) > MAX_RESPONSE_BYTES
            ):
                raise ValueError("Invalid or oversized saved response")
            for key in ("format_valid", "critical_failure"):
                if type(row[key]) is not bool:
                    raise ValueError("Invalid result check flags")
            checks = row["checks"]
            if not isinstance(checks, list) or (row["format_valid"] and not checks):
                raise ValueError("Missing scored checks")
            check_fields: set[str] = set()
            for check in checks:
                if (
                    not isinstance(check["field"], str)
                    or type(check["passed"]) is not bool
                    or type(check["critical"]) is not bool
                ):
                    raise ValueError("Invalid scored check")
                if not check["field"] or check["field"] in check_fields:
                    raise ValueError("Duplicate or empty scored check field")
                check_fields.add(check["field"])
            if row["passed"] != (row["format_valid"] and all(c["passed"] for c in checks)):
                raise ValueError("Case outcome contradicts its checks")
            is_critical = not row["format_valid"] or any(c["critical"] and not c["passed"] for c in checks)
            if row["critical_failure"] != is_critical:
                raise ValueError("Critical outcome contradicts its checks")
        else:
            if row["passed"]:
                raise ValueError("An unscored request cannot pass")
            errors += int(status == "error")
            not_run += int(status == "not_run")
        if row.get("critical_failure"):
            critical.append(f"{case}#{repeat}")
    case_ids = report.get("case_ids", list(case_categories))
    if (
        not isinstance(case_ids, list)
        or not all(isinstance(c, str) for c in case_ids)
        or not 1 <= len(case_ids) <= MAX_CASES
        or len(case_ids) != len(set(case_ids))
    ):
        raise ValueError("Invalid case manifest")
    if report["scoring_version"] >= 3 and "case_ids" not in report:
        raise ValueError("Missing case manifest")
    if identities != {(case, repeat) for case in case_ids for repeat in range(1, repeats + 1)}:
        raise ValueError("Incomplete report case/repetition schedule")
    for key, value in {"passed": passed, "total": len(rows), "scored": scored, "errors": errors, "not_run": not_run}.items():
        if type(report[key]) is not int or report[key] != value:
            raise ValueError("Report summary contradicts its results: " + key)
    score = round(passed / len(rows), 6)
    if not _number(report["score"]) or report["score"] != score:
        raise ValueError("Report summary contradicts its score")
    if report["critical_failures"] != critical or not strict_equal(report["categories"], categories):
        raise ValueError("Report summary contradicts critical/category checks")
    gate = (
        scored == len(rows)
        and not critical
        and passed / len(rows) >= policy["fail_under"]
        and not any(r.get("measurement_error") for r in rows)
    )
    if type(report["gate_passed"]) is not bool or report["gate_passed"] != gate:
        raise ValueError("Report gate contradicts its results")
    durations.sort()
    latency = {
        "total": sum(durations),
        "median": statistics.median(durations) if durations else None,
        "p95": durations[math.ceil(len(durations) * 0.95) - 1] if durations else None,
    }
    if any(not strict_equal(report["latency_ms"][k], v) for k, v in latency.items()) or not strict_equal(
        report["tokens"], tokens
    ):
        raise ValueError("Report measurements contradict its results")
    subtotal = round(sum(c for c in costs if c is not None), 6)
    cost = report["cost"]
    if not _number(cost["known_api_subtotal_usd"]) or cost["known_api_subtotal_usd"] != subtotal:
        raise ValueError("Report API subtotal contradicts its requests")
    total_cost = (
        round(sum(c for c in costs if c is not None), 6) if scored == len(rows) and all(c is not None for c in costs) else None
    )
    if (cost["estimated_api_usd"] is not None and not _number(cost["estimated_api_usd"])) or cost[
        "estimated_api_usd"
    ] != total_cost:
        raise ValueError("Report API total contradicts its requests")
