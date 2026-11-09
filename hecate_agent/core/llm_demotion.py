"""Eval gates that keep high-stakes capabilities on the complex tier.

Demoting ``hypothesis`` / Sigma / triage / research synthesis to the simple
(local) backend requires either an explicit allow env, or a written gate stamp
from a passing ``hecate-agent eval --tier simple --write-gate …`` run.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from hecate_agent.core.eval_harness import FIXTURES, EvalReport, Fixture, run_eval
from hecate_agent.core.llm_provider import LLMProvider

logger = logging.getLogger(__name__)

# Must stay on complex unless a gate (or explicit allow) unlocks demotion.
COMPLEX_LOCKED_CAPABILITIES = frozenset(
    {
        "hypothesis",
        "sigma_draft",
        "sigma_review",
        "finding_triage",
        "research_synthesize",
    }
)

ALLOW_DEMOTION_ENV = "HECATE_LLM_ALLOW_DEMOTION"
GATE_FILE_ENV = "HECATE_LLM_DEMOTION_GATES"
DEFAULT_FAIL_UNDER = 0.8


@dataclass
class DemotionGateResult:
    """Outcome of scoring the simple backend before allowing a demotion."""

    capability: str
    allowed: bool
    score: float
    fail_under: float
    provider: str
    model: str
    reason: str = ""
    report: Optional[EvalReport] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "capability": self.capability,
            "allowed": self.allowed,
            "score": round(self.score, 3),
            "fail_under": self.fail_under,
            "provider": self.provider,
            "model": self.model,
            "reason": self.reason,
            "passed_at": datetime.now(UTC).isoformat(),
        }
        if self.report is not None:
            data["eval"] = {
                "passed": self.report.passed_count,
                "total": self.report.total_count,
            }
        return data


def demotion_allow_all() -> bool:
    """True when operators explicitly unlock all demotions (lab / experiments)."""
    return os.getenv(ALLOW_DEMOTION_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def demotion_gates_path(explicit: Optional[Path] = None) -> Path:
    """Resolve the demotion gate stamp file."""
    if explicit is not None:
        return explicit
    env = os.getenv(GATE_FILE_ENV, "").strip()
    if env:
        return Path(env)
    try:
        from hecate_agent.core.workspace import workspace_root

        return workspace_root() / ".hecate" / "llm_demotion_gates.json"
    except Exception:
        return Path.cwd() / ".hecate" / "llm_demotion_gates.json"


def load_demotion_gates(path: Optional[Path] = None) -> Dict[str, Any]:
    gate_path = demotion_gates_path(path)
    if not gate_path.is_file():
        return {}
    try:
        data = json.loads(gate_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read demotion gates %s: %s", gate_path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def demotion_unlocked(capability: str, *, path: Optional[Path] = None) -> bool:
    """Whether ``capability`` may be routed to simple despite COMPLEX_LOCKED."""
    name = str(capability).strip()
    if name not in COMPLEX_LOCKED_CAPABILITIES:
        return True
    if demotion_allow_all():
        return True
    stamp = load_demotion_gates(path).get(name)
    if not isinstance(stamp, dict):
        return False
    return bool(stamp.get("allowed")) and float(stamp.get("score") or 0) >= float(
        stamp.get("fail_under") or DEFAULT_FAIL_UNDER
    )


def apply_demotion_locks(
    mapping: Mapping[str, str],
    *,
    path: Optional[Path] = None,
) -> Dict[str, str]:
    """Force locked capabilities back to complex when no gate unlocks them."""
    out: Dict[str, str] = {str(k): str(v).lower() for k, v in mapping.items()}
    for capability in COMPLEX_LOCKED_CAPABILITIES:
        if out.get(capability) != "simple":
            continue
        if demotion_unlocked(capability, path=path):
            continue
        logger.warning(
            "Ignoring demotion of %s to simple: pass "
            "`hecate-agent eval --tier simple --write-gate %s --fail-under %.2f` "
            "or set %s=1",
            capability,
            capability,
            DEFAULT_FAIL_UNDER,
            ALLOW_DEMOTION_ENV,
        )
        out[capability] = "complex"
    return out


def write_demotion_gate(
    result: DemotionGateResult,
    *,
    path: Optional[Path] = None,
) -> Path:
    """Persist a gate stamp for ``result.capability``."""
    gate_path = demotion_gates_path(path)
    gate_path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_demotion_gates(gate_path)
    payload = result.to_dict()
    # Drop nested eval blob from the stamp file to keep it small.
    payload.pop("eval", None)
    existing[result.capability] = payload
    gate_path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return gate_path


def evaluate_demotion_gate(
    provider: LLMProvider,
    capability: str,
    *,
    fail_under: float = DEFAULT_FAIL_UNDER,
    fixtures: Optional[List[Fixture]] = None,
) -> DemotionGateResult:
    """Run the known-answer harness on ``provider`` and decide if demotion is allowed."""
    name = str(capability).strip()
    report = run_eval(provider, fixtures=fixtures if fixtures is not None else FIXTURES)
    score = report.score
    allowed = score >= fail_under
    reason = (
        f"score {score:.3f} meets fail_under {fail_under:.3f}"
        if allowed
        else f"score {score:.3f} below fail_under {fail_under:.3f}"
    )
    return DemotionGateResult(
        capability=name,
        allowed=allowed,
        score=score,
        fail_under=fail_under,
        provider=provider.provider_name,
        model=str(getattr(provider, "model", getattr(provider, "model_id", "unknown"))),
        reason=reason,
        report=report,
    )
