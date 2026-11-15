"""Autonomous Detection Self-Tuning Engine (The Purple-Team Engine).

Iteratively refines candidate Sigma rules against adversary emulation telemetry
and benign system background noise until achieving 100% True-Positive capture
with 0% False Positives.

Closed-Loop Tuning Workflow:
1. Evaluate candidate rule against intrusion events (emulation) and baseline events (benign noise).
2. Check if rule is already perfect (100% recall, 0% FP).
3. If noisy (FP > 0), diagnose the firing selections and synthesize precise exclusion filters
   based on legitimate binary images, parent processes, or service accounts.
4. If missing attacks (FN > 0), diagnose the failing constraints and expand selection criteria
   or repair overly narrow field values.
5. Validate semantic integrity against `sigma_semantics.semantic_problem`.
6. Iterate until convergence or maximum iterations reached.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import yaml

from hecate_agent.core.emulation_runner import EmulationResult
from hecate_agent.core.llm_provider import LLMProvider
from hecate_agent.core.sigma_evaluator import EvaluationReport, SigmaEvaluator
from hecate_agent.core.sigma_semantics import semantic_problem

logger = logging.getLogger(__name__)

FIELD_ALIASES: Dict[str, str] = {
    "image": "Image",
    "process": "Image",
    "binary": "Image",
    "executable": "Image",
    "path": "Image",
    "filepath": "Image",
    "file_path": "Image",
    "directory": "Image",
    "folder": "Image",
    "commandline": "CommandLine",
    "command": "CommandLine",
    "cmd": "CommandLine",
    "args": "CommandLine",
    "arguments": "CommandLine",
    "user": "User",
    "username": "User",
    "account": "User",
    "parentimage": "ParentImage",
    "parent": "ParentImage",
    "parent_image": "ParentImage",
    "parentprocess": "ParentImage",
    "parent_process": "ParentImage",
    "parentcommandline": "ParentCommandLine",
    "parent_commandline": "ParentCommandLine",
    "parent_cmd": "ParentCommandLine",
    "currentdirectory": "CurrentDirectory",
    "originalfilename": "OriginalFileName",
    "targetfilename": "TargetFilename",
    "destinationip": "DestinationIp",
    "ip": "DestinationIp",
    "dest_ip": "DestinationIp",
    "destinationhostname": "DestinationHostname",
    "destinationport": "DestinationPort",
    "port": "DestinationPort",
    "dest_port": "DestinationPort",
    "hashes": "Hashes",
    "hash": "Hashes",
    "sha256": "Hashes",
    "md5": "Hashes",
    "scriptblocktext": "ScriptBlockText",
    "scriptblock": "ScriptBlockText",
    "eventid": "EventID",
    "provider_name": "Provider_Name",
    "queryname": "QueryName",
    "targetobject": "TargetObject",
    "details": "Details",
    "pipename": "PipeName",
    "imageloaded": "ImageLoaded",
    "eventsource": "eventSource",
    "eventname": "eventName",
    "operationname": "operationName",
    "resource": "resource",
}


@dataclass
class TuningIteration:
    """A single step in the self-tuning feedback loop."""

    iteration: int
    rule_yaml: str
    metrics: EvaluationReport
    actions_taken: List[str] = field(default_factory=list)


@dataclass
class SelfTuningReport:
    """Full summary of the self-tuning feedback loop execution."""

    initial_rule: str
    final_rule: str
    initial_metrics: EvaluationReport
    final_metrics: EvaluationReport
    history: List[TuningIteration] = field(default_factory=list)
    converged: bool = False
    total_iterations: int = 0

    @property
    def is_perfect(self) -> bool:
        """Whether the tuned rule achieved 100% recall with 0% noise."""
        return self.final_metrics.is_perfect

    @property
    def precision_improved(self) -> bool:
        """Whether precision improved through tuning."""
        return self.final_metrics.precision > self.initial_metrics.precision

    @property
    def recall_improved(self) -> bool:
        """Whether recall improved through tuning."""
        return self.final_metrics.recall > self.initial_metrics.recall

    def summary(self) -> str:
        """Format an executive purple-team tuning summary."""
        init_p = f"{self.initial_metrics.precision * 100:.1f}%"
        init_r = f"{self.initial_metrics.recall * 100:.1f}%"
        final_p = f"{self.final_metrics.precision * 100:.1f}%"
        final_r = f"{self.final_metrics.recall * 100:.1f}%"

        lines = [
            f"=== 🎯 Purple-Team Self-Tuning Engine: {self.final_metrics.rule_title} ===",
            f"  Status: {'CONVERGED (100% TP, 0% FP)' if self.converged else 'COMPLETED (Best Effort)'}",
            f"  Iterations: {self.total_iterations}",
            f"  Initial Metrics: Precision={init_p}, Recall={init_r} (TP={self.initial_metrics.true_positives}, FP={self.initial_metrics.false_positives}, FN={self.initial_metrics.false_negatives})",
            f"  Final Metrics:   Precision={final_p}, Recall={final_r} (TP={self.final_metrics.true_positives}, FP={self.final_metrics.false_positives}, FN={self.final_metrics.false_negatives})",
        ]
        if self.history:
            lines.append("  Tuning Actions Applied:")
            for step in self.history:
                for act in step.actions_taken:
                    lines.append(f"    - Iteration {step.iteration}: {act}")
        return "\n".join(lines)


class SigmaSelfTuner:
    """Self-tuning engine that autonomously optimizes Sigma detection rules."""

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        max_iterations: int = 3,
        strict_semantics: bool = True,
    ) -> None:
        self.llm_provider = llm_provider
        self.max_iterations = max_iterations
        self.strict_semantics = strict_semantics

    def _normalize_rule_dict(self, rule: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert YAML string or dict into a clean Python dictionary."""
        if isinstance(rule, dict):
            return dict(rule)
        try:
            parsed = yaml.safe_load(rule)
            return dict(parsed) if isinstance(parsed, dict) else {}
        except Exception as exc:
            logger.error("Failed to parse rule YAML: %s", exc)
            return {}

    def _synthesize_filter_for_fp(
        self,
        fp_events: List[Dict[str, Any]],
        intrusion_events: Sequence[Dict[str, Any]],
        current_detection: Dict[str, Any],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Synthesize a filter block targeting baseline FP events without excluding attacks."""
        if not fp_events:
            return None

        # Candidate discriminator fields in priority order
        discriminator_fields = ("Image", "User", "ParentImage", "CurrentDirectory")

        # Gather values used in intrusion events so we NEVER filter them
        intrusion_values: Dict[str, Set[str]] = {}
        for ev in intrusion_events:
            for f in discriminator_fields:
                val = ev.get(f)
                if val:
                    intrusion_values.setdefault(f, set()).add(str(val).lower())

        filter_constraints: Dict[str, Any] = {}

        # Look for baseline properties absent in all intrusion events
        for f in discriminator_fields:
            fp_vals = {str(ev[f]) for ev in fp_events if f in ev and ev[f]}
            safe_fp_vals = [v for v in fp_vals if v.lower() not in intrusion_values.get(f, set())]

            if safe_fp_vals:
                if len(safe_fp_vals) == 1:
                    filter_constraints[f] = safe_fp_vals[0]
                else:
                    filter_constraints[f] = sorted(safe_fp_vals)
                break  # Use the highest-priority differentiating field

        if not filter_constraints:
            return None

        # Generate a unique filter name
        filter_num = 1
        filter_name = "filter_legitimate"
        while filter_name in current_detection:
            filter_num += 1
            filter_name = f"filter_legitimate_{filter_num}"

        return filter_name, filter_constraints

    def _repair_rule_for_fn(
        self,
        rule_dict: Dict[str, Any],
        missed_events: List[Dict[str, Any]],
    ) -> List[str]:
        """Repair overly restrictive selections causing false negatives."""
        actions: List[str] = []
        detection = rule_dict.get("detection", {})

        for name, block in list(detection.items()):
            if name.lower() in ("condition", "timeframe") or not isinstance(block, dict):
                continue

            for key, val in list(block.items()):
                field_base = key.split("|")[0].strip()

                # If the rule has an Image constraint that missed the executed binary
                if field_base.lower() in ("image", "commandline"):
                    observed_vals = {str(ev[field_base]) for ev in missed_events if field_base in ev and ev[field_base]}
                    if observed_vals:
                        curr_vals = val if isinstance(val, list) else [val]
                        new_vals = list(curr_vals)
                        for obs in observed_vals:
                            if obs not in new_vals:
                                new_vals.append(obs)
                                actions.append(f"Expanded {key} to include observed value '{obs}'")
                        block[key] = new_vals if len(new_vals) > 1 else new_vals[0]

        return actions

    def _refine_programmatic(
        self,
        current_rule_dict: Dict[str, Any],
        report: EvaluationReport,
        intrusion_events: Sequence[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Programmatically refine the rule logic using diagnostic traces."""
        refined_dict = yaml.safe_load(yaml.dump(current_rule_dict))
        actions: List[str] = []
        detection = refined_dict.setdefault("detection", {})

        # 1. Address False Positives by adding an exclusion filter
        if report.false_positives > 0:
            res = self._synthesize_filter_for_fp(
                report.false_positive_events,
                intrusion_events,
                detection,
            )
            if res:
                filter_name, filter_block = res
                detection[filter_name] = filter_block

                # Update condition to include filter
                cond = str(detection.get("condition", "selection"))
                if "not " in cond:
                    new_cond = f"{cond} and not {filter_name}"
                else:
                    new_cond = f"({cond}) and not {filter_name}"
                detection["condition"] = new_cond
                actions.append(f"Added exclusion filter '{filter_name}' targeting {list(filter_block.keys())}")

        # 2. Address False Negatives by repairing overly restrictive constraints
        if report.false_negatives > 0:
            fn_actions = self._repair_rule_for_fn(refined_dict, report.missed_events)
            actions.extend(fn_actions)

        return refined_dict, actions

    def tune(
        self,
        rule: Union[str, Dict[str, Any]],
        intrusion_events: Sequence[Dict[str, Any]],
        baseline_events: Sequence[Dict[str, Any]],
    ) -> SelfTuningReport:
        """Run the autonomous detection self-tuning loop until convergence."""
        current_dict = self._normalize_rule_dict(rule)
        initial_yaml = yaml.dump(current_dict, sort_keys=False)

        # Baseline evaluation
        initial_eval = SigmaEvaluator.evaluate_rule(current_dict, intrusion_events, baseline_events)
        history: List[TuningIteration] = []

        best_dict = current_dict
        best_eval = initial_eval
        best_yaml = initial_yaml

        # If already perfect, return early
        if initial_eval.is_perfect:
            return SelfTuningReport(
                initial_rule=initial_yaml,
                final_rule=initial_yaml,
                initial_metrics=initial_eval,
                final_metrics=initial_eval,
                converged=True,
                total_iterations=0,
            )

        for i in range(1, self.max_iterations + 1):
            # Attempt refinement
            refined_dict, actions = self._refine_programmatic(best_dict, best_eval, intrusion_events)
            refined_yaml = yaml.dump(refined_dict, sort_keys=False)

            # Check semantic validity
            if self.strict_semantics:
                category = refined_dict.get("logsource", {}).get("category", "")
                sem_err = semantic_problem(refined_dict.get("detection", {}), category)
                if sem_err:
                    logger.warning("Refined rule failed semantic validation: %s", sem_err)
                    actions.append(f"Semantic validation warning: {sem_err}")

            # Re-evaluate refined rule
            new_eval = SigmaEvaluator.evaluate_rule(refined_dict, intrusion_events, baseline_events)
            iteration_step = TuningIteration(
                iteration=i,
                rule_yaml=refined_yaml,
                metrics=new_eval,
                actions_taken=actions,
            )
            history.append(iteration_step)

            # Accept if precision or recall improved without regressing the other
            improved = (new_eval.precision >= best_eval.precision and new_eval.recall >= best_eval.recall) and (
                new_eval.precision > best_eval.precision or new_eval.recall > best_eval.recall
            )

            if improved or new_eval.is_perfect:
                best_dict = refined_dict
                best_yaml = refined_yaml
                best_eval = new_eval

            if best_eval.is_perfect:
                break

        return SelfTuningReport(
            initial_rule=initial_yaml,
            final_rule=best_yaml,
            initial_metrics=initial_eval,
            final_metrics=best_eval,
            history=history,
            converged=best_eval.is_perfect,
            total_iterations=len(history),
        )

    def tune_emulation(
        self,
        rule: Union[str, Dict[str, Any]],
        emulation_result: EmulationResult,
        baseline_events: Sequence[Dict[str, Any]],
    ) -> SelfTuningReport:
        """Run self-tuning directly on telemetry harvested from an EmulationResult."""
        return self.tune(
            rule=rule,
            intrusion_events=emulation_result.events,
            baseline_events=baseline_events,
        )

    def _parse_single_clause(self, clause_text: str, default_action: str = "exclude") -> Tuple[str, str, str]:
        """Parse a single clause into (field_name, modifier, target_val)."""
        text = clause_text.strip()
        text = re.sub(r"(?i)^(?:where\s+|having\s+|with\s+|and\s+)", "", text).strip()
        tokens = text.split()
        if not tokens:
            return "", "", ""

        matched_alias = None
        val_part = ""
        explicit_mod = ""

        # Check two-word aliases first
        if len(tokens) >= 2:
            two_word = f"{tokens[0]} {tokens[1]}".lower()
            if two_word in FIELD_ALIASES:
                matched_alias = two_word
                val_part = text[len(tokens[0]) + 1 + len(tokens[1]):].strip()

        if not matched_alias:
            first_raw = tokens[0].rstrip(":=")
            first_base = first_raw.split("|")[0].lower()
            if first_base in FIELD_ALIASES:
                matched_alias = first_base
                explicit_mod = first_raw.split("|")[1] if "|" in first_raw else ""
                val_part = text[len(tokens[0]):].strip()

        if matched_alias:
            field_name = FIELD_ALIASES[matched_alias]
            mod = explicit_mod
            # Remove filler phrases
            val_clean = re.sub(
                r"(?i)^(?:to\s+include\s+|is\s+|equals?\s+|containing\s+|contains\s+|endswith\s+|ends\s+with\s+|startswith\s+|starts\s+with\s+|[:=]\s*)",
                "",
                val_part,
            ).strip()

            if not mod:
                if re.search(r"(?i)\b(?:containing|contains)\b", val_part):
                    mod = "contains"
                elif re.search(r"(?i)\b(?:endswith|ends\s+with)\b", val_part):
                    mod = "endswith"
                elif re.search(r"(?i)\b(?:startswith|starts\s+with)\b", val_part):
                    mod = "startswith"
                elif re.search(r"(?i)\b(?:equals?|is)\b", val_part):
                    mod = ""

            target_val = val_clean.strip(" :=\"'").strip()

            if not mod:
                if matched_alias in ("path", "filepath", "directory", "folder"):
                    mod = "startswith"
                elif field_name in ("Image", "ParentImage"):
                    if any(target_val.lower().endswith(ext) for ext in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".sh")):
                        mod = "endswith"
                    elif any(sep in target_val for sep in ("\\", "/")) and not target_val.endswith((".exe", ".dll")):
                        mod = "startswith"
                    else:
                        mod = "contains"
                elif field_name in ("CommandLine", "ParentCommandLine", "User"):
                    mod = "contains"
        else:
            target_val = text.strip(" :=\"'").strip()
            if any(target_val.lower().endswith(ext) for ext in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".sh")):
                field_name = "Image"
                mod = "endswith"
            elif any(target_val.startswith(p) for p in ("C:\\", "D:\\", "/usr/", "/bin/", "/etc/")) or ("\\" in target_val and not target_val.endswith(".exe")):
                field_name = "Image"
                mod = "startswith"
            elif any(u in target_val.upper() for u in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ADMIN")):
                field_name = "User"
                mod = "contains"
            elif target_val.startswith(("/", "-")):
                field_name = "CommandLine"
                mod = "contains"
            else:
                field_name = "CommandLine"
                mod = "contains"

        return field_name, mod, target_val

    def _parse_critique(self, critique: str) -> Tuple[str, List[Tuple[str, str, str]]]:
        """Parse analyst natural language critique into action and list of (field, mod, val)."""
        clean = critique.strip()
        clean = re.sub(r"<@[A-Za-z0-9]+>|@[\w.-]+", "", clean).strip()
        clean = re.sub(r"(?i)^(?:for\s+H-\d{4,}[,:\s]+)?(?:please\s+)?", "", clean).strip()
        clean = re.sub(r"(?i)^tune\s+", "", clean).strip()

        match_verb = re.match(
            r"(?i)^(exclude|filter\s+out|filter|ignore|suppress|omit|drop|broaden\s+to|expand\s+to|broaden|expand|include|add|allow)\b\s*(.*)",
            clean,
        )
        if match_verb:
            verb = match_verb.group(1).lower()
            rest = match_verb.group(2).strip()
            action_type = (
                "exclude"
                if any(v in verb for v in ["exclude", "filter", "ignore", "suppress", "omit", "drop"])
                else "include"
            )
        else:
            action_type = "exclude"
            rest = clean

        if not rest:
            return "unknown", []

        # Split compound clauses on secondary connectors like 'with parent', 'and parent', 'where parent'
        pattern = r"(?i)\s+(?:with|where|and|having)\s+(?=(?:parent(?:image|\s+process|\s+binary)?|commandline|cmd|user|image|path|process)\b)"
        raw_clauses = re.split(pattern, rest)

        clauses: List[Tuple[str, str, str]] = []
        for raw in raw_clauses:
            raw = raw.strip()
            if not raw:
                continue
            fld, mod, val = self._parse_single_clause(raw, default_action=action_type)
            if fld and val:
                clauses.append((fld, mod, val))

        return action_type, clauses

    def tune_rule(
        self,
        rule: Union[str, Dict[str, Any]],
        critique: str,
        events: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Tuple[str, str]:
        """Mutate a Sigma rule using natural language analyst feedback.

        Supports compound multi-field exclusion filters (e.g. 'exclude svchost.exe with parent services.exe',
        'filter path C:\\Program Files\\AdminTools'), inclusion broadening, and validates semantic
        integrity via `sigma_semantics.semantic_problem`.

        Returns:
            (updated_rule_yaml: str, action_summary: str)
        """
        rule_dict = self._normalize_rule_dict(rule)
        if not rule_dict:
            raise ValueError("Rule is not a valid YAML mapping")

        action_type, clauses = self._parse_critique(critique)
        if action_type == "unknown" or not clauses:
            raise ValueError(
                f"Could not understand tuning instruction: '{critique}'. "
                "Try instructions like 'Exclude svchost.exe with parent services.exe', "
                "'Filter path C:\\Program Files\\AdminTools', or 'Add Image pwsh.exe'."
            )

        detection = rule_dict.setdefault("detection", {})
        if not isinstance(detection, dict):
            raise ValueError("Rule 'detection' block is missing or not a mapping")

        if action_type == "exclude":
            filter_dict: Dict[str, Any] = {}
            name_parts: List[str] = []

            for fld, mod, val in clauses:
                fmt_val = val
                if mod == "endswith" and not fmt_val.startswith(("\\", "/")) and any(
                    fmt_val.lower().endswith(ext)
                    for ext in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".sh")
                ):
                    fmt_val = f"\\{fmt_val}"

                full_key = f"{fld}|{mod}" if mod else fld
                filter_dict[full_key] = fmt_val

                # Derive descriptive filter name from target values
                base = fmt_val.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                base = base.rsplit(".", 1)[0] if "." in base else base
                clean_base = re.sub(r"[^a-zA-Z0-9_]", "_", base).strip("_").lower()
                if clean_base and clean_base not in name_parts:
                    name_parts.append(clean_base)

            base_name = "_".join(name_parts[:2]) if name_parts else "exclusion"
            filter_name = f"filter_{base_name[:20]}"
            counter = 1
            while filter_name in detection:
                filter_name = f"filter_{base_name[:15]}_{counter}"
                counter += 1

            detection[filter_name] = filter_dict

            curr_cond = str(detection.get("condition", "selection")).strip()
            if "not " in curr_cond:
                new_cond = f"{curr_cond} and not {filter_name}"
            else:
                new_cond = f"({curr_cond}) and not {filter_name}"
            detection["condition"] = new_cond

            constraints_str = ", ".join(f"`{k}: {v}`" for k, v in filter_dict.items())
            summary = f"Added exclusion filter `{filter_name}`: {constraints_str}"

        else:  # action_type == "include"
            target_block = None
            for key in ["selection", "selection_main", "selection_1"]:
                if key in detection and isinstance(detection[key], dict):
                    target_block = detection[key]
                    break

            if not target_block:
                for key, val in detection.items():
                    if key not in ("condition", "timeframe") and isinstance(val, dict):
                        target_block = val
                        break

            actions: List[str] = []
            for fld, mod, val in clauses:
                full_key = f"{fld}|{mod}" if mod else fld
                if not target_block:
                    detection["selection_custom"] = {full_key: val}
                    curr_cond = str(detection.get("condition", "selection")).strip()
                    detection["condition"] = f"{curr_cond} or selection_custom"
                    actions.append(f"Added new selection block with `{full_key}: {val}`")
                    target_block = detection["selection_custom"]
                else:
                    existing_key = None
                    for k in target_block:
                        if k.split("|")[0].lower() == fld.lower():
                            existing_key = k
                            break

                    key_to_use = existing_key or full_key
                    curr_val = target_block.get(key_to_use)
                    if curr_val is None:
                        target_block[key_to_use] = val
                    elif isinstance(curr_val, list):
                        if val not in curr_val:
                            curr_val.append(val)
                    else:
                        if curr_val != val:
                            target_block[key_to_use] = [curr_val, val]

                    actions.append(f"Expanded `{key_to_use}` with `{val}`")

            summary = "; ".join(actions)

        # Semantic validation
        if self.strict_semantics:
            category = rule_dict.get("logsource", {}).get("category", "")
            sem_err = semantic_problem(detection, category)
            if sem_err:
                logger.warning("Tuned rule failed semantic validation: %s", sem_err)
                summary += f" (Semantic validation warning: {sem_err})"

        # Telemetry evaluation if events supplied
        if events:
            eval_res = SigmaEvaluator.evaluate_rule(rule_dict, intrusion_events=events, baseline_events=[])
            summary += f" (Evaluated: {eval_res.true_positives} TP hits on {len(events)} events)"

        updated_yaml = yaml.dump(rule_dict, sort_keys=False)
        return updated_yaml, summary
