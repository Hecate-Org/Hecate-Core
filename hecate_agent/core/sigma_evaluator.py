"""In-process, in-memory Sigma Rule Evaluator.

Parses Sigma rules (YAML, dictionary, or pySigma SigmaRule) and evaluates them
against streams of telemetry events. Computes detection performance metrics:
True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN),
Precision, Recall, and F1-score, providing granular diagnostics on why events
matched or failed to match.

Supports:
- Standard Sigma detection structures (single/multiple selections, filters, lists of maps)
- Field value modifiers: contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte, windash
- Boolean conditions: not, and, or, parentheses, 1 of ..., all of ..., any of ..., X of ...
- Logsource matching and category aliasing
- Case-insensitive field resolution with Sysmon, Linux auditd, and OCSF taxonomy normalization
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import yaml

logger = logging.getLogger(__name__)

#: Canonical field aliases across Sysmon, Windows Events, Linux auditd, and OCSF.
#: Maps lowered field name to alternative representations found in telemetry.
FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "image": (
        "image",
        "process",
        "process_name",
        "process_path",
        "process.name",
        "process.file.path",
        "exe",
        "process_path_name",
    ),
    "commandline": (
        "commandline",
        "command_line",
        "cmdline",
        "process_command_line",
        "process.cmd_line",
        "process.command_line",
    ),
    "parentimage": (
        "parentimage",
        "parent_image",
        "parent_process",
        "parent_process_name",
        "process.parent_process.name",
        "process.parent_process.file.path",
    ),
    "parentcommandline": (
        "parentcommandline",
        "parent_command_line",
        "parent_cmdline",
        "process.parent_process.cmd_line",
    ),
    "user": (
        "user",
        "username",
        "user_name",
        "targetusername",
        "actor.user.name",
        "user.name",
        "subjectusername",
    ),
    "hashes": ("hashes", "hash", "md5", "sha256", "sha1", "file.hash"),
    "targetfilename": (
        "targetfilename",
        "target_filename",
        "file_name",
        "filename",
        "file_path",
        "file.path",
        "file.name",
    ),
    "imageloaded": (
        "imageloaded",
        "image_loaded",
        "module_path",
        "module.file.path",
        "loaded_module",
        "module_name",
    ),
    "destinationip": (
        "destinationip",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "dst_endpoint.ip",
        "destination.ip",
    ),
    "destinationport": (
        "destinationport",
        "destination_port",
        "dest_port",
        "dst_port",
        "dst_endpoint.port",
        "destination.port",
    ),
    "destinationhostname": (
        "destinationhostname",
        "destination_hostname",
        "dest_host",
        "dest_hostname",
        "dst_host",
        "dst_hostname",
        "dst_endpoint.hostname",
        "query_name",
        "queryname",
    ),
    "sourceip": ("sourceip", "source_ip", "src_ip", "src_endpoint.ip", "source.ip"),
    "sourceport": ("sourceport", "source_port", "src_port", "src_endpoint.port", "source.port"),
    "queryname": ("queryname", "query_name", "query", "dns_query", "query.hostname"),
    "targetobject": ("targetobject", "target_object", "reg_key", "key_path", "registry.key"),
    "details": ("details", "reg_value", "value_data", "registry.value"),
    "processid": ("processid", "process_id", "pid", "process.pid"),
    "parentprocessid": ("parentprocessid", "parent_process_id", "ppid", "process.parent_process.pid"),
    "ja4": ("ja4", "ssl.ja4", "tls.ja4", "network.tls.ja4"),
    "ja4s": ("ja4s", "ssl.ja4s", "tls.ja4s", "network.tls.ja4s"),
    "jarm": ("jarm", "ssl.jarm", "tls.jarm", "network.tls.jarm"),
    "ja3": ("ja3", "ssl.ja3", "tls.ja3", "network.tls.ja3"),
    "eventname": ("eventname", "event_name", "eventName", "operationName", "api_operation"),
    "eventsource": ("eventsource", "event_source", "eventSource", "serviceName"),
    "useridentity": ("useridentity", "user_identity", "userIdentity", "caller_identity", "user.name"),
    "rolearn": ("rolearn", "role_arn", "roleArn", "resource_arn"),
    "targetservice": ("targetservice", "target_service", "service_name", "target_app"),
}

#: Category normalization
CATEGORY_ALIASES: Dict[str, Tuple[str, ...]] = {
    "process_creation": ("process_creation", "process_activity", "process", "exec"),
    "file_event": ("file_event", "file_activity", "file_system_activity", "file"),
    "network_connection": ("network_connection", "network_activity", "network", "net"),
    "dns_query": ("dns_query", "dns_activity", "dns"),
    "registry_event": ("registry_event", "registry_key_activity", "registry_value_activity", "registry"),
    "image_load": ("image_load", "module_activity", "module_load"),
    "authentication": ("authentication", "logon", "auth"),
    "cloud_audit": (
        "cloud_audit",
        "cloud_trail",
        "cloud",
        "aws_cloudtrail",
        "gcp_audit",
        "azure_activity",
        "management_activity",
    ),
    "identity_audit": (
        "identity_audit",
        "identity_directory",
        "azure_signin",
        "entra_id",
        "active_directory",
        "directory_service",
    ),
    "container_activity": ("container_activity", "kubernetes_audit", "k8s_audit", "container_runtime"),
}


def base_field(key: Any) -> str:
    """Extract the base field name before any '|' modifier."""
    return str(key).split("|")[0].strip()


def extract_modifiers(key: Any) -> List[str]:
    """Extract all modifiers from a field specification (e.g. Field|contains|all)."""
    return [m.strip().lower() for m in str(key).split("|")[1:]]


def normalize_value_list(raw: Any) -> List[Any]:
    """Normalize a value specification to a list."""
    if raw is None:
        return [None]
    if isinstance(raw, (list, tuple, set)):
        return list(raw)
    return [raw]


def _resolve_nested_key(data: Dict[str, Any], dotted_key: str) -> Tuple[bool, Any]:
    """Resolve a dot-separated key in a nested dictionary."""
    parts = dotted_key.split(".")
    curr: Any = data
    for part in parts:
        if not isinstance(curr, dict):
            return False, None
        # Try direct match or case-insensitive match
        if part in curr:
            curr = curr[part]
        else:
            lowered = {k.lower(): k for k in curr}
            if part.lower() in lowered:
                curr = curr[lowered[part.lower()]]
            else:
                return False, None
    return True, curr


def get_event_field(event: Dict[str, Any], field_name: str) -> Tuple[bool, Any]:
    """Look up a field value in an event dictionary with casing and alias fallback.

    Prefers leaf values over intermediate container dicts. Returns (found, value).
    """
    target_low = field_name.lower()
    lowered_keys = {k.lower(): k for k in event if isinstance(k, str)}

    # 1. Exact match (prefer non-dict)
    if field_name in event and not isinstance(event[field_name], dict):
        return True, event[field_name]

    # 2. Case-insensitive direct match (prefer non-dict)
    if target_low in lowered_keys and not isinstance(event[lowered_keys[target_low]], dict):
        return True, event[lowered_keys[target_low]]

    # 3. Dotted nested lookup if field_name contains dots
    if "." in field_name:
        found, val = _resolve_nested_key(event, field_name)
        if found and not isinstance(val, dict):
            return True, val

    # 4. Alias lookup: prioritize dotted/specific paths first, then non-dotted, preferring non-dict values
    aliases = FIELD_ALIASES.get(target_low)
    if aliases:
        # First pass: dotted aliases (e.g. process.name, process.cmd_line, dst_endpoint.ip)
        for alias in aliases:
            if "." in alias:
                found, val = _resolve_nested_key(event, alias)
                if found and not isinstance(val, dict):
                    return True, val

        # Second pass: direct alias keys that are non-dict
        for alias in aliases:
            if "." not in alias:
                if alias in event and not isinstance(event[alias], dict):
                    return True, event[alias]
                if alias.lower() in lowered_keys and not isinstance(event[lowered_keys[alias.lower()]], dict):
                    return True, event[lowered_keys[alias.lower()]]

    # Fallback: if exact match was a dict
    if field_name in event:
        return True, event[field_name]
    if target_low in lowered_keys:
        return True, event[lowered_keys[target_low]]

    return False, None


def _match_scalar_value(needle: Any, haystack: Any, modifiers: List[str]) -> bool:
    """Match a single needle against a single haystack value using specified modifiers."""
    if needle is None:
        return haystack is None

    # A non-null needle cannot match a None or missing haystack
    if haystack is None:
        return False

    # Prevent dicts/collections from stringifying into Python repr syntax matches
    if isinstance(haystack, (dict, list, tuple, set)):
        return False

    # CIDR evaluation for IP networks
    if "cidr" in modifiers:
        try:
            net = ipaddress.ip_network(str(needle).strip(), strict=False)
            ip = ipaddress.ip_address(str(haystack).strip())
            return ip in net
        except ValueError:
            return False

    # Regular expression match
    if "re" in modifiers:
        try:
            return re.search(str(needle), str(haystack), re.IGNORECASE) is not None
        except re.error:
            return False

    # Numeric comparisons
    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        try:
            v_h = float(str(haystack))
            v_n = float(str(needle))
            if "gt" in modifiers:
                return v_h > v_n
            if "gte" in modifiers:
                return v_h >= v_n
            if "lt" in modifiers:
                return v_h < v_n
            if "lte" in modifiers:
                return v_h <= v_n
        except ValueError:
            return False

    s_needle = str(needle)
    if isinstance(haystack, bool):
        s_haystack = "true" if haystack else "false"
    else:
        s_haystack = str(haystack)

    # windash normalization: normalize Windows command line / and - switches
    if "windash" in modifiers:
        s_needle = s_needle.replace("/", "-")
        s_haystack = s_haystack.replace("/", "-")

    # Sigma wildcards remain active when string modifiers add implicit wildcards.
    # A backslash only escapes another backslash or a wildcard; ordinary Windows
    # path separators remain literal.
    parts: List[str] = []
    i = 0
    while i < len(s_needle):
        char = s_needle[i]
        if char == "\\" and i + 1 < len(s_needle) and s_needle[i + 1] in "\\*?":
            i += 1
            parts.append(re.escape(s_needle[i]))
        elif char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        i += 1
    prefix = ".*" if "contains" in modifiers or "endswith" in modifiers else ""
    suffix = ".*" if "contains" in modifiers or "startswith" in modifiers else ""
    return re.fullmatch(prefix + "".join(parts) + suffix, s_haystack, re.IGNORECASE | re.DOTALL) is not None


def match_field_value(raw_val: Any, event_val: Any, modifiers: List[str]) -> bool:
    """Match a field condition (possibly containing lists and |all) against an event value."""
    # Null check: Field: null matches if event_val is None or empty string
    if raw_val is None:
        return event_val is None or event_val == ""

    is_all = "all" in modifiers
    mods_no_all = [m for m in modifiers if m != "all"]
    needles = normalize_value_list(raw_val)

    def match_single_needle(needle: Any) -> bool:
        if isinstance(event_val, (list, tuple, set)):
            return any(_match_scalar_value(needle, item, mods_no_all) for item in event_val)
        if isinstance(event_val, dict):
            return any(_match_scalar_value(needle, v, mods_no_all) for v in event_val.values())
        return _match_scalar_value(needle, event_val, mods_no_all)

    if is_all:
        return all(match_single_needle(v) for v in needles)
    else:
        return any(match_single_needle(v) for v in needles)


# -----------------------------------------------------------------------------
# Condition Evaluator
# -----------------------------------------------------------------------------


class ConditionEvaluator:
    """Parses and evaluates a Sigma condition string over evaluated block states."""

    @staticmethod
    def tokenize(expr: str) -> List[Tuple[str, str]]:
        token_spec = [
            ("LPAREN", r"\("),
            ("RPAREN", r"\)"),
            ("COMMA", r","),
            ("AND", r"\b(?i:and)\b"),
            ("OR", r"\b(?i:or)\b"),
            ("NOT", r"\b(?i:not)\b"),
            ("OF", r"\b(?i:of)\b"),
            ("ALL", r"\b(?i:all)\b"),
            ("ANY", r"\b(?i:any)\b"),
            ("THEM", r"\b(?i:them)\b"),
            ("NUM", r"\b\d+\b"),
            ("ID", r"[a-zA-Z0-9_*?-]+"),
            ("WS", r"\s+"),
        ]
        tok_regex = "|".join("(?P<%s>%s)" % pair for pair in token_spec)
        tokens = []
        for mo in re.finditer(tok_regex, expr):
            kind = mo.lastgroup
            val = mo.group()
            if kind != "WS" and kind is not None:
                tokens.append((kind, val))
        return tokens

    def __init__(self, condition_str: str, blocks: Dict[str, bool]):
        self.tokens = self.tokenize(condition_str)
        self.pos = 0
        self.blocks = blocks

    def peek(self) -> Tuple[str, str]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return ("EOF", "")

    def consume(self, expected_kind: Optional[str] = None) -> Tuple[str, str]:
        tok = self.peek()
        if expected_kind and tok[0] != expected_kind:
            raise ValueError(f"Expected {expected_kind}, got {tok[0]} ({tok[1]})")
        self.pos += 1
        return tok

    def evaluate(self) -> bool:
        if not self.tokens:
            return True
        res = self.expr()
        if self.pos < len(self.tokens):
            raise ValueError(f"Unexpected token after condition: {self.tokens[self.pos]}")
        return res

    def expr(self) -> bool:
        return self.or_expr()

    def or_expr(self) -> bool:
        res = self.and_expr()
        while self.peek()[0] == "OR":
            self.consume("OR")
            right = self.and_expr()
            res = res or right
        return res

    def and_expr(self) -> bool:
        res = self.not_expr()
        while self.peek()[0] == "AND":
            self.consume("AND")
            right = self.not_expr()
            res = res and right
        return res

    def not_expr(self) -> bool:
        if self.peek()[0] == "NOT":
            self.consume("NOT")
            return not self.not_expr()
        return self.atom()

    def atom(self) -> bool:
        tok = self.peek()
        # Quantifier: 1 of ..., all of ..., any of ...
        if tok[0] in ("NUM", "ALL", "ANY"):
            if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1][0] == "OF":
                return self.quantifier()

        if tok[0] == "LPAREN":
            self.consume("LPAREN")
            res = self.expr()
            self.consume("RPAREN")
            return res

        if tok[0] in ("ID", "THEM"):
            tok = self.consume()
            # Wildcard pattern shorthand, e.g. 'selection*'
            if "*" in tok[1] or "?" in tok[1]:
                return self._eval_pattern("1", [tok[1]])
            return self.blocks.get(tok[1], False)

        raise ValueError(f"Unexpected token in condition atom: {tok}")

    def quantifier(self) -> bool:
        q_tok = self.consume()
        self.consume("OF")
        patterns: List[str] = []
        next_tok = self.peek()
        if next_tok[0] == "THEM":
            self.consume("THEM")
            patterns = ["*"]
        elif next_tok[0] == "LPAREN":
            self.consume("LPAREN")
            while self.peek()[0] != "RPAREN" and self.peek()[0] != "EOF":
                p_tok = self.consume()
                if p_tok[0] in ("ID", "THEM"):
                    patterns.append(p_tok[1] if p_tok[0] == "ID" else "*")
                if self.peek()[0] == "COMMA":
                    self.consume("COMMA")
            self.consume("RPAREN")
        elif next_tok[0] == "ID":
            patterns = [self.consume("ID")[1]]
        else:
            raise ValueError(f"Invalid target for quantifier: {next_tok}")

        return self._eval_pattern(q_tok[1].lower(), patterns)

    def _eval_pattern(self, quant: str, patterns: List[str]) -> bool:
        matching_blocks: Set[str] = set()
        for pat in patterns:
            for block_name in self.blocks:
                if fnmatch.fnmatch(block_name.lower(), pat.lower()):
                    matching_blocks.add(block_name)

        matched_list = list(matching_blocks)
        if not matched_list:
            return False

        true_count = sum(1 for name in matched_list if self.blocks.get(name, False))
        total = len(matched_list)

        if quant == "all":
            return true_count == total
        elif quant in ("1", "any"):
            return true_count >= 1
        else:
            try:
                target = int(quant)
                return true_count >= target
            except ValueError:
                return False


# -----------------------------------------------------------------------------
# Diagnostics & Evaluation Reports
# -----------------------------------------------------------------------------


@dataclass
class EventMatchDiagnostic:
    """Detailed diagnostic information for a single event evaluation."""

    event: Dict[str, Any]
    matched: bool
    is_intrusion: bool
    logsource_matched: bool
    block_results: Dict[str, bool] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)


@dataclass
class EvaluationReport:
    """Results of evaluating a Sigma rule against an event stream."""

    rule_title: str
    rule_id: Optional[str] = None
    category: Optional[str] = None
    product: Optional[str] = None

    total_events: int = 0
    intrusion_events_count: int = 0
    baseline_events_count: int = 0

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    triggering_events: List[Dict[str, Any]] = field(default_factory=list)
    false_positive_events: List[Dict[str, Any]] = field(default_factory=list)
    missed_events: List[Dict[str, Any]] = field(default_factory=list)

    diagnostics: List[EventMatchDiagnostic] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def fired_on_intrusion(self) -> bool:
        """Whether the rule successfully fired on any intrusion telemetry."""
        return self.true_positives > 0

    @property
    def is_clean(self) -> bool:
        """Whether the rule has 0 false positives on baseline telemetry."""
        return self.false_positives == 0

    @property
    def is_perfect(self) -> bool:
        """100% recall with 0% false positives."""
        return self.false_positives == 0 and self.false_negatives == 0 and self.intrusion_events_count > 0

    def summary(self) -> str:
        """Format a human-readable summary of the evaluation results."""
        prec_pct = f"{self.precision * 100:.1f}%"
        rec_pct = f"{self.recall * 100:.1f}%"
        f1_pct = f"{self.f1_score * 100:.1f}%"
        return (
            f"Rule '{self.rule_title}' (Category: {self.category or 'any'}):\n"
            f"  Events Evaluated: {self.total_events} (Intrusion: {self.intrusion_events_count}, Baseline: {self.baseline_events_count})\n"
            f"  Confusion Matrix: TP={self.true_positives}, FP={self.false_positives}, FN={self.false_negatives}, TN={self.true_negatives}\n"
            f"  Metrics: Precision={prec_pct}, Recall={rec_pct}, F1={f1_pct}\n"
            f"  Status: {'PERFECT' if self.is_perfect else 'CLEAN (No FP)' if self.is_clean else 'NOISY (Has FP)'}"
        )


# -----------------------------------------------------------------------------
# Sigma Evaluator
# -----------------------------------------------------------------------------


class SigmaEvaluator:
    """In-process evaluator executing Sigma rules against telemetry event streams."""

    def __init__(
        self,
        rule: Union[str, Dict[str, Any], Any],
        strict_logsource: bool = False,
    ):
        """Initialize the evaluator with a rule YAML string, dict, or pySigma SigmaRule."""
        self.strict_logsource = strict_logsource
        self.raw_rule = rule
        self.rule_dict: Dict[str, Any] = {}
        self.errors: List[str] = []

        self._parse_rule(rule)

        # Extract primary metadata
        self.title: str = str(self.rule_dict.get("title", "Untitled Rule"))
        self.rule_id: Optional[str] = self.rule_dict.get("id")

        logsource = self.rule_dict.get("logsource", {})
        if isinstance(logsource, dict):
            self.category: Optional[str] = logsource.get("category")
            self.product: Optional[str] = logsource.get("product")
            self.service: Optional[str] = logsource.get("service")
        else:
            self.category = None
            self.product = None
            self.service = None

        self.detection: Dict[str, Any] = self.rule_dict.get("detection", {})
        raw_cond = self.detection.get("condition", "selection")
        if isinstance(raw_cond, list) and raw_cond:
            self.condition_str: str = " or ".join(f"({condition})" for condition in raw_cond)
        else:
            self.condition_str = str(raw_cond)

    def _parse_rule(self, rule: Union[str, Dict[str, Any], Any]) -> None:
        if isinstance(rule, dict):
            self.rule_dict = rule
        elif isinstance(rule, str):
            try:
                parsed = yaml.safe_load(rule)
                if isinstance(parsed, dict):
                    self.rule_dict = parsed
                else:
                    self.errors.append("Rule YAML parsed to non-dict")
            except Exception as exc:
                self.errors.append(f"YAML parsing failed: {exc}")
        elif hasattr(rule, "to_dict"):
            try:
                self.rule_dict = rule.to_dict()
            except Exception as exc:
                self.errors.append(f"Rule to_dict() failed: {exc}")
        else:
            # Try inspection of pySigma SigmaRule attributes
            try:
                self.rule_dict = {
                    "title": getattr(rule, "title", ""),
                    "id": getattr(rule, "id", None),
                    "logsource": {
                        "category": getattr(getattr(rule, "logsource", None), "category", None),
                        "product": getattr(getattr(rule, "logsource", None), "product", None),
                        "service": getattr(getattr(rule, "logsource", None), "service", None),
                    },
                    "detection": getattr(rule, "detection", {}),
                }
            except Exception as exc:
                self.errors.append(f"Failed to extract rule dictionary: {exc}")

    def matches_logsource(self, event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Check if an event matches the rule's logsource requirements."""
        if not self.category and not self.product and not self.service:
            return True, None

        # Check Category
        if self.category:
            ev_cat = event.get("category") or event.get("event_type") or event.get("class")
            if ev_cat is not None:
                ev_cat_str = str(ev_cat).lower()
                target_cat = self.category.lower()
                # Check direct or alias match
                allowed = CATEGORY_ALIASES.get(target_cat, (target_cat,))
                if ev_cat_str not in allowed and target_cat not in CATEGORY_ALIASES.get(ev_cat_str, (ev_cat_str,)):
                    return False, f"Event category '{ev_cat}' does not match rule category '{self.category}'"
            elif self.strict_logsource:
                return False, f"Event missing category for strict rule category '{self.category}'"

        # Check Product / Platform / OS
        if self.product:
            ev_prod = event.get("product") or event.get("platform") or event.get("os")
            if ev_prod is not None:
                if str(ev_prod).lower() != self.product.lower():
                    return False, f"Event product '{ev_prod}' does not match rule product '{self.product}'"
            elif self.strict_logsource:
                return False, f"Event missing product for strict rule product '{self.product}'"

        return True, None

    def _evaluate_field(self, key: str, raw_val: Any, event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        field_name = base_field(key)
        modifiers = extract_modifiers(key)

        found, ev_val = get_event_field(event, field_name)
        if not found:
            # Null check: field is missing or None
            if raw_val is None:
                return True, None
            return False, f"Field '{field_name}' not found in event"

        if raw_val is None:
            if ev_val is not None and ev_val != "":
                return False, f"Field '{field_name}' expected null/empty, got '{ev_val}'"
            return True, None

        matched = match_field_value(raw_val, ev_val, modifiers)
        if not matched:
            return False, f"Field '{field_name}' value '{ev_val}' did not match condition '{raw_val}' (mods: {modifiers})"
        return True, None

    def _evaluate_block_map(self, block_map: Dict[str, Any], event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Evaluate a dictionary of field conditions (AND-ed)."""
        reasons: List[str] = []
        for key, raw_val in block_map.items():
            matched, reason = self._evaluate_field(key, raw_val, event)
            if not matched:
                if reason:
                    reasons.append(reason)
                return False, reasons
        return True, reasons

    def evaluate_block(self, block_name: str, block: Any, event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Evaluate a named detection block (selection or filter)."""
        if isinstance(block, list):
            # A list of maps is OR-ed
            all_reasons: List[str] = []
            for item in block:
                if isinstance(item, dict):
                    matched, reasons = self._evaluate_block_map(item, event)
                    if matched:
                        return True, []
                    all_reasons.extend(reasons)
                else:
                    # Keyword search across all event values
                    found_any = False
                    for v in event.values():
                        if _match_scalar_value(item, v, []):
                            found_any = True
                            break
                    if found_any:
                        return True, []
            return False, all_reasons
        elif isinstance(block, dict):
            return self._evaluate_block_map(block, event)
        return False, [f"Unrecognized block structure in '{block_name}'"]

    def evaluate_event(self, event: Dict[str, Any], is_intrusion: bool = False) -> EventMatchDiagnostic:
        """Evaluate a single event against this Sigma rule and produce diagnostic details."""
        log_match, log_reason = self.matches_logsource(event)
        if not log_match:
            return EventMatchDiagnostic(
                event=event,
                matched=False,
                is_intrusion=is_intrusion,
                logsource_matched=False,
                reasons=[log_reason] if log_reason else ["Logsource mismatch"],
            )

        block_results: Dict[str, bool] = {}
        reasons: List[str] = []

        # Evaluate each named block
        for name, block in self.detection.items():
            if name.lower() in ("condition", "timeframe"):
                continue
            matched, block_reasons = self.evaluate_block(str(name), block, event)
            block_results[str(name)] = matched
            if not matched:
                reasons.extend(block_reasons)

        # Evaluate overall condition
        try:
            cond_eval = ConditionEvaluator(self.condition_str, block_results)
            overall_matched = cond_eval.evaluate()
        except Exception as exc:
            overall_matched = False
            reasons.append(f"Condition evaluation error on '{self.condition_str}': {exc}")

        return EventMatchDiagnostic(
            event=event,
            matched=overall_matched,
            is_intrusion=is_intrusion,
            logsource_matched=True,
            block_results=block_results,
            reasons=reasons,
        )

    def matches(self, event: Dict[str, Any]) -> bool:
        """Determine if an event triggers this Sigma rule."""
        diag = self.evaluate_event(event)
        return diag.matched

    def evaluate_stream(
        self,
        intrusion_events: Sequence[Dict[str, Any]],
        baseline_events: Sequence[Dict[str, Any]],
    ) -> EvaluationReport:
        """Evaluate distinct intrusion and baseline telemetry event streams."""
        tp_events: List[Dict[str, Any]] = []
        fn_events: List[Dict[str, Any]] = []
        fp_events: List[Dict[str, Any]] = []
        tn_events: List[Dict[str, Any]] = []
        diagnostics: List[EventMatchDiagnostic] = []

        # Intrusion events (ground truth: should trigger)
        for ev in intrusion_events:
            diag = self.evaluate_event(ev, is_intrusion=True)
            diagnostics.append(diag)
            if diag.matched:
                tp_events.append(ev)
            else:
                fn_events.append(ev)

        # Baseline events (ground truth: should NOT trigger)
        for ev in baseline_events:
            diag = self.evaluate_event(ev, is_intrusion=False)
            diagnostics.append(diag)
            if diag.matched:
                fp_events.append(ev)
            else:
                tn_events.append(ev)

        tp = len(tp_events)
        fp = len(fp_events)
        fn = len(fn_events)
        tn = len(tn_events)

        total_int = len(intrusion_events)
        total_base = len(baseline_events)
        total = total_int + total_base

        # Metrics calculation
        if (tp + fp) > 0:
            precision = tp / (tp + fp)
        else:
            # If no triggers at all, precision is 1.0 if clean, 0.0 if intrusion events were missed
            precision = 1.0 if total_int == 0 else 0.0

        if (tp + fn) > 0:
            recall = tp / (tp + fn)
        else:
            recall = 1.0

        if (precision + recall) > 0:
            f1 = 2 * (precision * recall) / (precision + recall)
        else:
            f1 = 0.0

        return EvaluationReport(
            rule_title=self.title,
            rule_id=self.rule_id,
            category=self.category,
            product=self.product,
            total_events=total,
            intrusion_events_count=total_int,
            baseline_events_count=total_base,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            triggering_events=tp_events,
            false_positive_events=fp_events,
            missed_events=fn_events,
            diagnostics=diagnostics,
            errors=list(self.errors),
        )

    def evaluate(
        self,
        events: Sequence[Dict[str, Any]],
        default_label: Optional[str] = None,
    ) -> EvaluationReport:
        """Evaluate a mixed sequence of events containing labels or boolean flags."""
        intrusion: List[Dict[str, Any]] = []
        baseline: List[Dict[str, Any]] = []

        for ev in events:
            # Check label indicators
            is_int = False
            if "_label" in ev:
                is_int = str(ev["_label"]).lower() in ("intrusion", "attack", "malicious", "positive")
            elif "is_intrusion" in ev:
                is_int = bool(ev["is_intrusion"])
            elif "is_malicious" in ev:
                is_int = bool(ev["is_malicious"])
            elif default_label:
                is_int = default_label.lower() in ("intrusion", "attack", "malicious", "positive")

            if is_int:
                intrusion.append(ev)
            else:
                baseline.append(ev)

        return self.evaluate_stream(intrusion, baseline)

    @classmethod
    def evaluate_rule(
        cls,
        rule: Union[str, Dict[str, Any], Any],
        intrusion_events: Sequence[Dict[str, Any]],
        baseline_events: Sequence[Dict[str, Any]],
        strict_logsource: bool = False,
    ) -> EvaluationReport:
        """One-shot helper to initialize evaluator and return evaluation metrics."""
        evaluator = cls(rule, strict_logsource=strict_logsource)
        return evaluator.evaluate_stream(intrusion_events, baseline_events)
