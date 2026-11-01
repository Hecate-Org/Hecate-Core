"""AST-level Semantic Subsumption and Deduplication Analyzer for Sigma Rules.

Provides AST decomposition, normal form evaluation, and formal boolean subsumption
checking between Sigma detection rules. Identifies:
  1. EQUIVALENT (Duplicates): Rules specifying identical detection spaces even if
     formatted differently, using wildcards instead of modifiers, or reordered keys.
  2. SUBSUMES: Rule A is broader than Rule B (any event triggering Rule B is guaranteed
     to trigger Rule A, making Rule B redundant when Rule A is active).
  3. SUBSUMED_BY: Rule A is narrower than Rule B (Rule A is covered by Rule B).
  4. OVERLAPPING: Rules targeting the same log source and sharing significant
     detection constraints without strict logical subsumption (consolidation candidates).
  5. DISJOINT: Rules targeting different log sources or mutually exclusive telemetry.
  6. INTERNAL REDUNDANCY: Dead code or subsumed selection blocks within the same rule.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

import yaml

from hecate_agent.core.sigma_evaluator import (
    CATEGORY_ALIASES,
    FIELD_ALIASES,
    base_field,
    extract_modifiers,
    normalize_value_list,
)

logger = logging.getLogger(__name__)


class SubsumptionRelation(str, Enum):
    """Logical relationship between two Sigma detection rules."""

    EQUIVALENT = "EQUIVALENT"  # A <=> B: identical detection space (duplicate)
    SUBSUMES = "SUBSUMES"  # B => A: A is broader than B (B is redundant if A is active)
    SUBSUMED_BY = "SUBSUMED_BY"  # A => B: A is narrower than B (A is covered by B)
    OVERLAPPING = "OVERLAPPING"  # A and B intersect non-trivially without strict implication
    DISJOINT = "DISJOINT"  # A and B cannot match the same event or use different log sources


# -----------------------------------------------------------------------------
# 1. Constraint-Level AST: FieldConstraint
# -----------------------------------------------------------------------------


def _canonicalize_field(name: str) -> str:
    """Normalize field name to lower-case canonical form."""
    lowered = name.strip().lower()
    for canon, aliases in FIELD_ALIASES.items():
        if lowered == canon or lowered in aliases:
            return canon
    return lowered


def _canonicalize_value_and_modifier(val: Any, modifiers: List[str]) -> Tuple[str, List[str]]:
    """Canonicalize a single value and implicit wildcard modifiers.

    Converts wildcard patterns like '*\\whoami.exe' into ('\\whoami.exe', ['endswith'])
    so syntactic variations produce identical AST representations.
    """
    s_val = str(val).strip()
    mods = [m.lower() for m in modifiers]

    # windash: replace '/' with '-'
    if "windash" in mods:
        s_val = s_val.replace("/", "-")

    # If already has explicit string modifiers, keep them
    if any(m in mods for m in ("contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte")):
        return s_val.lower(), mods

    # Check for implicit wildcard syntax: *foo*, *foo, foo*
    if s_val.startswith("*") and s_val.endswith("*") and len(s_val) > 2:
        mods.append("contains")
        s_val = s_val[1:-1]
    elif s_val.startswith("*") and len(s_val) > 1 and "*" not in s_val[1:]:
        mods.append("endswith")
        s_val = s_val[1:]
    elif s_val.endswith("*") and len(s_val) > 1 and "*" not in s_val[:-1]:
        mods.append("startswith")
        s_val = s_val[:-1]

    return s_val.lower(), mods


def _scalar_subsumes(val_a: str, mods_a: Sequence[str], val_b: str, mods_b: Sequence[str]) -> bool:
    """Check if atomic constraint (val_a, mods_a) subsumes (val_b, mods_b).

    Returns True if every string/value matching b is guaranteed to match a.
    """
    s_a = str(val_a).lower()
    s_b = str(val_b).lower()

    # CIDR evaluation
    if "cidr" in mods_a:
        try:
            net_a = ipaddress.ip_network(s_a.strip(), strict=False)
            if "cidr" in mods_b:
                net_b = ipaddress.ip_network(s_b.strip(), strict=False)
                if isinstance(net_a, ipaddress.IPv4Network) and isinstance(net_b, ipaddress.IPv4Network):
                    return net_b.subnet_of(net_a)
                if isinstance(net_a, ipaddress.IPv6Network) and isinstance(net_b, ipaddress.IPv6Network):
                    return net_b.subnet_of(net_a)
                return False
            else:
                ip_b = ipaddress.ip_address(s_b.strip())
                return ip_b in net_a
        except ValueError:
            return False

    # Numeric comparisons
    if any(m in mods_a for m in ("gt", "gte", "lt", "lte")):
        try:
            num_a = float(s_a.strip())
            num_b = float(s_b.strip())
            if "gt" in mods_a:
                if "gt" in mods_b:
                    return num_a <= num_b  # x > 200 => x > 100
                if "gte" in mods_b:
                    return num_a < num_b
            if "gte" in mods_a and ("gte" in mods_b or "gt" in mods_b):
                return num_a <= num_b
            if "lt" in mods_a:
                if "lt" in mods_b:
                    return num_a >= num_b  # x < 200 => x < 500
                if "lte" in mods_b:
                    return num_a > num_b
            if "lte" in mods_a and ("lte" in mods_b or "lt" in mods_b):
                return num_a >= num_b
        except ValueError:
            return False

    # Regex matching
    if "re" in mods_a or "re" in mods_b:
        return s_a == s_b

    # String modifier subsumption
    has_contains_a = "contains" in mods_a
    has_starts_a = "startswith" in mods_a
    has_ends_a = "endswith" in mods_a
    is_exact_a = not (has_contains_a or has_starts_a or has_ends_a)

    has_contains_b = "contains" in mods_b
    has_starts_b = "startswith" in mods_b
    has_ends_b = "endswith" in mods_b
    is_exact_b = not (has_contains_b or has_starts_b or has_ends_b)

    # Rule A has 'contains'
    if has_contains_a:
        # contains(s_a) subsumes contains(s_b) if s_a in s_b
        if has_contains_b:
            return s_a in s_b
        # contains(s_a) subsumes startswith(s_b) / endswith(s_b) / exact(s_b) if s_a in s_b
        return s_a in s_b

    # Rule A has 'startswith'
    if has_starts_a:
        if has_starts_b or is_exact_b:
            return s_b.startswith(s_a)
        return False

    # Rule A has 'endswith'
    if has_ends_a:
        if has_ends_b or is_exact_b:
            return s_b.endswith(s_a)
        return False

    # Rule A is exact
    if is_exact_a:
        if is_exact_b:
            return s_a == s_b
        return False

    return False


@dataclass(frozen=True)
class FieldConstraint:
    """AST representation of a field constraint in a selection block."""

    field: str  # canonical normalized field name
    modifiers: Tuple[str, ...]
    values: Tuple[str, ...]
    is_all: bool = False

    @classmethod
    def from_raw(cls, raw_key: Any, raw_value: Any) -> "FieldConstraint":
        base = _canonicalize_field(base_field(raw_key))
        raw_mods = extract_modifiers(raw_key)
        is_all = "all" in raw_mods
        active_mods = [m for m in raw_mods if m != "all"]

        raw_list = normalize_value_list(raw_value)
        norm_values: List[str] = []
        combined_mods: Set[str] = set(active_mods)

        for item in raw_list:
            if item is None:
                norm_values.append("")
                continue
            v_str, derived_mods = _canonicalize_value_and_modifier(item, active_mods)
            norm_values.append(v_str)
            combined_mods.update(derived_mods)

        # Deduplicate and sort values for deterministic AST identity
        unique_values = tuple(sorted(dict.fromkeys(norm_values)))
        sorted_mods = tuple(sorted(combined_mods))
        return cls(
            field=base,
            modifiers=sorted_mods,
            values=unique_values,
            is_all=is_all,
        )

    def subsumes(self, other: "FieldConstraint") -> bool:
        """Check if self logically subsumes other on the same field."""
        if self.field != other.field:
            return False

        # Case 1: Both are standard OR-lists (is_all = False)
        # Every value in other must be covered by at least one value in self.
        if not self.is_all and not other.is_all:
            for v_b in other.values:
                covered = any(_scalar_subsumes(v_a, self.modifiers, v_b, other.modifiers) for v_a in self.values)
                if not covered:
                    return False
            return True

        # Case 2: Both are AND-lists (is_all = True)
        # Every value required by self must be satisfied by a value in other.
        if self.is_all and other.is_all:
            for v_a in self.values:
                satisfied = any(_scalar_subsumes(v_a, self.modifiers, v_b, other.modifiers) for v_b in other.values)
                if not satisfied:
                    return False
            return True

        # Case 3: self is OR, other is AND
        # If any single value in self is satisfied by any value in other, self holds.
        if not self.is_all and other.is_all:
            return any(
                _scalar_subsumes(v_a, self.modifiers, v_b, other.modifiers) for v_a in self.values for v_b in other.values
            )

        # Case 4: self is AND, other is OR
        # An AND cannot generally subsume an OR unless all elements match.
        return False

    def value_overlap(self, other: "FieldConstraint") -> float:
        """Compute overlap score between 0.0 and 1.0 for matching values."""
        if self.field != other.field:
            return 0.0
        set_a = set(self.values)
        set_b = set(other.values)
        if not set_a or not set_b:
            return 0.0
        inter = len(set_a & set_b)
        union = len(set_a | set_b)
        if union == 0:
            return 0.0
        exact_score = inter / union
        # Check partial substring overlaps
        partial_hits = sum(1 for a in set_a for b in set_b if (a and b and (a in b or b in a)))
        partial_score = min(1.0, partial_hits / max(len(set_a), len(set_b)))
        return max(exact_score, partial_score * 0.8)


# -----------------------------------------------------------------------------
# 2. Conjunction-Level AST: ConjunctionAST
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ConjunctionAST:
    """AST representation of a conjunction of field constraints (AND)."""

    constraints: Tuple[FieldConstraint, ...]

    @property
    def fields(self) -> FrozenSet[str]:
        return frozenset(c.field for c in self.constraints)

    @classmethod
    def from_dict(cls, block: Dict[str, Any]) -> "ConjunctionAST":
        constraints = [FieldConstraint.from_raw(k, v) for k, v in block.items() if isinstance(k, str)]
        # Sort constraints by field name for deterministic representation
        sorted_constraints = tuple(sorted(constraints, key=lambda c: (c.field, c.modifiers)))
        return cls(constraints=sorted_constraints)

    def get_constraint(self, field_name: str) -> Optional[FieldConstraint]:
        for c in self.constraints:
            if c.field == field_name:
                return c
        return None

    def subsumes(self, other: "ConjunctionAST") -> bool:
        """Check if self subsumes other.

        An event satisfying other satisfies self if for every constraint in self,
        there is a corresponding constraint in other that is subsumed by it.
        (Having fewer constraints makes self broader / subsuming).
        """
        for c_self in self.constraints:
            c_other = other.get_constraint(c_self.field)
            if c_other is None:
                return False
            if not c_self.subsumes(c_other):
                return False
        return True

    def similarity(self, other: "ConjunctionAST") -> float:
        """Compute structural and semantic similarity between two conjunctions."""
        common_fields = self.fields & other.fields
        all_fields = self.fields | other.fields
        if not all_fields:
            return 1.0
        jaccard_fields = len(common_fields) / len(all_fields)
        if not common_fields:
            return 0.0

        constraint_overlaps: List[float] = []
        for f in common_fields:
            c_a = self.get_constraint(f)
            c_b = other.get_constraint(f)
            if c_a and c_b:
                constraint_overlaps.append(c_a.value_overlap(c_b))

        avg_val_overlap = sum(constraint_overlaps) / len(constraint_overlaps) if constraint_overlaps else 0.0
        return (0.4 * jaccard_fields) + (0.6 * avg_val_overlap)


# -----------------------------------------------------------------------------
# 3. Rule AST & DNF Expansion: SigmaRuleAST
# -----------------------------------------------------------------------------


def _normalize_category(cat: Any) -> str:
    """Normalize logsource category using CATEGORY_ALIASES."""
    raw = str(cat or "").strip().lower()
    for canon, aliases in CATEGORY_ALIASES.items():
        if raw == canon or raw in aliases:
            return canon
    return raw


class ConditionTokenKind(str, Enum):
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    OF = "OF"
    ALL = "ALL"
    ANY = "ANY"
    THEM = "THEM"
    NUM = "NUM"
    ID = "ID"


def _tokenize_condition(expr: str) -> List[Tuple[ConditionTokenKind, str]]:
    spec = [
        (ConditionTokenKind.LPAREN, r"\("),
        (ConditionTokenKind.RPAREN, r"\)"),
        (ConditionTokenKind.AND, r"\b(?i:and)\b"),
        (ConditionTokenKind.OR, r"\b(?i:or)\b"),
        (ConditionTokenKind.NOT, r"\b(?i:not)\b"),
        (ConditionTokenKind.OF, r"\b(?i:of)\b"),
        (ConditionTokenKind.ALL, r"\b(?i:all)\b"),
        (ConditionTokenKind.ANY, r"\b(?i:any)\b"),
        (ConditionTokenKind.THEM, r"\b(?i:them)\b"),
        (ConditionTokenKind.NUM, r"\b\d+\b"),
        (ConditionTokenKind.ID, r"[a-zA-Z0-9_*?-]+"),
        ("WS", r"\s+"),
    ]
    regex = "|".join("(?P<%s>%s)" % (k.value if isinstance(k, ConditionTokenKind) else k, p) for k, p in spec)
    tokens: List[Tuple[ConditionTokenKind, str]] = []
    for mo in re.finditer(regex, expr):
        kind_name = mo.lastgroup
        if kind_name != "WS" and kind_name is not None:
            tokens.append((ConditionTokenKind(kind_name), mo.group()))
    return tokens


@dataclass
class SigmaRuleAST:
    """Complete normalized AST representation of a Sigma detection rule."""

    id: str
    title: str
    category: str
    product: Optional[str]
    service: Optional[str]
    positive_conjunctions: Tuple[ConjunctionAST, ...]
    filter_conjunctions: Tuple[ConjunctionAST, ...]
    raw_dict: Dict[str, Any] = field(default_factory=dict, repr=False)
    file_path: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], file_path: Optional[str] = None) -> "SigmaRuleAST":
        rule_id = str(data.get("id") or "").strip()
        title = str(data.get("title") or "Untitled Rule").strip()
        logsource = data.get("logsource") or {}
        category = _normalize_category(logsource.get("category"))
        product = str(logsource.get("product")).strip().lower() if logsource.get("product") else None
        service = str(logsource.get("service")).strip().lower() if logsource.get("service") else None

        detection = data.get("detection") or {}
        pos_conjunctions, filt_conjunctions = cls._parse_detection_dnf(detection)

        return cls(
            id=rule_id,
            title=title,
            category=category,
            product=product,
            service=service,
            positive_conjunctions=tuple(pos_conjunctions),
            filter_conjunctions=tuple(filt_conjunctions),
            raw_dict=data,
            file_path=file_path,
        )

    @classmethod
    def from_yaml_file(cls, path: Union[str, Path]) -> "SigmaRuleAST":
        p = Path(path)
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"File {path} did not parse into a Sigma dictionary.")
        return cls.from_dict(data, file_path=str(p.resolve()))

    @classmethod
    def _parse_detection_dnf(cls, detection: Dict[str, Any]) -> Tuple[List[ConjunctionAST], List[ConjunctionAST]]:
        """Parse condition and detection blocks into positive and filter conjunctions."""
        condition_str = str(detection.get("condition") or "selection").strip()
        blocks: Dict[str, List[ConjunctionAST]] = {}

        for k, v in detection.items():
            if k in ("condition", "timeframe"):
                continue
            conj_list: List[ConjunctionAST] = []
            if isinstance(v, dict):
                conj_list.append(ConjunctionAST.from_dict(v))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        conj_list.append(ConjunctionAST.from_dict(item))
            if conj_list:
                blocks[k.lower()] = conj_list

        if not blocks:
            return [], []

        # Identify positive selection names vs filter names
        filter_names: Set[str] = set()
        pos_names: Set[str] = set()

        # Parse condition tokens to identify negated blocks and positive blocks
        tokens = _tokenize_condition(condition_str)
        negated = False
        i = 0
        while i < len(tokens):
            tok_kind, tok_val = tokens[i]
            if tok_kind == ConditionTokenKind.NOT:
                negated = True
                i += 1
                continue

            # Quantifiers: 1 of ..., all of ...
            if tok_kind in (ConditionTokenKind.NUM, ConditionTokenKind.ALL, ConditionTokenKind.ANY):
                if i + 1 < len(tokens) and tokens[i + 1][0] == ConditionTokenKind.OF:
                    target_tok = tokens[i + 2] if i + 2 < len(tokens) else None
                    if target_tok:
                        pat = "*" if target_tok[0] == ConditionTokenKind.THEM else target_tok[1]
                        for b_name in blocks:
                            if fnmatch.fnmatch(b_name, pat.lower()):
                                if negated or "filter" in b_name:
                                    filter_names.add(b_name)
                                else:
                                    pos_names.add(b_name)
                    i += 3
                    negated = False
                    continue

            if tok_kind in (ConditionTokenKind.ID, ConditionTokenKind.THEM):
                pat = "*" if tok_kind == ConditionTokenKind.THEM else tok_val
                for b_name in blocks:
                    if fnmatch.fnmatch(b_name, pat.lower()):
                        if negated or "filter" in b_name:
                            filter_names.add(b_name)
                        else:
                            pos_names.add(b_name)
                negated = False

            i += 1

        # Fallback if no positive names identified
        if not pos_names:
            for b_name in blocks:
                if b_name not in filter_names and not b_name.startswith("filter"):
                    pos_names.add(b_name)

        pos_conjunctions: List[ConjunctionAST] = []
        for name in pos_names:
            pos_conjunctions.extend(blocks.get(name, []))

        filter_conjunctions: List[ConjunctionAST] = []
        for name in filter_names:
            filter_conjunctions.extend(blocks.get(name, []))

        return pos_conjunctions, filter_conjunctions


# -----------------------------------------------------------------------------
# 4. Subsumption Engine: SubsumptionEngine & SubsumptionResult
# -----------------------------------------------------------------------------


@dataclass
class SubsumptionResult:
    """Result of AST-level comparison between two Sigma rules."""

    rule_a_id: str
    rule_a_title: str
    rule_b_id: str
    rule_b_title: str
    relation: SubsumptionRelation
    overlap_score: float  # 0.0 to 1.0
    shared_fields: List[str]
    divergent_fields: List[str]
    explanation: str
    rule_a_file: Optional[str] = None
    rule_b_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["relation"] = self.relation.value
        return d


class SubsumptionEngine:
    """Core engine for AST-level rule subsumption and equivalence checking."""

    def __init__(self, overlap_threshold: float = 0.5):
        self.overlap_threshold = overlap_threshold

    def compare(self, rule_a: SigmaRuleAST, rule_b: SigmaRuleAST) -> SubsumptionResult:
        """Compare Rule A and Rule B to determine logical subsumption or equivalence."""
        # 1. Log source category check
        if rule_a.category != rule_b.category:
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.DISJOINT,
                overlap_score=0.0,
                shared_fields=[],
                divergent_fields=[],
                explanation=(f"Different log source categories: '{rule_a.category}' vs '{rule_b.category}'."),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        # 2. Product compatibility check
        if rule_a.product and rule_b.product and rule_a.product != rule_b.product:
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.DISJOINT,
                overlap_score=0.0,
                shared_fields=[],
                divergent_fields=[],
                explanation=(f"Incompatible products: '{rule_a.product}' vs '{rule_b.product}'."),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        # 3. Check positive conjunction coverage
        # a_covers_b: for every clause in b, there is a clause in a that subsumes it
        a_covers_b = bool(rule_a.positive_conjunctions and rule_b.positive_conjunctions) and all(
            any(ca.subsumes(cb) for ca in rule_a.positive_conjunctions) for cb in rule_b.positive_conjunctions
        )

        # b_covers_a: for every clause in a, there is a clause in b that subsumes it
        b_covers_a = bool(rule_a.positive_conjunctions and rule_b.positive_conjunctions) and all(
            any(cb.subsumes(ca) for cb in rule_b.positive_conjunctions) for ca in rule_a.positive_conjunctions
        )

        # Check filter compatibility
        filter_identical = set(rule_a.filter_conjunctions) == set(rule_b.filter_conjunctions)
        has_filter_a = bool(rule_a.filter_conjunctions)
        has_filter_b = bool(rule_b.filter_conjunctions)

        # Compute field metrics
        fields_a: Set[str] = set()
        for c in rule_a.positive_conjunctions:
            fields_a.update(c.fields)
        fields_b: Set[str] = set()
        for c in rule_b.positive_conjunctions:
            fields_b.update(c.fields)

        shared_fields = sorted(fields_a & fields_b)
        divergent_fields = sorted(fields_a ^ fields_b)

        # Compute structural similarity
        sim_scores: List[float] = []
        for ca in rule_a.positive_conjunctions:
            for cb in rule_b.positive_conjunctions:
                sim_scores.append(ca.similarity(cb))
        max_sim = max(sim_scores) if sim_scores else 0.0

        # Case A: Equivalent (Duplicate)
        if a_covers_b and b_covers_a and (filter_identical or (not has_filter_a and not has_filter_b)):
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.EQUIVALENT,
                overlap_score=1.0,
                shared_fields=shared_fields,
                divergent_fields=[],
                explanation=(
                    f"Rules are logically equivalent: both specify identical detection criteria "
                    f"on category '{rule_a.category}' across fields: {', '.join(shared_fields)}."
                ),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        # Case A.1: Positive selections are equivalent, but one rule adds exclusion filters
        if a_covers_b and b_covers_a:
            if not has_filter_a and has_filter_b:
                return SubsumptionResult(
                    rule_a_id=rule_a.id,
                    rule_a_title=rule_a.title,
                    rule_b_id=rule_b.id,
                    rule_b_title=rule_b.title,
                    relation=SubsumptionRelation.SUBSUMES,
                    overlap_score=max_sim,
                    shared_fields=shared_fields,
                    divergent_fields=divergent_fields,
                    explanation=(
                        f"Rule A ('{rule_a.title}') is broader and SUBSUMES Rule B ('{rule_b.title}'). "
                        f"Both share identical positive selection logic, but Rule B restricts alerts with exclusion filters."
                    ),
                    rule_a_file=rule_a.file_path,
                    rule_b_file=rule_b.file_path,
                )
            elif has_filter_a and not has_filter_b:
                return SubsumptionResult(
                    rule_a_id=rule_a.id,
                    rule_a_title=rule_a.title,
                    rule_b_id=rule_b.id,
                    rule_b_title=rule_b.title,
                    relation=SubsumptionRelation.SUBSUMED_BY,
                    overlap_score=max_sim,
                    shared_fields=shared_fields,
                    divergent_fields=divergent_fields,
                    explanation=(
                        f"Rule A ('{rule_a.title}') is narrower and SUBSUMED BY Rule B ('{rule_b.title}'). "
                        f"Both share identical positive selection logic, but Rule A restricts alerts with exclusion filters."
                    ),
                    rule_a_file=rule_a.file_path,
                    rule_b_file=rule_b.file_path,
                )

        # Case B: Rule A SUBSUMES Rule B (Rule A is broader)
        if a_covers_b and not b_covers_a:
            if has_filter_a and not has_filter_b:
                return SubsumptionResult(
                    rule_a_id=rule_a.id,
                    rule_a_title=rule_a.title,
                    rule_b_id=rule_b.id,
                    rule_b_title=rule_b.title,
                    relation=SubsumptionRelation.OVERLAPPING,
                    overlap_score=max_sim,
                    shared_fields=shared_fields,
                    divergent_fields=divergent_fields,
                    explanation=(
                        f"Rule A ('{rule_a.title}') positive selections cover Rule B ('{rule_b.title}'), "
                        f"but Rule A carries exclusion filters that suppress events Rule B alerts on."
                    ),
                    rule_a_file=rule_a.file_path,
                    rule_b_file=rule_b.file_path,
                )
            extra = [f for f in divergent_fields if f in fields_b]
            extra_msg = f" while Rule B adds constraints on {extra}" if extra else ""
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.SUBSUMES,
                overlap_score=max_sim,
                shared_fields=shared_fields,
                divergent_fields=divergent_fields,
                explanation=(
                    f"Rule A ('{rule_a.title}') is broader and SUBSUMES Rule B ('{rule_b.title}'). "
                    f"Rule A covers all events matched by Rule B{extra_msg}."
                ),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        # Case C: Rule A SUBSUMED_BY Rule B (Rule A is narrower)
        if b_covers_a and not a_covers_b:
            if has_filter_b and not has_filter_a:
                return SubsumptionResult(
                    rule_a_id=rule_a.id,
                    rule_a_title=rule_a.title,
                    rule_b_id=rule_b.id,
                    rule_b_title=rule_b.title,
                    relation=SubsumptionRelation.OVERLAPPING,
                    overlap_score=max_sim,
                    shared_fields=shared_fields,
                    divergent_fields=divergent_fields,
                    explanation=(
                        f"Rule B ('{rule_b.title}') positive selections cover Rule A ('{rule_a.title}'), "
                        f"but Rule B carries exclusion filters that suppress events Rule A alerts on."
                    ),
                    rule_a_file=rule_a.file_path,
                    rule_b_file=rule_b.file_path,
                )
            extra = [f for f in divergent_fields if f in fields_a]
            extra_msg = f" while Rule A adds constraints on {extra}" if extra else ""
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.SUBSUMED_BY,
                overlap_score=max_sim,
                shared_fields=shared_fields,
                divergent_fields=divergent_fields,
                explanation=(
                    f"Rule A ('{rule_a.title}') is narrower and SUBSUMED BY Rule B ('{rule_b.title}'). "
                    f"Rule B covers all events matched by Rule A{extra_msg}."
                ),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        # Case D: Overlapping or Disjoint
        if max_sim >= self.overlap_threshold:
            return SubsumptionResult(
                rule_a_id=rule_a.id,
                rule_a_title=rule_a.title,
                rule_b_id=rule_b.id,
                rule_b_title=rule_b.title,
                relation=SubsumptionRelation.OVERLAPPING,
                overlap_score=max_sim,
                shared_fields=shared_fields,
                divergent_fields=divergent_fields,
                explanation=(
                    f"Rules share category '{rule_a.category}' and common fields {shared_fields} "
                    f"with {max_sim:.0%} AST similarity, but neither strictly subsumes the other."
                ),
                rule_a_file=rule_a.file_path,
                rule_b_file=rule_b.file_path,
            )

        return SubsumptionResult(
            rule_a_id=rule_a.id,
            rule_a_title=rule_a.title,
            rule_b_id=rule_b.id,
            rule_b_title=rule_b.title,
            relation=SubsumptionRelation.DISJOINT,
            overlap_score=max_sim,
            shared_fields=shared_fields,
            divergent_fields=divergent_fields,
            explanation=(
                f"Rules have non-subsuming, divergent constraints on category '{rule_a.category}' "
                f"(similarity: {max_sim:.0%})."
            ),
            rule_a_file=rule_a.file_path,
            rule_b_file=rule_b.file_path,
        )


# -----------------------------------------------------------------------------
# 5. Corpus Deduplication & Internal Redundancy Analyzer
# -----------------------------------------------------------------------------


@dataclass
class CorpusDedupReport:
    """Report summarizing duplicates, subsumptions, and redundancies in a rule corpus."""

    total_rules: int
    duplicates: List[SubsumptionResult] = field(default_factory=list)
    subsumptions: List[SubsumptionResult] = field(default_factory=list)
    overlaps: List[SubsumptionResult] = field(default_factory=list)
    internal_redundancies: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def has_issues(self) -> bool:
        return bool(self.duplicates or self.subsumptions or self.internal_redundancies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "duplicate_count": len(self.duplicates),
            "subsumption_count": len(self.subsumptions),
            "overlap_count": len(self.overlaps),
            "internal_redundancy_count": sum(len(v) for v in self.internal_redundancies.values()),
            "duplicates": [d.to_dict() for d in self.duplicates],
            "subsumptions": [s.to_dict() for s in self.subsumptions],
            "overlaps": [o.to_dict() for o in self.overlaps],
            "internal_redundancies": self.internal_redundancies,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class SigmaDeduplicator:
    """Analyzes a collection of Sigma rules for redundancy, subsumption, and deduplication."""

    def __init__(self, overlap_threshold: float = 0.5):
        self.engine = SubsumptionEngine(overlap_threshold=overlap_threshold)

    @staticmethod
    def audit_internal_redundancy(rule: SigmaRuleAST) -> List[str]:
        """Check for dead code or redundant alternative selections within a single rule."""
        issues: List[str] = []
        conjunctions = rule.positive_conjunctions
        n = len(conjunctions)
        if n > 1:
            for i in range(n):
                for j in range(n):
                    if i != j and conjunctions[i].subsumes(conjunctions[j]):
                        issues.append(
                            f"Selection clause #{i + 1} ({conjunctions[i].fields}) subsumes clause "
                            f"#{j + 1} ({conjunctions[j].fields}), making clause #{j + 1} dead/redundant."
                        )
        return issues

    def check_candidate(self, candidate: SigmaRuleAST, corpus: Sequence[SigmaRuleAST]) -> List[SubsumptionResult]:
        """Check a candidate rule against an existing corpus and return all non-disjoint matches."""
        results: List[SubsumptionResult] = []
        for existing in corpus:
            if existing.id and candidate.id and existing.id == candidate.id:
                continue
            res = self.engine.compare(candidate, existing)
            if res.relation != SubsumptionRelation.DISJOINT:
                results.append(res)
        # Sort so EQUIVALENT and SUBSUMES appear first, followed by score
        priority = {
            SubsumptionRelation.EQUIVALENT: 0,
            SubsumptionRelation.SUBSUMES: 1,
            SubsumptionRelation.SUBSUMED_BY: 2,
            SubsumptionRelation.OVERLAPPING: 3,
            SubsumptionRelation.DISJOINT: 4,
        }
        results.sort(key=lambda r: (priority[r.relation], -r.overlap_score))
        return results

    def analyze_corpus(self, rules: Sequence[SigmaRuleAST], include_overlaps: bool = True) -> CorpusDedupReport:
        """Scan an entire corpus of Sigma rules and compute pair-wise subsumption and deduplication."""
        report = CorpusDedupReport(total_rules=len(rules))

        # Check internal redundancies
        for rule in rules:
            internal = self.audit_internal_redundancy(rule)
            if internal:
                key = rule.id or rule.title
                report.internal_redundancies[key] = internal

        # Pair-wise comparison
        n = len(rules)
        for i in range(n):
            for j in range(i + 1, n):
                res = self.engine.compare(rules[i], rules[j])
                if res.relation == SubsumptionRelation.EQUIVALENT:
                    report.duplicates.append(res)
                elif res.relation in (SubsumptionRelation.SUBSUMES, SubsumptionRelation.SUBSUMED_BY):
                    report.subsumptions.append(res)
                elif res.relation == SubsumptionRelation.OVERLAPPING and include_overlaps:
                    report.overlaps.append(res)

        return report

    @classmethod
    def load_rules_from_directory(cls, dir_path: Union[str, Path]) -> List[SigmaRuleAST]:
        """Recursively scan directory and parse all .yml / .yaml Sigma rules."""
        p = Path(dir_path)
        if not p.exists() or not p.is_dir():
            return []
        rules: List[SigmaRuleAST] = []
        for f in sorted(p.rglob("*.y*ml")):
            if f.name.startswith((".", "_")):
                continue
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = yaml.safe_load(fp)
                if isinstance(data, dict) and "detection" in data and "logsource" in data:
                    rules.append(SigmaRuleAST.from_dict(data, file_path=str(f.resolve())))
            except Exception as e:
                logger.debug("Skipping %s (not a valid Sigma rule): %s", f, e)
        return rules
