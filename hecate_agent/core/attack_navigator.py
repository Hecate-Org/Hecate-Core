"""MITRE ATT&CK Navigator Layer exporter for Hecate.

Exports detection coverage (hunts and Sigma/SIEM queries) into ATT&CK Navigator
v4.5/v5.0 JSON layer files compatible with the official MITRE ATT&CK Navigator web UI.
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import yaml

from hecate_agent.core.attack_matrix import (
    canonical_tactic,
    get_attack_version,
    get_sorted_tactics,
    get_technique,
    get_techniques_for_tactic,
)
from hecate_agent.core.hunt_manager import HuntManager

logger = logging.getLogger(__name__)


class LayerScoringMetric(str, Enum):
    """Supported scoring metrics for ATT&CK Navigator layers."""

    HUNTS = "hunts"
    QUERIES = "queries"
    BINARY = "binary"


def _clean_attack_version(raw_version: Optional[str]) -> str:
    """Extract a clean ATT&CK version number suitable for Navigator schemas."""
    if not raw_version:
        return "19.1"
    match = re.search(r"(\d+(?:\.\d+)?)", raw_version)
    return match.group(1) if match else "19.1"


def _extract_technique_ids_from_sigma(yaml_content: str) -> Set[str]:
    """Extract ATT&CK technique IDs from Sigma rule tags."""
    technique_ids: Set[str] = set()
    try:
        data = yaml.safe_load(yaml_content)
        if isinstance(data, dict):
            tags = data.get("tags", [])
            for tag in tags:
                match = re.match(r"attack\.(t\d+(?:\.\d+)?)", str(tag), re.IGNORECASE)
                if match:
                    technique_ids.add(match.group(1).upper())
    except Exception as exc:
        logger.debug("Failed to parse YAML for technique extraction: %s", exc)
    return technique_ids


class NavigatorExporter:
    """Exports Hecate hunt and query detection coverage into ATT&CK Navigator layers."""

    def __init__(
        self,
        hunts_dir: Optional[Path] = None,
        queries_dir: Optional[Path] = None,
    ) -> None:
        self.hunts_dir = Path(hunts_dir) if hunts_dir else None
        self.queries_dir = Path(queries_dir) if queries_dir else None
        self.hunt_manager = HuntManager(self.hunts_dir)

    def scan_query_rules(self) -> Dict[str, List[Path]]:
        """Map technique IDs to associated query files in the workspace.

        Scans queries_dir (or default candidate locations) for Sigma YAML files and
        extracts ATT&CK tags.
        """
        tech_to_queries: Dict[str, List[Path]] = {}
        target_dir = self.queries_dir
        if target_dir is None:
            if self.hunts_dir:
                candidate = self.hunts_dir.parent / "queries"
                if candidate.is_dir():
                    target_dir = candidate
            if target_dir is None:
                candidate = Path.cwd() / "queries"
                if candidate.is_dir():
                    target_dir = candidate

        if not target_dir or not target_dir.is_dir():
            return tech_to_queries

        for yml_file in target_dir.rglob("*.yml"):
            try:
                content = yml_file.read_text(encoding="utf-8")
                tech_ids = _extract_technique_ids_from_sigma(content)
                for tid in tech_ids:
                    if tid not in tech_to_queries:
                        tech_to_queries[tid] = []
                    tech_to_queries[tid].append(yml_file)
            except Exception as exc:
                logger.debug("Could not read query file %s: %s", yml_file, exc)

        return tech_to_queries

    def build_layer(
        self,
        name: str = "Hecate Detection Coverage",
        description: Optional[str] = None,
        score_by: LayerScoringMetric | str = LayerScoringMetric.HUNTS,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
        include_uncovered: bool = False,
        min_score: Optional[float] = None,
        gradient_colors: Optional[List[str]] = None,
        domain: str = "enterprise-attack",
        attack_version: Optional[str] = None,
        navigator_version: str = "5.0.0",
        layer_version: str = "4.5",
    ) -> Dict[str, Any]:
        """Generate an ATT&CK Navigator JSON layer structure.

        Args:
            name: Title of the layer.
            description: Narrative summary in layer metadata.
            score_by: Metric used to calculate technique score ("hunts", "queries", "binary").
            tactic_filter: If provided, restricts exported layer to a single ATT&CK tactic.
            platform_filter: If provided, restricts exported techniques to matching platform.
            include_uncovered: If True, includes all techniques with a score of 0.
            min_score: Minimum score required for a technique to be included.
            gradient_colors: Custom list of hex color codes for heatmap gradient.
            domain: ATT&CK matrix domain (default: "enterprise-attack").
            attack_version: Override ATT&CK matrix version (defaults to provider version).
            navigator_version: Target ATT&CK Navigator schema version.
            layer_version: Navigator layer schema version.

        Returns:
            Dictionary conforming to the MITRE ATT&CK Navigator schema.
        """
        try:
            metric = LayerScoringMetric(score_by) if isinstance(score_by, str) else score_by
        except (ValueError, KeyError):
            metric = LayerScoringMetric.HUNTS
        resolved_attack_ver = _clean_attack_version(attack_version or get_attack_version())
        query_map = self.scan_query_rules()
        coverage_data = self.hunt_manager.calculate_attack_coverage()
        by_tactic = coverage_data.get("by_tactic", {})

        # Determine which tactics are in scope
        all_tactics = get_sorted_tactics()
        if tactic_filter:
            norm_tactic = canonical_tactic(tactic_filter.lower().strip())
            tactics_in_scope = [norm_tactic] if norm_tactic in all_tactics else [tactic_filter]
        else:
            tactics_in_scope = all_tactics

        techniques_list: List[Dict[str, Any]] = []
        covered_pairs: Set[Tuple[str, str]] = set()  # (technique_id, tactic)
        parent_techniques_to_expand: Set[Tuple[str, str]] = set()

        # 1. Process covered techniques from hunts
        for tactic in tactics_in_scope:
            tactic_data = by_tactic.get(tactic, {})
            techs_dict = tactic_data.get("techniques", {})

            for tech_id, hunt_ids in sorted(techs_dict.items()):
                tech_info = get_technique(tech_id) or {}

                # Platform filter check
                if platform_filter:
                    platforms = [p.lower() for p in tech_info.get("platforms", [])]
                    if platform_filter.lower() not in platforms:
                        continue

                # Query files mapped to this technique
                tech_queries = query_map.get(tech_id, [])

                # Calculate score
                if metric == LayerScoringMetric.HUNTS:
                    score = len(hunt_ids)
                elif metric == LayerScoringMetric.QUERIES:
                    score = len(tech_queries) if tech_queries else len(hunt_ids)
                elif metric == LayerScoringMetric.BINARY:
                    score = 1 if hunt_ids else 0

                if min_score is not None and score < min_score:
                    continue

                comment_parts = [f"Hunts: {', '.join(sorted(hunt_ids))}"]
                if tech_queries:
                    comment_parts.append(f"{len(tech_queries)} queries")
                comment = " | ".join(comment_parts)

                metadata = [
                    {"name": "hunts", "value": ", ".join(sorted(hunt_ids))},
                    {"name": "hunt_count", "value": str(len(hunt_ids))},
                    {"name": "query_count", "value": str(len(tech_queries))},
                ]

                entry: Dict[str, Any] = {
                    "techniqueID": tech_id,
                    "tactic": tactic,
                    "score": score,
                    "comment": comment,
                    "enabled": True,
                    "metadata": metadata,
                    "showSubtechniques": True,
                }

                if tech_info.get("url"):
                    entry["links"] = [{"label": "MITRE ATT&CK", "url": tech_info["url"]}]

                techniques_list.append(entry)
                covered_pairs.add((tech_id, tactic))

                # Track parent technique expansion
                parent_id = tech_info.get("parent_id")
                if tech_info.get("is_subtechnique") and parent_id:
                    parent_techniques_to_expand.add((parent_id, tactic))
                elif "." in tech_id:
                    parent_id = tech_id.split(".")[0]
                    parent_techniques_to_expand.add((parent_id, tactic))

        # 2. Ensure parent techniques have showSubtechniques=True
        existing_indices = {(t["techniqueID"], t.get("tactic")): i for i, t in enumerate(techniques_list)}
        for parent_id, tactic in parent_techniques_to_expand:
            if (parent_id, tactic) in existing_indices:
                techniques_list[existing_indices[(parent_id, tactic)]]["showSubtechniques"] = True
            elif (parent_id, tactic) not in covered_pairs:
                parent_info = get_technique(parent_id) or {}
                if platform_filter:
                    platforms = [p.lower() for p in parent_info.get("platforms", [])]
                    if platforms and platform_filter.lower() not in platforms:
                        continue
                parent_entry: Dict[str, Any] = {
                    "techniqueID": parent_id,
                    "tactic": tactic,
                    "enabled": True,
                    "showSubtechniques": True,
                }
                if parent_info.get("url"):
                    parent_entry["links"] = [{"label": "MITRE ATT&CK", "url": parent_info["url"]}]
                techniques_list.append(parent_entry)
                covered_pairs.add((parent_id, tactic))

        # 3. Include uncovered techniques if requested
        if include_uncovered:
            for tactic in tactics_in_scope:
                all_tactic_techs = get_techniques_for_tactic(tactic) or []
                for tech in all_tactic_techs:
                    tid = tech.get("id", "")
                    if not tid or (tid, tactic) in covered_pairs:
                        continue

                    if platform_filter:
                        platforms = [p.lower() for p in tech.get("platforms", [])]
                        if platform_filter.lower() not in platforms:
                            continue

                    entry = {
                        "techniqueID": tid,
                        "tactic": tactic,
                        "score": 0,
                        "color": "#ffffff",
                        "comment": "No coverage in Hecate",
                        "enabled": True,
                        "metadata": [{"name": "coverage", "value": "None"}],
                        "showSubtechniques": False,
                    }
                    if tech.get("url"):
                        entry["links"] = [{"label": "MITRE ATT&CK", "url": tech["url"]}]
                    techniques_list.append(entry)
                    covered_pairs.add((tid, tactic))

        # Determine gradient scale
        scores = [t["score"] for t in techniques_list if "score" in t]
        raw_max = max(scores) if scores else 1
        colors = gradient_colors or ["#ffffff", "#6baed6", "#08519c"]

        # Safeguard against mitreattack/colour float underflow when (maxValue - minValue)/(len(colors)-1) < 1
        max_val = max(raw_max, len(colors) - 1, 1)
        min_val = 0

        mid_color = colors[1] if len(colors) > 2 else colors[0]
        max_color = colors[-1]

        metric_label = metric.value
        legend_items = [
            {"label": "No coverage (0)", "color": colors[0]},
            {"label": f"Low coverage (1 {metric_label.rstrip('s')})", "color": mid_color},
            {"label": f"High coverage ({raw_max}+ {metric_label})", "color": max_color},
        ]

        desc = description or f"MITRE ATT&CK coverage exported from Hecate (scored by {metric.value})"

        layer_dict: Dict[str, Any] = {
            "name": name,
            "versions": {
                "attack": resolved_attack_ver,
                "navigator": navigator_version,
                "layer": layer_version,
            },
            "domain": domain,
            "description": desc,
            "filters": {"platforms": [platform_filter] if platform_filter else ["Linux", "macOS", "Windows"]},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": colors,
                "minValue": min_val,
                "maxValue": max_val,
            },
            "legendItems": legend_items,
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        # Validate with mitreattack.navlayers if available
        try:
            from mitreattack.navlayers import Layer

            validated = Layer(layer_dict).to_dict()
            if isinstance(validated, dict):
                return cast(Dict[str, Any], validated)
            logger.debug("mitreattack.navlayers returned None; using compliant raw layer dict")
            return layer_dict
        except Exception as exc:
            logger.debug("mitreattack.navlayers validation skipped (%s); returning compliant dict", exc)
            return layer_dict

    def export_to_file(
        self,
        output_path: Path | str,
        layer_dict: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Path:
        """Export the layer to a UTF-8 JSON file."""
        if layer_dict is None:
            layer_dict = self.build_layer(**kwargs)

        target = Path(output_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(layer_dict, f, indent=2, ensure_ascii=False)

        return target


def build_navigator_layer(
    hunts_dir: Optional[Path] = None,
    queries_dir: Optional[Path] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience function to build an ATT&CK Navigator layer dictionary."""
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    return exporter.build_layer(**kwargs)


def export_navigator_layer_to_file(
    output_path: Path | str,
    hunts_dir: Optional[Path] = None,
    queries_dir: Optional[Path] = None,
    **kwargs: Any,
) -> Path:
    """Convenience function to build and export an ATT&CK Navigator layer to disk."""
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    return exporter.export_to_file(output_path=output_path, **kwargs)
