"""Tests for MITRE ATT&CK Navigator Layer exporter and CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from hecate_agent.commands.attack import attack
from hecate_agent.core.attack_navigator import (
    LayerScoringMetric,
    NavigatorExporter,
    _clean_attack_version,
    _extract_technique_ids_from_sigma,
    export_navigator_layer_to_file,
)


@pytest.fixture(autouse=True)
def fixed_attack_catalog(monkeypatch):
    """Unit tests must not depend on an operator's installed STIX cache."""
    from hecate_agent.core import attack_matrix

    techniques = {
        "T1059": {"id": "T1059", "platforms": ["Windows", "Linux"], "tactic_shortnames": ["execution"]},
        "T1059.001": {
            "id": "T1059.001",
            "platforms": ["Windows"],
            "tactic_shortnames": ["execution"],
            "parent_id": "T1059",
            "is_subtechnique": True,
        },
        "T1190": {"id": "T1190", "platforms": ["Windows", "Linux"], "tactic_shortnames": ["initial-access"]},
        "T1566": {"id": "T1566", "platforms": ["Windows"], "tactic_shortnames": ["initial-access"]},
    }

    class FixtureProvider(attack_matrix.FallbackProvider):
        def get_technique_by_id(self, technique_id):
            return techniques.get(technique_id)

        def get_techniques_for_tactic(self, tactic_key):
            return [t for t in techniques.values() if tactic_key in t["tactic_shortnames"]]

    monkeypatch.setattr(attack_matrix, "_provider", FixtureProvider())


@pytest.fixture
def sample_workspace(tmp_path: Path) -> tuple[Path, Path]:
    """Create a temporary workspace with sample hunts and queries."""
    hunts_dir = tmp_path / "hunts"
    queries_dir = tmp_path / "queries"
    hunts_dir.mkdir(parents=True)
    queries_dir.mkdir(parents=True)

    # Hunt 1
    h1 = hunts_dir / "H-0001.md"
    h1.write_text(
        """---
hunt_id: H-0001
title: PowerShell Execution
status: completed
date: '2026-10-31'
tactics:
  - execution
techniques:
  - T1059.001
platform:
  - Windows
---
# Hunt H-0001: PowerShell Execution
## Overview
Testing powershell execution detection.
""",
        encoding="utf-8",
    )

    # Hunt 2
    h2 = hunts_dir / "H-0002.md"
    h2.write_text(
        """---
hunt_id: H-0002
title: Dual Technique Hunt
status: completed
date: '2026-10-31'
tactics:
  - execution
  - initial-access
techniques:
  - T1059.001
  - T1190
platform:
  - Windows
  - Linux
---
# Hunt H-0002: Dual Technique Hunt
## Overview
Testing web exploitation detection.
""",
        encoding="utf-8",
    )

    # Query Sigma file for T1059.001
    q1_dir = queries_dir / "H-0001"
    q1_dir.mkdir(parents=True)
    q1 = q1_dir / "powershell_rule.yml"
    q1.write_text(
        """title: Suspicious PowerShell Download
id: 11111111-2222-3333-4444-555555555555
status: experimental
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'DownloadString'
  condition: selection
""",
        encoding="utf-8",
    )

    # Second Query for T1059.001
    q2 = q1_dir / "powershell_encoded.yml"
    q2.write_text(
        """title: Encoded PowerShell Command
id: 22222222-3333-4444-5555-666666666666
status: experimental
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
""",
        encoding="utf-8",
    )

    # Query for T1190
    q2_dir = queries_dir / "H-0002"
    q2_dir.mkdir(parents=True)
    q3 = q2_dir / "exploit_rule.yml"
    q3.write_text(
        """title: Web Exploit Attempt
id: 33333333-4444-5555-6666-777777777777
status: experimental
tags:
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains: '/asl-node-check'
  condition: selection
""",
        encoding="utf-8",
    )

    return hunts_dir, queries_dir


def test_clean_attack_version() -> None:
    assert _clean_attack_version("v19.1 (STIX)") == "19.1"
    assert _clean_attack_version("14") == "14"
    assert _clean_attack_version("v15") == "15"
    assert _clean_attack_version(None) == "19.1"


def test_extract_technique_ids_from_sigma() -> None:
    yaml_text = """
title: Test
tags:
  - attack.t1059.001
  - attack.t1190
  - custom.tag
"""
    techs = _extract_technique_ids_from_sigma(yaml_text)
    assert techs == {"T1059.001", "T1190"}


def test_build_layer_basic(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(name="Test Layer")

    assert layer["name"] == "Test Layer"
    assert layer["domain"] == "enterprise-attack"
    assert "versions" in layer
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) > 0

    # Verify T1059.001 has score 2 (covered by H-0001 and H-0002)
    t1059_001 = next((t for t in layer["techniques"] if t.get("techniqueID") == "T1059.001"), None)
    assert t1059_001 is not None
    assert t1059_001["score"] == 2
    assert "H-0001" in t1059_001["comment"]
    assert "H-0002" in t1059_001["comment"]


def test_build_layer_score_by_queries(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(score_by=LayerScoringMetric.QUERIES)

    t1059_001 = next((t for t in layer["techniques"] if t.get("techniqueID") == "T1059.001"), None)
    assert t1059_001 is not None
    assert t1059_001["score"] == 2  # 2 queries for T1059.001


def test_build_layer_score_by_binary(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(score_by="binary")

    t1059_001 = next((t for t in layer["techniques"] if t.get("techniqueID") == "T1059.001"), None)
    assert t1059_001 is not None
    assert t1059_001["score"] == 1


def test_build_layer_invalid_score_by_defaults_gracefully(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(score_by="invalid_unknown_metric")

    t1059_001 = next((t for t in layer["techniques"] if t.get("techniqueID") == "T1059.001"), None)
    assert t1059_001 is not None
    assert t1059_001["score"] == 2  # Defaults to HUNTS metric


def test_build_layer_tactic_filter(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(tactic_filter="initial-access")

    tactics = {t.get("tactic") for t in layer["techniques"] if "tactic" in t}
    assert tactics == {"initial-access"}


def test_build_layer_platform_filter(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(platform_filter="Windows")

    assert len(layer["techniques"]) > 0
    assert layer["filters"]["platforms"] == ["Windows"]


def test_build_layer_include_uncovered(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    exporter = NavigatorExporter(hunts_dir=hunts_dir, queries_dir=queries_dir)
    layer = exporter.build_layer(include_uncovered=True, tactic_filter="initial-access")

    scores = [t.get("score") for t in layer["techniques"] if "score" in t]
    assert 0 in scores
    assert any(s > 0 for s in scores)


def test_export_to_file(sample_workspace: tuple[Path, Path], tmp_path: Path) -> None:
    hunts_dir, queries_dir = sample_workspace
    out_file = tmp_path / "exported_layer.json"

    result_path = export_navigator_layer_to_file(
        output_path=out_file,
        hunts_dir=hunts_dir,
        queries_dir=queries_dir,
        name="Saved Layer",
    )

    assert result_path.exists()
    content = json.loads(result_path.read_text(encoding="utf-8"))
    assert content["name"] == "Saved Layer"
    assert "techniques" in content


def test_cli_export_layer_stdout(sample_workspace: tuple[Path, Path]) -> None:
    hunts_dir, queries_dir = sample_workspace
    runner = CliRunner()
    result = runner.invoke(
        attack,
        ["export-layer", "--hunts-dir", str(hunts_dir), "--queries-dir", str(queries_dir)],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["name"] == "Hecate Detection Coverage"
    assert len(data["techniques"]) > 0


def test_cli_export_layer_to_file(sample_workspace: tuple[Path, Path], tmp_path: Path) -> None:
    hunts_dir, queries_dir = sample_workspace
    out_file = tmp_path / "cli_layer.json"
    runner = CliRunner()
    result = runner.invoke(
        attack,
        [
            "export-layer",
            "-o",
            str(out_file),
            "--name",
            "CLI Export Test",
            "--hunts-dir",
            str(hunts_dir),
            "--queries-dir",
            str(queries_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Exported ATT&CK Navigator layer to" in result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["name"] == "CLI Export Test"


def test_cli_layer_alias(sample_workspace: tuple[Path, Path], tmp_path: Path) -> None:
    hunts_dir, queries_dir = sample_workspace
    out_file = tmp_path / "alias_layer.json"
    runner = CliRunner()
    result = runner.invoke(
        attack,
        [
            "layer",
            "-o",
            str(out_file),
            "--score-by",
            "queries",
            "--hunts-dir",
            str(hunts_dir),
            "--queries-dir",
            str(queries_dir),
        ],
    )

    assert result.exit_code == 0
    assert out_file.exists()
