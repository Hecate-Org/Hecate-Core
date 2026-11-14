"""Tests for hecate-agent maturity assess command."""

import json
import importlib

import pytest
from pathlib import Path
from click.testing import CliRunner

from hecate_agent.commands.maturity import maturity, assess_workspace_maturity
from hecate_agent.commands.demo import demo


@pytest.fixture(autouse=True)
def offline_ollama_status(monkeypatch):
    module = importlib.import_module("hecate_agent.commands.maturity")
    monkeypatch.setattr(module, "_ollama_is_running", lambda *args, **kwargs: False)


def test_maturity_assess_empty_workspace(tmp_path: Path):
    """An empty workspace assesses as Level 0 (Ad-hoc) with recommendations to init or create."""
    runner = CliRunner()
    result = runner.invoke(maturity, ["assess", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Level 0: Ad-hoc" in result.output
    assert "hecate-agent demo init" in result.output or "hecate-agent hunt new" in result.output


def test_maturity_assess_demo_workspace(tmp_path: Path, monkeypatch):
    """A demo initialized workspace with AGENTS.md assesses as Level 2 or higher."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(demo, ["init"])
    (tmp_path / "AGENTS.md").write_text("# Environment Context")
    (tmp_path / "knowledge").mkdir(exist_ok=True)
    (tmp_path / "knowledge" / "hunting-knowledge.md").write_text("# Knowledge")

    assessment = assess_workspace_maturity(tmp_path)
    assert assessment["level"] >= 2
    assert "Searchable" in assessment["level_name"] or "Generative" in assessment["level_name"]


def test_maturity_assess_json_format(tmp_path: Path):
    """hecate-agent maturity assess --format json produces valid JSON."""
    runner = CliRunner()
    result = runner.invoke(maturity, ["assess", "--path", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "level" in data
    assert "level_name" in data
    assert "metrics" in data
    assert "recommendations" in data
    assert isinstance(data["recommendations"], list)
