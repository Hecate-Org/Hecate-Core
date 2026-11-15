"""The local evaluation helper keeps operational state and credentials isolated."""

import importlib.util
import json
import os
from pathlib import Path
from subprocess import CompletedProcess

import pytest


@pytest.fixture
def helper():
    path = Path(__file__).parents[1] / "scripts" / "eval_local_model.py"
    spec = importlib.util.spec_from_file_location("eval_local_model", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("score,exit_code", [(0.9, 0), (0.3, 1)])
def test_evaluation_retains_results_and_exit_status(helper, tmp_path, monkeypatch, score, exit_code):
    production_gate = tmp_path / "production-gates.json"
    production_gate.write_text("unchanged")
    monkeypatch.setenv("HECATE_LLM_DEMOTION_GATES", str(production_gate))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "private-value")
    monkeypatch.setenv("HECATE_LLM_SIMPLE_PROVIDER", "litellm")

    def fake_cli(command, *, cwd, env, stdout, stderr, check):
        assert command[1:5] == ["-m", "hecate_agent.cli", "eval", "--tier"]
        assert "--write-gate" not in command
        assert command[command.index("--fail-under") + 1] == "0.8"
        assert "ANTHROPIC_API_KEY" not in env
        assert env["HECATE_LLM_SIMPLE_PROVIDER"] == "ollama"
        assert env["HECATE_LLM_COMPLEX_PROVIDER"] == "ollama"
        assert env["HECATE_OLLAMA_THINK"] == "false"
        assert Path(env["HOME"]).parent == cwd
        assert Path(env["HECATE_LLM_DEMOTION_GATES"]).parent == cwd
        stdout.write(json.dumps({"model": "test-model", "passed": int(score * 10), "total": 10, "score": score}))
        return CompletedProcess(command, exit_code)

    monkeypatch.setattr(helper.subprocess, "run", fake_cli)
    assert helper.run_evaluation("test-model", tmp_path / "reports") == exit_code
    result = next((tmp_path / "reports").iterdir())
    if os.name == "posix":
        assert result.stat().st_mode & 0o777 == 0o700
    assert json.loads((result / "report.json").read_text())["score"] == score
    assert json.loads((result / "metadata.json").read_text())["exit_code"] == exit_code
    assert not (result / "unused-gates.json").exists()
    assert production_gate.read_text() == "unchanged"


def test_incomplete_report_cannot_pass(helper, tmp_path, monkeypatch):
    def fake_cli(command, **kwargs):
        kwargs["stdout"].write("Provider unavailable")
        return CompletedProcess(command, 0)

    monkeypatch.setattr(helper.subprocess, "run", fake_cli)
    assert helper.run_evaluation("test-model", tmp_path) == 1
