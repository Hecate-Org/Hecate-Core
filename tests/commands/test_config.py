"""Tests for hecate-agent config command."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from hecate_agent.commands.config import config, _read_env_file, _write_env_file


@pytest.fixture(autouse=True)
def offline_ollama_status(monkeypatch):
    monkeypatch.setattr("hecate_agent.core.llm_provider._ollama_is_running", lambda *args, **kwargs: False)


def test_write_env_file_preserves_existing(tmp_path: Path):
    """Writing to .env updates specified keys without erasing existing variables."""
    env_file = tmp_path / ".env"
    env_file.write_text("# Existing comment\nCUSTOM_VAR=hello\nHECATE_LLM_PROVIDER=old\n")

    _write_env_file(env_file, {"HECATE_LLM_PROVIDER": "ollama", "NEW_KEY": "val"})

    vars_read = _read_env_file(env_file)
    assert vars_read["CUSTOM_VAR"] == "hello"
    assert vars_read["HECATE_LLM_PROVIDER"] == "ollama"
    assert vars_read["NEW_KEY"] == "val"
    assert "# Existing comment" in env_file.read_text()


def test_config_ai_non_interactive_ollama(tmp_path: Path, monkeypatch):
    """hecate-agent config ai sets up ollama non-interactively."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        config,
        ["ai", "--provider", "ollama", "--model", "llama3", "--base-url", "http://localhost:11434", "--non-interactive"],
    )
    assert result.exit_code == 0
    assert "Configuration successfully persisted" in result.output

    env_vars = _read_env_file(tmp_path / ".env")
    assert env_vars.get("HECATE_LLM_PROVIDER") == "ollama"
    assert env_vars.get("HECATE_LLM_MODEL") == "llama3"
    assert env_vars.get("OLLAMA_HOST") == "http://localhost:11434"


def test_config_ai_non_interactive_openai(tmp_path: Path, monkeypatch):
    """hecate-agent config ai sets up openai non-interactively."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        config,
        ["ai", "--provider", "openai", "--model", "gpt-4o", "--api-key", "sk-test12345", "--non-interactive"],
    )
    assert result.exit_code == 0
    assert "Configuration successfully persisted" in result.output

    env_vars = _read_env_file(tmp_path / ".env")
    assert env_vars.get("HECATE_LLM_PROVIDER") == "openai"
    assert env_vars.get("HECATE_LLM_MODEL") == "gpt-4o"
    assert env_vars.get("OPENAI_API_KEY") == "sk-test12345"


def test_config_ai_none_mode(tmp_path: Path, monkeypatch):
    """hecate-agent config ai --provider none configures offline mode."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        config,
        ["ai", "--provider", "none", "--non-interactive"],
    )
    assert result.exit_code == 0
    assert "AI features will be disabled" in result.output

    env_vars = _read_env_file(tmp_path / ".env")
    assert env_vars.get("HECATE_LLM_PROVIDER") == "none"


def test_config_show(tmp_path: Path, monkeypatch):
    """hecate-agent config show displays status table."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(config, ["show"])
    assert result.exit_code == 0
    assert "Hecate AI Configuration Status" in result.output
