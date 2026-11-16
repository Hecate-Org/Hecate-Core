from pathlib import Path

import pytest
from click.testing import CliRunner

from hecate_agent.commands._hunt_dedup import _resolve_query_paths
from hecate_agent.commands.hunt import hunt
from hecate_agent.commands.monitor_metrics import _collect_hunts_metrics, _collect_purple_team_metrics, _find_siem_dir
from hecate_agent.core.workspace import load_workspace_env, workspace_root


@pytest.mark.parametrize("arguments", [["validate"], ["validate", "H-0001"]])
def test_validation_checks_selected_workspace_from_foreign_cwd(tmp_path, monkeypatch, sample_hunt_content, arguments):
    selected = tmp_path / "selected"
    (selected / "hunts").mkdir(parents=True)
    selected_file = selected / "hunts/H-0001.md"
    selected_file.write_text("This selected hunt is invalid.\n")
    foreign = tmp_path / "foreign"
    (foreign / "hunts").mkdir(parents=True)
    (foreign / "hunts/H-0001.md").write_text(sample_hunt_content)
    monkeypatch.chdir(foreign)
    monkeypatch.setenv("HECATE_WORKSPACE", str(selected))
    result = CliRunner().invoke(hunt, arguments)
    assert result.exit_code == 1, result.output
    assert "No hunt" not in result.output
    assert selected_file.read_text() == "This selected hunt is invalid.\n"


def test_validation_does_not_broaden_an_empty_selected_workspace(tmp_path, monkeypatch):
    selected = tmp_path / "empty-selected"
    (selected / "hunts").mkdir(parents=True)
    (tmp_path / "hunts").mkdir()
    (tmp_path / "hunts/H-9999.md").write_text("Invalid foreign content")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HECATE_WORKSPACE", str(selected))
    result = CliRunner().invoke(hunt, ["validate"])
    assert result.exit_code == 0
    assert "No hunt files found" in result.output
    assert "H-9999" not in result.output


def test_dedup_uses_selected_workspace_and_never_broadens_missing_scope(tmp_path, monkeypatch):
    selected = tmp_path / "renamed-catalog"
    root = selected / "queries"
    (root / "H-0001").mkdir(parents=True)
    monkeypatch.setenv("HECATE_WORKSPACE", str(selected))
    monkeypatch.chdir(tmp_path)
    assert _resolve_query_paths(None, None) == [root]
    assert _resolve_query_paths(None, "h-0001") == [root / "H-0001"]
    assert _resolve_query_paths(None, "H-9999") == []
    assert _resolve_query_paths("missing-directory", None) == []


def test_monitor_does_not_import_sibling_siem_state(tmp_path):
    selected = tmp_path / "selected"
    selected.mkdir()
    foreign = tmp_path / "Hecate-Public/.hecate/siem"
    foreign.mkdir(parents=True)
    (foreign / "drift_state.json").write_text("{}")
    assert _find_siem_dir(selected) is None
    own = selected / ".hecate/siem"
    own.mkdir(parents=True)
    (own / "drift_state.json").write_text("{}")
    assert _find_siem_dir(selected) == own


def test_missing_workspace_does_not_switch_to_another_catalog(tmp_path, monkeypatch):
    selected = tmp_path / "eval-fresh"
    selected.mkdir()
    foreign = tmp_path / "Hecate-Workspace/hunts"
    foreign.mkdir(parents=True)
    (foreign / "H-0001.md").write_text("---\nhunt_id: H-0001\n---\n")
    monkeypatch.chdir(foreign.parent)
    assert _collect_hunts_metrics(selected).total_hunts == 0
    assert _collect_purple_team_metrics(selected / "missing").hunts_validated == 0


def test_missing_explicit_workspace_is_honored(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    monkeypatch.setenv("HECATE_WORKSPACE", str(missing))
    assert workspace_root() == missing
    assert workspace_root(tmp_path / "explicit") == tmp_path / "explicit"


def test_environment_discovery_never_loads_old_home_checkout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    old = home / "betas/Hecate-Workspace"
    old.mkdir(parents=True)
    (old / ".env").write_text("HECATE_ISOLATION_TEST_VALUE=foreign\n")
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(fresh)
    monkeypatch.setenv("HECATE_WORKSPACE", str(fresh))
    monkeypatch.delenv("HECATE_ISOLATION_TEST_VALUE", raising=False)
    load_workspace_env()
    import os

    assert "HECATE_ISOLATION_TEST_VALUE" not in os.environ
