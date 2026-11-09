"""Context exports must not leak a sibling checkout into the selected workspace."""

import json
from types import SimpleNamespace

from click.testing import CliRunner

from hecate_agent.commands.context import context


def test_context_export_reads_selected_workspace_from_another_checkout(tmp_path, monkeypatch):
    selected = tmp_path / "workspace"
    checkout = tmp_path / "core"
    for directory, marker in ((selected, "selected-marker"), (checkout, "wrong-checkout-marker")):
        (directory / "knowledge").mkdir(parents=True)
        (directory / "knowledge" / "environment.md").write_text(marker)
        (directory / "knowledge" / "hunting-knowledge.md").write_text(marker + "-knowledge")
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("HECATE_WORKSPACE", str(selected))
    result = CliRunner().invoke(context, ["--full", "--format", "json"])
    assert result.exit_code == 0, result.output
    bundle = json.loads(result.output)
    assert "selected-marker" in bundle["environment"]
    assert any("selected-marker-knowledge" in item["content"] for item in bundle["domain_knowledge"])
    assert "wrong-checkout-marker" not in result.output


def test_explicit_api_workspace_reaches_environment_and_hypothesis_rules(tmp_path, monkeypatch):
    import hecate_agent.api as api

    selected = tmp_path / "selected"
    other = tmp_path / "other"
    (selected / "knowledge").mkdir(parents=True)
    other.mkdir()
    (selected / "knowledge" / "environment.md").write_text("explicit-api-estate")
    monkeypatch.chdir(other)
    monkeypatch.setenv("HECATE_WORKSPACE", str(other))
    seen = []

    class FakeAgent:
        def __init__(self, **kwargs):
            pass

        def execute(self, data):
            seen.append(data)
            return SimpleNamespace(success=True, data="fake-hypothesis", metadata={})

    monkeypatch.setattr(api, "HypothesisGeneratorAgent", FakeAgent)
    output, _ = api.generate_hypothesis_with_metrics("source text", workspace=selected)
    assert output == "fake-hypothesis"
    assert seen[0].workspace == selected
    assert "explicit-api-estate" in seen[0].environment["environment_md"]
    assert not (selected / "research").exists()
