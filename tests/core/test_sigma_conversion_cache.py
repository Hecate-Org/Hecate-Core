"""Conversion reuse must not share mutable results or bypass validation."""

from concurrent.futures import ThreadPoolExecutor
import sys
from types import SimpleNamespace

import pytest

from hecate_agent import api
from hecate_agent.core import sigma_transpiler as st
from hecate_agent.core.query_validator import QueryValidationResult, ValidationIssue

RULE = "title: Test process\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\cmd.exe'\n  condition: selection\n"
TARGET = st.SigmaTranspiler.TARGET_SPLUNK


@pytest.fixture
def harness(monkeypatch):
    st.SigmaTranspiler.clear_cache()
    state = {"calls": [], "validations": [], "valid": True, "fail": False}
    monkeypatch.setattr(st, "PYSIGMA_AVAILABLE", True)

    def convert(self, rule, target):
        state["calls"].append((rule, target))
        if state["fail"]:
            raise ValueError("Backend temporarily unavailable")
        return f"{target}: {rule}"

    def validate(target, query):
        state["validations"].append((target, query))
        issues = [] if state["valid"] else [ValidationIssue("error", "policy", "Rejected by current validator")]
        return QueryValidationResult(target, target, query, state["valid"], 1.0, issues)

    monkeypatch.setattr(st.SigmaTranspiler, "_transpile_single_target", convert)
    monkeypatch.setattr(st, "QueryValidator", lambda: SimpleNamespace(validate=validate))
    yield state
    st.SigmaTranspiler.clear_cache()


def test_api_instances_reuse_queries_but_not_mutable_results(harness):
    first = api.transpile_sigma_rule(RULE, [TARGET])[TARGET]
    expected = first.query
    first.query = "caller changed this result"
    first.validation.issues.append(ValidationIssue("error", "caller", "caller mutation"))
    second = api.transpile_sigma_rule(RULE, [TARGET])[TARGET]
    assert second.query == expected
    assert second.validation.issues == []
    assert second is not first
    assert len(harness["calls"]) == 1
    assert len(harness["validations"]) == 2


def test_exact_yaml_and_target_changes_do_not_reuse_old_conversion(harness):
    api.transpile_sigma_rule(RULE, [TARGET])
    changed = RULE.replace("cmd.exe", "powershell.exe")
    assert "powershell" in api.transpile_sigma_rule(changed, [TARGET])[TARGET].query
    api.transpile_sigma_rule(RULE, [st.SigmaTranspiler.TARGET_MDE])
    assert len(harness["calls"]) == 3
    api.transpile_sigma_rule(RULE, [TARGET])
    assert len(harness["calls"]) == 3


def test_cached_query_is_revalidated_and_invalid_results_are_not_retained(harness):
    assert api.transpile_sigma_rule(RULE, [TARGET])[TARGET].success
    harness["valid"] = False
    assert not api.transpile_sigma_rule(RULE, [TARGET])[TARGET].success
    assert len(harness["calls"]) == 1
    harness["valid"] = True
    assert api.transpile_sigma_rule(RULE, [TARGET])[TARGET].success
    assert len(harness["calls"]) == 2


def test_failed_conversion_can_recover_without_cache_clear(harness):
    harness["fail"] = True
    assert not api.transpile_sigma_rule(RULE, [TARGET])[TARGET].success
    harness["fail"] = False
    assert api.transpile_sigma_rule(RULE, [TARGET])[TARGET].success
    assert len(harness["calls"]) == 2


def test_clear_backend_cache_also_invalidates_query_text(harness):
    api.transpile_sigma_rule(RULE, [TARGET])
    st.clear_backend_cache()
    api.transpile_sigma_rule(RULE, [TARGET])
    assert len(harness["calls"]) == 2


def test_concurrent_identical_requests_convert_once(harness):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: api.transpile_sigma_rule(RULE, [TARGET])[TARGET].query, range(4)))
    assert len(set(results)) == 1
    assert len(harness["calls"]) == 1
    assert len(harness["validations"]) == 4


def test_cache_is_bounded_and_large_queries_are_not_retained(harness, monkeypatch):
    monkeypatch.setattr(st, "MAX_QUERY_CACHE_ENTRIES", 2)
    for title in ("one", "two", "three", "one"):
        api.transpile_sigma_rule(RULE.replace("Test process", title), [TARGET])
    assert len(harness["calls"]) == 4
    assert len(st._QUERY_CACHE) == 2
    st.clear_backend_cache()
    monkeypatch.setattr(st, "MAX_CACHED_QUERY_BYTES", 1)
    api.transpile_sigma_rule(RULE, [TARGET])
    api.transpile_sigma_rule(RULE, [TARGET])
    assert len(harness["calls"]) == 6


def test_subclass_instance_settings_are_not_shared(harness):
    class Custom(st.SigmaTranspiler):
        def _transpile_single_target(self, rule, target):
            return self.query_text

    one, two = Custom(), Custom()
    one.query_text, two.query_text = "first custom mapping", "second custom mapping"
    assert one.transpile(RULE, [TARGET])[TARGET].query == one.query_text
    assert two.transpile(RULE, [TARGET])[TARGET].query == two.query_text


def test_unchanged_native_files_keep_identity_and_permissions(tmp_path):
    path = tmp_path / "query.spl"
    assert st.write_query_if_changed(path, "  index=test  ")
    path.chmod(0o600)
    before = path.stat()
    assert not st.write_query_if_changed(path, "index=test\n")
    assert (path.stat().st_ino, path.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert st.write_query_if_changed(path, "index=updated")
    assert path.read_text() == "index=updated\n"
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
    path.unlink()
    assert st.write_query_if_changed(path, "index=updated")


def test_partial_artifact_write_keeps_already_returned_paths(tmp_path, monkeypatch):
    original = st.write_query_if_changed

    def write(path, query):
        if path.suffix == ".kql":
            raise PermissionError("Destination is read-only")
        return original(path, query)

    monkeypatch.setattr(st, "write_query_if_changed", write)
    results = {
        "splunk": SimpleNamespace(success=True, query="index=test", file_extension=".spl"),
        "kql": SimpleNamespace(success=True, query="DeviceEvents", file_extension=".kql"),
    }
    paths = []
    with pytest.raises(PermissionError):
        paths.extend(st.write_transpiled_queries(tmp_path / "rule.yml", results))
    assert paths == [tmp_path / "rule.spl"]
