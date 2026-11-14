"""
Pytest configuration and shared fixtures for Hecate tests.
"""

import shutil
import tempfile
from pathlib import Path

import pytest

from hecate_agent.core import attack_matrix

pytest_plugins = ("tests.offline_guard",)

# Live developer shells often export workspace / SIEM / LLM vars (or load them
# via dotenv). Those leak into unit tests that assert missing-file, missing-
# credential, or walk-up behavior. CI runners do not set them; clear them here
# so local suite results match CI.
_ENV_VARS_TO_ISOLATE = (
    "HECATE_WORKSPACE",
    "HECATE_HUNTING_KNOWLEDGE",
    "HECATE_LLM_PROVIDER",
    "HECATE_LLM_MODEL",
    "HECATE_LLM_SIMPLE_PROVIDER",
    "HECATE_LLM_SIMPLE_MODEL",
    "HECATE_LLM_SIMPLE_BASE_URL",
    "HECATE_LLM_COMPLEX_PROVIDER",
    "HECATE_LLM_COMPLEX_MODEL",
    "HECATE_LLM_COMPLEX_BASE_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "SPLUNK_HOST",
    "SPLUNK_TOKEN",
    "SPLUNK_PASSWORD",
    "SPLUNK_USERNAME",
    "SPLUNK_VERIFY_SSL",
)


@pytest.fixture(autouse=True)
def _isolate_live_operator_env(monkeypatch):
    for var in _ENV_VARS_TO_ISOLATE:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _reset_attack_matrix_provider(monkeypatch):
    """Undo a test's explicit `attack_matrix.reset_provider(...)` call, if it
    made one, after that test finishes.

    Several tests call `attack_matrix.reset_provider(FallbackProvider())` to
    exercise fallback behavior, with no corresponding teardown -- since the
    singleton is a plain module global (not test-scoped), that mutation
    otherwise leaks into every test that runs afterward in the same pytest
    session, silently swapping the real STIX-backed technique/tactic data
    for the fallback provider (which has no per-technique data at all) for
    any test that happens to run later and assumes the real provider is
    active. Order-dependent test pollution, caught when a real-data-dependent
    test (ATT&CK coverage misattribution) started failing only when run as
    part of the full suite, never in isolation.

    Deliberately does NOT snapshot-and-restore `_provider` unconditionally
    around every test -- an earlier version of this fixture did exactly
    that, and it was itself a bug: it also undid a test's first-ever
    *organic* cache warm (e.g. simply calling calculate_attack_coverage()),
    discarding the freshly-built singleton and forcing the next test to
    pay the multi-second STIX parse all over again. Repeated ~20x across
    the suite, that turned a 15s run into 156s. Only reset_provider() itself
    -- the deliberate, test-scoped mutation -- should be undone; normal
    lazy-loading must be left alone so the singleton stays warm and shared
    for the rest of the session, same as it is in production.
    """
    original = attack_matrix._provider
    mutated_via_reset_provider = False
    real_reset_provider = attack_matrix.reset_provider

    def tracking_reset_provider(provider: object = None) -> None:
        nonlocal mutated_via_reset_provider
        mutated_via_reset_provider = True
        real_reset_provider(provider)  # type: ignore

    monkeypatch.setattr(attack_matrix, "reset_provider", tracking_reset_provider)
    yield
    if mutated_via_reset_provider:
        attack_matrix._provider = original


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir)
    shutil.rmtree(tmpdir)


@pytest.fixture
def sample_hunt_content():
    """Provide sample hunt content for testing."""
    return """---
hunt_id: H-0001
title: Test Hunt
status: completed
date: 2025-12-02
hunter: Test Hunter
techniques: [T1003.001]
tactics: [credential-access]
platforms: [windows]
data_sources: [windows-event-logs]
tags: [lsass, credential-dumping]
true_positives: 1
false_positives: 0
---

# H-0001: Test Hunt

## LEARN: Prepare the Hunt

### Hypothesis Statement

Test hypothesis for credential dumping detection.

### Threat Context

LSASS memory access is a common technique used by adversaries.

## OBSERVE: Expected Behaviors

### What Normal Looks Like

Legitimate LSASS access by system processes.

### What Suspicious Looks Like

Unsigned processes accessing LSASS memory.

## CHECK: Execute & Analyze

### Data Source Information

- **Index/Data Source:** windows-event-logs
- **Time Range:** Last 7 days

### Hunting Queries

```spl
index=windows EventCode=10 TargetImage="*lsass.exe"
| stats count by SourceImage
```

## KEEP: Findings & Response

### Executive Summary

Found 1 true positive of credential dumping activity.

### Findings

- True Positive: Mimikatz detected on DESKTOP-001
"""


@pytest.fixture
def sample_config_content():
    """Provide sample config file content for testing."""
    return """siem: splunk
edr: crowdstrike
hunt_prefix: H
retention_days: 90
initialized: 2025-12-02T14:30:00
version: 0.2.2
"""


@pytest.fixture
def hecate_workspace(temp_dir, sample_config_content):
    """Create a complete Hecate workspace structure for testing."""
    # Create directories
    (temp_dir / "hunts").mkdir()
    (temp_dir / "queries").mkdir()
    (temp_dir / "runs").mkdir()
    (temp_dir / "templates").mkdir()

    # Create config file
    config_path = temp_dir / ".hecateconfig.yaml"
    config_path.write_text(sample_config_content)

    # Create AGENTS.md
    agents_path = temp_dir / "AGENTS.md"
    agents_path.write_text("# Hecate AI Assistant Instructions\n\nTest content.")

    yield temp_dir


@pytest.fixture
def sample_hunt_file(hecate_workspace, sample_hunt_content):
    """Create a sample hunt file in the workspace."""
    hunt_path = hecate_workspace / "hunts" / "H-0001.md"
    hunt_path.write_text(sample_hunt_content)
    return hunt_path


@pytest.fixture
def hecate_workspace_with_hunts(hecate_workspace, sample_hunt_content):
    """Create an Hecate workspace with sample hunt files."""
    # Create first hunt
    hunt1_path = hecate_workspace / "hunts" / "H-0001.md"
    hunt1_path.write_text(sample_hunt_content)

    # Create second hunt with different content
    hunt2_content = sample_hunt_content.replace("H-0001", "H-0002").replace("Test Hunt", "Second Hunt")
    hunt2_path = hecate_workspace / "hunts" / "H-0002.md"
    hunt2_path.write_text(hunt2_content)

    return hecate_workspace


# Custom markers for categorizing tests
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test (fast, isolated)")
    config.addinivalue_line("markers", "integration: mark test as an integration test (slower, multiple components)")
    config.addinivalue_line("markers", "slow: mark test as slow (skipped in quick test runs)")
