"""Credential roles fail closed in an isolated service."""

import pytest

from hecate_agent.core.splunk_credentials import splunk_token


def values():
    return {name: "-".join([role, "fixture"]) for name, role in [
        ("SPLUNK_READ_TOKEN", "reader"), ("SPLUNK_WRITE_TOKEN", "writer"),
        ("SPLUNK_TOKEN", "legacy"),
    ]}


def test_reader_and_writer_choose_distinct_credentials():
    env = values()
    assert splunk_token("read", env) == env["SPLUNK_READ_TOKEN"]
    assert splunk_token("write", env) == env["SPLUNK_WRITE_TOKEN"]


@pytest.mark.parametrize("role", ["read", "write"])
def test_strict_mode_never_falls_back_to_legacy_or_the_other_role(role):
    env = values()
    env["HECATE_STRICT_CREDENTIAL_ROLES"] = "1"
    env.pop("SPLUNK_READ_TOKEN" if role == "read" else "SPLUNK_WRITE_TOKEN")
    assert splunk_token(role, env) is None


def test_explicit_blank_disables_a_role_and_legacy_is_opt_in_compatible():
    env = values()
    env["SPLUNK_READ_TOKEN"] = ""
    assert splunk_token("read", env) is None
    env.pop("SPLUNK_READ_TOKEN")
    assert splunk_token("read", env) == env["SPLUNK_TOKEN"]
