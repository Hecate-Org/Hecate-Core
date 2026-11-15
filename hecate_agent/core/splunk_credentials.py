"""Separate Splunk search credentials from saved-search writer credentials."""

from __future__ import annotations

import os
from typing import Mapping, Optional


def splunk_token(role: str = "read", env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    if role not in {"read", "write"}:
        raise ValueError("Unknown Splunk credential role")
    values = os.environ if env is None else env
    name = "SPLUNK_READ_TOKEN" if role == "read" else "SPLUNK_WRITE_TOKEN"
    if name in values:
        return values[name] or None
    if values.get("HECATE_STRICT_CREDENTIAL_ROLES", "").lower() in {"1", "true", "yes"}:
        return None
    # Compatibility for existing deployments; hardened services set strict mode.
    return values.get("SPLUNK_TOKEN") or values.get("SPLUNK_API_TOKEN")
