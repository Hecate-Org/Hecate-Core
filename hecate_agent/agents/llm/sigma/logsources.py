"""Logsource derivation, platform compatibility, and selector utilities."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Sigma log source categories this agent will emit. Restricted to the ones
# with well-established field names across backends -- an invented category
# converts to nothing and silently drops the rule at pySigma time.
VALID_LOGSOURCE_CATEGORIES = {
    "process_creation",
    "network_connection",
    "dns_query",
    "file_event",
    "registry_event",
    "image_load",
    "authentication",
    "proxy",
    "webserver",
    "cloud_audit",
    "identity_audit",
    "container_runtime",
}

#: Field names each log source actually carries, so the prompt for one
#: category never offers another's fields -- a borrowed field name matches
#: nothing and fails silently at pySigma conversion time.
_LOGSOURCE_FIELDS = {
    "process_creation": "Image, CommandLine, ParentImage, OriginalFileName, User",
    "network_connection": "DestinationIp, DestinationHostname, DestinationPort, Initiated, Image",
    "dns_query": "QueryName, QueryResults, Image",
    "file_event": "TargetFilename, Image, User",
    "registry_event": "TargetObject, Details, EventType, Image",
    "image_load": "ImageLoaded, Image, Signed, Signature",
    "authentication": (
        "TargetUserName, SubjectUserName, LogonType, AuthenticationPackageName, WorkstationName, IpAddress, Status, SubStatus"
    ),
    "proxy": (
        "c-uri, c-uri-stem, c-uri-query, c-uri-extension, c-useragent, cs-cookie, cs-host, cs-method, cs-referrer, sc-status, src_ip, dst_ip"
    ),
    "webserver": "cs-method, cs-uri-stem, cs-uri-query, cs-user-agent, cs-cookie, cs-referrer, sc-status, c-ip",
    "cloud_audit": ("eventSource, eventName, userIdentity, sourceIPAddress, userAgent, awsRegion, requestParameters, action"),
    "identity_audit": (
        "eventName, operationType, appId, appDisplayName, targetResources, initiatedBy, roles, permissions, status"
    ),
    "container_runtime": (
        "Image, ContainerId, ContainerName, CommandLine, VolumeMount, Privileged, HostPath, User, Namespace"
    ),
}

#: Sigma aggregation grammar: ``<func>(<field>?) [by <field>] <op> <number>``.
_AGGREGATION_RE = re.compile(
    r"^(?:count|min|max|avg|sum)\s*\(\s*[A-Za-z0-9_.\-]*\s*\)"
    r"(?:\s+by\s+[A-Za-z0-9_.\-]+)?"
    r"\s*(?:>=|<=|==|!=|>|<|=)\s*\d+(?:\.\d+)?$",
    re.IGNORECASE,
)

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

# technique prefix -> log source categories that technique is observable in.
_TECHNIQUE_LOGSOURCES: Dict[str, Set[str]] = {
    "T1059": {"process_creation"},
    "T1106": {"process_creation"},
    "T1204": {"process_creation"},
    "T1620": {"process_creation", "image_load"},
    "T1027": {"process_creation", "file_event"},
    "T1140": {"process_creation"},
    "T1105": {"network_connection", "file_event"},
    "T1041": {"network_connection"},
    "T1071": {"network_connection", "dns_query"},
    "T1090": {"network_connection"},
    "T1005": {"file_event", "process_creation"},
    "T1083": {"file_event", "process_creation"},
    "T1070": {"file_event"},
    "T1574": {"image_load", "file_event"},
    "T1547": {"registry_event", "process_creation", "file_event"},
    "T1543": {"registry_event", "process_creation"},
    "T1112": {"registry_event"},
    "T1611": {"container_runtime", "process_creation"},
    "T1610": {"container_runtime", "process_creation"},
    "T1059.013": {"container_runtime", "process_creation"},
    "T1612": {"container_runtime", "process_creation"},
    "T1613": {"container_runtime", "process_creation"},
    "T1562": {"process_creation", "file_event"},
    "T1003": {"process_creation", "file_event"},
    "T1218": {"process_creation"},
    "T1567": {"process_creation", "network_connection"},
    "T1564": {"process_creation", "file_event"},
    "T1573": {"network_connection"},
    "T1104": {"network_connection", "process_creation"},
    "T1485": {"process_creation", "file_event"},
    "T1546": {"process_creation", "file_event", "registry_event"},
    "T1110": {"authentication"},
    "T1078": {"authentication"},
    "T1078.004": {"authentication", "identity_audit", "cloud_audit"},
    "T1098": {"authentication"},
    "T1098.003": {"authentication", "identity_audit", "cloud_audit"},
    "T1621": {"authentication"},
    "T1550": {"authentication"},
    "T1550.001": {"authentication", "identity_audit"},
    "T1528": {"identity_audit", "cloud_audit"},
    "T1538": {"cloud_audit"},
    "T1580": {"cloud_audit"},
    "T1530": {"cloud_audit"},
    "T1556": {"authentication", "registry_event"},
    "T1187": {"authentication", "network_connection"},
    "T1566": {"file_event", "network_connection"},
    "T1598": {"network_connection"},
    "T1036": {"process_creation", "file_event"},
    "T1203": {"process_creation", "image_load"},
    "T1068": {"process_creation"},
    "T1557": {"network_connection", "authentication"},
    "T1021": {"authentication", "network_connection"},
    "T1189": {"network_connection", "proxy"},
    "T1190": {"webserver", "network_connection", "process_creation"},
    "T1505": {"webserver", "file_event", "process_creation"},
    "T1595": {"webserver", "network_connection"},
    "T1133": {"network_connection", "authentication"},
    "T1486": {"file_event", "process_creation"},
    "T1053": {"process_creation", "file_event"},
    "T1037": {"process_creation", "file_event", "registry_event"},
}

_INDICATOR_LOGSOURCES: Dict[str, Set[str]] = {
    "ip-dst": {"network_connection"},
    "ip-src": {"network_connection"},
    "domain": {"dns_query", "network_connection"},
    "hostname": {"dns_query", "network_connection"},
    "url": {"network_connection"},
    "uri": {"network_connection"},
    "proxy.c-uri": {"proxy"},
    "c-uri": {"proxy"},
    "proxy": {"proxy"},
    "filename": {"file_event", "process_creation"},
    "filepath": {"file_event"},
    "md5": {"file_event"},
    "sha1": {"file_event"},
    "sha256": {"file_event"},
    "regkey": {"registry_event"},
    "mutex": {"process_creation"},
    "ipv4": {"network_connection"},
    "ipv6": {"network_connection"},
    "filehash-md5": {"file_event"},
    "filehash-sha1": {"file_event"},
    "filehash-sha256": {"file_event"},
}

_PLATFORM_ONLY_LOGSOURCES: Dict[str, Any] = {
    "registry_event": "windows",
    "container_runtime": {"containers", "linux"},
}

APPLIANCE_PLATFORMS = frozenset({"network devices"})
HOST_SENSOR_LOGSOURCES = frozenset({"process_creation", "file_event", "registry_event", "image_load"})


def applicable_logsources(
    techniques: List[str],
    indicator_types: Optional[List[str]] = None,
) -> List[str]:
    """Derive which Sigma log sources this hunt should cover."""
    found: Set[str] = set()

    for technique in techniques or []:
        normalised = str(technique).upper().strip()
        for prefix, sources in _TECHNIQUE_LOGSOURCES.items():
            if normalised.startswith(prefix):
                found |= sources

    for indicator_type in indicator_types or []:
        found |= _INDICATOR_LOGSOURCES.get(str(indicator_type).lower().strip(), set())

    if not found:
        logger.warning(
            "No log source maps to techniques %s or indicator types %s; "
            "falling back to process_creation, which may not carry this behaviour",
            list(techniques or []),
            list(indicator_types or []),
        )
        return ["process_creation"]
    return sorted(found)


def appliance_only(platforms: List[str]) -> bool:
    """Whether every platform the hunt is scoped to is an appliance without host sensors."""
    known = {str(p).strip().lower() for p in platforms or [] if str(p).strip()}
    return bool(known) and known <= APPLIANCE_PLATFORMS


def _platform_consistent_logsources(logsources: List[str], platforms: List[str]) -> List[str]:
    """Drop log sources none of the hunt's platforms can produce."""
    known = {str(p).strip().lower() for p in platforms or [] if str(p).strip()}
    if not known:
        return logsources
    kept: List[str] = []
    for ls in logsources:
        req = _PLATFORM_ONLY_LOGSOURCES.get(ls, "")
        if not req:
            kept.append(ls)
        elif isinstance(req, str) and req in known:
            kept.append(ls)
        elif isinstance(req, (set, list, tuple, frozenset)) and bool(set(req) & known):
            kept.append(ls)
    if appliance_only(platforms):
        kept = [ls for ls in kept if ls not in HOST_SENSOR_LOGSOURCES]
    for dropped in sorted(set(logsources) - set(kept)):
        logger.info("Skipping %s: no platform of this hunt (%s) produces it", dropped, ", ".join(sorted(known)))
    return kept or (["webserver"] if appliance_only(platforms) else ["process_creation"])


_HASH_TYPES: Dict[str, Tuple[str, int]] = {
    "md5": ("MD5", 32),
    "filehash-md5": ("MD5", 32),
    "sha1": ("SHA1", 40),
    "filehash-sha1": ("SHA1", 40),
    "sha256": ("SHA256", 64),
    "filehash-sha256": ("SHA256", 64),
    "imphash": ("IMPHASH", 32),
    "filehash-imphash": ("IMPHASH", 32),
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def hash_selectors(indicators: Dict[str, List[str]]) -> List[str]:
    """``ALGO=hex`` values for every well-formed hash indicator, in order."""
    selectors: List[str] = []
    for itype, values in (indicators or {}).items():
        spec = _HASH_TYPES.get(str(itype).lower().strip())
        if not spec:
            continue
        label, length = spec
        for value in values:
            text = str(value).strip()
            if len(text) == length and _HEX_RE.match(text):
                selector = f"{label}={text.lower()}"
                if selector not in selectors:
                    selectors.append(selector)
    return selectors


_IP_TYPES = frozenset({"ip-dst", "ip-src", "ipv4", "ipv6", "ip-dst|port", "ip-src|port"})
_NAME_TYPES = frozenset({"domain", "hostname"})
_URL_TYPES = frozenset({"url", "uri", "link"})
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_URL_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?([^/:?#\s]+)", re.IGNORECASE)


def _global_ip(value: str) -> Optional[str]:
    """The address in ``1.2.3.4``, ``1.2.3.4|443`` or ``1.2.3.4:443``, if routable."""
    import ipaddress

    text = value.strip().split("|", 1)[0]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _classify_network_value(kind: str, value: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(address, exact name, ``.domain`` suffix) one indicator value contributes."""
    if kind in _IP_TYPES:
        return _global_ip(value), None, None
    if kind == "domain|ip":
        name, _, address = value.partition("|")
        name = name.lower()
        return _global_ip(address), name if _DOMAIN_RE.match(name) else None, None
    if kind not in _NAME_TYPES and kind not in _URL_TYPES:
        return None, None, None
    if kind in _URL_TYPES:
        match = _URL_HOST_RE.match(value)
        value = match.group(1) if match else ""
    name = value.lower().rstrip(".")
    if _global_ip(name):
        return _global_ip(name), None, None
    if not _DOMAIN_RE.match(name):
        return None, None, None
    return None, name, "." + name if kind == "domain" else None


def network_selectors(indicators: Dict[str, List[str]]) -> Tuple[List[str], List[str], List[str]]:
    """(addresses, exact host names, ``.domain`` suffixes) from supplied indicators."""
    buckets: Tuple[List[str], List[str], List[str]] = ([], [], [])
    for itype, values in (indicators or {}).items():
        kind = str(itype).lower().strip()
        for raw in values:
            for bucket, found in zip(buckets, _classify_network_value(kind, str(raw).strip())):
                if found and found not in bucket:
                    bucket.append(found)
    return buckets
