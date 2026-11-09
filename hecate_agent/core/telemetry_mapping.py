"""Telemetry mapping: valid OCSF fields, mapped to the organization's own fields.

R-0616's mapping flagged all six fields "NOT AN OCSF FIELD", and printed the
flags inline in the research document. Five were right apart from an event
class prefix the reference never uses (``process_activity.process.cmd_line``
for ``process.cmd_line``), and the validator's suggestions made it worse
("did you mean file.name?" for ``process.name``). Its Data Source Availability
said registry events were available because the environment template lists
them under an EDR product that is still "[To be configured]".

Here a field is normalized before it is judged, a field that is still invalid
is removed from the mapping and listed separately, a valid one is mapped to
the event field the environment profile documents for it, and availability
counts only what a configured telemetry section of the profile says.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from hecate_agent.core.ocsf_fields import canonical_paths, is_ocsf_field, suggest

#: A finding reads "field: what it captures"; only the part before the colon is the field.
_FIELD_IN_FINDING = re.compile(r"^\s*`?([A-Za-z_][A-Za-z0-9_.]*\.[A-Za-z0-9_.]+)`?\s*:\s*(.*)$", re.S)
#: Event class names the model writes in front of a field: the reference documents objects, not classes.
_CLASS_PREFIX = re.compile(
    r"^(process_activity|network_activity|file_activity|file_system_activity|dns_activity|http_activity|"
    r"registry_key_activity|registry_value_activity|module_activity|authentication|kernel_activity|"
    r"memory_activity|script_activity|detection_finding)\."
)
#: Where OCSF nests an object the model wrote at the root.
_ROOT_MOVES = {"parent_process.": "process.parent_process."}
#: The object an event class is about, for a class prefix followed by a bare attribute
#: (the A3 replay's ``file_activity.path`` means ``file.path``).
_CLASS_OBJECT = {
    "process_activity": "process", "file_activity": "file", "file_system_activity": "file", "dns_activity": "query",
    "module_activity": "module", "registry_key_activity": "reg_key", "registry_value_activity": "reg_value",
}  # fmt: skip

#: OCSF path -> names organizations give the same field. The first one the
#: environment profile documents is the mapping; none documented is "unmapped".
_ORG_NAMES: Dict[str, Tuple[str, ...]] = {
    "process.name": ("process_name", "image", "process", "processname", "exe"),
    "process.file.path": ("process_path", "image", "process_path_name"),
    "process.cmd_line": ("command_line", "commandline", "cmdline", "process_command_line"),
    "process.pid": ("pid", "process_id", "processid"),
    "process.parent_process.name": ("parent_process", "parent_process_name", "parentimage", "parent_image"),
    "process.parent_process.cmd_line": ("parent_command_line", "parentcommandline"),
    "actor.user.name": ("user", "username", "user_name", "targetusername"),
    "user.name": ("user", "username", "user_name", "targetusername"),
    "dst_endpoint.ip": ("dest_ip", "dst_ip", "destinationip", "dest"),
    "dst_endpoint.port": ("dest_port", "dst_port", "destinationport"),
    "dst_endpoint.hostname": ("dest_host", "dest_hostname", "destinationhostname"),
    "src_endpoint.ip": ("src_ip", "source_ip", "sourceip", "sourcenetworkaddress"),
    "src_endpoint.port": ("src_port", "source_port", "sourceport"),
    "device.hostname": ("computername", "host", "hostname", "dest"),
    "file.path": ("file_path", "target_filename", "targetfilename", "file"),
    "file.name": ("file_name", "filename"),
    "query.hostname": ("query", "query_name", "queryname", "dns_query"),
}  # fmt: skip


@dataclass
class TelemetryMap:
    """The mapping as rendered: kept findings (normalized and mapped), and removed fields."""

    findings: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)


def normalize_field(name: str) -> Optional[str]:
    """The documented OCSF path ``name`` means, or None when it is not one."""
    cleaned = name.strip().strip("`").lower()
    if is_ocsf_field(cleaned):
        return cleaned
    stripped = _CLASS_PREFIX.sub("", cleaned)
    for root, nested in _ROOT_MOVES.items():
        if stripped.startswith(root):
            stripped = nested + stripped[len(root) :]
    if is_ocsf_field(stripped):
        return stripped
    event_class = cleaned.split(".", 1)[0]
    if event_class in _CLASS_OBJECT and is_ocsf_field(f"{_CLASS_OBJECT[event_class]}.{stripped}"):
        return f"{_CLASS_OBJECT[event_class]}.{stripped}"
    return None


def environment_fields(environment: str) -> Dict[str, List[str]]:
    """``{label: [field, ...]}`` from the profile's "Common Fields" list ("- Endpoint: `a`, `b`")."""
    out: Dict[str, List[str]] = {}
    contract = _verified_contract_rows(environment)
    if contract is not None:
        for row in contract:
            names = re.findall(r"`([^`]+)`", row[3])
            if names:
                out[row[0]] = names
        return out
    if "unverified-template" in (environment or "").lower():
        return out
    in_list = False
    for line in (environment or "").splitlines():
        if re.match(r"^\s*-\s*\*\*common fields:?\*\*", line, re.I):
            in_list = True
            continue
        if not in_list:
            continue
        item = re.match(r"^\s{2,}-\s*([^:]+):\s*(.*)$", line)
        if not item:
            if line.strip():
                in_list = False
            continue
        names = re.findall(r"`([^`]+)`", item.group(2))
        if names:
            out[item.group(1).strip()] = names
    return out


def organization_field(path: str, documented: Dict[str, List[str]]) -> Optional[Tuple[str, str]]:
    """``(field, label)`` the environment documents for an OCSF path, or None."""
    for candidate in _ORG_NAMES.get(path, ()):
        for label, names in documented.items():
            match = next((n for n in names if n.lower() == candidate), None)
            if match:
                return match, label
    return None


def _target(path: str, documented: Dict[str, List[str]]) -> str:
    """ " → `field` (label)", or both sides for a bare ``network_endpoint`` path, or "unmapped"."""
    if path.startswith("network_endpoint."):
        # The reference documents the object; an event carries it as the
        # destination or the source endpoint, so both fields are candidates.
        leaf = path.split(".", 1)[1]
        sides = [organization_field(f"{side}_endpoint.{leaf}", documented) for side in ("dst", "src")]
        found = [m for m in sides if m]
        if found:
            return " → " + " / ".join(f"`{m[0]}`" for m in found) + f" ({found[0][1]}; destination / source endpoint)"
    mapped = organization_field(path, documented)
    return f" → `{mapped[0]}` ({mapped[1]})" if mapped else " → unmapped: the environment profile documents no field"


def map_findings(findings: List[str], environment: str = "") -> TelemetryMap:
    """Normalize, validate and map each "field: description" finding.

    Findings that name no field (prose, the no-telemetry marker) pass through.
    With no OCSF reference to check against, fields pass through unchanged:
    reporting every field invalid would be worse than not checking.
    """
    if not canonical_paths():
        return TelemetryMap(findings=list(findings))
    documented = environment_fields(environment)
    result = TelemetryMap()
    for finding in findings:
        match = _FIELD_IN_FINDING.match(finding)
        if match is None:
            result.findings.append(finding)
            continue
        written, description = match.group(1), match.group(2).strip()
        path = normalize_field(written)
        if path is None:
            hint = suggest(_CLASS_PREFIX.sub("", written.lower()))
            result.removed.append(f"`{written}`" + (f" (closest documented field: `{hint}`)" if hint else ""))
            continue
        target = _target(path, documented)
        origin = f" (written as `{written}`)" if path != written.strip("`").lower() else ""
        result.findings.append(f"`{path}`{target}{origin}: {description}")
    return result


# --- Data source availability ----------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\[(to be configured|specify|link to|tbd|todo)[^\]]*\]", re.I)
#: A configured section says what product it is; a template leaves the placeholder.
_PRODUCT_LINE = re.compile(r"^\s*-\s*\*\*(product|platform|firewalls|ids/ips):?\*\*\s*(.*)$", re.I)
_TELEMETRY_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "process_execution": ("process execution", "process creation", "process and lineage", "endpoint telemetry", "sysmon"),
    "file_operations": ("file event", "file operation", "file integrity", "file monitoring"),
    "network_connections": (
        "network connection", "network flow", "netflow", "firewall log", "proxy log", "dns log", "dns quer",
    ),
    "registry_events": ("registry modification", "registry event", "registry telemetry", "registry change"),
}  # fmt: skip


def _verified_contract_rows(environment: str) -> Optional[List[List[str]]]:
    """Read explicit source contracts; unknown rows must never become availability.

    Return None for legacy profiles, [] for a contract with no verified rows.
    Check metadata as well as the word 'verified': an unchanged placeholder row
    does not establish collection just because its status was changed.
    """
    rows: List[List[str]] = []
    in_contract = False
    found = False
    for line in (environment or "").splitlines():
        if line.startswith("## "):
            in_contract = line.strip().lower() == "## telemetry availability contract"
            found = found or in_contract
            continue
        if not in_contract or not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 7 or cells[1].lower() != "verified":
            continue
        missing = re.compile(r"\b(unknown|unverified|not verified|not supplied|tbd|to be configured)\b", re.I)
        if any(not cell or missing.search(cell) or _PLACEHOLDER.search(cell) for cell in cells[2:]):
            continue
        rows.append(cells)
    return rows if found else None


def _telemetry_sections(environment: str) -> List[List[str]]:
    """The ``###`` subsections under the profile's monitoring-tools heading, as lines."""
    sections: List[List[str]] = []
    in_tools = True  # an abridged profile may start at its ### sections
    lines = (environment or "").splitlines()
    if not any(line.startswith("### ") for line in lines):
        return [lines]
    for line in lines:
        if line.startswith("## "):
            in_tools = bool(re.search(r"(?i)security|monitoring|telemetry|logging|data sources", line))
            continue
        if not in_tools:
            continue
        if line.startswith("### "):
            sections.append([])
        elif sections:
            sections[-1].append(line)
    return sections


def documented_data_sources(environment: str) -> Dict[str, bool]:
    """Which data sources a configured telemetry section of the profile says it collects.

    Keywords count only in telemetry sections, on lines that are not
    template placeholders, in a section whose product is not itself a
    placeholder. The template's EDR section lists "registry modifications"
    under "Product: [To be configured]"; that documents nothing.
    """
    found = dict.fromkeys(_TELEMETRY_KEYWORDS, False)
    contract = _verified_contract_rows(environment)
    if contract is not None:
        for row in contract:
            # Match the event family and mapping only, not unrelated free-form
            # comments in provenance/retention columns.
            text = f"{row[0]} {row[3]}".lower()
            for source, keywords in _TELEMETRY_KEYWORDS.items():
                if any(keyword in text for keyword in keywords):
                    found[source] = True
        return found
    if "unverified-template" in (environment or "").lower():
        return found
    for lines in _telemetry_sections(environment):
        product = next((m.group(2) for m in map(_PRODUCT_LINE.match, lines) if m), "")
        if product and _PLACEHOLDER.search(product):
            continue
        text = " ".join(line for line in lines if not _PLACEHOLDER.search(line)).lower()
        for source, keywords in _TELEMETRY_KEYWORDS.items():
            if any(k in text for k in keywords):
                found[source] = True
    return found
