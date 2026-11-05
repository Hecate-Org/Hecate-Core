"""Semantic checks for a Sigma rule: does it mean what it says, on one real event?

Syntax validation (pySigma) accepts a rule whose fields belong to another log
source, whose selections cannot all hold on one event, or whose description
promises matching the selection does not do. H-0618's rules had each of these:

- ``ParentImage`` and ``IpAddress`` in an ``image_load`` rule, and
  ``DestinationIp``/``DestinationPort`` in a ``process_creation`` rule;
- ``Hashes``, ``Image`` and ``TargetFilename`` AND-ed on a ``file_event``, which
  carries no hashes;
- the ``Beep`` API matched in ``CommandLine``, where an API call never appears;
- a DNS rule described as matching subdomains with exact ``QueryName`` values.

Each check returns the reason the rule is wrong, or ``None``. The field table
is Sigma's taxonomy for the Windows/Sysmon-style categories the generator
writes; it is shared with ``eval-gold`` so the generator and the gold set agree
on what a valid field is. No backend-specific field mapping is configured, so
backend readiness is out of scope here.
"""

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

#: Fields each Sigma log source category carries.
SIGMA_FIELDS: Dict[str, Tuple[str, ...]] = {
    "process_creation": (
        "Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "User",
        "Hashes", "CurrentDirectory", "IntegrityLevel", "Product", "Company", "Description",
        "FileVersion", "ParentUser", "ProcessId", "ParentProcessId", "LogonId",
    ),
    "file_event": ("TargetFilename", "Image", "User", "CreationUtcTime", "ProcessId"),
    "network_connection": (
        "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName", "SourceIp",
        "SourceHostname", "SourcePort", "Initiated", "Image", "Protocol", "User", "ProcessId",
    ),
    "dns_query": ("QueryName", "QueryResults", "QueryStatus", "Image", "ProcessId", "User"),
    "image_load": (
        "ImageLoaded", "Image", "Signed", "Signature", "SignatureStatus", "Hashes",
        "OriginalFileName", "Product", "Company", "Description", "ProcessId", "User",
    ),
    "registry_event": ("TargetObject", "Details", "EventType", "Image", "NewName", "ProcessId", "User"),
    "authentication": (
        "TargetUserName", "SubjectUserName", "LogonType", "AuthenticationPackageName",
        "WorkstationName", "IpAddress", "Status", "SubStatus",
    ),
    "proxy": (
        "c-uri", "c-uri-extension", "c-uri-query", "c-uri-stem", "c-useragent", "cs-bytes", "cs-cookie",
        "cs-host", "cs-method", "cs-referrer", "cs-version", "r-dns", "sc-bytes", "sc-status", "src_ip", "dst_ip",
    ),
    "webserver": ("cs-uri-query", "cs-uri-stem", "cs-method", "cs-referrer", "cs-user-agent", "sc-status", "c-ip"),
    "cloud_audit": (
        "eventSource", "eventName", "userIdentity", "sourceIPAddress", "userAgent",
        "awsRegion", "requestParameters", "responseElements", "errorCode", "errorMessage",
        "serviceName", "action", "recipientAccountId", "resources",
    ),
    "identity_audit": (
        "eventName", "operationType", "appId", "appDisplayName", "targetResources",
        "initiatedBy", "userPrincipalName", "roles", "permissions", "ipAddress",
        "status", "reason", "clientAppUsed", "correlationId",
    ),
    "container_runtime": (
        "Image", "ContainerId", "ContainerName", "CommandLine", "ImageId",
        "Namespace", "PodName", "Repository", "Tag", "VolumeMount",
        "Privileged", "Capabilities", "User", "HostPath",
    ),
}  # fmt: skip

#: Fields naming the process an event belongs to.
IMAGE_FIELDS = frozenset({"image", "parentimage", "originalfilename"})
#: Files that are opened, never run as a process image.
NON_EXECUTABLE = (".txt", ".log", ".docx", ".doc", ".pdf", ".zip", ".rar", ".7z", ".dat", ".png", ".jpg")
#: A description promising subdomain or suffix matching, which only an
#: ``endswith``/``contains`` modifier or a leading wildcard delivers.
SUFFIX_CLAIM_RE = re.compile(r"(?i)\bsub-?domains?\b|\bsuffix\b|\bwildcard\b")

#: Windows API and Linux syscall names: code calls them, no command line carries them.
API_NAMES = frozenset(
    {
        "memfd_create", "virtualalloc", "virtualallocex", "virtualprotect", "createthread", "createremotethread",
        "rtlmovememory", "waitforsingleobject", "getprocaddress", "loadlibrary", "loadlibrarya", "loadlibraryw", "beep", "allocadsmem", "reallocadsmem",
        "ntallocatevirtualmemory", "writeprocessmemory", "execve", "ptrace", "mmap", "mprotect",
    }
)  # fmt: skip
_COMMAND_LINE_FIELDS = frozenset({"commandline", "parentcommandline"})
#: Programs whose command line can carry inline code, and with it API names.
_SCRIPT_HOSTS = ("powershell", "pwsh", "cscript", "wscript", "mshta", "python", "node", "perl", "ruby", "bash", "sh.exe")
_FILE_NAME_FIELDS = frozenset({"image", "parentimage", "originalfilename", "imageloaded", "targetfilename"})
#: File extensions that are not also top-level domains (.zip and .mov are TLDs).
_FILE_EXTENSION_RE = re.compile(
    r"\.(txt|log|docx?|xlsx?|pdf|exe|dll|sys|ps1|bat|cmd|vbs|js|hta|lnk|iso|dat|bin|tmp|rar|7z)$", re.IGNORECASE
)
#: An elision copied from a report: "Beijing Institute of Technology_..._resume.docx".
_ELLIPSIS_RE = re.compile(r"\.\.\.|…")
_LOCAL_PATH_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "currentdirectory"})
_URL_FIELDS = frozenset({"c-uri", "c-uri-stem", "cs-uri-stem", "cs-uri", "url", "uri", "requesturl"})
_HOST_FIELDS = frozenset({"destinationhostname", "queryname", "cs-host", "r-dns"})
#: Fields that hold one value per event, so two AND-ed constraints must agree.
_SINGLE_VALUED = frozenset(
    {
        "image", "parentimage", "originalfilename", "targetfilename", "imageloaded", "destinationip",
        "destinationport", "destinationhostname", "queryname", "targetobject", "sourceip",
    }
)  # fmt: skip
_SCALAR_FIELDS = _SINGLE_VALUED | frozenset({"ipaddress", "sourcehostname", "sourceport", "user", "username", "computername"})


def repair_sigma_semantics(detection: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Self-healing rewriter for Sigma detection blocks.

    Auto-repairs mathematically impossible modifier combinations, such as '|all'
    on single-valued scalar fields (e.g. DestinationIp|all, Image|all, CommandLine|all
    without substring modifiers). Strips '|all' to restore standard Sigma OR-list matching.

    Returns:
        (repaired_detection_dict, list_of_repair_descriptions)
    """
    if not isinstance(detection, dict):
        return {}, []

    repairs: List[str] = []

    def _repair_block(block: Dict[str, Any]) -> Dict[str, Any]:
        new_block: Dict[str, Any] = {}
        for key, val in block.items():
            if not isinstance(key, str) or "|" not in key:
                new_block[key] = val
                continue

            parts = [p.strip() for p in key.split("|")]
            base = parts[0]
            base_lower = base.lower()
            modifiers = [m.lower() for m in parts[1:]]

            if "all" in modifiers:
                has_sub = any(m in ("contains", "startswith", "endswith", "re") for m in modifiers)
                is_scalar_exact = base_lower in _SCALAR_FIELDS and not has_sub
                is_net_field = base_lower in ("destinationip", "sourceip", "destinationport", "sourceport", "ipaddress")
                is_cmd_exact = base_lower in ("commandline", "parentcommandline") and not has_sub

                if is_scalar_exact or is_net_field or is_cmd_exact:
                    filtered_mods = [m for m in parts[1:] if m.strip().lower() != "all"]
                    new_key = "|".join([base] + filtered_mods) if filtered_mods else base
                    repairs.append(f"Stripped impossible '|all' modifier from '{key}' -> '{new_key}' on scalar field {base!r}")
                    if new_key in new_block:
                        existing = new_block[new_key]
                        combined = _values(existing) + [v for v in _values(val) if v not in _values(existing)]
                        new_block[new_key] = combined
                    else:
                        new_block[new_key] = val
                    continue

            new_block[key] = val
        return new_block

    new_detection: Dict[str, Any] = {}
    for name, item in detection.items():
        if name in ("condition", "timeframe"):
            new_detection[name] = item
        elif isinstance(item, dict):
            new_detection[name] = _repair_block(item)
        elif isinstance(item, list):
            new_detection[name] = [_repair_block(sub_item) if isinstance(sub_item, dict) else sub_item for sub_item in item]
        else:
            new_detection[name] = item

    repairs += _shell_child_of_runtime(new_detection)
    return new_detection, repairs


#: Runtimes that spawn a shell for the code they run: Node-RED's exec node, a Java web app, a Python service.
_RUNTIME_IMAGE_RE = re.compile(r"(^|[\\/])(node|nodejs|java|python[\d.]*|ruby|perl|php[\d.-]*|php-fpm)(\.exe)?$", re.IGNORECASE)
#: A command line that begins with a shell: the shell's own, never its parent's.
_SHELL_COMMAND_RE = re.compile(r"^\s*((/usr)?/bin/)?(ba|da|z)?sh\s+-c\b|^\s*cmd(\.exe)?\s+/c\b", re.IGNORECASE)


def _shell_child_of_runtime(detection: Dict[str, Any]) -> List[str]:
    """Move a runtime from ``Image`` to ``ParentImage`` when the rule ANDs it with a shell's command line.

    H-0018's host rule for Node-RED's exec node read ``Image|endswith: /node``
    and ``CommandLine|contains: /bin/sh -c``: one process that is both node and
    a shell, which never occurs. The shell is node's child, so node is the
    parent image. Applied only when nothing names a parent already and the
    condition joins the selections with ``and`` alone.
    """
    condition = str(detection.get("condition", ""))
    tokens = set(_condition_tokens(condition))
    if not condition or tokens & {"or", "not"} or ("of" in tokens and "all" not in tokens):
        return []
    named = [(n, b) for n, b in blocks(detection)]
    if any(base_field(k).lower() == "parentimage" for _, b in named for k in b):
        return []
    shell = any(
        base_field(k).lower() == "commandline" and any(_SHELL_COMMAND_RE.search(v) for v in _values(val))
        for _, b in named
        for k, val in b.items()
    )
    if not shell:
        return []
    repairs: List[str] = []
    for name, block in named:
        for key in [k for k in block if base_field(k).lower() == "image"]:
            values = _values(block[key])
            if values and all(_RUNTIME_IMAGE_RE.search(v.strip("*")) for v in values):
                new_key = "ParentImage" + key[len(key.split("|")[0]) :]
                block[new_key] = block.pop(key)
                repairs.append(f"Moved runtime {values} from '{key}' to '{new_key}' in {name}: the shell is its child")
    return repairs


repair_scalar_all_modifiers = repair_sigma_semantics


def base_field(key: Any) -> str:
    return str(key).split("|")[0].strip()


def _modifiers(key: Any) -> List[str]:
    return [m.strip().lower() for m in str(key).split("|")[1:]]


def _values(raw: Any) -> List[str]:
    if raw is None:
        return []
    return [str(v) for v in raw] if isinstance(raw, list) else [str(raw)]


def blocks(detection: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Each selection map with its name; a list of maps is OR-ed, so each map is its own block."""
    for name, block in detection.items():
        if name == "condition":
            continue
        for item in block if isinstance(block, list) else [block]:
            if isinstance(item, dict):
                yield str(name), item


# --- Field and value checks ------------------------------------------------------------------


def field_outside_category(detection: Dict[str, Any], category: str) -> Optional[str]:
    allowed = SIGMA_FIELDS.get(category)
    if not allowed:
        return None
    lowered = {f.lower() for f in allowed}
    for _, block in blocks(detection):
        for key in block:
            field = base_field(key)
            if field.lower() not in lowered:
                return (
                    f"{field} is not a {category} field, so the rule can never match; "
                    f"{category} carries {', '.join(allowed[:8])}. Put other telemetry in its own rule"
                )
    return None


def non_executable_image(detection: Dict[str, Any]) -> Optional[str]:
    """A document or archive as a process image or a loaded module.

    Word opening a .docx loads no .docx: H-0618 matched ``ImageLoaded|endswith: .docx``.
    """
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            if field not in IMAGE_FIELDS and field != "imageloaded":
                continue
            what = "a loaded module" if field == "imageloaded" else "a process image"
            for value in _values(raw):
                if value.strip().strip("*").lower().endswith(NON_EXECUTABLE):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, a file that is opened, never {what}; "
                        "match the program that opens it, and the file in CommandLine or TargetFilename"
                    )
    return None


def _bare(value: str) -> str:
    return value.strip().strip("*").strip().strip("'\"").removesuffix("()").lower()


def api_in_command_line(detection: Dict[str, Any]) -> Optional[str]:
    """An API or syscall name matched where only command lines, files and modules appear.

    H-0618 matched the ``Beep`` API in ``cmd.exe``'s ``CommandLine``, and on a
    later run in ``ImageLoaded`` (Beep lives in kernel32.dll; no module is
    named after it). A script host's command line can carry inline code that
    names APIs (PowerShell P/Invoke), so a command-line match is rejected only
    when the rule pins its process to something that is not a script host.
    """
    pinned = _field_values(detection, "image") + _field_values(detection, "originalfilename")
    script_host_or_unpinned = not pinned or any(h in v for v in pinned for h in _SCRIPT_HOSTS)
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            in_command_line = field in _COMMAND_LINE_FIELDS
            if in_command_line and script_host_or_unpinned:
                continue
            if not in_command_line and field not in _FILE_NAME_FIELDS:
                continue
            for value in _values(raw):
                bare = _bare(value)
                named = bare in API_NAMES or (
                    in_command_line and any(len(api) >= 10 and re.search(rf"\b{api}\b", bare) for api in API_NAMES)
                )
                if named:
                    where = "no command line shows it" if in_command_line else "it is not a file or module name"
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, an API or system call; a program calls it "
                        f"at run time and {where}"
                    )
    return None


def number_as_path(detection: Dict[str, Any]) -> Optional[str]:
    """A bare number in a file or module field: a port or ID mistaken for a path.

    H-0618 matched ``ImageLoaded|contains: '50813'``, the staging port.
    """
    for _, block in blocks(detection):
        for key, raw in block.items():
            if base_field(key).lower() not in _FILE_NAME_FIELDS:
                continue
            for value in _values(raw):
                if re.fullmatch(r"\d{2,}", value.strip().strip("*")):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, a bare number; a port or ID is not a file "
                        "or module path. Ports belong in network_connection"
                    )
    return None


def elided_value(detection: Dict[str, Any]) -> Optional[str]:
    """A value with the report's "..." in it: the elided part never appears in telemetry."""
    for _, block in blocks(detection):
        for key, raw in block.items():
            if "re" in _modifiers(key):
                continue
            for value in _values(raw):
                if _ELLIPSIS_RE.search(value):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, which keeps the report's elision; "
                        "match the parts the report gives in full"
                    )
    return None


def url_path_confusion(detection: Dict[str, Any]) -> Optional[str]:
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            for value in _values(raw):
                text = value.strip().strip("*")
                is_url = "://" in text or text.lower().startswith(("http", "www."))
                if field in _LOCAL_PATH_FIELDS and is_url:
                    return f"{base_field(key)} is a local path but matches the URL {value.strip()!r}"
                # Sigma escapes a literal wildcard as \? or \*; that backslash is not a path.
                unescaped = re.sub(r"\\[*?\\]", "", text)
                if field in _URL_FIELDS and (re.match(r"(?i)^[a-z]:\\", text) or "\\" in unescaped):
                    return f"{base_field(key)} is a URL but matches the local path {value.strip()!r}"
                if field in _HOST_FIELDS and "/" in text:
                    return f"{base_field(key)} holds a host name but matches the URL {value.strip()!r}"
                if field in _HOST_FIELDS and _FILE_EXTENSION_RE.search(text):
                    return f"{base_field(key)} holds a host name but matches the file name {value.strip()!r}"
    return None


# --- One event: AND-ed constraints must agree ------------------------------------------------


def _condition_tokens(condition: str) -> List[str]:
    return re.findall(r"[\w*]+", condition.lower())


def _and_only_positive(detection: Dict[str, Any], condition: str) -> Optional[List[str]]:
    """The selections a pure AND condition requires, or None when the condition ORs or counts."""
    tokens = _condition_tokens(condition)
    if not tokens or {"or", "of"} & set(tokens) or "|" in condition:
        return None
    names = {str(k).lower(): str(k) for k in detection if k != "condition"}
    positive: List[str] = []
    negate = False
    for token in tokens:
        if token == "not":
            negate = True
            continue
        if token == "and":
            continue
        if token in names and not negate:
            positive.append(names[token])
        negate = False
    return positive


def _constraint(key: Any, value: str) -> Optional[Tuple[str, str]]:
    """``(kind, value)`` for exact, endswith and startswith matches; None for anything looser."""
    mods = set(_modifiers(key))
    text = value.strip().lower()
    if mods - {"endswith", "startswith"} or len(mods) > 1:
        return None
    if "endswith" in mods:
        return ("ends", text.lstrip("*"))
    if "startswith" in mods:
        return ("starts", text.rstrip("*"))
    core = text.strip("*")
    if "*" in core or "?" in core:
        return None
    if text.startswith("*") and text.endswith("*"):
        return None
    if text.startswith("*"):
        return ("ends", core)
    if text.endswith("*"):
        return ("starts", core)
    return ("exact", core)


def _compatible(a: Tuple[str, str], b: Tuple[str, str]) -> bool:
    (ka, va), (kb, vb) = sorted([a, b])
    if ka == "ends" and kb == "ends":
        return va.endswith(vb) or vb.endswith(va)
    if ka == "starts" and kb == "starts":
        return va.startswith(vb) or vb.startswith(va)
    if ka == "ends" and kb == "exact":
        return vb.endswith(va)
    if ka == "exact" and kb == "starts":
        return va.startswith(vb)
    if ka == "exact" and kb == "exact":
        return va == vb
    return True  # startswith against endswith: one value can satisfy both


def impossible_conjunction(detection: Dict[str, Any]) -> Optional[str]:
    """AND-ed constraints one event cannot meet: two different process images, two target files.

    A process chain (Word, then cmd.exe) is two events; written as one AND it
    matches nothing. ParentImage and Image in one selection is the one-event form.
    """
    positive = _and_only_positive(detection, str(detection.get("condition", "")))
    if positive is None:
        return None
    groups: Dict[str, List[Tuple[str, List[Tuple[str, str]]]]] = {}
    for name in positive:
        block = detection.get(name)
        if not isinstance(block, dict):
            continue  # a list of maps is an OR of its own
        for key, raw in block.items():
            field = base_field(key).lower()
            if field not in _SINGLE_VALUED:
                continue
            alternatives = [_constraint(key, v) for v in _values(raw)]
            if not alternatives or any(c is None for c in alternatives):
                continue
            groups.setdefault(field, []).append((f"{name}.{key}", [c for c in alternatives if c]))
    for field, constraints in groups.items():
        for i, (left_key, left) in enumerate(constraints):
            for right_key, right in constraints[i + 1 :]:
                if not any(_compatible(a, b) for a in left for b in right):
                    return (
                        f"{left_key} and {right_key} require different {base_field(left_key.split('.', 1)[1])} "
                        "values on the same event, which no event has; a sequence of events is not one AND. "
                        "Use ParentImage for the parent, or write one rule per event"
                    )
    return None


# --- The description matches the selection --------------------------------------------------

_CHAIN_RE = re.compile(
    r"\b(?P<a>[a-z][\w-]*)(?:\.exe)?\s+(?:process\s+)?(?:spawns?|spawning|launch(?:es|ing)?|start(?:s|ing)|executes|executing)"
    r"\s+(?:a\s+|an\s+|the\s+)?(?P<b>[a-z][\w-]*)(?:\.exe)?\b"
    r"|\b(?P<c>[a-z][\w-]*)(?:\.exe)?\s+(?:is\s+|being\s+)?(?:spawned|launched|started)\s+by\s+(?:a\s+|an\s+|the\s+)?"
    r"(?P<d>[a-z][\w-]*)(?:\.exe)?\b",
    re.IGNORECASE,
)
_PROCESS_ALIASES = {"word": "winword", "excel": "excel", "powershell": "powershell"}


def _field_values(detection: Dict[str, Any], field: str) -> List[str]:
    """Values of one field across the selections the condition does not negate."""
    negated = set(_negated_names(detection))
    return [
        v.lower()
        for name, block in blocks(detection)
        if name not in negated
        for key, raw in block.items()
        if base_field(key).lower() == field
        for v in _values(raw)
    ]


def _names(values: List[str], process: str) -> bool:
    process = _PROCESS_ALIASES.get(process.lower(), process.lower())
    return any(re.search(rf"(^|[\\/*]){re.escape(process)}(\.exe)?\*?$", v) for v in values)


def description_mismatch(detection: Dict[str, Any], description: str) -> Optional[str]:
    if SUFFIX_CLAIM_RE.search(description):
        suffix_logic = any(
            {"endswith", "contains"} & set(_modifiers(key)) or any(v.startswith(("*", ".")) or "*" in v for v in _values(raw))
            for _, block in blocks(detection)
            for key, raw in block.items()
        )
        if not suffix_logic:
            return "the description promises subdomain or suffix matching, but every selection is an exact match"
    parents = _field_values(detection, "parentimage")
    children = _field_values(detection, "image")
    if re.search(r"\b(spawned by|child process|parent[- ]child)\b", description, re.I):
        if not (parents or _field_values(detection, "parentcommandline")):
            return "the description claims a parent-child relationship, but no parent process field constrains the detection"
    if not parents or not children:
        return None
    for match in _CHAIN_RE.finditer(description):
        parent, child = (match.group("a"), match.group("b")) if match.group("a") else (match.group("d"), match.group("c"))
        if _names(children, parent) and _names(parents, child) and not _names(parents, parent):
            return (
                f"the description says {parent} starts {child}, but the selection has {child} as ParentImage "
                f"and {parent} as Image; make the two agree with the source"
            )
    return None


def _negated_names(detection: Dict[str, Any]) -> List[str]:
    condition = str(detection.get("condition", "")).lower()
    negated = {m.group(1) for m in re.finditer(r"\bnot\s+(?:1 of\s+|all of\s+)?([\w*]+)", condition)}
    return [
        str(name)
        for name in detection
        if name != "condition" and any(re.fullmatch(n.replace("*", ".*"), str(name).lower()) for n in negated)
    ]


def _all_values(block: Any) -> List[str]:
    out: List[str] = []
    for item in block if isinstance(block, list) else [block]:
        if isinstance(item, dict):
            for raw in item.values():
                out += _values(raw)
        else:
            out += _values(item)
    return out


def filter_excludes_named_artifact(detection: Dict[str, Any], named: List[str]) -> Optional[str]:
    """A negated filter that removes an artifact the hunt names as the threat's.

    H-0618's rules excluded "personal resume (2).docx", the decoy the source
    reports the loader writing, so each rule filtered out the event it hunts.
    A directory is judged by what it would exclude: ``C:\\Windows\\System32\\``
    is ordinary tuning, but the A1 replay excluded ``\\Windows\\Temp\\``, where
    the source says the decoy is written.
    """
    corpus = "\n".join(named).lower()
    if not corpus:
        return None
    fragments = _file_name_fragments(named)
    paths = _named_paths(named)
    for name in _negated_names(detection):
        block = detection[name]
        for item in block if isinstance(block, list) else [block]:
            if not isinstance(item, dict):
                continue
            for key, raw in item.items():
                for value in _values(raw):
                    hit = next((p for p in paths if _filter_matches(key, value, p)), None)
                    if hit:
                        return (
                            f"filter {name!r} excludes {value.strip()!r}, which matches {hit!r}, an artifact the hunt "
                            "names as the threat's own; the rule would drop the event it hunts for"
                        )
        for value in _all_values(detection[name]):
            lowered = value.strip().strip("*").lower()
            for part in _ELLIPSIS_RE.split(lowered):
                part = part.strip().strip("_")
                if len(part) >= 8 and not part.endswith(("\\", "/")) and part in corpus:
                    return (
                        f"filter {name!r} excludes {value.strip()!r}, which the hunt names as the threat's own "
                        "artifact; the rule would drop the event it hunts for"
                    )
            # A later run excluded "Beijing Institute of Technology_2023_": the
            # decoy's own name with an invented year, which may be the decoy.
            reused = next((f for f in fragments if f in lowered), None)
            if reused:
                return (
                    f"filter {name!r} excludes {value.strip()!r}, built from {reused!r} in the threat's own file name; "
                    "it may drop the event the rule hunts for"
                )
    return None


_NAMED_PATH_RE = re.compile(
    r"(?:[A-Za-z]:|%\w+%)?(?:\\[^\\\n'\"`|]+)+\.[a-z0-9]{2,5}\b"
    # Unix and macOS paths of at least two segments, with an optional $HOME / ~ prefix.
    r"|(?:\$\{?\w+\}?|~)?(?:/[^/\s'\"`|]+){2,}",
    re.IGNORECASE,
)


def _named_paths(named: List[str]) -> List[str]:
    """Full Windows paths in what the hunt names, with any elision kept."""
    return sorted({m.group(0) for text in named for m in _NAMED_PATH_RE.finditer(text)})


def _filter_matches(key: Any, value: str, path: str) -> bool:
    """Whether a filter's condition would match an artifact path (an elision stands for any text)."""
    mods = set(_modifiers(key))
    if mods - {"contains", "startswith", "endswith"} or base_field(key).lower() not in _PATH_FILTER_FIELDS:
        return False
    # An elision or a redaction ("/Users/<redacted>/...") stands for any text.
    concrete = re.sub(r"<[^<>/\\]{1,30}>", "x", _ELLIPSIS_RE.sub("x", path)).lower()
    concrete = re.sub(r"^(\$\{?\w+\}?|~)(?=/)", "/users/x", concrete)
    needle = value.strip().lower()
    if not needle.strip("*?"):
        return False
    # The value as a Sigma pattern: modifiers and leading/trailing * set the anchoring,
    # and a * inside it ("/Users/*/Library/LaunchAgents/") matches any text.
    starts = "contains" in mods or "endswith" in mods or needle.startswith("*")
    ends = "contains" in mods or "startswith" in mods or needle.endswith("*")
    core = re.escape(needle.strip("*")).replace(r"\*", ".*").replace(r"\?", ".")
    pattern = ("" if starts else "^") + core + ("" if ends else "$")
    return re.search(pattern, concrete) is not None


_PATH_FILTER_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "commandline", "parentcommandline"})


def _file_name_fragments(named: List[str]) -> List[str]:
    """Distinctive pieces of the file names the hunt names: the base name, split at any elision."""
    out: List[str] = []
    for text in named:
        for path in re.findall(r"[^\s:'\"`|]*[\\/][^\\/\n'\"`|]+\.[a-z0-9]{2,5}\b", text, re.IGNORECASE):
            base = re.split(r"[\\/]", path)[-1].lower()
            out += [p.strip().strip("_") for p in _ELLIPSIS_RE.split(base) if len(p.strip().strip("_")) >= 12]
    return out


def filter_cancels_selection(detection: Dict[str, Any]) -> Optional[str]:
    """A negated filter every selected event also matches: the rule can never fire.

    H-0618's #6 replay drafted ``selection: {ImageLoaded|contains: vshell, Image|endswith: \\cmd.exe}``
    with ``filter: {ImageLoaded|contains: vshell}`` and ``selection and not filter``.
    """
    positive = _and_only_positive(detection, str(detection.get("condition", "")))
    if not positive:
        return None
    required = {
        (str(key).lower(), tuple(sorted(v.lower() for v in _values(raw))))
        for name in positive
        if isinstance(detection.get(name), dict)
        for key, raw in detection[name].items()
    }
    for name in _negated_names(detection):
        block = detection.get(name)
        if not isinstance(block, dict) or not block:
            continue
        constraints = {(str(key).lower(), tuple(sorted(v.lower() for v in _values(raw)))) for key, raw in block.items()}
        if constraints <= required:
            return (
                f"filter {name!r} repeats conditions the selection already requires, so every event the "
                "selection matches is filtered out and the rule never fires"
            )
    return None


#: Fields that say which module an image_load event is about. Every process
#: loads modules, so a rule constraining none of them matches all of them.
_LOADED_MODULE_FIELDS = (
    "imageloaded", "hashes", "signed", "signature", "signaturestatus", "originalfilename", "product", "company",
    "description",
)  # fmt: skip


def actor_only_selection(detection: Dict[str, Any], category: str) -> Optional[str]:
    """An image_load rule that says which process, but not which module: every DLL it loads.

    H-0618's end-to-end replay kept one with only ``Image|endswith: \\cmd.exe``.
    Only image_load: a process that should never connect out, write a file or
    resolve a name (notepad.exe, eqnedt32.exe) is a sound rule on ``Image``
    alone in those categories, and SigmaHQ has a dozen of them; every process
    loads DLLs.
    """
    if category != "image_load":
        return None
    negated = set(_negated_names(detection))
    constrained = {base_field(key).lower() for name, block in blocks(detection) if name not in negated for key in block}
    if constrained and not constrained & set(_LOADED_MODULE_FIELDS):
        return (
            f"the rule constrains only {', '.join(sorted(constrained))}, so it matches every module that process loads; "
            "say which module (ImageLoaded, Hashes or Signed)"
        )
    return None


def literal_wildcard(detection: Dict[str, Any]) -> Optional[str]:
    """A literal * in a command line or target filename where bash/cmd expands it.

    The OS expands * before logging process creation, so the logged command line
    has the actual paths, not the literal *.
    """
    for name, block in detection.items():
        if not isinstance(block, dict) or name.lower() in ("condition", "timeframe"):
            continue
        for key, raw in block.items():
            field = base_field(key).lower()
            if field in ("commandline", "targetfilename", "image"):
                for v in _values(raw):
                    if "contains" in _modifiers(key):
                        if "*" in v:
                            return f"{name} expects a literal '*' in {field}, but shells expand wildcards before execution"
    return None


def hallucinated_filter(detection: Dict[str, Any], named: List[str]) -> Optional[str]:
    """A negated filter that arbitrarily excludes a specific image not in the intelligence."""
    from hecate_agent.core.query_literals import SYSTEM_IMAGES

    named_lower = {n.lower() for n in named}
    for name in _negated_names(detection):
        block = detection.get(name)
        if not isinstance(block, dict):
            continue
        for key, raw in block.items():
            field = base_field(key).lower()
            if field in ("image", "parentimage", "originalfilename"):
                for v in _values(raw):
                    val_lower = v.lower()
                    if val_lower.startswith("\\\\"):
                        val_lower = val_lower[2:]
                    elif val_lower.startswith("\\"):
                        val_lower = val_lower[1:]

                    found = False
                    for sys_img in SYSTEM_IMAGES:
                        if sys_img in val_lower or val_lower in sys_img:
                            found = True
                            break
                    if found and not any(n in val_lower for n in named_lower):
                        return f"{name} excludes {v} but the source intelligence does not authorize this filter"
    return None


def dual_use_destination_without_process_context(detection: Dict[str, Any], category: str) -> Optional[str]:
    """Reject a network connection rule matching dual-use cloud/SaaS endpoints without process context.

    Public cloud storage and SaaS endpoints (e.g., AWS S3, Azure Blob, Google Cloud Storage,
    Discord, Telegram) must never be matched as bare standalone destinations: they create
    massive alert storms. They must be bound to the specific initiating process (Image / CommandLine)
    or filter legitimate software.
    """
    if category != "network_connection":
        return None

    negated = set(_negated_names(detection))
    has_process_constraint = False
    for name, block in blocks(detection):
        for key in block:
            field = base_field(key).lower()
            if field in ("image", "commandline", "parentimage", "originalfilename"):
                has_process_constraint = True
                break
        if has_process_constraint:
            break

    if has_process_constraint:
        return None

    from hecate_agent.core.provenance import is_dual_use

    for name, block in blocks(detection):
        if name in negated:
            continue
        for key, raw in block.items():
            field = base_field(key).lower()
            if field in ("destinationhostname", "queryname", "destinationip"):
                for val in _values(raw):
                    if is_dual_use(val):
                        return (
                            f"detection matches dual-use cloud destination {val!r} without process context; "
                            "dual-use network indicators must be bound to the initiating process (e.g. Image) "
                            "or filter legitimate browsers to prevent alert storms"
                        )
    return None


_CONDITION_KEYWORDS = frozenset({"and", "or", "not", "of", "all", "them", "1", "any"})


def condition_names_missing_selection(detection: Dict[str, Any]) -> Optional[str]:
    """A condition term ("selection_dest_*", "filter") that names no detection block.

    Such a rule never matches, and nothing downstream says so: H-0830's
    dual-use rule kept "(1 of selection_dest_*) and not filter_legit" after
    every selection_dest_ block was dropped, and was reported validated.
    """
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    blocks = [k for k in detection if k not in ("condition", "timeframe")]
    for text in conditions:
        if not isinstance(text, str):
            continue
        body = text.split("|", 1)[0]  # an aggregation tail names fields, not blocks
        for term in re.findall(r"[A-Za-z_][\w*]*", body):
            if term.lower() in _CONDITION_KEYWORDS:
                continue
            pattern = re.compile("^" + re.escape(term).replace(r"\*", ".*") + "$")
            if not any(pattern.match(block) for block in blocks):
                return f"condition names '{term}', which matches no detection block"
    return None


def unexpanded_environment_path(detection: Dict[str, Any]) -> Optional[str]:
    """Endpoint path fields normally contain expanded Windows paths."""
    images = _field_values(detection, "image")
    command_shell = any(re.search(r"(?i)(?:^|[\\/])cmd(?:\.exe)?$", value) for value in images)
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            if field not in {"image", "parentimage", "commandline", "targetfilename"}:
                continue
            if field == "commandline" and command_shell:
                continue  # cmd itself can receive an unexpanded variable.
            if any(
                re.search(r"(?i)%(?:appdata|localappdata|temp|tmp|userprofile|windir)%[\\/]", value) for value in _values(raw)
            ):
                return (
                    "path selection uses an unexpanded environment variable; match the expanded path or a stable path fragment"
                )
    return None


def registry_operation_mismatch(detection: Dict[str, Any], category: str, description: str) -> Optional[str]:
    if category != "registry_event" or not re.search(r"(?i)modif|value (?:set|writ)", description):
        return None
    event_types = {value.lower() for value in _field_values(detection, "eventtype")}
    if event_types == {"createkey"}:
        return "registry modification is described, but CreateKey misses writes to existing values; use a matching value-write event or describe key creation only"
    return None


def argument_obfuscation_mismatch(detection: Dict[str, Any], category: str, description: str) -> Optional[str]:
    """A script location alone cannot establish obfuscated arguments."""
    if category != "process_creation" or not re.search(r"(?i)\bobfuscat(?:ed|ion|ing)\b", description):
        return None
    arguments = [
        (key, value)
        for name, block in blocks(detection)
        if name not in _negated_names(detection)
        for key, raw in block.items()
        if base_field(key).lower() == "commandline"
        for value in _values(raw)
    ]
    if not arguments or all(
        "re" not in _modifiers(key)
        and re.fullmatch(r"[\w .:*?%/\\-]+", value)
        and ("\\" in value or "/" in value)
        for key, value in arguments
    ):
        return "obfuscated arguments are claimed, but only a script path or process is tested; describe temporary-path execution or test the claimed argument property"
    return None


def non_deployable_source_values(detection: Dict[str, Any], category: str) -> Optional[str]:
    """Report redactions and pseudo-file reads cannot become literal endpoint detections."""
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            for value in _values(raw):
                if re.search(r"(?i)\[(?:auth\b|[^\]]*redacted)|\.redacted\.|<[^>]+>", value):
                    return "selection contains a report redaction, not an observed value; match the supported behavior without placeholder credentials or targets"
                if category == "file_event" and field == "targetfilename":
                    if (not _modifiers(key) or "endswith" in _modifiers(key)) and value.endswith(("/", "\\")):
                        return "exact file-event selection names a directory, not a file; use a supported file artifact"
                    if re.fullmatch(r"/proc/(?:self/|\d+/|/)?(?:exe|cmdline|maps|status|stat|net/(?:tcp6?|udp6?))", value):
                        return "a read-only /proc lookup is a pseudo-file read, not a payload file creation; use telemetry for the actual operation"
    images = _field_values(detection, "image")
    if category == "process_creation" and any(v.endswith("/nc") for v in images):
        if "echo" in _field_values(detection, "commandline"):
            return "echo belongs to the sending side of the shell pipeline, not the nc argument list"
    return None


def semantic_problem(
    detection: Dict[str, Any], category: str, description: str = "", named: Optional[List[str]] = None
) -> Optional[str]:
    """The first semantic defect in a structurally valid rule, or None.

    ``named`` is what the hunt names as the threat's (observables and
    indicators); a filter may not exclude any of it.
    """
    checks = (
        lambda: condition_names_missing_selection(detection),
        lambda: field_outside_category(detection, category),
        lambda: non_executable_image(detection),
        lambda: non_deployable_source_values(detection, category),
        lambda: unexpanded_environment_path(detection),
        lambda: registry_operation_mismatch(detection, category, description),
        lambda: argument_obfuscation_mismatch(detection, category, description),
        lambda: literal_wildcard(detection),
        lambda: api_in_command_line(detection),
        lambda: url_path_confusion(detection),
        lambda: elided_value(detection),
        lambda: number_as_path(detection),
        lambda: impossible_conjunction(detection),
        lambda: description_mismatch(detection, description),
        lambda: installer_tampering_without_evidence(detection, category, description),
        lambda: filter_cancels_selection(detection),
        lambda: actor_only_selection(detection, category),
        lambda: filter_excludes_named_artifact(detection, named or []),
        lambda: hallucinated_filter(detection, named or []),
        lambda: dual_use_destination_without_process_context(detection, category),
    )
    for check in checks:
        problem = check()
        if problem:
            return problem
    return None


def installer_tampering_without_evidence(detection: Dict[str, Any], category: str, description: str) -> Optional[str]:
    """A familiar MSI filename cannot establish that its contents were altered."""
    if category != "file_event" or not re.search(r"\b(tamper\w*|trojaniz\w*|modified|altered)\b", description, re.I):
        return None
    fields = {str(key).split("|")[0].lower() for _, block in blocks(detection) for key in block}
    names = _field_values(detection, "targetfilename")
    if fields == {"targetfilename"} and any(".msi" in name.lower() for name in names):
        return "an MSI filename alone cannot establish installer tampering; use integrity or behavior evidence, or describe a filename lead"
    return None
