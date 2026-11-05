"""The source author's own detection guidance, as cited candidate analytics.

A report that says "hunt for resume-themed executables launching cmd.exe and
then Word" has done the detection engineering already. H-0618's pipeline
ignored that section, asked the model for behavioural rules, and got a Word ->
cmd.exe chain (the reverse of the report), an API name matched as a module, and
nothing for the kill-switch file.

Each guidance item keeps its words and its source, and is routed to the
telemetry that can actually see it:

- ``sigma``: files, process launches and registry keys. File and process-chain
  items become deterministic Sigma candidates, one per event: a chain of two
  launches is two events, and joining them needs backend correlation.
- ``edr``: memory allocation, API call sequences, code-signing state. Sigma's
  generic categories carry none of these.
- ``network-content``: byte patterns and frame layouts, for IDS or NDR.
- ``indicator``: bare addresses, hosts and hashes; the IOC rules cover them.
- ``review``: guidance no rule above recognises; listed so it is not lost.
"""

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from hecate_agent.core.provenance import refang
from hecate_agent.core.sigma_semantics import API_NAMES

ROUTES = ("sigma", "edr", "network-content", "indicator", "review")

_START_RE = re.compile(
    r"^(detection|detections|detection and hunting|hunting|hunting and detection|detection opportunities|"
    r"detection guidance|hunting guidance|how to detect|detection and response|detection recommendations|"
    r"detection rules)\s*[:⌗#]*\s*$",
    re.IGNORECASE,
)
#: A markdown heading: its level and its words.
_HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")
#: Separators between the entries of a scraped nav bar ("Check · Exploit · Detection · PCAP").
_NAV_SEPARATORS = frozenset({"·", "|", "•", "/"})
_END_RE = re.compile(
    r"^(iocs?|indicators( of compromise)?|references|final thoughts|conclusions?|appendix|about( the author)?|"
    r"mitre att&ck|att&ck mapping|acknowledg\w+|timeline|summary)\s*[:⌗#]*\s*$",
    re.IGNORECASE,
)
_SUBSECTION_RE = re.compile(r"^(network|endpoint|host|hosts|file system|registry|process|memory|cloud|identity)\s*$", re.I)
#: Lead-ins that introduce a list rather than say anything themselves.
_GENERIC_LEAD_RE = re.compile(
    r"^(hunt for|look for|block( or investigate)?|investigate|monitor( for)?|watch for|search for)\s*:\s*$", re.I
)
#: Heading glyphs and bullets; lone commas and full stops are content and are kept.
_DECORATION_RE = re.compile(r"^[⌗#*•·\-–—=_~|]{1,3}$")
_HEX_ROW_RE = re.compile(r"^(?:[0-9a-f]{2}\s+){3,}[0-9a-f]{2}\s*$", re.IGNORECASE)
_JOINING_END_RE = re.compile(
    r"(\b(launching|spawning|starting|running|executing|opening|and|or|then|with|as|by|of|to|from|the|a|an|is|are|"
    r"beginning|followed|such|via|into|under|named|called)|[,(])$",
    re.IGNORECASE,
)
_CONTINUATION_START_RE = re.compile(r"^([a-z,.;)]|(and|or|then|followed|with)\b)")
_EXPLANATION_START_RE = re.compile(r"^(this|these|it|they)\b", re.IGNORECASE)

_IOC_TOKEN_RE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|"
    r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?|https?://\S+)$",
    re.IGNORECASE,
)
_NETWORK_CONTENT_RE = re.compile(
    r"\b(bytes?|byte sequence|frames?|nonces?|packets?|tags?|headers?|magic|little-endian|big-endian|network-order|"
    r"beginning with|starts? with)\b",
    re.IGNORECASE,
)
_EDR_RE = re.compile(
    r"\b(memory|allocat\w*|inject\w*|hollow\w*|certificate|signature|signed|signing|hashmismatch|api calls?|"
    r"syscalls?|executable memory|thread)\b",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"(?:%\w+%|[A-Za-z]:)?(?:\\[^\\\s:*?\"<>|]+)+\.\w{1,5}\b"
    r"|(?:\$\{?\w+\}?|~)(?:/[\w.@-]+){2,}|(?:/(?:tmp|var|etc|dev|usr|opt|home|users|library|private)(?:/[\w.@<>-]+)+)"
)
_REGISTRY_RE = re.compile(r"\bHK(LM|CU|EY_[A-Z_]+)\\", re.IGNORECASE)
_CHAIN_RE = re.compile(
    r"^(?P<subject>.+?)\s+(?:launching|spawning|starting|running|executing)\s+(?P<a>[\w./-]+)"
    r"(?P<args>(?:\s+-{1,2}\w+)*)"
    r"(?:\s*,?\s*(?:and\s+)?(?:then|which (?:opens|launches|starts))\s+(?P<b>[\w./-]+))?\s*\.?$",
    re.IGNORECASE,
)
#: "the Node-RED process (`node` running `node-red`)": the runtime and the script it runs.
_RUNS_SCRIPT_RE = re.compile(r"\b(?P<runtime>[\w./-]+)\s+running\s+(?P<script>[\w./-]+)\)", re.IGNORECASE)
#: A sentence end inside an item: "... spawning `/bin/sh -c`. The `exec` node is ...".
_SENTENCE_END_RE = re.compile(r"(?<=[\w)`])\.\s+(?=[A-Z])")
_UNIX_PROCESSES = frozenset(
    {"node", "nodejs", "python", "python3", "java", "php", "ruby", "perl", "sh", "bash", "dash", "zsh", "busybox"}
)
_UNIX_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "busybox"})
_THEME_RE = re.compile(r"\b(?P<theme>[a-z][\w]{2,})-(?:themed|named|looking|lured?)\b", re.IGNORECASE)
_PROCESS_ALIASES = {
    "word": "winword.exe", "winword": "winword.exe", "excel": "excel.exe", "powerpoint": "powerpnt.exe",
    "outlook": "outlook.exe", "powershell": "powershell.exe", "pwsh": "pwsh.exe", "cmd": "cmd.exe",
    "rundll32": "rundll32.exe", "regsvr32": "regsvr32.exe", "mshta": "mshta.exe", "wscript": "wscript.exe",
    "cscript": "cscript.exe", "explorer": "explorer.exe",
}  # fmt: skip


@dataclass
class GuidanceItem:
    """One piece of the source's detection guidance, and where it can run."""

    id: str
    text: str
    route: str
    reason: str
    section: str = ""
    lead: str = ""
    source: str = ""
    #: Deterministic Sigma candidates (category, title, detection, note) for ``sigma`` items.
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _furniture(lines: List[str], index: int) -> bool:
    """Whether a lone "Detection" line is page furniture, not a heading.

    A GitHub page lists each folder name twice ("detection" / "detection") and
    renders the README's nav bar one entry per line between "·" separators.
    """
    line = lines[index].lower()
    neighbours = [lines[j] for j in (index - 1, index + 1) if 0 <= j < len(lines)]
    return any(n.lower() == line or n in _NAV_SEPARATORS for n in neighbours)


def guidance_lines(text: str) -> List[str]:
    """The lines of the report's detection section, or [] when it has none.

    A markdown section ends at the next heading of its level or above, so a
    README's "## PCAP" after "## Detection Rules" is not read as guidance.
    """
    lines = [line.strip() for line in refang(text or "").splitlines()]
    # A "# ..." line inside a code block is a shell comment, not a heading.
    in_code, headings = False, []
    for line in lines:
        if line.startswith("```"):
            in_code = not in_code
        headings.append(None if in_code else _HEADING_RE.match(line))
    start, level = None, 0
    for i, line in enumerate(lines):
        heading = headings[i]
        if heading and _START_RE.match(heading["title"]):
            start, level = i, len(heading["marks"])
            break
        if not heading and _START_RE.match(line) and not _furniture(lines, i):
            start = i
            break
    if start is None:
        return []
    out: List[str] = []
    for i in range(start + 1, len(lines)):
        line, heading = lines[i], headings[i]
        if heading and level and len(heading["marks"]) <= level:
            break
        if heading:
            line = heading["title"]
        if _END_RE.match(line):
            break
        if line and not _DECORATION_RE.match(line) and not line.startswith("```"):
            out.append(line)
    return out


def _items(lines: List[str]) -> List[Dict[str, Any]]:
    """Rebuild list items from scraped lines, where every inline element is its own line."""
    items: List[Dict[str, Any]] = []
    section = lead = ""
    for line in lines:
        if _SUBSECTION_RE.match(line):
            section, lead = line.lower(), ""
            continue
        if _GENERIC_LEAD_RE.match(line):
            lead = line.rstrip(":").strip()
            continue
        previous = items[-1] if items else None
        joins = previous is not None and (
            _JOINING_END_RE.search(previous["text"])
            or _CONTINUATION_START_RE.match(line)
            or (_HEX_ROW_RE.match(line) and (previous["hex"] or previous["text"].endswith(":")))
            or (previous["hex"] and _EXPLANATION_START_RE.match(line))
            or _inline_token(previous["text"], line)
        )
        if joins and previous is not None:
            sep = "" if line[0] in ",.;)" else " "
            previous["text"] = f"{previous['text']}{sep}{line}"
            previous["hex"] = previous["hex"] or bool(_HEX_ROW_RE.match(line))
        else:
            items.append({"text": line, "section": section, "lead": lead, "hex": bool(_HEX_ROW_RE.match(line))})
    return [i for i in items if not i["text"].endswith(":") or i["hex"]]


def _inline_token(previous: str, line: str) -> bool:
    """A lone token mid-sentence ("network-order port" / "50812"), not the next list entry.

    Consecutive indicators ("1.2.3.4:50812" then "1.2.3.4:50813") are separate entries.
    """
    # A capitalised token ("AllocADsMem") starts the next entry; mid-sentence
    # tokens are lowercase or numeric ("cmd.exe", "50812", "w32").
    if " " in line or re.search(r"[.:!?]$", previous) or not re.match(r"[a-z0-9%\\]", line):
        return False
    return not (_IOC_TOKEN_RE.match(previous.split()[-1]) and _IOC_TOKEN_RE.match(line))


def classify(text: str, has_hex: bool = False) -> Dict[str, str]:
    """``{"route", "reason"}`` for one guidance item."""
    words = text.replace(",", " ").split()
    if words and all(_IOC_TOKEN_RE.match(w) for w in words):
        return {"route": "indicator", "reason": "published indicators; the IOC rules cover them"}
    if (
        has_hex
        or _NETWORK_CONTENT_RE.search(text)
        and re.search(r"\b(tcp|udp|traffic|outbound|inbound|stream|c2)\b", text, re.I)
    ):
        return {
            "route": "network-content",
            "reason": "matches bytes inside network traffic; needs an IDS/NDR signature, not a Sigma log source",
        }
    apis = [w for w in re.findall(r"[A-Za-z_]\w+", text) if w.lower() in API_NAMES]
    if apis or _EDR_RE.search(text):
        what = f"the API sequence {', '.join(apis)}" if apis else "memory, code-signing or thread activity"
        return {"route": "edr", "reason": f"{what} is visible to EDR telemetry, not Sigma's generic log sources"}
    if _PATH_RE.search(text) or _REGISTRY_RE.search(text) or _chain(text):
        return {"route": "sigma", "reason": "a file, registry key or process launch that endpoint logs record"}
    return {"route": "review", "reason": "no telemetry route recognised; review by hand"}


def _chain(text: str) -> Optional["re.Match[str]"]:
    """A process chain in the item's first sentence, read without markdown code marks."""
    first = _SENTENCE_END_RE.split(text.replace("`", ""), maxsplit=1)[0]
    return _CHAIN_RE.match(first.strip())


def _process(token: str) -> Optional[str]:
    """The ``Image|endswith`` value for a process the text names, with its platform's separator."""
    lowered = token.lower().strip("().,")
    if lowered.endswith(".exe"):
        return "\\" + lowered
    if lowered in _PROCESS_ALIASES:
        return "\\" + _PROCESS_ALIASES[lowered]
    name = lowered.rsplit("/", 1)[-1]
    if name in _UNIX_PROCESSES and (lowered == name or lowered.startswith("/")):
        return "/" + name
    return None


def _bare(endswith: str) -> str:
    return endswith.lstrip("\\/")


def sigma_candidates(text: str) -> List[Dict[str, Any]]:
    """Deterministic Sigma candidates for one ``sigma`` guidance item; [] when no template fits."""
    out: List[Dict[str, Any]] = []
    chain = _chain(text)
    if chain:
        first, second = _process(chain.group("a")), _process(chain.group("b") or "")
        subject = chain.group("subject")
        theme = _THEME_RE.search(subject)
        parent = next((p for p in map(_process, reversed(subject.split())) if p), None)
        if first and (theme or parent):
            selection: Dict[str, Any] = (
                {"ParentImage|contains": theme.group("theme").lower()}
                if theme
                else {"ParentImage|endswith": str(parent)}
            )
            runs = _RUNS_SCRIPT_RE.search(subject)
            if runs and not theme and _process(runs.group("runtime")) == parent:
                selection["ParentCommandLine|contains"] = runs.group("script")
            selection["Image|endswith"] = first
            if first.lstrip("/") in _UNIX_SHELLS and re.search(r"(?<!\w)-c\b", chain.group("args")):
                selection["CommandLine|contains"] = " -c "
            launcher = f"a {theme.group('theme').lower()}-themed executable" if theme else _bare(str(parent))
            out.append(
                {
                    "category": "process_creation",
                    "title": f"{launcher.capitalize()} launching {_bare(first)}",
                    "detection": {"selection": selection, "condition": "selection"},
                    "note": "one event of the chain the source describes",
                }
            )
        if first and second:
            out.append(
                {
                    "category": "process_creation",
                    "title": f"{_bare(first)} launching {_bare(second)}",
                    "detection": {
                        "selection": {"ParentImage|endswith": first, "Image|endswith": second},
                        "condition": "selection",
                    },
                    "note": "the next event of the chain; joining the two events needs backend correlation",
                }
            )
    for path in _PATH_RE.findall(text):
        name = re.split(r"[\\/]", path)[-1]
        env = re.match(r"%(\w+)%|\$\{?\w+\}?|~", path)
        # An environment variable resolves differently per user and host: match what follows it.
        tail = path[env.end() :] if env else path
        out.append(
            {
                "category": "file_event",
                "title": f"File {name} written",
                "detection": {"selection": {"TargetFilename|endswith": tail}, "condition": "selection"},
                "note": "file_event records creation; a file the malware only checks for or reads needs EDR file-access telemetry",
            }
        )
    return out


def extract_guidance(text: str, source: str = "") -> List[GuidanceItem]:
    """The report's detection guidance, item by item, each routed and cited."""
    items: List[GuidanceItem] = []
    for raw in _items(guidance_lines(text)):
        verdict = classify(raw["text"], raw["hex"])
        item = GuidanceItem(
            id=f"G{len(items) + 1}",
            text=raw["text"],
            route=verdict["route"],
            reason=verdict["reason"],
            section=raw["section"],
            lead=raw["lead"],
            source=source,
        )
        if item.route == "sigma":
            item.candidates = sigma_candidates(item.text)
        items.append(item)
    return items
