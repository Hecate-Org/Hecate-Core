"""Evidence from the primary source a CTI item cites.

Feeds deliver a summary; the report it links to carries the process tree, file
paths, ports, what each hash is, and which indicators are current. H-0618 was
drafted from a 2,194-character OTX blurb while the report held 32,920
characters, including the hash roles and the note that the listed hostnames
were historical. This module fetches the report, extracts artifacts from all
of it, and keeps only what the text supports:

- every value must appear verbatim in the page (after refanging);
- a role or status is kept only with a supporting passage found in the page;
  without one it is recorded as ``unknown``;
- confidence is the report's own label ("HIGH confidence"), never the model's.

Extracted text is evidence from one source, not independent confirmation; the
records carry that provenance so later stages can say where a claim came from.
"""

import ipaddress
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from hecate_agent.core.provenance import (
    HASH_ROLES,
    NETWORK_ROLES,
    STATUSES,
    IndicatorRecord,
    refang,
    split_host_port,
    trim_shell_tail,
)

logger = logging.getLogger(__name__)

#: Characters per extraction call. The whole report is read, in chunks: the
#: H-0618 report kept its hash roles and historical-domain note past 25,000.
CHUNK_CHARS = 11000
CHUNK_OVERLAP = 600
#: Hard ceiling on page text, so a runaway page cannot turn into dozens of calls.
MAX_PAGE_CHARS = 120000
#: Words that must match contiguously for a quoted passage to count as found.
EVIDENCE_WINDOW = 8

_SKIP_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0")
_LINK_RE = re.compile(r"https?://[^\s<>\"')\]]+")
_CONFIDENCE_RE = re.compile(r"(?i)\b(high|medium|low)\s+confidence\b")

_DISALLOWED_EXTENSIONS = {
    ".bin",
    ".exe",
    ".dll",
    ".sys",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".elf",
    ".so",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".iso",
    ".img",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".apk",
    ".dat",
    ".payload",
    ".scr",
    ".msi",
    ".hta",
    ".vbe",
    ".wsf",
    ".jar",
    ".class",
}
_DISALLOWED_PATHS = {
    "/gate.php",
    "/c2",
    "/beacon",
}


def is_safe_report_url(url: str) -> bool:
    """True if ``url`` looks like a public advisory/article and not adversary infra or a payload drop."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url.strip())
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    host = host.lower()
    if host in _SKIP_HOSTS or host.endswith(".local") or host.endswith(".internal") or host.endswith(".onion"):
        return False
    try:
        ipaddress.ip_address(host)
        return False  # Raw IP addresses are adversary C2/staging, not published CTI articles
    except ValueError:
        pass
    if "." not in host:
        return False
    if parsed.port is not None:
        if parsed.scheme == "http" and parsed.port != 80:
            return False
        if parsed.scheme == "https" and parsed.port != 443:
            return False
    path = (parsed.path or "").lower()
    for ext in _DISALLOWED_EXTENSIONS:
        if path.endswith(ext):
            return False
    for bad_path in _DISALLOWED_PATHS:
        if path.endswith(bad_path) or bad_path in path:
            return False
    return True


INDICATOR_KINDS = {
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "ipv4": "ipv4",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
}
BEHAVIOUR_KINDS = (
    "file_path",
    "registry_key",
    "command_line",
    "process",
    "api",
    "mutex",
    "named_pipe",
    "scheduled_task",
    "service",
)

SYSTEM_PROMPT = f"""You extract artifacts from one part of a threat intelligence report.
Copy every value EXACTLY as the text writes it. Do not invent, complete or reformat.

For each artifact return:
- "value": the exact string. For a network endpoint with a port, use "ip:port" as written.
- "kind": one of {sorted(INDICATOR_KINDS) + list(BEHAVIOUR_KINDS)}
- "role": for hashes one of {list(HASH_ROLES)}; for IPs, domains, hostnames and URLs one of
  {list(NETWORK_ROLES)}; for other kinds a short phrase using the text's own words for what the
  artifact is in this intrusion, or "unknown" when the text does not say.
  Hash roles: executable = a program run from disk; library = a DLL, dylib or shared object loaded
  from disk; script = a shell, PowerShell or other script run by an interpreter;
  archive = a ZIP/RAR container; document = a decoy or lure document;
  memory_only = shellcode or a payload that only exists in memory;
  network_content = an encrypted or encoded download or stream;
  non_file = a token, key or certificate fingerprint that only looks like a hash.
  Network roles: target = an address the actor attacked, scanned or tested against (a victim);
  inbound = an address the attack traffic came from (exploitation or scanning source).
  Use "historical" when the text says an indicator is old, unrelated, or not a campaign IOC.
- "status": one of {list(STATUSES)} ("historical" when the text says so, else "active" if the
  text ties it to this campaign, else "unknown")
- "evidence": one sentence copied word for word from the text that states the role or status.

Return strict JSON: {{"artifacts": [ ... ]}}. Return {{"artifacts": []}} if there are none.
"""


@dataclass
class SourceArtifact:
    value: str
    kind: str
    role: str = "unknown"
    status: str = "unknown"
    confidence: str = "unknown"
    evidence: str = ""


@dataclass
class SourceEvidence:
    url: str
    chars: int = 0
    chunks: int = 0
    artifacts: List[SourceArtifact] = field(default_factory=list)
    indicators: List[IndicatorRecord] = field(default_factory=list)
    dropped: List[str] = field(default_factory=list)
    error: str = ""
    text: str = ""
    #: Running provider totals for every model call made about this source.
    usage: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.artifacts)

    def usage_metadata(self) -> Dict[str, Any]:
        """Provider usage in the shape agents report it; empty when no call reported any."""
        if not self.usage:
            return {}
        from hecate_agent.core.cost_tracker import summarize_cost

        snapshot = {key: self.usage[key] for key in ("llm_calls", "input_tokens", "output_tokens", "llm_duration_ms")}
        snapshot["models"] = sorted(self.usage["models"])
        # Zero from a local model or from missing usage is unknown, not free.
        cost, basis = summarize_cost(
            snapshot["models"],
            snapshot["llm_calls"],
            snapshot["input_tokens"],
            snapshot["output_tokens"],
            float(self.usage["cost_usd"]),
        )
        snapshot["estimated_cost_usd"] = cost
        snapshot["cost_basis"] = basis
        return snapshot

    @property
    def behaviours(self) -> List[SourceArtifact]:
        return [a for a in self.artifacts if a.kind not in INDICATOR_KINDS]

    def summary_block(self, max_chars: int = 6000) -> str:
        """The verified artifacts as compact text for a prompt, with their provenance."""
        if not self.artifacts:
            return ""
        lines = [f"Primary source ({self.url}), artifacts verified verbatim in its text:"]
        for a in self.artifacts:
            evidence = f' — "{a.evidence}"' if a.evidence else ""
            lines.append(f"- [{a.kind}] {a.value} — role: {a.role}; status: {a.status}; confidence: {a.confidence}{evidence}")
        text = "\n".join(lines)
        return text if len(text) <= max_chars else text[: max_chars - 20].rsplit("\n", 1)[0] + "\n- [truncated]"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "chars": self.chars,
            "chunks": self.chunks,
            "artifacts": [asdict(a) for a in self.artifacts],
            "indicators": [r.to_dict() for r in self.indicators],
            "dropped": self.dropped,
            "error": self.error,
        }


# --- Fetching --------------------------------------------------------------------------------


def report_urls(threat_intel: str, source_url: str = "", limit: int = 1) -> List[str]:
    """The report(s) a CTI item points to: its own link first, then links in its text."""
    urls: List[str] = []
    candidates = [source_url] if source_url else []
    candidates.extend(m.group(0).rstrip(".,;:)") for m in _LINK_RE.finditer(threat_intel or ""))
    for url in candidates:
        if url and is_safe_report_url(url) and url not in urls:
            urls.append(url)
            if len(urls) == limit:
                break
    return urls


_GITHUB_REPO_URL = re.compile(r"^https://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")


def github_readme_text(url: str, timeout: float = 20.0) -> str:
    """A GitHub repository's README as markdown, or "" when ``url`` is not a repository root or it cannot be read.

    The rendered page mixes GitHub's own interface into the text and loses heading
    levels: a PoC repository's "detection" folder in the file listing, then its
    nav bar, were each read as the start of the author's detection guidance.
    """
    import os

    match = _GITHUB_REPO_URL.match(url or "")
    if not match:
        return ""
    headers = {"Accept": "application/vnd.github.raw+json", "User-Agent": "hecate-agent"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.get(
            f"https://api.github.com/repos/{match['owner']}/{match['repo']}/readme",
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return ""
    text = response.text.strip() if response.status_code == 200 else ""
    return text if len(text) >= 100 else ""


def fetch_page_text(url: str, timeout: float = 20.0) -> str:
    """Visible text of a report page, or raise on any failure."""
    import os
    import subprocess
    from bs4 import BeautifulSoup

    readme = github_readme_text(url, timeout)
    if readme:
        return readme[:MAX_PAGE_CHARS]

    tavily_key = os.getenv("TAVILY_API_KEY")
    if tavily_key:
        try:
            r = httpx.post(
                "https://api.tavily.com/extract",
                json={"urls": [url], "api_key": tavily_key},
                timeout=min(timeout, 15.0),
            )
            if r.status_code == 200:
                data = r.json()
                results = data.get("results") if isinstance(data, dict) else []
                if results and isinstance(results[0], dict) and results[0].get("raw_content"):
                    content = str(results[0]["raw_content"]).strip()
                    if len(content) >= 100:
                        return strip_page_furniture(strip_repeated_body(content))[:MAX_PAGE_CHARS]
        except Exception:
            pass

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        response = httpx.get(url, timeout=timeout, headers=headers, follow_redirects=True)
        response.raise_for_status()
        html = response.text
    except Exception as exc:
        try:
            res = subprocess.run(
                ["curl", "-sL", "-m", str(int(timeout)), url],
                capture_output=True,
                text=True,
                check=True,
            )
            html = res.stdout
            if not html.strip():
                raise exc
        except Exception:
            raise exc

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()
    return strip_page_furniture(strip_repeated_body(str(soup.get_text(separator="\n", strip=True))))[:MAX_PAGE_CHARS]


#: A repeated run of lines this long is a second copy of the article, not a repeated phrase.
_REPEAT_MIN_CHARS = 2000
#: Lines shorter than this recur legitimately (headings, table cells), so they cannot start a match.
_REPEAT_ANCHOR_CHARS = 80


def strip_repeated_body(text: str) -> str:
    """The page text with a second copy of the article body removed.

    hunt.io's Redis botnet page rendered the whole article twice (60,000
    characters each), so extraction read every chunk twice: 20 of that run's
    30 minutes. A run of identical lines totalling ``_REPEAT_MIN_CHARS`` that
    starts at a long line already seen is a copy; it is cut, together with
    the identical short lines (headings, a table of contents) just before it.
    """
    lines = text.split("\n")
    first_at: Dict[str, int] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        j = first_at.setdefault(line, i) if len(line) >= _REPEAT_ANCHOR_CHARS else i
        if j == i:
            i += 1
            continue
        start, n = i, 0
        while start + n < len(lines) and j + n < start and lines[j + n] == lines[start + n]:
            n += 1
        while j > 0 and start - 1 >= j + n and lines[j - 1] == lines[start - 1]:
            j, start, n = j - 1, start - 1, n + 1
        if sum(len(x) for x in lines[start : start + n]) >= _REPEAT_MIN_CHARS:
            del lines[start : start + n]
            i = start
        else:
            i += 1
    return "\n".join(lines)


#: Headings that start a page's related-content block. The Huntress report's
#: page ended with "You Might Also Like" teasers for AMOS, GhostSocks and
#: NetSupport articles, and technique mapping took T1036 from one of them.
#: Words may sit on separate lines: hunt.io renders its heading as "Related" / "Posts".
_FURNITURE_RE = re.compile(
    (
        r"^(you (might|may) also like|related (posts?|articles?|reading|content|research|stories|blogs?)|recommended "
        r"(reading|for you|articles?)|more from (the )?\w+|read (next|more)|latest (posts|articles|research)|popular posts)"
    ).replace(" ", r"\s+")
    + r"\s*:?$",
    re.IGNORECASE | re.MULTILINE,
)


def strip_page_furniture(text: str) -> str:
    """The page text before its related-content block, when one appears after the article body."""
    for match in _FURNITURE_RE.finditer(text):
        if match.start() > len(text) * 0.4:  # a heading near the top is navigation, not the tail
            return text[: match.start()].rstrip()
    return text


def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Split on line boundaries into overlapping chunks, so no artifact is cut in two."""
    if len(text) <= size:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            newline = text.rfind("\n", start + size // 2, end)
            end = newline if newline > start else end
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


# --- Verification ----------------------------------------------------------------------------


def normalise(text: str) -> str:
    """Lowercase, refang, one backslash, collapsed whitespace: the form values are compared in."""
    text = refang(text).lower().replace("\\\\", "\\")
    return re.sub(r"\s+", " ", text).strip()


def _words(text: str) -> List[str]:
    return re.findall(r"[\w.:/\\%-]+", normalise(text))


def evidence_found(evidence: str, page_words: str) -> bool:
    """True when the passage, or a run of EVIDENCE_WINDOW of its words, appears in the page."""
    words = _words(evidence)
    if not words:
        return False
    if len(words) <= EVIDENCE_WINDOW:
        return " ".join(words) in page_words
    return any(" ".join(words[i : i + EVIDENCE_WINDOW]) in page_words for i in range(len(words) - EVIDENCE_WINDOW + 1))


_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
#: A placeholder where a URL's host belongs: "<c2-host>", "{host}", "$C2", "[server]".
_TEMPLATE_HOST = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?[^/]*(<[^>]*>|\{[^}]*\}|\$\w+|\[[a-z][^\]]*\])")

#: Report wording that fixes what a hash is, checked in this order: a payload
#: that only ever ran in memory must not be mistaken for a file on disk
#: (H-0618's "Decoded SHA-256", labelled executable by the model).
_HASH_ROLE_WORDS = (
    ("memory_only", r"\b(decoded|decrypted|shellcode|in[- ]memory|fileless|reflective(ly)?)\b"),
    ("network_content", r"\b(encoded|encrypted|http response|stream|download(ed)? blob)\b"),
    ("archive", r"\b(archive|zip|rar|7z)\b"),
    ("installer", r"\.msi\b|\bwindows installer\b"),
    ("document", r"\b(docx?|decoy|document|pdf|lure file)\b"),
    # Before executable: the Huntress report's "Profiler/loader Bash script" is a loader, and a script.
    (
        "script",
        r"\b(bash|shell|sh|zsh|powershell|python|perl|javascript|vbscript|applescript|batch) script\b"
        r"|\.(sh|ps1|py|js|vbs|bat)\b",
    ),
    # "Library" as a path segment ("/Users/x/Library/Caches") is a directory, not a DLL.
    ("library", r"\b(dll|dylib|shared (library|object))\b|(?<![/\\])\blibrary\b(?![/\\])"),
    (
        "executable",
        r"\b(loader|executable|dropper|installer|mach-o|elf binary|\.exe)\b|\bpayload\b[^.]{0,80}\bat\s+(/|[a-z]:\\)",
    ),
)


def _valid_value(kind: str, value: str) -> bool:
    """The value has the shape its kind requires: an AES key is not an MD5."""
    text = value.strip().lower()
    if kind in _HASH_LENGTHS:
        return len(text) == _HASH_LENGTHS[kind] and bool(_HEX.match(text))
    if kind == "ipv4":
        import ipaddress

        host, _ = split_host_port(text)
        try:
            return ipaddress.ip_address(host).version == 4
        except ValueError:
            return False
    if kind in ("domain", "hostname"):
        return bool(_DOMAIN.match(text.rstrip(".")))
    if kind == "url":
        # "http://<c2-host>:10000/ping?h=<hostname>" is the report's template, not a URL.
        return "/" in text and ("." in text or ":" in text) and not _TEMPLATE_HOST.search(text)
    return True


def _routable(value: str) -> bool:
    """Whether an IPv4 value is an address another host could be seen connecting to."""
    import ipaddress

    return ipaddress.ip_address(split_host_port(value.strip())[0]).is_global


def _names_a_role(text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for _, pattern in _HASH_ROLE_WORDS)


def _hash_role_from_evidence(evidence: str, role: str) -> str:
    for derived, pattern in _HASH_ROLE_WORDS:
        if re.search(pattern, evidence, re.IGNORECASE):
            return derived
    return role


_ROLE_STOPWORDS = frozenset({"the", "a", "an", "of", "for", "to", "and", "or", "in", "on", "by", "used", "file", "path"})


def _role_supported(role: str, evidence: str, value: str, page: str = "") -> bool:
    """Whether a free-text role shares a content word with the text around the artifact.

    The evidence sentence, the value, and the page text near where the value
    appears: VShell's decoy path is described as "a real Word document" in the
    sentence before "It saves it as: C:\\...docx".
    """
    words = {w for w in re.findall(r"[a-z0-9]+", role.lower()) if w not in _ROLE_STOPWORDS and len(w) > 2}
    near = ""
    at = page.find(normalise(value)) if page else -1
    if at >= 0:
        near = page[max(0, at - 300) : at + len(value) + 300]
    text = f"{evidence} {value} {near}".lower()
    return not words or any(re.search(rf"\b{re.escape(w)}", text) for w in words)


def _checked(raw: Dict[str, Any], page: str, page_words: str) -> Tuple[Optional[SourceArtifact], str]:
    value = refang(str(raw.get("value", ""))).strip()
    kind = str(raw.get("kind", "")).strip().lower()
    if kind in _HASH_LENGTHS:
        value = re.sub(r"\s+", "", value)
    if not value or kind not in (*INDICATOR_KINDS, *BEHAVIOUR_KINDS):
        return None, f"{value or '(empty)'}: unknown kind {kind!r}"
    if kind == "url":
        value = trim_shell_tail(value)
    if not _valid_value(kind, value):
        return None, f"{value}: not a well-formed {kind}"
    if kind == "ipv4" and normalise(value) not in page:
        # "188.245.99.156" / ":10000" on separate lines of a table is still that endpoint;
        # an address the page has with some other port, or none, keeps only the address.
        host, port = split_host_port(value)
        if port is not None and re.search(re.escape(host) + r"\s*:\s*" + str(port) + r"(?!\d)", page):
            pass
        elif port is not None and host in page:
            value = host
    # PDF table cells wrap hashes. Join only complete, bounded hex chunks,
    # never arbitrary document whitespace or a substring of a longer hash.
    if kind in _HASH_LENGTHS:
        found = False
        for match in re.finditer(r"(?<![a-z0-9])[a-f0-9]{16,}(?:\s+[a-f0-9]{16,})*(?![a-z0-9])", page, re.I):
            chunks = match.group().lower().split()
            for start in range(len(chunks)):
                candidate = ""
                for chunk in chunks[start:]:
                    candidate += chunk
                    if len(candidate) >= len(value):
                        found = found or candidate == value.lower()
                        break
    else:
        found = normalise(value) in page or (kind == "ipv4" and split_host_port(value)[0] in page)
    if not found:
        return None, f"{value}: not found verbatim in the source"
    if kind == "ipv4" and not _routable(value):
        # A bind address or a private one is no indicator: the Redis botnet's C2
        # launch line ("c2_persist.py 10000 0.0.0.0") became a C2 at 0.0.0.0:10000.
        return None, f"{value}: not a routable address"
    evidence = str(raw.get("evidence", "")).strip()
    if evidence and not evidence_found(evidence, page_words):
        evidence = ""
    allowed_roles = HASH_ROLES if kind in ("sha256", "sha1", "md5") else NETWORK_ROLES if kind in INDICATOR_KINDS else None
    role = str(raw.get("role", "unknown")).strip().lower() or "unknown"
    status = str(raw.get("status", "unknown")).strip().lower()
    if allowed_roles is not None and role not in allowed_roles:
        role = "unknown"
    if role == "inbound" and not _INBOUND_WORDING.search(evidence):
        # Inbound turns the address's rules around; a C2 misread as a source
        # would lose its outbound rule. Only the passage's own wording decides.
        role = "unknown"
    if status not in STATUSES:
        status = "unknown"
    if not evidence:
        # A classification nothing in the text supports is the model's, not the source's.
        role = "unknown" if allowed_roles is not None else role
        status = "unknown"
    if kind in _HASH_LENGTHS and evidence:
        role = _hash_role_from_evidence(evidence, role)
    if kind in _HASH_LENGTHS and evidence and not _names_a_role(evidence):
        # Evidence that is only "SHA-256: 0524..." states no role: the model's guess
        # ("executable" for SNOWLIGHT shellcode on a VShell replay) is not the source's.
        role = "unknown"
    if allowed_roles is None and role != "unknown" and not _role_supported(role, evidence, value, page):
        # A free-text role must use the passage's words: on the Huntress report the
        # model labelled osascript, a launchctl command and two paths "decoy
        # document path", the example the prompt used to give.
        role = "unknown"
    label = _CONFIDENCE_RE.search(evidence)
    confidence = label.group(1).lower() if label else "unknown"
    return SourceArtifact(value=value, kind=kind, role=role, status=status, confidence=confidence, evidence=evidence), ""


# --- What the text itself says a value is -----------------------------------------------------

_NON_FILE_NAME = (
    r"(token|secret|passw(or)?d|passphrase|key|fingerprint|thumbprint|nonce|salt|ja3s?|jarm|serial|session|cookie|uuid|guid)"
)
#: The text right before a hash-shaped value assigns it to such a name: "C2_TOKEN=", "--tls-fingerprint=", "AES key: ".
_NON_FILE_ASSIGNED = re.compile(rf"[\w-]*{_NON_FILE_NAME}[\w-]*\s*[=:]\s*[\"']?$", re.IGNORECASE)
#: A version identifier named just before it, as a whole word ("reverse_shell_sha256:" is a file):
#: a Node-RED PoC's "GET /flows -> 200 (0 nodes, rev 4f53...)" and '{"rev":"781d..."}'.
_NON_FILE_VERSION_ID = re.compile(r"(?<![\w-])(rev|revision|etag|commit)[\"']?(\s*[=:]\s*|\s+)[\"']?$", re.IGNORECASE)
#: The table cell after it says so: "TLS fingerprint", "Bearer token".
_NON_FILE_LABEL = re.compile(
    rf"^\W*((tls|ssl|ssh|x\.?509|certificate|cert|public|private|bearer|auth\w*|api|access|c2|session)\s+){{0,3}}"
    rf"{_NON_FILE_NAME}\b",
    re.IGNORECASE,
)


def non_file_passage(text: str, value: str) -> str:
    """The passage showing a hash-shaped value is a token, key or fingerprint, or "" when nothing says so."""
    lines = refang(text or "").split("\n")
    needle = value.lower()
    for index, line in enumerate(lines):
        at = line.lower().find(needle)
        if at < 0:
            continue
        assigned = _NON_FILE_ASSIGNED.search(line[:at]) or _NON_FILE_VERSION_ID.search(line[:at])
        if assigned:
            return line[assigned.start() : at + len(value)].strip()
        following = next((x.strip() for x in lines[index + 1 : index + 3] if x.strip()), "")
        if line.strip().lower() == needle and _NON_FILE_LABEL.search(following):
            return f"{line.strip()} {following}"[:300]
    return ""


_IPV4_LINE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
#: The source calls the address something the actor aimed at, not something it runs.
_TARGET_WORDING = re.compile(
    r"\b(qa|test|probe|exploitation|scan|scanning|attack|spray|dev/qa|dev/test|reset-utility|brute[- ]force)[ /-](test )?targets?\b"
    r"|\btargets? (list|pool|host|ip|address)(es|s)?\b|\bvictim (ip|host|address)(es|s)?\b|\b(dev|qa)/(test|qa) pool\b",
    re.IGNORECASE,
)
#: The source names the address as where attack traffic came from: "Source IPs:",
#: "exploitation attempts from", "scanning originating from", "attacker IP".
_INBOUND_WORDING = re.compile(
    r"\b(source|attacker|attacking|scanner|scanning|exploitation|exploiting|threat actor) (ip|ips|ip address(es)?|address(es)?)\b"
    r"|\b(exploitation|exploit|scan(ning)?|attack|brute[- ]force|(password )?spray(ing)?|login|probing|requests?|traffic|"
    r"connections?)( attempts?)? (originat(ed|ing) )?from\b"
    r"|\boriginat(ed|ing) from\b|\binbound (connections?|requests?|traffic) from\b",
    re.IGNORECASE,
)
#: The source gives the address a job victims would see it doing.
_INFRASTRUCTURE_WORDING = re.compile(
    r"\b(c2|c&c|command[- ]and[- ]control|callback|check[- ]?in|staging|rogue|payload|exfiltrat\w+|mining pool|download(s|ed)? from)\b",
    re.IGNORECASE,
)
#: The source ties the address to a different operation.
_OTHER_OPERATION_WORDING = re.compile(
    r"\b(separate|earlier|unrelated|prior|previous|different)\b[^.\n]{0,40}\b(open directory|campaign|toolkit|operation|intrusion)\b",
    re.IGNORECASE,
)


#: The source gives only the name's registry history: who registered it, where its nameservers pointed.
_REGISTRY_WORDING = re.compile(
    r"\b(registration|registrar|whois|nameserver|name[- ]server|dns[- ]hosting) (history|record|churn)s?\b"
    r"|\bre-?regist(ered|ration)\b|\bpreviously[- ]expired\b|\bprior (registrant|owner)s?\b"
    r"|\bnameserver providers?\b",
    re.IGNORECASE,
)


def _own_mention(value: str) -> "re.Pattern[str]":
    """Matches ``value`` where it stands by itself, not as the tail or head of a longer name.

    A search for "example.net" also finds "c2.example.net", so a parent
    domain was read by everything the report says about its subdomains, and
    "1.2.3.4" by "11.2.3.4". A wildcard ("*.example.net") is the name itself.
    """
    return re.compile(rf"(?<![\w-])(?<![\w-]\.){re.escape(value.lower())}(?![\w-])(?!\.[\w-])")


#: A line that stops mid-phrase: it ends in punctuation that opens something, or in a joining word.
_RUNS_ON = re.compile(r"([(\[,:]|\b(at|to|on|from|and|or|of|for|with|the|is|as|by|via|in|against))\s*$", re.IGNORECASE)


def _local_contexts(text: str, value: str) -> List[str]:
    """The words beside each mention of ``value``: the line before, its own line, and the description after.

    Page extraction puts each inline element and table cell on its own line,
    so a table row reads value, type, role on consecutive lines, and several
    addresses can share one role cell. Separator lines and other addresses are
    skipped; the next three lines of words are the description.
    """
    lines = [line.strip() for line in refang(text or "").split("\n")]
    needle = value.lower()
    mention = _own_mention(value)
    contexts: List[str] = []
    for index, line in enumerate(lines):
        if not mention.search(line.lower()):
            continue
        # The line before belongs to this mention only when it runs on into it
        # ("... open directory at" / "194.48.248.105"); a finished table cell is the row above.
        parts = [lines[index - 1]] if index and _RUNS_ON.search(lines[index - 1]) else []
        parts.append(line)
        described = 0
        for later in lines[index + 1 : index + 12]:
            if _IPV4_LINE.search(later) and len(later.split()) <= 2:
                if described:
                    break
                continue
            if len(re.findall(r"[A-Za-z]{2,}", later)) >= 2:
                parts.append(later)
                described += 1
                if described == 3:
                    break
        # Prose lines are long: keep what is near the value, not the paragraph's other subjects.
        joined = " ".join(parts)
        found = mention.search(joined.lower())
        at = found.start() if found else joined.lower().find(needle)
        contexts.append(joined[max(0, at - 200) : at + len(value) + 200])
    return contexts


def network_role_from_context(text: str, value: str) -> Tuple[str, str, str]:
    """(role, status, passage) the text fixes for an address or host, or ("", "", "").

    The Redis botnet report listed eight addresses: one C2, one pool, and six
    the operator tested or attacked ("Observed QA/test target", "Recurring
    WordPress exploitation target"). Typed by the model, three of the six came
    out as C2. An address tied to a different operation ("Earlier, separate
    open directory linked by wallet reuse") is historical for this one.
    Wording that gives it a role victims would see always wins.

    A name the source mentions only for its registry history (who registered
    it, where its nameservers pointed) is a record about the name, not a
    sighting of it in the campaign: the feed listed a parent domain beside its
    live hostname, the report gave the parent's nameserver history and nothing
    else, and it got high-severity DNS and connection rules.
    """
    contexts = _local_contexts(text, value)
    if any(_INFRASTRUCTURE_WORDING.search(c) and not _OTHER_OPERATION_WORDING.search(c) for c in contexts):
        return "", "", ""
    for wording, role, status in (
        (_OTHER_OPERATION_WORDING, "historical", "historical"),
        (_TARGET_WORDING, "target", ""),
        (_INBOUND_WORDING, "inbound", ""),
    ):
        for context in contexts:
            if wording.search(context):
                return role, status, context[:300]
    if contexts and all(_REGISTRY_WORDING.search(c) for c in contexts):
        return "historical", "historical", contexts[0][:300]
    return "", "", ""


def _apply_text_roles(items: List[Any], text: str, kind_of: Callable[[Any], str]) -> None:
    """Set the roles the text itself fixes, over whatever the model chose."""
    for item in items:
        kind = kind_of(item)
        if kind in _HASH_LENGTHS:
            passage = non_file_passage(text, item.value)
            if passage:
                item.role, item.evidence = "non_file", passage
        elif kind in ("ipv4", "domain", "hostname"):
            role, status, passage = network_role_from_context(text, item.value)
            if role:
                item.role, item.status, item.evidence = role, status or item.status, passage


#: A file whose existence under one of these directories is the persistence. Linux, system-wide.
_PERSISTENCE_FILE_RE = re.compile(
    r"(?<![\w.$~/-])(/etc/cron\.(?:d|hourly|daily|weekly|monthly)/\.?\w[\w.@-]*|/var/spool/cron/(?:crontabs/)?\w[\w.-]*"
    r"|/etc/systemd/system/[\w.@-]+\.(?:service|timer)|/etc/profile\.d/\w[\w.-]*|/etc/apt/apt\.conf\.d/\w[\w.-]*"
    r"|/etc/init\.d/\w[\w.-]*)"
)


#: Characters either side of a path that count as its table row.
_ROW_WINDOW = 100


def persistence_file_artifacts(text: str) -> List[SourceArtifact]:
    """Files under persistence directories that the text reports, found without the model.

    The Redis botnet report says the victim "writes it verbatim to
    /etc/cron.d/.redis-miner" and lists the fallback paths in its IOC table;
    the extraction model returned none of them, so no rule looked for the one
    file every victim has. A file there is written by whoever installs it, so
    the path needs no judgement, only a sentence that reports it as observed.
    """
    from hecate_agent.core.technique_evidence import actor_material_report, passage_status, sentence_status, sentences

    found: Dict[str, SourceArtifact] = {}
    actor_material = actor_material_report(text)
    for sentence in sentences(text):
        for match in _PERSISTENCE_FILE_RE.finditer(sentence):
            value = match.group(1).rstrip(".")
            if value.rsplit("/", 1)[-1] == "crontabs" or value.lower() in found:
                continue
            status, passage = passage_status(sentence, match.start(), match.end(), actor_material)
            if passage is not sentence:
                # A run-on segment is usually a flattened table: judge and quote the row, in
                # whole words, not the rows around it.
                passage = sentence[max(0, match.start() - _ROW_WINDOW) : match.end() + _ROW_WINDOW]
                passage = passage[passage.find(" ") + 1 : passage.rfind(" ")]
                status = sentence_status(passage, actor_material)
            if status == "observed":
                found[value.lower()] = SourceArtifact(value, "file_path", "persistence file", "active", "unknown", passage)
    return list(found.values())


#: The role given to an artifact the text places on the actor's own side.
ATTACKER_SIDE_ROLE = "attacker-side"


def _mark_attacker_side(artifacts: List[SourceArtifact], text: str) -> None:
    """Untie from the intrusion each behaviour artifact the text places on the actor's own machine.

    The Redis botnet replay wrote "file written by the malware" rules for
    redis_fleet.txt, c2_persist.db and xmrig.exe: the operator's target list,
    C2 database and own miner. An artifact is the actor's when a sentence
    naming it is about the actor's side. It keeps its place in the evidence table, with the
    passage, but its status is no longer ``active``, so no rule is built on it.
    """
    for artifact in artifacts:
        if artifact.kind in INDICATOR_KINDS:
            continue
        passage = attacker_side_passage(text, artifact.value)
        if passage:
            artifact.role, artifact.status, artifact.evidence = ATTACKER_SIDE_ROLE, "unknown", passage


#: Extensions that make a dotted name a file, not a domain ("github.com") or a version ("6.22.2").
FILE_EXTENSIONS = (
    "py|sh|ps1|bat|cmd|exe|dll|sys|php|pl|rb|js|vbs|hta|jar|json|txt|log|db|sqlite|b64|bin|elf|so|dylib|plist|save|bak"
    "|zip|rar|7z|tgz|gz|tar|iso|html|docx?|xlsx?|pdf|lnk|msi|ya?ml|conf|cfg|ini|service|timer|dat|tmp|key|pem"
)
#: A file name with no directory: nothing says where on a host it would be.
_BARE_FILE_RE = re.compile(rf"^[\w.-]+\.({FILE_EXTENSIONS})$")
_VICTIM_WORDING_RE = re.compile(r"\bvictims?\b|\bcompromised (hosts?|servers?|machines?|systems?)\b")


def attacker_side_passage(text: str, value: str) -> str:
    """The passage that places ``value`` on the actor's own side, or "" when the text does not.

    Usable for any value, not only extracted artifacts: the drafting model
    names files in its prose that extraction never returned.
    """
    from hecate_agent.core.technique_evidence import actor_material_report, attacker_side, passage_status, sentences

    needle = refang(value).lower().strip()
    if len(needle) < 4:
        return ""
    actor_material = actor_material_report(text)
    mentions: List[Tuple[str, str]] = []
    for sentence in sentences(text):
        at = sentence.lower().find(needle)
        if at >= 0:
            mentions.append(passage_status(sentence, at, at + len(needle), actor_material))
    # Only wording about the actor's side counts. "No sentence reports it as observed" was tried
    # and untied the Huntress stealer's own path, named in a sentence that read as capability.
    own = next((p for status, p in mentions if status == "context" and attacker_side(p.lower(), actor_material)), "")
    if not own and actor_material and _BARE_FILE_RE.match(needle):
        # A report written from the actor's own files names those files without a location.
        # One named by itself, never beside anything on a victim, is theirs: the Redis
        # report's SAM.save was a registry hive exported on the operator's host.
        alone = [p for _, p in mentions if re.search(r"(?<![\w/\\.-])" + re.escape(needle), p.lower())]
        if alone and not any(_VICTIM_WORDING_RE.search(p.lower()) for _, p in mentions):
            own = alone[0]
    return " ".join(own.split())[:300]


#: A path that says where on a host the file is: absolute, or under a home or environment variable.
#: A top-level directory alone ("/tmp") is not a file's location.
_LOCATED_PATH_RE = re.compile(r"^(/[^/]+/|~/|\$\{?\w+\}?/|%\w+%\\|[A-Za-z]:[\\/]).*[^/\\]$")
#: A passage that does not report the path being used: advice to the reader, a path the
#: malware only checks for, or one an attempt was aimed at ("SSH key-injection targets").
_NOT_OBSERVATION_RE = re.compile(
    r"\b(audit|monitor|watch for|hunt for|look for|search for|alert on|block|treat any|disable|enforce|restrict"
    r"|checks? (whether|for|if)|looks? for|targets?|candidates?|probe[sd]?|attempt\w*)\b",
    re.I,
)


def _tie_observed_paths(artifacts: List[SourceArtifact], text: str) -> None:
    """Tie a located file path to the intrusion when the report itself shows it in observed activity.

    Whether a path got a rule depended on the model quoting a sentence for it.
    One Redis replay returned ``/tmp/.xmrig`` with no passage, so its status
    stayed unknown and the hidden miner had no rule; the run before had it.
    The report says where the miner goes ("points the resulting hidden
    /tmp/.xmrig binary at ..."), and that sentence needs no model to find.
    Only a path with a location qualifies: a bare name could be anywhere.
    Advice ("audit /etc/crontab for ..."), a path the malware only checks for
    and one an attempt was aimed at are not observations of it in use.
    """
    from hecate_agent.core.technique_evidence import actor_material_report, passage_status, sentences

    pending = [
        a
        for a in artifacts
        if a.kind in ("file_path", "path", "file", "filename", "file_name")
        and a.status == "unknown"
        and a.role != ATTACKER_SIDE_ROLE
        and _LOCATED_PATH_RE.match(a.value)
    ]
    if not pending:
        return
    actor_material = actor_material_report(text)
    all_sentences = sentences(text)
    for artifact in pending:
        needle = refang(artifact.value).lower()
        for sentence in all_sentences:
            at = sentence.lower().find(needle)
            if at < 0:
                continue
            status, passage = passage_status(sentence, at, at + len(needle), actor_material)
            if status == "observed" and not _NOT_OBSERVATION_RE.search(passage):
                artifact.status = "active"
                artifact.evidence = artifact.evidence or " ".join(passage.split())[:300]
                break


def _tie_fuller_paths(artifacts: List[SourceArtifact]) -> None:
    """A path whose file the source ties to the intrusion is tied to it too.

    Reports name a file in the narrative and give its full path in an IOC
    table: Huntress wrote "under the name com.apple.verified" and listed
    "$HOME/Library/Caches/com.apple.trustd/com.apple.verified ... Filesystem
    path used by this malware". The name came out active and the path
    unknown, so the stealer's own path got no rule and the draft's claim audit
    struck it as "the source does not tie it to this intrusion".
    """
    paths = ("file_path", "path", "file", "filename", "file_name")
    active = [a for a in artifacts if a.kind in paths and a.status == "active" and len(a.value) >= 4]
    for artifact in artifacts:
        if artifact.kind not in paths or artifact.role == ATTACKER_SIDE_ROLE:
            continue
        if artifact.status != "unknown" and not (artifact.status == "active" and artifact.role == "unknown"):
            continue
        name = re.split(r"[/\\]", artifact.value)[-1]
        tied = next((a for a in active if a is not artifact and a.value in (name, artifact.value)), None)
        if tied is None:
            continue
        artifact.status = "active"
        artifact.evidence = artifact.evidence or tied.evidence
        if artifact.role == "unknown":
            artifact.role = tied.role


def _merge(existing: SourceArtifact, new: SourceArtifact) -> SourceArtifact:
    """Prefer the reading with supporting evidence; fill gaps from the other."""
    best, other = (new, existing) if new.evidence and not existing.evidence else (existing, new)
    for attr in ("role", "status", "confidence"):
        if getattr(best, attr) == "unknown" and getattr(other, attr) != "unknown":
            setattr(best, attr, getattr(other, attr))
    return best


def _to_record(artifact: SourceArtifact, url: str) -> IndicatorRecord:
    rtype = INDICATOR_KINDS[artifact.kind]
    value, port = split_host_port(artifact.value) if rtype == "ipv4" else (artifact.value, None)
    if rtype in ("sha256", "sha1", "md5", "domain", "hostname"):
        value = value.lower().rstrip(".")
    return IndicatorRecord(
        value=value,
        type=rtype,
        role=artifact.role,
        status=artifact.status,
        confidence=artifact.confidence,
        source=url,
        evidence=artifact.evidence,
        ports=[port] if port else [],
    )


def _parse(text: str, diagnostics: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        if diagnostics is not None:
            diagnostics.append("source extraction response contains no complete JSON object")
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        if diagnostics is not None:
            diagnostics.append("source extraction response is incomplete or malformed; only complete artifacts were retained")
        # Token limits may cut off the final artifact. Retain only complete
        # preceding entries; every entry still goes through source checks.
        start = re.match(r'\{\s*"artifacts"\s*:\s*\[', text[match.start() :])
        if not start:
            return []
        remaining = text[match.start() + start.end() :].lstrip()
        recovered: List[Dict[str, Any]] = []
        decoder = json.JSONDecoder()
        while remaining:
            try:
                item, end = decoder.raw_decode(remaining)
            except json.JSONDecodeError:
                break
            if not isinstance(item, dict):
                break
            recovered.append(item)
            remaining = remaining[end:].lstrip()
            if not remaining.startswith(","):
                break
            remaining = remaining[1:].lstrip()
        return recovered
    items = data.get("artifacts") if isinstance(data, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


# --- Targeted classification of feed indicators ----------------------------------------------

CLASSIFY_PROMPT = f"""You classify indicators using ONLY the report passages provided.
For each listed indicator return its role and status as the passages state them.
Hash roles: {list(HASH_ROLES)}. Network roles: {list(NETWORK_ROLES)}. Statuses: {list(STATUSES)}.
Use "historical" when the passages say an indicator is old, a prior tenant, unrelated, or not a
campaign IOC. "evidence" is one sentence copied word for word from the passages.
Return strict JSON: {{"artifacts": [{{"value": ..., "kind": ..., "role": ..., "status": ..., "evidence": ...}}]}}
"""

#: Characters of context around each occurrence of an indicator.
CONTEXT_CHARS = 700


def _contexts(text: str, value: str, limit: int = 2) -> List[str]:
    """Passages around the first occurrences of ``value`` (defanged or not) in ``text``."""
    target = normalise(value)
    found: List[str] = []
    # Its own mentions, as in ``_own_mention``: not as part of a longer name.
    pattern = r"(?<![\w-])(?<![\w-]\.)(?<![\w-]\[\.\])" + re.escape(value).replace(r"\.", r"(?:\.|\[\.\]|\(\.\))")
    for match in re.finditer(pattern + r"(?![\w-])(?!(?:\.|\[\.\])[\w-])", text, re.IGNORECASE):
        start, end = max(0, match.start() - CONTEXT_CHARS), match.end() + CONTEXT_CHARS
        found.append(text[start:end])
        if len(found) == limit:
            break
    return found if found or not target else []


def classify_feed_indicators(
    records: List[IndicatorRecord], evidence: "SourceEvidence", complete: Optional["Complete"] = None
) -> List[IndicatorRecord]:
    """Role and status for feed indicators the chunked pass did not classify.

    Only indicators the source actually mentions are asked about, with the
    passages around them; the reply goes through the same verbatim checks.
    Indicators the source never mentions are returned unchanged.
    """
    known = {(r.type, r.value) for r in evidence.indicators if r.evidence}
    pending = [r for r in records if (r.type, r.value) not in known and normalise(r.value) in normalise(evidence.text)]
    if not pending:
        return []
    passages: List[str] = []
    for record in pending:
        for passage in _contexts(evidence.text, record.value):
            if passage not in passages:
                passages.append(passage)
    listing = "\n".join(f"- {r.value} ({r.type})" for r in pending)
    prompt = f"Indicators:\n{listing}\n\nPassages:\n" + "\n---\n".join(passages)
    try:
        reply = (complete or partial(_default_complete, usage=evidence.usage))(
            [{"role": "system", "content": CLASSIFY_PROMPT}, {"role": "user", "content": prompt[: CHUNK_CHARS * 2]}]
        )
    except Exception as exc:  # the provider raises its SDK's own error types
        logger.warning("Feed indicator classification failed: %s", exc)
        return []
    page = normalise(evidence.text)
    page_words = " ".join(_words(evidence.text))
    wanted = {normalise(r.value): r.type for r in pending}
    classified: List[IndicatorRecord] = []
    for raw in _parse(reply, evidence.dropped):
        value_key = normalise(str(raw.get("value", "")))
        rtype = wanted.get(value_key) or wanted.get(split_host_port(value_key)[0])
        if not rtype:
            continue
        raw = {**raw, "kind": rtype}
        artifact, problem = _checked(raw, page, page_words)
        if artifact is None:
            evidence.dropped.append(problem)
            continue
        classified.append(_to_record(artifact, evidence.url))
    return classified


# --- Extraction ------------------------------------------------------------------------------

Complete = Callable[[List[Dict[str, str]]], str]


def _default_complete(messages: List[Dict[str, str]], usage: Optional[Dict[str, Any]] = None) -> str:
    """One provider call; its token usage is added to ``usage`` when one is given."""
    from hecate_agent.core.llm_provider import create_provider

    response = create_provider().complete(messages, max_tokens=3000, temperature=0.0)
    if usage is not None:
        usage["llm_calls"] = usage.get("llm_calls", 0) + 1
        usage["input_tokens"] = usage.get("input_tokens", 0) + response.input_tokens
        usage["output_tokens"] = usage.get("output_tokens", 0) + response.output_tokens
        usage["llm_duration_ms"] = usage.get("llm_duration_ms", 0) + response.duration_ms
        usage["cost_usd"] = usage.get("cost_usd", 0.0) + response.cost_usd
        usage["models"] = sorted({*usage.get("models", []), response.model})
    return response.text


def extract_source_evidence(
    url: str, *, page_text: Optional[str] = None, complete: Optional[Complete] = None
) -> SourceEvidence:
    """Fetch ``url`` (unless ``page_text`` is given) and extract verified artifacts from all of it.

    Never raises: a fetch or model failure comes back as ``error`` so the
    caller can draft from the feed item as before.
    """
    evidence = SourceEvidence(url=url)
    try:
        text = page_text if page_text is not None else fetch_page_text(url)
    except (httpx.HTTPError, ValueError) as exc:
        evidence.error = f"fetch failed: {exc}"
        return evidence
    evidence.text = text
    evidence.chars = len(text)
    page = normalise(text)
    page_words = " ".join(_words(text))
    merged: Dict[Tuple[str, str], SourceArtifact] = {}
    call = complete or partial(_default_complete, usage=evidence.usage)
    chunks = chunk_text(text)
    evidence.chunks = len(chunks)
    extraction_incomplete = False
    pending = [(chunk, 0) for chunk in chunks]
    while pending:
        chunk, depth = pending.pop(0)
        try:
            reply = call([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": chunk}])
        except Exception as exc:  # the provider raises its SDK's own error types
            logger.warning("Source evidence extraction call failed: %s", exc)
            evidence.error = evidence.error or f"extraction failed: {exc}"
            continue
        diagnostics: List[str] = []
        parsed = _parse(reply, diagnostics)
        if diagnostics:
            extraction_incomplete = True
            retry = depth < 2 and len(chunk) >= 1200
            action = "retrying smaller source sections" if retry else "section remains incomplete after bounded recovery"
            evidence.dropped.extend(f"{message}; {action}" for message in diagnostics)
            if retry:
                midpoint = len(chunk) // 2
                boundary = chunk.rfind("\n", len(chunk) // 3, midpoint)
                boundary = boundary + 1 if boundary >= 0 else midpoint
                pending[0:0] = [(chunk[:boundary], depth + 1), (chunk[boundary:], depth + 1)]
        for raw in parsed:
            artifact, problem = _checked(raw, page, page_words)
            if artifact is None:
                evidence.dropped.append(problem)
                continue
            key = (artifact.kind, normalise(artifact.value))
            merged[key] = _merge(merged[key], artifact) if key in merged else artifact
    for artifact in persistence_file_artifacts(text):
        key = (artifact.kind, normalise(artifact.value))
        merged[key] = _merge(merged[key], artifact) if key in merged else artifact
    evidence.artifacts = list(merged.values())
    _apply_text_roles(evidence.artifacts, text, lambda a: str(a.kind))
    _mark_attacker_side(evidence.artifacts, text)
    _tie_observed_paths(evidence.artifacts, text)
    _tie_fuller_paths(evidence.artifacts)
    evidence.indicators = [_to_record(a, url) for a in evidence.artifacts if a.kind in INDICATOR_KINDS]
    if evidence.artifacts:
        evidence.error = ""  # a partial failure still produced verified evidence
    elif extraction_incomplete:
        evidence.error = "source extraction incomplete: no verified artifacts recovered; see dropped diagnostics"
    return evidence


def build_indicator_records(
    cti_indicators: Dict[str, List[str]], evidence: Optional[SourceEvidence], complete: Optional[Complete] = None
) -> List[IndicatorRecord]:
    """The feed's indicators, typed with whatever the primary source says about them.

    Without usable source evidence the feed indicators come back with unknown
    roles, which route exactly as untyped indicators always have.
    """
    from hecate_agent.core.provenance import (
        attach_text_ports,
        attach_url_ports,
        mark_source_pages,
        merge_records,
        records_from_cti,
    )

    cti = records_from_cti(cti_indicators)
    if evidence is None or not evidence.text:
        return cti
    extra = classify_feed_indicators(cti, evidence, complete)
    records = merge_records(cti, [*evidence.indicators, *extra])
    _apply_text_roles(records, evidence.text, lambda r: str(r.type))
    for record in records:
        if record.source == "cti" and normalise(record.value) in normalise(evidence.text):
            record.source = evidence.url
        if record.role in ("non_file", "target", "historical") and record.evidence and record.source == "cti":
            record.source = evidence.url
        if record.role in ("target", "historical"):
            record.ports = []
    mark_source_pages(records, [evidence.url])
    attach_url_ports(records)
    attach_text_ports(records, evidence.text)
    return records
