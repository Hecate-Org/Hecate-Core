"""ATT&CK techniques the source text itself points at, found without a model.

The hypothesis model picks technique IDs from memory, and on a 14B local model
that went badly: across six drafts (H-0002..H-0007) none of the eight IDs it
chose was right. LabubaRAT "masquerades as NVIDIA software" and got T1027.004
Compile After Delivery; a macOS Terraform intrusion got T1207 Rogue Domain
Controller. The right answers were in the text -- the model just was not
looking for them.

This finds them deterministically and hands them to the model as candidates.
Precision matters more than recall: a wrong candidate is a suggestion the
model may take. So a technique is proposed only when its name appears in the
text *as a phrase* -- "screen capture", "process injection", "masquerading"
-- not when its words turn up separately. Tried first and rejected: requiring
every distinctive word anywhere in the text, which proposed every "...
Discovery" technique for any report saying "discovered" and Accessibility
Features for "remote access ... features".
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from hecate_agent.core.attack_matrix import TechniqueInfo

_WORD_RE = re.compile(r"[a-z0-9]+")

#: Suffixes stripped before comparing, longest first, so "Masquerading",
#: "masquerades" and "masquerade" all reduce to "masquerad". A fixed-length
#: prefix was tried and failed both ways: six letters let "Screensaver" match
#: "screen" and "Systemctl" match "system"; longer ones lost "masquerades".
#: A plural "s" comes off first, so "containers" and "Container" agree.
_SUFFIXES = ("ation", "ated", "ating", "ing", "ion", "ed", "er", "e")

#: Derivational suffixes that leave a different word behind when the root is
#: short: "portion" is not "port", "region" is not "reg".
_LONG_ROOT_SUFFIXES = frozenset({"ation", "ion"})


def _stem(word: str) -> str:
    """Reduce a word to the form its variants share.

    Kept in step with hecate-runner's grounding audit, which stems the same
    way: the two decide from the same words whether a source describes a
    technique, and drifting apart is how one proposed what the other dropped.
    """
    if word.endswith("s") and not word.endswith("ss") and len(word) - 1 >= 4:
        word = word[:-1]
    for suffix in _SUFFIXES:
        floor = 5 if suffix in _LONG_ROOT_SUFFIXES else 4
        if word.endswith(suffix) and len(word) - len(suffix) >= floor:
            return word[: -len(suffix)]
    return word


#: Words in technique names that do not say *which* behaviour is meant, so
#: their presence in a report is no evidence for the technique. Kept in step
#: with hecate-runner's grounding audit, which judges with the same idea.
_GENERIC_NAME_WORDS = frozenset(
    {
        "account", "accounts", "after", "application", "before", "command",
        "control", "controller", "controls", "data", "delivery", "domain",
        "domains", "execution", "extension", "extensions", "file", "files",
        "from", "information", "into", "legitimate", "local", "location",
        "match", "module", "modules", "name", "network", "other", "process",
        "protocol", "remote", "resource", "service", "services", "software",
        "standard", "system", "systems", "tool", "tools", "user", "using",
        "with", "over", "through", "abuse", "deployment", "malicious", "valid",
    }
)  # fmt: skip

#: One-word technique names that are also everyday words, so a report using
#: the word is no evidence for the technique. "Trap" (T1546.005, a Unix shell
#: builtin) was proposed for a Teams vishing campaign on "OAuth Traps"; "proxy"
#: is as often the defender's web proxy as the attacker's. Report wording can
#: still name either deliberately ("socks proxy" for T1090).
#:
#: The rest name a thing, not a behaviour: the sub-techniques of T1213 (Data
#: from Information Repositories) are called after the repository, so
#: "Databases" was proposed for every report on a database server and
#: "Confluence" would be for one about exploiting it. A screensaver is a
#: screensaver far more often than it is T1546.002.
_EVERYDAY_ONE_WORD_NAMES = frozenset({"trap", "proxy", "databases", "confluence", "sharepoint", "screensaver"})


def name_is_everyday_word(name: str) -> bool:
    """Whether a technique's name is one everyday word, so a text using the word does not name the technique."""
    tokens = [w for w in _WORD_RE.findall(name.lower()) if w not in _JOINERS]
    return len(tokens) == 1 and tokens[0] in _EVERYDAY_ONE_WORD_NAMES

#: Tactics describing what happens before the intrusion, on the adversary's
#: own infrastructure. Their technique names are everyday report nouns
#: ("Malware", "Server", "Exploits", "Botnet"), so name matching would propose
#: them for every report, and they are rarely something a hunt can observe.
#: Report wording below can still name one deliberately.
_EXCLUDED_TACTICS = frozenset({"resource-development", "reconnaissance"})

#: How reports describe techniques whose ATT&CK names they rarely use. Each
#: phrase must describe only that behaviour: an entry here is a suggestion
#: made to the model every time the phrase appears. Matched on whole words.
_REPORT_WORDING: Dict[str, Tuple[str, ...]] = {
    "T1127.001": ("msbuild",),
    "T1027": ("obfuscated", "obfuscation"),
    "T1583.001": ("typosquatted", "typosquatting", "typosquat"),
    "T1608.006": ("seo poisoning", "search engine poisoning"),
    "T1553.001": ("gatekeeper",),
    "T1059.001": ("powershell",),
    "T1059.002": ("applescript", "osascript"),
    "T1059.004": ("bash", "zsh", "shell script", "shell_exec"),
    "T1059.007": ("javascript", "jscript"),
    "T1071.004": ("dns tunneling", "dns tunnelling", "dns tunnel"),
    "T1090": ("socks5", "socks proxy"),
    "T1113": ("screen capture", "screenshot", "screenshots"),
    "T1056.001": ("keylogger", "keylogging"),
    "T1195.002": ("supply chain", "supply-chain"),
    "T1566": ("phishing",),
    "T1078": ("compromised credentials", "stolen credentials", "default credentials", "valid accounts", "valid account"),
    # Not "malicious file": nearly every report says it, whoever ran the file.
    # It put User Execution on a VeloCloud exploit that involved no user.
    "T1204.002": ("fake job interview", "fake job interviews"),
    "T1102": ("dead drop", "dead-drop", "etherhiding"),
    "T1003.001": ("lsass",),
    "T1218.011": ("rundll32",),
    "T1047": ("wmi", "wmic"),
    "T1053.005": ("schtasks", "scheduled task"),
    "T1053.003": ("crontab", "cron job"),
    "T1543.004": ("launchdaemon", "launch daemon"),
    "T1543.001": ("launchagent", "launch agent"),
    "T1068": ("privilege escalation", "elevation of privilege"),
    # Not "zero-day" or "0-day": they say a bug was unknown, not where it was.
    # They put T1190 on DarkMe, a campaign that had abandoned exploits, and on
    # a browser 0-day that is client-side (T1203/T1189), not public-facing.
    "T1190": ("remote code execution", "rce", "exploit public-facing", "public-facing", "internet-facing"),
    # ATT&CK now names this sub-technique just "DLL", which is too short to
    # match as a name, so without these DLL hijacking was never proposed.
    "T1574.001": (
        "dll hijacking",
        "dll hijack",
        "dll search order hijacking",
        "search order hijacking",
        "dll sideloading",
        "dll side-loading",
        "sideloads",
        "sideloading",
        "side-loading",
        "sideloaded",
    ),
    "T1036": ("disguised as",),
    # DNS used to move data out, not as the C2 channel (T1071.004 has the
    # tunnelling phrases). H-0017, "Abusing Open Recursive DNS for
    # Exfiltration", was otherwise mapped to T1027 alone.
    "T1048.003": (
        "dns exfiltration",
        "exfiltration over dns",
        "exfiltration via dns",
        "dns for exfiltration",
        "exfiltrate data over dns",
        "exfiltrate data via dns",
        "exfiltrates data over dns",
        "exfiltrates data via dns",
    ),
    "T1105": (
        "download",
        "downloads",
        "downloaded",
        "downloading",
        "downloader",
        "ingress tool transfer",
    ),
    "T1059.005": ("vbs", "vbscript"),
}


#: Joining words dropped from a name before phrase matching, so "Boot or
#: Logon Autostart Execution" is not required to be quoted with its "or".
_JOINERS = frozenset({"a", "an", "and", "or", "the", "of", "for", "to", "via", "in", "on"})


def _name_tokens(name: str) -> List[str]:
    """A technique name as the stems a report would have to use, in order.

    Empty for a name that says nothing specific ("Services", "Malicious
    File"): as a phrase of its own it would match every report. "Malicious
    File" put User Execution on a VeloCloud advisory for "malicious files".
    """
    tokens = [w for w in _WORD_RE.findall(name.lower()) if w not in _JOINERS]
    if all(t in _GENERIC_NAME_WORDS for t in tokens):
        return []
    if len(tokens) == 1 and (len(tokens[0]) < 4 or tokens[0] in _EVERYDAY_ONE_WORD_NAMES):
        return []
    return [_stem(t) for t in tokens]


def _phrase_in(tokens: List[str], words: List[str]) -> bool:
    """Whether ``tokens`` occur consecutively in ``words`` (both stemmed)."""
    n = len(tokens)
    if not n:
        return False
    for i in range(len(words) - n + 1):
        # Equal stems, not a shared prefix: prefix matching read "VCO
        # deployments contain a critical vulnerability" as T1610 Deploy
        # Container.
        if all(words[i + j] == tokens[j] for j in range(n)):
            return True
    return False


def _all_techniques() -> Iterable["TechniqueInfo"]:
    from hecate_agent.core.attack_matrix import get_sorted_tactics, get_techniques_for_tactic

    seen: Set[str] = set()
    for tactic in get_sorted_tactics():
        for tech in get_techniques_for_tactic(tactic):
            tid = str(tech.get("id", ""))
            if tid and tid not in seen:
                seen.add(tid)
                yield tech


def _wording_matches(text: str) -> Iterable[Tuple[str, str, int]]:
    """Techniques named by report wording. Scored above any name match: an
    entry was written down because the phrase is specific."""
    from hecate_agent.core.attack_matrix import get_technique

    phrase_text = " " + " ".join(_WORD_RE.findall(text.lower())) + " "
    for tid, phrases in _REPORT_WORDING.items():
        if any(" {} ".format(" ".join(_WORD_RE.findall(p))) in phrase_text for p in phrases):
            info = get_technique(tid)
            if info:
                yield tid, str(info.get("name", tid)), 100


def _name_matches(text: str) -> Iterable[Tuple[str, str, int]]:
    """Techniques whose name the text quotes; a longer name is the more
    specific claim, so it scores higher."""
    words = [_stem(w) for w in _WORD_RE.findall(text.lower()) if w not in _JOINERS]
    for tech in _all_techniques():
        tactics = set(tech.get("tactic_shortnames") or [])
        if tactics and tactics <= _EXCLUDED_TACTICS:
            continue
        tokens = _name_tokens(str(tech.get("name", "")))
        if _phrase_in(tokens, words):
            yield str(tech["id"]), str(tech.get("name", "")), 50 + len(tokens)


class _SemanticTechniqueMatcher:
    """TF-IDF semantic retriever across MITRE ATT&CK STIX descriptions."""

    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.techs: List[Tuple[str, str]] = []
        docs: List[str] = []
        for tech in _all_techniques():
            tactics = set(tech.get("tactic_shortnames") or [])
            if tactics and tactics <= _EXCLUDED_TACTICS:
                continue
            name = str(tech.get("name", ""))
            if name_is_everyday_word(name):
                continue
            tid = str(tech["id"])
            desc = str(tech.get("description", ""))
            phrases = " ".join(_REPORT_WORDING.get(tid, ()))
            doc = f"{name} {name} {name} {phrases} {phrases}. {desc}"
            self.techs.append((tid, name))
            docs.append(doc)

        if not docs:
            self.vectorizer = None
            self.matrix = None
            return

        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=25000)
        self.matrix = self.vectorizer.fit_transform(docs)

    def match(self, text: str, threshold: float = 0.14) -> Iterable[Tuple[str, str, int]]:
        if not self.vectorizer or self.matrix is None:
            return
        from sklearn.metrics.pairwise import cosine_similarity

        if not text or not text.strip():
            return
        # Score the whole text along with substantial paragraphs (>= 100 chars)
        # to ensure tradecraft context rather than out-of-context unigrams.
        paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) >= 100]
        units = [text.strip(), *paragraphs] if paragraphs else [text.strip()]
        unit_vecs = self.vectorizer.transform(units)
        sims = cosine_similarity(unit_vecs, self.matrix)
        scored: Dict[str, Tuple[int, str]] = {}
        for row in sims:
            for idx in row.argsort()[::-1][:5]:
                score = float(row[idx])
                if score >= threshold:
                    tid, name = self.techs[idx]
                    int_score = int(score * 100)
                    if tid not in scored or scored[tid][0] < int_score:
                        scored[tid] = (int_score, name)
        for tid, (score, name) in scored.items():
            yield tid, name, score


_SEMANTIC_MATCHER: Optional[_SemanticTechniqueMatcher] = None


def _semantic_matches(text: str) -> Iterable[Tuple[str, str, int]]:
    """Techniques identified by semantic TF-IDF similarity against ATT&CK STIX data."""
    global _SEMANTIC_MATCHER
    try:
        from hecate_agent.core.attack_matrix import is_using_stix

        if not is_using_stix():
            return []
        if _SEMANTIC_MATCHER is None:
            _SEMANTIC_MATCHER = _SemanticTechniqueMatcher()
        return _SEMANTIC_MATCHER.match(text)
    except Exception:
        return []


def candidate_techniques(text: str, limit: int = 16, semantic: bool = True) -> List[Tuple[str, str]]:
    """(ID, name) for techniques the text describes, strongest evidence first.

    ``semantic`` adds TF-IDF similarity matches. Those are leads for a prompt,
    not evidence: on a Node-RED exploit README they proposed RC Scripts,
    Password Managers and Audio Capture (from "PCAP capture"). Anything that
    treats a candidate as support for a technique wants :func:`named_techniques`.

    Returns an empty list when the ATT&CK data cannot be read: no candidates
    is the honest answer, and the caller's prompt simply omits the section.
    """
    if not text or not text.strip():
        return []
    # Automated OSINT enrichment blocks (WHOIS/RDAP, Shodan port lists, API responses)
    # contain metadata and error lines, not adversary tradecraft.
    if "### 🛡️ Automated Threat Enrichment" in text:
        text = text.split("### 🛡️ Automated Threat Enrichment", 1)[0]
    elif "Automated Threat Enrichment" in text:
        text = text.split("Automated Threat Enrichment", 1)[0]
    if not text.strip():
        return []
    scored: Dict[str, Tuple[int, str]] = {}
    try:
        similar = _semantic_matches(text) if semantic else []
        for tid, name, score in [*_wording_matches(text), *similar, *_name_matches(text)]:
            if tid not in scored or scored[tid][0] < score:
                scored[tid] = (score, name)
    except Exception:
        return []
    ranked = sorted(scored.items(), key=lambda kv: (-kv[1][0], kv[0]))
    return [(tid, name) for tid, (_, name) in ranked[:limit]]


def named_techniques(text: str, limit: int = 16) -> List[Tuple[str, str]]:
    """(ID, name) for techniques the text names as a phrase: report wording or the ATT&CK name."""
    return candidate_techniques(text, limit=limit, semantic=False)


def format_candidates(candidates: List[Tuple[str, str]]) -> Optional[str]:
    """The prompt block for ``candidates``, or None when there are none."""
    if not candidates:
        return None
    lines = ["  {}: {}".format(tid, name) for tid, name in candidates]
    return "\n".join(lines)
