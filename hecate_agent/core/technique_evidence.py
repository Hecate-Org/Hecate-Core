"""Behaviour-to-technique mapping with the passage that supports it.

Reports describe what malware does ("sandbox detection, CPU checks, and
sleep-timer evasion", "XOR-decodes it with key 0x99"), not ATT&CK's names for
it. Matching technique names alone found 2 of the 11 techniques H-0618's
report shows in use, and one of those two (T1113 Screen Capture) came from a
list of what VShell *can* do, not what this intrusion did.

This module maps described behaviour to technique IDs through a small curated
catalog, and judges each supporting sentence: a sentence describing what the
sample or actor did is ``observed``; one describing what a tool offers or can
do is ``capability``. A technique is proposed only on observed evidence, and
every mapping keeps the sentence it rests on so a reviewer can check it. A
bare label is not evidence: "fileless" alone does not establish T1620; an
in-memory execution sequence does.
"""

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from hecate_agent.core.provenance import refang


@dataclass
class TechniqueEvidence:
    technique_id: str
    status: str  # "observed" | "capability" | "negated" | "context"
    passage: str
    source: str  # where the passage came from, e.g. "cti", "primary source"
    behaviour: str  # the catalog entry that matched, or "technique name"

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


#: technique ID -> (behaviour label, pattern). Patterns run on refanged,
#: lowercased sentences. Keep each specific enough that a match describes the
#: behaviour, not merely a topic word; a pattern here proposes a technique.
_CATALOG: Tuple[Tuple[str, str, str], ...] = (
    ("T1204.002", "lure the recipient runs",
     r"\b(disguised|masquerad\w+|posing) as (a |an )?(\w+[- ])?(resume|cv|invoice|document|pdf|report|installer)\b"
     r"|\b(victim|user|recipient)s? (runs?|opens?|execut\w+|launch\w*|double[- ]click\w*)\b"),
    ("T1036", "disguised as something benign",
     r"\bdisguised as\b|\bmasquerad\w+ as\b|\bposing as\b|\bfake (resume|invoice|document|installer|update)\b"),
    ("T1059.003", "Windows command shell", r"\bcmd\.exe\b|\bcommand prompt\b|\bwindows command shell\b"),
    ("T1059.001", "PowerShell", r"\bpowershell(\.exe)?\b"),
    ("T1059.005", "Visual Basic", r"\bvbscript\b|\.vbs\b|\bvisual basic\b"),
    # A ".js" name alone is a file, often a config ("ships no settings.js"); it
    # counts only when something runs it.
    ("T1059.007", "JavaScript",
     r"\bjavascript\b|\bjscript\b|\b(wscript|cscript|node)(\.exe)?\s+\S+\.js\b"
     r"|\b(runs?|ran|execut\w+|launch\w*)\b[^.]{0,40}\.js\b|\.js\b[^.]{0,40}\b(runs|ran|executes|executed|launched)\b"),
    ("T1059.004", "Unix shell",
     r"\b(ba|z)?sh -c\b|/bin/(ba|z)?sh\b|\b(bash|shell) script\b|\bbash \.?[\w.-]+\b|\b(curl|wget)\b.{0,200}?\|\s*(ba|z)?sh\b"),
    ("T1059.002", "AppleScript", r"\bosascript\b|\bapplescript\b"),
    ("T1204.004", "malicious copy and paste",
     r"\bclickfix\b|\bfake captcha\b|\bpast(e|es|ed|ing) (a |the |this )?(\w+ ){0,3}(command|script|string)s? into "
     r"(the |a )?(\w+ )?(terminal|run dialog|powershell|command prompt)\b"),
    ("T1497.001", "sandbox or system checks",
     r"\bsandbox (detection|checks?|evasion)\b|\banti[- ]?(sandbox|vm|analysis)\b"
     r"|\b(cpu|processor|core)s? (count|checks?)\b|\bcpu checks?\b|\blogical processors\b"
     r"|\bvirtual machine (detection|checks?)\b|\bchecks? (for|whether) (a |an )?(sandbox|virtual|vm|debugger)"),
    ("T1497.003", "time-based evasion",
     r"\bsleep[- ]?(timer|checks?|evasion|verification)\b|\btiming (checks?|verification)\b"
     r"|\btime[- ]based (checks?|evasion)\b|\bdelay(ed)? execution\b|\bbeepsleep\b"),
    ("T1105", "downloads a further stage",
     r"\b(download|fetch|retriev|pull|drop|stag)\w*\b.{0,35}?\b(payload|stager|implant|malware|binary|executable|backdoor|stage|tool)s?\b"
     r"|\bdownload(s|ed|ing)?\s+\d[\d.,]*\s*(kb|mb|gb|bytes)\b"
     r"|\bdownload(s|ed|ing)? the [\w-]+ (malware|payload|executable|binary)\b"
     r"|\b(curl|wget)\b.{0,300}?\s-o\s?\S"),
    ("T1140", "decodes or decrypts a payload",
     r"\bxor[- ]?(decod\w*|decrypt\w*)\b|\bxor(s|ed)? (it|the|with)\b"
     r"|\bdecod(es|ed|ing) (it|the (payload|config\w*|data|shellcode))\b"
     r"|\bdecrypt(s|ed|ing)? (it|the (payload|config\w*|data|shellcode|strings))\b"
     r"|\bbase64[- ]?decod\w*\b|\baes[- ](cbc |gcm )?decrypt\w*\b"),
    ("T1620", "code executed from memory",
     r"\breflective(ly)? (load\w*|inject\w*)\b"
     r"|\ballocat\w+ memory\b.{0,120}\b(marks? (them|it) executable|creates? a thread)\b"
     r"|\b(virtualalloc|allocadsmem|allocat\w+ (executable|rwx) memory)\b.{0,160}\b(virtualprotect|createthread)\b"
     r"|\bexecut\w+ (it |the (payload|shellcode|stager) )?(directly )?(in|from) memory\b"
     r"|\bin[- ]memory (execution|loader|loading)\b|\bshellcode (loader|execution|runner)\b"),
    # HTTP requests or traffic alone are any web exchange, an exploit's own
    # included ("7 HTTP requests over 7 connections" in a PoC's lab capture);
    # they count only beside the C2 they serve.
    ("T1071.001", "HTTP for staging or C2",
     r"\bhttps? (staging|c2|c&c|beacon\w*)\b"
     r"|\bhttps? (requests?|communications?|traffic)\b.{0,80}?\b(c2|c&c|command[- ]and[- ]control|beacon\w*|callback|implant|backdoor)\b"
     r"|\b(c2|c&c|command[- ]and[- ]control|beacon\w*|callback|implant|backdoor)\b.{0,80}?\bhttps? (requests?|communications?|traffic)\b"
     r"|\b(c2|c&c|command[- ]and[- ]control|beacon\w*|callback|implant|backdoor|payload|stager)s?\b.{0,80}?\bover https?\b"
     # The Redis botnet's heartbeat: "pings c2_persist.py (...:10000) with a plain HTTP GET".
     r"|\b(check(s|ed|ing)?[- ]in|call(s|ed|ing)? back|beacon\w*|heartbeat|pings?)\b.{0,120}?\bhttps? (get|post)s?\b"
     r"|\bhttps? (get|post)s?\b.{0,120}?\b(c2|c&c|check[- ]?in|callback|heartbeat|beacon\w*)\b"),
    ("T1571", "C2 on a non-standard port",
     r"\bnon[- ]standard (tcp |udp )?ports?\b|\b(unusual|uncommon) (tcp |udp )?ports?\b"
     r"|\b(c2|c&c|command[- ]and[- ]control|callback|check[- ]?in|beacon\w*|heartbeat)\b.{0,80}?\bport (?!(80|443|53|22|25)\b)\d{2,5}\b"
     r"|\bport (?!(80|443|53|22|25)\b)\d{2,5}\b.{0,80}?\b(c2|c&c|command[- ]and[- ]control|callback|check[- ]?in|beacon\w*)\b"
     # An endpoint written "address:port" beside its role: "188.245.99.156:10000 ... C2 callback endpoint".
     r"|\b\d{1,3}(\.\d{1,3}){3}\s?:\s?(?!(80|443|53|22|25)\b)\d{2,5}\b.{0,60}?\b(c2|c&c|callback|check[- ]?in)\b"
     r"|\b(c2|c&c|callback|check[- ]?in)\b.{0,60}?\b\d{1,3}(\.\d{1,3}){3}\s?:\s?(?!(80|443|53|22|25)\b)\d{2,5}\b"),
    ("T1095", "non-application-layer C2",
     r"\braw tcp\b|\bcustom (binary|tcp|udp) protocol\b|\bnon-application[- ]layer\b"
     r"|\btcp (socket|stream|connection)s? (to|for|with) (the )?(c2|server|operator)\b"),
    ("T1573", "encrypted C2 channel",
     r"\baes[- ]gcm\b|\bencrypted (https? )?(c2|c&c|channel|traffic|communications?|protocol)\b"
     r"|\b(rc4|aes|chacha\w*)[- ]encrypted (c2|traffic|channel|communications?)\b|\b(certificate|tls) pinning\b"),
    ("T1027", "obfuscated or encrypted content",
     r"\bobfuscat\w+\b|\bencrypted (config\w*|strings|payload)\b|\bencoded (config\w*|payload|strings)\b"),
    ("T1480", "execution guardrail", r"\bkill[- ]?switch\b|\bexecution guardrails?\b|\benvironment(al)? keying\b"),
    ("T1053.005", "scheduled task", r"\bscheduled task\b|\bschtasks(\.exe)?\b"),
    ("T1547.001", "Run key or Startup folder", r"\brun key\b|currentversion\\run\b|\bstartup folder\b"),
    ("T1566.001", "phishing attachment", r"\b(spear)?phishing (email|attachment)s?\b|\bmalicious attachments?\b"),
    ("T1566.002", "phishing link",
     r"\bphishing links?\b|\bmalicious links?\b|\b(followed|clicked|opened) (a|the) link\b[^.]{0,60}\b(e-?mail|message)"),
    ("T1218.011", "rundll32", r"\brundll32(\.exe)?\b"),
    ("T1218.007", "msiexec", r"\bmsiexec(\.exe)?\b"),
    ("T1218.005", "mshta", r"\bmshta(\.exe)?\b"),
    ("T1055", "process injection",
     r"\bprocess injection\b|\binject(s|ed|ing)? (it |the \w+ )?into\s+"
     r"(?:(?:a|the|another|remote|target|running)\s+)*(?:process\b|[\w.-]+\.exe\b)"),
    ("T1055.012", "process hollowing", r"\bprocess hollowing\b|\bhollow(s|ed|ing) (out )?(a |the )?\w*\s?process\b"),
    ("T1574.001", "DLL side-loading or hijacking", r"\bdll (side[- ]?load\w*|hijack\w*|search order)\b|\bside[- ]?load\w*\b"),
    ("T1113", "screen capture", r"\bscreen ?(capture|shot)s?\b"),
    ("T1070.004", "self-deletion or file cleanup",
     r"\bdelet(es|ed|ing) (itself|the (loader|dropper|file|binary))\b|\bself[- ]delet\w+\b|\brm -(f|rf|fr)\b"
     r"|\bthen delet(e|es|ed) the (temporar\w+ )?(stored )?(file|script|payload)\b"),
    ("T1070.003", "shell history cleared",
     r"\bhistory -[dc]\b|\bfc -p\b|\.(bash|zsh)_history\b|\b(delet|clear|wip)(es|ed|ing)? (the )?(\w+ )?command history\b"),
    ("T1082", "system information discovery",
     r"\bioreg\b|\bsystem_profiler\b|\buname -[amr]\b|\bsysteminfo(\.exe)?\b|\bhostnamectl\b"
     r"|\b(profile|profil\w+|collects?|gather\w*) [^.]{0,40}\b(system|hardware) (info\w*|details|profile)\b"),
    ("T1033", "user discovery", r"\bwhoami\b|\bcurrently logged[- ]in user\b|\bquser\b"),
    ("T1553.001", "Gatekeeper bypass",
     r"\bcom\.apple\.quarantine\b|\bxattr -[dc]\b|\bgatekeeper (bypass|bit|prompt)\b|\bremoves? the (gatekeeper|quarantine)\b"),
    ("T1036.005", "legitimate name or location",
     r"\bmimics? the name\b|\bmimic\w* (a |the )?legitimate\b|\bnamed (after|like) (a |the )?legitimate\b"
     r"|\bimpersonat\w+ (a |the )?(legitimate |system )?(process|service|binary|file|path|directory)\b"),
    ("T1543.001", "Launch Agent", r"\blaunch ?agents?\b|/library/launchagents/|\blaunchctl (bootstrap|load)\b"),
    ("T1543.004", "Launch Daemon", r"\blaunch ?daemons?\b|/library/launchdaemons/"),
    ("T1543.002", "systemd service", r"/etc/systemd/system/[\w.@-]+\.service\b|\bsystemctl (enable|start)\b"),
    ("T1053.003", "cron job", r"\bcrontab\b|/etc/cron\.|/var/spool/cron\b"),
    # Server-side tradecraft: no user runs anything. The Redis botnet report
    # (hunt.io) showed all of these and the catalog, built from two
    # user-execution cases, had none.
    ("T1190", "exposed service exploited",
     r"\bexploit\w* (\w+ ){0,3}(unauthenticated|exposed|internet[- ]facing|public[- ]facing|publicly accessible|misconfigured)"
     r" (\w+ ){0,3}(instances?|servers?|services?|hosts?|appliances?|devices?|endpoints?|databases?|apis?)\b"
     r"|\b(unauthenticated|exposed|internet[- ]facing) (\w+ ){0,2}(instances?|servers?|services?|hosts?|databases?) "
     r"(were|was|got|are|is) (compromised|exploited|hijacked|abused)\b"
     r"|\b(slaveof|replicaof)\b.{0,160}?\b(rogue|attacker|crafted)\b|\brogue (redis )?(replication|master|server)\b"),
    ("T1496", "cryptomining on the victim",
     r"\bxmrig\b|\bcrypto(currency )?[- ]?min(er|ers|ing)\b|\bcoin[- ]?miners?\b|\b(monero|xmr) (miner|mining)\b"
     r"|\bmin(es|ed|ing) (monero|xmr|cryptocurrency)\b|\bstratum\+(tcp|ssl)\b"),
    ("T1564.001", "hidden file or directory",
     r"\bhidden (file|director(y|ies)|binary|folder)s?\b|\bdot[- ]?prefixed\b|\bdotfiles?\b"
     r"|(?<![\w.])/(tmp|var/tmp|dev/shm)/\.[a-z][\w.-]*"),
    ("T1056.002", "fake credential prompt",
     r"\bosascript\b[^.]{0,80}\b(password|credentials?)\b|\b(password|credentials?)\b[^.]{0,80}\bosascript\b"
     r"|\b(fake|spoofed|bogus) (password|login|system|authentication) (prompt|dialog|window)\b"
     r"|\bprompt(s|ed|ing)? (the )?(victim|user|target) (for|to enter) (their |a )?(password|credentials)\b"),
    ("T1555.001", "Keychain credentials", r"\bkeychain\b"),
    ("T1555.003", "browser credential stores",
     r"\bbrowser (password|credential)s?( stores?| databases?)?\b|\bsaved (browser )?passwords\b|\blogin data\b"),
    ("T1112", "registry modification", r"\bmodif(y|ies|ied) (the )?registry\b"),
    ("T1543.003", "Windows service created", r"\b(creates?|install\w*) (a )?(new )?(windows )?service\b|\bsc(\.exe)? create\b"),
    ("T1003.001", "LSASS access", r"\blsass\b"),
    ("T1611", "container breakout", r"\bcontainer (escape|breakout)\b|\bescape(s|d|ing)? to (the )?host\b|\bnsenter\b"),
    ("T1562.001", "disable or modify tools", r"\bblind(s|ed|ing)? (host-based monitoring|auditd|edr|telemetry)\b|\bkernel tracepoints?\b|\bbpftool\b|\bebpf (rootkit|bytecode|program)\b|\bsuppress(es|ed|ing)? (telemetry|monitoring|events?)\b"),
    ("T1567.002", "exfiltration to cloud storage", r"\bexfiltrat\w+ (to|directly to) (cloud storage|aws s3|s3 bucket)\b|\bs3://|\brclone(\.exe)?\b|\bsvchost_sync(\.exe)?\b"),
    ("T1021.006", "Windows Remote Management", r"\bwinrm\b|\bwsmprovhost(\.exe)?\b|\bremote management over (tcp|http)\b"),
    ("T1550.001", "Application Access Token", r"\boauth (app|application|token|consent)\b|\bconsent grant\b|\btoken theft\b"),
)  # fmt: skip

_COMPILED = tuple((tid, label, re.compile(pattern)) for tid, label, pattern in _CATALOG)

#: A sentence about what a tool offers or could do, rather than what happened.
_CAPABILITY_RE = re.compile(
    r"\b(public|published|prior|vendor) (\w+ ){0,2}(analysis|reporting|research|documentation)\b"
    r"|\bgives? (an |the )?operators?\b|\b(meant|intended) to\b|\bobjective\b|\bcapabilit(y|ies)\b|\bcan (be used to|also|perform|take|capture|execute|run|steal)\b"
    r"|\b(is|are) (able|capable) (to|of)\b|\bsupports?\b|\boffers?\b|\bprovid(es|ing) \w+( \w+)? with\b"
    r"|\bfeatures? (include|such as)\b|\ballows? (operators|attackers|the operator)\b|\bdesigned to\b|\bcould be used\b"
    # A feature list: "a fileless VShell RAT ... enabling command execution, file access, screen capture".
    r"|\b(enabl(es?|ing)|allow(s|ing))\b[^.;]{0,80},"
)
#: A sentence that reports what the sample, actor or intrusion actually did.
_OBSERVED_RE = re.compile(
    r"\bobserved\b|\bin this (sample|campaign|intrusion|case|run)\b|\bduring (execution|the (run|analysis|sandbox))\b"
    r"|\bwe (saw|observed|found)\b|\bwas (seen|observed)\b|\bthe (sample|pcap|sandbox run)\b"
)

#: A sentence about another actor or campaign, typical of attribution
#: comparisons ("UAT-8302 ... sideloading ... no lure match"). It describes
#: someone else's tradecraft, so it neither supports nor rules out a mapping.
_CONTEXT_RE = re.compile(
    r"\b(unc|uat|apt|ta|fin|dev)-?\d{2,5}\b|\bearth [a-z]+\b|\bno (ioc|lure|infrastructure|windows)\b[^.]{0,30}\bmatch\b"
    r"|\bdifferent malware\b|\bpublished (chains|access|reporting)\b|\b(an|the) unrelated\b"
    # A description of what a legitimate subsystem does, not of this intrusion:
    # "BTM ... is used to track anything that installs itself to run
    # automatically (like launch agents, login items, or cron jobs)".
    r"|\bis a legitimate (apple|macos|windows|microsoft|linux|system) \w+\b|\ba legitimate (apple|macos|windows|microsoft|linux) "
    r"(subsystem|process|service|tool|utility|binary)\b|\b(is|are) (typically |commonly )?used (by macos|by windows|by the "
    r"(os|operating system)|for automatic)\b"
)

#: A sentence about the actor's own side of the operation: their machine, their
#: toolkit, the directory it was recovered from, the hosts they tested on. The
#: Redis botnet report (hunt.io) was written from an exposed directory on the
#: operator's Windows server, so most of it described that server: registry
#: hive exports, xmrig.exe, a fileless Python loader. Read as victim evidence
#: it scoped the hunt to Windows and mapped T1620 from the operator's loader.
_ATTACKER_SIDE_RE = re.compile(
    r"\b(operator|attacker|actor|adversary)(['\u2019]s)? own\b"
    r"|\b(operator|attacker|actor|adversary)['\u2019]s (host|machine|workstation|box|server|system|toolkit|tooling|files"
    r"|scripts|infrastructure|working (directory|environment)|campaign (logs?|telemetry|results?)|c2 server|windows\w*)\b"
    r"|\bon (their|its) own (host|machine|workstation|box|server|infrastructure)\b"
    r"|\b(open|exposed) director(y|ies)\b|\bin the (same |exposed |open )?directory\b"
    r"|\bthe (toolkit|directory) (also )?(holds?|held|ships|carries|contains?|includes?|is)\b"
    r"|\b(in|throughout|across) the toolkit\b|\bexploit (source|scripts?)\b|\bcampaign([- ]results?)? logs?\b"
    r"|\brecovered (files?|scripts?|evidence|toolkit)\b|\b(qa|test|dev/test|dev/qa) (hosts?|targets?|box(es)?|pool)\b"
)
#: A tool or data file named on its own, not as part of a path: "rogue.py", "wp_scan_results.json".
_TOOL_FILE_RE = re.compile(r"(?<![\w/\\.-])[\w-]+\.(py|sh|ps1|bat|php|pl|rb|b64|json|txt|log|db)\b")
#: How much of a report's opening is read to learn what it was written from.
_FRAME_CHARS = 6000

#: What happens on the victim's side, which keeps a sentence evidence even when it also mentions the actor's.
_VICTIM_SIDE_RE = re.compile(r"\bvictims?\b|\bcompromised (hosts?|servers?|machines?|systems?)\b")
#: How far back a quoted block's introduction is looked for, and how much of it is read.
_LEAD_IN = 500
_LEAD_IN_CLAUSE = 250

#: Label and metadata lines in a CTI item: a title or a tag list names a topic
#: without describing what happened, so it is not evidence.
_LABEL_LINE = re.compile(
    r"^\s*(>\s*)?(otx pulse|misp event|rss|tags|adversary/attribution|indicators|key indicators|references|link|source"
    r"|org|tlp|threat level|mitre att&ck techniques|filehash-\w+|ipv4|url|hostname|domain)\b.{0,40}:",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def sentences(text: str) -> List[str]:
    """Sentences of ``text``, rebuilt across the line breaks page extraction inserts.

    Scraped pages put every inline element on its own line ("launching \\n
    cmd.exe \\n , opening a DOCX"), so lines are joined before splitting on
    sentence punctuation. Label lines (titles, tag lists, indicator lists) are
    dropped first.
    """
    lines = [line for line in refang(text or "").splitlines() if not _LABEL_LINE.match(line)]
    joined = re.sub(r"\s+", " ", " ".join(lines)).replace(" ,", ",").replace(" .", ".")
    return [s.strip() for s in _SENTENCE_SPLIT.split(joined) if len(s.strip()) > 3]


#: A statement that something did NOT happen ("Not observed: an operator
#: issuing a command"). It rules a behaviour out; it is not evidence of it.
_NEGATED_RE = re.compile(
    r"\b(not|never|n't) (been )?(observed|seen|successful|succeeded)\b"
    r"|\bnot one (?:[\w\s]{1,40})?succeeded\b"
    r"|\b(?:zero|no|0) confirmed (?:compromise|infection|victim|execution|success)s?\b"
    r"|\bno (?:evidence|sign|indication)s? (?:of|that)\b"
    r"|\b(?:did|does|was|were) not (?:use|show|perform|occur|succeed)\w*\b"
    r"|\b(?:unsuccessful|failed to|attempted but failed)\b"
)
#: Advice to defenders: mitigation, remediation, hardening. It names what to
#: change, not what happened. A PoC README's "stop the service if it is not
#: needed: systemctl disable --now node-red" was read as observed T1569.003.
_DEFENDER_ADVICE_RE = re.compile(
    r"\b(to mitigate|as a mitigation|mitigation steps?|remediation|workarounds?|we recommend"
    r"|(is|are) (strongly )?recommended|(defenders|administrators|admins) should"
    r"|if (it is|it's|they are) not (needed|required|in use)|enable authentication"
    r"|upgrade to (version |v)?\d|apply the (vendor )?(patch|update|fix))\b"
)
#: Segments longer than this are judged, and quoted, by a window around the
#: match: scraped headings carry no punctuation, so unrelated sections can
#: run together into one "sentence".
_WINDOW_OVER = 450
_WINDOW = 200


def extract_primary_actor(text: str) -> Optional[str]:
    """Actor name the report attributes activity to, e.g. UNC-3882, APT29, UAT-8302."""
    match = re.search(
        r"(?:^|\n)\s*(?:>\s*)?(?:\*\*)?(?:Adversary/Attribution|Threat Actor|Actor|Adversary|Attribution)(?:\*\*)?\s*:\s*(?:\*\*)?([^\n\r(]+)",
        text or "",
        re.IGNORECASE,
    )
    if match:
        val = match.group(1).strip().strip("*_` #:\t ")
        if val and val.lower() not in ("none", "unknown", "unattributed", "n/a"):
            return val
    return None


def sentence_status(sentence: str, actor_material: bool = False, primary_actor: Optional[str] = None) -> str:
    """Whether a passage reports observed use, a tool capability, a negation, or another actor's tradecraft.

    ``actor_material``: the report was written from the actor's own files (:func:`actor_material_report`).
    """
    lowered = sentence.lower()
    # Analyst constraints are not observations of the mentioned behavior.
    if re.match(r"^(?:do not|never)\s+(?:infer|claim|label|manufacture|assert)\b", lowered):
        return "context"
    ctx_match = _CONTEXT_RE.search(lowered)
    if ctx_match:
        matched_str = ctx_match.group(0).lower().replace("-", "")
        clean_actor = (primary_actor or "").lower().replace("-", "").strip("*_` #:\t ")
        if not (clean_actor and (clean_actor == matched_str or clean_actor in matched_str or matched_str in clean_actor)):
            return "context"
    if attacker_side(lowered, actor_material):
        return "context"
    # "negated", not "context": advice mentions the technique without it
    # happening, so it must not stand as observed use for an asserted ID either.
    if _NEGATED_RE.search(lowered) or _DEFENDER_ADVICE_RE.search(lowered):
        return "negated"
    if _CAPABILITY_RE.search(lowered) and not _OBSERVED_RE.search(lowered):
        return "capability"
    return "observed"


def actor_material_report(text: str) -> bool:
    """Whether a report says, at its opening, that it was written from the actor's own material.

    An exposed directory, a leaked toolkit or a seized server yields a report
    whose files are the actor's: hunt.io's Redis botnet report opens with "This
    one held the operator's entire working toolkit" and "all trace back to the
    operator's own files". Two different such statements are needed, so one
    passing mention of an open directory does not reframe an ordinary report.
    """
    opening = refang(text or "")[:_FRAME_CHARS].lower()
    return len({m.group(0) for m in _ATTACKER_SIDE_RE.finditer(opening)}) >= 2


def attacker_side(lowered: str, actor_material: bool = False) -> bool:
    """Whether a lowercased passage describes the actor's own machine or toolkit and nothing on a victim.

    In a report written from the actor's own material, a passage that names a
    tool or data file by itself is about that tool: "wp_spray.py sprays
    credentials across the fleet" describes a script on the operator's host.
    """
    if _VICTIM_SIDE_RE.search(lowered):
        return False
    return bool(_ATTACKER_SIDE_RE.search(lowered)) or (actor_material and bool(_TOOL_FILE_RE.search(lowered)))


def passage_status(
    sentence: str,
    start: int,
    end: int,
    actor_material: bool = False,
    primary_actor: Optional[str] = None,
) -> Tuple[str, str]:
    """(status, passage) for a match at ``start``..``end`` of ``sentence``: the sentence, or a window of a run-on one.

    A quoted block has no sentence of its own, so in a run-on segment it takes
    the side of the clause that introduces it: "... right on the operator's
    own host: cd /d C:\\Users\\Public\\xmrig ..." is the operator's command line.
    """
    if len(sentence) <= _WINDOW_OVER:
        return sentence_status(sentence, actor_material, primary_actor=primary_actor), sentence
    passage = sentence[max(0, start - _WINDOW) : min(len(sentence), end + _WINDOW)]
    status = sentence_status(passage, actor_material, primary_actor=primary_actor)
    if status == "observed":
        lead = sentence[max(0, start - _LEAD_IN) : start].lower()
        colon = lead.rfind(": ")
        if colon >= 0 and attacker_side(lead[max(0, colon - _LEAD_IN_CLAUSE) : colon], actor_material):
            status = "context"
    return status, passage


def _clip(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def map_behaviours(texts: Iterable[Tuple[str, str]], primary_actor: Optional[str] = None) -> List[TechniqueEvidence]:
    """Techniques the described behaviour supports, one entry each, with a passage.

    ``texts`` is ``(source label, text)`` pairs, most authoritative first. An
    observed passage outranks a capability one wherever it appears; within a
    status the first source wins.
    """
    found: Dict[str, TechniqueEvidence] = {}
    texts = list(texts)
    actor_material = any(actor_material_report(text) for _, text in texts)
    if not primary_actor:
        for _, text in texts:
            primary_actor = extract_primary_actor(text)
            if primary_actor:
                break
    for source, text in texts:
        for sentence in sentences(text):
            lowered = sentence.lower()
            for tid, label, pattern in _COMPILED:
                match = pattern.search(lowered)
                if not match:
                    continue
                status, passage = passage_status(
                    sentence, match.start(), match.end(), actor_material, primary_actor=primary_actor
                )
                if status in ("context", "negated"):
                    continue
                current = found.get(tid)
                if current is None or (current.status == "capability" and status == "observed"):
                    found[tid] = TechniqueEvidence(tid, status, _clip(passage), source, label)
    return list(found.values())


def _name_pattern(names: Iterable[str]) -> Optional["re.Pattern[str]"]:
    from hecate_agent.core.technique_candidates import name_is_everyday_word

    # "Databases" is T1213.006's whole name; a report on a database server says
    # the word in every paragraph without describing data being taken from one.
    phrases = [re.escape(n.lower()) for n in names if n and len(n) >= 4 and not name_is_everyday_word(n)]
    return re.compile(r"\b(" + "|".join(phrases) + r")\b") if phrases else None


def technique_support(technique_id: str, names: Iterable[str], text: str) -> Optional[TechniqueEvidence]:
    """The best passage in ``text`` for a technique, by its catalog behaviour or its ATT&CK name.

    Returns None when nothing in the text mentions it. The result's status
    says whether any mention is an observed use; only ``capability`` passages
    means the text describes the technique solely as something a tool can do.
    """
    from hecate_agent.core.technique_candidates import _REPORT_WORDING

    catalog = [(label, pattern) for tid, label, pattern in _COMPILED if tid == technique_id]
    # The phrases that proposed it as a candidate ("remote code execution" for
    # T1190), so a candidate the source supports has a passage to show.
    phrases = [re.escape(p.lower()) for p in _REPORT_WORDING.get(technique_id, ())]
    if phrases:
        catalog.append(("report wording", re.compile(r"\b(" + "|".join(phrases) + r")\b")))
    by_name = _name_pattern(names)
    best: Optional[TechniqueEvidence] = None
    actor_material = actor_material_report(text)
    for sentence in sentences(text):
        lowered = sentence.lower()
        match, label = None, None
        for lbl, pattern in catalog:
            match = pattern.search(lowered)
            if match:
                label = lbl
                break
        if match is None and by_name is not None:
            match = by_name.search(lowered)
            label = "technique name" if match else None
        if match is None or label is None:
            continue
        status, passage = passage_status(sentence, match.start(), match.end(), actor_material)
        if status == "context":
            continue
        if status == "negated":
            status = "capability"  # mentioned, but not as something that happened
        if best is None or (best.status == "capability" and status == "observed"):
            best = TechniqueEvidence(technique_id, status, _clip(passage), "", label)
        if best.status == "observed":
            break
    return best
