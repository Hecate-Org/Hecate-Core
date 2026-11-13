"""Process rules from the command lines a report shows being run.

Reports often quote the exact commands an intrusion ran. The Huntress ClickFix
report lists the loader's sequence: ``ioreg -c IOPlatformExpertDevice -d 2``,
``system_profiler SPHardwareDataType``, ``xattr -d com.apple.quarantine ...``,
``launchctl bootstrap gui/501 ...``. Left to the model, those became at most
one generic rule; a command quoted in the report is the most specific thing a
process rule can match, and needs no judgement.

Each command of a known external program, found in a sentence that reports
what happened (the status test from :mod:`technique_evidence`), becomes one
``process_creation`` candidate: the program's image and the command's first
distinctive argument. Shell builtins (``history``, ``fc``, ``export``, ``cd``)
are left out: they run inside the user's shell, start no process, and no
process event can see them.
"""

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hecate_agent.core.provenance import refang
from hecate_agent.core.technique_evidence import actor_material_report, sentence_status

#: program -> (platform, rule level). Discovery tools run constantly on healthy
#: hosts, so a match on them alone is a low-level lead.
_UNIX: Dict[str, str] = {
    "xattr": "medium", "launchctl": "medium", "osascript": "medium", "curl": "medium", "wget": "medium",
    "chmod": "low", "chown": "low", "cp": "low", "mv": "low", "rm": "low", "mkdir": "low", "security": "medium",
    "codesign": "low", "spctl": "medium", "systemctl": "medium", "crontab": "medium", "dscl": "medium",
    "defaults": "low", "base64": "low", "openssl": "low", "nohup": "low", "ioreg": "low", "system_profiler": "low",
    "sudo": "low", "pkill": "low", "killall": "low", "ditto": "low", "hdiutil": "low", "bash": "medium",
    "sh": "medium", "zsh": "medium", "python3": "low", "perl": "low", "nc": "medium", "socat": "medium",
    "nsenter": "high", "bpftool": "high", "kubectl": "medium", "crictl": "medium", "docker": "medium",
    "podman": "medium", "nerdctl": "medium", "runc": "high", "insmod": "high", "modprobe": "medium", "rmmod": "medium",
    "rclone": "high",
}  # fmt: skip
_WINDOWS: Dict[str, str] = {
    "powershell": "medium", "pwsh": "medium", "cmd": "low", "rundll32": "medium", "regsvr32": "medium",
    "mshta": "medium", "wmic": "medium", "certutil": "medium", "bitsadmin": "medium", "vssadmin": "high",
    "bcdedit": "high", "wevtutil": "medium", "schtasks": "medium", "reg": "medium", "sc": "medium", "msiexec": "medium",
    "wscript": "medium", "cscript": "medium", "net": "low", "nltest": "medium", "curl.exe": "medium",
    "rclone": "high", "svchost_sync": "high", "wsmprovhost": "medium",
}  # fmt: skip
#: Tokens that end a command in running text: a shell separator, or a colon
#: introducing the report's explanation of it.
_STOP_RE = re.compile(r"^(;|&&?|\|\|?|>|>>|2>|:|\)|->|—)$|^:")
_PLACEHOLDER_RE = re.compile(r"^\[.*\]$|^<.*>$|^\$\(|^\$\{?\w+\}?$|\.\.\.|…|<[^>]+>|http\(s\)|^\[|\]$")
_VARIABLE_PREFIX_RE = re.compile(r"^(\$\{?\w+\}?|~|%\w+%)(?=[/\\])")
#: Commands that configure a local lab environment, test harness, or loopback probe
#: rather than showing adversary execution.
_LAB_HARNESS_RE = re.compile(
    r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b"
    r"|/__lab/|/__test/|/lab/status"
    r"|\b(?:docker-compose|docker\s+compose|podman-compose|docker\s+build|podman\s+build)\b"
    r"|\b(?:npm\s+install|pip\s+install\s+-r|mvn\s+clean|gradle\s+build|cargo\s+build|npm\s+test|pytest|python3?\s+-m\s+unittest)\b"
    r"|\b(?:benchmark|reproduce-benchmark|verify-sandbox)\b",
    re.IGNORECASE,
)
#: Explicit indicators of Linux / Unix tools or paths in CTI text, used for multi-platform fallback.
LINUX_MARKERS = re.compile(
    r"(?i)\b(nsenter|bpftool|ebpf|kprobe|cgroup|auditd|syslog|sys/fs/bpf|/bin/(?:bash|sh|zsh)|/usr/bin/|systemctl|journalctl)\b"
)
#: Programs whose first argument is a plain-word subcommand ("launchctl bootstrap").
_SUBCOMMANDS = frozenset(
    {"launchctl", "systemctl", "defaults", "dscl", "net", "sc", "reg", "schtasks", "wmic", "bcdedit", "vssadmin",
     "wevtutil", "crontab", "spctl", "codesign", "hdiutil", "openssl", "bpftool", "kubectl", "crictl", "docker",
     "podman", "nerdctl", "nsenter", "rclone", "svchost_sync"}
)  # fmt: skip
#: The subcommands of the container CLIs. Any lowercase word after "docker" read
#: as one: a README's keyword list ("... industrial os docker lab 6ES7647 ...")
#: became the rule "docker lab 6ES7647-0BA00-1YA2".
_CONTAINER_SUBCOMMANDS = frozenset(
    {"run", "exec", "cp", "create", "start", "stop", "kill", "restart", "rm", "rmi", "pull", "push", "build", "load",
     "import", "export", "save", "commit", "attach", "logs", "inspect", "ps", "images", "container", "image", "volume",
     "network", "compose", "login", "update", "pause", "unpause", "top", "port", "events", "info", "version",
     "apply", "get", "describe", "delete", "edit", "patch", "scale", "expose", "rollout", "debug", "label",
     "annotate", "set", "auth", "config", "proxy", "port-forward", "runp", "pods"}
)  # fmt: skip
_CONTAINER_CLIS = frozenset({"docker", "podman", "nerdctl", "kubectl", "crictl"})
#: Words that follow a program name in prose ("cmd.exe and then Word", "Bash script that").
_PROSE_WORDS = frozenset(
    {"and", "then", "the", "to", "a", "an", "that", "which", "is", "was", "from", "with", "for", "or", "in", "on", "as",
     "are", "itself", "script", "scripts", "command", "commands", "process", "window", "binary", "shell", "loader",
     "profiler", "tool", "tools", "awareness", "team", "teams", "operations", "center", "centre", "training",
     "executable", "executables", "utility", "utilities"}
)  # fmt: skip
#: A token shaped like a command-line argument.
_ARGUMENT_SHAPE_RE = re.compile(r"^[-+/.~$\"'%\\]|[./:=\\]|[a-z][A-Z]|\d")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


@dataclass
class ObservedCommand:
    program: str
    platform: str
    argument: str
    command: str
    passage: str
    level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _program_re(programs: Sequence[str]) -> re.Pattern:
    names = "|".join(sorted((re.escape(p) for p in programs), key=len, reverse=True))
    return re.compile(rf"(?:(?<=\s)|^|(?<=[(`'\"]))(?:[\w./\\-]*[/\\])?(?P<prog>{names})(?:\.exe)?(?=\s)", re.IGNORECASE)


def _distinctive(tokens: List[str], program: str = "") -> Optional[str]:
    """The first argument that says what the command does: not a flag, placeholder or bare number."""
    if program in ("bpftool", "kubectl", "crictl", "docker", "podman", "nerdctl", "rclone", "svchost_sync"):
        clean = [t.strip("\"'`,);") for t in tokens if t and not _PLACEHOLDER_RE.search(t)]
        if len(clean) >= 2 and not clean[0].startswith("-") and not clean[1].startswith("-"):
            return f"{clean[0]} {clean[1]}"
    if program == "nsenter":
        for tok in tokens:
            cleaned_tok = tok.strip("\"'`,);")
            if cleaned_tok.startswith(("/", "\\")) or "sh" in cleaned_tok:
                return cleaned_tok
        return "--target"
    if program == "schtasks":
        for i, tok in enumerate(tokens):
            if tok.lower() in ("/tn", "-tn") and i + 1 < len(tokens):
                name = tokens[i + 1].strip("\"'`,").rstrip(";)")
                if name and not _PLACEHOLDER_RE.search(name) and len(name) >= 3:
                    return name
        for i, tok in enumerate(tokens):
            if tok.lower() in ("/tr", "-tr") and i + 1 < len(tokens):
                target = tokens[i + 1].strip("\"'`,").rstrip(";)")
                if target and not _PLACEHOLDER_RE.search(target) and len(target) >= 3:
                    return target
    flag = ""
    for token in tokens:
        token = token.strip("\"'`,").rstrip(";)")
        if not token or _PLACEHOLDER_RE.search(token):
            flag = ""
            continue
        if token.startswith(("-", "+")) or (token.startswith("/") and len(token) <= 3):
            flag = token
            continue
        stripped = _VARIABLE_PREFIX_RE.sub("", token)
        if len(stripped) < 4 or stripped.isdigit():
            flag = ""
            continue
        # Keep the flag in front of the argument when it is a short option ("-d com.apple.quarantine"),
        # but not across a stripped variable: "mkdir -p $HOME/Library/x" runs as "-p /Users/me/Library/x",
        # so "-p /Library/x" never occurs.
        return f"{flag} {stripped}" if flag and len(flag) <= 3 and stripped == token else stripped
    return None


def _command_sentences(text: str) -> List[str]:
    """Sentences with the text's own spacing: page extraction breaks lines inside commands, and
    the technique joiner's punctuation tidy-up turns "bash .UlaccK" into "bash.UlaccK"."""
    lines = []
    for line in refang(text or "").splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        if (
            trimmed.startswith(("-", "*", "•"))
            or trimmed.startswith("#")
            or trimmed.startswith("```")
            or trimmed.endswith("```")
        ):
            lines.append(". " + trimmed.strip("-*•# `\t") + " .")
        else:
            lines.append(trimmed)
    joined = re.sub(r"\s+", " ", " ".join(lines))
    return [s.strip(" .") for s in _SENTENCE_RE.split(joined) if s.strip(" .")]


def _command_shaped(program: str, written: str, tokens: List[str], platform: str = "unix") -> bool:
    """Whether a program name starts a command rather than a sentence about the program."""
    if not tokens:
        return False
    if platform == "unix" and written != written.lower():
        return False  # on Unix, commands are quoted as typed; "Bash script" is prose
    first = tokens[0].strip("\"'`,").rstrip(".;:!?)")
    if first.lower() in _PROSE_WORDS:
        return False
    if program in _CONTAINER_CLIS and first.isalpha() and first.lower() not in _CONTAINER_SUBCOMMANDS:
        return False
    return bool(_ARGUMENT_SHAPE_RE.search(first)) or (program in _SUBCOMMANDS and first.isalpha() and first.islower())


def observed_commands(
    text: str,
    platforms: Sequence[str] = (),
    limit: int = 10,
    primary_actor: Optional[str] = None,
) -> List[ObservedCommand]:
    """Commands of known programs in the observed sentences of ``text``, one per program and argument."""
    wanted = {p.lower() for p in platforms}
    has_linux_markers = bool(LINUX_MARKERS.search(text))
    catalogs: List[Tuple[str, Dict[str, str]]] = []
    if not wanted or wanted & {"macos", "linux", "containers"} or has_linux_markers:
        catalogs.append(("unix", _UNIX))
    if not wanted or "windows" in wanted:
        catalogs.append(("windows", _WINDOWS))
    found: List[ObservedCommand] = []
    seen: set = set()
    actor_material = actor_material_report(text)
    if not primary_actor:
        from hecate_agent.core.technique_evidence import extract_primary_actor

        primary_actor = extract_primary_actor(text)
    for sentence in _command_sentences(text):
        if sentence_status(sentence, actor_material, primary_actor=primary_actor) != "observed":
            continue
        for platform, catalog in catalogs:
            for match in _program_re(list(catalog)).finditer(sentence):
                if platform == "windows" and match.group(0).startswith("/"):
                    continue
                program = match.group("prog").lower()
                rest = sentence[match.end() :].split()
                tokens: List[str] = []
                for token in rest[:12]:
                    if _STOP_RE.search(token):
                        break
                    tokens.append(token)
                if not _command_shaped(program, match.group("prog"), tokens, platform):
                    continue
                argument = _distinctive(tokens, program)
                if not argument or (program, argument.lower()) in seen:
                    continue
                command = " ".join([match.group("prog"), *tokens])[:200]
                if _LAB_HARNESS_RE.search(command) or _LAB_HARNESS_RE.search(argument):
                    continue
                seen.add((program, argument.lower()))
                found.append(ObservedCommand(program, platform, argument, command, sentence[:300], catalog[program]))
    # Specific commands first; discovery and file utilities fill what room is left.
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(found, key=lambda c: rank.get(c.level, 3))[:limit]


#: A download tool's output option and its value: the part of the command that says it saves what it fetches.
_OUTPUT_OPTION_RE = re.compile(r"\s-[oO]\s*\S+")


def _own_text(cmd: ObservedCommand) -> str:
    """The words that are this command's alone, for judging what behaviour it shows.

    ``command`` runs on into whatever followed it in a quoted block ("chmod +x
    /tmp/.xmrig rm -rf /tmp/x.tgz ..."), so the program and the argument the
    rule matches are the safe reading. A download keeps its output option:
    "curl <url> -o <file>" is a transfer, "curl <url>" alone need not be.
    """
    if cmd.program in ("curl", "wget", "curl.exe"):
        output = _OUTPUT_OPTION_RE.search(cmd.command)
        if output:
            return cmd.command[: output.end()]
    return f"{cmd.program} {cmd.argument}"


def command_candidates(text: str, platforms: Sequence[str] = (), primary_actor: Optional[str] = None) -> List[Dict[str, Any]]:
    """Sigma candidates (category, title, detection, level, command, passage) for the observed commands."""
    out: List[Dict[str, Any]] = []
    for cmd in observed_commands(text, platforms, primary_actor=primary_actor):
        arg = (cmd.argument or "").strip()
        if not arg or _PLACEHOLDER_RE.search(arg) or _LAB_HARNESS_RE.search(arg) or _LAB_HARNESS_RE.search(cmd.command):
            continue
        image = f"/{cmd.program}" if cmd.platform == "unix" else f"\\{cmd.program.removesuffix('.exe')}.exe"
        selection: Dict[str, Any] = {"Image|endswith": image, "CommandLine|contains": cmd.argument}
        if cmd.program == "schtasks":
            action = re.search(r"(?i)(?:^|\s)(/(?:create|change|delete|query|run|end))\b", cmd.command)
            if action:
                selection.pop("CommandLine|contains")
                selection["CommandLine|contains|all"] = [action.group(1).lower(), cmd.argument]
        out.append(
            {
                "category": "process_creation",
                "platform": cmd.platform,
                "title": f"{cmd.program} {cmd.argument}"[:100],
                "detection": {
                    "selection": selection,
                    "condition": "selection",
                },
                "level": cmd.level,
                "command": cmd.command,
                "behaviour": _own_text(cmd),
                "passage": cmd.passage,
            }
        )
        if (
            cmd.program == "schtasks"
            and "/create" in cmd.command.lower()
            and cmd.argument
            and not cmd.argument.startswith("/")
        ):
            out.append(
                {
                    "category": "file_event",
                    "title": f"Scheduled task created on disk: {cmd.argument}"[:100],
                    "detection": {
                        "selection": {"TargetFilename|contains": f"\\Tasks\\{cmd.argument}"},
                        "condition": "selection",
                    },
                    "level": cmd.level,
                    "command": cmd.command,
                    "behaviour": f"scheduled task file {cmd.argument}",
                    "passage": cmd.passage,
                }
            )
    return out


#: Headings of a tool README's sections about operating the tool: building its
#: lab, installing it, running its scanner or exploit, its file list, a capture
#: of a test run. What they show happens on the tester's machine.
_TOOLING_HEADINGS = (
    r"usage|lab( setup)?|setup|install(ation|ing)?|build(ing)?|requirements|prerequisites|dependencies"
    r"|quick ?start|getting started|how to (run|use)|running|run|demo|tests?|testing|verif(y|ication)"
    r"|check|scan(ner|ning)?|exploit|exploitation steps|teardown|clean ?up|files|repository structure"
    r"|disclaimer|pcap|capture"
)
_TOOLING_HEADING_RE = re.compile(rf"^({_TOOLING_HEADINGS})\s*:?\s*$", re.IGNORECASE)
#: Those, and the sections for defenders: their commands patch, harden or test a rule.
_OPERATOR_HEADING_RE = re.compile(
    rf"^({_TOOLING_HEADINGS}|mitigations?|remediation|workarounds?|hardening|fix(es)?|patch(es|ing)?"
    r"|detection( rules)?|detections|references)\s*:?\s*$",
    re.IGNORECASE,
)
_MD_HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")


def _without_sections(markdown: str, headings: "re.Pattern[str]") -> str:
    """``markdown`` without the sections whose heading matches ``headings``.

    A section ends at the next heading of its level or above; ``# ...`` inside
    a code block is a shell comment, not a heading.
    """
    kept: List[str] = []
    skipping_at = 0
    in_code = False
    for line in (markdown or "").splitlines():
        stripped = line.strip()
        heading = None if in_code else _MD_HEADING_RE.match(stripped)
        if stripped.startswith("```"):
            in_code = not in_code
        if heading:
            level = len(heading["marks"])
            if skipping_at and level > skipping_at:
                continue
            title = re.sub(r"[`*_]|\(.*?\)", "", heading["title"]).strip()
            skipping_at = level if headings.match(title) else 0
        if not skipping_at:
            kept.append(line)
    return "\n".join(kept)


def without_operator_sections(markdown: str) -> str:
    """A tool README without the sections whose commands run on the tester's or defender's machine.

    A PoC repository's README is written for the person running it: "### Lab
    setup" builds the target, "### Exploit" fires ``python3 poc.py`` at it,
    "### Verify" repeats that. H-0018 made a process rule of each, ``python3
    setup.py`` included. What the README says happens on the target ("The
    Bug", "The Proof") is kept.
    """
    return _without_sections(markdown, _OPERATOR_HEADING_RE)


def without_tooling_sections(markdown: str) -> str:
    """A tool README without its usage, lab, file-list and capture sections; its detection advice stays.

    H-0018 drafted rules for the PoC's own ``poc.py`` and for the
    ``/tmp/suricata-test/fast.log`` its author's IDS test wrote.
    """
    return _without_sections(markdown, _TOOLING_HEADING_RE)
