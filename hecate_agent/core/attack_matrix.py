"""MITRE ATT&CK Matrix reference data with optional STIX integration.

This module provides ATT&CK tactic and technique data through a provider
abstraction. When mitreattack-python is installed, it uses live STIX data
(835+ techniques with full metadata). Otherwise, it falls back to a
hardcoded dictionary of 14 tactics with approximate counts.

Backward compatible: ATTACK_TACTICS, TOTAL_TECHNIQUES, and all existing
functions continue to work identically via module-level __getattr__.
"""

import json
import logging
import os
import re
import sqlite3
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class TacticInfo(TypedDict):
    """Type definition for tactic information."""

    name: str
    technique_count: int
    order: int


class TechniqueInfo(TypedDict, total=False):
    """Type definition for technique metadata from STIX data."""

    id: str
    name: str
    description: str
    platforms: List[str]
    data_sources: List[str]
    tactic_shortnames: List[str]
    is_subtechnique: bool
    parent_id: Optional[str]
    url: str


class GroupSoftwareInfo(TypedDict, total=False):
    """Type definition for software/tool/malware associated with an adversary group."""

    id: str
    name: str
    type: str  # "tool", "malware", or "software"
    description: str


class GroupTechniqueInfo(TypedDict, total=False):
    """Type definition for a technique used by an adversary group."""

    id: str
    name: str


class GroupInfo(TypedDict, total=False):
    """Type definition for adversary threat actor group profile from STIX data."""

    id: str
    name: str
    aliases: List[str]
    description: str
    url: str
    techniques: List[GroupTechniqueInfo]
    software: List[GroupSoftwareInfo]


# ---------------------------------------------------------------------------
# Fallback data (MITRE ATT&CK Enterprise Matrix v19, current as of this file)
# ---------------------------------------------------------------------------
#
# Keep this vocabulary in step with the STIX bundle `attack update` downloads.
# When the two disagree a hunt is valid or invalid depending on whether the
# machine happens to have STIX installed: drafts written on a workstation with
# live data failed CI, which has none. Tactic *renames* are absorbed by
# _TACTIC_RENAMES below rather than by holding this table back.
#
# technique_count is parent techniques only, excluding sub-techniques, which is
# what the v14 table it replaced counted.

_FALLBACK_TACTICS: Dict[str, TacticInfo] = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "technique_count": 12,
        "order": 1,
    },
    "resource-development": {
        "name": "Resource Development",
        "technique_count": 9,
        "order": 2,
    },
    "initial-access": {
        "name": "Initial Access",
        "technique_count": 11,
        "order": 3,
    },
    "execution": {
        "name": "Execution",
        "technique_count": 20,
        "order": 4,
    },
    "persistence": {
        "name": "Persistence",
        "technique_count": 22,
        "order": 5,
    },
    "privilege-escalation": {
        "name": "Privilege Escalation",
        "technique_count": 13,
        "order": 6,
    },
    "stealth": {
        "name": "Stealth",
        "technique_count": 30,
        "order": 7,
    },
    "defense-impairment": {
        "name": "Defense Impairment",
        "technique_count": 18,
        "order": 8,
    },
    "credential-access": {
        "name": "Credential Access",
        "technique_count": 17,
        "order": 9,
    },
    "discovery": {
        "name": "Discovery",
        "technique_count": 34,
        "order": 10,
    },
    "lateral-movement": {
        "name": "Lateral Movement",
        "technique_count": 9,
        "order": 11,
    },
    "collection": {
        "name": "Collection",
        "technique_count": 17,
        "order": 12,
    },
    "command-and-control": {
        "name": "Command and Control",
        "technique_count": 18,
        "order": 13,
    },
    "exfiltration": {
        "name": "Exfiltration",
        "technique_count": 9,
        "order": 14,
    },
    "impact": {
        "name": "Impact",
        "technique_count": 15,
        "order": 15,
    },
}


#: Tactic shortnames ATT&CK has renamed, mapped old -> current. v18 renamed
#: TA0005 "Defense Evasion" to "Stealth" and split the impair/disable behaviors
#: out into TA0112 "Defense Impairment". Hunts, docs and Sigma tags written
#: against the old vocabulary are still describing a real tactic, so callers
#: translate before rejecting -- the same courtesy get_superseding_technique_id()
#: extends to revoked technique IDs.
_TACTIC_RENAMES: Dict[str, str] = {
    "defense-evasion": "stealth",
}

_FALLBACK_GROUPS: List[GroupInfo] = [
    {
        "id": "G0016",
        "name": "APT29",
        "aliases": [
            "APT29",
            "Cozy Bear",
            "Midnight Blizzard",
            "NOBELIUM",
            "UNC2452",
            "Dark Halo",
            "The Dukes",
            "IRON RITUAL",
        ],
        "description": (
            "APT29 is a threat group that has been attributed to Russia's"
            " Foreign Intelligence Service (SVR). They have conducted cyber"
            " espionage campaigns against government, think-tank, and"
            " technology organizations, including the SolarWinds supply chain"
            " compromise and OAuth token abuse against cloud services."
        ),
        "url": "https://attack.mitre.org/groups/G0016",
        "techniques": [
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1098", "name": "Account Manipulation"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1588", "name": "Obtain Capabilities"},
        ],
        "software": [
            {
                "id": "S0684",
                "name": "ROADTools",
                "type": "tool",
                "description": "Azure AD / Entra ID exploration toolkit.",
            },
            {
                "id": "S0514",
                "name": "WellMess",
                "type": "malware",
                "description": "Golang/.NET RAT used for command execution.",
            },
            {
                "id": "S0584",
                "name": "GoldMax",
                "type": "malware",
                "description": "Second-stage C2 backdoor.",
            },
        ],
    },
    {
        "id": "G0007",
        "name": "APT28",
        "aliases": [
            "APT28",
            "Fancy Bear",
            "Strontium",
            "Sednit",
            "Sofacy",
            "Pawn Storm",
            "T-APT-07",
        ],
        "description": (
            "APT28 is a threat group that has been attributed to Russia's"
            " General Staff Main Intelligence Directorate (GRU) 85th Main"
            " Special Service Center (GTsSS). Active since at least 2004."
        ),
        "url": "https://attack.mitre.org/groups/G0007",
        "techniques": [
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1003", "name": "OS Credential Dumping"},
            {"id": "T1021", "name": "Remote Services"},
        ],
        "software": [
            {
                "id": "S0023",
                "name": "CHOPSTICK",
                "type": "malware",
                "description": "Modular backdoor.",
            },
            {
                "id": "S0148",
                "name": "Zebrocy",
                "type": "malware",
                "description": "Trojan used to download payloads.",
            },
        ],
    },
    {
        "id": "G0034",
        "name": "Sandworm Team",
        "aliases": [
            "Sandworm Team",
            "TeleBots",
            "Voodoo Bear",
            "BlackEnergy Group",
            "ELECTRUM",
            "UAC-0082",
            "FROZENBARENTS",
        ],
        "description": (
            "Sandworm Team is a Russian military cyber operations unit (GRU"
            " Unit 74455). Responsible for attacks against Ukrainian electrical"
            " substations, NotPetya, and industrial SCADA/OT disruptions."
        ),
        "url": "https://attack.mitre.org/groups/G0034",
        "techniques": [
            {"id": "T1485", "name": "Data Destruction"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1562", "name": "Impair Defenses"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
        ],
        "software": [
            {
                "id": "S0089",
                "name": "BlackEnergy",
                "type": "malware",
                "description": "Modular malware targeting ICS/SCADA.",
            },
            {
                "id": "S0688",
                "name": "CaddyWiper",
                "type": "malware",
                "description": "Destructive wiper.",
            },
            {
                "id": "S0176",
                "name": "Industroyer",
                "type": "malware",
                "description": "Malware targeting electric substations.",
            },
        ],
    },
    {
        "id": "G0096",
        "name": "APT41",
        "aliases": [
            "APT41",
            "Double Dragon",
            "Wicked Panda",
            "BARIUM",
            "Brass Typhoon",
        ],
        "description": (
            "APT41 is a prolific state-sponsored cyber espionage group based"
            " in China that also conducts financially motivated operations."
        ),
        "url": "https://attack.mitre.org/groups/G0096",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1505", "name": "Server Software Component"},
            {"id": "T1055", "name": "Process Injection"},
        ],
        "software": [
            {
                "id": "S0154",
                "name": "Cobalt Strike",
                "type": "tool",
                "description": "Penetration testing and adversary simulation.",
            },
            {
                "id": "S0013",
                "name": "PlugX",
                "type": "malware",
                "description": "Modular remote access tool.",
            },
            {
                "id": "S0537",
                "name": "ShadowPad",
                "type": "malware",
                "description": "Modular backdoor.",
            },
        ],
    },
    {
        "id": "G0061",
        "name": "FIN8",
        "aliases": ["FIN8", "Sentry Whirlpool", "ATK 113"],
        "description": (
            "FIN8 is a financially motivated cybercrime group known for"
            " targeting retail, restaurant, and hospitality sectors using"
            " POS-scraping malware and BYOVD driver exploits."
        ),
        "url": "https://attack.mitre.org/groups/G0061",
        "techniques": [
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1562", "name": "Impair Defenses"},
        ],
        "software": [
            {
                "id": "S0616",
                "name": "Sardonic",
                "type": "malware",
                "description": "C++ backdoor used for staging.",
            },
            {
                "id": "S0197",
                "name": "PUNCHTRACK",
                "type": "malware",
                "description": "POS memory scraper.",
            },
        ],
    },
    {
        "id": "G0050",
        "name": "Carbanak",
        "aliases": ["Carbanak", "Anunak"],
        "description": (
            "Carbanak is a threat group that has targeted financial"
            " institutions across the globe, stealing hundreds of millions"
            " of dollars."
        ),
        "url": "https://attack.mitre.org/groups/G0050",
        "techniques": [
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1055", "name": "Process Injection"},
            {"id": "T1003", "name": "OS Credential Dumping"},
        ],
        "software": [
            {
                "id": "S0030",
                "name": "Carbanak",
                "type": "malware",
                "description": "Backdoor targeting financial networks.",
            }
        ],
    },
    {
        "id": "G0032",
        "name": "Lazarus Group",
        "aliases": [
            "Lazarus Group",
            "HIDDEN COBRA",
            "Guardians of Peace",
            "Zinc",
            "Diamond Sleet",
        ],
        "description": (
            "Lazarus Group is a North Korean state-sponsored cyber group"
            " attributed to the Reconnaissance General Bureau (RGB)."
        ),
        "url": "https://attack.mitre.org/groups/G0032",
        "techniques": [
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1204", "name": "User Execution"},
            {"id": "T1055", "name": "Process Injection"},
        ],
        "software": [
            {
                "id": "S0045",
                "name": "Brambul",
                "type": "malware",
                "description": "SMB brute-force worm.",
            },
            {
                "id": "S0151",
                "name": "Fallchill",
                "type": "malware",
                "description": "Command and control RAT.",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Provider abstraction & Deprecated Technique Mappings
# ---------------------------------------------------------------------------

#: Well-known legacy / deprecated ATT&CK techniques replaced in ATT&CK v7+
#: whose STIX entries were marked deprecated rather than revoked-by.
_DEPRECATED_TECHNIQUE_MAP: Dict[str, str] = {
    "T1064": "T1059",      # Scripting -> Command and Scripting Interpreter
    "T1086": "T1059.001",  # PowerShell -> Command and Scripting Interpreter: PowerShell
    "T1067": "T1542.003",  # Bootkit -> Firmware Corruption: Bootkit
    "T1093": "T1055.012",  # Process Hollowing -> Process Injection: Process Hollowing
    "T1175": "T1021.003",  # Component Object Model and Distributed COM -> Remote Services: Distributed COM
    "T1076": "T1021.001",  # Remote Desktop Protocol -> Remote Services: Remote Desktop Protocol
    "T1077": "T1021.002",  # Windows Admin Shares -> Remote Services: SMB/Windows Admin Shares
}


class AttackDataProvider(ABC):
    """Abstract base class for ATT&CK data providers."""

    @abstractmethod
    def get_tactics(self) -> Dict[str, TacticInfo]:
        """Return all tactics as {shortname: TacticInfo}."""

    @abstractmethod
    def get_total_techniques(self) -> int:
        """Return the total number of techniques across all tactics."""

    @abstractmethod
    def get_sorted_tactic_keys(self) -> List[str]:
        """Return tactic keys sorted by ATT&CK matrix order."""

    @abstractmethod
    def get_technique_by_id(self, technique_id: str) -> Optional[TechniqueInfo]:
        """Look up a technique by its ATT&CK ID (e.g., 'T1003.001')."""

    @abstractmethod
    def get_techniques_for_tactic(self, tactic_key: str) -> List[TechniqueInfo]:
        """Return all techniques mapped to a given tactic."""

    @abstractmethod
    def get_sub_techniques(self, parent_id: str) -> List[TechniqueInfo]:
        """Return sub-techniques for a parent technique ID (e.g., 'T1003')."""

    @abstractmethod
    def get_groups(self) -> List[GroupInfo]:
        """Return all known threat actor groups."""

    @abstractmethod
    def get_group_by_id(self, group_id: str) -> Optional[GroupInfo]:
        """Look up a threat actor group by ATT&CK ID (e.g. 'G0016')."""

    @abstractmethod
    def find_group(self, name_or_alias: str) -> Optional[GroupInfo]:
        """Find a threat actor group by name or alias (case-insensitive)."""

    @abstractmethod
    def get_version(self) -> str:
        """Return the ATT&CK version string."""

    @abstractmethod
    def is_stix(self) -> bool:
        """Return True if backed by live STIX data."""

    def get_superseding_technique_id(self, technique_id: str) -> Optional[str]:
        """Return the current ATT&CK ID that replaced a revoked or deprecated one.

        Deliberately concrete rather than abstract: resolving this needs
        ATT&CK's revoked-by relationship or deprecated mappings.
        """
        return _DEPRECATED_TECHNIQUE_MAP.get(technique_id.upper())


# ---------------------------------------------------------------------------
# Fallback provider (hardcoded data)
# ---------------------------------------------------------------------------


class FallbackProvider(AttackDataProvider):
    """Provider backed by the hardcoded v14 tactic dictionary."""

    def get_tactics(self) -> Dict[str, TacticInfo]:
        return _FALLBACK_TACTICS

    def get_total_techniques(self) -> int:
        return sum(t["technique_count"] for t in _FALLBACK_TACTICS.values())

    def get_sorted_tactic_keys(self) -> List[str]:
        return sorted(_FALLBACK_TACTICS.keys(), key=lambda k: _FALLBACK_TACTICS[k]["order"])

    def get_technique_by_id(self, technique_id: str) -> Optional[TechniqueInfo]:
        return None

    def get_techniques_for_tactic(self, tactic_key: str) -> List[TechniqueInfo]:
        return []

    def get_sub_techniques(self, parent_id: str) -> List[TechniqueInfo]:
        return []

    def get_groups(self) -> List[GroupInfo]:
        return list(_FALLBACK_GROUPS)

    def get_group_by_id(self, group_id: str) -> Optional[GroupInfo]:
        gid = group_id.strip().upper()
        for g in _FALLBACK_GROUPS:
            if g["id"].upper() == gid:
                return g
        return None

    def find_group(self, name_or_alias: str) -> Optional[GroupInfo]:
        target = name_or_alias.strip().lower()
        for g in _FALLBACK_GROUPS:
            if g["name"].lower() == target:
                return g
            for a in g.get("aliases", []):
                if a.lower() == target:
                    return g
        return None

    def get_version(self) -> str:
        return "v14 (hardcoded fallback)"

    def is_stix(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# STIX provider (mitreattack-python)
# ---------------------------------------------------------------------------


def _get_stix_cache_dir() -> Path:
    """Return the STIX data cache directory.

    Checks (in order):
    1. HECATE_STIX_CACHE env var
    2. {workspace}/.hecate/stix-data/ if .hecateconfig.yaml exists
    3. ~/.hecate/stix-data/ (global default)
    """
    env_path = os.environ.get("HECATE_STIX_CACHE")
    if env_path:
        return Path(env_path)

    # Workspace-local cache. HECATE_WORKSPACE is the workspace a caller has
    # explicitly declared; cwd is the fallback for interactive use from inside
    # a workspace. They usually coincide -- but a caller that sets
    # HECATE_WORKSPACE and runs from a different directory silently got the wrong
    # cache directory, even though this docstring has always said "{workspace}".
    workspace_env = os.environ.get("HECATE_WORKSPACE")
    workspace = Path(workspace_env) if workspace_env else Path.cwd()
    if (workspace / ".hecateconfig.yaml").exists():
        return workspace / ".hecate" / "stix-data"

    # Global default
    return Path.home() / ".hecate" / "stix-data"


def _get_stix_file_path() -> Path:
    """Return the canonical path for the STIX JSON file.

    This is the *write* location -- where ``hecate-agent attack update`` downloads
    to. Readers should use :func:`_resolve_stix_file`, which falls back to
    the global cache when a workspace has no copy of its own.
    """
    return _get_stix_cache_dir() / "enterprise-attack.json"


def _resolve_stix_file() -> Path:
    """Return the STIX JSON file to *read*, honouring the documented order.

    ``_get_stix_cache_dir`` returns the workspace-local directory whenever a
    .hecateconfig.yaml is present, without checking that a STIX file is
    actually there. A workspace that had a config but no STIX copy of its own
    therefore reported "stix_unavailable" even with a perfectly good global
    cache on disk -- which silently degraded every ``attack lookup`` to empty
    metadata (no tactics, no platforms, no validation of technique IDs) with
    nothing logged. Fall through to the global cache instead, which is what
    _get_stix_cache_dir's own "checks in order" docstring already promises.
    """
    preferred = _get_stix_file_path()
    if preferred.exists():
        return preferred

    fallback = Path.home() / ".hecate" / "stix-data" / "enterprise-attack.json"
    if fallback.exists():
        logger.debug("No STIX data at %s; using global cache %s", preferred, fallback)
        return fallback

    return preferred


def _extract_attack_id(stix_obj: Any) -> str:
    """Return a STIX object's ATT&CK ID (e.g. 'T1055.012'), or '' if absent."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id", ""))
    return ""


def compile_stix_to_sqlite(stix_path: Path, sqlite_path: Optional[Path] = None) -> Path:
    """Compile a STIX enterprise-attack.json bundle into an indexed SQLite cache."""
    if sqlite_path is None:
        sqlite_path = stix_path.with_suffix(".sqlite3")

    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        dir=sqlite_path.parent,
        prefix=f".{sqlite_path.name}.",
        suffix=".tmp",
    )
    os.close(fd)
    temp_path = Path(temp_name)
    success = False

    conn = None
    try:
        from mitreattack.stix20 import MitreAttackData

        attack_data = MitreAttackData(str(stix_path))
        conn = sqlite3.connect(str(temp_path))
        with conn:
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute(
                "CREATE TABLE tactics (shortname TEXT PRIMARY KEY, name TEXT, technique_count INTEGER, sort_order INTEGER)"
            )
            conn.execute(
                """CREATE TABLE techniques (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    platforms TEXT,
                    data_sources TEXT,
                    tactic_shortnames TEXT,
                    is_subtechnique INTEGER,
                    parent_id TEXT,
                    url TEXT
                )"""
            )
            conn.execute("CREATE INDEX idx_techniques_parent ON techniques(parent_id)")
            conn.execute(
                "CREATE TABLE revoked_techniques (old_id TEXT PRIMARY KEY, new_id TEXT)"
            )
            conn.execute(
                """CREATE TABLE groups (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    aliases TEXT,
                    description TEXT,
                    url TEXT,
                    techniques TEXT,
                    software TEXT
                )"""
            )
            conn.execute(
                "CREATE TABLE group_aliases (alias_clean TEXT PRIMARY KEY, group_id TEXT)"
            )
            conn.execute("CREATE INDEX idx_group_aliases_group ON group_aliases(group_id)")

            # Meta version
            version = ""
            try:
                with open(str(stix_path), "r", encoding="utf-8") as f:
                    bundle = json.load(f)
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "x-mitre-collection":
                        v = obj.get("x_mitre_version", "")
                        if v:
                            version = f"v{v} (STIX)"
                            break
            except Exception:
                pass
            if not version:
                mtime = stix_path.stat().st_mtime
                age_days = int((time.time() - mtime) / 86400)
                version = f"STIX (downloaded {age_days}d ago)"
            conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("version", version))

            # Tactics
            order_map = {k: v["order"] for k, v in _FALLBACK_TACTICS.items()}
            stix_tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
            for st in stix_tactics:
                sname = st.get("x_mitre_shortname", "")
                if not sname:
                    continue
                techs = attack_data.get_techniques_by_tactic(
                    sname, "enterprise-attack", remove_revoked_deprecated=True
                )
                conn.execute(
                    "INSERT INTO tactics (shortname, name, technique_count, sort_order) VALUES (?, ?, ?, ?)",
                    (sname, st.get("name", ""), len(techs), order_map.get(sname, 99)),
                )

            # Techniques
            techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
            for tech in techniques:
                attack_id = ""
                url = ""
                for ref in tech.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break
                if not attack_id:
                    continue

                is_sub = 1 if tech.get("x_mitre_is_subtechnique", False) else 0
                parent_id = None
                if is_sub and "." in attack_id:
                    parent_id = attack_id.split(".")[0]

                tactic_shortnames = [
                    phase["phase_name"]
                    for phase in tech.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]
                data_sources = tech.get("x_mitre_data_sources", [])

                conn.execute(
                    """INSERT INTO techniques
                       (id, name, description, platforms, data_sources, tactic_shortnames, is_subtechnique, parent_id, url)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        attack_id,
                        tech.get("name", ""),
                        tech.get("description", ""),
                        json.dumps(tech.get("x_mitre_platforms", [])),
                        json.dumps(data_sources),
                        json.dumps(tactic_shortnames),
                        is_sub,
                        parent_id,
                        url,
                    ),
                )

            # Revoked relationships
            try:
                from stix2 import Filter

                relationships = attack_data.src.query(
                    [
                        Filter("type", "=", "relationship"),
                        Filter("relationship_type", "=", "revoked-by"),
                    ]
                )
                patterns = attack_data.get_objects_by_type(
                    "attack-pattern", remove_revoked_deprecated=False
                )
                by_stix_id = {obj["id"]: obj for obj in patterns}
                rev_index: Dict[str, str] = {}
                for rel in relationships:
                    revoked = by_stix_id.get(rel.get("source_ref"))
                    successor = by_stix_id.get(rel.get("target_ref"))
                    if revoked is None or successor is None:
                        continue
                    old_id = _extract_attack_id(revoked)
                    new_id = _extract_attack_id(successor)
                    if old_id and new_id:
                        rev_index[old_id] = new_id

                for old_id, first_hop in rev_index.items():
                    seen = {old_id}
                    target = first_hop
                    while target in rev_index and target not in seen:
                        seen.add(target)
                        target = rev_index[target]
                    if target in rev_index:
                        continue
                    conn.execute(
                        "INSERT OR REPLACE INTO revoked_techniques (old_id, new_id) VALUES (?, ?)",
                        (old_id, target),
                    )
            except Exception as e:
                logger.warning("Could not compile revoked relationships: %s", e)

            # Groups and software
            stix_groups = attack_data.get_groups(remove_revoked_deprecated=True)
            for sg in stix_groups:
                gid = _extract_attack_id(sg)
                if not gid:
                    continue
                gname = sg.get("name", "")
                aliases = list(sg.get("aliases", []))
                if gname and gname not in aliases:
                    aliases.insert(0, gname)

                gurl = ""
                for ref in sg.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        gurl = ref.get("url", "")
                        break

                stix_id = sg.get("id", "")
                g_techs: List[Dict[str, str]] = []
                seen_techs: Set[str] = set()
                if stix_id:
                    for entry in attack_data.get_techniques_used_by_group(stix_id):
                        t_obj = entry.get("object") if isinstance(entry, dict) else None
                        if t_obj:
                            tid = _extract_attack_id(t_obj)
                            if tid and tid not in seen_techs:
                                seen_techs.add(tid)
                                g_techs.append({"id": tid, "name": t_obj.get("name", "")})
                g_techs.sort(key=lambda t: t.get("id", ""))

                g_soft: List[Dict[str, str]] = []
                seen_soft: Set[str] = set()
                if stix_id:
                    for entry in attack_data.get_software_used_by_group(stix_id):
                        s_obj = entry.get("object") if isinstance(entry, dict) else None
                        if s_obj:
                            sid = _extract_attack_id(s_obj)
                            sname = s_obj.get("name", "")
                            if sid and sid not in seen_soft:
                                seen_soft.add(sid)
                                stype = s_obj.get("type", "software")
                                kind = "malware" if stype == "malware" else ("tool" if stype == "tool" else "software")
                                g_soft.append(
                                    {
                                        "id": sid,
                                        "name": sname,
                                        "type": kind,
                                        "description": s_obj.get("description", ""),
                                    }
                                )
                g_soft.sort(key=lambda s: s.get("name", ""))

                conn.execute(
                    """INSERT INTO groups (id, name, aliases, description, url, techniques, software)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        gid,
                        gname,
                        json.dumps(aliases),
                        sg.get("description", ""),
                        gurl,
                        json.dumps(g_techs),
                        json.dumps(g_soft),
                    ),
                )

                for alias in aliases:
                    clean = alias.strip().lower()
                    if clean:
                        conn.execute(
                            "INSERT OR REPLACE INTO group_aliases (alias_clean, group_id) VALUES (?, ?)",
                            (clean, gid),
                        )
        success = True
    finally:
        if conn is not None:
            conn.close()
        if success:
            temp_path.replace(sqlite_path)
        else:
            temp_path.unlink(missing_ok=True)

    return sqlite_path


class StixProvider(AttackDataProvider):
    """Provider backed by STIX data with SQLite indexing.

    Prefers compiled SQLite cache for sub-millisecond execution,
    falling back to mitreattack-python lazy loading if unavailable.
    """

    def __init__(self, stix_path: Optional[Path] = None):
        self._stix_path = stix_path or _get_stix_file_path()
        self._sqlite_path = self._stix_path.with_suffix(".sqlite3")
        self._attack_data: Any = None  # MitreAttackData instance
        self._tactics_cache: Optional[Dict[str, TacticInfo]] = None
        self._technique_cache: Optional[Dict[str, TechniqueInfo]] = None
        self._tactic_techniques_cache: Dict[str, List[TechniqueInfo]] = {}
        self._revoked_cache: Optional[Dict[str, str]] = None
        self._groups_cache: Optional[Dict[str, GroupInfo]] = None
        self._alias_to_group_id: Optional[Dict[str, str]] = None
        self._stix_groups_by_id: Optional[Dict[str, Any]] = None
        self._sqlite_loaded: bool = False
        self._version_str: Optional[str] = None

    def _load_from_sqlite(self, db_path: Path) -> None:
        """Hydrate provider caches instantly from compiled SQLite file."""
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT value FROM meta WHERE key = 'version'")
            row = cur.fetchone()
            self._version_str = row[0] if row else "STIX"

            cur.execute("SELECT shortname, name, technique_count, sort_order FROM tactics")
            tactics: Dict[str, TacticInfo] = {}
            for sname, name, count, order in cur.fetchall():
                tactics[sname] = TacticInfo(name=name, technique_count=count, order=order)
            self._tactics_cache = tactics

            cur.execute(
                "SELECT id, name, description, platforms, data_sources, tactic_shortnames, is_subtechnique, parent_id, url FROM techniques"
            )
            tech_index: Dict[str, TechniqueInfo] = {}
            for tid, tname, desc, plats, ds, tnames, is_sub, parent, url in cur.fetchall():
                tech_index[tid] = TechniqueInfo(
                    id=tid,
                    name=tname,
                    description=desc,
                    platforms=json.loads(plats) if plats else [],
                    data_sources=json.loads(ds) if ds else [],
                    tactic_shortnames=json.loads(tnames) if tnames else [],
                    is_subtechnique=bool(is_sub),
                    parent_id=parent,
                    url=url,
                )
            self._technique_cache = tech_index

            cur.execute("SELECT old_id, new_id FROM revoked_techniques")
            self._revoked_cache = dict(cur.fetchall())

            cur.execute("SELECT id, name, aliases, description, url, techniques, software FROM groups")
            groups: Dict[str, GroupInfo] = {}
            for gid, gname, aliases, desc, url, techs, soft in cur.fetchall():
                groups[gid] = GroupInfo(
                    id=gid,
                    name=gname,
                    aliases=json.loads(aliases) if aliases else [],
                    description=desc,
                    url=url,
                    techniques=json.loads(techs) if techs else [],
                    software=json.loads(soft) if soft else [],
                )
            self._groups_cache = groups

            cur.execute("SELECT alias_clean, group_id FROM group_aliases")
            self._alias_to_group_id = dict(cur.fetchall())

            self._sqlite_loaded = True
        finally:
            conn.close()

    def _ensure_loaded(self) -> None:
        """Lazily load STIX data on first access, preferring fast SQLite cache."""
        if self._attack_data is not None or self._sqlite_loaded:
            return

        if not self._stix_path.exists():
            raise FileNotFoundError(
                f"STIX data not found at {self._stix_path}. Run 'hecate-agent attack update' to download it."
            )

        if self._sqlite_path.exists() and self._sqlite_path.stat().st_mtime >= self._stix_path.stat().st_mtime:
            try:
                self._load_from_sqlite(self._sqlite_path)
                logger.debug("Loaded STIX data from SQLite cache %s", self._sqlite_path)
                return
            except Exception as exc:
                logger.warning("Failed to load STIX SQLite cache (%s); recompiling", exc)

        try:
            compile_stix_to_sqlite(self._stix_path, self._sqlite_path)
            self._load_from_sqlite(self._sqlite_path)
            logger.debug("Compiled and loaded STIX SQLite cache %s", self._sqlite_path)
            return
        except Exception as exc:
            logger.warning("Could not build STIX SQLite cache (%s); falling back to direct JSON", exc)

        from mitreattack.stix20 import MitreAttackData

        logger.debug("Loading STIX data from %s", self._stix_path)
        self._attack_data = MitreAttackData(str(self._stix_path))

    def _build_tactics(self) -> Dict[str, TacticInfo]:
        """Build tactic dictionary from STIX data."""
        self._ensure_loaded()
        if self._tactics_cache is not None:
            return self._tactics_cache

        tactics: Dict[str, TacticInfo] = {}
        stix_tactics = self._attack_data.get_tactics(remove_revoked_deprecated=True)

        # Kill-chain order, shared with the fallback table so both providers
        # agree. A tactic the table has not caught up with sorts last rather
        # than being dropped.
        order_map = {k: v["order"] for k, v in _FALLBACK_TACTICS.items()}

        for stix_tactic in stix_tactics:
            shortname = stix_tactic.get("x_mitre_shortname", "")
            if not shortname:
                continue

            # Count techniques for this tactic
            techniques = self._attack_data.get_techniques_by_tactic(
                shortname, "enterprise-attack", remove_revoked_deprecated=True
            )

            tactics[shortname] = TacticInfo(
                name=stix_tactic["name"],
                technique_count=len(techniques),
                order=order_map.get(shortname, 99),
            )

        return tactics

    def _build_technique_index(self) -> Dict[str, TechniqueInfo]:
        """Build technique lookup index from STIX data."""
        self._ensure_loaded()
        if self._technique_cache is not None:
            return self._technique_cache

        index: Dict[str, TechniqueInfo] = {}
        techniques = self._attack_data.get_techniques(remove_revoked_deprecated=True)

        for tech in techniques:
            ext_refs = tech.get("external_references", [])
            attack_id = ""
            url = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            if not attack_id:
                continue

            is_sub = tech.get("x_mitre_is_subtechnique", False)
            parent_id = None
            if is_sub and "." in attack_id:
                parent_id = attack_id.split(".")[0]

            # Extract tactic shortnames from kill chain phases
            tactic_shortnames: List[str] = []
            for phase in tech.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic_shortnames.append(phase["phase_name"])

            # Extract data sources
            data_sources: List[str] = tech.get("x_mitre_data_sources", [])

            index[attack_id] = TechniqueInfo(
                id=attack_id,
                name=tech.get("name", ""),
                description=tech.get("description", ""),
                platforms=tech.get("x_mitre_platforms", []),
                data_sources=data_sources if data_sources else [],
                tactic_shortnames=tactic_shortnames,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                url=url,
            )

        return index

    def get_tactics(self) -> Dict[str, TacticInfo]:
        if self._tactics_cache is None:
            self._tactics_cache = self._build_tactics()
        return self._tactics_cache

    def get_total_techniques(self) -> int:
        return sum(t["technique_count"] for t in self.get_tactics().values())

    def get_sorted_tactic_keys(self) -> List[str]:
        tactics = self.get_tactics()
        return sorted(tactics.keys(), key=lambda k: tactics[k]["order"])

    def _build_revoked_index(self) -> Dict[str, str]:
        """Map revoked ATT&CK technique IDs to the IDs that replaced them.

        Built separately from the main technique index, which is
        deliberately loaded with remove_revoked_deprecated=True so revoked
        techniques never inflate coverage counts or tactic listings. They're
        still worth *resolving*, though: an LLM trained on years of threat
        reporting routinely names a real behavior using its pre-subtechnique
        ID (T1093 for Process Hollowing, T1067 for Bootkit), and ATT&CK's
        own STIX ships the revoked-by relationship needed to translate that
        into the current ID rather than discarding a correct call.
        """
        self._ensure_loaded()
        if self._revoked_cache is not None:
            return self._revoked_cache

        # Queried as one bulk relationship lookup rather than a
        # get_revoking_object() call per revoked technique: that helper
        # rescans the whole store each time, which measured ~20s to build
        # this index versus ~0.2s here for identical output.
        from stix2 import Filter

        index: Dict[str, str] = {}
        try:
            relationships = self._attack_data.src.query(
                [
                    Filter("type", "=", "relationship"),
                    Filter("relationship_type", "=", "revoked-by"),
                ]
            )
            patterns = self._attack_data.get_objects_by_type("attack-pattern", remove_revoked_deprecated=False)
        except Exception:  # pragma: no cover - depends on mitreattack internals
            logger.warning(
                "Could not read ATT&CK revoked-by relationships; deprecated "
                "technique IDs will be reported as unknown instead of remapped.",
                exc_info=True,
            )
            return {}

        by_stix_id = {obj["id"]: obj for obj in patterns}
        for rel in relationships:
            revoked = by_stix_id.get(rel.get("source_ref"))
            successor = by_stix_id.get(rel.get("target_ref"))
            if revoked is None or successor is None:
                # revoked-by also covers groups/software/mitigations; only
                # technique-to-technique pairs belong in this index.
                continue
            old_id = _extract_attack_id(revoked)
            new_id = _extract_attack_id(successor)
            # A successor that is itself revoked (ATT&CK has chained a few
            # over the years) is resolved transitively below, once the whole
            # index is built -- following the chain here would depend on
            # dict insertion order.
            if old_id and new_id:
                index[old_id] = new_id

        # Collapse chains (A -> B -> C becomes A -> C) so a caller never has
        # to re-resolve, and drop any cycle rather than loop forever.
        resolved: Dict[str, str] = {}
        for old_id, first_hop in index.items():
            seen = {old_id}
            target = first_hop
            while target in index and target not in seen:
                seen.add(target)
                target = index[target]
            if target in index:
                # Loop exited because we came back around, not because we
                # reached a live technique -- no honest answer to give.
                continue
            resolved[old_id] = target
        return resolved

    def get_superseding_technique_id(self, technique_id: str) -> Optional[str]:
        if self._revoked_cache is None:
            self._revoked_cache = self._build_revoked_index()
        target = self._revoked_cache.get(technique_id.upper())
        if target:
            return target
        return _DEPRECATED_TECHNIQUE_MAP.get(technique_id.upper())

    def get_technique_by_id(self, technique_id: str) -> Optional[TechniqueInfo]:
        if self._technique_cache is None:
            self._technique_cache = self._build_technique_index()
        return self._technique_cache.get(technique_id.upper())

    def get_techniques_for_tactic(self, tactic_key: str) -> List[TechniqueInfo]:
        if tactic_key in self._tactic_techniques_cache:
            return self._tactic_techniques_cache[tactic_key]

        if self._technique_cache is None:
            self._technique_cache = self._build_technique_index()

        result = [t for t in self._technique_cache.values() if tactic_key in t.get("tactic_shortnames", [])]
        result.sort(key=lambda t: t.get("id", ""))
        self._tactic_techniques_cache[tactic_key] = result
        return result

    def get_sub_techniques(self, parent_id: str) -> List[TechniqueInfo]:
        if self._technique_cache is None:
            self._technique_cache = self._build_technique_index()

        parent = parent_id.upper()
        return sorted(
            [t for t in self._technique_cache.values() if t.get("parent_id") == parent],
            key=lambda t: t.get("id", ""),
        )

    def get_version(self) -> str:
        self._ensure_loaded()
        if self._sqlite_loaded and self._version_str:
            return self._version_str
        # Try to extract version from STIX bundle
        try:
            with open(str(self._stix_path), "r") as f:
                bundle = json.load(f)
            for obj in bundle.get("objects", []):
                if obj.get("type") == "x-mitre-collection":
                    version = obj.get("x_mitre_version", "")
                    if version:
                        return f"v{version} (STIX)"
        except Exception:
            pass

        # Fallback: use file modification time
        mtime = self._stix_path.stat().st_mtime
        age_days = int((time.time() - mtime) / 86400)
        return f"STIX (downloaded {age_days}d ago)"

    def _ensure_groups_loaded(self) -> None:
        """Lazily load threat actor groups from STIX data."""
        self._ensure_loaded()
        if self._groups_cache is not None:
            return

        stix_groups = self._attack_data.get_groups(remove_revoked_deprecated=True)
        groups_cache: Dict[str, GroupInfo] = {}
        alias_map: Dict[str, str] = {}
        stix_by_id: Dict[str, Any] = {}

        for sg in stix_groups:
            attack_id = _extract_attack_id(sg)
            if not attack_id:
                continue

            name = sg.get("name", "")
            aliases = list(sg.get("aliases", []))
            if name and name not in aliases:
                aliases.insert(0, name)

            url = ""
            for ref in sg.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    url = ref.get("url", "")
                    break

            group_info: GroupInfo = {
                "id": attack_id,
                "name": name,
                "aliases": aliases,
                "description": sg.get("description", ""),
                "url": url,
                "techniques": [],
                "software": [],
            }
            groups_cache[attack_id] = group_info
            stix_by_id[attack_id] = sg

            for alias in aliases:
                clean_alias = alias.strip().lower()
                if clean_alias:
                    alias_map[clean_alias] = attack_id

        self._groups_cache = groups_cache
        self._alias_to_group_id = alias_map
        self._stix_groups_by_id = stix_by_id

    def _populate_group_details(self, attack_id: str) -> Optional[GroupInfo]:
        """Populate techniques and software used by the group."""
        self._ensure_groups_loaded()
        assert self._groups_cache is not None
        group = self._groups_cache.get(attack_id)
        if group is None:
            return None
        if group.get("techniques") or group.get("software") or self._sqlite_loaded:
            return group

        assert self._stix_groups_by_id is not None

        sg = self._stix_groups_by_id.get(attack_id)
        if not sg:
            return group
        stix_id = sg.get("id")
        if not stix_id:
            return group

        raw_techs = self._attack_data.get_techniques_used_by_group(stix_id)
        techniques: List[GroupTechniqueInfo] = []
        seen_techs: Set[str] = set()
        for entry in raw_techs:
            t_obj = entry.get("object") if isinstance(entry, dict) else None
            if not t_obj:
                continue
            t_id = _extract_attack_id(t_obj)
            if t_id and t_id not in seen_techs:
                seen_techs.add(t_id)
                techniques.append(
                    {
                        "id": t_id,
                        "name": t_obj.get("name", ""),
                    }
                )
        techniques.sort(key=lambda t: t.get("id", ""))
        group["techniques"] = techniques

        raw_soft = self._attack_data.get_software_used_by_group(stix_id)
        software: List[GroupSoftwareInfo] = []
        seen_soft: Set[str] = set()
        for entry in raw_soft:
            s_obj = entry.get("object") if isinstance(entry, dict) else None
            if not s_obj:
                continue
            s_id = _extract_attack_id(s_obj)
            s_name = s_obj.get("name", "")
            if s_id and s_id not in seen_soft:
                seen_soft.add(s_id)
                s_type = s_obj.get("type", "software")
                kind = "malware" if s_type == "malware" else ("tool" if s_type == "tool" else "software")
                software.append(
                    {
                        "id": s_id,
                        "name": s_name,
                        "type": kind,
                        "description": s_obj.get("description", ""),
                    }
                )
        software.sort(key=lambda s: s.get("name", ""))
        group["software"] = software
        return group

    def get_groups(self) -> List[GroupInfo]:
        self._ensure_groups_loaded()
        assert self._groups_cache is not None
        return list(self._groups_cache.values())

    def get_group_by_id(self, group_id: str) -> Optional[GroupInfo]:
        self._ensure_groups_loaded()
        assert self._groups_cache is not None
        gid = group_id.strip().upper()
        if gid in self._groups_cache:
            return self._populate_group_details(gid)
        return None

    def find_group(self, name_or_alias: str) -> Optional[GroupInfo]:
        self._ensure_groups_loaded()
        assert self._alias_to_group_id is not None
        clean = name_or_alias.strip().lower()
        gid = self._alias_to_group_id.get(clean)
        if gid:
            return self.get_group_by_id(gid)
        return None

    def is_stix(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Provider singleton
# ---------------------------------------------------------------------------

_provider: Optional[AttackDataProvider] = None


def _get_provider() -> AttackDataProvider:
    """Get or create the singleton ATT&CK data provider.

    Auto-selects StixProvider if mitreattack-python is installed AND
    cached STIX data exists, otherwise falls back to FallbackProvider.
    """
    global _provider
    if _provider is not None:
        return _provider

    try:
        import mitreattack.stix20  # noqa: F401

        stix_path = _resolve_stix_file()
        if stix_path.exists():
            _provider = StixProvider(stix_path)
            logger.debug("Using STIX provider: %s", stix_path)
        else:
            logger.debug(
                "mitreattack-python installed but no STIX data at %s. "
                "Run 'hecate-agent attack update' to download. Using fallback.",
                stix_path,
            )
            _provider = FallbackProvider()
    except ImportError:
        logger.debug("mitreattack-python not installed. Using fallback provider.")
        _provider = FallbackProvider()

    return _provider


def reset_provider(provider: Optional[AttackDataProvider] = None) -> None:
    """Reset the provider singleton (for testing or after update).

    Args:
        provider: Optional specific provider to use. If None, auto-selects.
    """
    global _provider
    _provider = provider


# ---------------------------------------------------------------------------
# Original public API (backward compatible)
# ---------------------------------------------------------------------------


def get_tactic_display_name(tactic_key: str) -> str:
    """Get the display name for a tactic key.

    Args:
        tactic_key: Tactic key (e.g., "credential-access")

    Returns:
        Display name (e.g., "Credential Access")
    """
    tactic_key = canonical_tactic(tactic_key)
    tactics = _get_provider().get_tactics()
    if tactic_key in tactics:
        return tactics[tactic_key]["name"]
    return tactic_key.replace("-", " ").title()


def get_tactic_technique_count(tactic_key: str) -> int:
    """Get the total technique count for a tactic.

    Args:
        tactic_key: Tactic key (e.g., "credential-access")

    Returns:
        Total technique count for the tactic
    """
    tactic_key = canonical_tactic(tactic_key)
    tactics = _get_provider().get_tactics()
    if tactic_key in tactics:
        return tactics[tactic_key]["technique_count"]
    return 0


def get_sorted_tactics() -> List[str]:
    """Get all tactic keys sorted by ATT&CK matrix order.

    Returns:
        List of tactic keys in matrix order
    """
    return _get_provider().get_sorted_tactic_keys()


def get_total_techniques() -> int:
    """Get the total technique count across all tactics.

    Returns:
        Total technique count
    """
    return _get_provider().get_total_techniques()


# ---------------------------------------------------------------------------
# New public API
# ---------------------------------------------------------------------------


def get_technique(technique_id: str) -> Optional[TechniqueInfo]:
    """Look up a technique by ATT&CK ID.

    Args:
        technique_id: ATT&CK technique ID (e.g., "T1003.001")

    Returns:
        TechniqueInfo dict or None if not found / using fallback provider.
    """
    return _get_provider().get_technique_by_id(technique_id)


def canonical_tactic(tactic_key: str) -> str:
    """Return the current ATT&CK shortname for a possibly-renamed tactic.

    ATT&CK renames tactics as well as revoking technique IDs -- v18 turned
    TA0005 "Defense Evasion" into "Stealth". Content written against the old
    name still names a live tactic, so validation translates before rejecting.
    Unknown keys pass through untouched for the caller to reject.

    Args:
        tactic_key: Tactic shortname (e.g., "defense-evasion")

    Returns:
        The current shortname (e.g., "stealth"), or the input unchanged.
    """
    return _TACTIC_RENAMES.get(tactic_key, tactic_key)


def get_superseding_technique_id(technique_id: str) -> Optional[str]:
    """Return the current ATT&CK ID that replaced a revoked technique ID.

    ATT&CK revokes IDs when it restructures (T1093 "Process Hollowing"
    became sub-technique T1055.012; T1067 "Bootkit" became T1542.003).
    Threat reporting written before a restructure -- and models trained on
    it -- still cite the old ID for a behavior that is otherwise named
    correctly, so callers validating IDs should offer this translation
    before rejecting one as unknown.

    Args:
        technique_id: Possibly-revoked ATT&CK technique ID (e.g., "T1093")

    Returns:
        The replacement ID (e.g., "T1055.012"), or None when the ID isn't
        revoked, has no recorded successor, or STIX data isn't installed.
    """
    return _get_provider().get_superseding_technique_id(technique_id)


def get_techniques_for_tactic(tactic_key: str) -> List[TechniqueInfo]:
    """Get all techniques mapped to a tactic.

    Args:
        tactic_key: Tactic shortname (e.g., "credential-access")

    Returns:
        List of TechniqueInfo dicts. Empty if using fallback provider.
    """
    return _get_provider().get_techniques_for_tactic(canonical_tactic(tactic_key))


def get_sub_techniques(parent_id: str) -> List[TechniqueInfo]:
    """Get sub-techniques for a parent technique.

    Args:
        parent_id: Parent technique ID (e.g., "T1003")

    Returns:
        List of TechniqueInfo dicts. Empty if using fallback provider.
    """
    return _get_provider().get_sub_techniques(parent_id)


def get_attack_version() -> str:
    """Get the ATT&CK data version string."""
    return _get_provider().get_version()


def is_using_stix() -> bool:
    """Check if using live STIX data."""
    return _get_provider().is_stix()


_EXCLUDED_ALIAS_WORDS = {
    "team",
    "group",
    "threat",
    "spider",
    "bear",
    "chollima",
    "temp",
    "iron",
    "sand",
    "gang",
    "dukes",
    "kitsune",
    "storm",
    "tempest",
    "halo",
    "noble",
    "laser",
    "kitten",
    "typhoon",
    "blizzard",
    "sleet",
    "cyber",
}


def get_groups() -> List[GroupInfo]:
    """Get all known threat actor groups."""
    return _get_provider().get_groups()


def get_group(group_id: str) -> Optional[GroupInfo]:
    """Look up a threat actor group by ATT&CK ID (e.g., 'G0016')."""
    return _get_provider().get_group_by_id(group_id)


def find_group(name_or_alias: str) -> Optional[GroupInfo]:
    """Find a threat actor group by name or alias (case-insensitive)."""
    return _get_provider().find_group(name_or_alias)


def search_groups_in_text(text: str) -> List[GroupInfo]:
    """Scan text for mentions of threat actor groups or their known aliases."""
    if not text or not isinstance(text, str):
        return []

    provider = _get_provider()
    groups = provider.get_groups()
    if not groups:
        return []

    alias_to_id: Dict[str, str] = {}
    for g in groups:
        gid = g.get("id")
        if not gid:
            continue
        name = g.get("name")
        if name and len(name) >= 3 and name.lower() not in _EXCLUDED_ALIAS_WORDS:
            alias_to_id[name.lower()] = gid
        for a in g.get("aliases", []):
            a_clean = a.strip()
            if (
                len(a_clean) >= 3
                and a_clean.lower() not in _EXCLUDED_ALIAS_WORDS
                and not (len(a_clean) <= 4 and a_clean.isupper() and a_clean in ("THE",))
            ):
                alias_to_id[a_clean.lower()] = gid

    if not alias_to_id:
        return []

    sorted_aliases = sorted(alias_to_id.keys(), key=len, reverse=True)
    pattern = re.compile(r"\b(" + "|".join(re.escape(a) for a in sorted_aliases) + r")\b", re.IGNORECASE)

    matches = pattern.findall(text)
    if not matches:
        return []

    matched_gids: List[str] = []
    seen_gids: Set[str] = set()
    for m in matches:
        gid = alias_to_id.get(m.lower())
        if gid and gid not in seen_gids:
            seen_gids.add(gid)
            matched_gids.append(gid)

    results: List[GroupInfo] = []
    for gid in matched_gids:
        g_info = provider.get_group_by_id(gid)
        if g_info:
            results.append(g_info)
    return results


_MOBILE_ICS_CACHE: Optional[Tuple[Dict[str, List[str]], Dict[str, List[str]]]] = None


def _load_mobile_ics_mappings() -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """Load mobile and ICS technique-to-tactic mappings from STIX cache if present."""
    global _MOBILE_ICS_CACHE
    if _MOBILE_ICS_CACHE is not None:
        return _MOBILE_ICS_CACHE

    stix_dir = _get_stix_cache_dir()
    candidate_dirs = [
        stix_dir,
        Path.home() / ".hecate" / "stix-data",
        Path("/home/chemch/.hecate/stix-data"),
    ]
    mobile_map: Dict[str, List[str]] = {}
    ics_map: Dict[str, List[str]] = {}

    for dom_key, fname, target_map in (
        ("mobile", "mobile-attack.json", mobile_map),
        ("ics", "ics-attack.json", ics_map),
    ):
        file_path: Optional[Path] = None
        for cdir in candidate_dirs:
            p = cdir / fname
            if p.exists():
                file_path = p
                break
        if not file_path:
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            for obj in bundle.get("objects", []):
                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                    for ref in obj.get("external_references", []):
                        if (
                            ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
                            and "external_id" in ref
                        ):
                            t_id = ref["external_id"]
                            tactics = [
                                str(kc.get("phase_name")) for kc in obj.get("kill_chain_phases", []) if kc.get("phase_name")
                            ]
                            target_map[t_id] = tactics
                            break
        except Exception as exc:
            logger.debug("Failed reading %s: %s", file_path, exc)

    _MOBILE_ICS_CACHE = (mobile_map, ics_map)
    return _MOBILE_ICS_CACHE


def categorize_techniques_by_matrix(technique_ids: Set[str]) -> Dict[str, Any]:
    """Categorize a set of ATT&CK technique IDs across Enterprise, Mobile, and ICS matrices.

    Returns a dict with:
        enterprise: {tactic_shortname: count}
        mobile: {tactic_shortname: count}
        ics: {tactic_shortname: count}
        total_unique: count of unique techniques given
        enterprise_total: sum of enterprise tactic instances
        mobile_total: sum of mobile tactic instances
        ics_total: sum of ics tactic instances
    """
    ent_tactics: Dict[str, int] = {
        "reconnaissance": 0,
        "resource-development": 0,
        "initial-access": 0,
        "execution": 0,
        "persistence": 0,
        "privilege-escalation": 0,
        "stealth": 0,
        "defense-impairment": 0,
        "credential-access": 0,
        "discovery": 0,
        "lateral-movement": 0,
        "collection": 0,
        "command-and-control": 0,
        "exfiltration": 0,
        "impact": 0,
    }
    cloud_tactics: Dict[str, int] = {
        "initial-access": 0,
        "execution": 0,
        "persistence": 0,
        "privilege-escalation": 0,
        "stealth": 0,
        "defense-impairment": 0,
        "credential-access": 0,
        "discovery": 0,
        "lateral-movement": 0,
        "collection": 0,
        "exfiltration": 0,
        "impact": 0,
    }
    container_tactics: Dict[str, int] = {
        "initial-access": 0,
        "execution": 0,
        "persistence": 0,
        "privilege-escalation": 0,
        "stealth": 0,
        "defense-impairment": 0,
        "credential-access": 0,
        "discovery": 0,
        "lateral-movement": 0,
        "impact": 0,
    }
    mob_tactics: Dict[str, int] = {
        "initial-access": 0,
        "execution": 0,
        "persistence": 0,
        "privilege-escalation": 0,
        "defense-evasion": 0,
        "credential-access": 0,
        "discovery": 0,
        "lateral-movement": 0,
        "collection": 0,
        "command-and-control": 0,
        "exfiltration": 0,
        "impact": 0,
        "network-effects": 0,
        "remote-service-effects": 0,
    }
    ics_tactics: Dict[str, int] = {
        "initial-access": 0,
        "execution": 0,
        "persistence": 0,
        "privilege-escalation": 0,
        "evasion": 0,
        "discovery": 0,
        "lateral-movement": 0,
        "collection": 0,
        "command-and-control": 0,
        "inhibit-response-function": 0,
        "impair-process-control": 0,
        "impact": 0,
    }

    mobile_map, ics_map = _load_mobile_ics_mappings()

    for tid in technique_ids:
        clean_tid = tid.strip()
        if not clean_tid:
            continue

        # Check ICS domain first (T08xx or in ics_map)
        if clean_tid.startswith("T08") or clean_tid in ics_map:
            tacs = ics_map.get(clean_tid, ["impact"])
            for tac in tacs:
                if tac in ics_tactics:
                    ics_tactics[tac] += 1

        # Check Mobile domain
        if clean_tid in mobile_map:
            for tac in mobile_map[clean_tid]:
                if tac in mob_tactics:
                    mob_tactics[tac] += 1

        # Check Enterprise, Cloud, and Container domains
        info = get_technique(clean_tid)
        if info and info.get("tactic_shortnames"):
            platforms = {str(p).lower() for p in (info.get("platforms") or [])}
            is_cloud = bool(platforms & {"iaas", "saas", "identity provider", "office suite"})
            is_container = bool(platforms & {"containers", "kubernetes"})
            for tac in info["tactic_shortnames"]:
                canon = canonical_tactic(tac)
                if canon in ent_tactics:
                    ent_tactics[canon] += 1
                elif tac in ent_tactics:
                    ent_tactics[tac] += 1
                if is_cloud:
                    if canon in cloud_tactics:
                        cloud_tactics[canon] += 1
                    elif tac in cloud_tactics:
                        cloud_tactics[tac] += 1
                if is_container:
                    if canon in container_tactics:
                        container_tactics[canon] += 1
                    elif tac in container_tactics:
                        container_tactics[tac] += 1

    return {
        "enterprise": ent_tactics,
        "cloud": cloud_tactics,
        "containers": container_tactics,
        "mobile": mob_tactics,
        "ics": ics_tactics,
        "total_unique": len(technique_ids),
        "enterprise_total": sum(ent_tactics.values()),
        "cloud_total": sum(cloud_tactics.values()),
        "containers_total": sum(container_tactics.values()),
        "mobile_total": sum(mob_tactics.values()),
        "ics_total": sum(ics_tactics.values()),
    }


# ---------------------------------------------------------------------------
# Module-level __getattr__ (PEP 562) for backward compatibility
# ---------------------------------------------------------------------------


def __getattr__(name: str) -> Any:
    """Support 'from hecate_agent.core.attack_matrix import ATTACK_TACTICS'."""
    if name == "ATTACK_TACTICS":
        return _get_provider().get_tactics()
    if name == "TOTAL_TECHNIQUES":
        return _get_provider().get_total_techniques()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
