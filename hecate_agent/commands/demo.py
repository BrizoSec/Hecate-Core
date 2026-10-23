"""Demo commands for quickstart and zero-configuration initialization."""

from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from hecate_agent.core.hunt_manager import get_hunt_directory

console = Console()

DEMO_RESEARCH_R0001 = """---
research_id: R-0001
topic: LSASS Memory Credential Dumping
mitre_techniques:
  - T1003.001
created_date: {date}
status: completed
tags:
  - credential-access
  - lsass
  - memory-dump
---

# R-0001: LSASS Memory Credential Dumping Research

**Topic:** LSASS Memory Credential Dumping
**MITRE ATT&CK:** T1003.001
**Duration:** 15.0 minutes

---

## 1. System Research: How It Works

### Summary
The Local Security Authority Subsystem Service (LSASS) is a core Windows process (`lsass.exe`) responsible
for enforcing security policy, verifying users logging on, handling password changes, and creating access
tokens. It caches active credentials, including NTLM password hashes, Kerberos tickets (TGT/TGS), and
plaintext credentials used by WDigest and SSP packages in process memory.

### Key Findings
- LSASS runs in user space with `SYSTEM` privileges, protected by LSA Protection (RunAsPPL) on modern Windows.
- Accessing LSASS memory requires process handle access rights such as `PROCESS_VM_READ` (0x0010) and
  `PROCESS_QUERY_INFORMATION` (0x0400).
- Normal administrative operations rarely require reading LSASS memory; legitimate callers are typically
  restricted to EDR sensors, antivirus engines, and diagnostic kernel routines.

### Sources
- [Microsoft Learn: Local Security Authority Subsystem Service](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/)
- [MITRE ATT&CK: OS Credential Dumping: LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/)

---

## 2. Adversary Tradecraft: Abuse Techniques

### Summary
Adversaries target LSASS to harvest credentials for lateral movement and privilege escalation.
Common techniques utilize built-in APIs or living-off-the-land binaries (LOLBins) to write process memory
to disk or stream it over network pipes.

### Key Findings
- Tools like Mimikatz inject or open handles directly via `OpenProcess` / `MiniDumpWriteDump`.
- LOLBins such as `rundll32.exe comsvcs.dll,MiniDump` or `procdump.exe` are commonly weaponized.
- Evasion variants use direct system calls (Syswhispers) or handle duplication to bypass API hooks.

---

## 3. Telemetry Mapping

### Telemetry Sources
- **Sysmon Event ID 10**: ProcessAccess events where `TargetImage` is `*\\lsass.exe` and `GrantedAccess` includes `0x1010` or `0x1FFFFF`.
- **Windows Security Event ID 4663 / 4656**: Object access attempts against LSASS process object.
- **Sysmon Event ID 1**: Process creation events where command lines invoke `comsvcs.dll` or `procdump`.

---

## 4. Related Work
- Initial baseline investigation into endpoint credential hygiene.

---

## 5. Research Synthesis: Actionable Insights
- Focus detection on anomalous source processes requesting read access to `lsass.exe`.
- Exclude validated EDR sensors (`MsMpEng.exe`, `csagent.exe`) and baseline any IT diagnostic tools.
- Priority hunt: Identify any unapproved processes opening LSASS with memory read permissions.
"""

DEMO_HUNT_H0001 = """---
id: H-0001
title: LSASS Memory Credential Dumping via Suspicious Process Access
type: hunt
status: completed
created: {date}
hunter: sec-ops
tactics:
  - credential-access
techniques:
  - T1003.001
platform:
  - Windows
data_sources:
  - EDR
  - SIEM
  - Sysmon
spawned_from: R-0001
detection_rule: detections/H-0001.yml
---

# H-0001: LSASS Memory Credential Dumping via Suspicious Process Access

## Learn
Adversaries harvest credentials directly from LSASS memory to escalate privileges and move laterally
within Active Directory environments. Grounded in research R-0001, reading LSASS memory requires process
handle permissions (`PROCESS_VM_READ` 0x0010, `PROCESS_QUERY_INFORMATION` 0x0400).
Telemetry available: Sysmon Event ID 10 (ProcessAccess), Windows Security Log 4663, and EDR sensor events.

## Observe
Hypothesis: Adversaries or unapproved tools will attempt to open handles to `lsass.exe` requesting
`PROCESS_VM_READ` (`0x1010`, `0x1FFFFF`, `0x1410`). Any non-system, non-EDR executable performing this access
warrants immediate triage as potential credential theft.

## Check
Run bounded telemetry search over the last 14 days of endpoint process access logs:

```spl
index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x1010", "0x1FFFFF", "0x1410")
| search NOT (SourceImage IN ("*\\\\MsMpEng.exe", "*\\\\csagent.exe", "*\\\\taskmgr.exe"))
| stats count min(_time) as first_seen max(_time) as last_seen by Computer, SourceImage, SourceUser, GrantedAccess
| sort - count
```

Alternative Microsoft Sentinel / Defender KQL query:

```kql
DeviceEvents
| where ActionType == "OpenProcessHandle" and FileName has "lsass.exe"
| where AdditionalFields.DesiredAccess in ("0x1010", "0x1FFFFF", "0x1410")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "SenseCncProxy.exe", "csagent.exe")
| summarize count(), min(Timestamp), max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
```

## Keep
- **Findings**: Evaluated 14 days of telemetry across 1,200 Windows endpoints.
  Identified 1 benign administrative tool (`ProcDump.exe` used during diagnostic troubleshooting by IT support)
  and 0 malicious intrusions.
- **Baseline Tuning**: Established approved change-management exclusion for diagnostic utilities when signed
  and executed from protected directories.
- **Actionable Output**: Generated production Sigma rule `detections/H-0001.yml` to alert detection engineering
  on new or unapproved callers to LSASS.
- **Next Steps**: Expand hunting to LSASS mini-dump file artifacts written to disk (`*.dmp` files in `%TEMP%`).
"""

DEMO_QUERY_SPL = """# H-0001: LSASS Process Access Query (Splunk)
index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x1010", "0x1FFFFF", "0x1410")
| search NOT (SourceImage IN ("*\\\\MsMpEng.exe", "*\\\\csagent.exe", "*\\\\taskmgr.exe"))
| stats count min(_time) as first_seen max(_time) as last_seen by Computer, SourceImage, SourceUser, GrantedAccess
| sort - count
"""

DEMO_QUERY_KQL = """// H-0001: LSASS Process Access Query (KQL)
DeviceEvents
| where ActionType == "OpenProcessHandle" and FileName has "lsass.exe"
| where AdditionalFields.DesiredAccess in ("0x1010", "0x1FFFFF", "0x1410")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "SenseCncProxy.exe", "csagent.exe")
| summarize count(), min(Timestamp), max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
"""

DEMO_SIGMA = """title: LSASS Memory Credential Dumping via Suspicious Process Access
id: 3c9d6402-23c2-4a0b-8d54-8e4dcfb6f932
status: test
description: Detects suspicious process access to lsass.exe requesting memory read permissions, characteristic of credential dumping tools.
references:
  - 'hecate://hunts/H-0001'
  - 'https://attack.mitre.org/techniques/T1003/001/'
author: sec-ops
date: {date_slash}
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1FFFFF'
      - '0x1410'
  filter_legitimate:
    SourceImage|endswith:
      - '\\MsMpEng.exe'
      - '\\csagent.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Antivirus and EDR software
  - Approved diagnostic dumps by system administrators
level: high
"""


@click.group(name="demo")
def demo() -> None:
    """Manage demo workflows and sample data."""
    pass


@demo.command(name="init")
@click.option("--force", is_flag=True, help="Overwrite existing demo files if they exist.")
@click.option(
    "--path",
    "target_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Target workspace directory (default: current directory).",
)
def demo_init(force: bool, target_dir: Optional[Path]) -> None:
    """Initialize a zero-configuration demo workspace with a complete example hunt.

    \\b
    Creates the complete directory structure and seeds an end-to-end example hunt
    (LSASS Credential Dumping - T1003.001) in hunts/, research/, queries/, and detections/.

    \\b
    Examples:
      # Initialize demo in current directory
      hecate-agent demo init

      # Overwrite existing demo files
      hecate-agent demo init --force
    """
    root = target_dir or Path.cwd()
    today_iso = datetime.now().strftime("%Y-%m-%d")
    today_slash = datetime.now().strftime("%Y/%m/%d")

    # Target directories
    hunt_dir = root / get_hunt_directory()
    research_dir = root / "research"
    queries_dir = root / "queries"
    detections_dir = root / "detections"

    for d in [hunt_dir, research_dir, queries_dir, detections_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # File paths
    hunt_file = hunt_dir / "H-0001.md"
    research_file = research_dir / "R-0001.md"
    spl_file = queries_dir / "H-0001-lsass-dumping.spl"
    kql_file = queries_dir / "H-0001-lsass-dumping.kql"
    sigma_file = detections_dir / "H-0001.yml"

    files_to_create = [
        (research_file, DEMO_RESEARCH_R0001.format(date=today_iso)),
        (hunt_file, DEMO_HUNT_H0001.format(date=today_iso)),
        (spl_file, DEMO_QUERY_SPL),
        (kql_file, DEMO_QUERY_KQL),
        (sigma_file, DEMO_SIGMA.format(date_slash=today_slash)),
    ]

    created = []
    skipped = []

    for file_path, content in files_to_create:
        if file_path.exists() and not force:
            skipped.append(file_path)
        else:
            file_path.write_text(content, encoding="utf-8")
            created.append(file_path)

    console.print()
    console.print(
        Panel.fit(
            "[bold green]🎯 Hecate Demo Workspace Initialized![/bold green]\n"
            "[dim]A complete example hunt (LSASS Credential Dumping - T1003.001) is ready to inspect.[/dim]",
            border_style="green",
        )
    )

    if created:
        console.print("[bold]Created files:[/bold]")
        for f in created:
            rel = f.relative_to(root) if f.is_relative_to(root) else f
            console.print(f"  [green]✓[/green] [cyan]{rel}[/cyan]")
        console.print()

    if skipped:
        console.print("[yellow]Existing files kept (use --force to overwrite):[/yellow]")
        for f in skipped:
            rel = f.relative_to(root) if f.is_relative_to(root) else f
            console.print(f"  [dim]- {rel}[/dim]")
        console.print()

    console.print("[bold]Next Steps:[/bold]")
    console.print("  • List hunts:         [cyan]hecate-agent hunt list[/cyan]")
    console.print("  • View hunt stats:    [cyan]hecate-agent hunt stats[/cyan]")
    console.print("  • Assess maturity:    [cyan]hecate-agent maturity assess[/cyan]")
    console.print("  • Promote to rule:    [cyan]hecate-agent hunt promote --hunt H-0001 --output sigma[/cyan]")
    console.print("  • Monitor dashboard:  [cyan]hecate-agent monitor[/cyan]")
    console.print()
