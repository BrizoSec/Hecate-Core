---
research_id: R-0616
topic: A fake resume invoked China's defence-tech elite, then installed VShell
mitre_techniques: []
status: completed
depth: advanced
duration_minutes: 2.8
linked_hunts: [H-0618]
web_searches: 2
grounding: independent
llm_calls: 4
total_cost_usd: null
cost_basis: 'not priced: local model (qwen3:30b-a3b-instruct-2507-q4_K_M) has no per-token price; compute is not metered'
data_source_availability: {process_execution: true, file_operations: true, network_connections: true, registry_events: false}
estimated_hunt_complexity: high
created_date: '2026-10-03'
---

# R-0616: A fake resume invoked China's defence-tech elite, then installed VShell Research

**Topic:** A fake resume invoked China's defence-tech elite, then installed VShell
**Duration:** 2.8 minutes

---

## 1. System Research: How It Works

### Summary
A malicious Chinese-language executable, masquerading as a Beijing Institute of Technology graduate's resume, triggers a multi-stage infection chain via a custom Go loader that evades detection through sandbox checks, CPU validation, and sleep timers. The loader downloads a legitimate DOCX file from a decoy server and executes a 1,454-byte SNOWLIGHT stager that connects to a C2 server at 38.207.178.192:50812, downloads 4.65 MB of data, XOR-decodes it with key 0x99, and launches a fileless VShell RAT. The malware enables command execution, file access, screen capture, and lateral movement on the compromised system.

### Key Findings
- The Go loader checks for sandbox environments, verifies at least four CPU cores, and uses sleep-timer evasion before proceeding with the infection chain.
- A legitimate DOCX file (SHA256: de3f56d0d5b71f2a1a1905f0b01b84fbab237e9d4c5179a05b127d806823f83c) is downloaded from http://38.207.178.192:50813/MySQL_LOG.txt and saved to C:\Windows\Temp\Beijing Institute of Technology_..._personal resume (2).docx.
- The SNOWLIGHT stager connects to 38.207.178.192:50812 (active C2) to download and XOR-decode 4.65 MB of encrypted payload using key 0x99, resulting in a fileless VShell RAT execution.
- The malware creates a kill-switch marker file at %TEMP%\log_de.log; if this file exists, the payload exits, indicating a deliberate operator exclusion or kill-switch mechanism.
- Network activity shows connections to hostnames like d.d.edsxhbba06.shop, oa.muxmyee520.shop, pan.qlam.cc, v.n.1.xcwanmei09.shop, and www.qlam.cc, with the primary C2 at 38.207.178.192:50812 and secondary download endpoint at 38.207.178.192:50813.

### Sources
- [A fake resume invoked China's defence-tech elite, then installed VShell - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/a-fake-resume-invoked-chinas-defence-tech-elite-then-installed-vshell-eb5fae956dc0ad69)
- [a fake resume invoked China's defence-tech elite, then installed VShell :: Himanshu Anand :: Security & Other Notes](https://blog.himanshuanand.com/2026/08/a-fake-resume-invoked-chinas-defence-tech-elite-then-installed-vshell)
- [Fake Resume Delivers VShell to China’s Defense-Tech Sector](https://socprime.com/active-threats/vshell-malware-delivered-through-a-fake-resume-targeting-chinas-defense-industry)
- [vshell :: Himanshu Anand :: Security & Other Notes](https://blog.himanshuanand.com/tags/vshell)
- [A fake resume invoked China's defence-tech elite, then installed VShell | Hacker News](https://news.ycombinator.com/item?id=49466504)

---

## 2. Adversary Tradecraft: Attack Techniques

### Summary
Adversaries abused a fake resume masquerading as a Beijing Institute of Technology graduate's application to deliver a multi-stage malware payload targeting Chinese defense-tech academics. The attack leveraged a custom Go loader with sandbox evasion and CPU checks to deploy the SNOWLIGHT stager, which downloaded and executed a fileless VShell RAT via a decoy DOCX document. The campaign used infrastructure at 38.207.178.192 across multiple ports for C2 and payload delivery.

### Key Findings
- The attack used a Chinese-language executable disguised as a resume from a Beijing Institute of Technology graduate student to lure academic targets in electrical engineering, power systems, and AI research.
- A custom Go loader with sandbox detection, CPU checks, and sleep-timer evasion was used to execute a 1,454-byte SNOWLIGHT stager that downloaded 4.65 MB of data XOR-decoded with key 0x99.
- The SNOWLIGHT stager launched a fileless VShell RAT, enabling command execution, file access, screen capture, and lateral movement, with the C2 infrastructure hosted at 38.207.178.192:50812.
- The malware downloaded a legitimate DOCX decoy from http://38.207.178.192:50813/MySQL_LOG.txt, saved as C:\Windows\Temp\Beijing Institute of Technology_..._personal resume (2).docx.
- Indicators include multiple SHA256 hashes (e.g., c25d4412f7f93e7de5b2aaf41747175d94cffd983ca20efbd0efcdd718b58c4d for the Go loader), the IP 38.207.178.192, and domain-like hostnames such as d.d.edsxhbba06.shop and pan.qlam.cc.
- The attack chain includes a kill-switch mechanism via the creation of %TEMP%\log_de.log, and the use of widely available, panel-generated SNOWLIGHT components now found in cracked VShell releases, reducing the reliability of actor-level attribution.

### Sources
- [Fake Resume Delivers VShell to China’s Defense-Tech Sector](https://socprime.com/active-threats/vshell-malware-delivered-through-a-fake-resume-targeting-chinas-defense-industry)

---

## 3. Telemetry Mapping: OCSF Fields

### Summary
The source intelligence describes a malicious attack chain involving a Go loader, sandbox evasion, fileless execution, and deployment of the VShell RAT via a deceptive academic resume lure targeting Chinese defense-tech researchers. The behavior includes initial execution of a malicious binary, anti-analysis techniques (CPU checks, sleep timers), download of a legitimate DOCX file, execution of a stager that decodes and launches a fileless payload, and C2 communication with infrastructure. This constitutes clear adversary behavior, not just a list of indicators, and is therefore suitable for telemetry mapping.

### Key Fields

OCSF path → the event field `knowledge/environment.md` documents for it.

- `process.name` → `process_name` (Endpoint) (written as `process_activity.process.name`): captures the execution of the Go loader (e.g., 'personal_resume.exe') and the subsequent fileless VShell RAT process ('vshell'), including process creation and command-line arguments.
- `process.parent_process.name` → `parent_process` (Endpoint) (written as `process_activity.parent_process.name`): identifies the parent process (e.g., explorer.exe or word.exe) to detect process injection or spawning from a legitimate application.
- `dst_endpoint.ip` → `dest_ip` (Network) (written as `network_activity.dst_endpoint.ip`): detects outbound connections to the C2 IP 38.207.178.192 on ports 50812 and 50813, indicating data exfiltration or command reception.
- `dst_endpoint.hostname` → unmapped: the environment profile documents no field (written as `network_activity.dst_endpoint.hostname`): detects DNS or HTTP requests to domains like 'd.d.edsxhbba06.shop' or 'pan.qlam.cc', which may be used for C2 or decoy downloads.
- `file.path` → unmapped: the environment profile documents no field (written as `file_activity.path`): identifies file creation in temporary directories such as 'C:\Windows\Temp\Beijing Institute of Technology_..._personal resume (2).docx' or '%TEMP%\log_de.log', indicating payload dropping or kill-switch marker creation.

### Fields Removed (not in the OCSF reference)

- `file_activity.hashes.sha256`

### Data Source Availability

- Process Execution: Documented in the environment profile
- File Operations: Documented in the environment profile
- Network Connections: Documented in the environment profile
- Registry Events: Unknown: not documented in the environment profile

---

## 4. Related Work: Past Hunts

### Summary
No related hunts found for A fake resume invoked China's defence-tech elite, then installed VShell - this may be a new research area

### Related Hunts
- No related past hunts found

---

## 5. Research Synthesis

### Executive Summary
Adversaries leverage a custom Go loader with sandbox evasion, CPU validation, and sleep-timer techniques to execute a fileless SNOWLIGHT stager from a deceptive Chinese-language resume lure targeting Beijing Institute of Technology-affiliated academics. The stager connects to C2 at 38.207.178.192:50812, downloads and XOR-decodes a 4.65 MB payload using key 0x99, and launches a fileless VShell RAT without disk persistence, while using a legitimate DOCX decoy and a kill-switch marker at %TEMP%\log_de.log to evade detection and control execution.

### Recommended Hypothesis
> Adversaries use a multi-stage, fileless execution chain with sandbox evasion and CPU-based detection bypasses to deliver a VShell RAT via a deceptive academic resume lure targeting Chinese defense-tech researchers.

### Gaps Identified
- The use of XOR-decoded payloads with a known key (0x99) and dynamic C2 infrastructure on non-standard ports (50812/50813) is not consistently detected due to lack of memory-based analysis for decoded payloads and insufficient network correlation across port activity.
- The presence of a kill-switch marker file (%TEMP%\log_de.log) is not monitored in endpoint telemetry, enabling undetected persistence and evasion of detection during post-compromise analysis.

### Key Findings
- Hypothesis: Adversaries use a multi-stage, fileless execution chain with sandbox evasion and CPU-based detection bypasses to deliver a VShell RAT via a deceptive academic resume lure targeting Chinese defense-tech researchers.
- Gap: The use of XOR-decoded payloads with a known key (0x99) and dynamic C2 infrastructure on non-standard ports (50812/50813) is not consistently detected due to lack of memory-based analysis for decoded payloads and insufficient network correlation across port activity.
- Gap: The presence of a kill-switch marker file (%TEMP%\log_de.log) is not monitored in endpoint telemetry, enabling undetected persistence and evasion of detection during post-compromise analysis.
- Focus: Implement memory injection and runtime decoding analysis for known stager patterns (e.g., SNOWLIGHT) to detect fileless execution of VShell via XOR-decoded payloads.
- Focus: Map outbound network activity to 38.207.178.192 across multiple ports (50812, 50813) with correlation to process creation of 'vshell' and document decoy downloads from non-standard endpoints.
- Focus: Instrument endpoint telemetry to detect creation of the kill-switch file %TEMP%\log_de.log as a behavioral indicator of active payload execution or operator exclusion.

### Hunt Complexity Assessment
**Estimated Complexity:** High

---

## Appendix: Research Metrics

- Web Searches: 2
- LLM Calls: 4
- Tokens: 14,247 input, 1,949 output
- Total Cost: unknown (not priced: local model (qwen3:30b-a3b-instruct-2507-q4_K_M) has no per-token price; compute is not metered)
- Duration: 170.1 seconds
