---
research_id: R-0001
topic: Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam
mitre_techniques: []
status: completed
depth: advanced
duration_minutes: 2.2
linked_hunts: [H-0001]
web_searches: 2
grounding: independent
llm_calls: 4
total_cost_usd: null
cost_basis: 'not priced: local model (qwen3:30b-a3b-instruct-2507-q4_K_M) has no per-token price; compute is not metered'
data_source_availability: {process_execution: true, file_operations: true, network_connections: true, registry_events: false}
estimated_hunt_complexity: high
created_date: '2026-10-03'
---

# R-0001: Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam Research

**Topic:** Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam
**Duration:** 2.2 minutes

---

## 1. System Research: How It Works

### Summary
The malware operates by tricking users into executing a malicious command via a fake CAPTCHA prompt, leading to the download and execution of a Bash profiler script that collects system data and deploys architecture-specific Mach-O payloads. It achieves persistence through macOS Background Task Management by injecting into the launchctl bootstrap process and uses a fake system prompt via osascript to harvest credentials, ultimately targeting cryptocurrency wallets and keychain data.

### Key Findings
- The initial infection vector involves a malicious URL (http://193.29.224.151/92392991a0cca55?force=1) hosted on a sanctioned Russian bulletproof hosting provider, delivering a Bash script with SHA256 5bad988affc1094f12b8b8bed659ef55b20e2988eb25441e1c1b34dd03b3eb52 that acts as a loader.
- The malware establishes persistence by injecting a malicious Mach-O payload into the Background Task Management (BTM) subsystem via launchctl bootstrap gui/501, using the path /Users/<redacted>/Library/LaunchAgents/com.apple.softwareupdated.plist and copying the payload to com.apple.verified.
- The payload communicates with a C2 server at 138.124.118.69:8133 over HTTP on a nonstandard port, indicating C2 activity that may be used for command and control or data exfiltration.
- The malware leverages osascript to display a fake system prompt, attempting to harvest user credentials through social engineering, which are then used to unlock the Apple Keychain and access stored passwords and crypto wallet data.
- The malware targets multiple cryptocurrencies (Bitcoin, Litecoin, Dogecoin, Monero, Ethereum, XRP) and uses a DRAIN function to siphon funds, with the malicious payload being ad-hoc signed and having extended file attributes stripped to evade detection.

### Sources
- [Fake CleanMyMac site installs SHub Stealer and backdoors crypto wallets | Malwarebytes](https://www.malwarebytes.com/blog/threat-intel/2026/03/fake-cleanmymac-site-installs-shub-stealer-and-backdoors-crypto-wallets)
- [Mac malware GlassWorm steals crypto wallet data and passwords from users | Fox News](https://www.foxnews.com/tech/malicious-mac-extensions-steal-crypto-wallets-passwords)
- [Wallet Drainers: How Scams Steal Funds](https://www.darktrace.com/blog/crypto-wallets-continue-to-be-drained-in-elaborate-social-media-scam)
- [Odyssey Stealer: Inside a macOS Crypto-Stealing Operation - Censys](https://censys.com/blog/odyssey-stealer-inside-a-macos-crypto-stealing-operation)
- [CrashStealer Malware (Mac) - Removal steps, and macOS cleanup (updated)](https://www.pcrisk.com/removal-guides/35648-crashstealer-malware-mac)

---

## 2. Adversary Tradecraft: Attack Techniques

### Summary
Adversaries exploit macOS users through social engineering via fake CAPTCHA prompts delivered in emails, tricking victims into executing malicious commands in Terminal. This initiates a multi-stage attack that downloads a profiling script, deploys architecture-specific Go-based Mach-O payloads, and establishes persistence via macOS Background Task Management, ultimately enabling the theft of cryptocurrency wallets through a DRAIN function that gradually redirects funds to attacker-controlled accounts.

### Key Findings
- The attack begins with a ClickFix social engineering tactic, using fake CAPTCHA prompts to诱导 users into running malicious commands in Terminal.
- A Bash script (SHA256: 5bad988affc1094f12b8b8bed659ef55b20e2988eb25441e1c1b34dd03b3eb52) is downloaded and executed, which collects system information and deploys architecture-specific Go-based Mach-O payloads.
- Malware achieves persistence by incorporating the payload into the Background Task Management (BTM) subsystem via launchctl bootstrap, using paths such as /Users/<redacted>/Library/LaunchAgents/com.apple.softwareupdated.plist and copying the executable to com.apple.verified.
- The malware includes a DRAIN function that targets multiple cryptocurrencies (Bitcoin, Litecoin, Dogecoin, Monero, Ethereum, XRP) by redirecting portions of wallet balances to attacker-controlled accounts.
- C2 communication occurs via HTTP on nonstandard port 8133 to the IP address 138.124.118.69, with initial payload delivery from domains and IPs linked to the sanctioned Aeza Group, including profitnow.io and 193.29.224.151.
- Evasion techniques include Gatekeeper bypass, ad-hoc signing, stripping of extended file attributes, and credential harvesting via fake osascript dialogues prompting users for their system credentials.

### Sources
- [Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/mac-malware-drains-crypto-wallets-via-fake-captcha-scam-d953300733715421)
- [Mac Malware Found Draining Crypto Wallets After Fake CAPTCHA Trick - IT Security Guru](https://www.itsecurityguru.org/2026/08/06/mac-malware-found-draining-crypto-wallets-after-fake-captcha-trick)
- [Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam | Huntress](https://www.huntress.com/blog/mac-crypto-draining-malware)
- [One pasted Terminal command opens the door to Mac crypto wallet theft — AppleInsider Forums](https://forums.appleinsider.com/discussion/245187/one-pasted-terminal-command-opens-the-door-to-mac-crypto-wallet-theft)
- [ClickFix Attacks Deliver macOS Stealer That Can Drain Crypto Wallets](https://aviatrix.ai/threat-research-center/clickfix-attacks-deliver-macos-stealer-2026)
- [macOS Stealer Uses ClickFix to Drain Crypto Wallets](https://socprime.com/active-threats/macos-infostealer-targets-cryptocurrency-wallets)
- [From Fake CAPTCHA to Hidden Desktop: Unpacking CastleRAT and Operation Device Manager](https://lumu.io/blog/castlerat-clickfix-analysis)

---

## 3. Telemetry Mapping: OCSF Fields

### Summary
The source intelligence describes a sophisticated macOS malware campaign involving social engineering via fake CAPTCHA prompts, execution of malicious commands in Terminal, deployment of architecture-specific Go-based Mach-O payloads, credential harvesting, cryptocurrency wallet theft via a DRAIN function, persistence via macOS Background Task Management, and C2 communication. The behavior includes file dropping, process creation with elevated privileges, credential capture via AppleScript, and use of ad-hoc signing and quarantine bypass techniques. These actions are detectable through specific telemetry across process, file, network, and authentication event classes.

### Key Fields

OCSF path → the event field `knowledge/environment.md` documents for it.

- `process.name` → `process_name` (Endpoint): /usr/bin/osascript - Detects execution of AppleScript for credential capture via fake system prompts.
- `process.cmd_line` → `command_line` (Endpoint): launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist - Detects persistence via Background Task Management (BTM) subsystem.
- `file.path` → unmapped: the environment profile documents no field: /Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate - Detects malware payload storage in a legitimate-looking cache directory.
- `file.path` → unmapped: the environment profile documents no field: $HOME/Library/Caches/com.apple.trustd/com.apple.verified - Detects use of a forged system path to hide malicious file.
- `network_endpoint.ip` → `dest_ip` / `src_ip` (Network; destination / source endpoint): 138.124.118.69 - Detects C2 communication over non-standard port 8133.

### Fields Removed (not in the OCSF reference)

- `file.hashes.sha256`

### Data Source Availability

- Process Execution: Documented in the environment profile
- File Operations: Documented in the environment profile
- Network Connections: Documented in the environment profile
- Registry Events: Unknown: not documented in the environment profile

---

## 4. Related Work: Past Hunts

### Summary
No related hunts found for Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam - this may be a new research area

### Related Hunts
- No related past hunts found

---

## 5. Research Synthesis

### Executive Summary
Adversaries leverage a multi-stage macOS malware campaign that uses social engineering via fake CAPTCHA prompts to execute a malicious Bash profiler script, which deploys architecture-specific Go-based Mach-O payloads. The malware achieves persistence through manipulation of macOS's Background Task Management via launchctl bootstrap, hides within legitimate-looking cache paths, and uses osascript to harvest credentials via deceptive system prompts, enabling targeted cryptocurrency theft via a DRAIN function across multiple blockchain assets.

### Recommended Hypothesis
> Adversaries use fake system prompts delivered via malicious CAPTCHA links to execute a Bash loader in Terminal, which deploys architecture-specific Mach-O payloads via ad-hoc signing and injects them into the Background Task Management subsystem using launchctl bootstrap, enabling persistent, stealthy access to cryptocurrency wallets and credentials.

### Gaps Identified
- Detection of the malicious Mach-O payload is hindered by its use of legitimate-looking file paths (e.g., /Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate) and the absence of telemetry mapping for file paths under com.apple.* cache directories, which allows evasion of endpoint file monitoring.
- The use of ad-hoc signing and quarantine bypass techniques, combined with the execution of osascript via deceptive UI prompts, creates a stealthy credential harvesting vector that is not reliably captured in standard process or authentication event logs without deep inspection of AppleScript execution context.

### Key Findings
- Hypothesis: Adversaries use fake system prompts delivered via malicious CAPTCHA links to execute a Bash loader in Terminal, which deploys architecture-specific Mach-O payloads via ad-hoc signing and injects them into the Background Task Management subsystem using launchctl bootstrap, enabling persistent, stealthy access to cryptocurrency wallets and credentials.
- Gap: Detection of the malicious Mach-O payload is hindered by its use of legitimate-looking file paths (e.g., /Users/<redacted>/Library/Caches/com.apple.softwareupdate/SoftwareUpdate) and the absence of telemetry mapping for file paths under com.apple.* cache directories, which allows evasion of endpoint file monitoring.
- Gap: The use of ad-hoc signing and quarantine bypass techniques, combined with the execution of osascript via deceptive UI prompts, creates a stealthy credential harvesting vector that is not reliably captured in standard process or authentication event logs without deep inspection of AppleScript execution context.
- Focus: Prioritize detection of non-standard launchctl bootstrap commands targeting GUI session 501 with paths under /Users/*/Library/LaunchAgents/com.apple.softwareupdated.plist, especially when paired with execution of osascript or process creation from non-interactive shells.
- Focus: Implement file integrity monitoring and behavioral detection for file creation or modification in cache directories under $HOME/Library/Caches/com.apple.* with names resembling system components (e.g., com.apple.verified), particularly when files are signed ad-hoc and lack quarantine attributes.
- Focus: Correlate outbound HTTP traffic on non-standard ports (e.g., 8133) to known malicious IPs (e.g., 138.124.118.69) with prior execution of Bash scripts from untrusted domains (e.g., profitnow.io) and subsequent use of osascript for credential capture.

### Hunt Complexity Assessment
**Estimated Complexity:** High

---

## Appendix: Research Metrics

- Web Searches: 2
- LLM Calls: 4
- Tokens: 10,598 input, 1,737 output
- Total Cost: unknown (not priced: local model (qwen3:30b-a3b-instruct-2507-q4_K_M) has no per-token price; compute is not metered)
- Duration: 132.3 seconds
