---
research_id: R-0616
topic: Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files
mitre_techniques: []
status: completed
depth: advanced
duration_minutes: 2.4
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

# R-0616: Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files Research

**Topic:** Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files
**Duration:** 2.4 minutes

---

## 1. System Research: How It Works

### Summary
Redis instances exposed to the internet without authentication are exploited via rogue replication to inject a malicious RDB blob into the victim's /etc/cron.d/.redis-miner file, which executes a persistent cron job. This job downloads and runs the XMRig cryptominer from GitHub, connecting to the Monero mining pool at pool.moneroocean.stream:443 over TLS, while also periodically pinging a C2 server at 188.245.99.156:10000 for command and control persistence.

### Key Findings
- The malicious payload is delivered via a crafted RDB blob written to /etc/cron.d/.redis-miner, which is executed by the system's cron daemon as a legitimate-looking persistence mechanism.
- The XMRig miner is downloaded from the official GitHub release page (https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-linux-static-x64.tar.gz), avoiding direct connections to attacker infrastructure and evading egress monitoring.
- Persistence is maintained through periodic HTTP GET requests to 188.245.99.156:10000 with a token (f90c8b1dcd374d4f552744ee1765583d) in the query string, logged in a local SQLite database (c2_persist.db) on the attacker's side.
- The operator uses a hardcoded QA target (47.250.92.230) across multiple scripts for testing, indicating a repeatable and methodical deployment process.
- The attack chain is initiated via Redis replication commands (PING, REPLCONF, PSYNC), mimicking legitimate replica behavior, which allows the attacker to inject the malicious RDB without triggering immediate detection.

### Sources
- [🚨 Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/redis-cryptomining-botnet-compromised-3562-servers-exposed-by-the-operators-own-files-93e528b1783eb7fa)
- [Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files | Cyber Hub](https://www.cyberhub.blog/article/31843-redis-cryptomining-botnet-compromised-3562-servers-exposed-by-the-operators-own-files)
- [Redis Botnet Hijacks 3,562 Servers, Operator Files Expose Toolkit — GetKhojo](https://getkhojo.com/blog/redis-botnet-hijacks-3-562-servers-operator-files-expose-toolkit)
- [Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/redis-cryptomining-botnet-compromised-3562-servers-exposed-by-the-operators-own-files-3eabca6a23483e81)
- [Redis Cryptomining Botnet Hits 3,562 Servers](https://securityonline.info/redis-cryptomining-botnet)

---

## 2. Adversary Tradecraft: Attack Techniques

### Summary
Adversaries exploited unauthenticated Redis instances by leveraging rogue replication to inject malicious cron jobs, deploying XMRig cryptominers to mine Monero. The attack was enabled by widespread misconfiguration rather than software vulnerabilities, with the operator's own exposed toolkit revealing campaign logs, scripts, and infrastructure details.

### Key Findings
- The attack used rogue Redis replication to deliver a crafted RDB blob, which was written to /etc/cron.d/.redis-miner on victim systems, enabling persistence and execution of the miner.
- The payload used a legitimate, unmodified XMRig binary from github.com/xmrig/xmrig, downloaded over TLS to avoid detection and reduce the attacker's hosting footprint.
- The operator's infrastructure included a C2 server at 188.245.99.156, with a token-protected endpoint (188.245.99.156:10000) used for callback pings, logged in a SQLite database (c2_persist.db).
- The attack targeted 12,966 Redis hosts, with 3,562 confirmed compromises; the operator reused a QA target (47.250.92.230) across multiple scripts for testing and campaign execution.
- The attacker's toolkit included Python scripts (e.g., redis_bgsave_test.py, deploy_all.py) and encoded payloads (e.g., exploit_wp.py, exploit_wp2.py) that used obfuscation techniques like chained chr() calls to evade detection.
- Indicators include the MD5 and SHA256 hashes of the C2 token (f90c8b1dcd374d4f552744ee1765583d and 420c7850e09b7c2b9e39e2a93e204e3c56bcf08a685ff1daa986e3c348da5d2a), the C2 IP (188.245.99.156), and the domain socket.ayakliborsa.net, which resolved to the same IP.

### Sources
- [🚨 Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/redis-cryptomining-botnet-compromised-3562-servers-exposed-by-the-operators-own-files-93e528b1783eb7fa)
- [Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files | Cyber Hub](https://www.cyberhub.blog/article/31843-redis-cryptomining-botnet-compromised-3562-servers-exposed-by-the-operators-own-files)
- [Threats Tagged 'redis' | Threat Radar](https://radar.offseq.com/threats?tag=redis)
- [Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files | Community Portal | Gurucul](https://community.gurucul.com/articles/ThreatResearch/Redis-Cryptomining-Botnet-Compromised-9-9-2026)
- [Redis Botnet Hijacks 3,562 Servers, Operator Files Expose Toolkit — GetKhojo](https://getkhojo.com/blog/redis-botnet-hijacks-3-562-servers-operator-files-expose-toolkit)
- [Redis Cryptomining Botnet Hits 3,562 Servers](https://securityonline.info/redis-cryptomining-botnet)
- [Week 37 – 2026 – This Week In 4n6](https://thisweekin4n6.com/2026/09/13/week-37-2026)

---

## 3. Telemetry Mapping: OCSF Fields

### Summary
The source intelligence describes adversary behavior involving the exploitation of unauthenticated Redis instances via rogue replication to inject malicious cron jobs, deploy XMRig cryptominers, and maintain persistence. The attacker uses a staged delivery mechanism involving RDB blob injection into /etc/cron.d/, executes a Python-based C2 persistence script, and downloads XMRig from GitHub. The behavior includes initial access through Redis misconfiguration, persistence via cron, command and control over HTTP, and payload execution. These actions are detectable through file, process, network, and system telemetry.

### Key Fields

OCSF path → the event field `knowledge/environment.md` documents for it.

- `file.path` → unmapped: the environment profile documents no field: /etc/cron.d/.redis-miner — Indicates malicious persistence via cron job injection, a hallmark of cron-injection technique.
- `process.cmd_line` → `command_line` (Endpoint): crontab -l or crontab -e — Reflects user or system-level cron configuration changes, consistent with post-exploitation persistence.
- `network_endpoint.ip` → `dest_ip` / `src_ip` (Network; destination / source endpoint): 188.245.99.156 — Primary C2 server IP used to deliver RDB blobs and receive beaconing data from compromised hosts.
- `network_endpoint.port` → `dest_port` / `src_port` (Network; destination / source endpoint): 10000 — Port used by the C2 persistence script (c2_persist.py) for beaconing, indicating ongoing C2 communication.
- `file.path` → unmapped: the environment profile documents no field: /tmp/.xmrig — Indicates execution of a dynamically downloaded XMRig miner binary, a key sign of cryptomining payload deployment.
- `process.name` → `process_name` (Endpoint): python.exe — Used to execute attacker-controlled scripts (e.g., c2_persist.py, deploy_all.py), indicating malicious process execution.

### Data Source Availability

- Process Execution: Documented in the environment profile
- File Operations: Documented in the environment profile
- Network Connections: Documented in the environment profile
- Registry Events: Unknown: not documented in the environment profile

---

## 4. Related Work: Past Hunts

### Summary
No related hunts found for Redis Cryptomining Botnet Compromised 3,562 Servers, Exposed by the Operator's Own Files - this may be a new research area

### Related Hunts
- No related past hunts found

---

## 5. Research Synthesis

### Executive Summary
Adversaries exploit unauthenticated Redis instances via rogue replication to inject a malicious RDB blob into /etc/cron.d/.redis-miner, enabling persistent execution of a legitimate XMRig miner downloaded from GitHub. The payload establishes C2 persistence through token-protected HTTP beaconing to 188.245.99.156:10000, with the operator’s own infrastructure revealing a staged, repeatable campaign using hardcoded QA targets and Python-based tooling.

### Recommended Hypothesis
> Adversaries use rogue Redis replication to inject malicious RDB blobs into /etc/cron.d/ files to achieve persistence and deploy XMRig cryptominers via legitimate GitHub downloads, while maintaining C2 via token-protected HTTP beaconing to 188.245.99.156:10000.

### Gaps Identified
- The use of legitimate GitHub domains for payload delivery (e.g., github.com/xmrig/xmrig) and TLS-encrypted connections to pool.moneroocean.stream:443 obscures the malicious payload from egress monitoring and deep packet inspection, limiting visibility into command and control traffic.
- The malicious cron job is written to a system-level cron directory with a legitimate-looking filename (.redis-miner), which is not currently mapped in endpoint telemetry for file path-based detection, creating a blind spot in host-based monitoring.

### Key Findings
- Hypothesis: Adversaries use rogue Redis replication to inject malicious RDB blobs into /etc/cron.d/ files to achieve persistence and deploy XMRig cryptominers via legitimate GitHub downloads, while maintaining C2 via token-protected HTTP beaconing to 188.245.99.156:10000.
- Gap: The use of legitimate GitHub domains for payload delivery (e.g., github.com/xmrig/xmrig) and TLS-encrypted connections to pool.moneroocean.stream:443 obscures the malicious payload from egress monitoring and deep packet inspection, limiting visibility into command and control traffic.
- Gap: The malicious cron job is written to a system-level cron directory with a legitimate-looking filename (.redis-miner), which is not currently mapped in endpoint telemetry for file path-based detection, creating a blind spot in host-based monitoring.
- Focus: Implement file integrity monitoring (FIM) on /etc/cron.d/ and detect unexpected writes to system cron directories, especially with non-standard filenames or content patterns.
- Focus: Monitor for outbound HTTP GET requests to 188.245.99.156:10000 with query strings containing the MD5 token f90c8b1dcd374d4f552744ee1765583d, particularly from Linux systems with no prior outbound traffic to that IP.
- Focus: Correlate Redis server exposure (port 6379 or 16379-16385) with subsequent execution of Python scripts that download from github.com/xmrig/xmrig, especially when followed by cron job creation and XMRig process execution.

### Hunt Complexity Assessment
**Estimated Complexity:** High

---

## Appendix: Research Metrics

- Web Searches: 2
- LLM Calls: 4
- Tokens: 13,215 input, 1,742 output
- Total Cost: unknown (not priced: local model (qwen3:30b-a3b-instruct-2507-q4_K_M) has no per-token price; compute is not metered)
- Duration: 142.5 seconds
