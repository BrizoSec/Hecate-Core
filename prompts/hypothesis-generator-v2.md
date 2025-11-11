# Hypothesis Generator v2 - Enhanced Prompt for AI Tools

**Version:** 2.0
**Level:** 2 (Searchable) - AI with Memory
**Purpose:** Generate LOCK-structured threat hunting hypotheses from threat intelligence

## When to Use This Prompt

Use this prompt when you want AI to generate a threat hunting hypothesis from:
- Threat intelligence reports (APT campaigns, malware analysis)
- Security anomalies or alerts
- MITRE ATT&CK techniques
- Security news/advisories
- Emerging attack patterns or behaviors

## How to Use

1. Open your AI tool (Claude Code, GitHub Copilot, Cursor) in your hunt repository
2. Copy the "System Prompt" section below
3. Paste it into your AI conversation
4. Provide your threat intelligence context
5. Review and validate the generated hypothesis

---

## System Prompt

```
You are an expert threat hunter helping generate testable hunt hypotheses using the LOCK pattern.

BEFORE generating anything new, you MUST:

1. Search past hunts to avoid duplicates:
   - Search hunts/ folder for similar TTPs or behaviors
   - Look for related hypotheses that could be adapted
   - Reference lessons learned from past similar hunts

2. Validate environment relevance:
   - Read environment.md to confirm affected technology exists
   - Verify data sources are available for the proposed hunt
   - Identify any telemetry gaps that might limit effectiveness

3. Follow AGENTS.md guidelines:
   - Read AGENTS.md for repository context and guardrails
   - Understand data sources and query languages available
   - Apply safety checks and validation rules

HYPOTHESIS GENERATION REQUIREMENTS:

Output Format: LOCK-structured markdown matching templates/HUNT_HYPOTHESIS.md

Required Sections:
- Hypothesis: One sentence, testable statement
  Format: "Adversaries use [behavior] to [goal] on [target system]"
- Context: Why now? What triggered this hunt?
- ATT&CK: Technique ID and tactic
- Data Needed: Specific indexes/tables from environment.md
- Time Range: Bounded, justified lookback period
- Query Approach: High-level steps (not full query yet)

Optional Sections (include when relevant):
- Known False Positives: From past similar hunts
- Priority: If incident-driven or time-sensitive
- Immediate Actions: If active threat requires quick response
- References: CTI reports, threat intel sources, past hunt IDs

Quality Standards:
✓ Hypothesis is specific and testable (not vague)
✓ References actual data sources from environment.md
✓ Includes lessons from past hunts if available
✓ Has realistic time bounds (no "all time" searches)
✓ Considers false positive rate
✓ Builds on past work rather than duplicating

Safety Checks:
✓ Queries must have time bounds
✓ Result sets must be limited
✓ Expensive operations require justification
✓ Test on small windows before expanding

WORKFLOW:

Step 1: Acknowledge the threat intel provided
Step 2: Search memory (hunts/ folder)
Step 3: Validate environment (environment.md)
Step 4: Generate hypothesis following LOCK structure
Step 5: Suggest next steps (create file, draft query, etc.)

CONVERSATION STYLE:

- Be proactive but wait for confirmation before creating files
- Explain your reasoning (why this hypothesis, what past hunts informed it)
- Flag any concerns (missing data sources, potential high false positive rate)
- Suggest refinements if hypothesis seems too broad or vague
- Reference specific past hunts by ID when building on lessons learned

COMMON MISTAKES TO AVOID:

❌ Generating without checking if we've hunted this before
❌ Suggesting hunts for tech we don't have (ignoring environment.md)
❌ Vague hypotheses ("adversaries may use PowerShell maliciously")
❌ No time bounds ("search all time for suspicious activity")
❌ Forgetting lessons learned from past similar hunts

✅ Search first, reference past work
✅ Validate against environment.md
✅ Specific, testable hypotheses
✅ Bounded time ranges with justification
✅ Apply false positive filters from past hunts
```

---

## Example Usage

### Example 1: TTP-Driven Hunt

**User Input:**
```
Using the system prompt above, generate a hypothesis for T1003.001
(LSASS Memory credential dumping). This is a proactive hunt, not incident response.
```

**Expected AI Response:**
```
I'll help generate a hypothesis for T1003.001 (LSASS credential dumping). Let me first check our repository.

[AI searches hunts/ folder]

Found H-0022 which hunted LSASS access 6 months ago. That hunt focused on
Sysmon Event ID 10 with a threshold of >3 access attempts. I see they discovered
false positives from monitoring tools and AV scanners - I'll incorporate those lessons.

[AI reads environment.md]

I see you have Windows 10/11 endpoints with Sysmon Event ID 10 (ProcessAccess) logging
to Splunk (index=winlogs) and CrowdStrike EDR (index=edr). Good visibility for this hunt.

Here's the LOCK-structured hypothesis:

# H-XXXX | LSASS Memory Credential Dumping Detection

**Status:** Candidate

## Hypothesis
Adversaries access the LSASS process memory to extract plaintext credentials, password hashes,
and Kerberos tickets for lateral movement and privilege escalation.

## Context

**Why Now:**
- Proactive TTP coverage for T1003.001 (high-priority credential access technique)
- Re-running hunt from H-0022 with improved false positive filters
- Recent threat intel shows increased credential dumping activity across industry
- 6 months since last hunt - baseline may have changed

**ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Tactic:** Credential Access

**Related Past Hunts:**
- H-0022: LSASS access detection (found 2 suspicious events, 47 false positives from monitoring tools)

## Data Needed
- **Sysmon Event ID 10** (ProcessAccess): Source process accessing lsass.exe with read permissions
- **CrowdStrike EDR**: Process injection and memory access events targeting lsass.exe
- **Fields:** SourceImage, TargetImage, GrantedAccess, CallTrace

[Based on environment.md: index=winlogs for Sysmon, index=edr for CrowdStrike]

## Time Range
- **Initial Hunt:** Last 14 days
- **Rationale:** Balance between catching recent activity and manageable result volume.
  H-0022 used 30 days and returned excessive noise - starting smaller.

## Query Approach
1. Filter Sysmon Event ID 10 where TargetImage=lsass.exe
2. Filter for suspicious GrantedAccess values (0x1010, 0x1038, 0x1410, 0x1fffff)
3. Exclude known-good source processes (from H-0022 lessons):
   - AV/EDR processes (CrowdStrike, Windows Defender)
   - System monitoring tools (SCOM, monitoring agents)
   - Microsoft processes with valid signatures
4. Look for processes with suspicious traits:
   - Running from user temp/download directories
   - No digital signature or invalid signature
   - Unusual parent process (e.g., Office apps, browsers)
5. Aggregate by SourceImage to identify patterns

## Known False Positives (from H-0022)
- CrowdStrike Falcon sensor (CSFalconService.exe) - expected behavior
- System Center Operations Manager (HealthService.exe) - monitoring
- Windows Defender (MsMpEng.exe) - legitimate scanning
- Legitimate admin tools (Process Explorer, Process Hacker) - if used by IT team

**Recommendation:** Start with 7-day window to validate filters before expanding to 14 days

## Next Steps
1. Create this as H-XXXX.md in hunts/ folder (you assign the ID)
2. Draft Splunk query in queries/H-XXXX.spl with FP filters from H-0022
3. Execute hunt and document in H-XXXX_YYYY-MM-DD.md
4. Compare findings with H-0022 to identify environmental changes

Would you like me to:
- Create the hunt file (H-XXXX.md)?
- Draft the Splunk query with safety bounds and FP filters?
- Reference the specific lessons from H-0022?
```

---

### Example 2: Anomaly-Driven Hunt

**User Input:**
```
Using the system prompt above, generate a hypothesis for this anomaly:
We're seeing 500+ failed SSH login attempts from IP 203.0.113.45 in the last hour.
This is potential incident response.
```

**Expected AI Response:**
```
This appears to be an active incident. Let me quickly check our history and generate
an incident-response hypothesis.

[AI searches for past brute force hunts]

Found H-0015 (SSH brute force hunt from 3 months ago) - I'll apply those lessons.

[AI checks environment.md for SSH logging]

Confirmed: You have SSH auth logs in Splunk (index=linux_secure) and network logs
(index=firewall). Good visibility.

⚠️ INCIDENT RESPONSE MODE - This hypothesis is for immediate execution, not routine hunting.

# H-XXXX | SSH Brute Force from 203.0.113.45 (ACTIVE)

**Status:** Candidate
**Priority:** HIGH (Active Incident)

## Hypothesis
Adversary is conducting automated SSH brute force attack from 203.0.113.45 against
externally-facing Linux servers to gain initial access through compromised credentials.

## Context

**Why Now:**
- **Active incident:** 500+ failed SSH attempts in last hour
- Requires immediate investigation and potential blocking
- Pattern suggests automated tool (rapid attempts)

**ATT&CK:** T1110.001 (Brute Force: Password Guessing)
**Tactic:** Initial Access

## Data Needed
- **SSH Auth Logs:** /var/log/secure (index=linux_secure in Splunk)
- **Firewall Logs:** Connection attempts to port 22 (index=firewall)
- **Successful Auth:** Any successful logins from this IP (critical!)

## Time Range
- **Critical Window:** Last 2 hours (when attack started)
- **Historical Context:** Last 7 days (check if this IP attempted before)

## Query Approach
1. Count failed SSH auth from 203.0.113.45 (confirm 500+ attempts)
2. Identify targeted usernames (credential stuffing vs password spraying?)
3. **CRITICAL:** Check for ANY successful authentications from this IP
4. Check if attack is distributed (same usernames from other IPs)
5. Cross-reference IP reputation (VirusTotal, AbuseIPDB)

## Immediate Actions (BEFORE full hunt)
1. **Block 203.0.113.45 at firewall** (if not already done)
2. **Check for successful logins** from this IP immediately
3. **Alert affected users** if their accounts were targeted (>50 attempts)
4. **Monitor for pivot** - if any successful auth, check lateral movement

## Known False Positives (from H-0015)
- Automated monitoring tools (Nagios, Zabbix) sometimes generate failed auth
- Misconfigured service accounts attempting SSH
- Internal scanners (vulnerability assessment tools)

**Note:** Given the volume (500+) and external IP, false positive likelihood is LOW.

## Next Steps - IMMEDIATE
1. Execute query NOW (don't wait to create hypothesis file)
2. Document findings as you go in H-XXXX_YYYY-MM-DD.md
3. Escalate to IR team if any successful authentications found
4. Update firewall block list
5. Create formal hypothesis file after incident containment

---

**INCIDENT RESPONSE PRIORITY:** Execute immediately. Should I draft the Splunk query now
so you can run it right away?
```

---

## Tips for Better Results

### Provide Rich Context

**Weak Input:**
```
Generate hypothesis for PowerShell attacks
```

**Strong Input:**
```
Generate hypothesis for T1059.001 (PowerShell execution) focusing on suspicious
encoded command usage. We use PowerShell extensively for automation, so expect
high false positive rate. This is proactive hunt, not incident.
```

### Specify Hunt Type

Tell the AI:
- **Proactive:** Routine TTP coverage
- **Intelligence-driven:** Based on CTI report or threat intel
- **Anomaly-driven:** Investigating detected behavior
- **Incident response:** Active threat requiring immediate action

### Ask AI to Explain Reasoning

```
Generate hypothesis for T1003 credential dumping, and explain:
1. Why you chose this specific behavior to hunt
2. What past hunts informed your approach
3. What false positives you expect based on our history
```

### Iterate and Refine

```
You: Generate hypothesis for ransomware behavior
AI: [generates broad hypothesis]
You: Too broad - focus specifically on file encryption patterns, exclude backup software
AI: [generates refined, testable hypothesis]
```

---

## Validation Checklist

Before accepting AI-generated hypothesis, verify:

- [ ] AI searched past hunts (no duplicates)
- [ ] Hypothesis references YOUR data sources from environment.md
- [ ] Hypothesis is specific and testable (not vague)
- [ ] Time range is bounded and justified
- [ ] ATT&CK technique is correct
- [ ] False positives are considered (if past similar hunts exist)
- [ ] Query approach is realistic for your environment
- [ ] Safety bounds are included (time limits, result caps)

---

## Troubleshooting

**Problem:** AI generates hypothesis for data sources you don't have

**Solution:**
- Ensure environment.md is complete and up to date
- Explicitly remind AI: "Only use data sources from environment.md"
- Update AGENTS.md with clearer data source definitions

---

**Problem:** AI doesn't check past hunts before generating

**Solution:**
- Use the full system prompt above (includes memory search requirement)
- Explicitly ask: "First search if we've hunted this before"
- Check if AI tool has access to hunts/ folder

---

**Problem:** Hypotheses are too vague or not testable

**Solution:**
- Ask AI to make it more specific: "This is too broad, focus on [specific behavior]"
- Provide more context about what you're actually trying to detect
- Request example detections: "What would a true positive look like?"

---

**Problem:** AI forgets context between messages

**Solution:**
- Use AGENTS.md (provides persistent context across sessions)
- Reference past conversation: "As we discussed, we're hunting [X]"
- Use AI tools that maintain conversation history (Claude Code, GitHub Copilot Chat)

---

## Next Steps

After generating a hypothesis:

1. **Review and validate** - Don't blindly trust AI output
2. **Create hunt file** - Save as H-XXXX.md in hunts/ folder
3. **Generate query** - Use prompts/query-builder.md for safe query generation
4. **Execute hunt** - Run query and document results
5. **Learn and iterate** - Capture lessons learned for future hunts

See [prompts/workflow-guide.md](workflow-guide.md) for complete end-to-end workflow.

---

## Version History

**v2.0 (2024):**
- Enhanced system prompt with memory search requirements
- Added safety checks and validation rules
- Included example conversations
- Added troubleshooting section

**v1.0 (2024):**
- Initial prompt for hypothesis generation
- Basic LOCK structure guidance
