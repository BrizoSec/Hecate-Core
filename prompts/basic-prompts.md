# Basic Hunt Prompts

---

## Section 1: Generate Hypothesis

### Prompt Template

```
You are a threat hunting expert helping generate behavior-based hunt hypotheses.

CONTEXT:
[Paste your context here - CTI snippet, alert, baseline drift, or gap]

RULES:
1. Generate 1-3 tightly scoped hypotheses
2. Each hypothesis must follow this pattern: "Adversaries use [behavior] to [goal] on [target]"
3. Focus on observable behaviors in data, not indicators
4. Include relevant ATT&CK technique (T####)
5. Keep hypotheses specific and testable

OUTPUT FORMAT:
For each hypothesis provide:
- Hypothesis statement
- ATT&CK Technique
- Tactic
- Data sources needed (e.g., "Windows Event Logs, Sysmon")
- Why this is worth hunting now

EXAMPLE OUTPUT:
Hypothesis: "Adversaries use base64-encoded PowerShell commands to establish persistence on Windows servers"
ATT&CK: T1059.001 (PowerShell)
Tactic: TA0003 (Persistence)
Data Needed: Sysmon Event ID 1, PowerShell logs
Why Now: Recent CTI shows APT29 using this technique; baseline shows low historical usage on servers

Generate hypothesis now:
```

---

## Section 2: Build Query

### Prompt Template

```
You are a threat hunting query expert. Help me write a safe, bounded query to test a hunt hypothesis.

HYPOTHESIS:
[Your hypothesis here]

PLATFORM: [Splunk / KQL (Sentinel/Defender) / Elastic]

DATA AVAILABLE:
- Index/Table: [name]
- Sourcetype/DataSource: [name]
- Key fields: [list]

CONSTRAINTS:
1. Time range: earliest=-24h latest=now (adjust as needed)
2. Result cap: head 1000 (or | take 1000 for KQL)
3. Use tstats (Splunk) or summarize (KQL) when possible for performance
4. Include metadata comments with hunt ID and ATT&CK technique
5. Return only essential fields
6. Add eval/extend to tag results with hunt_id and attack_technique

OUTPUT FORMAT:
Provide:
1. The complete query
2. Brief explanation of what it does
3. Expected runtime estimate
4. Suggestions for tuning if results are too noisy

Generate query now:
```

### Query Templates

**Splunk SPL:**

```spl
/* H-#### | ATT&CK: T#### | Purpose: [description]
   Earliest: -24h | Latest: now | Cap: 1000 | Owner: [name] */

| tstats count from datamodel=YourDataModel where
  [your conditions]
  by _time, host, [key_fields] span=5m
| head 1000
| eval hunt_id="H-####", attack_technique="T####"
| fields _time, host, [relevant_fields], hunt_id, attack_technique
```

**KQL:**

```kql
// H-#### | ATT&CK: T#### | Purpose: [description]
// TimeRange: ago(24h) | Cap: 1000 | Owner: [name]

YourTable
| where TimeGenerated >= ago(24h)
| where [your conditions]
| summarize Count=count() by bin(TimeGenerated, 5m), Computer, [key_fields]
| take 1000
| extend HuntId="H-####", AttackTechnique="T####"
```
---

## Section 3: Document Results

### Prompt Template

```
You are a threat hunting analyst helping document hunt results following the LOCK pattern.

HYPOTHESIS:
[Your hypothesis]

QUERY EXECUTED:
[Paste query]

RESULTS SUMMARY:
- Time range: [earliest to latest]
- Rows examined: [count]
- Rows returned: [count]
- Runtime: [seconds]
- Key findings: [brief description of what you found]

RAW OBSERVATIONS:
[Paste sample results or describe what you saw]

TASK:
Write a concise summary for the KEEP section of my hunt file.
Focus on:
- What we found (2-4 sentences)
- Decision (accept/reject/needs_changes) with reason
- Next steps (one concrete action)
- Lessons learned (one key takeaway)

Keep it to 5-8 sentences total.

Generate summary now:
```
