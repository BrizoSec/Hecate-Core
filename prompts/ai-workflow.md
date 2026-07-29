# AI-Assisted Threat Hunting Workflow
---

## System Prompt for AI Tools

When starting a hunting session, provide this context to your AI assistant:

```
You are an expert threat hunter helping generate testable hunt hypotheses using the LOCK pattern.

BEFORE generating anything new, you MUST:

0. Load hunting brain knowledge:
   - Read knowledge/hunting-knowledge.md for expert hunting knowledge
   - Internalize Section 1 (Hypothesis Generation) and Section 5 (Pyramid of Pain)
   - Apply behavioral models from Section 2 (ATT&CK TTP → Observables)
   - All hunts MUST focus on behaviors/TTPs (top of Pyramid of Pain), never just hashes/IPs

TOOLS AVAILABLE:
   - If athf CLI installed: Use `athf hunt` commands for search, create, list, stats
   - If CLI unavailable: Use grep across hunts/ folder
   - Check availability: `athf --version`
   - Never fail workflow if CLI unavailable - always have fallback

1. Search past hunts to avoid duplicates:
   - Search hunts/ folder for similar TTPs or behaviors
   - Reference lessons learned from past similar hunts
   - Apply false positive filters from past work

2. Validate environment relevance:
   - Read environment.md to confirm affected technology exists
   - Verify data sources are available for the proposed hunt
   - Identify any telemetry gaps

3. Follow repository guidelines:
   - Read AGENTS.md for repository context and guardrails
   - Understand data sources and query languages available
   - Apply safety checks and validation rules

HYPOTHESIS GENERATION REQUIREMENTS:

Output Format: LOCK-structured markdown matching templates/HUNT_LOCK.md

Required Sections:
- Hypothesis: One sentence, testable statement
  Format: "Adversaries use [behavior] to [goal] on [target system]"
- Context: Why now? What triggered this hunt?
- ATT&CK: Technique ID and tactic
- Data Needed: Specific indexes/tables from environment.md
- Time Range: Bounded, justified lookback period
- Query Approach: High-level steps

Quality Standards (from hunting-knowledge.md Section 1):
✓ Hypothesis is specific and testable (not vague)
✓ Falsifiable - Can be proven true or false with data
✓ Scoped - Bounded by target, timeframe, or behavior
✓ Observable - Tied to specific log sources and fields
✓ Actionable - Can inform detection or response
✓ Contextual - References environment, threat landscape, or business risk
✓ Focuses on BEHAVIOR/TTP (top of Pyramid of Pain), not indicators
✓ References actual data sources from environment.md
✓ Includes lessons from past hunts if available
✓ Has realistic time bounds (no "all time" searches)
✓ Considers false positive rate
✓ Builds on past work rather than duplicating

Safety Checks:
✓ Queries must have time bounds
✓ Result sets must be limited
✓ Test on small windows before expanding

WORKFLOW:
1. Consult hunting brain (knowledge/hunting-knowledge.md) - Load relevant sections
2. Acknowledge the threat intel or context provided
3. Search memory (hunts/ folder) for similar past work
4. Validate environment (environment.md)
5. Apply Pyramid of Pain - Ensure hypothesis targets behaviors/TTPs, not indicators
6. Generate hypothesis following LOCK structure with quality criteria
7. Apply analytical rigor - Check for biases, score confidence appropriately
8. Suggest next steps

CONVERSATION STYLE:
- Be proactive but wait for confirmation before creating files
- Explain your reasoning
- Flag concerns (missing data sources, high FP rate potential)
- Reference specific past hunts by ID when building on lessons learned
```

---

## Quick Start Workflows

### Workflow 1: Threat Intel-Driven Hunt (Most Common)

**Scenario:** You receive threat intelligence about adversary TTPs
**Total Time:** 5-10 minutes

**Step 1: Check Memory (2 min)**

**With CLI:**
```
You: "Check if we've hunted T1003.001 before:
athf hunt search 'T1003.001'
athf hunt list --technique T1003.001
Summarize lessons learned from results."
```

**Without CLI:**
```
You: "Check if we've hunted T1003.001 (LSASS credential dumping) before.
Search hunts/ folder for this TTP and any related credential dumping hunts.
Summarize lessons learned."
```

**Step 2: Validate Environment (1 min)**

```
You: "Read environment.md and tell me:
1. Do we have visibility into this behavior?
2. What data sources can we use?
3. Any telemetry gaps?"
```

**Step 3: Generate Hypothesis (2 min)**

```
You: "Generate a LOCK-structured hypothesis for T1003.001.
Use the system prompt above. This is a proactive hunt."
```

**Review checklist:**

- [ ] Hypothesis is testable and specific
- [ ] Data sources match environment.md
- [ ] Time range is reasonable
- [ ] ATT&CK mapping is correct

**Step 4: Create Hunt File (1 min)**

**With CLI:**
```
You: "Create this hypothesis using:
athf hunt new --technique T1003.001 --title 'LSASS Credential Dumping Detection'
Then review and edit the generated file as needed."
```

**Without CLI:**
```
You: "Create this hypothesis as H-XXXX.md in hunts/ folder.
Use the next available hunt number."
```

**Step 5: Generate Query (2-3 min)**

```
You: "Generate a Splunk query with:
- Time bounds (last 14 days)
- Result limits (head 1000)
- False positive filters from past hunts
- Save as queries/H-XXXX.spl"
```

---

### Workflow 2: Anomaly Investigation (Fast Response)

**Scenario:** SOC alerts you to unusual behavior
**Total Time:** 3-5 minutes

**Quick Response Steps:**

**1. Rapid Context (1 min)**

```
You: "Search past hunts for [behavior/TTP].
What have we learned about false positives?"
```

**2. Incident Hypothesis (2 min)**

```
You: "Generate incident-response hypothesis for:
[paste anomaly description]
Mark as HIGH priority, active investigation."
```

**3. Immediate Query (1 min)**

```
You: "Draft query for last 24 hours with these IOCs:
[paste indicators]
This is incident response - make it fast."
```

**4. Document As You Go**

```
You: "Summarize these results in LOCK format for the KEEP section of H-XXXX.md"
```

---

### Workflow 3: Proactive TTP Coverage

**Scenario:** Monthly hunt plan, covering MITRE ATT&CK techniques
**Total Time:** 10-15 minutes

**Step 1: Coverage Gap Analysis (3 min)**

```
You: "Analyze past hunts and tell me:
1. Which tactics have we hunted most/least?
2. What high-priority TTPs have we never covered?
3. Suggest 3 hunts to improve ATT&CK coverage
Consider our environment from environment.md."
```

**Step 2: Select TTP and Research (2 min)**

```
You: "I want to hunt T1003 (Credential Dumping).
Search past hunts for:
1. What sub-techniques we've covered
2. What we haven't covered
3. Lessons about false positives"
```

**Step 3: Generate and Review (5 min)**

Follow Workflow 1 steps 3-5, then:

```
You: "Review this hypothesis and critique:
1. Is it testable? Too vague?
2. High false positive risk?
3. Is the time range appropriate?
4. What could go wrong?"
```

Iterate based on feedback.

---

### Workflow 4: Post-Hunt Documentation

**Scenario:** You've executed a hunt and have results
**Total Time:** 5-7 minutes

**Step 1: Results Summarization (3 min)**

```
You: "Analyze these query results from H-XXXX:
1. Summary of findings (patterns, counts)
2. True positives vs false positives
3. Interesting anomalies worth investigating
4. Recommended next actions

[paste query output - first 100 rows if large]"
```

**Step 2: Update Hunt File (2 min)**

```
You: "Update H-XXXX.md KEEP section with:
- Query details (runtime, rows returned)
- Findings summary
- Status: [Completed|Needs Changes]
- Lessons learned"
```

**Step 3: Apply Lessons (1 min)**

```
You: "Based on these results, what changes would improve this hunt?
Should we update the hypothesis or query filters?"
```

---

## Example: Complete Hunt Conversation

This example shows how AI searches memory, validates environment, and generates a hypothesis.

**User:**

```
Using the system prompt, generate a hypothesis for T1003.001
(LSASS Memory credential dumping). This is a proactive hunt.
```

**AI Response:**

```
I'll help generate a hypothesis for T1003.001. Let me first consult the hunting brain and check our repository.

[Reads .claude/hunting-knowledge.md Section 1 and Section 2]

From hunting brain - Key principle: Focus on BEHAVIOR (LSASS process access pattern),
not indicators. T1003.001 maps to observable: Sysmon Event 10 ProcessAccess to lsass.exe
with specific GrantedAccess values (0x1010, 0x1038, 0x1410, 0x1fffff). This is top of
Pyramid of Pain (TTP level) - adversary can't easily change this behavior.

[Searches hunts/ folder]

Found H-0022 which hunted LSASS access 6 months ago. That hunt focused on
Sysmon Event ID 10 with a threshold of >3 access attempts. They discovered
false positives from monitoring tools and AV scanners - I'll incorporate those lessons.

[Reads environment.md]

I see you have Windows endpoints with Sysmon Event ID 10 (ProcessAccess) logging
to Splunk (index=winlogs) and CrowdStrike EDR. Good visibility for this hunt.

Here's the LOCK-structured hypothesis:

# H-XXXX | LSASS Memory Credential Dumping Detection

**Status:** Planning

## LEARN: Prepare the Hunt

### Hypothesis Statement
Adversaries access the LSASS process memory to extract plaintext credentials,
password hashes, and Kerberos tickets for lateral movement and privilege escalation.

### Context
**Why Now:**
- Proactive TTP coverage for T1003.001 (high-priority credential access technique)
- Re-running hunt from H-0022 with improved false positive filters
- 6 months since last hunt - baseline may have changed

**ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Tactic:** Credential Access

**Related Past Hunts:**
- H-0022: LSASS access detection (found 2 suspicious events, 47 false positives from monitoring tools)

### ABLE Scoping
| Field | Your Input |
|-------|-----------|
| **Behavior** | Process access to lsass.exe with read/write permissions (GrantedAccess: 0x1010, 0x1038, 0x1410, 0x1fffff) |
| **Location** | Windows endpoints, focus on servers |
| **Evidence** | **Source:** Sysmon Event ID 10 (ProcessAccess), CrowdStrike EDR<br>**Key Fields:** SourceImage, TargetImage, GrantedAccess, CallTrace<br>**Example:** Unsigned process from temp directory accessing lsass.exe with 0x1010 permissions |

## OBSERVE: Expected Behaviors
Legitimate LSASS access occurs from:
- AV/EDR tools (CrowdStrike, Windows Defender)
- System monitoring (SCOM agents)
- Signed Microsoft processes

Suspicious indicators:
- Access from user temp/download directories
- Missing or invalid digital signatures
- Unusual parent process (Office apps, browsers)
- Outside business hours

## CHECK: Execute & Analyze

### Hunting Queries
```spl
/* H-XXXX | T1003.001 | LSASS Memory Access Detection */

index=winlogs sourcetype=sysmon EventCode=10
TargetImage="*\\lsass.exe"
(GrantedAccess=0x1010 OR GrantedAccess=0x1038 OR GrantedAccess=0x1410 OR GrantedAccess=0x1fffff)
| search NOT [| inputlookup known_good_lsass_access.csv | fields SourceImage]
| eval suspicious_path=if(match(SourceImage, "(?i)(temp|download|appdata\\\\local)"), "Yes", "No")
| stats count by SourceImage, TargetImage, GrantedAccess, suspicious_path
| where suspicious_path="Yes" OR count > 10
| head 1000
```

**Time Range:** Last 14 days
**Rationale:** H-0022 used 30 days and returned excessive noise - starting smaller.

**Known False Positives (from H-0022):**

- CrowdStrike Falcon sensor (CSFalconService.exe)
- System Center Operations Manager (HealthService.exe)
- Windows Defender (MsMpEng.exe)
