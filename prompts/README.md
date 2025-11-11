# AI Prompt Library

This folder contains prompts to help you at **Level 0-1: Manual/Documented** (before AI integration).

## What's Here

### hypothesis-generator.md
Use with ChatGPT, Claude, or other AI assistants to generate behavior-based hunt hypotheses from context like CTI, alerts, or anomalies.

**When to use**: You have context but need help forming a testable hypothesis

### query-builder.md
Use to draft safe, bounded queries for Splunk, KQL, or Elastic from your hypothesis.

**When to use**: You have a hypothesis but need help writing the query

### summarizer.md
Use to help document hunt results and capture lessons learned in LOCK pattern format.

**When to use**: You ran a query and need help writing a concise run note

## How to Use These Prompts

1. **Copy the prompt** from the markdown file
2. **Fill in your context** (hypothesis, data sources, results)
3. **Paste into your AI assistant** (ChatGPT, Claude, etc.)
4. **Review and refine** the output
5. **Test before using** - AI can make mistakes!

## Important Notes

### AI Assistance ≠ Autopilot

- **Always review** AI-generated hypotheses for feasibility
- **Always test** AI-generated queries on small timeframes first
- **Always validate** that queries are safe and bounded
- **Use your judgment** - You know your environment better than AI

### Keep It Simple

These prompts are designed to:
- Help you think through the LOCK pattern systematically
- Reduce writer's block when starting hunts
- Capture lessons more consistently
- NOT to fully automate hunting (that's Level 3+: Autonomous)

### Learning Tool

Think of these prompts as training wheels:
- They help you get started faster
- They teach you the LOCK pattern structure
- Over time, you'll need them less
- But they remain useful for complex hunts

## Platform-Specific Tips

### For Splunk Users
- Mention "Splunk SPL" in your prompt
- Specify data models when available
- AI knows common Splunk patterns

### For KQL Users
- Mention "KQL for Sentinel" or "KQL for Defender"
- Specify table names (SecurityEvent, DeviceProcessEvents, etc.)
- AI understands Sentinel-specific syntax

### For Elastic Users
- Mention "Elastic EQL" or "Lucene query"
- Specify index patterns
- Note which Elastic stack version

## Customizing Prompts

Feel free to modify these prompts for your environment:

- Add your organization's specific data sources
- Include your ATT&CK coverage gaps
- Reference your baseline automation
- Add your threat model priorities

## Contributing

Have a better prompt? Found a useful variation?
- Submit a PR with your improved prompts
- Share what works in your environment
- Help others get started faster

## Next: Add AI Integration (Level 1 → 2)

Once you reach **Level 2: Searchable**, you'll use AI tools (GitHub Copilot, Claude Code, Cursor) that automatically read your hunt repository via AGENTS.md.

These prompts remain useful for:
- Teams without AI tool access
- Manual workflows
- Understanding what AI should generate

**Before Level 2, you can still enhance these prompts with manual memory:**

- "Check if we've hunted this before: [paste grep results from hunts/]"
- "What lessons from past hunts apply here?"
- "Compare this hypothesis to previous ones: [paste relevant hunt notes]"

Example workflow:
```bash
# Before starting a hunt, search your memory
grep -l "T1110.001" hunts/*.md        # Find by TTP
grep -i "brute force" hunts/*.md      # Find by behavior
grep -i "powershell" hunts/*.md       # Find by technology
grep -i "active directory" hunts/*.md # Find by application
grep -i "privilege escalation" hunts/*.md  # Find by keyword

# Share relevant past hunts with your AI assistant
# Then use the prompts above
```

This manual recall loop works at Level 1: Documented. At Level 2: Searchable, AI tools do this automatically.

## Using Environmental Context (environment.md)

At **Level 2: Searchable**, incorporate environmental context into your workflow:

### Before Planning a Hunt

```bash
# Threat Intel: "Adversaries abusing LSASS process access for credential dumping"

# 1. Check if we have visibility into this behavior
grep -i "lsass\|credential" environment.md
# Result: Found "Sysmon Event ID 10 (ProcessAccess) enabled on Windows endpoints"

# 2. Check for similar past hunts
grep -i "lsass" hunts/*.md
grep -i "T1003" hunts/*.md
grep -i "credential" hunts/*.md
# Result: H-0022 hunted LSASS access 6 months ago

# 3. Review past lessons
cat hunts/H-0022*.md | grep -A5 "Lessons Learned"
# Result: Found false positives from AV scanners and monitoring tools

# 4. Use prompt with enriched context
# Copy to AI: "We have Sysmon Event ID 10. Past hunt H-0022 found FPs from AV tools. Generate hypothesis for LSASS credential dumping..."
```

### Environment-Aware Hypothesis Generation

When using **hypothesis-generator.md**, include environmental context:

```
Context: Threat intel reports adversaries using living-off-the-land binaries (LOLBins) for lateral movement, specifically abusing certutil.exe to download malicious payloads

Our environment (from environment.md):
- Windows endpoints with Sysmon Event ID 1 (Process Creation)
- Command line logging enabled
- Logs: Windows logs in Splunk (index=winlogs)
- Network: Egress proxy logs capture external connections

Past similar hunts:
- H-0041: PowerShell download cradles (found 3 legitimate admin scripts, 0 malicious)
- H-0028: BITSAdmin abuse (found 1 suspicious transfer from contractor)

Generate LOCK hypothesis for hunting certutil.exe abuse for payload downloads.
```

This provides AI with:
- **Tech context** (what visibility we have)
- **Data context** (where to look)
- **Historical context** (past lessons and FPs)

### Level 3+ Automation Example

At Level 3, this becomes automated:

```python
# Threat intel monitoring agent (runs daily)
def check_new_threat_intel():
    new_intel = fetch_threat_feeds()  # CTI feeds, MITRE updates, etc.

    # Read tech stack and data sources
    tech_stack = parse_environment_md()
    past_hunts = load_hunt_history()

    for intel in new_intel:
        # Check if we have visibility for this TTP
        if has_data_sources_for_ttp(intel.ttp, tech_stack):
            # Check if we've hunted this recently
            if not hunted_in_last_90_days(intel.ttp, past_hunts):
                # Check threat relevance
                if intel.threat_score >= 7.0:
                    # Search for similar past hunts
                    similar_hunts = grep_similar_hunts(intel.ttp)

                    # Generate hypothesis using AI
                    hypothesis = generate_hypothesis(
                        ttp=intel.ttp,
                        environment=tech_stack,
                        past_lessons=similar_hunts
                    )

                    # Alert human for review
                    notify_slack(f"New hunt opportunity: {intel.ttp} - {intel.description}")
```

**Key insight:** environment.md + past hunt memory enable behavior-driven hunting at scale.
