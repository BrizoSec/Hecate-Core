# Recording AI Search Demo (Exfiltration Example)

This demo shows your AI assistant searching your hunt repository and providing intelligent summaries.

## What This Demonstrates

**Level 2 Capability:** AI reads your hunt repository and recalls past work

**The Interaction:**
```
You: "search for past hunts where we looked at exfiltration"

AI Assistant: [Searches hunts/]
              [Analyzes 3 hunts: H-0001, H-0003, H-0004]
              [Returns structured table with coverage summary]
              [Identifies telemetry gaps across all hunts]
```

## Quick Record

```bash
cd /Users/sydney/work/agentic-threat-hunting-framework/scripts

# Record
asciinema rec --idle-time-limit 2 \
  -c "./demo-ai-search-exfiltration.sh" \
  athf-ai-search.cast

# Convert to GIF
agg --speed 1.2 --theme monokai --font-size 12 \
  athf-ai-search.cast \
  ../assets/athf-ai-search-exfiltration.gif

# Check size
ls -lh ../assets/athf-ai-search-exfiltration.gif
```

## Terminal Settings

**Optimal size:**
```bash
# 100 columns × 32 rows (fits table comfortably)
printf '\e[8;32;100t'
```

**Clean prompt:**
```bash
export PS1="\$ "
```

## What's Shown

1. **User query:** "search for past hunts where we looked at exfiltration"

2. **AI processing:**
   - Searches hunts/ directory
   - Reads H-0001, H-0003, H-0004
   - Finds 3 matching hunts

3. **Structured output:**
   ```
   Summary of Exfiltration Coverage

   Hunt    Primary Technique         Data Volume       Findings          Status
   H-0001  T1041 - Exfiltration     67.6M network     No exfiltration   ✓ Complete
           Over C2                   events            detected

   H-0003  T1071.004 - DNS          2.2B DNS records  Methodology       ✓ Complete
           Tunneling                                   validated

   H-0004  T1105 - Ingress Tool     29.5B EDR events  3 suspicious      ✓ Complete
           Transfer                                    findings
   ```

4. **Telemetry gap analysis:**
   - Missing HTTP URI paths
   - No file read/access monitoring
   - Limited NXDOMAIN visibility

5. **Follow-up:** AI offers to provide more details

## Runtime

- **Total:** ~30 seconds
- **With speed 1.2:** ~25 seconds playback
- **File size:** ~2-3MB

## Use Cases

**Blog post:** Show AI memory capabilities
**Documentation:** Demonstrate Level 2 searchable memory
**README:** Illustrate intelligent hunt recall

## For Your Blog Post

Embed this GIF with:

```markdown
## AI-Powered Hunt Search

![AI Search Example](assets/athf-ai-search-exfiltration.gif)

Ask your AI assistant to search past hunts, and it instantly recalls:
- Which techniques you've covered
- Data volumes analyzed
- Findings and status
- Common telemetry gaps

What took 20 minutes of manual searching now takes 5 seconds.
```

## Alternative: With Different Query

You can modify the script to show different queries:

**Coverage gap analysis:**
```bash
You: "What ATT&CK techniques are we missing for credential access?"
```

**Related hunts:**
```bash
You: "Show me all hunts related to T1003"
```

**Success rate:**
```bash
You: "What's our detection success rate for persistence techniques?"
```

## One Command

```bash
cd /Users/sydney/work/agentic-threat-hunting-framework/scripts && \
export PS1="\$ " && \
printf '\e[8;32;100t' && \
asciinema rec --idle-time-limit 2 -c "./demo-ai-search-exfiltration.sh" athf-ai-search.cast && \
agg --speed 1.2 --theme monokai --font-size 12 athf-ai-search.cast ../assets/athf-ai-search-exfiltration.gif && \
rm athf-ai-search.cast && \
echo "✓ GIF ready: assets/athf-ai-search-exfiltration.gif"
```

Perfect for showing how AI assistants recall hunt history!
