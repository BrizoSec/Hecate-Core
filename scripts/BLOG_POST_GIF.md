# Blog Post CLI Demo GIF

Quick reference for creating the CLI workflow GIF for your blog post.

## The 5-Step Workflow

This demo covers exactly what you specified in your blog post:

1. ✅ **Initialize your workspace** - `athf init`
2. ✅ **Create a new hunt** - `athf hunt new` (H-0001 macOS stealer)
3. ✅ **Validate your hunts** - `athf hunt validate`
4. ✅ **Track ATT&CK coverage** - `athf hunt coverage`
5. ✅ **Use AI assistants with your repo** - Demo AI interaction

## Quick Record

```bash
cd /Users/sydney/work/agentic-threat-hunting-framework/scripts

# Setup terminal
export PS1="\$ "
printf '\e[8;38;120t'

# Record
asciinema rec --idle-time-limit 2 -c "./demo-cli-workflow.sh" athf-cli-workflow.cast

# Convert to GIF
agg --speed 1.2 --theme monokai --font-size 12 \
  athf-cli-workflow.cast \
  ../assets/athf-cli-workflow.gif

# Check result
ls -lh ../assets/athf-cli-workflow.gif
open ../assets/athf-cli-workflow.gif
```

## What's Demonstrated

**Step 1: Initialize**
```
$ athf init
✓ Created workspace configuration
✓ Initialized hunts/ directory
✓ Context files ready
```
→ "Builds the full workspace with consistent memory layer"

**Step 2: Create Hunt**
```
$ athf hunt new --technique T1005 --title "macOS Data Collection Review"
✓ Created hunt: H-0001
  ID: H-0001
  Technique: T1005 - Data from Local System
```
→ "LOCK-ready hunt file with every required section"

**Step 3: Validate**
```
$ athf hunt validate
✓ H-0001.md - Valid LOCK structure
  ✓ YAML frontmatter valid
  ✓ LOCK sections present
```
→ "AI tools rely on this consistency"

**Step 4: Coverage**
```
$ athf hunt coverage
MITRE ATT&CK Coverage Report
Collection (TA0009)
  ✓ T1005 - Data from Local System (1 hunt)

Suggested next hunts:
  • T1003 - OS Credential Dumping
```
→ "Removes the need to maintain spreadsheets"

**Step 5: AI Assistants**
```
You: "What should I hunt for next based on H-0001?"

AI reads:
  • hunts/H-0001.md
  • AGENTS.md
  • knowledge/hunting-knowledge.md

AI: "Based on H-0001's findings, extend to Firefox/Brave..."
```
→ "Context-aware suggestions from hunt memory"

## For Your Blog Post

Use this GIF in the section:

```markdown
## The CLI Workflow

![ATHF CLI Workflow](assets/athf-cli-workflow.gif)

1. **Initialize your workspace** - `athf init` builds the full workspace
2. **Create a new hunt** - `athf hunt new` generates LOCK-ready files
3. **Validate your hunts** - Ensures consistency for AI tools
4. **Track ATT&CK coverage** - See gaps at a glance
5. **Use AI assistants** - Get context-aware suggestions from hunt memory
```

## Runtime

- **Total:** ~50 seconds
- **With speed 1.2:** ~42 seconds playback
- **File size target:** < 5MB for embedding

## Alternative Speeds

**For quick overview:**
```bash
agg --speed 1.5 --theme monokai --font-size 12 \
  athf-cli-workflow.cast \
  athf-cli-workflow-fast.gif
```

**For detailed viewing:**
```bash
agg --speed 1.0 --theme monokai --font-size 14 \
  athf-cli-workflow.cast \
  athf-cli-workflow-detailed.gif
```

## One Command to Record

```bash
cd scripts && \
export PS1="\$ " && \
printf '\e[8;38;120t' && \
asciinema rec --idle-time-limit 2 -c "./demo-cli-workflow.sh" athf-cli-workflow.cast && \
agg --speed 1.2 --theme monokai --font-size 12 athf-cli-workflow.cast ../assets/athf-cli-workflow.gif && \
rm athf-cli-workflow.cast && \
echo "✓ GIF created: ../assets/athf-cli-workflow.gif"
```

Ready for your blog post! 🎬
