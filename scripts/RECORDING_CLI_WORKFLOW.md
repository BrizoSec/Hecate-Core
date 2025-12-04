# Recording the CLI Workflow Demo

This demo shows the complete CLI workflow: init → hunt new → validate → coverage

## Quick Record

```bash
cd /Users/sydney/work/agentic-threat-hunting-framework/scripts

# Record (auto-plays the script)
asciinema rec --idle-time-limit 2 -c "./demo-cli-workflow.sh" athf-cli-workflow.cast

# Convert to GIF (optimized for README)
agg --speed 1.2 --theme monokai --font-size 12 \
  athf-cli-workflow.cast \
  ../assets/athf-cli-workflow.gif
```

## What This Demo Shows

**The Complete CLI Workflow (5 Steps):**

1. **Initialize workspace** (`athf init`)
   - Creates hunts/, templates/, knowledge/, queries/
   - Sets up AGENTS.md and environment.md
   - Explains: "consistent memory layer"

2. **Create hunt** (`athf hunt new --technique T1005 --title "macOS Data Collection Review"`)
   - Shows H-0001 creation with details
   - Explains: "LOCK-ready hunt file"

3. **Validate** (`athf hunt validate`)
   - Checks YAML frontmatter, LOCK sections, metadata
   - Explains: "AI tools rely on consistency"

4. **Track coverage** (`athf hunt coverage`)
   - Shows MITRE ATT&CK coverage report
   - Suggests next hunts
   - Explains: "removes need for spreadsheets"

5. **Use AI assistants** (Demo interaction)
   - Shows asking AI: "What should I hunt for next based on H-0001?"
   - AI reads hunts/, AGENTS.md, knowledge/
   - AI suggests Firefox extension based on H-0001
   - Explains: "context-aware suggestions from hunt memory"

**Runtime:** ~50 seconds with speed 1.2

## Terminal Settings

**Optimal size for this demo:**
```bash
# 120 columns × 38 rows (taller to fit all 5 steps)
printf '\e[8;38;120t'
```

**Clean prompt:**
```bash
export PS1="\$ "
```

## GIF Conversion Options

### For README (Recommended)
```bash
agg --speed 1.2 --theme monokai --font-size 12 \
  athf-cli-workflow.cast \
  ../assets/athf-cli-workflow.gif
```

### Higher Quality
```bash
agg --speed 1.0 --theme monokai --font-size 14 \
  athf-cli-workflow.cast \
  athf-cli-workflow-hq.gif
```

### Faster Overview
```bash
agg --speed 1.5 --theme monokai --font-size 11 \
  athf-cli-workflow.cast \
  athf-cli-workflow-fast.gif
```

## Alternative Themes

Try these for different looks:

```bash
# Dracula (purple/pink)
agg --speed 1.2 --theme dracula --font-size 12 \
  athf-cli-workflow.cast test-dracula.gif

# Nord (blue/white)
agg --speed 1.2 --theme nord --font-size 12 \
  athf-cli-workflow.cast test-nord.gif

# Solarized Dark (beige/blue)
agg --speed 1.2 --theme solarized-dark --font-size 12 \
  athf-cli-workflow.cast test-solarized.gif
```

## Testing

Preview the script before recording:
```bash
./demo-cli-workflow.sh
```

## Where to Use This GIF

Add to README.md:
```markdown
## A Quick Look at the CLI Workflow

![ATHF CLI Workflow](assets/athf-cli-workflow.gif)

1. **Initialize your workspace** - `athf init` builds the full workspace
2. **Create a new hunt** - `athf hunt new` generates LOCK-ready files
3. **Validate your hunts** - `athf hunt validate` ensures consistency
4. **Track ATT&CK coverage** - `athf hunt coverage` shows gaps
```

## Complete Workflow

```bash
# Setup
cd /Users/sydney/work/agentic-threat-hunting-framework/scripts
export PS1="\$ "
printf '\e[8;35;120t'
clear

# Record
asciinema rec --idle-time-limit 2 -c "./demo-cli-workflow.sh" athf-cli-workflow.cast

# Preview (optional)
asciinema play athf-cli-workflow.cast

# Convert
agg --speed 1.2 --theme monokai --font-size 12 \
  athf-cli-workflow.cast \
  ../assets/athf-cli-workflow.gif

# Check size
ls -lh ../assets/athf-cli-workflow.gif
# Target: < 5MB for GitHub

# Clean up
rm athf-cli-workflow.cast
```

## Differences from Level 1 Demo

| Feature | Level 1 Demo | CLI Workflow Demo |
|---------|--------------|-------------------|
| Focus | Getting started basics | Complete workflow showcase |
| Commands | init, new (2x), validate, list | init, new (1x), validate, **coverage** |
| Duration | ~30 seconds | ~40 seconds |
| Emphasis | Hunt catalog | Memory layer + ATT&CK tracking |
| Target audience | New users | README visitors |

## Troubleshooting

**Text too small?**
```bash
# Increase font size
agg --speed 1.2 --theme monokai --font-size 14 ...
```

**GIF too large?**
```bash
# Speed up
agg --speed 1.5 --theme monokai --font-size 12 ...

# Or reduce idle time during recording
asciinema rec --idle-time-limit 1 -c "./demo-cli-workflow.sh" ...
```

**Colors look wrong?**
```bash
# Try different theme
agg --speed 1.2 --theme dracula --font-size 12 ...
```
