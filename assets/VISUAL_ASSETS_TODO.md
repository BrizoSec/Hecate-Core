# Visual Assets TODO

This document tracks visual assets that need to be created for ATHF's professional presentation.

## Priority 1: Demo GIF (demo.gif)

**Purpose:** Show the `athf` CLI in action on the README

**Tool Options:**
- [asciinema](https://asciinema.org/) - Record terminal, convert to GIF
- [ttyrec](http://0xcc.net/ttyrec/) + ttygif
- [term](https://github.com/buger/term)
- Simple screen recording → GIF conversion

**Content to Record (30-45 seconds):**

```bash
# Scene 1: Initialize ATHF (5-8 seconds)
$ athf init
🎯 Initializing Agentic Threat Hunting Framework

📋 Quick setup questions:
1. What SIEM do you use? [Splunk/Sentinel/Elastic]: Splunk
2. What's your primary EDR? [CrowdStrike/SentinelOne]: CrowdStrike
3. Hunt prefix [H-]: H-

✅ ATHF initialized!

# Scene 2: Create a new hunt (10-12 seconds)
$ athf hunt new
🎯 Creating new hunt

🔍 Let's build your hypothesis:
1. MITRE ATT&CK Technique: T1003.001
2. Hunt Title: LSASS Memory Credential Dumping
3. Primary Tactic: credential-access
4. Target Platform: Windows
5. Data Sources: Sysmon, Windows Security Events, EDR

✅ Created H-0001: LSASS Memory Credential Dumping

# Scene 3: List hunts (8-10 seconds)
$ athf hunt list

📋 Hunt Catalog (3 total)

┌──────────┬──────────────────────────────┬───────────┬──────────┬──────────┐
│ Hunt ID  │ Title                        │ Status    │ Technique│ Findings │
├──────────┼──────────────────────────────┼───────────┼──────────┼──────────┤
│ H-0001   │ LSASS Memory Dumping         │ planning  │ T1003.001│ -        │
│ H-0002   │ Linux Crontab Persistence    │ completed │ T1053.003│ 5 (2 TP) │
│ H-0003   │ Kerberoasting Detection      │ completed │ T1558.003│ 3 (3 TP) │
└──────────┴──────────────────────────────┴───────────┴──────────┴──────────┘

$ # End
```

**Recording Instructions:**
1. Build CLI first (Phase 2)
2. Record with clean terminal (dark theme recommended)
3. Use realistic typing speed (not instant)
4. Convert to optimized GIF (< 2MB for GitHub performance)
5. Place at `assets/demo.gif`
6. Update README.md to embed the GIF

**Placeholder for now:** README already references demo.gif with note "Coming soon"

---

## Priority 2: Results Showcase Diagram (results-showcase.png)

**Purpose:** Visual comparison of hunt efficiency improvements

**Tool Options:**
- [Excalidraw](https://excalidraw.com/) - Simple, clean diagrams
- [draw.io](https://draw.io/) - More detailed
- PowerPoint/Keynote → Export as PNG
- Figma - Professional design

**Content:**

**Before ATHF:**
```
┌─────────────────────────────────────┐
│  Ad-hoc Hunt Workflow               │
├─────────────────────────────────────┤
│  1. Hunt idea from analyst memory   │  ⏱️ 20 min
│  2. Build query from scratch        │  ⏱️ 45 min
│  3. Refine based on trial and error │  ⏱️ 60 min
│  4. Document in ticket (maybe)      │  ⏱️ 15 min
│  5. Knowledge lost after 90 days    │  ⏱️ ∞
├─────────────────────────────────────┤
│  Total Time: 2+ hours                │
│  Reusability: Low                    │
│  Knowledge Retention: Poor           │
└─────────────────────────────────────┘
```

**After ATHF:**
```
┌─────────────────────────────────────┐
│  ATHF LOCK-based Hunt Workflow      │
├─────────────────────────────────────┤
│  1. AI suggests similar past hunts  │  ⏱️ 2 min
│  2. Adapt proven query from H-0027  │  ⏱️ 10 min
│  3. Refine using documented lessons │  ⏱️ 15 min
│  4. Auto-document in LOCK format    │  ⏱️ 2 min
│  5. Searchable forever              │  ⏱️ Instant recall
├─────────────────────────────────────┤
│  Total Time: 30 min (-75%)           │
│  Reusability: High                   │
│  Knowledge Retention: Permanent      │
└─────────────────────────────────────┘
```

**Design Notes:**
- Use green/positive colors for "After"
- Use grey/neutral for "Before"
- Include clock icons for time saved
- Keep it simple and scannable
- Export at 2x resolution for Retina displays

---

## Priority 3: Architecture Diagram Enhancement (Optional)

**Purpose:** Show how ATHF integrates with existing tools

**Existing Assets:**
- `assets/athf_lock.png` - LOCK pattern flow
- `assets/athf_fivelevels.png` - Maturity model

**Potential New Diagram:** ATHF ecosystem integration

```
┌──────────────────────────────────────────────┐
│              ATHF Framework                   │
│  ┌────────────────────────────────────────┐  │
│  │  Hunts (LOCK Pattern Documentation)   │  │
│  │  ├─ H-0001.md (macOS)                 │  │
│  │  ├─ H-0027.md (Kerberoasting)         │  │
│  │  └─ H-0042.md (AWS Lambda)            │  │
│  └────────────────────────────────────────┘  │
│            ↕ AI reads and references          │
│  ┌────────────────────────────────────────┐  │
│  │    Claude Code / Copilot / Cursor      │  │
│  │  "Generate hypothesis for T1003.001"   │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
           ↕ Queries execute via
┌──────────────────────────────────────────────┐
│           Your Security Stack                 │
│  ┌────────┐  ┌────────┐  ┌────────┐          │
│  │ Splunk │  │  EDR   │  │  TIP   │          │
│  └────────┘  └────────┘  └────────┘          │
└──────────────────────────────────────────────┘
```

**Design Notes:**
- Show bidirectional flow
- Emphasize AI integration point
- Show real security tool logos (if permitted)
- Keep it high-level, not too technical

---

## Priority 4: Social Media Assets (Post-launch)

For Twitter/LinkedIn/Reddit when announcing ATHF:

1. **Twitter card image** (1200x630px)
   - ATHF logo
   - Key value prop: "Give your threat hunting program memory"
   - Screenshot of hunt catalog

2. **GitHub social preview** (1280x640px)
   - Similar to Twitter card
   - Automatically shown when repo is shared

3. **Blog post hero image** (1600x900px)
   - Professional header for blog announcement

---

## Notes

- All images should be optimized for web (< 500KB each)
- Use consistent color scheme matching ATHF logo
- Ensure text is readable at various screen sizes
- Export at 2x resolution for Retina/HiDPI displays
- Use PNG for diagrams (lossless), WebP or optimized GIF for demo

## Status

- [ ] demo.gif - **Waiting for Phase 2 (CLI implementation)**
- [ ] results-showcase.png - Can create now with Excalidraw
- [ ] architecture-integration.png - Optional, lower priority
- [ ] Social media assets - Post-launch only

**Current priority:** Placeholder notes complete. Visual assets will be created after CLI is built (Phase 2).
