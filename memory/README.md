# Hunt Memory

This folder is reserved for **structured memory** - the optional "recall system" for Level 4+ hunting.

## Level 2: Searchable - Use Grep

At Level 2 (AI-augmented hunting), your `hunts/` folder IS your memory. Before starting a new hunt, search through past hunt notes:

```bash
# Find hunts by TTP
grep -l "T1110.001" ../hunts/*.md

# Find by behavior
grep -i "brute force" ../hunts/*.md

# Find by technology
grep -i "powershell" ../hunts/*.md

# Find by application
grep -i "active directory" ../hunts/*.md

# Find by keyword
grep -i "privilege escalation" ../hunts/*.md

# Find what worked
grep "Decision: Accept" ../hunts/*.md
```

**No additional files needed.** The discipline of reviewing old hunts before starting new ones is what creates memory.

## Level 3: Automated - Grep Still Works

At Level 3 (single-agent automation), grep-based memory is still effective. An agent can automatically search past hunts before generating new hypotheses. No structured memory needed yet.

## Level 4+: Autonomous - Add Structure When Grep Fails

When you have 50+ hunts or need multi-agent coordination, grep becomes painful. At that point, create structured memory:

### Option 1: JSON Index
```json
{
  "hunts": [
    {
      "hunt_id": "H-0001",
      "ttps": ["T1059.001", "T1027"],
      "decision": "accept",
      "lessons": ["baseline automation critical"]
    }
  ]
}
```

### Option 2: SQLite Database
Queryable, supports complex filters, still portable as a single file.

### Option 3: Markdown Index
Human-readable table linking to run notes with key metadata.

## Why Wait?

Early optimization kills simplicity. Build the habit of reviewing past hunts first. Add structure only when complexity demands it.

The goal: **Make recall easy, not fancy.**
