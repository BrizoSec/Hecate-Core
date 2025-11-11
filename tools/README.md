# ATHF Tools

This directory contains Level 3 tools that empower AI assistants with specialized hunting capabilities.

## Hypothesis Generator

**File:** `hypothesis_generator.py`

**Purpose:** Generate LOCK-formatted hunt hypotheses using memory from past hunts.

### Usage

```bash
cd /Users/sydney/test/agentic-threat-hunting-framework
python3 tools/hypothesis_generator.py <technique_id> "<threat_context>"
```

### Example

```bash
python3 tools/hypothesis_generator.py T1110.001 "New SSH brute force campaign from compromised cloud hosting providers"
```

### Output

The tool returns:
- Past hunts related to the technique
- Available data sources from AGENTS.md
- Lessons learned from previous hunts
- Next available hunt ID
- Instructions for Claude to generate the hypothesis

### Using with Claude

1. Run the tool to get context
2. Copy the JSON output
3. Paste into Claude Code and ask:
   > "Using this context, generate a complete LOCK-formatted hunt hypothesis"

Claude will create a hunt that:
- References past work
- Incorporates lessons learned
- Uses your actual data sources
- Follows the LOCK pattern
- Is ready to save to `hunts/H-XXXX.md`

## MCP Server (Level 3)

Ready to move from **Level 2 (Searchable)** to **Level 3 (Generative)**?

The full MCP server is included in this repository at **[tools/mcp/](mcp/)**

### What It Does

The MCP server gives Claude Code a specialized `generate_hunt_hypothesis` tool that:
- Searches past hunts for the specified technique
- Loads data sources from AGENTS.md automatically
- Extracts lessons learned from previous hunts
- Returns structured context for generating memory-aware hypotheses

### Quick Setup

```bash
cd tools/mcp
./setup.sh
```

See **[tools/mcp/QUICKSTART.md](mcp/QUICKSTART.md)** for the 5-minute setup guide.

### What Level 3 Gives You

This brings you to **Level 3: Generative** - where AI assistants have specialized hunting tools instead of just file access:

- **Level 2**: Claude reads your files and answers questions
- **Level 3**: Claude calls specialized tools to search, analyze, and generate hunts automatically

Instead of asking "search my past hunts for T1059", Claude automatically searches when generating hypotheses.

## Future Tools

Additional Level 3 tools will be added here:
- Query validator (validates query syntax before execution)
- Coverage analyzer (maps hunts to MITRE ATT&CK coverage)
- Hunt executor (read-only query execution with telemetry logging)
