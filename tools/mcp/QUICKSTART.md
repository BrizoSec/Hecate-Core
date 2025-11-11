# Quick Start - ATHF Hunt Server

Get Level 3 hypothesis generation working in 5 minutes.

## Prerequisites

- **Python 3.10+ installed** (the setup script will find it automatically, or see troubleshooting)
- Claude Code installed
- ATHF repository cloned (you're already here!)

## Installation

### 1. Navigate and Run Setup

```bash
cd tools/mcp
./setup.sh
```

The script will:
- **Automatically find Python 3.10+** (checks Homebrew, system Python, etc.)
- Create a virtual environment
- Install dependencies (fastmcp, mcp)
- Verify repository structure (paths are automatic!)
- Install in Claude Code

**Tip:** If your system Python is too old, the script will automatically find newer versions or you can specify: `PYTHON=/path/to/python3.13 ./setup.sh`

### 2. Add stdio Transport

Edit `~/.claude.json` and add these two lines to the args array:

```json
"--transport",
"stdio",
```

Full example (config is per-project):
```json
{
  "projects": {
    "/full/path/to/agentic-threat-hunting-framework": {
      "mcpServers": {
        "athf-hunt-server": {
          "type": "stdio",
          "command": "uv",
          "args": [
            "run",
            "--with",
            "fastmcp",
            "fastmcp",
            "run",
            "--transport",        <- Add this
            "stdio",              <- Add this
            "/full/path/to/agentic-threat-hunting-framework/tools/mcp/hunt_mcp_server.py:mcp"
          ]
        }
      }
    }
  }
}
```

**Note:** The server is project-specific and will only load when you open Claude Code in the ATHF directory.

### 3. Verify

```bash
claude mcp list
```

You should see:
```
✓ athf-hunt-server: Connected
```

## Usage

Open Claude Code and try:

```
Generate a hunt hypothesis for T1059.003 about "PowerShell ransomware loaders"
```

Claude will automatically search your past hunts, load your data sources, and generate a complete LOCK-formatted hypothesis.

## Troubleshooting

**Python version error?**
```bash
# If your system Python is too old, specify a newer one:
PYTHON=/opt/homebrew/bin/python3.13 ./setup.sh

# Or install Python 3.10+:
brew install python@3.13
```

**Server not connected?**
```bash
# Test the server directly
uv run --with fastmcp fastmcp run --transport stdio hunt_mcp_server.py:mcp

# Check Claude Code logs
cat ~/.claude/logs/*.log | grep athf-hunt-server
```

**No hunts found?**
- Paths are configured automatically using relative paths
- Verify hunt files exist: `ls ../../hunts/H-*.md`

**Permission errors?**
- Approve the tool when Claude Code asks
- Or add to your project in `~/.claude.json`:
  ```json
  "allowedTools": ["mcp__athf-hunt-server__*"]
  ```

## What's Next?

See [README.md](README.md) for:
- Detailed configuration options
- Advanced usage examples
- Full troubleshooting guide
- Level 4 autonomous agent patterns

## Support

Found a bug? Open an issue: https://github.com/sydney-nebulock/athf-mcp-server/issues
