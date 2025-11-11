# ATHF Hunt Server - MCP Implementation

This is a working implementation of the Level 3 hypothesis generation tool from the Agentic Threat Hunting Framework (ATHF).

## What It Does

This MCP server provides Claude Code with a `generate_hunt_hypothesis` tool that:
- Searches past hunts for related techniques
- Loads your data sources from AGENTS.md
- Extracts lessons learned from previous hunts
- Returns structured context for generating memory-aware hunt hypotheses

This brings your threat hunting to **Level 3: Generative** - where AI assistants have specialized tools to generate context-aware hunt hypotheses automatically.

## Prerequisites

- **Python 3.10 or higher** (if your system Python is older, see [Troubleshooting](#python-version-issues))
- [uv](https://github.com/astral-sh/uv) (Python package installer)
- [Claude Code](https://claude.ai/download) or compatible MCP client
- An ATHF repository with hunts in LOCK format

## Quick Start

### 1. Navigate to MCP Directory

```bash
cd tools/mcp
```

Note: Paths are configured automatically using relative paths from the repository root. No configuration needed!

### 2. Run Setup Script

```bash
./setup.sh
```

This will:
- Create a virtual environment
- Install dependencies (fastmcp, mcp)
- Configure Claude Code
- Verify repository structure

### 3. Manual Step: Add stdio Transport

Edit `~/.claude.json` and add `--transport` and `stdio` to the args array (the setup script shows you exactly where).

### 4. Verify Installation

```bash
claude mcp list
```

You should see: `✓ athf-hunt-server: Connected`

## Alternative: Manual Install

Using the FastMCP CLI (recommended):

```bash
# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install fastmcp

# Install in Claude Code
fastmcp install claude-code hunt_mcp_server.py:mcp
```

This automatically configures Claude Code to use your MCP server.

### 4. Add stdio Transport Flag

Edit your Claude Code config at `~/.claude.json` and add `--transport` and `stdio` to the args array:

```json
{
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
        "--transport",
        "stdio",
        "/full/path/to/hunt_mcp_server.py:mcp"
      ]
    }
  }
}
```

### 5. Verify Installation

```bash
claude mcp list
```

You should see:
```
✓ athf-hunt-server: Connected
```

## Usage

### Basic Example

Open Claude Code in your ATHF repository and try:

```
Generate a hunt hypothesis for T1059.003 based on this threat context:
"New ransomware campaign using obfuscated PowerShell loaders from compromised cloud infrastructure"
```

Claude will automatically:
1. Call the `generate_hunt_hypothesis` tool
2. Search for related past hunts about T1059.003
3. Load your available data sources from AGENTS.md
4. Extract lessons learned from previous similar hunts
5. Generate a complete LOCK-formatted hypothesis

### Advanced Example

```
I just received a CTI report about Qakbot:

[paste full CTI report]

Create a hunt for T1059.001 (PowerShell execution) that:
- References our past Qakbot hunts
- Uses only our Splunk and EDR data sources
- Includes lessons learned from H-0142
```

### Expected Output

```markdown
# H-0157: PowerShell-Based Qakbot Loader Detection (T1059.003)

**Learn**
New Qakbot campaign observed using Windows Script Host to execute obfuscated
PowerShell commands. Based on H-0142, previous campaigns used base64 encoding
and registry persistence via Run keys.

**Observe**
Adversaries execute PowerShell with -EncodedCommand parameter from wscript.exe
or cscript.exe parent processes. Suspicious execution chains originate from
non-standard parents and target multiple hosts.

**Check**
index=winlogs EventCode=4688
| search ParentImage="*wscript.exe" OR ParentImage="*cscript.exe"
| search Image="*powershell.exe"
| where CommandLine LIKE "%EncodedCommand%" OR CommandLine LIKE "%-enc%"
| stats count by User, Computer, CommandLine

**Keep**
[To be completed after hunt execution]
- Reference H-0142: check HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Expand to include WMI execution if query yields high volume
- Cross-reference with EDR process trees for parent-child relationships
```

## How It Works

When you ask Claude to generate a hunt hypothesis:

1. **Tool Call** - Claude invokes `generate_hunt_hypothesis(threat_context, technique_id)`
2. **Context Search** - Server searches `hunts/` directory for past hunts matching the technique
3. **Data Loading** - Server parses AGENTS.md to find available data sources
4. **Lesson Extraction** - Server pulls "Keep" sections from related past hunts
5. **Context Return** - Server returns structured JSON with all context
6. **Hypothesis Generation** - Claude uses the context to create a memory-aware LOCK hypothesis

## Troubleshooting

### Python Version Issues

If your system Python is older than 3.10, the setup script will automatically search for newer versions in common locations (Homebrew, etc.).

**Symptoms:**
```
❌ Python 3.9 found. Python 3.10 or higher required.
```

**Solution 1: Install Python 3.10+ via Homebrew**
```bash
brew install python@3.13
# Then run setup.sh again
./setup.sh
```

**Solution 2: Specify Python manually**
```bash
# If you have Python 3.10+ installed elsewhere
PYTHON=/opt/homebrew/bin/python3.13 ./setup.sh

# Or use pyenv
PYTHON=$(pyenv which python3.11) ./setup.sh
```

**Solution 3: Create venv manually**
```bash
# Use specific Python version
/opt/homebrew/bin/python3.13 -m venv venv
./venv/bin/pip install fastmcp mcp
./venv/bin/fastmcp install claude-code hunt_mcp_server.py:mcp
# Then manually add --transport stdio to ~/.claude.json
```

### Configuration Structure

Claude Code MCP servers are **project-specific**. Your `~/.claude.json` should have this structure:

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
            "--transport",
            "stdio",
            "/full/path/to/tools/mcp/hunt_mcp_server.py:mcp"
          ]
        }
      }
    }
  }
}
```

The server will only be available when you open Claude Code in the ATHF project directory.

### Server Won't Connect

```bash
# Check if the server can start
uv run --with fastmcp fastmcp run --transport stdio hunt_mcp_server.py:mcp

# Verify configuration
claude mcp list

# Check for errors
cat ~/.claude/logs/*.log | grep athf-hunt-server
```

### No Past Hunts Found

```bash
# Verify paths are correct
python3 -c "from pathlib import Path; print(Path('/your/path/to/hunts').exists())"

# Check hunt files exist
ls /your/path/to/agentic-threat-hunting-framework/hunts/H-*.md
```

### No Data Sources Loaded

```bash
# Verify AGENTS.md exists
cat /your/path/to/agentic-threat-hunting-framework/AGENTS.md | grep "## Data Sources"

# Ensure it has a proper table format with | delimiters
```

### Permission Errors

If Claude Code asks for permission to use the tool, approve it. You can pre-approve by adding to your project settings in `~/.claude.json`:

```json
{
  "projects": {
    "/path/to/athf": {
      "allowedTools": ["mcp__athf-hunt-server__*"]
    }
  }
}
```

## Testing Without Claude Code

You can test the server manually:

```bash
# Activate virtual environment
source venv/bin/activate

# Run the server in test mode
python3 -c "
from hunt_mcp_server import generate_hunt_hypothesis
result = generate_hunt_hypothesis(
    'New Qakbot campaign',
    'T1059.003'
)
print(result)
"
```

## Directory Structure

```
agentic-threat-hunting-framework/
├── hunts/                       # Hunt files (H-0001.md, H-0002.md, etc.)
├── AGENTS.md                    # Data sources and AI context
├── README.md                    # Main framework docs
└── tools/
    ├── README.md                # Tools overview
    ├── hypothesis_generator.py  # Standalone CLI version
    └── mcp/                     # MCP server (Level 3) ← You are here
        ├── hunt_mcp_server.py   # Main MCP server
        ├── README.md            # This file
        ├── QUICKSTART.md        # 5-minute setup
        ├── setup.sh             # Automated installer
        ├── pyproject.toml       # Dependencies
        └── venv/                # Virtual environment (gitignored)
```

## Next Steps

Once Level 3 is working:

1. **Test with real CTI** - Feed actual threat intelligence into Claude and generate hunts
2. **Refine past hunts** - Ensure your "Keep" sections have actionable lessons
3. **Expand data sources** - Keep AGENTS.md updated with your real data platforms
4. **Build Level 4** - Create autonomous agents that use this tool automatically

See the main ATHF blog post for Level 4 examples with multi-agent coordination.

## Configuration Reference

### Full .claude.json Example

The MCP server configuration is **project-specific** and lives under the `projects` key:

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
            "--transport",
            "stdio",
            "/full/path/to/agentic-threat-hunting-framework/tools/mcp/hunt_mcp_server.py:mcp"
          ],
          "env": {}
        }
      },
      "allowedTools": ["mcp__athf-hunt-server__*"]
    }
  }
}
```

**Important Notes:**
- The server is scoped to the project path (the ATHF repository root)
- The server will only load when you open Claude Code in that directory
- Use absolute paths for the hunt_mcp_server.py location
- The `allowedTools` entry pre-approves the tool to avoid permission prompts

## Contributing

Found a bug or have an improvement? Pull requests welcome!

## License

MIT
