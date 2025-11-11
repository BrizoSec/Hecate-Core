# ATHF Hunt Server - Implementation Notes

## What Was Built

A fully functional **Level 3 MCP server** that gives Claude Code the ability to generate memory-aware threat hunt hypotheses using the LOCK pattern.

### Key Components

1. **[hunt_mcp_server.py](hunt_mcp_server.py)** - FastMCP server with `generate_hunt_hypothesis` tool
2. **[README.md](README.md)** - Comprehensive documentation with troubleshooting
3. **[QUICKSTART.md](QUICKSTART.md)** - 5-minute setup guide
4. **[setup.sh](setup.sh)** - Automated installation script
5. **[pyproject.toml](pyproject.toml)** - Python dependencies (mcp, fastmcp)

## Architecture

```
┌─────────────────────┐
│   Claude Code       │
│   (AI Assistant)    │
└──────────┬──────────┘
           │ MCP Protocol (stdio)
           │
┌──────────▼──────────┐
│ ATHF Hunt Server    │
│ (FastMCP)           │
└──────────┬──────────┘
           │
    ┌──────┴─────────┬────────────────┐
    │                │                │
┌───▼────┐   ┌──────▼──────┐   ┌────▼─────┐
│ hunts/ │   │ AGENTS.md   │   │ Context  │
│H-*.md  │   │(data sources│   │ Builder  │
└────────┘   └─────────────┘   └──────────┘
```

## How It Works

When Claude generates a hunt hypothesis:

1. **User Request** → "Generate hunt for T1059.003 about ransomware"
2. **Tool Call** → Claude invokes `generate_hunt_hypothesis(threat_context, technique_id)`
3. **Context Search** → Server searches past hunts for T1059.003
4. **Data Loading** → Server parses AGENTS.md for available data sources
5. **Lesson Extraction** → Server extracts "Keep" sections from related hunts
6. **Context Return** → Server returns structured JSON with all context
7. **Generation** → Claude creates LOCK-formatted hypothesis using context
8. **Result** → Complete hunt ready to save to `hunts/H-XXXX.md`

## Configuration

### Paths (Lines 15-16 of hunt_mcp_server.py)

```python
HUNTS_DIR = Path("/path/to/your/hunts")
AGENTS_FILE = Path("/path/to/your/AGENTS.md")
```

### Claude Code Config (~/.claude.json)

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

## Testing

### Manual Test

```python
python3 -c "
from hunt_mcp_server import generate_hunt_hypothesis
result = generate_hunt_hypothesis('New ransomware campaign', 'T1059.003')
print(result)
"
```

### MCP Connection Test

```bash
claude mcp list
# Should show: ✓ athf-hunt-server: Connected
```

### End-to-End Test

Open Claude Code and ask:
```
Generate a hunt hypothesis for T1059.003 about PowerShell ransomware loaders
```

## Key Design Decisions

### Why FastMCP?

- Modern MCP SDK with simpler API
- Built-in transport handling (stdio/http/sse)
- Better error handling and debugging
- Active development and community support

### Why stdio Transport?

- Required for Claude Code integration
- Lightweight and efficient
- No network configuration needed
- Secure local communication

### Why Structured Return?

The tool returns formatted text instead of JSON because:
- Claude can better parse natural language instructions
- Context and instructions are clearly separated
- Human-readable for debugging
- Easier for Claude to incorporate into responses

## Maintenance

### Updating Paths

Edit [hunt_mcp_server.py](hunt_mcp_server.py) lines 15-16, then restart Claude Code.

### Adding New Features

1. Add new tool function with `@mcp.tool()` decorator
2. Document in README.md
3. Test manually before using with Claude

### Debugging

Enable verbose logging:
```bash
# Run server with logging
uv run --with fastmcp fastmcp run --transport stdio --log-level DEBUG hunt_mcp_server.py:mcp
```

## Future Enhancements

### Short Term
- [ ] Add query validator tool
- [ ] Add hunt coverage analyzer
- [ ] Add technique search by tactic/name
- [ ] Cache parsed hunts for faster searches

### Medium Term
- [ ] Multi-repository support
- [ ] Hunt versioning and diffs
- [ ] Automated query syntax validation
- [ ] Integration with MITRE ATT&CK API

### Long Term (Level 4)
- [ ] Autonomous CTI monitoring agent
- [ ] Automated hypothesis generation pipeline
- [ ] Multi-agent hunt coordination
- [ ] Read-only query execution with telemetry

## Related Files

- Main framework: `/Users/sydney/test/agentic-threat-hunting-framework/`
- Standalone tool: `/Users/sydney/test/agentic-threat-hunting-framework/tools/hypothesis_generator.py`
- Blog post: `/Users/sydney/work/athf_blog_post.md`

## Success Metrics

Level 3 is successful when:

- ✅ Claude can search past hunts automatically
- ✅ New hypotheses reference lessons learned
- ✅ Data sources are validated against AGENTS.md
- ✅ Hunt generation time < 30 seconds
- ✅ Analysts spend time refining, not writing from scratch

## Resources

- [MCP Protocol Docs](https://github.com/modelcontextprotocol/specification)
- [FastMCP GitHub](https://github.com/jlowin/fastmcp)
- [Claude Code Docs](https://docs.claude.com/claude-code)
- [ATHF Framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework)

## Notes

This implementation was dogfooded while building it - Claude Code used the MCP server to help debug and improve itself!

The setup uses `uv` for dependency management because:
- Fast dependency resolution
- Isolated environments per project
- Compatible with Claude Code's expectations
- Widely supported in Python ecosystem

## Version History

- **v1.0** (2025-11-10) - Initial FastMCP implementation
  - Single tool: generate_hunt_hypothesis
  - Searches past hunts by technique ID
  - Loads data sources from AGENTS.md
  - Extracts lessons from Keep sections
  - Returns structured context for Claude

---

**Maintainer**: Sydney @ Nebulock
**Status**: Production Ready
**License**: MIT
