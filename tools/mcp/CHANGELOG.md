# MCP Server Setup Improvements

## Changes Made (2025-01-11)

### Problem
The original setup documentation and script had several issues that made setup difficult:

1. **Python Version Detection**: Script only checked system Python and failed if it was < 3.10, even if newer versions were installed
2. **Configuration Structure**: Documentation didn't clearly explain that MCP servers are project-specific in Claude Code
3. **Missing Workarounds**: No guidance for users with old system Python but newer Homebrew installations

### Solutions Implemented

#### 1. Enhanced setup.sh

**New Features:**
- Automatic Python version search in multiple locations (system, Homebrew, /usr/local)
- Support for `PYTHON` environment variable to manually specify Python path
- Helpful error messages showing all available Python versions
- Automatic detection and use of Python 3.10+ from common locations

**Usage Examples:**
```bash
# Automatic detection (tries system Python, then Homebrew)
./setup.sh

# Manual Python specification
PYTHON=/opt/homebrew/bin/python3.13 ./setup.sh

# Works with pyenv
PYTHON=$(pyenv which python3.11) ./setup.sh
```

**Python Detection Order:**
1. Check if `PYTHON` environment variable is set (use that)
2. Check system `python3` (if >= 3.10)
3. Check Homebrew locations: `/opt/homebrew/bin/python3.{13,12,11,10}`
4. Check old Homebrew: `/usr/local/bin/python3.{13,12,11,10}`
5. If none found, show helpful error with suggestions

#### 2. Updated README.md

**New Sections:**
- **Python Version Issues**: Comprehensive troubleshooting for Python < 3.10
- **Configuration Structure**: Clear explanation of project-specific MCP server config
- **Solution Options**: Three different ways to resolve Python version issues

**Key Additions:**
- Prerequisites now link to troubleshooting section
- Full configuration examples show correct project-specific structure
- Better explanation of Claude Code's per-project MCP scope
- Added logs location for debugging: `~/.claude/logs/*.log`

#### 3. Updated QUICKSTART.md

**Improvements:**
- Documents automatic Python detection feature
- Shows project-specific configuration structure
- Added Python troubleshooting to quick reference
- Clarifies that server only loads in ATHF directory

#### 4. Configuration Examples

**Before (misleading):**
```json
{
  "mcpServers": {
    "athf-hunt-server": { ... }
  }
}
```

**After (correct):**
```json
{
  "projects": {
    "/full/path/to/agentic-threat-hunting-framework": {
      "mcpServers": {
        "athf-hunt-server": { ... }
      }
    }
  }
}
```

### Testing Results

The improved setup script correctly:
- ✓ Detects system Python 3.9 is too old
- ✓ Finds Homebrew Python 3.13 automatically
- ✓ Uses Homebrew Python for venv creation
- ✓ Provides clear project-specific configuration examples
- ✓ Shows helpful error messages with solutions

### Files Modified

1. `setup.sh` - Complete rewrite of Python detection logic
2. `README.md` - Added troubleshooting sections and corrected config examples
3. `QUICKSTART.md` - Updated with Python detection info and project-specific config
4. `CHANGELOG.md` - This file (new)

### Backward Compatibility

✓ All changes are backward compatible
✓ Users with Python 3.10+ system Python see no change
✓ New features only activate when needed (old system Python)

### Migration Guide

**If you previously set up manually:**
- No action required - your existing config will continue to work
- Consider updating your config to the project-specific structure shown in README

**If setup failed before:**
- Simply re-run `./setup.sh` - it will now find your Homebrew Python
- Or use: `PYTHON=/path/to/your/python3.13 ./setup.sh`

### Known Limitations

- Script currently only checks Homebrew paths on macOS
- Does not yet support pyenv automatic detection (but can be specified via `PYTHON` variable)
- Windows paths not yet included

### Future Improvements

Potential enhancements for future versions:
1. Add pyenv automatic detection
2. Support for Windows Python installations
3. Add Poetry/PDM support
4. Automatic detection of PATH Python installations
5. Option to use system Python with pip install --user

## Credits

Improvements based on real-world setup experience with:
- macOS with system Python 3.9
- Homebrew Python 3.13
- Claude Code VSCode extension
