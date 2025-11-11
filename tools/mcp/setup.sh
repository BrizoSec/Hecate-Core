#!/bin/bash
# ATHF Hunt Server Setup Script
# Automates installation of the Level 3 MCP server

set -e

echo "🔧 ATHF Hunt Server Setup"
echo "=========================="
echo ""

# Function to check if a Python version meets requirements
check_python_version() {
    local python_cmd=$1
    if ! command -v "$python_cmd" &> /dev/null; then
        return 1
    fi

    local version=$($python_cmd -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || echo "0.0")
    local required="3.10"

    # Check if version >= 3.10
    if [ "$(printf '%s\n' "$required" "$version" | sort -V | head -n1)" = "$required" ]; then
        echo "$version"
        return 0
    fi
    return 1
}

# Find suitable Python installation
PYTHON_CMD=""

# Check if user specified PYTHON environment variable
if [ -n "$PYTHON" ]; then
    echo "Using user-specified Python: $PYTHON"
    if version=$(check_python_version "$PYTHON"); then
        PYTHON_CMD="$PYTHON"
        echo "✓ Python $version found"
    else
        echo "❌ Specified Python ($PYTHON) is not Python 3.10+"
        exit 1
    fi
else
    # Search for Python 3.10+ in common locations
    echo "Searching for Python 3.10+..."

    # Try system python3 first
    if version=$(check_python_version "python3"); then
        PYTHON_CMD="python3"
        echo "✓ Found system Python $version"
    else
        # Check Homebrew locations
        for py_path in /opt/homebrew/bin/python3.{13,12,11,10} /usr/local/bin/python3.{13,12,11,10}; do
            if version=$(check_python_version "$py_path"); then
                PYTHON_CMD="$py_path"
                echo "✓ Found Python $version at $py_path"
                break
            fi
        done
    fi
fi

# If no suitable Python found, show helpful error
if [ -z "$PYTHON_CMD" ]; then
    echo "❌ Python 3.10 or higher not found."
    echo ""
    echo "Available Python versions found:"
    for cmd in python3 /opt/homebrew/bin/python3.* /usr/local/bin/python3.*; do
        if command -v "$cmd" &> /dev/null 2>&1; then
            version=$($cmd --version 2>&1 || echo "unknown")
            echo "  - $cmd: $version"
        fi
    done
    echo ""
    echo "Solutions:"
    echo "  1. Install Python 3.10+ via Homebrew:"
    echo "     brew install python@3.13"
    echo ""
    echo "  2. Or specify a Python installation manually:"
    echo "     PYTHON=/path/to/python3.10 ./setup.sh"
    echo ""
    exit 1
fi
echo ""

# Check if Claude CLI is available
if ! command -v claude &> /dev/null; then
    echo "⚠️  Claude CLI not found. Install from https://claude.ai/download"
    echo "   Continuing with manual configuration..."
    CLAUDE_CLI=false
else
    echo "✓ Claude CLI found"
    CLAUDE_CLI=true
fi
echo ""

# Create virtual environment in tools/mcp directory
echo "📦 Creating virtual environment..."
if [ ! -d "venv" ]; then
    "$PYTHON_CMD" -m venv venv
    echo "✓ Virtual environment created with $PYTHON_CMD"
else
    echo "✓ Virtual environment already exists"
fi
echo ""

# Activate and install dependencies
echo "📦 Installing dependencies..."
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet fastmcp mcp

echo "✓ Dependencies installed"
echo ""

# Paths are automatic now (relative from hunt_mcp_server.py)
echo "🔧 Configuration"
echo "---------------"
echo "✓ Paths configured automatically (using relative paths)"
echo "  - HUNTS_DIR: ../../hunts/"
echo "  - AGENTS_FILE: ../../AGENTS.md"
echo ""

# Verify repository structure
REPO_ROOT="$(cd ../.. && pwd)"
if [ ! -d "$REPO_ROOT/hunts" ]; then
    echo "⚠️  Warning: $REPO_ROOT/hunts does not exist"
    echo "   You may need to create it before using the server."
fi

if [ ! -f "$REPO_ROOT/AGENTS.md" ]; then
    echo "⚠️  Warning: $REPO_ROOT/AGENTS.md does not exist"
    echo "   You may need to create it before using the server."
fi
echo ""

# Install in Claude Code
if [ "$CLAUDE_CLI" = true ]; then
    echo "🚀 Installing in Claude Code..."

    # Get current directory
    CURRENT_DIR=$(pwd)

    # Install using fastmcp
    ./venv/bin/fastmcp install claude-code "$CURRENT_DIR/hunt_mcp_server.py:mcp"

    echo ""
    echo "⚠️  IMPORTANT: Manual step required!"
    echo ""
    echo "Edit ~/.claude.json and add these flags to the args array:"
    echo "  \"--transport\","
    echo "  \"stdio\","
    echo ""
    echo "The config should be nested under your project path:"
    echo ""
    echo "{"
    echo "  \"projects\": {"
    echo "    \"$REPO_ROOT\": {"
    echo "      \"mcpServers\": {"
    echo "        \"athf-hunt-server\": {"
    echo "          \"args\": ["
    echo "            \"run\","
    echo "            \"--with\","
    echo "            \"fastmcp\","
    echo "            \"fastmcp\","
    echo "            \"run\","
    echo "            \"--transport\",     <- Add this"
    echo "            \"stdio\",           <- Add this"
    echo "            \"$CURRENT_DIR/hunt_mcp_server.py:mcp\""
    echo "          ]"
    echo "        }"
    echo "      }"
    echo "    }"
    echo "  }"
    echo "}"
    echo ""
else
    echo "📝 Manual Configuration Required"
    echo "------------------------------"
    echo ""
    echo "Add this to your ~/.claude.json file under projects:"
    echo ""
    echo "{"
    echo "  \"projects\": {"
    echo "    \"$REPO_ROOT\": {"
    echo "      \"mcpServers\": {"
    echo "        \"athf-hunt-server\": {"
    echo "          \"type\": \"stdio\","
    echo "          \"command\": \"uv\","
    echo "          \"args\": ["
    echo "            \"run\","
    echo "            \"--with\","
    echo "            \"fastmcp\","
    echo "            \"fastmcp\","
    echo "            \"run\","
    echo "            \"--transport\","
    echo "            \"stdio\","
    echo "            \"$(pwd)/hunt_mcp_server.py:mcp\""
    echo "          ],"
    echo "          \"env\": {}"
    echo "        }"
    echo "      }"
    echo "    }"
    echo "  }"
    echo "}"
    echo ""
fi

echo ""
echo "✅ Setup Complete!"
echo ""
echo "Next steps:"
echo "1. Edit ~/.claude.json to add --transport stdio flags (see above)"
echo "2. Restart Claude Code or reload the project"
echo "3. Run: claude mcp list"
echo "4. You should see: ✓ athf-hunt-server: Connected"
echo ""
echo "Try it out:"
echo '  Generate a hunt hypothesis for T1059.003 about "ransomware using PowerShell loaders"'
echo ""
echo "See README.md for full documentation."
