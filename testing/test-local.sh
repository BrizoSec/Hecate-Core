#!/bin/bash
# test-local.sh
# Tests ATHF installation using local Python virtual environments
# Useful when Docker is not available

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}ATHF Local Installation Test${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Detect Python version
PYTHON_CMD=$(which python3)
if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}ERROR: python3 not found${NC}"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version | cut -d' ' -f2)
echo -e "${BLUE}Using: Python ${PYTHON_VERSION}${NC}"
echo ""

# Create temporary test directory
TEST_DIR=$(mktemp -d -t athf-test-XXXXXX)
trap "rm -rf $TEST_DIR" EXIT

echo -e "${YELLOW}Step 1: Creating test virtual environment...${NC}"
$PYTHON_CMD -m venv "$TEST_DIR/venv"
source "$TEST_DIR/venv/bin/activate"

echo -e "${YELLOW}Step 2: Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel > /dev/null 2>&1 || {
    echo -e "${RED}ERROR: pip upgrade failed${NC}"
    exit 1
}

echo -e "${YELLOW}Step 3: Installing ATHF from repository root...${NC}"
# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

pip install -e "$REPO_ROOT" || {
    echo -e "${RED}ERROR: Installation failed${NC}"
    exit 1
}

echo -e "${YELLOW}Step 4: Verifying installation...${NC}"
athf --version || {
    echo -e "${RED}ERROR: athf command not found${NC}"
    exit 1
}

echo -e "${YELLOW}Step 5: Creating test workspace...${NC}"
mkdir -p "$TEST_DIR/workspace"
cd "$TEST_DIR/workspace"

echo -e "${YELLOW}Step 6: Initializing ATHF workspace...${NC}"
athf init --non-interactive || {
    echo -e "${RED}ERROR: athf init failed${NC}"
    exit 1
}

echo -e "${YELLOW}Step 7: Verifying directory structure...${NC}"
[ -d "hunts" ] || { echo -e "${RED}ERROR: hunts/ not created${NC}"; exit 1; }
[ -d "knowledge" ] || { echo -e "${RED}ERROR: knowledge/ not created${NC}"; exit 1; }
[ -d "integrations" ] || { echo -e "${RED}ERROR: integrations/ not created${NC}"; exit 1; }
[ -f "AGENTS.md" ] || { echo -e "${RED}ERROR: AGENTS.md not created${NC}"; exit 1; }
echo -e "${GREEN}✓ Directory structure correct${NC}"

echo -e "${YELLOW}Step 8: Creating test hunt...${NC}"
athf hunt new \
    --technique T1003.001 \
    --title "Local Test Hunt" \
    --platform windows \
    --non-interactive || {
    echo -e "${RED}ERROR: Hunt creation failed${NC}"
    exit 1
}

echo -e "${YELLOW}Step 9: Verifying hunt file...${NC}"
[ -f "hunts/H-0001.md" ] || { echo -e "${RED}ERROR: Hunt file not created${NC}"; exit 1; }
grep -q "T1003.001" hunts/H-0001.md || { echo -e "${RED}ERROR: Hunt missing technique${NC}"; exit 1; }
echo -e "${GREEN}✓ Hunt file created correctly${NC}"

echo -e "${YELLOW}Step 10: Testing hunt commands...${NC}"
athf hunt list > /dev/null || { echo -e "${RED}ERROR: hunt list failed${NC}"; exit 1; }
athf hunt validate > /dev/null || { echo -e "${RED}ERROR: hunt validate failed${NC}"; exit 1; }
athf hunt stats > /dev/null || { echo -e "${RED}ERROR: hunt stats failed${NC}"; exit 1; }
echo -e "${GREEN}✓ All hunt commands working${NC}"

echo -e "${YELLOW}Step 11: Testing help commands...${NC}"
athf --help > /dev/null || { echo -e "${RED}ERROR: athf --help failed${NC}"; exit 1; }
athf hunt --help > /dev/null || { echo -e "${RED}ERROR: hunt --help failed${NC}"; exit 1; }
echo -e "${GREEN}✓ Help commands working${NC}"

# Cleanup
deactivate

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}🎉 All local tests passed!${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}Python ${PYTHON_VERSION} - Installation works correctly${NC}"
echo ""
echo -e "${BLUE}Test artifacts created in: ${TEST_DIR}/workspace${NC}"
echo -e "${BLUE}(Will be cleaned up automatically)${NC}"
