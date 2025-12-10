#!/bin/bash
# test-fresh-install.sh
# Tests ATHF installation and basic commands in a fresh Docker container
# Simulates a new user following the README instructions

set -e  # Exit on any error

# Get repository root (parent of testing directory)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default Python versions to test
PYTHON_VERSIONS=${PYTHON_VERSIONS:-"3.9 3.11 3.13"}

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}ATHF Fresh Installation Test${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to test installation in a Docker container
test_installation() {
    local python_version=$1
    echo -e "${YELLOW}Testing with Python ${python_version}...${NC}"

    # Run tests in Docker container
    docker run --rm \
        -v "$REPO_ROOT:/athf" \
        -w /tmp \
        python:${python_version}-slim \
        bash -c '
            set -e

            echo "=== Step 1: Installing system dependencies ==="
            apt-get update -qq && apt-get install -y -qq git > /dev/null 2>&1

            echo "=== Step 2: Cloning repository (simulating git clone) ==="
            cp -r /athf /tmp/agentic-threat-hunting-framework
            cd /tmp/agentic-threat-hunting-framework

            echo "=== Step 3: Installing ATHF from source ==="
            pip install -q -e . || exit 1

            echo "=== Step 4: Verifying installation ==="
            athf --version || exit 1

            echo "=== Step 5: Testing athf init (non-interactive) ==="
            cd /tmp/test-workspace
            athf init --non-interactive || exit 1

            echo "=== Step 6: Verifying directory structure ==="
            [ -d "hunts" ] || { echo "ERROR: hunts/ directory not created"; exit 1; }
            [ -d "knowledge" ] || { echo "ERROR: knowledge/ directory not created"; exit 1; }
            [ -d "integrations" ] || { echo "ERROR: integrations/ directory not created"; exit 1; }
            [ -f "AGENTS.md" ] || { echo "ERROR: AGENTS.md not created"; exit 1; }

            echo "=== Step 7: Creating a new hunt ==="
            athf hunt new \
                --technique T1003.001 \
                --title "LSASS Credential Dumping Test" \
                --platform windows \
                --non-interactive || exit 1

            echo "=== Step 8: Verifying hunt creation ==="
            [ -f "hunts/H-0001.md" ] || { echo "ERROR: Hunt file not created"; exit 1; }
            grep -q "T1003.001" hunts/H-0001.md || { echo "ERROR: Hunt file missing technique"; exit 1; }

            echo "=== Step 9: Testing hunt list command ==="
            athf hunt list || exit 1

            echo "=== Step 10: Testing hunt validation ==="
            athf hunt validate || exit 1

            echo "=== Step 11: Testing hunt stats ==="
            athf hunt stats || exit 1

            echo "=== Step 12: Testing hunt search ==="
            athf hunt search "LSASS" || exit 1

            echo "=== Step 13: Testing --help commands ==="
            athf --help > /dev/null || exit 1
            athf hunt --help > /dev/null || exit 1
            athf hunt new --help > /dev/null || exit 1

            echo "=== All tests passed for this Python version! ==="
        ' && echo -e "${GREEN}✓ Python ${python_version} - PASSED${NC}" || echo -e "${RED}✗ Python ${python_version} - FAILED${NC}"
}

# Main execution
echo -e "${BLUE}Testing installation across Python versions: ${PYTHON_VERSIONS}${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Track results
PASSED=0
FAILED=0

# Test each Python version
for version in $PYTHON_VERSIONS; do
    if test_installation "$version"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi
    echo ""
done

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All installation tests passed!${NC}"
    echo -e "${GREEN}Your README instructions are working correctly.${NC}"
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please review the output above.${NC}"
    exit 1
fi
