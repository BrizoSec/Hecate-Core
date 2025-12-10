#!/bin/bash
# test-quick.sh
# Quick test with just Python 3.11 for faster iteration

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "🚀 Running quick installation test (Python 3.11 only)..."
echo ""

cd "$SCRIPT_DIR"
PYTHON_VERSIONS="3.11" ./test-fresh-install.sh
