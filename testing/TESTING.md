# Testing ATHF Installation

This document describes how to test the ATHF installation process to ensure new users can successfully follow the README instructions.

## Quick Start

### Run All Tests (Python 3.9, 3.11, 3.13)

```bash
./test-fresh-install.sh
```

### Quick Test (Python 3.11 only)

```bash
./test-quick.sh
```

### Custom Python Versions

```bash
PYTHON_VERSIONS="3.8 3.12 3.13" ./test-fresh-install.sh
```

## What Gets Tested

Each test simulates a fresh user installation and validates:

1. ✅ **System Dependencies** - Git installation
2. ✅ **Repository Clone** - Simulates `git clone`
3. ✅ **Package Installation** - `pip install -e .`
4. ✅ **Version Check** - `athf --version`
5. ✅ **Workspace Init** - `athf init --non-interactive`
6. ✅ **Directory Structure** - Verifies hunts/, knowledge/, integrations/, AGENTS.md
7. ✅ **Hunt Creation** - `athf hunt new` with all flags
8. ✅ **Hunt File Validation** - Checks file exists and contains correct data
9. ✅ **List Command** - `athf hunt list`
10. ✅ **Validation Command** - `athf hunt validate`
11. ✅ **Stats Command** - `athf hunt stats`
12. ✅ **Search Command** - `athf hunt search`
13. ✅ **Help Commands** - All `--help` variations

## Prerequisites

- Docker must be installed and running
- No other dependencies needed (tests run in isolated containers)

## Test Output

### Successful Test

```
======================================
ATHF Fresh Installation Test
======================================

Testing installation across Python versions: 3.9 3.11 3.13

Testing with Python 3.9...
=== Step 1: Installing system dependencies ===
=== Step 2: Cloning repository (simulating git clone) ===
...
=== All tests passed for this Python version! ===
✓ Python 3.9 - PASSED

======================================
Test Summary
======================================
Passed: 3
Failed: 0

🎉 All installation tests passed!
Your README instructions are working correctly.
```

### Failed Test

If a test fails, you'll see:
- Which Python version failed
- Which step failed
- The error message
- Failed count in the summary

## CI Integration

### GitHub Actions

Add to `.github/workflows/test-installation.yml`:

```yaml
name: Test Installation

on: [push, pull_request]

jobs:
  test-install:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Test installation
        run: ./test-fresh-install.sh
```

## Manual Testing Checklist

In addition to automated tests, have real users test:

- [ ] Fresh clone on their machine (not Docker)
- [ ] Both installation methods (PyPI and source)
- [ ] On different operating systems (macOS, Linux, Windows)
- [ ] With their actual Python version
- [ ] Following README exactly without improvising
- [ ] Time how long it takes
- [ ] Ask them to note any confusion or unclear instructions

## Debugging Failed Tests

If tests fail:

1. **Check Docker is running**: `docker info`
2. **Run quick test first**: `./test-quick.sh`
3. **Run manually in container**:
   ```bash
   docker run -it --rm -v $(pwd):/athf -w /athf python:3.11-slim bash
   pip install -e .
   athf --version
   ```
4. **Check specific Python version**: `PYTHON_VERSIONS="3.11" ./test-fresh-install.sh`

## Adding New Tests

To add new test steps, edit `test-fresh-install.sh` and add new echo statements following the pattern:

```bash
echo "=== Step N: Description ==="
command || exit 1
```

## Performance

- Quick test (1 version): ~30-60 seconds
- Full test (3 versions): ~2-3 minutes
- Depends on Docker image pull time (first run is slower)

## Notes

- Tests run in completely isolated Docker containers
- No local files are modified
- Each test gets a fresh Python environment
- Tests simulate the exact steps from the README
