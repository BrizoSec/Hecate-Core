# ATHF Installation Testing

This folder contains scripts to test the ATHF installation process, simulating a new user following the README instructions.

## Quick Start

```bash
# Local test (no Docker needed) - RECOMMENDED
./test-local.sh

# Docker test (requires Docker running)
./test-quick.sh              # Single Python version
./test-fresh-install.sh      # Multiple Python versions
```

## Documentation

- **TESTING.md** - Complete testing guide
- **TEST-SUMMARY.md** - Quick reference and test results

## Test Coverage

All scripts verify:
- ✅ Installation (`pip install -e .`)
- ✅ Version check (`athf --version`)
- ✅ Workspace initialization (`athf init`)
- ✅ Hunt creation (`athf hunt new`)
- ✅ All CLI commands work
- ✅ Help documentation is accessible

## When to Run

- Before publishing a new release
- After changing installation instructions
- When adding new CLI commands
- When testing on different Python versions or OS

## Results

Last successful test: ✅ All tests passing (Python 3.9.6)
