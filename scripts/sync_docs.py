#!/usr/bin/env python3
"""Sync GitHub framework guides to their installed package-data copies."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
MIRRORED_GUIDES = (
    "CLI_REFERENCE.md",
    "environment.md",
    "getting-started.md",
    "level4-agentic-workflows.md",
    "lock-pattern.md",
    "maturity-model.md",
    "why-hecate.md",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report out-of-sync package copies without changing files",
    )
    args = parser.parse_args()

    source_dir = ROOT / "docs"
    package_dir = ROOT / "hecate_agent" / "data" / "docs"
    drift = []
    for name in MIRRORED_GUIDES:
        source = source_dir / name
        packaged = package_dir / name
        if args.check:
            if source.read_bytes() != packaged.read_bytes():
                drift.append(name)
        else:
            shutil.copyfile(source, packaged)

    if drift:
        print("Package documentation copies are out of sync:", file=sys.stderr)
        for name in drift:
            print(f"  {name}", file=sys.stderr)
        print("Run: python scripts/sync_docs.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
