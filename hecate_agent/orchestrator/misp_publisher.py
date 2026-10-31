"""Compatibility module for the retired direct MISP writer.

Runner owns downstream storage, provenance, idempotency, and read-back checks.
Core generation must not turn extracted candidates into active IDS indicators.
"""

import os
from typing import List


def _setting(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _misp_verify_tls() -> bool:
    return _setting("MISP_VERIFY_SSL", "true").lower() != "false"


def publish_hunt_to_misp(topic: str, hypothesis: str, observables: List[str]) -> str:
    """Refuse the old writer rather than silently bypass Runner's output policy."""
    raise RuntimeError(
        "Direct Core MISP publishing is retired. Use hecate-runner misp publish H-XXXX "
        "for private, unpublished storage with provenance and read-back verification."
    )
