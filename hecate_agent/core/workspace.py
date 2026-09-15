"""Locate the workspace whose knowledge files an agent should read.

Agents are frequently run as a subprocess by something else. The orchestrator
does set ``cwd`` to the workspace when it invokes ``hecate-agent``, so the
older ``Path.cwd() / "knowledge" / ...`` resolution worked for that caller --
but it made correctness depend on every caller remembering to do the same,
and silently returned "not found" for any that did not. A manual
``hecate-agent research new`` from another directory is exactly such a
caller, and writes its output there too.

Resolution mirrors ``mcp.utils.find_workspace`` but lives here because
``mcp`` is an optional dependency, and it returns a path instead of raising:
a missing workspace should degrade the prompt, exactly as it does today, not
crash a hunt cycle.
"""

import os
from pathlib import Path
from typing import Optional

#: Marker that identifies a directory as a workspace root.
_CONFIG_NAMES = (".hecateconfig.yaml", "config/.hecateconfig.yaml")


def workspace_root(explicit: Optional[Path] = None) -> Path:
    """Best guess at the workspace root.

    Order: explicit argument, ``HECATE_WORKSPACE``, the nearest ancestor of
    the working directory holding a workspace config, then the working
    directory itself.
    """
    if explicit is not None and Path(explicit).is_dir():
        return Path(explicit)

    env_path = os.environ.get("HECATE_WORKSPACE")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_dir():
            return candidate

    current = Path.cwd()
    for parent in [current, *current.parents]:
        for name in _CONFIG_NAMES:
            if (parent / name).exists():
                return parent

    return current


def knowledge_file(filename: str, explicit: Optional[Path] = None) -> Path:
    """Path to one file under the workspace's ``knowledge/`` directory.

    The file is not required to exist; callers decide what a missing file
    means for their prompt.
    """
    return workspace_root(explicit) / "knowledge" / filename
