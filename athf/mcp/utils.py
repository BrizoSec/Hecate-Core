"""Utility functions for the ATHF MCP server."""

import os
from pathlib import Path
from typing import Optional

import yaml


def find_workspace(explicit_path: Optional[str] = None) -> Path:
    """Find the ATHF workspace root directory.

    Resolution order:
    1. Explicit path argument
    2. ATHF_WORKSPACE environment variable
    3. Walk up from cwd looking for .athfconfig.yaml

    Args:
        explicit_path: Explicitly provided workspace path.

    Returns:
        Path to the workspace root.

    Raises:
        FileNotFoundError: If no workspace can be found.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.is_dir():
            return p
        raise FileNotFoundError("Workspace path does not exist: {}".format(explicit_path))

    env_path = os.environ.get("ATHF_WORKSPACE")
    if env_path:
        p = Path(env_path)
        if p.is_dir():
            return p

    # Walk up from cwd
    current = Path.cwd()
    for parent in [current, *current.parents]:
        if (parent / ".athfconfig.yaml").exists():
            return parent
        if (parent / "config" / ".athfconfig.yaml").exists():
            return parent

    raise FileNotFoundError(
        "No ATHF workspace found. Set ATHF_WORKSPACE or run from within an ATHF workspace."
    )


def load_workspace_config(workspace: Path) -> dict:
    """Load .athfconfig.yaml from workspace.

    Args:
        workspace: Workspace root path.

    Returns:
        Config dict (empty dict if file not found).
    """
    for candidate in [workspace / ".athfconfig.yaml", workspace / "config" / ".athfconfig.yaml"]:
        if candidate.is_file():
            with open(str(candidate), "r") as fh:
                data = yaml.safe_load(fh)
                return data if isinstance(data, dict) else {}
    return {}
