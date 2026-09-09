"""Utility functions for the Hecate MCP server."""

import os
from pathlib import Path
from typing import Optional

import yaml


def find_workspace(explicit_path: Optional[str] = None) -> Path:
    """Find the Hecate workspace root directory.

    Resolution order:
    1. Explicit path argument
    2. HECATE_WORKSPACE environment variable
    3. Walk up from cwd looking for .hecateconfig.yaml

    Args:
        explicit_path: Explicitly provided workspace path.

    Returns:
        Path to the workspace root.

    Raises:
        FileNotFoundError: If no workspace can be found or path lacks Hecate structure.
    """
    if explicit_path:
        p = Path(explicit_path)
        if not p.is_dir():
            raise FileNotFoundError(f"Workspace path does not exist: {explicit_path}")
        _validate_workspace(p)
        return p

    env_path = os.environ.get("HECATE_WORKSPACE")
    if env_path:
        p = Path(env_path)
        if p.is_dir():
            _validate_workspace(p)
            return p

    # Walk up from cwd
    current = Path.cwd()
    for parent in [current, *current.parents]:
        if (parent / ".hecateconfig.yaml").exists():
            return parent
        if (parent / "config" / ".hecateconfig.yaml").exists():
            return parent

    raise FileNotFoundError("No Hecate workspace found. Set HECATE_WORKSPACE or run from within an Hecate workspace.")


def _validate_workspace(path: Path) -> None:
    """Validate that a directory looks like an Hecate workspace.

    Raises FileNotFoundError if neither .hecateconfig.yaml nor config/.hecateconfig.yaml exists.
    """
    if (path / ".hecateconfig.yaml").exists():
        return
    if (path / "config" / ".hecateconfig.yaml").exists():
        return
    raise FileNotFoundError(f"Not an Hecate workspace: {path} (missing .hecateconfig.yaml).")


def load_workspace_config(workspace: Path) -> dict:
    """Load .hecateconfig.yaml from workspace.

    Args:
        workspace: Workspace root path.

    Returns:
        Config dict (empty dict if file not found).
    """
    for candidate in [workspace / ".hecateconfig.yaml", workspace / "config" / ".hecateconfig.yaml"]:
        if candidate.is_file():
            with open(str(candidate), "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                return data if isinstance(data, dict) else {}
    return {}
