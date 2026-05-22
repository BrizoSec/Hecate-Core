"""Envelope-reduction response contract — reference implementation.

See ``docs/envelope-reduction-contract.md`` for the full specification.

The contract gives MCP tools and CLI commands a uniform way to reduce
the inline-payload size of a tool result by writing the body to disk
and returning a small reference instead. This module is the canonical
Python helper.

Usage::

    from athf.core.envelope import build_envelope

    # Gate A — parent artifact (the artifact owns the bytes; envelope
    # always returned).
    env = build_envelope(
        payload=rendered_text,
        parent_artifact="R-0042",
        path=str(research_file),
        metadata={"mitre_techniques": ["T1016"]},
    )

    # Gate B — byte threshold (small payloads pass through inline).
    env = build_envelope(
        payload=rendered_rows,
        threshold=2048,
        persist_dir="/tmp/query-results",
        artifact_name="a1b2c3d4.json",
        metadata={"row_count": 1000},
    )
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


_DEFAULT_THRESHOLD = 2048
_DEFAULT_PREVIEW_CHARS = 200


def _serialize(payload: Any) -> str:
    """Render ``payload`` as the string that would otherwise be the inline body."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (bytes, bytearray)):
        return payload.decode("utf-8", errors="replace")
    return json.dumps(payload, default=str)


def _make_preview(text: str, max_chars: int = _DEFAULT_PREVIEW_CHARS) -> str:
    """One-line, ``max_chars``-bounded summary of ``text``."""
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 3].rstrip() + "..."


def build_envelope(
    payload: Any,
    *,
    threshold: int = _DEFAULT_THRESHOLD,
    persist_dir: Optional[str] = None,
    parent_artifact: Optional[str] = None,
    path: Optional[str] = None,
    artifact_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    preview: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a contract-compliant envelope dict for ``payload``.

    Two persistence gates:

    - **Gate A — parent artifact.** When ``parent_artifact`` is supplied,
      the envelope always reports ``persisted=True`` and ``path`` is
      taken from the explicit ``path`` argument (the producer is
      responsible for the actual write — typically the artifact already
      exists on disk under its canonical name and this helper just shapes
      the response).
    - **Gate B — byte threshold.** When ``parent_artifact`` is omitted,
      the helper measures the rendered serialization. If it exceeds
      ``threshold`` bytes and ``persist_dir`` is provided, the helper
      writes the bytes to ``<persist_dir>/<artifact_name>`` and returns
      the envelope. Below threshold, the helper returns
      ``persisted=False`` with an empty ``path``.

    Args:
        payload: The body that would have been inlined. ``str`` is used
            as-is; anything else is JSON-serialized via ``default=str``.
        threshold: Byte threshold for Gate B. Default 2048.
        persist_dir: Directory to write to when Gate B fires. The
            directory is created if missing.
        parent_artifact: Identifier (e.g. ``research_id``) signalling
            Gate A. When set, ``path`` must also be supplied.
        path: Absolute path to the artifact on disk. Required for Gate
            A; ignored for Gate B (which derives the path from
            ``persist_dir`` + ``artifact_name``).
        artifact_name: Filename for Gate B. Required when Gate B fires.
        metadata: Producer-specific extension keys. The contract is
            opaque to its contents.
        preview: Optional explicit preview. When omitted, a one-line
            ~200-char summary of the rendered payload is computed.

    Returns:
        Dict with the four core contract fields plus ``metadata``:

        ``preview`` (str), ``path`` (str, absolute when persisted),
        ``persisted`` (bool), ``byte_count`` (int), ``metadata`` (dict).

    Raises:
        ValueError: when ``parent_artifact`` is set without ``path``,
            or when Gate B fires without ``persist_dir`` and
            ``artifact_name``.
    """
    rendered = _serialize(payload)
    byte_count = len(rendered.encode("utf-8"))
    preview_text = preview if preview is not None else _make_preview(rendered)
    meta: Dict[str, Any] = dict(metadata) if metadata else {}

    if parent_artifact is not None:
        if not path:
            raise ValueError(
                "build_envelope: parent_artifact requires an explicit path argument"
            )
        absolute = str(Path(path).resolve())
        return {
            "preview": preview_text,
            "path": absolute,
            "persisted": True,
            "byte_count": byte_count,
            "metadata": meta,
        }

    if byte_count <= threshold:
        return {
            "preview": preview_text,
            "path": "",
            "persisted": False,
            "byte_count": byte_count,
            "metadata": meta,
        }

    if not persist_dir or not artifact_name:
        raise ValueError(
            "build_envelope: Gate B fired (byte_count > threshold) but "
            "persist_dir and artifact_name were not both supplied"
        )

    artifact_rel = Path(artifact_name)
    # Reject anything that looks absolute on ANY platform — including
    # POSIX paths supplied to a Windows runtime, which Path.is_absolute()
    # alone would miss because Windows requires a drive letter.
    if artifact_rel.is_absolute() or artifact_name.startswith(("/", "\\")):
        raise ValueError(
            "build_envelope: artifact_name must be a relative filename"
        )

    persist_path = Path(persist_dir).expanduser()
    persist_path.mkdir(parents=True, exist_ok=True)
    persist_path_resolved = persist_path.resolve()
    artifact_path = (persist_path_resolved / artifact_rel).resolve()
    try:
        artifact_path.relative_to(persist_path_resolved)
    except ValueError:
        raise ValueError(
            "build_envelope: artifact_name escapes persist_dir"
        ) from None

    artifact_path.write_text(rendered, encoding="utf-8")
    absolute = str(artifact_path)

    return {
        "preview": preview_text,
        "path": absolute,
        "persisted": True,
        "byte_count": byte_count,
        "metadata": meta,
    }
