"""Check that a field name is really an OCSF field.

Handing the model `knowledge/OCSF_SCHEMA_REFERENCE.md` was not enough. With
the reference loaded, a telemetry mapping still came back as:

    process.execution.command_line
    file.file_name
    process.creation.create_time
    network.tcp.connection.remote_address

None of those exist. The model produces the *shape* of an OCSF path -- dotted,
lowercase, plausible -- without consulting the dictionary in front of it. This
is the same failure as the Sigma rules that were valid YAML and meaningless
Sigma, and it has the same answer: check the output rather than hope the
prompt lands.

The canonical set is parsed from the reference file itself, so the document
the model reads and the rule the output is checked against cannot drift apart.
"""

import difflib
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from hecate_agent.core.workspace import knowledge_file

_REFERENCE = "OCSF_SCHEMA_REFERENCE.md"

#: Where an object can legitimately appear inside an event, beyond its own
#: name. `network_endpoint` is never called that in an event -- it is
#: `src_endpoint` or `dst_endpoint` -- and `process`/`user` appear nested
#: under `actor`.
_POSITIONS: Dict[str, Tuple[str, ...]] = {
    "network_endpoint": ("src_endpoint", "dst_endpoint", "network_endpoint"),
    "process": ("process", "actor.process", "process.parent_process"),
    "user": ("user", "actor.user", "process.user"),
    "file": ("file", "process.file", "module.file"),
    "device": ("device",),
    "actor": ("actor",),
    "dns_query": ("query",),
    "module": ("module",),
    "reg_key": ("reg_key",),
    "reg_value": ("reg_value",),
}

_OBJECT_HEADING = re.compile(r"^### `([a-z_]+)`", re.M)
_FIELD_ROW = re.compile(r"^\| `([a-z_]+)` \|", re.M)


@lru_cache(maxsize=4)
def _object_fields(reference: Optional[Path] = None) -> Dict[str, FrozenSet[str]]:
    """Object name -> its documented field names, from the reference file."""
    path = reference or knowledge_file(_REFERENCE)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    objects: Dict[str, FrozenSet[str]] = {}
    matches = list(_OBJECT_HEADING.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.end() : end]
        objects[match.group(1)] = frozenset(_FIELD_ROW.findall(block))
    return objects


@lru_cache(maxsize=4)
def canonical_paths(reference: Optional[Path] = None) -> FrozenSet[str]:
    """Every field path this program will accept as OCSF."""
    paths: Set[str] = set()
    for obj, fields in _object_fields(reference).items():
        for prefix in _POSITIONS.get(obj, (obj,)):
            for name in fields:
                paths.add(f"{prefix}.{name}")
    return frozenset(paths)


def is_ocsf_field(name: str, reference: Optional[Path] = None) -> bool:
    """Whether ``name`` is a field path the reference documents."""
    return name.strip().strip("`").lower() in canonical_paths(reference)


def invalid_fields(names: List[str], reference: Optional[Path] = None) -> List[str]:
    """Those of ``names`` that are not OCSF paths.

    Returns [] when the reference is unavailable: with no dictionary to check
    against, everything would be reported invalid, which is worse than not
    checking. The caller warns about the missing reference separately.
    """
    if not canonical_paths(reference):
        return []
    return [n for n in names if not is_ocsf_field(n, reference)]


def suggest(name: str, reference: Optional[Path] = None) -> Optional[str]:
    """The documented path a wrong one probably meant, or None.

    The observed mistakes are near-misses on the leaf -- `command_line` for
    `cmd_line`, `file_name` for `name`, `create_time` for `created_time` --
    so an exact leaf match finds none of them. Close matching does, and a
    high cutoff keeps it from inventing a correction it cannot justify.
    Ambiguity returns None: a wrong suggestion is worse than none, because it
    would be copied.
    """
    paths = canonical_paths(reference)
    if not paths:
        return None
    cleaned = name.strip().strip("`").lower()
    if cleaned in paths:
        return None

    leaf = cleaned.rsplit(".", 1)[-1]
    head = cleaned.split(".", 1)[0]

    # Prefer a path under the same root object -- `file.file_name` is about
    # a file whatever its middle segments say.
    same_root = [p for p in paths if p.split(".", 1)[0] == head]
    for candidates in (same_root, sorted(paths)):
        by_leaf: Dict[str, List[str]] = {}
        for path in candidates:
            by_leaf.setdefault(path.rsplit(".", 1)[-1], []).append(path)
        close = difflib.get_close_matches(leaf, list(by_leaf), n=2, cutoff=0.72)
        if not close:
            continue
        if len(close) > 1:
            # Two different leaves match equally well; correcting to either
            # would be a guess.
            continue
        # One leaf, possibly several positions for it. Prefer the most direct
        # -- `process.created_time` over `process.file.created_time`, which
        # is a different field about a different thing.
        return min(by_leaf[close[0]], key=lambda p: (p.count("."), len(p)))
    return None


def clear_cache() -> None:
    """Forget the parsed reference.

    Two caches back this module, and clearing only one leaves the other
    serving the old file -- a trap for tests that point `HECATE_WORKSPACE`
    somewhere else. One entry point so that cannot happen.
    """
    _object_fields.cache_clear()
    canonical_paths.cache_clear()
