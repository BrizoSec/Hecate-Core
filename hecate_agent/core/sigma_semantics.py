"""Semantic checks for a Sigma rule: does it mean what it says, on one real event?

Syntax validation (pySigma) accepts a rule whose fields belong to another log
source, whose selections cannot all hold on one event, or whose description
promises matching the selection does not do. H-0618's rules had each of these:

- ``ParentImage`` and ``IpAddress`` in an ``image_load`` rule, and
  ``DestinationIp``/``DestinationPort`` in a ``process_creation`` rule;
- ``Hashes``, ``Image`` and ``TargetFilename`` AND-ed on a ``file_event``, which
  carries no hashes;
- the ``Beep`` API matched in ``CommandLine``, where an API call never appears;
- a DNS rule described as matching subdomains with exact ``QueryName`` values.

Each check returns the reason the rule is wrong, or ``None``. The field table
is Sigma's taxonomy for the Windows/Sysmon-style categories the generator
writes; it is shared with ``eval-gold`` so the generator and the gold set agree
on what a valid field is. No backend-specific field mapping is configured, so
backend readiness is out of scope here.
"""

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

#: Fields each Sigma log source category carries.
SIGMA_FIELDS: Dict[str, Tuple[str, ...]] = {
    "process_creation": (
        "Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "User",
        "Hashes", "CurrentDirectory", "IntegrityLevel", "Product", "Company", "Description",
        "FileVersion", "ParentUser", "ProcessId", "ParentProcessId", "LogonId",
    ),
    "file_event": ("TargetFilename", "Image", "User", "CreationUtcTime", "ProcessId"),
    "network_connection": (
        "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName", "SourceIp",
        "SourceHostname", "SourcePort", "Initiated", "Image", "Protocol", "User", "ProcessId",
    ),
    "dns_query": ("QueryName", "QueryResults", "QueryStatus", "Image", "ProcessId", "User"),
    "image_load": (
        "ImageLoaded", "Image", "Signed", "Signature", "SignatureStatus", "Hashes",
        "OriginalFileName", "Product", "Company", "Description", "ProcessId", "User",
    ),
    "registry_event": ("TargetObject", "Details", "EventType", "Image", "NewName", "ProcessId", "User"),
    "authentication": (
        "TargetUserName", "SubjectUserName", "LogonType", "AuthenticationPackageName",
        "WorkstationName", "IpAddress", "Status", "SubStatus",
    ),
    "proxy": (
        "c-uri", "c-uri-extension", "c-uri-query", "c-uri-stem", "c-useragent", "cs-bytes", "cs-cookie",
        "cs-host", "cs-method", "cs-referrer", "cs-version", "r-dns", "sc-bytes", "sc-status", "src_ip", "dst_ip",
    ),
    "webserver": ("cs-uri-query", "cs-uri-stem", "cs-method", "cs-referrer", "cs-user-agent", "sc-status", "c-ip"),
}  # fmt: skip

#: Fields naming the process an event belongs to.
IMAGE_FIELDS = frozenset({"image", "parentimage", "originalfilename"})
#: Files that are opened, never run as a process image.
NON_EXECUTABLE = (".txt", ".log", ".docx", ".doc", ".pdf", ".zip", ".rar", ".7z", ".dat", ".png", ".jpg")
#: A description promising subdomain or suffix matching, which only an
#: ``endswith``/``contains`` modifier or a leading wildcard delivers.
SUFFIX_CLAIM_RE = re.compile(r"(?i)\bsub-?domains?\b|\bsuffix\b|\bwildcard\b")

#: Windows API and Linux syscall names: code calls them, no command line carries them.
API_NAMES = frozenset(
    {
        "memfd_create", "virtualalloc", "virtualallocex", "virtualprotect", "createthread", "createremotethread",
        "rtlmovememory", "waitforsingleobject", "getprocaddress", "loadlibrary", "loadlibrarya", "loadlibraryw", "beep", "allocadsmem", "reallocadsmem",
        "ntallocatevirtualmemory", "writeprocessmemory", "execve", "ptrace", "mmap", "mprotect",
    }
)  # fmt: skip
_COMMAND_LINE_FIELDS = frozenset({"commandline", "parentcommandline"})
#: Programs whose command line can carry inline code, and with it API names.
_SCRIPT_HOSTS = ("powershell", "pwsh", "cscript", "wscript", "mshta", "python", "node", "perl", "ruby", "bash", "sh.exe")
_FILE_NAME_FIELDS = frozenset({"image", "parentimage", "originalfilename", "imageloaded", "targetfilename"})
#: File extensions that are not also top-level domains (.zip and .mov are TLDs).
_FILE_EXTENSION_RE = re.compile(
    r"\.(txt|log|docx?|xlsx?|pdf|exe|dll|sys|ps1|bat|cmd|vbs|js|hta|lnk|iso|dat|bin|tmp|rar|7z)$", re.IGNORECASE
)
#: An elision copied from a report: "Beijing Institute of Technology_..._resume.docx".
_ELLIPSIS_RE = re.compile(r"\.\.\.|…")
_LOCAL_PATH_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "currentdirectory"})
_URL_FIELDS = frozenset({"c-uri", "c-uri-stem", "cs-uri-stem", "cs-uri", "url", "uri", "requesturl"})
_HOST_FIELDS = frozenset({"destinationhostname", "queryname", "cs-host", "r-dns"})
#: Fields that hold one value per event, so two AND-ed constraints must agree.
_SINGLE_VALUED = frozenset(
    {
        "image", "parentimage", "originalfilename", "targetfilename", "imageloaded", "destinationip",
        "destinationport", "destinationhostname", "queryname", "targetobject", "sourceip",
    }
)  # fmt: skip


def base_field(key: Any) -> str:
    return str(key).split("|")[0].strip()


def _modifiers(key: Any) -> List[str]:
    return [m.strip().lower() for m in str(key).split("|")[1:]]


def _values(raw: Any) -> List[str]:
    if raw is None:
        return []
    return [str(v) for v in raw] if isinstance(raw, list) else [str(raw)]


def blocks(detection: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Each selection map with its name; a list of maps is OR-ed, so each map is its own block."""
    for name, block in detection.items():
        if name == "condition":
            continue
        for item in block if isinstance(block, list) else [block]:
            if isinstance(item, dict):
                yield str(name), item


# --- Field and value checks ------------------------------------------------------------------


def field_outside_category(detection: Dict[str, Any], category: str) -> Optional[str]:
    allowed = SIGMA_FIELDS.get(category)
    if not allowed:
        return None
    lowered = {f.lower() for f in allowed}
    for _, block in blocks(detection):
        for key in block:
            field = base_field(key)
            if field.lower() not in lowered:
                return (
                    f"{field} is not a {category} field, so the rule can never match; "
                    f"{category} carries {', '.join(allowed[:8])}. Put other telemetry in its own rule"
                )
    return None


def non_executable_image(detection: Dict[str, Any]) -> Optional[str]:
    """A document or archive as a process image or a loaded module.

    Word opening a .docx loads no .docx: H-0618 matched ``ImageLoaded|endswith: .docx``.
    """
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            if field not in IMAGE_FIELDS and field != "imageloaded":
                continue
            what = "a loaded module" if field == "imageloaded" else "a process image"
            for value in _values(raw):
                if value.strip().strip("*").lower().endswith(NON_EXECUTABLE):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, a file that is opened, never {what}; "
                        "match the program that opens it, and the file in CommandLine or TargetFilename"
                    )
    return None


def _bare(value: str) -> str:
    return value.strip().strip("*").strip().strip("'\"").removesuffix("()").lower()


def api_in_command_line(detection: Dict[str, Any]) -> Optional[str]:
    """An API or syscall name matched where only command lines, files and modules appear.

    H-0618 matched the ``Beep`` API in ``cmd.exe``'s ``CommandLine``, and on a
    later run in ``ImageLoaded`` (Beep lives in kernel32.dll; no module is
    named after it). A script host's command line can carry inline code that
    names APIs (PowerShell P/Invoke), so a command-line match is rejected only
    when the rule pins its process to something that is not a script host.
    """
    pinned = _field_values(detection, "image") + _field_values(detection, "originalfilename")
    script_host_or_unpinned = not pinned or any(h in v for v in pinned for h in _SCRIPT_HOSTS)
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            in_command_line = field in _COMMAND_LINE_FIELDS
            if in_command_line and script_host_or_unpinned:
                continue
            if not in_command_line and field not in _FILE_NAME_FIELDS:
                continue
            for value in _values(raw):
                bare = _bare(value)
                named = bare in API_NAMES or (
                    in_command_line and any(len(api) >= 10 and re.search(rf"\b{api}\b", bare) for api in API_NAMES)
                )
                if named:
                    where = "no command line shows it" if in_command_line else "it is not a file or module name"
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, an API or system call; a program calls it "
                        f"at run time and {where}"
                    )
    return None


def number_as_path(detection: Dict[str, Any]) -> Optional[str]:
    """A bare number in a file or module field: a port or ID mistaken for a path.

    H-0618 matched ``ImageLoaded|contains: '50813'``, the staging port.
    """
    for _, block in blocks(detection):
        for key, raw in block.items():
            if base_field(key).lower() not in _FILE_NAME_FIELDS:
                continue
            for value in _values(raw):
                if re.fullmatch(r"\d{2,}", value.strip().strip("*")):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, a bare number; a port or ID is not a file "
                        "or module path. Ports belong in network_connection"
                    )
    return None


def elided_value(detection: Dict[str, Any]) -> Optional[str]:
    """A value with the report's "..." in it: the elided part never appears in telemetry."""
    for _, block in blocks(detection):
        for key, raw in block.items():
            if "re" in _modifiers(key):
                continue
            for value in _values(raw):
                if _ELLIPSIS_RE.search(value):
                    return (
                        f"{base_field(key)} matches {value.strip()!r}, which keeps the report's elision; "
                        "match the parts the report gives in full"
                    )
    return None


def url_path_confusion(detection: Dict[str, Any]) -> Optional[str]:
    for _, block in blocks(detection):
        for key, raw in block.items():
            field = base_field(key).lower()
            for value in _values(raw):
                text = value.strip().strip("*")
                is_url = "://" in text or text.lower().startswith(("http", "www."))
                if field in _LOCAL_PATH_FIELDS and is_url:
                    return f"{base_field(key)} is a local path but matches the URL {value.strip()!r}"
                # Sigma escapes a literal wildcard as \? or \*; that backslash is not a path.
                unescaped = re.sub(r"\\[*?\\]", "", text)
                if field in _URL_FIELDS and (re.match(r"(?i)^[a-z]:\\", text) or "\\" in unescaped):
                    return f"{base_field(key)} is a URL but matches the local path {value.strip()!r}"
                if field in _HOST_FIELDS and "/" in text:
                    return f"{base_field(key)} holds a host name but matches the URL {value.strip()!r}"
                if field in _HOST_FIELDS and _FILE_EXTENSION_RE.search(text):
                    return f"{base_field(key)} holds a host name but matches the file name {value.strip()!r}"
    return None


# --- One event: AND-ed constraints must agree ------------------------------------------------


def _condition_tokens(condition: str) -> List[str]:
    return re.findall(r"[\w*]+", condition.lower())


def _and_only_positive(detection: Dict[str, Any], condition: str) -> Optional[List[str]]:
    """The selections a pure AND condition requires, or None when the condition ORs or counts."""
    tokens = _condition_tokens(condition)
    if not tokens or {"or", "of"} & set(tokens) or "|" in condition:
        return None
    names = {str(k).lower(): str(k) for k in detection if k != "condition"}
    positive: List[str] = []
    negate = False
    for token in tokens:
        if token == "not":
            negate = True
            continue
        if token == "and":
            continue
        if token in names and not negate:
            positive.append(names[token])
        negate = False
    return positive


def _constraint(key: Any, value: str) -> Optional[Tuple[str, str]]:
    """``(kind, value)`` for exact, endswith and startswith matches; None for anything looser."""
    mods = set(_modifiers(key))
    text = value.strip().lower()
    if mods - {"endswith", "startswith"} or len(mods) > 1:
        return None
    if "endswith" in mods:
        return ("ends", text.lstrip("*"))
    if "startswith" in mods:
        return ("starts", text.rstrip("*"))
    core = text.strip("*")
    if "*" in core or "?" in core:
        return None
    if text.startswith("*") and text.endswith("*"):
        return None
    if text.startswith("*"):
        return ("ends", core)
    if text.endswith("*"):
        return ("starts", core)
    return ("exact", core)


def _compatible(a: Tuple[str, str], b: Tuple[str, str]) -> bool:
    (ka, va), (kb, vb) = sorted([a, b])
    if ka == "ends" and kb == "ends":
        return va.endswith(vb) or vb.endswith(va)
    if ka == "starts" and kb == "starts":
        return va.startswith(vb) or vb.startswith(va)
    if ka == "ends" and kb == "exact":
        return vb.endswith(va)
    if ka == "exact" and kb == "starts":
        return va.startswith(vb)
    if ka == "exact" and kb == "exact":
        return va == vb
    return True  # startswith against endswith: one value can satisfy both


def impossible_conjunction(detection: Dict[str, Any]) -> Optional[str]:
    """AND-ed constraints one event cannot meet: two different process images, two target files.

    A process chain (Word, then cmd.exe) is two events; written as one AND it
    matches nothing. ParentImage and Image in one selection is the one-event form.
    """
    positive = _and_only_positive(detection, str(detection.get("condition", "")))
    if positive is None:
        return None
    groups: Dict[str, List[Tuple[str, List[Tuple[str, str]]]]] = {}
    for name in positive:
        block = detection.get(name)
        if not isinstance(block, dict):
            continue  # a list of maps is an OR of its own
        for key, raw in block.items():
            field = base_field(key).lower()
            if field not in _SINGLE_VALUED:
                continue
            alternatives = [_constraint(key, v) for v in _values(raw)]
            if not alternatives or any(c is None for c in alternatives):
                continue
            groups.setdefault(field, []).append((f"{name}.{key}", [c for c in alternatives if c]))
    for field, constraints in groups.items():
        for i, (left_key, left) in enumerate(constraints):
            for right_key, right in constraints[i + 1 :]:
                if not any(_compatible(a, b) for a in left for b in right):
                    return (
                        f"{left_key} and {right_key} require different {base_field(left_key.split('.', 1)[1])} "
                        "values on the same event, which no event has; a sequence of events is not one AND. "
                        "Use ParentImage for the parent, or write one rule per event"
                    )
    return None


# --- The description matches the selection --------------------------------------------------

_CHAIN_RE = re.compile(
    r"\b(?P<a>[a-z][\w-]*)(?:\.exe)?\s+(?:process\s+)?(?:spawns?|spawning|launch(?:es|ing)?|start(?:s|ing)|executes|executing)"
    r"\s+(?:a\s+|an\s+|the\s+)?(?P<b>[a-z][\w-]*)(?:\.exe)?\b"
    r"|\b(?P<c>[a-z][\w-]*)(?:\.exe)?\s+(?:is\s+|being\s+)?(?:spawned|launched|started)\s+by\s+(?:a\s+|an\s+|the\s+)?"
    r"(?P<d>[a-z][\w-]*)(?:\.exe)?\b",
    re.IGNORECASE,
)
_PROCESS_ALIASES = {"word": "winword", "excel": "excel", "powershell": "powershell"}


def _field_values(detection: Dict[str, Any], field: str) -> List[str]:
    """Values of one field across the selections the condition does not negate."""
    negated = set(_negated_names(detection))
    return [
        v.lower()
        for name, block in blocks(detection)
        if name not in negated
        for key, raw in block.items()
        if base_field(key).lower() == field
        for v in _values(raw)
    ]


def _names(values: List[str], process: str) -> bool:
    process = _PROCESS_ALIASES.get(process.lower(), process.lower())
    return any(re.search(rf"(^|[\\/*]){re.escape(process)}(\.exe)?\*?$", v) for v in values)


def description_mismatch(detection: Dict[str, Any], description: str) -> Optional[str]:
    if SUFFIX_CLAIM_RE.search(description):
        suffix_logic = any(
            {"endswith", "contains"} & set(_modifiers(key)) or any(v.startswith(("*", ".")) or "*" in v for v in _values(raw))
            for _, block in blocks(detection)
            for key, raw in block.items()
        )
        if not suffix_logic:
            return "the description promises subdomain or suffix matching, but every selection is an exact match"
    parents = _field_values(detection, "parentimage")
    children = _field_values(detection, "image")
    if not parents or not children:
        return None
    for match in _CHAIN_RE.finditer(description):
        parent, child = (match.group("a"), match.group("b")) if match.group("a") else (match.group("d"), match.group("c"))
        if _names(children, parent) and _names(parents, child) and not _names(parents, parent):
            return (
                f"the description says {parent} starts {child}, but the selection has {child} as ParentImage "
                f"and {parent} as Image; make the two agree with the source"
            )
    return None


def _negated_names(detection: Dict[str, Any]) -> List[str]:
    condition = str(detection.get("condition", "")).lower()
    negated = {m.group(1) for m in re.finditer(r"\bnot\s+(?:1 of\s+|all of\s+)?([\w*]+)", condition)}
    return [
        str(name)
        for name in detection
        if name != "condition" and any(re.fullmatch(n.replace("*", ".*"), str(name).lower()) for n in negated)
    ]


def _all_values(block: Any) -> List[str]:
    out: List[str] = []
    for item in block if isinstance(block, list) else [block]:
        if isinstance(item, dict):
            for raw in item.values():
                out += _values(raw)
        else:
            out += _values(item)
    return out


def filter_excludes_named_artifact(detection: Dict[str, Any], named: List[str]) -> Optional[str]:
    """A negated filter that removes an artifact the hunt names as the threat's.

    H-0618's rules excluded "personal resume (2).docx", the decoy the source
    reports the loader writing, so each rule filtered out the event it hunts.
    A directory is judged by what it would exclude: ``C:\\Windows\\System32\\``
    is ordinary tuning, but the A1 replay excluded ``\\Windows\\Temp\\``, where
    the source says the decoy is written.
    """
    corpus = "\n".join(named).lower()
    if not corpus:
        return None
    fragments = _file_name_fragments(named)
    paths = _named_paths(named)
    for name in _negated_names(detection):
        block = detection[name]
        for item in block if isinstance(block, list) else [block]:
            if not isinstance(item, dict):
                continue
            for key, raw in item.items():
                for value in _values(raw):
                    hit = next((p for p in paths if _filter_matches(key, value, p)), None)
                    if hit:
                        return (
                            f"filter {name!r} excludes {value.strip()!r}, which matches {hit!r}, an artifact the hunt "
                            "names as the threat's own; the rule would drop the event it hunts for"
                        )
        for value in _all_values(detection[name]):
            lowered = value.strip().strip("*").lower()
            for part in _ELLIPSIS_RE.split(lowered):
                part = part.strip().strip("_")
                if len(part) >= 8 and not part.endswith(("\\", "/")) and part in corpus:
                    return (
                        f"filter {name!r} excludes {value.strip()!r}, which the hunt names as the threat's own "
                        "artifact; the rule would drop the event it hunts for"
                    )
            # A later run excluded "Beijing Institute of Technology_2023_": the
            # decoy's own name with an invented year, which may be the decoy.
            reused = next((f for f in fragments if f in lowered), None)
            if reused:
                return (
                    f"filter {name!r} excludes {value.strip()!r}, built from {reused!r} in the threat's own file name; "
                    "it may drop the event the rule hunts for"
                )
    return None


_NAMED_PATH_RE = re.compile(r"(?:[A-Za-z]:|%\w+%)?(?:\\[^\\\n'\"`|]+)+\.[a-z0-9]{2,5}\b", re.IGNORECASE)


def _named_paths(named: List[str]) -> List[str]:
    """Full Windows paths in what the hunt names, with any elision kept."""
    return sorted({m.group(0) for text in named for m in _NAMED_PATH_RE.finditer(text)})


def _filter_matches(key: Any, value: str, path: str) -> bool:
    """Whether a filter's condition would match an artifact path (an elision stands for any text)."""
    mods = set(_modifiers(key))
    if mods - {"contains", "startswith", "endswith"} or base_field(key).lower() not in _PATH_FILTER_FIELDS:
        return False
    concrete = _ELLIPSIS_RE.sub("x", path).lower()
    needle = value.strip().lower()
    if "*" in needle.strip("*") or "?" in needle:
        return False
    needle = needle.strip("*")
    if not needle:
        return False
    if "contains" in mods or (value.startswith("*") and value.endswith("*")):
        return needle in concrete
    if "startswith" in mods or value.endswith("*"):
        return concrete.startswith(needle)
    if "endswith" in mods or value.startswith("*"):
        return concrete.endswith(needle)
    return concrete == needle


_PATH_FILTER_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "commandline", "parentcommandline"})


def _file_name_fragments(named: List[str]) -> List[str]:
    """Distinctive pieces of the file names the hunt names: the base name, split at any elision."""
    out: List[str] = []
    for text in named:
        for path in re.findall(r"[^\s:'\"`|]*[\\/][^\\/\n'\"`|]+\.[a-z0-9]{2,5}\b", text, re.IGNORECASE):
            base = re.split(r"[\\/]", path)[-1].lower()
            out += [p.strip().strip("_") for p in _ELLIPSIS_RE.split(base) if len(p.strip().strip("_")) >= 12]
    return out


def filter_cancels_selection(detection: Dict[str, Any]) -> Optional[str]:
    """A negated filter every selected event also matches: the rule can never fire.

    H-0618's #6 replay drafted ``selection: {ImageLoaded|contains: vshell, Image|endswith: \\cmd.exe}``
    with ``filter: {ImageLoaded|contains: vshell}`` and ``selection and not filter``.
    """
    positive = _and_only_positive(detection, str(detection.get("condition", "")))
    if not positive:
        return None
    required = {
        (str(key).lower(), tuple(sorted(v.lower() for v in _values(raw))))
        for name in positive
        if isinstance(detection.get(name), dict)
        for key, raw in detection[name].items()
    }
    for name in _negated_names(detection):
        block = detection.get(name)
        if not isinstance(block, dict) or not block:
            continue
        constraints = {(str(key).lower(), tuple(sorted(v.lower() for v in _values(raw)))) for key, raw in block.items()}
        if constraints <= required:
            return (
                f"filter {name!r} repeats conditions the selection already requires, so every event the "
                "selection matches is filtered out and the rule never fires"
            )
    return None


def semantic_problem(
    detection: Dict[str, Any], category: str, description: str = "", named: Optional[List[str]] = None
) -> Optional[str]:
    """The first semantic defect in a structurally valid rule, or None.

    ``named`` is what the hunt names as the threat's (observables and
    indicators); a filter may not exclude any of it.
    """
    checks = (
        lambda: field_outside_category(detection, category),
        lambda: non_executable_image(detection),
        lambda: api_in_command_line(detection),
        lambda: url_path_confusion(detection),
        lambda: elided_value(detection),
        lambda: number_as_path(detection),
        lambda: impossible_conjunction(detection),
        lambda: description_mismatch(detection, description),
        lambda: filter_cancels_selection(detection),
        lambda: filter_excludes_named_artifact(detection, named or []),
    )
    for check in checks:
        problem = check()
        if problem:
            return problem
    return None
