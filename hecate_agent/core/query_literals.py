"""Two-pass query generation, pass one: the exact values a rule may match.

Asked for rules from a hypothesis, the model reached for plausible strings:
``vshell`` as a loaded module, ``Beep`` as a DLL, ``C:\\Windows\\Temp\\Beijing
Institute of Technology_2023_`` with an invented year, and the report's
``..._personal resume (2).docx`` elision copied verbatim. Semantic checks
rejected each one after the fact, and the decoy path never reached a rule.

Pass one turns the primary source's verified artifacts into Sigma-ready
literals: each with the value as Sigma must write it and the fields it can
appear in. Pass two (the Sigma generator) may use only these values, plus
standard system binaries, in file, process, command-line and registry
fields. An elision becomes a wildcard, which is how Sigma says "some
characters the report did not give".
"""

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Sequence

#: Fields where a rule names a file, process, command or key: the ones a literal must ground.
GROUNDED_FIELDS = frozenset(
    {"targetfilename", "image", "parentimage", "imageloaded", "originalfilename", "commandline", "parentcommandline",
     "targetobject"}
)  # fmt: skip
#: System binaries a behavioural rule may name without the source spelling them out.
SYSTEM_IMAGES = frozenset(
    {"cmd.exe", "powershell.exe", "pwsh.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "explorer.exe",
     "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "svchost.exe",
     "conhost.exe", "schtasks.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "kernel32.dll", "ntdll.dll",
     # Unix and macOS: the Huntress replay rejected a rule for /bin/bash.
     "bash", "sh", "zsh", "dash", "curl", "wget", "osascript", "launchctl", "xattr", "chmod", "chown", "cp", "mv", "rm",
     "mkdir", "python", "python3", "perl", "ruby", "systemctl", "crontab", "nohup", "open", "security", "codesign",
     "spctl", "launchd", "uname", "ioreg", "system_profiler", "whoami", "sudo", "base64", "openssl", "ditto",
     "hdiutil", "installer", "pkill", "killall", "ps", "tar", "unzip", "nc", "ncat", "socat", "ssh", "scp"}
)  # fmt: skip
#: Directory prefixes a rule may scope by on their own ("C:\\Windows\\Temp\\" with ".docx").
SYSTEM_DIRECTORIES = frozenset(
    {"c:\\windows\\", "c:\\windows\\temp\\", "c:\\windows\\system32\\", "c:\\users\\", "c:\\programdata\\",
     "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\temp\\", "\\windows\\temp\\",
     "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/",
     "/etc/", "/home/", "/users/", "/library/", "/library/caches/", "/library/launchagents/", "/library/launchdaemons/",
     "/system/library/", "/applications/", "/etc/cron.d/", "/etc/systemd/system/"}
)  # fmt: skip
_APP_ALIASES = {"word": "winword.exe", "excel": "excel.exe", "powerpoint": "powerpnt.exe", "outlook": "outlook.exe"}
_ELLIPSIS_RE = re.compile(r"\.\.\.|\u2026")
#: A leading variable: Windows %TEMP%, or Unix $HOME, ${HOME} and ~.
_ENV_RE = re.compile(r"^(%\w+%|\$\{?\w+\}?|~)(?=[\\/])")
#: A report's redaction of part of a path: "/Users/<redacted>/Library/...".
_REDACTION_RE = re.compile(r"<[^<>/\\]{1,30}>")
#: Evidence that the malware creates the file, not merely checks for or reads it
#: ("cp [random filename] $HOME/Library/..." and "deploying a payload ... at /Users/...").
_WRITTEN_RE = re.compile(
    r"\b(saves?|saved|writes?|written|wrote|drops?|dropped|creates?|created|copies|copied|cp|moves?|moved|mv|"
    r"installs?|installed|deploy(s|ed|ing)?|downloads? .{0,40} to)\b",
    re.I,
)
#: Evidence that a file without a Windows extension is a program: macOS and Linux executables have none.
_PROGRAM_RE = re.compile(r"\b(executable|payload|binary|malware|mach-o|elf|stealer|implant|backdoor)\b", re.I)


@dataclass
class QueryLiteral:
    """One value a rule may match, as Sigma writes it, and where it can appear."""

    value: str
    sigma: str
    kind: str
    fields: List[str]
    role: str = ""
    evidence: str = ""
    #: How to match: "exact" (whole value), "endswith" (a path under a variable
    #: directory), or "wildcard" (the report elided part of it).
    match: str = "exact"
    #: The source says the malware writes this file ("It saves it as: ...").
    written: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _path_literal(value: str) -> Dict[str, str]:
    """``{"sigma", "match"}`` for a file path: elisions become ``*``, a leading variable an ``endswith``."""
    if _ENV_RE.match(value):
        # %TEMP% and $HOME resolve per user and host; match what follows them.
        tail = _ENV_RE.sub("", value)
        if _ELLIPSIS_RE.search(tail) or _REDACTION_RE.search(tail):
            return {"sigma": "*" + _REDACTION_RE.sub("*", _ELLIPSIS_RE.sub("*", tail)), "match": "wildcard"}
        return {"sigma": tail, "match": "endswith"}
    if _ELLIPSIS_RE.search(value) or _REDACTION_RE.search(value):
        return {"sigma": _REDACTION_RE.sub("*", _ELLIPSIS_RE.sub("*", value)), "match": "wildcard"}
    return {"sigma": value, "match": "exact"}


#: A value only Windows can show: a drive letter, a %VARIABLE%, a UNC or registry-style path, an .exe or .dll.
_WINDOWS_VALUE_RE = re.compile(r"^[A-Za-z]:[\\/]|^%\w+%|^\\\\|^HK(LM|CU|EY_)|\.(exe|dll|bat|ps1|lnk|msi)$", re.I)
#: A value only a Unix-like system can show: an absolute path, or one under $HOME or ~.
_UNIX_VALUE_RE = re.compile(r"^(/|~/|\$\{?HOME\}?/)")


def off_platform(value: str, platforms: Sequence[str]) -> bool:
    """Whether no platform the hunt covers can show ``value``; never when the platforms are unknown."""
    known = {str(p).strip().lower() for p in platforms or [] if str(p).strip()}
    if not known:
        return False
    if _WINDOWS_VALUE_RE.search(value):
        return "windows" not in known
    if _UNIX_VALUE_RE.search(value):
        return known == {"windows"}
    return False


def literals_from_artifacts(artifacts: Iterable[Dict[str, Any]], platforms: Sequence[str] = ()) -> List[QueryLiteral]:
    """Sigma-ready literals from verified source artifacts that describe this intrusion.

    Artifacts the source does not tie to the intrusion (status other than
    ``active``) are left out: H-0618's list held ``personal_resume.exe`` from
    the author's closing joke. API names are EDR telemetry, not Sigma fields.
    So are values none of the hunt's ``platforms`` can show: a Linux hunt on
    the Redis botnet was offered ``C:\\host_public\\python311\\c2_persist.py``
    from the operator's Windows server.
    """
    out: List[QueryLiteral] = []
    seen: set = set()
    for artifact in artifacts:
        value = str(artifact.get("value", "")).strip()
        kind = str(artifact.get("kind", "")).lower()
        if not value or str(artifact.get("status", "")).lower() != "active" or off_platform(value, platforms):
            continue
        role, evidence = str(artifact.get("role", "")), " ".join(str(artifact.get("evidence", "")).split())[:200]
        literal: QueryLiteral
        if kind in ("file_path", "path", "file", "filename", "file_name"):
            value = _fuller_path(value, " ".join(str(artifact.get("evidence", "")).split()))
            shape = _path_literal(value)
            image = value.lower().endswith((".exe", ".dll", ".scr", ".com")) or (
                "/" in value and "." not in value.rsplit("/", 1)[-1][1:] and bool(_PROGRAM_RE.search(evidence))
            )
            fields = ["file_event.TargetFilename", "process_creation.CommandLine"]
            if image:
                fields += ["process_creation.Image", "process_creation.ParentImage"]
            literal = QueryLiteral(
                value, shape["sigma"], kind, fields, role, evidence, shape["match"], _written(value, role, evidence)
            )
        elif kind == "process":
            windows = not platforms or any(str(p).lower() == "windows" for p in platforms)
            name = _APP_ALIASES.get(value.lower(), value if "." in value or not windows else f"{value}.exe")
            # An image path ends "\\name.exe" on Windows and "/name" everywhere else.
            sigma = "\\" + name.split("\\")[-1] if windows else "/" + name.split("/")[-1]
            literal = QueryLiteral(
                value, sigma, kind, ["process_creation.Image", "process_creation.ParentImage"], role, evidence, "endswith",
            )  # fmt: skip
        elif kind in ("command_line", "command", "cmdline"):
            literal = QueryLiteral(value, value, kind, ["process_creation.CommandLine"], role, evidence)
        elif kind in ("registry_key", "registry", "reg_key", "registry_value"):
            literal = QueryLiteral(value, value, kind, ["registry_event.TargetObject"], role, evidence)
        else:
            continue  # api, hashes, addresses: EDR telemetry or the IOC rules' business
        if literal.sigma.lower() not in seen:
            seen.add(literal.sigma.lower())
            out.append(literal)
    return out


#: The report says the file is only checked for or read, not created (VShell's kill-switch marker).
_CHECKED_RE = re.compile(r"\b(marker|kill[- ]?switch|checks? (for|whether|if)|exists?|already exists|reads?)\b", re.I)
#: Places a file is written to persist: its existence there is the installation.
_PERSISTENCE_DIR_RE = re.compile(
    r"/library/launch(agents|daemons)/|/etc/systemd/system/|/etc/cron\.|/var/spool/cron/|/etc/profile\.d/"
    r"|/etc/apt/apt\.conf\.d/|/etc/init\.d/|\\start menu\\programs\\startup\\",
    re.I,
)


def _written(value: str, role: str, evidence: str) -> bool:
    """Whether the malware creates this file: a write verb, a persistence location, or the malware's own file.

    The Huntress replay's IOC table said only "Filesystem path used by this
    malware" for both stealer paths: the malware's own file on disk is written
    when it is installed. A file it only checks for is not.
    """
    # The name itself is no verb: "SAM.save" read as "save" made a registry hive export a written file.
    evidence = evidence.replace(value, " ")
    context = f"{role} {evidence}"
    if _CHECKED_RE.search(context):
        return False
    return bool(_WRITTEN_RE.search(evidence) or _PERSISTENCE_DIR_RE.search(value) or _PROGRAM_RE.search(context))


#: A user's home directory, generalized so a rule is not tied to one victim account.
_USER_DIR_RE = re.compile(r"^(/Users/|/home/|[A-Za-z]:\\Users\\)(?!\*|<)[^/\\]+", re.I)


def _fuller_path(value: str, evidence: str) -> str:
    """The full path the evidence gives for a bare file name, with the user directory generalized.

    The Huntress replay extracted "com.apple.softwareupdated.plist" while its
    evidence read ".../launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist".
    """
    if "/" in value or "\\" in value:
        return value
    match = re.search(r"(?:[A-Za-z]:\\|/)[^\s'\"`|]*[/\\]" + re.escape(value) + r"\b", evidence)
    if not match:
        return value
    return _USER_DIR_RE.sub(lambda m: m.group(1) + "*", match.group(0))


def _pieces(sigma_value: str) -> List[str]:
    """The literal characters of a Sigma value, split at its wildcards."""
    return [p.lower() for p in re.split(r"[*?]", sigma_value) if p]


def ungrounded_value(detection: Dict[str, Any], literals: List[Dict[str, Any]]) -> str:
    """The first value in a grounded field that no literal or system binary supplies, or ""."""
    if not literals:
        return ""
    supplied = [piece for lit in literals for piece in _pieces(str(lit.get("sigma", "")))]
    for block in _blocks(detection):
        for key, raw in block.items():
            if str(key).split("|")[0].strip().lower() not in GROUNDED_FIELDS:
                continue
            for value in raw if isinstance(raw, list) else [raw]:
                text = str(value)
                for piece in _pieces(text):
                    # A path-boundary suffix does not invent a directory: the
                    # source's bare pypa.py may match TargetFilename|endswith
                    # "\\pypa.py", but not an invented full path or basename.
                    field, *modifiers = str(key).lower().split("|")
                    if (field == "targetfilename" and "endswith" in modifiers
                            and re.fullmatch(r"[\\/][^\\/]+", piece)
                            and piece[1:] in supplied):
                        continue
                    if field == "commandline" and _source_supported_task_action(block, piece, literals):
                        continue
                    bare = piece.strip().lstrip("\\").lstrip("/")
                    if not bare or bare in SYSTEM_IMAGES or _is_extension(bare) or piece.strip() in SYSTEM_DIRECTORIES:
                        continue
                    if _system_binary_path(piece.strip()):
                        continue
                    # A value may use a literal or part of one, never extend it: H-0618's
                    # "...Technology_2023_" added an invented year to "...Technology_".
                    if not any(piece.strip() in s for s in supplied):
                        return text
    return ""


def _source_supported_task_action(block: Dict[str, Any], piece: str, literals: List[Dict[str, Any]]) -> bool:
    """Permit a documented tool switch for a source-supported behavior candidate.

    This derives a task-creation predicate, not a claim that the report showed
    this exact command. Task names and payload paths still need source values.
    Require the binary in the same selection so an unrelated OR branch cannot
    license an arbitrary command-line fragment.
    """
    if piece.strip() != "/create":
        return False
    images = [str(v).lower().replace("/", "\\") for k, raw in block.items()
              if str(k).lower() in {"image", "image|endswith"}
              for v in (raw if isinstance(raw, list) else [raw])]
    if not any(v.rsplit("\\", 1)[-1] == "schtasks.exe" for v in images):
        return False
    from hecate_agent.core.technique_evidence import sentence_status

    return any(
        re.search(r"\bscheduled tasks?\b", str(lit.get("evidence", "")), re.I)
        and re.search(r"\b(creat\w*|persist\w*)\b", str(lit.get("evidence", "")), re.I)
        and sentence_status(str(lit.get("evidence", ""))) == "observed"
        for lit in literals
    )


def _system_binary_path(piece: str) -> bool:
    """``C:\\Windows\\System32\\cmd.exe`` or ``/usr/bin/xattr``: a standard binary under a standard directory."""
    sep = "/" if "/" in piece and "\\" not in piece else "\\"
    directory, _, name = piece.rpartition(sep)
    return name in SYSTEM_IMAGES and (directory + sep) in SYSTEM_DIRECTORIES


def _is_extension(piece: str) -> bool:
    return bool(re.fullmatch(r"\.?[a-z0-9]{1,5}", piece))


def _blocks(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for name, block in detection.items():
        if name == "condition":
            continue
        out += [b for b in (block if isinstance(block, list) else [block]) if isinstance(b, dict)]
    return out


def render_literals(literals: List[Dict[str, Any]]) -> str:
    """The prompt block: each value as Sigma writes it, and the fields it belongs in."""
    lines = []
    for lit in literals:
        how = {"endswith": " (match with |endswith)", "wildcard": " (the report elided part of it: keep the *)"}.get(
            str(lit.get("match")), ""
        )
        lines.append(f"  - {lit.get('sigma')}{how} -> {', '.join(lit.get('fields') or [])} [{lit.get('role', '')}]")
    return "\n".join(lines)
