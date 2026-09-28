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
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List

#: Fields where a rule names a file, process, command or key: the ones a literal must ground.
GROUNDED_FIELDS = frozenset(
    {"targetfilename", "image", "parentimage", "imageloaded", "originalfilename", "commandline", "parentcommandline",
     "targetobject"}
)  # fmt: skip
#: System binaries a behavioural rule may name without the source spelling them out.
SYSTEM_IMAGES = frozenset(
    {"cmd.exe", "powershell.exe", "pwsh.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "explorer.exe",
     "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "svchost.exe",
     "conhost.exe", "schtasks.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "kernel32.dll", "ntdll.dll"}
)  # fmt: skip
#: Directory prefixes a rule may scope by on their own ("C:\\Windows\\Temp\\" with ".docx").
SYSTEM_DIRECTORIES = frozenset(
    {"c:\\windows\\", "c:\\windows\\temp\\", "c:\\windows\\system32\\", "c:\\users\\", "c:\\programdata\\",
     "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\temp\\", "\\windows\\temp\\"}
)  # fmt: skip
_APP_ALIASES = {"word": "winword.exe", "excel": "excel.exe", "powerpoint": "powerpnt.exe", "outlook": "outlook.exe"}
_ELLIPSIS_RE = re.compile(r"\.\.\.|\u2026")
_ENV_RE = re.compile(r"^%\w+%")
#: Evidence that the malware creates the file, not merely checks for or reads it.
_WRITTEN_RE = re.compile(
    r"\b(saves?|saved|writes?|written|wrote|drops?|dropped|creates?|created|downloads? .{0,40} to)\b", re.I
)


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
        # %TEMP% resolves per user and host; match what follows it.
        return {"sigma": _ENV_RE.sub("", value), "match": "endswith"}
    if _ELLIPSIS_RE.search(value):
        return {"sigma": _ELLIPSIS_RE.sub("*", value), "match": "wildcard"}
    return {"sigma": value, "match": "exact"}


def literals_from_artifacts(artifacts: Iterable[Dict[str, Any]]) -> List[QueryLiteral]:
    """Sigma-ready literals from verified source artifacts that describe this intrusion.

    Artifacts the source does not tie to the intrusion (status other than
    ``active``) are left out: H-0618's list held ``personal_resume.exe`` from
    the author's closing joke. API names are EDR telemetry, not Sigma fields.
    """
    out: List[QueryLiteral] = []
    seen: set = set()
    for artifact in artifacts:
        value = str(artifact.get("value", "")).strip()
        kind = str(artifact.get("kind", "")).lower()
        if not value or str(artifact.get("status", "")).lower() != "active":
            continue
        role, evidence = str(artifact.get("role", "")), " ".join(str(artifact.get("evidence", "")).split())[:200]
        literal: QueryLiteral
        if kind in ("file_path", "path", "file", "filename", "file_name"):
            shape = _path_literal(value)
            image = value.lower().endswith((".exe", ".dll", ".scr", ".com"))
            fields = ["file_event.TargetFilename", "process_creation.CommandLine"]
            if image:
                fields += ["process_creation.Image", "process_creation.ParentImage"]
            literal = QueryLiteral(
                value, shape["sigma"], kind, fields, role, evidence, shape["match"], bool(_WRITTEN_RE.search(evidence))
            )
        elif kind == "process":
            name = _APP_ALIASES.get(value.lower(), value if "." in value else f"{value}.exe")
            literal = QueryLiteral(
                value, "\\" + name.split("\\")[-1], kind, ["process_creation.Image", "process_creation.ParentImage"],
                role, evidence, "endswith",
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
                    bare = piece.strip().lstrip("\\")
                    if not bare or bare in SYSTEM_IMAGES or _is_extension(bare) or piece.strip() in SYSTEM_DIRECTORIES:
                        continue
                    if _system_binary_path(piece.strip()):
                        continue
                    # A value may use a literal or part of one, never extend it: H-0618's
                    # "...Technology_2023_" added an invented year to "...Technology_".
                    if not any(piece.strip() in s for s in supplied):
                        return text
    return ""


def _system_binary_path(piece: str) -> bool:
    """``C:\\Windows\\System32\\cmd.exe``: a standard binary under a standard directory."""
    directory, _, name = piece.rpartition("\\")
    return name in SYSTEM_IMAGES and (directory + "\\") in SYSTEM_DIRECTORIES


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
