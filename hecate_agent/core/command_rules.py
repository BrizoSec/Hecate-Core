"""Process rules from the command lines a report shows being run.

Reports often quote the exact commands an intrusion ran. The Huntress ClickFix
report lists the loader's sequence: ``ioreg -c IOPlatformExpertDevice -d 2``,
``system_profiler SPHardwareDataType``, ``xattr -d com.apple.quarantine ...``,
``launchctl bootstrap gui/501 ...``. Left to the model, those became at most
one generic rule; a command quoted in the report is the most specific thing a
process rule can match, and needs no judgement.

Each command of a known external program, found in a sentence that reports
what happened (the status test from :mod:`technique_evidence`), becomes one
``process_creation`` candidate: the program's image and the command's first
distinctive argument. Shell builtins (``history``, ``fc``, ``export``, ``cd``)
are left out: they run inside the user's shell, start no process, and no
process event can see them.
"""

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hecate_agent.core.provenance import refang
from hecate_agent.core.technique_evidence import actor_material_report, sentence_status

#: program -> (platform, rule level). Discovery tools run constantly on healthy
#: hosts, so a match on them alone is a low-level lead.
_UNIX: Dict[str, str] = {
    "xattr": "medium", "launchctl": "medium", "osascript": "medium", "curl": "medium", "wget": "medium",
    "chmod": "low", "chown": "low", "cp": "low", "mv": "low", "rm": "low", "mkdir": "low", "security": "medium",
    "codesign": "low", "spctl": "medium", "systemctl": "medium", "crontab": "medium", "dscl": "medium",
    "defaults": "low", "base64": "low", "openssl": "low", "nohup": "low", "ioreg": "low", "system_profiler": "low",
    "sudo": "low", "pkill": "low", "killall": "low", "ditto": "low", "hdiutil": "low", "bash": "medium",
    "sh": "medium", "zsh": "medium", "python3": "low", "perl": "low", "nc": "medium", "socat": "medium",
    "nsenter": "high", "bpftool": "high", "kubectl": "medium", "crictl": "medium", "docker": "medium",
    "podman": "medium", "nerdctl": "medium", "runc": "high", "insmod": "high", "modprobe": "medium", "rmmod": "medium",
}  # fmt: skip
_WINDOWS: Dict[str, str] = {
    "powershell": "medium", "pwsh": "medium", "cmd": "low", "rundll32": "medium", "regsvr32": "medium",
    "mshta": "medium", "wmic": "medium", "certutil": "medium", "bitsadmin": "medium", "vssadmin": "high",
    "bcdedit": "high", "wevtutil": "medium", "schtasks": "medium", "reg": "medium", "sc": "medium", "msiexec": "medium",
    "wscript": "medium", "cscript": "medium", "net": "low", "nltest": "medium", "curl.exe": "medium",
}  # fmt: skip
#: Tokens that end a command in running text: a shell separator, or a colon
#: introducing the report's explanation of it.
_STOP_RE = re.compile(r"^(;|&&?|\|\|?|>|>>|2>|:|\)|->|—)$|^:")
_PLACEHOLDER_RE = re.compile(r"^\[.*\]$|^<.*>$|^\$\(|^\$\{?\w+\}?$|^\.\.\.$|^\[|\]$")
_VARIABLE_PREFIX_RE = re.compile(r"^(\$\{?\w+\}?|~|%\w+%)(?=[/\\])")
#: Programs whose first argument is a plain-word subcommand ("launchctl bootstrap").
_SUBCOMMANDS = frozenset(
    {"launchctl", "systemctl", "defaults", "dscl", "net", "sc", "reg", "schtasks", "wmic", "bcdedit", "vssadmin",
     "wevtutil", "crontab", "spctl", "codesign", "hdiutil", "openssl", "bpftool", "kubectl", "crictl", "docker",
     "podman", "nerdctl", "nsenter"}
)  # fmt: skip
#: Words that follow a program name in prose ("cmd.exe and then Word", "Bash script that").
_PROSE_WORDS = frozenset(
    {"and", "then", "the", "to", "a", "an", "that", "which", "is", "was", "from", "with", "for", "or", "in", "on", "as",
     "are", "itself", "script", "scripts", "command", "commands", "process", "window", "binary", "shell", "loader",
     "profiler", "tool", "tools", "awareness", "team", "teams", "operations", "center", "centre", "training"}
)  # fmt: skip
#: A token shaped like a command-line argument.
_ARGUMENT_SHAPE_RE = re.compile(r"^[-+/.~$\"'%\\]|[./:=\\]|[a-z][A-Z]|\d")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


@dataclass
class ObservedCommand:
    program: str
    platform: str
    argument: str
    command: str
    passage: str
    level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _program_re(programs: Sequence[str]) -> re.Pattern:
    names = "|".join(sorted((re.escape(p) for p in programs), key=len, reverse=True))
    return re.compile(rf"(?:(?<=\s)|^|(?<=[(`'\"]))(?:[\w./\\-]*[/\\])?(?P<prog>{names})(?:\.exe)?(?=\s)", re.IGNORECASE)


def _distinctive(tokens: List[str], program: str = "") -> Optional[str]:
    """The first argument that says what the command does: not a flag, placeholder or bare number."""
    if program in ("bpftool", "kubectl", "crictl", "docker", "podman", "nerdctl"):
        clean = [t.strip("\"'`,);") for t in tokens if t and not _PLACEHOLDER_RE.search(t)]
        if len(clean) >= 2 and not clean[0].startswith("-") and not clean[1].startswith("-"):
            return f"{clean[0]} {clean[1]}"
    if program == "nsenter":
        for tok in tokens:
            cleaned_tok = tok.strip("\"'`,);")
            if cleaned_tok.startswith(("/", "\\")) or "sh" in cleaned_tok:
                return cleaned_tok
        return "--target"
    if program == "schtasks":
        for i, tok in enumerate(tokens):
            if tok.lower() in ("/tn", "-tn") and i + 1 < len(tokens):
                name = tokens[i + 1].strip("\"'`,").rstrip(";)")
                if name and not _PLACEHOLDER_RE.search(name) and len(name) >= 3:
                    return name
        for i, tok in enumerate(tokens):
            if tok.lower() in ("/tr", "-tr") and i + 1 < len(tokens):
                target = tokens[i + 1].strip("\"'`,").rstrip(";)")
                if target and not _PLACEHOLDER_RE.search(target) and len(target) >= 3:
                    return target
    flag = ""
    for token in tokens:
        token = token.strip("\"'`,").rstrip(";)")
        if not token or _PLACEHOLDER_RE.search(token):
            flag = ""
            continue
        if token.startswith(("-", "+")) or (token.startswith("/") and len(token) <= 3):
            flag = token
            continue
        stripped = _VARIABLE_PREFIX_RE.sub("", token)
        if len(stripped) < 4 or stripped.isdigit():
            flag = ""
            continue
        # Keep the flag in front of the argument when it is a short option ("-d com.apple.quarantine"),
        # but not across a stripped variable: "mkdir -p $HOME/Library/x" runs as "-p /Users/me/Library/x",
        # so "-p /Library/x" never occurs.
        return f"{flag} {stripped}" if flag and len(flag) <= 3 and stripped == token else stripped
    return None


def _command_sentences(text: str) -> List[str]:
    """Sentences with the text's own spacing: page extraction breaks lines inside commands, and
    the technique joiner's punctuation tidy-up turns "bash .UlaccK" into "bash.UlaccK"."""
    lines = []
    for line in refang(text or "").splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        if (
            trimmed.startswith(("-", "*", "•"))
            or trimmed.startswith("#")
            or trimmed.startswith("```")
            or trimmed.endswith("```")
        ):
            lines.append(". " + trimmed.strip("-*•# `\t") + " .")
        else:
            lines.append(trimmed)
    joined = re.sub(r"\s+", " ", " ".join(lines))
    return [s.strip(" .") for s in _SENTENCE_RE.split(joined) if s.strip(" .")]


def _command_shaped(program: str, written: str, tokens: List[str], platform: str = "unix") -> bool:
    """Whether a program name starts a command rather than a sentence about the program."""
    if not tokens:
        return False
    if platform == "unix" and written != written.lower():
        return False  # on Unix, commands are quoted as typed; "Bash script" is prose
    first = tokens[0].strip("\"'`,").rstrip(".;:!?)")
    if first.lower() in _PROSE_WORDS:
        return False
    return bool(_ARGUMENT_SHAPE_RE.search(first)) or (program in _SUBCOMMANDS and first.isalpha() and first.islower())


def observed_commands(
    text: str,
    platforms: Sequence[str] = (),
    limit: int = 10,
    primary_actor: Optional[str] = None,
) -> List[ObservedCommand]:
    """Commands of known programs in the observed sentences of ``text``, one per program and argument."""
    wanted = {p.lower() for p in platforms}
    catalogs: List[Tuple[str, Dict[str, str]]] = []
    if not wanted or wanted & {"macos", "linux", "containers"}:
        catalogs.append(("unix", _UNIX))
    if not wanted or "windows" in wanted:
        catalogs.append(("windows", _WINDOWS))
    found: List[ObservedCommand] = []
    seen: set = set()
    actor_material = actor_material_report(text)
    if not primary_actor:
        from hecate_agent.core.technique_evidence import extract_primary_actor

        primary_actor = extract_primary_actor(text)
    for sentence in _command_sentences(text):
        if sentence_status(sentence, actor_material, primary_actor=primary_actor) != "observed":
            continue
        for platform, catalog in catalogs:
            for match in _program_re(list(catalog)).finditer(sentence):
                if platform == "windows" and match.group(0).startswith("/"):
                    continue
                program = match.group("prog").lower()
                rest = sentence[match.end() :].split()
                tokens: List[str] = []
                for token in rest[:12]:
                    if _STOP_RE.search(token):
                        break
                    tokens.append(token)
                if not _command_shaped(program, match.group("prog"), tokens, platform):
                    continue
                argument = _distinctive(tokens, program)
                if not argument or (program, argument.lower()) in seen:
                    continue
                seen.add((program, argument.lower()))
                command = " ".join([match.group("prog"), *tokens])[:200]
                found.append(ObservedCommand(program, platform, argument, command, sentence[:300], catalog[program]))
    # Specific commands first; discovery and file utilities fill what room is left.
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(found, key=lambda c: rank.get(c.level, 3))[:limit]


#: A download tool's output option and its value: the part of the command that says it saves what it fetches.
_OUTPUT_OPTION_RE = re.compile(r"\s-[oO]\s*\S+")


def _own_text(cmd: ObservedCommand) -> str:
    """The words that are this command's alone, for judging what behaviour it shows.

    ``command`` runs on into whatever followed it in a quoted block ("chmod +x
    /tmp/.xmrig rm -rf /tmp/x.tgz ..."), so the program and the argument the
    rule matches are the safe reading. A download keeps its output option:
    "curl <url> -o <file>" is a transfer, "curl <url>" alone need not be.
    """
    if cmd.program in ("curl", "wget", "curl.exe"):
        output = _OUTPUT_OPTION_RE.search(cmd.command)
        if output:
            return cmd.command[: output.end()]
    return f"{cmd.program} {cmd.argument}"


def command_candidates(text: str, platforms: Sequence[str] = (), primary_actor: Optional[str] = None) -> List[Dict[str, Any]]:
    """Sigma candidates (category, title, detection, level, command, passage) for the observed commands."""
    out: List[Dict[str, Any]] = []
    for cmd in observed_commands(text, platforms, primary_actor=primary_actor):
        image = f"/{cmd.program}" if cmd.platform == "unix" else f"\\{cmd.program.removesuffix('.exe')}.exe"
        out.append(
            {
                "category": "process_creation",
                "title": f"{cmd.program} {cmd.argument}"[:100],
                "detection": {
                    "selection": {"Image|endswith": image, "CommandLine|contains": cmd.argument},
                    "condition": "selection",
                },
                "level": cmd.level,
                "command": cmd.command,
                "behaviour": _own_text(cmd),
                "passage": cmd.passage,
            }
        )
        if (
            cmd.program == "schtasks"
            and "/create" in cmd.command.lower()
            and cmd.argument
            and not cmd.argument.startswith("/")
        ):
            out.append(
                {
                    "category": "file_event",
                    "title": f"Scheduled task created on disk: {cmd.argument}"[:100],
                    "detection": {
                        "selection": {"TargetFilename|contains": f"\\Tasks\\{cmd.argument}"},
                        "condition": "selection",
                    },
                    "level": cmd.level,
                    "command": cmd.command,
                    "behaviour": f"scheduled task file {cmd.argument}",
                    "passage": cmd.passage,
                }
            )
    return out
