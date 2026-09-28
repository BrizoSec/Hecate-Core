"""How OS internals actually appear in telemetry, for the prompts that name observables and fields.

The model knows the names of OS internals and not where they show up in logs.
H-0618 and its research listed ``process.file.name: memfd_create`` (a Linux
system call, never a file name), matched the ``Beep`` API in ``CommandLine``
and as a loaded DLL, and looked for a reflectively loaded stager in
``image_load``, which only records modules loaded from disk. The claim audit
(#7) and the Sigma gates (#5) now reject those after the fact; these examples
aim to stop the model writing them.

Each entry says what an internal is, where it really appears (the event and
field, with a concrete value), and where it never appears. Entries are chosen
by what the hunt's text mentions, on the hunt's platforms, so a prompt carries
a handful of relevant examples rather than the whole table.
"""

import re
from dataclasses import dataclass
from typing import List, Sequence, Tuple


@dataclass(frozen=True)
class TelemetryExample:
    platform: str
    concept: str
    triggers: str
    appears_as: str
    never_as: str


EXAMPLES: Tuple[TelemetryExample, ...] = (
    # --- Linux ---------------------------------------------------------------------------------
    TelemetryExample(
        "Linux", "memfd_create (system call)", r"memfd",
        "the executed image path `/memfd:<name> (deleted)` in process_creation `Image` (Sysmon for Linux), or "
        "`syscall=memfd_create` in an auditd SYSCALL record",
        "a process name, file name or command-line argument",
    ),
    TelemetryExample(
        "Linux", "/proc/self/fd/N execution", r"/proc/self/fd|/proc/\d+/fd|fexecve",
        "`Image` or `CommandLine` beginning `/proc/self/fd/` in process_creation",
        "a file written to disk (no file_event exists for it)",
    ),
    TelemetryExample(
        "Linux", "/dev/shm staging", r"/dev/shm|tmpfs|shared memory",
        "file_event `TargetFilename` beginning `/dev/shm/`, then process_creation `Image` beginning `/dev/shm/`",
        "a Windows temp path",
    ),
    TelemetryExample(
        "Linux", "LD_PRELOAD hijacking", r"ld_preload|ld\.so\.preload",
        "file_event `TargetFilename: /etc/ld.so.preload`; the environment variable itself only in auditd execve "
        "records or EDR",
        "a process name or a registry key",
    ),
    TelemetryExample(
        "Linux", "ptrace injection", r"ptrace",
        "auditd `syscall=ptrace` or EDR process-access telemetry",
        "a process_creation field (ptrace starts no process)",
    ),
    TelemetryExample(
        "Linux", "cron or systemd persistence", r"\bcron|crontab|systemd|systemctl",
        "file_event `TargetFilename` under `/etc/cron.d/`, `/var/spool/cron/` or `/etc/systemd/system/*.service`; "
        "process_creation of `crontab` or `systemctl`",
        "a registry key",
    ),
    # --- Windows -------------------------------------------------------------------------------
    TelemetryExample(
        "Windows", "Win32 API calls (VirtualAlloc, VirtualProtect, CreateThread, Beep, AllocADsMem)",
        r"virtualalloc|virtualprotect|createthread|\bbeep\b|allocadsmem|rtlmovememory|\bwin32 api",
        "only EDR API or ETW threat-intelligence telemetry; Sigma's generic log sources carry none of them",
        "a process name, file name, loaded DLL or command-line argument (PowerShell inline P/Invoke is the one "
        "exception)",
    ),
    TelemetryExample(
        "Windows", "reflective or in-memory loading", r"reflective|fileless|memory[- ]only|in[- ]memory",
        "EDR memory telemetry (executable private memory, unbacked threads); the process that hosts it appears in "
        "process_creation",
        "image_load, which records only modules loaded from a file on disk",
    ),
    TelemetryExample(
        "Windows", "process injection", r"process injection|inject(s|ed|ing)? into|hollow|createremotethread|writeprocessmemory",
        "create_remote_thread (`SourceImage`, `TargetImage`, Sysmon event 8) and process_access "
        "(`GrantedAccess`, event 10)",
        "process_creation fields alone",
    ),
    TelemetryExample(
        "Windows", "LSASS credential access", r"lsass|credential dump|mimikatz|minidump",
        "process_access `TargetImage` ending `\\lsass.exe` with `GrantedAccess` such as `0x1010`",
        "a file_event unless a dump file is written",
    ),
    TelemetryExample(
        "Windows", "%TEMP% and other environment variables", r"%temp%|%appdata%|%programdata%|%localappdata%",
        "the expanded path: `C:\\Users\\<user>\\AppData\\Local\\Temp\\` (or `C:\\Windows\\Temp\\` for SYSTEM); "
        "match with `|endswith` on the part after the variable",
        "the literal text `%TEMP%` (logs record expanded paths)",
    ),
    TelemetryExample(
        "Windows", "Run-key persistence", r"run key|currentversion\\run|autorun",
        "registry_event `TargetObject` containing `\\CurrentVersion\\Run\\`",
        "a file_event",
    ),
    TelemetryExample(
        "Windows", "scheduled tasks", r"scheduled task|schtasks",
        "process_creation `Image` ending `\\schtasks.exe` with `/create` in `CommandLine`; file_event under "
        "`C:\\Windows\\System32\\Tasks\\`",
        "a registry Run key",
    ),
    TelemetryExample(
        "Windows", "DLL side-loading", r"side-?load|dll hijack|search order",
        "image_load `ImageLoaded` outside `C:\\Windows\\System32\\` for a DLL normally loaded from there, with a "
        "signed `Image`",
        "process_creation (loading a DLL starts no process)",
    ),
    # --- macOS ---------------------------------------------------------------------------------
    TelemetryExample(
        "macOS", "LaunchAgent or LaunchDaemon persistence", r"launch(agent|daemon)|launchctl",
        "file_event `TargetFilename` under `~/Library/LaunchAgents/` or `/Library/LaunchDaemons/` ending `.plist`; "
        "process_creation of `launchctl`",
        "a Windows registry key",
    ),
    TelemetryExample(
        "macOS", "AppleScript execution", r"osascript|applescript",
        "process_creation `Image: /usr/bin/osascript` with the script or `-e` in `CommandLine`",
        "a file name alone",
    ),
    TelemetryExample(
        "macOS", "Gatekeeper quarantine removal", r"gatekeeper|quarantine|xattr",
        "process_creation of `/usr/bin/xattr` with `com.apple.quarantine` in `CommandLine`",
        "a network event",
    ),
    TelemetryExample(
        "macOS", "DYLD_INSERT_LIBRARIES injection", r"dyld|dylib|insert_libraries",
        "the environment of an Endpoint Security exec event, visible to EDR only",
        "a process name or command-line argument",
    ),
)  # fmt: skip

#: Always included: the confusion behind every example above.
GENERAL_RULE = (
    "A system call or API (memfd_create, VirtualAlloc, CreateThread, Beep) is something a program calls, not a "
    "process, file, module or command-line value; name the event and field where its effect is recorded, or say "
    "it needs EDR."
)


def _observed_text(text: str) -> str:
    """The sentences that report what happened: capability, negation and other actors' tradecraft are left out.

    The VShell report says the chain runs "without persistence" and lists
    other actors' "sideloading"; neither should put a persistence or
    side-loading example in front of the model.
    """
    from hecate_agent.core.technique_evidence import sentence_status, sentences

    return "\n".join(s for s in sentences(text) if sentence_status(s) == "observed" and not _NEGATION_RE.search(s))


_NEGATION_RE = re.compile(r"\bwithout\b|\bno (persistence|evidence)\b|\bnot (observed|seen|used)\b", re.I)


def select_examples(text: str, platforms: Sequence[str] = (), limit: int = 6) -> List[TelemetryExample]:
    """Examples whose triggers an observed sentence mentions, on the hunt's platforms (all when none is known)."""
    wanted = {p.lower() for p in platforms}
    observed = _observed_text(text)
    chosen: List[TelemetryExample] = []
    for example in EXAMPLES:
        if wanted and example.platform.lower() not in wanted:
            continue
        if re.search(example.triggers, observed, re.IGNORECASE):
            chosen.append(example)
    return chosen[:limit]


def render_examples(text: str, platforms: Sequence[str] = (), limit: int = 6) -> str:
    """The prompt block: the general rule and the relevant examples, or "" when nothing is relevant."""
    chosen = select_examples(text, platforms, limit)
    if not chosen:
        return ""
    lines = [f"HOW OS INTERNALS APPEAR IN TELEMETRY (use these; do not invent fields). {GENERAL_RULE}"]
    for example in chosen:
        lines.append(
            f"- {example.concept} ({example.platform}): appears as {example.appears_as}. Never as {example.never_as}."
        )
    return "\n".join(lines) + "\n\n"
