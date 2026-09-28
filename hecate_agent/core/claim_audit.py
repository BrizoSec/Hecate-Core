"""Audit a draft's observables and prose against what the evidence supports.

The model writes the hypothesis, justification, ABLE fields and observables.
Across the H-0618 runs those carried the same kinds of defect again and again:
placeholder observables (``<unknown executable name>``), baselines about
"similar SHA256 hashes", command-line fields said to show logic that runs
inside a binary, API names used as file names (``memfd_create``), and tool
capability stated as fact ("enables persistent, stealthy access" when the
source showed no persistence mechanism).

Observables that cannot be observed are removed. A capability claim with no
observed technique behind it is softened to "could ...", in place, and recorded.
"Fileless" beside a loader the source publishes as an executable becomes
"in-memory". Every action is reported, so nothing changes silently.
"""

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from hecate_agent.core.sigma_semantics import API_NAMES


@dataclass
class ClaimFinding:
    field: str
    text: str
    action: str  # "removed" | "softened" | "corrected"
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


# --- Observables -----------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"<[^>\n]{2,}>|\[[^\]\n]*(populate|placeholder|todo|tbd|unknown)[^\]\n]*\]", re.I)
_SIMILAR_HASH = re.compile(r"\bsimilar (sha-?(1|256)|md5|file )?hash(es)?\b|\bsimilar sha-?(1|256)\b", re.I)
_CMDLINE_INTERNAL = re.compile(
    r"\b(command|cmd)[ _-]?line\b[^\n]{0,60}\b(sleep|timer|cpu checks?|sandbox checks?|api calls?|logic|virtualalloc|virtualprotect"
    r"|createthread|beep|memfd_create)\b",
    re.I,
)
_NAME_FIELD = re.compile(
    r"^\s*(process|file|image|parent_process|process\.file|file_activity\.file)[\w.]*\.?(name|path|image)\s*[:=]\s*['\"]?([\w.-]+)",
    re.I,
)


def audit_observables(
    values: Iterable[str], field: str, unobservable: Optional[Dict[str, str]] = None
) -> Tuple[List[str], List[ClaimFinding]]:
    """Keep observables that name something telemetry can show; report the rest.

    ``unobservable`` maps values the pipeline already knows cannot be seen in
    logs (a hash that exists only in memory, an artifact the source does not
    tie to this intrusion) to the reason, matched case-insensitively.
    """
    known = {k.lower(): v for k, v in (unobservable or {}).items()}
    kept: List[str] = []
    findings: List[ClaimFinding] = []
    for raw in values:
        text = str(raw).strip()
        reason = _observable_problem(text) or known.get(text.strip("`").lower(), "")
        if reason:
            findings.append(ClaimFinding(field, text, "removed", reason))
        elif text:
            kept.append(text)
    return kept, findings


def _observable_problem(text: str) -> str:
    if _PLACEHOLDER.search(text):
        return "placeholder, not a value"
    if _SIMILAR_HASH.search(text):
        return "hashes match exactly or not at all; there is no similar hash"
    if _CMDLINE_INTERNAL.search(text):
        return "checks and API calls run inside the binary; a command line does not show them"
    name = _NAME_FIELD.match(text)
    if name and name.group(3).lower().rstrip(".") in API_NAMES:
        return f"{name.group(3)} is an API or system call, not a file or process name"
    if text.strip().strip("`'\"").rstrip("()").lower() in API_NAMES:
        # The A3 replay listed a bare "Beep" as something suspicious to look for.
        return "an API call a program makes; only EDR API telemetry records it, no log shows it as a value"
    return ""


# --- Capability stated as fact ---------------------------------------------------------------

#: Behaviour a report often lists as a tool's capability, and the technique
#: prefixes whose observed use would support stating it as fact.
_CAPABILITY_CLAIMS: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    ("persistence", r"persisten(t|ce)",
     ("T1053", "T1547", "T1543", "T1546", "T1574", "T1137", "T1197", "T1136", "T1098", "T1505")),
    ("exfiltration", r"exfiltrat\w*|data theft|steal(s|ing)? (data|files|documents)",
     ("T1041", "T1048", "T1567", "T1020", "T1030", "T1011", "T1052")),
    ("lateral movement", r"lateral movement|mov(e|es|ing) laterally",
     ("T1021", "T1570", "T1210", "T1534", "T1080")),
    ("credential theft", r"credential (theft|dumping|harvesting|access)|steal(s|ing)? credentials",
     ("T1003", "T1555", "T1552", "T1056", "T1110", "T1558", "T1539")),
)  # fmt: skip

_ASSERTIVE_VERBS = {
    "enables": "enable", "enable": "enable", "provides": "provide", "provide": "provide",
    "allows": "allow", "allow": "allow", "achieves": "achieve", "achieve": "achieve",
    "maintains": "maintain", "maintain": "maintain", "establishes": "establish", "establish": "establish",
    "gains": "gain", "gain": "gain", "performs": "perform", "perform": "perform",
    "conducts": "conduct", "conduct": "conduct", "results": "result", "leads": "lead",
    "achieving": "achieve", "maintaining": "maintain", "establishing": "establish", "enabling": "enable",
}  # fmt: skip
_HEDGES = re.compile(r"\b(could|may|might|can|would|potential(ly)?|possibl[ey]|capab\w+)\b", re.I)
_NOTE = " (capability; not observed in the source)"


def _supported(prefixes: Tuple[str, ...], techniques: Set[str]) -> bool:
    return any(t.upper().startswith(prefixes) for t in techniques)


def soften_capability_claims(text: str, field: str, techniques: Set[str]) -> Tuple[str, List[ClaimFinding]]:
    """Soften "<verb> ... persistence/exfiltration/..." to "could <verb> ..." without supporting techniques."""
    findings: List[ClaimFinding] = []
    for label, noun, prefixes in _CAPABILITY_CLAIMS:
        if _supported(prefixes, techniques):
            continue
        verbs = "|".join(sorted(_ASSERTIVE_VERBS, key=len, reverse=True))
        pattern = re.compile(rf"\b({verbs})\b(?P<gap>[^.;:]{{0,60}}?)\b(?P<noun>{noun})\b", re.I)

        def repl(match: "re.Match[str]") -> str:
            before = text[max(0, match.start() - 40) : match.start()]
            if _HEDGES.search(before.split(".")[-1]):
                return match.group(0)
            verb = match.group(1)
            base = _ASSERTIVE_VERBS[verb.lower()]
            findings.append(
                ClaimFinding(
                    field, match.group(0), "softened", f"{label} is a capability here: no {label} technique was observed"
                )
            )
            # "..., enabling X" stays a participle: "..., potentially enabling X".
            # "to achieve X" stays an infinitive: "to potentially achieve X".
            infinitive = re.search(r"\bto\s*$", before, re.I) is not None
            modal = "potentially" if verb.lower().endswith("ing") or infinitive else "could"
            softened = f"{modal} {base if modal == 'could' or infinitive else verb.lower()}"
            softened = softened[0].upper() + softened[1:] if verb[0].isupper() else softened
            return f"{softened}{match.group('gap')}{match.group('noun')}{_NOTE}"

        text = pattern.sub(repl, text)
    return text, findings


# --- On-disk component called fileless -------------------------------------------------------

_FILELESS_LOADER = re.compile(
    r"\bfileless\b[^.;]{0,40}\b(loader|dropper|installer|executable)\b|\b(loader|dropper)\b[^.;]{0,20}\bfileless\b", re.I
)


def correct_fileless_on_disk(text: str, field: str, on_disk_executable: bool) -> Tuple[str, List[ClaimFinding]]:
    """Call the loader's execution "in-memory", not "fileless", when the source publishes it as an on-disk file.

    The later stages do run in memory, so "in-memory" stays true; "fileless"
    tells a hunter there is no file to look for, and the loader is one.
    """
    if not on_disk_executable:
        return text, []
    findings: List[ClaimFinding] = []

    def repl(match: "re.Match[str]") -> str:
        findings.append(
            ClaimFinding(
                field,
                match.group(0),
                "corrected",
                "the source publishes the loader as an on-disk executable; only later stages run in memory",
            )
        )
        return re.sub(
            r"\bfileless\b", lambda m: "In-memory" if m.group(0)[0].isupper() else "in-memory", match.group(0), flags=re.I
        )

    return _FILELESS_LOADER.sub(repl, text), findings


def audit_prose(
    fields: Dict[str, str], techniques: Set[str], on_disk_executable: bool
) -> Tuple[Dict[str, str], List[ClaimFinding]]:
    """Softened copies of the prose fields, and every finding, in field order."""
    out: Dict[str, str] = {}
    findings: List[ClaimFinding] = []
    for name, text in fields.items():
        softened, found = soften_capability_claims(text or "", name, techniques)
        corrected, fixed = correct_fileless_on_disk(softened, name, on_disk_executable)
        out[name] = corrected
        findings += found + fixed
    return out, findings


def render_findings(findings: List[ClaimFinding], limit: Optional[int] = None) -> str:
    """Markdown bullets for a draft's Claim Audit section."""
    lines = [f'- **{f.action}** ({f.field}): "{f.text}" — {f.reason}' for f in findings[:limit]]
    return "\n".join(lines)
