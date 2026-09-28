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
        reason = _observable_problem(text) or _known_reason(text, known)
        if reason:
            findings.append(ClaimFinding(field, text, "removed", reason))
        elif text:
            kept.append(text)
    return kept, findings


def _known_reason(text: str, known: Dict[str, str]) -> str:
    """The reason for a known-unobservable value, whole or inside the entry ("SHA-256: c666...")."""
    lowered = text.strip("`").lower()
    if lowered in known:
        return known[lowered]
    return next((why for value, why in known.items() if len(value) >= 12 and value in lowered), "")


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
    mentioned = next((w for w in re.findall(r"[A-Za-z_]\w+", text) if w.lower() in API_NAMES), "")
    if mentioned and len(text.split()) > 1:
        # "System processes using Beep API for diagnostics" in a normal baseline.
        return f"{mentioned} is an API call; no log records it, so this entry cannot be checked"
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
        # An adverb before the verb is consumed: "directly enables" became
        # "directly could enable" on the end-to-end replay.
        pattern = re.compile(
            rf"(?:\b(?P<adv>\w+ly|also|thereby|further)\s+)?\b({verbs})\b(?P<gap>[^.;:]{{0,60}}?)\b(?P<noun>{noun})\b", re.I
        )

        def repl(match: "re.Match[str]") -> str:
            before = text[max(0, match.start() - 40) : match.start()]
            if _HEDGES.search(before.split(".")[-1]):
                return match.group(0)
            verb = match.group(2)
            base = _ASSERTIVE_VERBS[verb.lower()]
            adverb = match.group("adv")
            findings.append(
                ClaimFinding(
                    field, match.group(0), "softened", f"{label} is a capability here: no {label} technique was observed"
                )
            )
            # "..., enabling X" stays a participle: "..., potentially enabling X".
            # "to achieve X" stays an infinitive: "to potentially achieve X".
            infinitive = re.search(r"\bto\s*$", before, re.I) is not None
            modal = "potentially" if verb.lower().endswith("ing") or infinitive else "could"
            # The adverb is dropped: "directly enables" overstated a capability,
            # and "could directly enable" is still read as unhedged by a pattern
            # that looks for the modal right before the verb.
            softened = f"{modal} {base if modal == 'could' or infinitive else verb.lower()}"
            first = adverb or verb
            softened = softened[0].upper() + softened[1:] if first[0].isupper() else softened
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
    fields: Dict[str, str],
    techniques: Set[str],
    on_disk_executable: bool,
    source_text: str = "",
    unobservable: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], List[ClaimFinding]]:
    """Softened copies of the prose fields, and every finding, in field order.

    ``source_text`` (the feed item and primary source) lets a target sector or
    motive the source never states be marked unconfirmed; ``unobservable``
    values (artifacts the source does not tie to this intrusion) are marked
    where the prose names them.
    """
    out: Dict[str, str] = {}
    findings: List[ClaimFinding] = []
    for name, text in fields.items():
        softened, found = soften_capability_claims(text or "", name, techniques)
        corrected, fixed = correct_fileless_on_disk(softened, name, on_disk_executable)
        scoped, unconfirmed = mark_unconfirmed_scope(corrected, name, source_text) if source_text else (corrected, [])
        marked, flagged = mark_unobservable_values(scoped, name, unobservable or {})
        out[name] = marked
        findings += found + fixed + unconfirmed + flagged
    return out, findings


# --- Target sector and motive the source does not state ---------------------------------------

#: "in China's defense-tech sector", "core assets in the energy industry".
_SECTOR_RE = re.compile(
    r"\s*\b(?:in|within|across|of|targeting)\s+(?P<phrase>(?:[\w'\u2019-]+\s+){0,4}?(?P<kind>sector|industry|ecosystem|vertical)s?)\b",
    re.IGNORECASE,
)
#: "targeting Chinese defense-tech researchers": a sector word on a target group.
_SECTOR_GROUP_RE = re.compile(
    r"\b(?P<prep>targeting|against|aimed at|at|on)\s+(?P<pre>(?:[A-Z][\w'\u2019-]*\s+)?)"
    r"(?P<sector>(?:defen[cs]e(?:[- ]tech(?:nology)?|[- ]industrial|[- ]related)?|military|government|energy|power[- ]grid|"
    r"healthcare|financial|telecom(?:munications)?|aerospace|critical[- ]infrastructure|manufacturing))\s+"
    r"(?P<noun>researchers|organi[sz]ations|entities|companies|contractors|institutions|agencies|targets|systems|"
    r"networks|personnel|firms|academics|victims|users)\b",
    re.IGNORECASE,
)
_MOTIVE_RE = re.compile(
    r"\b(?:for|to conduct|to enable|aimed at|in order to (?:conduct|enable))\s+(?P<motive>(?:state-sponsored\s+)?"
    r"(?:espionage|intellectual property theft|financial gain|sabotage|cyber ?espionage))\b",
    re.IGNORECASE,
)


def _stated(phrase: str, source_text: str) -> bool:
    """Whether the source states the phrase (defence/defense spelled either way)."""
    norm = lambda t: re.sub(r"\s+", " ", t.lower().replace("defence", "defense").replace("\u2019", "'"))  # noqa: E731
    return norm(phrase) in norm(source_text)


def mark_unconfirmed_scope(text: str, field: str, source_text: str) -> Tuple[str, List[ClaimFinding]]:
    """Replace a target sector the source never states; mark an asserted motive it never states.

    H-0618's source assesses a likely academic recipient and says the sector
    and final motivation are unconfirmed; the drafts kept placing the victim
    "in China's defense-tech sector".
    """
    findings: List[ClaimFinding] = []

    def sector(match: "re.Match[str]") -> str:
        phrase = match.group("phrase")
        core = re.sub(r"^(?:the|a|an)\s+", "", phrase, flags=re.I)
        if _stated(core, source_text):
            return match.group(0)
        findings.append(
            ClaimFinding(field, match.group(0).strip(), "corrected", "the source does not state this target sector")
        )
        return f" (target {match.group('kind').lower()} unconfirmed by the source)"

    def motive(match: "re.Match[str]") -> str:
        before = text[max(0, match.start() - 40) : match.start()]
        if _HEDGES.search(before.split(".")[-1]) or _stated(match.group("motive"), source_text):
            return match.group(0)
        findings.append(ClaimFinding(field, match.group(0), "softened", "the source does not state this motive"))
        return f"{match.group(0)} (motive unconfirmed by the source)"

    def sector_group(match: "re.Match[str]") -> str:
        if _stated(f"{match.group('sector')} {match.group('noun')}", source_text):
            return match.group(0)
        findings.append(ClaimFinding(field, match.group(0), "corrected", "the source does not state this target sector"))
        return f"{match.group('prep')} {match.group('pre')}{match.group('noun')} (target sector unconfirmed by the source)"

    text = _SECTOR_RE.sub(sector, text)
    # The confirmation replay wrote "targeting Chinese defense-tech researchers".
    text = _SECTOR_GROUP_RE.sub(sector_group, text)
    text = _MOTIVE_RE.sub(motive, text)
    return text, findings


def mark_unobservable_values(text: str, field: str, unobservable: Dict[str, str]) -> Tuple[str, List[ClaimFinding]]:
    """Mark, in place, values the pipeline knows are not this intrusion's (e.g. an artifact from the report's aside)."""
    findings: List[ClaimFinding] = []
    for value, reason in unobservable.items():
        if len(value) < 6 or value.lower() not in text.lower():
            continue
        pattern = re.compile(re.escape(value) + r"(?!\s*\[)", re.IGNORECASE)
        if pattern.search(text):
            text = pattern.sub(lambda m: f"{m.group(0)} [{reason}]", text, count=1)
            findings.append(ClaimFinding(field, value, "flagged", reason))
    return text, findings


def render_findings(findings: List[ClaimFinding], limit: Optional[int] = None) -> str:
    """Markdown bullets for a draft's Claim Audit section."""
    lines = [f'- **{f.action}** ({f.field}): "{f.text}" — {f.reason}' for f in findings[:limit]]
    return "\n".join(lines)
