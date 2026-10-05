"""Which platforms the specimen's own evidence shows, marker by marker.

H-0618 was scoped to Linux and Windows because the model's ABLE Location said
"Linux and Windows workstations", and a hypothesis naming platforms outranked
everything else. The report showed a Windows x86 chain: an .exe, cmd.exe,
Word, kernel32, activeds.dll, a w32 architecture tag. Its only Linux mentions
were other actors' SNOWLIGHT chains in an attribution table.

A platform counts as evidenced by distinct markers only it has, found in
sentences that report what happened (the status test from
:mod:`technique_evidence`): a capability list, a negation or another actor's
tradecraft is not this specimen. Scoping then keeps what the evidence shows
and drops what only the model named.
"""

import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Tuple

from hecate_agent.core.technique_evidence import actor_material_report, passage_status, sentences

#: Markers unique to one platform. Ambiguous ones stay out: bash, cron, /tmp/
#: and Python run on Linux and macOS alike, and architecture tags such as
#: ``l64`` appear in capability lists far more often than in a specimen.
_MARKERS: Dict[str, Tuple[str, ...]] = {
    "Windows": (
        r"\w+\.exe", r"\w+\.dll", r"\bcmd\.exe", r"\bpowershell\b", r"\bkernel32\b", r"\bntdll\b", r"\badvapi32\b",
        r"\bactiveds\b", r"\brundll32\b", r"\bregsvr32\b", r"\bmshta\b", r"\bwmic\b", r"\blsass\b", r"\bHK(LM|CU)\\",
        r"%(temp|appdata|programdata|userprofile)%", r"\b[a-z]:\\\\?(windows|users|programdata)\b", r"\bwinword\b",
        r"\bwindows (defender|registry|service|event log)\b", r"\bwin(32|64) api\b", r"\bPE32\b", r"\.lnk\b", r"\.msi\b",
    ),
    "Linux": (
        r"\bELF\b", r"/proc/", r"/dev/shm\b", r"\bsystemd\b", r"\bcrontab\b", r"/etc/(passwd|shadow|ld\.so)",
        r"\bld_preload\b", r"\bmemfd_create\b", r"\.so\b", r"\b(apt|yum|dnf)-get\b|\b(apt|yum|dnf) install\b",
    ),
    "macOS": (
        r"\blaunch(agent|daemon)s?\b", r"\bosascript\b", r"\bapplescript\b", r"\bmach-?o\b", r"\bgatekeeper\b",
        r"~?/library/", r"\.app/contents\b", r"\bxprotect\b", r"\btcc\.db\b",
    ),
}  # fmt: skip
#: A platform named outright: counted like a marker, once.
_NAMES: Dict[str, str] = {"windows": "Windows", "linux": "Linux", "macos": "macOS", "mac os": "macOS"}
#: Distinct markers a platform needs before its evidence outranks the hypothesis.
MIN_MARKERS = 2


@dataclass
class PlatformEvidence:
    """Distinct markers per platform, each with the passage that shows it."""

    markers: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)

    @property
    def supported(self) -> List[str]:
        """Platforms the specimen shows by at least two distinct markers.

        One marker is not enough to overrule the hypothesis: Kapibala's feed
        text said only "PowerShell-based collection" about a campaign on
        Linux web servers. Weak evidence is left to the existing intel scoping.
        """
        return [p for p, found in self.markers.items() if len(found) >= MIN_MARKERS]

    def to_dict(self) -> Dict[str, object]:
        return {**asdict(self), "supported": self.supported}


def platform_evidence(texts: List[str]) -> PlatformEvidence:
    """Platform markers in the sentences of ``texts`` that report observed activity."""
    found: Dict[str, Dict[str, str]] = {}
    patterns = [(p, m) for p, markers in _MARKERS.items() for m in markers]
    patterns += [(platform, rf"\b{re.escape(name)}\b") for name, platform in _NAMES.items()]
    actor_material = any(actor_material_report(text) for text in texts)
    for sentence in (s for text in texts for s in sentences(text)):
        for platform, pattern in patterns:
            for match in re.finditer(pattern, sentence, re.IGNORECASE):
                if passage_status(sentence, match.start(), match.end(), actor_material)[0] != "observed":
                    continue
                marker = key = match.group(0).lower()
                slot = found.setdefault(platform, {})
                if key not in slot:
                    slot[key] = f"{marker}\t{sentence[max(0, match.start() - 80) : match.end() + 80].strip()}"
    return PlatformEvidence(markers={platform: _distinct(slot) for platform, slot in found.items()})


def _distinct(slot: Dict[str, str]) -> List[Dict[str, str]]:
    """One entry per artifact: "kernel32" is dropped when "kernel32.dll" is also found."""
    keys = list(slot)
    kept = [k for k in keys if not any(k != other and k in other for other in keys)]
    return [{"marker": k, "passage": slot[k].split("\t", 1)[1]} for k in kept]
