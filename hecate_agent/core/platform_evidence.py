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
        r"\bwscript\b", r"\bcscript\b", r"\bschtasks\b", r"\bregistry run keys?\b",
        r"\bdocx?\b",
    ),
    "Linux": (
        r"\bELF\b", r"/proc/", r"/dev/shm\b", r"\bsystemd\b", r"\bcrontab\b", r"/etc/(passwd|shadow|ld\.so)",
        r"\bld_preload\b", r"\bmemfd_create\b", r"\.so\b", r"\b(apt|yum|dnf)-get\b|\b(apt|yum|dnf) install\b",
    ),
    "macOS": (
        r"\blaunch(agent|daemon)s?\b", r"\bosascript\b", r"\bapplescript\b", r"\bmach-?o\b", r"\bgatekeeper\b",
        r"~?/library/", r"\.app/contents\b", r"\bxprotect\b", r"\btcc\.db\b",
    ),
    "Containers": (
        r"\bkubernetes\b", r"\bk8s\b", r"\bdocker\b", r"\bpod(s)?\b", r"\be-?k-?s\b",
        r"\bg-?k-?e\b", r"\ba-?k-?s\b", r"\bcontainerd\b", r"\bnsenter\b", r"\bcrictl\b",
        r"\bkubectl\b", r"\bdaemonset\b", r"\bconfigmap\b", r"\bhelm\b",
    ),
    "IaaS": (
        r"\baws\b", r"\bcloudtrail\b", r"\biam role\b", r"\bec2\b", r"\bs3\b",
        r"\bassumerole\b", r"\bazure\b", r"\bgcp\b", r"\bgoogle cloud\b", r"\biaas\b",
        r"\bvpc\b", r"\bsecurity group\b",
    ),
    "Identity Provider": (
        r"\bentra id\b", r"\bazure ad\b", r"\bokta\b", r"\boauth\b", r"\bdevice code\b",
        r"\bconsent grant\b", r"\bsso\b", r"\bsaml\b", r"\bidentity provider\b",
        r"\btoken theft\b", r"\bgraph api\b", r"\brefresh token\b",
    ),
    "SaaS": (
        r"\bsaas\b", r"\bm365\b", r"\boffice 365\b", r"\bgoogle workspace\b",
        r"\bsharepoint\b", r"\bonedrive\b", r"\bslack\b",
    ),
    "ESXi": (
        r"\besxi\b", r"\bvcenter\b", r"\bvmware\b", r"\bvmx\b", r"\bvmdk\b",
    ),
    "Network Devices": (
        r"\bfortios\b", r"\bcisco\b", r"\bpan-os\b", r"\bjuniper\b",
    ),
    "Android": (
        r"\.apk\b", r"\.dex\b", r"\.aab\b", r"\bandroid\b", r"\bdalvik\b", r"\bart runtime\b",
        r"\bplay store\b", r"\bgoogle play\b", r"\badb\b", r"\byahfa\b", r"\bdobby\b",
    ),
    "iOS": (
        r"\.ipa\b", r"\bios\b", r"\biphone\b", r"\bipad\b", r"\bjailbreak\b", r"\bcydia\b",
        r"\bapp store\b", r"\btestflight\b",
    ),
}  # fmt: skip
#: A platform named outright: counted like a marker, once.
_NAMES: Dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "mac os": "macOS",
    "android": "Android",
    "ios": "iOS",
    "iphone": "iOS",
    "ipad": "iOS",
    "container": "Containers",
    "containers": "Containers",
    "kubernetes": "Containers",
    "k8s": "Containers",
    "docker": "Containers",
    "iaas": "IaaS",
    "aws": "IaaS",
    "cloud": "IaaS",
    "identity provider": "Identity Provider",
    "entra id": "Identity Provider",
    "azure ad": "Identity Provider",
    "okta": "Identity Provider",
    "saas": "SaaS",
    "office suite": "Office Suite",
    "office 365": "Office Suite",
    "m365": "Office Suite",
    "esxi": "ESXi",
    "network devices": "Network Devices",
    "network device": "Network Devices",
}
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
