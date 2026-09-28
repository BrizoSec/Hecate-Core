"""Behaviour-to-technique mapping with the passage that supports it.

Reports describe what malware does ("sandbox detection, CPU checks, and
sleep-timer evasion", "XOR-decodes it with key 0x99"), not ATT&CK's names for
it. Matching technique names alone found 2 of the 11 techniques H-0618's
report shows in use, and one of those two (T1113 Screen Capture) came from a
list of what VShell *can* do, not what this intrusion did.

This module maps described behaviour to technique IDs through a small curated
catalog, and judges each supporting sentence: a sentence describing what the
sample or actor did is ``observed``; one describing what a tool offers or can
do is ``capability``. A technique is proposed only on observed evidence, and
every mapping keeps the sentence it rests on so a reviewer can check it. A
bare label is not evidence: "fileless" alone does not establish T1620; an
in-memory execution sequence does.
"""

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from hecate_agent.core.provenance import refang


@dataclass
class TechniqueEvidence:
    technique_id: str
    status: str  # "observed" | "capability" | "negated" | "context"
    passage: str
    source: str  # where the passage came from, e.g. "cti", "primary source"
    behaviour: str  # the catalog entry that matched, or "technique name"

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


#: technique ID -> (behaviour label, pattern). Patterns run on refanged,
#: lowercased sentences. Keep each specific enough that a match describes the
#: behaviour, not merely a topic word; a pattern here proposes a technique.
_CATALOG: Tuple[Tuple[str, str, str], ...] = (
    ("T1204.002", "lure the recipient runs",
     r"\b(disguised|masquerad\w+|posing) as (a |an )?(\w+[- ])?(resume|cv|invoice|document|pdf|report|installer)\b"
     r"|\b(victim|user|recipient)s? (runs?|opens?|execut\w+|launch\w*|double[- ]click\w*)\b"),
    ("T1036", "disguised as something benign",
     r"\bdisguised as\b|\bmasquerad\w+ as\b|\bposing as\b|\bfake (resume|invoice|document|installer|update)\b"),
    ("T1059.003", "Windows command shell", r"\bcmd\.exe\b|\bcommand prompt\b|\bwindows command shell\b"),
    ("T1059.001", "PowerShell", r"\bpowershell(\.exe)?\b"),
    ("T1059.005", "Visual Basic", r"\bvbscript\b|\b[wc]script\.exe\b|\bvisual basic\b"),
    ("T1059.004", "Unix shell", r"\b(ba)?sh -c\b|/bin/(ba)?sh\b"),
    ("T1497.001", "sandbox or system checks",
     r"\bsandbox (detection|checks?|evasion)\b|\banti[- ]?(sandbox|vm|analysis)\b"
     r"|\b(cpu|processor|core)s? (count|checks?)\b|\bcpu checks?\b|\blogical processors\b"
     r"|\bvirtual machine (detection|checks?)\b|\bchecks? (for|whether) (a |an )?(sandbox|virtual|vm|debugger)"),
    ("T1497.003", "time-based evasion",
     r"\bsleep[- ]?(timer|checks?|evasion|verification)\b|\btiming (checks?|verification)\b"
     r"|\btime[- ]based (checks?|evasion)\b|\bdelay(ed)? execution\b|\bbeepsleep\b"),
    ("T1105", "downloads a further stage",
     r"\bdownload(s|ed|ing)? (\d[\d.,]*\s?(kb|mb|gb|bytes)|the (payload|stager|next stage|second stage|decoy)"
     r"|a (payload|stager|second[- ]stage|decoy|real)|additional (payloads?|tools?|modules?))"
     r"|\b(fetch|retriev)(es|ed)? (the|a) (payload|stager|next stage|second[- ]stage)\b"),
    ("T1140", "decodes or decrypts a payload",
     r"\bxor[- ]?(decod\w*|decrypt\w*)\b|\bxor(s|ed)? (it|the|with)\b"
     r"|\bdecod(es|ed|ing) (it|the (payload|config\w*|data|shellcode))\b"
     r"|\bdecrypt(s|ed|ing)? (it|the (payload|config\w*|data|shellcode|strings))\b"
     r"|\bbase64[- ]?decod\w*\b|\baes[- ](cbc |gcm )?decrypt\w*\b"),
    ("T1620", "code executed from memory",
     r"\breflective(ly)? (load\w*|inject\w*)\b"
     r"|\ballocat\w+ memory\b.{0,120}\b(marks? (them|it) executable|creates? a thread)\b"
     r"|\b(virtualalloc|allocadsmem|allocat\w+ (executable|rwx) memory)\b.{0,160}\b(virtualprotect|createthread)\b"
     r"|\bexecut\w+ (it |the (payload|shellcode|stager) )?(directly )?(in|from) memory\b"
     r"|\bin[- ]memory (execution|loader|loading)\b|\bshellcode (loader|execution|runner)\b"),
    ("T1071.001", "HTTP for staging or C2",
     r"\bhttps? (staging|c2|c&c|beacon\w*|requests?|communications?|traffic)\b|\bover https?\b"),
    ("T1095", "non-application-layer C2",
     r"\braw tcp\b|\bcustom (binary|tcp|udp) protocol\b|\bnon-application[- ]layer\b"
     r"|\btcp (socket|stream|connection)s? (to|for|with) (the )?(c2|server|operator)\b"),
    ("T1573", "encrypted C2 channel",
     r"\baes[- ]gcm\b|\bencrypted (https? )?(c2|c&c|channel|traffic|communications?|protocol)\b"
     r"|\b(rc4|aes|chacha\w*)[- ]encrypted (c2|traffic|channel|communications?)\b|\b(certificate|tls) pinning\b"),
    ("T1027", "obfuscated or encrypted content",
     r"\bobfuscat\w+\b|\bencrypted (config\w*|strings|payload)\b|\bencoded (config\w*|payload|strings)\b"),
    ("T1480", "execution guardrail", r"\bkill[- ]?switch\b|\bexecution guardrails?\b|\benvironment(al)? keying\b"),
    ("T1053.005", "scheduled task", r"\bscheduled task\b|\bschtasks(\.exe)?\b"),
    ("T1547.001", "Run key or Startup folder", r"\brun key\b|currentversion\\run\b|\bstartup folder\b"),
    ("T1566.001", "phishing attachment", r"\b(spear)?phishing (email|attachment)s?\b|\bmalicious attachments?\b"),
    ("T1566.002", "phishing link", r"\bphishing links?\b|\bmalicious links?\b"),
    ("T1218.011", "rundll32", r"\brundll32(\.exe)?\b"),
    ("T1218.007", "msiexec", r"\bmsiexec(\.exe)?\b"),
    ("T1218.005", "mshta", r"\bmshta(\.exe)?\b"),
    ("T1055", "process injection", r"\bprocess injection\b|\binject(s|ed|ing)? (it |the \w+ )?into\b"),
    ("T1055.012", "process hollowing", r"\bprocess hollowing\b|\bhollow(s|ed|ing) (out )?(a |the )?\w*\s?process\b"),
    ("T1574.001", "DLL side-loading or hijacking", r"\bdll (side[- ]?load\w*|hijack\w*|search order)\b|\bside[- ]?load\w*\b"),
    ("T1113", "screen capture", r"\bscreen ?(capture|shot)s?\b"),
    ("T1070.004", "self-deletion", r"\bdelet(es|ed|ing) (itself|the (loader|dropper|file|binary))\b|\bself[- ]delet\w+\b"),
    ("T1112", "registry modification", r"\bmodif(y|ies|ied) (the )?registry\b"),
    ("T1543.003", "Windows service created", r"\b(creates?|install\w*) (a )?(new )?(windows )?service\b|\bsc(\.exe)? create\b"),
    ("T1003.001", "LSASS access", r"\blsass\b"),
)  # fmt: skip

_COMPILED = tuple((tid, label, re.compile(pattern)) for tid, label, pattern in _CATALOG)

#: A sentence about what a tool offers or could do, rather than what happened.
_CAPABILITY_RE = re.compile(
    r"\b(public|published|prior|vendor) (\w+ ){0,2}(analysis|reporting|research|documentation)\b"
    r"|\bgives? (an |the )?operators?\b|\b(meant|intended) to\b|\bobjective\b|\bcapabilit(y|ies)\b|\bcan (be used to|also|perform|take|capture|execute|run|steal)\b"
    r"|\b(is|are) (able|capable) (to|of)\b|\bsupports?\b|\boffers?\b|\bprovid(es|ing) \w+( \w+)? with\b"
    r"|\bfeatures? (include|such as)\b|\ballows? (operators|attackers|the operator)\b|\bdesigned to\b|\bcould be used\b"
    # A feature list: "a fileless VShell RAT ... enabling command execution, file access, screen capture".
    r"|\b(enabl(es?|ing)|allow(s|ing))\b[^.;]{0,80},"
)
#: A sentence that reports what the sample, actor or intrusion actually did.
_OBSERVED_RE = re.compile(
    r"\bobserved\b|\bin this (sample|campaign|intrusion|case|run)\b|\bduring (execution|the (run|analysis|sandbox))\b"
    r"|\bwe (saw|observed|found)\b|\bwas (seen|observed)\b|\bthe (sample|pcap|sandbox run)\b"
)

#: A sentence about another actor or campaign, typical of attribution
#: comparisons ("UAT-8302 ... sideloading ... no lure match"). It describes
#: someone else's tradecraft, so it neither supports nor rules out a mapping.
_CONTEXT_RE = re.compile(
    r"\b(unc|uat|apt|ta|fin|dev)-?\d{2,5}\b|\bearth [a-z]+\b|\bno (ioc|lure|infrastructure|windows)\b[^.]{0,30}\bmatch\b"
    r"|\bdifferent malware\b|\bpublished (chains|access|reporting)\b"
)

#: Label and metadata lines in a CTI item: a title or a tag list names a topic
#: without describing what happened, so it is not evidence.
_LABEL_LINE = re.compile(
    r"^\s*(>\s*)?(otx pulse|misp event|rss|tags|adversary/attribution|indicators|key indicators|references|link|source"
    r"|org|tlp|threat level|mitre att&ck techniques|filehash-\w+|ipv4|url|hostname|domain)\b.{0,40}:",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def sentences(text: str) -> List[str]:
    """Sentences of ``text``, rebuilt across the line breaks page extraction inserts.

    Scraped pages put every inline element on its own line ("launching \\n
    cmd.exe \\n , opening a DOCX"), so lines are joined before splitting on
    sentence punctuation. Label lines (titles, tag lists, indicator lists) are
    dropped first.
    """
    lines = [line for line in refang(text or "").splitlines() if not _LABEL_LINE.match(line)]
    joined = re.sub(r"\s+", " ", " ".join(lines)).replace(" ,", ",").replace(" .", ".")
    return [s.strip() for s in _SENTENCE_SPLIT.split(joined) if len(s.strip()) > 3]


#: A statement that something did NOT happen ("Not observed: an operator
#: issuing a command"). It rules a behaviour out; it is not evidence of it.
_NEGATED_RE = re.compile(
    r"\b(not|never|n't) (been )?(observed|seen)\b|\bno (evidence|sign|indication)s? (of|that)\b"
    r"|\b(did|does|was|were) not (use|show|perform|occur)\w*\b"
)
#: Segments longer than this are judged, and quoted, by a window around the
#: match: scraped headings carry no punctuation, so unrelated sections can
#: run together into one "sentence".
_WINDOW_OVER = 450
_WINDOW = 200


def sentence_status(sentence: str) -> str:
    """Whether a passage reports observed use, a tool capability, a negation, or another actor's tradecraft."""
    lowered = sentence.lower()
    if _CONTEXT_RE.search(lowered):
        return "context"
    if _NEGATED_RE.search(lowered):
        return "negated"
    if _CAPABILITY_RE.search(lowered) and not _OBSERVED_RE.search(lowered):
        return "capability"
    return "observed"


def _clip(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _passage(sentence: str, match: "re.Match[str]") -> str:
    """The sentence, or for a run-on segment the window around the match."""
    if len(sentence) <= _WINDOW_OVER:
        return sentence
    start = max(0, match.start() - _WINDOW)
    end = min(len(sentence), match.end() + _WINDOW)
    return sentence[start:end]


def map_behaviours(texts: Iterable[Tuple[str, str]]) -> List[TechniqueEvidence]:
    """Techniques the described behaviour supports, one entry each, with a passage.

    ``texts`` is ``(source label, text)`` pairs, most authoritative first. An
    observed passage outranks a capability one wherever it appears; within a
    status the first source wins.
    """
    found: Dict[str, TechniqueEvidence] = {}
    for source, text in texts:
        for sentence in sentences(text):
            lowered = sentence.lower()
            for tid, label, pattern in _COMPILED:
                match = pattern.search(lowered)
                if not match:
                    continue
                passage = _passage(sentence, match)
                status = sentence_status(passage)
                if status in ("context", "negated"):
                    continue
                current = found.get(tid)
                if current is None or (current.status == "capability" and status == "observed"):
                    found[tid] = TechniqueEvidence(tid, status, _clip(passage), source, label)
    return list(found.values())


def _name_pattern(names: Iterable[str]) -> Optional["re.Pattern[str]"]:
    phrases = [re.escape(n.lower()) for n in names if n and len(n) >= 4]
    return re.compile(r"\b(" + "|".join(phrases) + r")\b") if phrases else None


def technique_support(technique_id: str, names: Iterable[str], text: str) -> Optional[TechniqueEvidence]:
    """The best passage in ``text`` for a technique, by its catalog behaviour or its ATT&CK name.

    Returns None when nothing in the text mentions it. The result's status
    says whether any mention is an observed use; only ``capability`` passages
    means the text describes the technique solely as something a tool can do.
    """
    catalog = [(label, pattern) for tid, label, pattern in _COMPILED if tid == technique_id]
    by_name = _name_pattern(names)
    best: Optional[TechniqueEvidence] = None
    for sentence in sentences(text):
        lowered = sentence.lower()
        match, label = None, None
        for lbl, pattern in catalog:
            match = pattern.search(lowered)
            if match:
                label = lbl
                break
        if match is None and by_name is not None:
            match = by_name.search(lowered)
            label = "technique name" if match else None
        if match is None or label is None:
            continue
        passage = _passage(sentence, match)
        status = sentence_status(passage)
        if status == "context":
            continue
        if status == "negated":
            status = "capability"  # mentioned, but not as something that happened
        if best is None or (best.status == "capability" and status == "observed"):
            best = TechniqueEvidence(technique_id, status, _clip(passage), "", label)
        if best.status == "observed":
            break
    return best
