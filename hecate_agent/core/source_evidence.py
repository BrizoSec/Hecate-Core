"""Evidence from the primary source a CTI item cites.

Feeds deliver a summary; the report it links to carries the process tree, file
paths, ports, what each hash is, and which indicators are current. H-0618 was
drafted from a 2,194-character OTX blurb while the report held 32,920
characters, including the hash roles and the note that the listed hostnames
were historical. This module fetches the report, extracts artifacts from all
of it, and keeps only what the text supports:

- every value must appear verbatim in the page (after refanging);
- a role or status is kept only with a supporting passage found in the page;
  without one it is recorded as ``unknown``;
- confidence is the report's own label ("HIGH confidence"), never the model's.

Extracted text is evidence from one source, not independent confirmation; the
records carry that provenance so later stages can say where a claim came from.
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from hecate_agent.core.provenance import (
    HASH_ROLES,
    NETWORK_ROLES,
    STATUSES,
    IndicatorRecord,
    refang,
    split_host_port,
)

logger = logging.getLogger(__name__)

#: Characters per extraction call. The whole report is read, in chunks: the
#: H-0618 report kept its hash roles and historical-domain note past 25,000.
CHUNK_CHARS = 11000
CHUNK_OVERLAP = 600
#: Hard ceiling on page text, so a runaway page cannot turn into dozens of calls.
MAX_PAGE_CHARS = 120000
#: Words that must match contiguously for a quoted passage to count as found.
EVIDENCE_WINDOW = 8

_SKIP_HOSTS = ("localhost", "127.0.0.1")
_LINK_RE = re.compile(r"https?://[^\s<>\"')\]]+")
_CONFIDENCE_RE = re.compile(r"(?i)\b(high|medium|low)\s+confidence\b")

INDICATOR_KINDS = {
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "ipv4": "ipv4",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
}
BEHAVIOUR_KINDS = (
    "file_path",
    "registry_key",
    "command_line",
    "process",
    "api",
    "mutex",
    "named_pipe",
    "scheduled_task",
    "service",
)

SYSTEM_PROMPT = f"""You extract artifacts from one part of a threat intelligence report.
Copy every value EXACTLY as the text writes it. Do not invent, complete or reformat.

For each artifact return:
- "value": the exact string. For a network endpoint with a port, use "ip:port" as written.
- "kind": one of {sorted(INDICATOR_KINDS) + list(BEHAVIOUR_KINDS)}
- "role": for hashes one of {list(HASH_ROLES)}; for IPs, domains, hostnames and URLs one of
  {list(NETWORK_ROLES)}; for other kinds a short phrase (e.g. "decoy document path").
  Hash roles: executable = a program run from disk; library = a DLL loaded from disk;
  archive = a ZIP/RAR container; document = a decoy or lure document;
  memory_only = shellcode or a payload that only exists in memory;
  network_content = an encrypted or encoded download or stream.
  Use "historical" when the text says an indicator is old, unrelated, or not a campaign IOC.
- "status": one of {list(STATUSES)} ("historical" when the text says so, else "active" if the
  text ties it to this campaign, else "unknown")
- "evidence": one sentence copied word for word from the text that states the role or status.

Return strict JSON: {{"artifacts": [ ... ]}}. Return {{"artifacts": []}} if there are none.
"""


@dataclass
class SourceArtifact:
    value: str
    kind: str
    role: str = "unknown"
    status: str = "unknown"
    confidence: str = "unknown"
    evidence: str = ""


@dataclass
class SourceEvidence:
    url: str
    chars: int = 0
    chunks: int = 0
    artifacts: List[SourceArtifact] = field(default_factory=list)
    indicators: List[IndicatorRecord] = field(default_factory=list)
    dropped: List[str] = field(default_factory=list)
    error: str = ""
    text: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.artifacts)

    @property
    def behaviours(self) -> List[SourceArtifact]:
        return [a for a in self.artifacts if a.kind not in INDICATOR_KINDS]

    def summary_block(self, max_chars: int = 6000) -> str:
        """The verified artifacts as compact text for a prompt, with their provenance."""
        if not self.artifacts:
            return ""
        lines = [f"Primary source ({self.url}), artifacts verified verbatim in its text:"]
        for a in self.artifacts:
            evidence = f' — "{a.evidence}"' if a.evidence else ""
            lines.append(f"- [{a.kind}] {a.value} — role: {a.role}; status: {a.status}; confidence: {a.confidence}{evidence}")
        text = "\n".join(lines)
        return text if len(text) <= max_chars else text[: max_chars - 20].rsplit("\n", 1)[0] + "\n- [truncated]"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "chars": self.chars,
            "chunks": self.chunks,
            "artifacts": [asdict(a) for a in self.artifacts],
            "indicators": [r.to_dict() for r in self.indicators],
            "dropped": self.dropped,
            "error": self.error,
        }


# --- Fetching --------------------------------------------------------------------------------


def report_urls(threat_intel: str, source_url: str = "", limit: int = 1) -> List[str]:
    """The report(s) a CTI item points to: its own link first, then links in its text."""
    urls: List[str] = []
    for url in [source_url, *(m.group(0).rstrip(".,;:") for m in _LINK_RE.finditer(threat_intel or ""))]:
        if url and url.startswith("http") and not any(h in url for h in _SKIP_HOSTS) and url not in urls:
            urls.append(url)
    return urls[:limit]


def fetch_page_text(url: str, timeout: float = 20.0) -> str:
    """Visible text of a report page, or raise on any failure."""
    from bs4 import BeautifulSoup

    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return str(soup.get_text(separator="\n", strip=True))[:MAX_PAGE_CHARS]


def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Split on line boundaries into overlapping chunks, so no artifact is cut in two."""
    if len(text) <= size:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            newline = text.rfind("\n", start + size // 2, end)
            end = newline if newline > start else end
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


# --- Verification ----------------------------------------------------------------------------


def normalise(text: str) -> str:
    """Lowercase, refang, one backslash, collapsed whitespace: the form values are compared in."""
    text = refang(text).lower().replace("\\\\", "\\")
    return re.sub(r"\s+", " ", text).strip()


def _words(text: str) -> List[str]:
    return re.findall(r"[\w.:/\\%-]+", normalise(text))


def evidence_found(evidence: str, page_words: str) -> bool:
    """True when the passage, or a run of EVIDENCE_WINDOW of its words, appears in the page."""
    words = _words(evidence)
    if not words:
        return False
    if len(words) <= EVIDENCE_WINDOW:
        return " ".join(words) in page_words
    return any(" ".join(words[i : i + EVIDENCE_WINDOW]) in page_words for i in range(len(words) - EVIDENCE_WINDOW + 1))


_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

#: Report wording that fixes what a hash is, checked in this order: a payload
#: that only ever ran in memory must not be mistaken for a file on disk
#: (H-0618's "Decoded SHA-256", labelled executable by the model).
_HASH_ROLE_WORDS = (
    ("memory_only", r"\b(decoded|decrypted|shellcode|in[- ]memory|fileless|reflective(ly)?)\b"),
    ("network_content", r"\b(encoded|encrypted|http response|stream|download(ed)? blob)\b"),
    ("archive", r"\b(archive|zip|rar|7z)\b"),
    ("document", r"\b(docx?|decoy|document|pdf|lure file)\b"),
    ("library", r"\b(dll|library)\b"),
    ("executable", r"\b(loader|executable|dropper|installer|\.exe)\b"),
)


def _valid_value(kind: str, value: str) -> bool:
    """The value has the shape its kind requires: an AES key is not an MD5."""
    text = value.strip().lower()
    if kind in _HASH_LENGTHS:
        return len(text) == _HASH_LENGTHS[kind] and bool(_HEX.match(text))
    if kind == "ipv4":
        import ipaddress

        host, _ = split_host_port(text)
        try:
            return ipaddress.ip_address(host).version == 4
        except ValueError:
            return False
    if kind in ("domain", "hostname"):
        return bool(_DOMAIN.match(text.rstrip(".")))
    if kind == "url":
        return "/" in text and ("." in text or ":" in text)
    return True


def _hash_role_from_evidence(evidence: str, role: str) -> str:
    for derived, pattern in _HASH_ROLE_WORDS:
        if re.search(pattern, evidence, re.IGNORECASE):
            return derived
    return role


def _checked(raw: Dict[str, Any], page: str, page_words: str) -> Tuple[Optional[SourceArtifact], str]:
    value = refang(str(raw.get("value", ""))).strip()
    kind = str(raw.get("kind", "")).strip().lower()
    if not value or kind not in (*INDICATOR_KINDS, *BEHAVIOUR_KINDS):
        return None, f"{value or '(empty)'}: unknown kind {kind!r}"
    if not _valid_value(kind, value):
        return None, f"{value}: not a well-formed {kind}"
    if normalise(value) not in page:
        return None, f"{value}: not found verbatim in the source"
    evidence = str(raw.get("evidence", "")).strip()
    if evidence and not evidence_found(evidence, page_words):
        evidence = ""
    allowed_roles = HASH_ROLES if kind in ("sha256", "sha1", "md5") else NETWORK_ROLES if kind in INDICATOR_KINDS else None
    role = str(raw.get("role", "unknown")).strip().lower() or "unknown"
    status = str(raw.get("status", "unknown")).strip().lower()
    if allowed_roles is not None and role not in allowed_roles:
        role = "unknown"
    if status not in STATUSES:
        status = "unknown"
    if not evidence:
        # A classification nothing in the text supports is the model's, not the source's.
        role = "unknown" if allowed_roles is not None else role
        status = "unknown"
    if kind in _HASH_LENGTHS and evidence:
        role = _hash_role_from_evidence(evidence, role)
    label = _CONFIDENCE_RE.search(evidence)
    confidence = label.group(1).lower() if label else "unknown"
    return SourceArtifact(value=value, kind=kind, role=role, status=status, confidence=confidence, evidence=evidence), ""


def _merge(existing: SourceArtifact, new: SourceArtifact) -> SourceArtifact:
    """Prefer the reading with supporting evidence; fill gaps from the other."""
    best, other = (new, existing) if new.evidence and not existing.evidence else (existing, new)
    for attr in ("role", "status", "confidence"):
        if getattr(best, attr) == "unknown" and getattr(other, attr) != "unknown":
            setattr(best, attr, getattr(other, attr))
    return best


def _to_record(artifact: SourceArtifact, url: str) -> IndicatorRecord:
    rtype = INDICATOR_KINDS[artifact.kind]
    value, port = split_host_port(artifact.value) if rtype == "ipv4" else (artifact.value, None)
    if rtype in ("sha256", "sha1", "md5", "domain", "hostname"):
        value = value.lower().rstrip(".")
    return IndicatorRecord(
        value=value,
        type=rtype,
        role=artifact.role,
        status=artifact.status,
        confidence=artifact.confidence,
        source=url if artifact.evidence else "cti",
        evidence=artifact.evidence,
        ports=[port] if port else [],
    )


def _parse(text: str) -> List[Dict[str, Any]]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    items = data.get("artifacts") if isinstance(data, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


# --- Targeted classification of feed indicators ----------------------------------------------

CLASSIFY_PROMPT = f"""You classify indicators using ONLY the report passages provided.
For each listed indicator return its role and status as the passages state them.
Hash roles: {list(HASH_ROLES)}. Network roles: {list(NETWORK_ROLES)}. Statuses: {list(STATUSES)}.
Use "historical" when the passages say an indicator is old, a prior tenant, unrelated, or not a
campaign IOC. "evidence" is one sentence copied word for word from the passages.
Return strict JSON: {{"artifacts": [{{"value": ..., "kind": ..., "role": ..., "status": ..., "evidence": ...}}]}}
"""

#: Characters of context around each occurrence of an indicator.
CONTEXT_CHARS = 700


def _contexts(text: str, value: str, limit: int = 2) -> List[str]:
    """Passages around the first occurrences of ``value`` (defanged or not) in ``text``."""
    target = normalise(value)
    found: List[str] = []
    for match in re.finditer(re.escape(value).replace(r"\.", r"(?:\.|\[\.\]|\(\.\))"), text, re.IGNORECASE):
        start, end = max(0, match.start() - CONTEXT_CHARS), match.end() + CONTEXT_CHARS
        found.append(text[start:end])
        if len(found) == limit:
            break
    return found if found or not target else []


def classify_feed_indicators(
    records: List[IndicatorRecord], evidence: "SourceEvidence", complete: Optional["Complete"] = None
) -> List[IndicatorRecord]:
    """Role and status for feed indicators the chunked pass did not classify.

    Only indicators the source actually mentions are asked about, with the
    passages around them; the reply goes through the same verbatim checks.
    Indicators the source never mentions are returned unchanged.
    """
    known = {(r.type, r.value) for r in evidence.indicators if r.evidence}
    pending = [r for r in records if (r.type, r.value) not in known and normalise(r.value) in normalise(evidence.text)]
    if not pending:
        return []
    passages: List[str] = []
    for record in pending:
        for passage in _contexts(evidence.text, record.value):
            if passage not in passages:
                passages.append(passage)
    listing = "\n".join(f"- {r.value} ({r.type})" for r in pending)
    prompt = f"Indicators:\n{listing}\n\nPassages:\n" + "\n---\n".join(passages)
    try:
        reply = (complete or _default_complete)(
            [{"role": "system", "content": CLASSIFY_PROMPT}, {"role": "user", "content": prompt[: CHUNK_CHARS * 2]}]
        )
    except Exception as exc:  # the provider raises its SDK's own error types
        logger.warning("Feed indicator classification failed: %s", exc)
        return []
    page = normalise(evidence.text)
    page_words = " ".join(_words(evidence.text))
    wanted = {normalise(r.value): r.type for r in pending}
    classified: List[IndicatorRecord] = []
    for raw in _parse(reply):
        value_key = normalise(str(raw.get("value", "")))
        rtype = wanted.get(value_key) or wanted.get(split_host_port(value_key)[0])
        if not rtype:
            continue
        raw = {**raw, "kind": rtype}
        artifact, problem = _checked(raw, page, page_words)
        if artifact is None:
            evidence.dropped.append(problem)
            continue
        classified.append(_to_record(artifact, evidence.url))
    return classified


# --- Extraction ------------------------------------------------------------------------------

Complete = Callable[[List[Dict[str, str]]], str]


def _default_complete(messages: List[Dict[str, str]]) -> str:
    from hecate_agent.core.llm_provider import create_provider

    return create_provider().complete(messages, max_tokens=3000, temperature=0.0).text


def extract_source_evidence(
    url: str, *, page_text: Optional[str] = None, complete: Optional[Complete] = None
) -> SourceEvidence:
    """Fetch ``url`` (unless ``page_text`` is given) and extract verified artifacts from all of it.

    Never raises: a fetch or model failure comes back as ``error`` so the
    caller can draft from the feed item as before.
    """
    evidence = SourceEvidence(url=url)
    try:
        text = page_text if page_text is not None else fetch_page_text(url)
    except (httpx.HTTPError, ValueError) as exc:
        evidence.error = f"fetch failed: {exc}"
        return evidence
    evidence.text = text
    evidence.chars = len(text)
    page = normalise(text)
    page_words = " ".join(_words(text))
    merged: Dict[Tuple[str, str], SourceArtifact] = {}
    call = complete or _default_complete
    chunks = chunk_text(text)
    evidence.chunks = len(chunks)
    for chunk in chunks:
        try:
            reply = call([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": chunk}])
        except Exception as exc:  # the provider raises its SDK's own error types
            logger.warning("Source evidence extraction call failed: %s", exc)
            evidence.error = evidence.error or f"extraction failed: {exc}"
            continue
        for raw in _parse(reply):
            artifact, problem = _checked(raw, page, page_words)
            if artifact is None:
                evidence.dropped.append(problem)
                continue
            key = (artifact.kind, normalise(artifact.value))
            merged[key] = _merge(merged[key], artifact) if key in merged else artifact
    evidence.artifacts = list(merged.values())
    evidence.indicators = [_to_record(a, url) for a in evidence.artifacts if a.kind in INDICATOR_KINDS]
    if evidence.artifacts:
        evidence.error = ""  # a partial failure still produced verified evidence
    return evidence


def build_indicator_records(
    cti_indicators: Dict[str, List[str]], evidence: Optional[SourceEvidence], complete: Optional[Complete] = None
) -> List[IndicatorRecord]:
    """The feed's indicators, typed with whatever the primary source says about them.

    Without usable source evidence the feed indicators come back with unknown
    roles, which route exactly as untyped indicators always have.
    """
    from hecate_agent.core.provenance import attach_url_ports, merge_records, records_from_cti

    cti = records_from_cti(cti_indicators)
    if evidence is None or not evidence.text:
        return cti
    extra = classify_feed_indicators(cti, evidence, complete)
    records = merge_records(cti, [*evidence.indicators, *extra])
    attach_url_ports(records)
    return records
