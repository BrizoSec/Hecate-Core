"""Typed indicator provenance: what an indicator is, not just its value.

The pipeline used to carry indicators as ``{type: [values]}`` and routed every
hash to a process-image rule and every host to DNS and network rules. H-0618
showed why that is wrong: of its seven SHA-256 values only one was a process
image (the others were an archive, a decoy document, network content and two
payloads that only ever existed in memory), and its five hostnames were, in
the primary report's words, "historical tenants of the same IP, not campaign
IOCs". An :class:`IndicatorRecord` keeps the role, status and confidence the
source gives, with the passage that says so, and :func:`placements` routes each
record only to the telemetry that can actually observe it.
"""

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

#: What a hash identifies. Only ``executable`` and ``library`` exist as a file a
#: process runs or loads; the rest cannot match a process-image hash.
HASH_ROLES = ("executable", "library", "archive", "document", "memory_only", "network_content", "unknown")
#: What a network indicator does in the intrusion.
NETWORK_ROLES = ("c2", "staging", "download", "historical", "unknown")
STATUSES = ("active", "historical", "unknown")
CONFIDENCES = ("high", "medium", "low", "unknown")

HASH_TYPES = ("md5", "sha1", "sha256", "imphash")
NETWORK_TYPES = ("ipv4", "ipv6", "domain", "hostname", "url")

#: CTI provider type names (OTX, MISP) -> record type.
_CTI_TYPE_MAP = {
    "md5": "md5", "filehash-md5": "md5",
    "sha1": "sha1", "filehash-sha1": "sha1",
    "sha256": "sha256", "filehash-sha256": "sha256",
    "imphash": "imphash", "filehash-imphash": "imphash",
    "ipv4": "ipv4", "ip-dst": "ipv4", "ip-src": "ipv4", "ipv6": "ipv6",
    "domain": "domain", "hostname": "hostname",
    "url": "url", "uri": "url", "link": "url",
}  # fmt: skip

_PORT_SUFFIX_RE = re.compile(r"^(?P<host>[^/\s]+?):(?P<port>\d{1,5})$")
_URL_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?P<host>[^/:?#\s]+)(?::(?P<port>\d{1,5}))?(?P<path>/[^?#\s]*)?", re.I)


@dataclass
class IndicatorRecord:
    """One indicator with the context that decides where it may be hunted."""

    value: str
    type: str
    role: str = "unknown"
    status: str = "unknown"
    confidence: str = "unknown"
    #: Where the value came from: the primary report's URL, or "cti" when only
    #: the feed that delivered the item names it.
    source: str = "cti"
    #: The source passage supporting role and status, verbatim. Empty means
    #: the role and status are unverified and treated as unknown.
    evidence: str = ""
    #: Destination ports the source ties to this address or URL host.
    ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IndicatorRecord":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        record = cls(**known)
        record.ports = sorted({int(p) for p in record.ports or [] if str(p).isdigit() and 0 < int(p) < 65536})
        return record


def refang(value: str) -> str:
    """Undo report defanging ("hxxp", "[.]", "(.)") so the value matches telemetry."""
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return re.sub(r"hxxp", "http", value, flags=re.IGNORECASE)


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    """``1.2.3.4:443`` -> (``1.2.3.4``, 443); anything else -> (value, None)."""
    match = _PORT_SUFFIX_RE.match(value.strip())
    if match and match.group("host").count(":") == 0:
        port = int(match.group("port"))
        if 0 < port < 65536:
            return match.group("host"), port
    return value.strip(), None


def url_parts(url: str) -> Tuple[str, Optional[int], str]:
    """(host, port, path) of a URL, with an empty path when there is none."""
    match = _URL_RE.match(refang(url).strip())
    if not match:
        return "", None, ""
    port = int(match.group("port")) if match.group("port") else None
    return match.group("host").lower(), port, match.group("path") or ""


def _normalise_value(value: str, rtype: str) -> str:
    value = refang(str(value)).strip()
    if rtype in HASH_TYPES or rtype in ("domain", "hostname"):
        return value.lower().rstrip(".")
    return value


def records_from_cti(indicators: Mapping[str, Iterable[str]], source: str = "cti") -> List[IndicatorRecord]:
    """Untyped feed indicators as records with unknown role and status."""
    records: List[IndicatorRecord] = []
    for itype, values in (indicators or {}).items():
        rtype = _CTI_TYPE_MAP.get(str(itype).lower().strip())
        if not rtype:
            continue
        for raw in values:
            value = _normalise_value(raw, rtype)
            if value and not any(r.value == value and r.type == rtype for r in records):
                records.append(IndicatorRecord(value=value, type=rtype, source=source))
    return records


_STATUS_RANK = {"unknown": 0, "historical": 1, "active": 2}


def _combine(into: IndicatorRecord, reading: IndicatorRecord) -> None:
    """Fold another reading of the same indicator into ``into``.

    Status precedence is active > historical > unknown: an address the source
    ties to this intrusion stays active even when the same address also has an
    older, unrelated history. The winning reading supplies role, confidence
    and evidence; a tie only fills gaps. Ports come only from non-historical
    readings, so an old service port (H-0618's ``:40010``) never scopes a
    current rule.
    """
    wins = _STATUS_RANK.get(reading.status, 0) > _STATUS_RANK.get(into.status, 0)
    ties = reading.status == into.status
    if wins:
        into.status = reading.status
    for attr in ("role", "confidence"):
        offered = getattr(reading, attr)
        if offered != "unknown" and (wins or (ties and getattr(into, attr) == "unknown")):
            setattr(into, attr, offered)
    if reading.evidence and (wins or (ties and not into.evidence)):
        into.evidence, into.source = reading.evidence, reading.source
    if reading.status != "historical":
        into.ports = sorted(set(into.ports) | set(reading.ports))


def merge_records(cti: List[IndicatorRecord], extracted: List[IndicatorRecord]) -> List[IndicatorRecord]:
    """Feed indicators enriched with what the primary source says about them.

    A feed value the source also names takes the source's role, status,
    confidence, evidence and ports. Values only the source names are added:
    they passed the verbatim check against the source text. Feed values the
    source never mentions keep an unknown role.
    """
    by_key: Dict[Tuple[str, str], IndicatorRecord] = {}
    for record in [*cti, *extracted]:
        key = (record.type, record.value)
        if key not in by_key:
            fresh = IndicatorRecord(**asdict(record))
            if fresh.status == "historical":
                fresh.ports = []
            by_key[key] = fresh
        else:
            _combine(by_key[key], record)
    return list(by_key.values())


def attach_url_ports(records: List[IndicatorRecord]) -> None:
    """Give each address the ports its URLs use, so network rules are port-scoped."""
    for url in (r for r in records if r.type == "url" and r.status != "historical"):
        host, port, _ = url_parts(url.value)
        if port is None:
            continue
        for record in records:
            if record.type in ("ipv4", "ipv6", "hostname", "domain") and record.value == host and port not in record.ports:
                record.ports = sorted(record.ports + [port])


def placements(record: IndicatorRecord) -> List[str]:
    """``<category>.<Field>`` placements a record may appear in, from its role and status.

    Historical indicators are never placed: they describe what the
    infrastructure hosted before, not this intrusion. A hash is placed only
    where a file with that hash can be observed. Unknown roles keep the old
    placements, since an unreviewed indicator is still worth sweeping for.
    """
    if record.status == "historical" or record.role == "historical":
        return []
    if record.type in HASH_TYPES:
        if record.role in ("executable", "unknown"):
            return ["process_creation.Hashes"]
        if record.role == "library":
            return ["image_load.Hashes"]
        return []
    if record.type in ("ipv4", "ipv6"):
        return ["network_connection.DestinationIp"]
    if record.type in ("domain", "hostname"):
        return ["dns_query.QueryName", "network_connection.DestinationHostname"]
    if record.type == "url":
        return ["proxy.c-uri"]
    return []


def hash_label(rtype: str) -> str:
    return {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "imphash": "IMPHASH"}[rtype]


def routable_indicators(records: List[IndicatorRecord]) -> Dict[str, List[str]]:
    """``{type: [values]}`` for the records a rule may use, for prompts and checks.

    Historical indicators and hashes of things no telemetry sees as a file
    (archives, documents, network content, in-memory payloads) are left out,
    so a model-drafted rule that reaches for them is rejected as invented.
    """
    out: Dict[str, List[str]] = {}
    for record in records:
        if placements(record):
            out.setdefault(record.type, [])
            if record.value not in out[record.type]:
                out[record.type].append(record.value)
    return out
