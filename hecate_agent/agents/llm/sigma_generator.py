"""Sigma rule generator agent - drafts portable detection logic for a hunt.

Emits Sigma because the hunt program has no committed query platform yet: a
Sigma rule converts to Splunk, Elastic, CrowdStrike or Defender later via
pySigma, so drafting here commits to nothing. Rules are *proposals for an
operator to review*, never anything executed -- generation deliberately sits
before human review in the hunt lifecycle, not after it.

Two design choices are worth stating, because both are load-bearing:

**The model never writes YAML.** It returns JSON, and this module serialises
the YAML itself. A model asked for YAML directly produces plausible-looking
text that fails to parse (or, worse, parses into the wrong shape) often
enough to matter, and a malformed rule is indistinguishable from a real one
until someone tries to convert it. Generating structure and rendering it
deterministically makes malformed output impossible by construction.

**Applicable log sources are derived, not asked for.** Which telemetry a hunt
needs follows from its ATT&CK techniques and the indicator types the CTI
actually carried -- both facts already in hand. Asking the model to nominate
them invites it to reach for whatever it writes about most, which is how a
hunt against a backdoor with nine C2 URLs ends up scoped to process
telemetry alone.
"""

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from hecate_agent.agents.base import AgentResult, LLMAgent
from hecate_agent.core.sigma_semantics import base_field, blocks, repair_sigma_semantics, semantic_problem

logger = logging.getLogger(__name__)

# Sigma log source categories this agent will emit. Restricted to the ones
# with well-established field names across backends -- an invented category
# converts to nothing and silently drops the rule at pySigma time.
VALID_LOGSOURCE_CATEGORIES = {
    "process_creation",
    "network_connection",
    "dns_query",
    "file_event",
    "registry_event",
    "image_load",
    # Every other category here is host/endpoint telemetry. Without an
    # authentication category no credential-access technique mapped anywhere,
    # so `applicable_logsources` fell through to its process_creation fallback
    # and the model was asked to detect credential stuffing in process command
    # lines. It answered `CommandLine|contains: login`, which is the best
    # available answer to an impossible question.
    "authentication",
    "proxy",
    # Web server and reverse-proxy access logs: the telemetry an exploited
    # edge appliance actually produces. Without it H-0830 (NetScaler RCE via
    # User-Agent log poisoning) could only be drafted as process_creation.
    "webserver",
    # Cloud control-plane and identity provider audit logs: capture Stage 1
    # OAuth consent abuse, app registrations, and AWS STS role assumptions.
    "cloud_audit",
    "identity_audit",
}

#: Field names each log source actually carries, so the prompt for one
#: category never offers another's fields -- a borrowed field name matches
#: nothing and fails silently at pySigma conversion time.
_LOGSOURCE_FIELDS = {
    "process_creation": "Image, CommandLine, ParentImage, OriginalFileName, User",
    "network_connection": "DestinationIp, DestinationHostname, DestinationPort, Initiated, Image",
    "dns_query": "QueryName, QueryResults, Image",
    "file_event": "TargetFilename, Image, User",
    "registry_event": "TargetObject, Details, EventType, Image",
    "image_load": "ImageLoaded, Image, Signed, Signature",
    # Sigma's cross-platform authentication taxonomy. Deliberately not Windows
    # EventCode: a rule pinned to Security 4625 stops matching the moment the
    # hunt is scoped to Linux or a SaaS identity provider.
    "authentication": (
        "TargetUserName, SubjectUserName, LogonType, AuthenticationPackageName, WorkstationName, IpAddress, Status, SubStatus"
    ),
    "proxy": (
        "c-uri, c-uri-stem, c-uri-query, c-uri-extension, c-useragent, cs-host, cs-method, cs-referrer, sc-status, src_ip, dst_ip"
    ),
    "webserver": "cs-method, cs-uri-stem, cs-uri-query, cs-user-agent, cs-referrer, sc-status, c-ip",
    "cloud_audit": ("eventSource, eventName, userIdentity, sourceIPAddress, userAgent, awsRegion, requestParameters, action"),
    "identity_audit": (
        "eventName, operationType, appId, appDisplayName, targetResources, initiatedBy, roles, permissions, status"
    ),
}

#: Sigma aggregation grammar: ``<func>(<field>?) [by <field>] <op> <number>``.
#: The functions the specification defines, plus the comparison operators a
#: threshold can use.
_AGGREGATION_RE = re.compile(
    r"^(?:count|min|max|avg|sum)\s*\(\s*[A-Za-z0-9_.\-]*\s*\)"
    r"(?:\s+by\s+[A-Za-z0-9_.\-]+)?"
    r"\s*(?:>=|<=|==|!=|>|<|=)\s*\d+(?:\.\d+)?$",
    re.IGNORECASE,
)

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

# technique prefix -> log source categories that technique is observable in.
# Prefix matching so a sub-technique inherits its parent's mapping
# (T1059.003 matches "T1059") without enumerating every sub-technique.
_TECHNIQUE_LOGSOURCES: Dict[str, Set[str]] = {
    "T1059": {"process_creation"},
    "T1106": {"process_creation"},
    "T1204": {"process_creation"},
    "T1620": {"process_creation", "image_load"},
    "T1027": {"process_creation", "file_event"},
    "T1140": {"process_creation"},
    "T1105": {"network_connection", "file_event"},
    "T1041": {"network_connection"},
    "T1071": {"network_connection", "dns_query"},
    "T1090": {"network_connection"},
    "T1005": {"file_event", "process_creation"},
    "T1083": {"file_event", "process_creation"},
    "T1070": {"file_event"},
    "T1574": {"image_load", "file_event"},
    "T1547": {"registry_event", "process_creation", "file_event"},
    "T1543": {"registry_event", "process_creation"},
    "T1112": {"registry_event"},
    "T1611": {"process_creation"},
    "T1562": {"process_creation", "file_event"},
    "T1003": {"process_creation", "file_event"},
    "T1218": {"process_creation"},
    "T1567": {"process_creation", "network_connection"},
    "T1564": {"process_creation", "file_event"},
    "T1573": {"network_connection"},
    "T1104": {"network_connection", "process_creation"},
    "T1485": {"process_creation", "file_event"},
    "T1546": {"process_creation", "file_event", "registry_event"},
    # Credential access and account abuse. These are observable in
    # authentication telemetry and essentially nowhere else -- mapping them to
    # nothing is what forced them into process_creation.
    "T1110": {"authentication"},
    "T1078": {"authentication"},
    "T1078.004": {"authentication", "identity_audit", "cloud_audit"},
    "T1098": {"authentication"},
    "T1098.003": {"authentication", "identity_audit", "cloud_audit"},
    "T1621": {"authentication"},
    "T1550": {"authentication"},
    "T1550.001": {"authentication", "identity_audit"},
    "T1528": {"identity_audit", "cloud_audit"},
    "T1538": {"cloud_audit"},
    "T1580": {"cloud_audit"},
    "T1530": {"cloud_audit"},
    "T1556": {"authentication", "registry_event"},
    "T1187": {"authentication", "network_connection"},
    # Added from the fallback warning's own output: these fell through to
    # process_creation over four days of live drafting, so the model was asked
    # to express phishing and adversary-in-the-middle as process telemetry.
    "T1566": {"file_event", "network_connection"},
    "T1598": {"network_connection"},
    "T1036": {"process_creation", "file_event"},
    "T1203": {"process_creation", "image_load"},
    "T1068": {"process_creation"},
    "T1557": {"network_connection", "authentication"},
    "T1021": {"authentication", "network_connection"},
    "T1189": {"network_connection", "proxy"},
    "T1190": {"webserver", "network_connection", "process_creation"},
    # Web shells are installed by writing a file and used through web requests.
    "T1505": {"webserver", "file_event", "process_creation"},
    "T1595": {"webserver", "network_connection"},
    "T1133": {"network_connection", "authentication"},
    "T1486": {"file_event", "process_creation"},
    "T1053": {"process_creation", "file_event"},
    "T1037": {"process_creation", "file_event", "registry_event"},
}

# MISP/OTX attribute type -> log source category. The indicator types a CTI
# item actually carried are direct evidence of which telemetry can match it:
# nine C2 URLs mean network hunting is applicable whatever the prose said.
_INDICATOR_LOGSOURCES: Dict[str, Set[str]] = {
    "ip-dst": {"network_connection"},
    "ip-src": {"network_connection"},
    "domain": {"dns_query", "network_connection"},
    "hostname": {"dns_query", "network_connection"},
    "url": {"network_connection"},
    "uri": {"network_connection"},
    "proxy.c-uri": {"proxy"},
    "c-uri": {"proxy"},
    "proxy": {"proxy"},
    "filename": {"file_event", "process_creation"},
    "filepath": {"file_event"},
    "md5": {"file_event"},
    "sha1": {"file_event"},
    "sha256": {"file_event"},
    "regkey": {"registry_event"},
    "mutex": {"process_creation"},
    # OTX names the same concepts differently (verified against live pulses:
    # domain, hostname, URL, IPv4, FileHash-SHA256/MD5/SHA1, CVE). Lookups
    # lowercase the type, so only the genuinely different spellings need
    # listing here. CVE is deliberately absent -- a CVE identifies a
    # vulnerability, not an observable a detection rule can match.
    "ipv4": {"network_connection"},
    "ipv6": {"network_connection"},
    "filehash-md5": {"file_event"},
    "filehash-sha1": {"file_event"},
    "filehash-sha256": {"file_event"},
}


def applicable_logsources(
    techniques: List[str],
    indicator_types: Optional[List[str]] = None,
) -> List[str]:
    """Derive which Sigma log sources this hunt should cover.

    Deterministic and independent of the LLM on purpose: this is the
    "applicable data sources" decision, and it should be reproducible and
    arguable from the inputs rather than resampled per run.

    Falls back to ``process_creation`` only when nothing matched at all --
    an empty list would mean generating no rules, which is a worse answer
    than the single most broadly useful log source.
    """
    found: Set[str] = set()

    for technique in techniques or []:
        normalised = str(technique).upper().strip()
        for prefix, sources in _TECHNIQUE_LOGSOURCES.items():
            if normalised.startswith(prefix):
                found |= sources

    for indicator_type in indicator_types or []:
        found |= _INDICATOR_LOGSOURCES.get(str(indicator_type).lower().strip(), set())

    if not found:
        # Reported, not silent. This fallback is how a credential-stuffing hunt
        # ended up with a process_creation rule: nothing matched, the default
        # was substituted, and the draft gave no sign that its log source was a
        # guess rather than a derivation. A rule still beats no rule, but the
        # reader needs to know which one they are holding.
        logger.warning(
            "No log source maps to techniques %s or indicator types %s; "
            "falling back to process_creation, which may not carry this behaviour",
            list(techniques or []),
            list(indicator_types or []),
        )
        return ["process_creation"]
    # Stable order so a rerun on identical input yields identical filenames.
    return sorted(found)


#: Log sources that exist on only some platforms. H-0004, scoped to macOS and
#: Linux, was drafted a Windows registry rule because one of its (wrong)
#: techniques mapped to registry persistence.
_PLATFORM_ONLY_LOGSOURCES: Dict[str, str] = {"registry_event": "windows"}

#: Platforms that run no host sensor: a hunt scoped only to these cannot see
#: process, file, registry or module-load events, only what the device logs
#: and what the network sees. H-0830's NetScaler hunt was drafted for EDR the
#: appliance does not have.
APPLIANCE_PLATFORMS = frozenset({"network devices"})
HOST_SENSOR_LOGSOURCES = frozenset({"process_creation", "file_event", "registry_event", "image_load"})


def appliance_only(platforms: List[str]) -> bool:
    """Whether every platform the hunt is scoped to is an appliance without host sensors."""
    known = {str(p).strip().lower() for p in platforms or [] if str(p).strip()}
    return bool(known) and known <= APPLIANCE_PLATFORMS


def _platform_consistent_logsources(logsources: List[str], platforms: List[str]) -> List[str]:
    """Drop log sources none of the hunt's platforms can produce.

    An empty platform list means scope is unknown, not that nothing applies,
    so nothing is dropped then.
    """
    known = {str(p).strip().lower() for p in platforms or [] if str(p).strip()}
    if not known:
        return logsources
    kept = [ls for ls in logsources if _PLATFORM_ONLY_LOGSOURCES.get(ls, "") in known | {""}]
    if appliance_only(platforms):
        kept = [ls for ls in kept if ls not in HOST_SENSOR_LOGSOURCES]
    for dropped in sorted(set(logsources) - set(kept)):
        logger.info("Skipping %s: no platform of this hunt (%s) produces it", dropped, ", ".join(sorted(known)))
    return kept or (["webserver"] if appliance_only(platforms) else ["process_creation"])


#: Indicator type (MISP and OTX spellings, lowercased) -> the algorithm label
#: Sysmon writes in its ``Hashes`` field, and the hex length a real value has.
_HASH_TYPES: Dict[str, Tuple[str, int]] = {
    "md5": ("MD5", 32),
    "filehash-md5": ("MD5", 32),
    "sha1": ("SHA1", 40),
    "filehash-sha1": ("SHA1", 40),
    "sha256": ("SHA256", 64),
    "filehash-sha256": ("SHA256", 64),
    "imphash": ("IMPHASH", 32),
    "filehash-imphash": ("IMPHASH", 32),
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def hash_selectors(indicators: Dict[str, List[str]]) -> List[str]:
    """``ALGO=hex`` values for every well-formed hash indicator, in order.

    Malformed values (wrong length, non-hex) are dropped rather than repaired:
    a truncated hash matches nothing and would read as coverage.
    """
    selectors: List[str] = []
    for itype, values in (indicators or {}).items():
        spec = _HASH_TYPES.get(str(itype).lower().strip())
        if not spec:
            continue
        label, length = spec
        for value in values:
            text = str(value).strip()
            if len(text) == length and _HEX_RE.match(text):
                # Lowercase, as intel publishes it: Sigma's `contains` is
                # case-insensitive, and the grounding audit matches the rule's
                # values against the CTI text.
                selector = f"{label}={text.lower()}"
                if selector not in selectors:
                    selectors.append(selector)
    return selectors


_IP_TYPES = frozenset({"ip-dst", "ip-src", "ipv4", "ipv6", "ip-dst|port", "ip-src|port"})
_NAME_TYPES = frozenset({"domain", "hostname"})
_URL_TYPES = frozenset({"url", "uri", "link"})


def _global_ip(value: str) -> Optional[str]:
    """The address in ``1.2.3.4``, ``1.2.3.4|443`` or ``1.2.3.4:443``, if routable."""
    import ipaddress

    text = value.strip().split("|", 1)[0]
    if text.count(":") == 1:  # IPv4 with a port; IPv6 has several colons
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _classify_network_value(kind: str, value: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(address, exact name, ``.domain`` suffix) one indicator value contributes."""
    if kind in _IP_TYPES:
        return _global_ip(value), None, None
    if kind == "domain|ip":
        name, _, address = value.partition("|")
        name = name.lower()
        return _global_ip(address), name if _DOMAIN_RE.match(name) else None, None
    if kind not in _NAME_TYPES and kind not in _URL_TYPES:
        return None, None, None
    if kind in _URL_TYPES:
        match = _URL_HOST_RE.match(value)
        value = match.group(1) if match else ""
    name = value.lower().rstrip(".")
    if _global_ip(name):
        return _global_ip(name), None, None
    if not _DOMAIN_RE.match(name):
        return None, None, None
    return None, name, "." + name if kind == "domain" else None


def network_selectors(indicators: Dict[str, List[str]]) -> Tuple[List[str], List[str], List[str]]:
    """(addresses, exact host names, ``.domain`` suffixes) from supplied indicators.

    Only routable addresses and well-formed names survive; a private address
    or a malformed name matches nothing the intel describes. Suffixes are
    built from ``domain`` indicators only, so a supplied registrable domain
    also covers its subdomains, while a specific ``hostname`` stays exact.
    """
    buckets: Tuple[List[str], List[str], List[str]] = ([], [], [])
    for itype, values in (indicators or {}).items():
        kind = str(itype).lower().strip()
        for raw in values:
            for bucket, found in zip(buckets, _classify_network_value(kind, str(raw).strip())):
                if found and found not in bucket:
                    bucket.append(found)
    return buckets


@dataclass
class SigmaGenerationInput:
    """Input for Sigma rule generation."""

    hypothesis: str
    threat_intel: str = ""
    hunt_id: str = ""
    justification: str = ""
    techniques: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    # attribute type -> concrete values from the source CTI, e.g.
    # {"hostname": ["api.wiresguard.com"], "filename": ["...svchost.exe"]}.
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    # Behavioural observables the hunt draft named -- process names, paths,
    # channels -- mostly from grounded research. Model output, so they steer
    # the prompt and are never required: an earlier check that demanded an
    # indicator rejected every rule on three consecutive live cycles.
    observables: List[str] = field(default_factory=list)
    # Explicit override; when empty the log sources are derived.
    logsources: List[str] = field(default_factory=list)
    # Typed indicators (hecate_agent.core.provenance.IndicatorRecord as dicts):
    # role, status and ports from the primary source. When present, the
    # deterministic IOC rules route each indicator by role instead of placing
    # every hash in a process rule and every host in DNS and network rules.
    indicator_records: List[Dict[str, Any]] = field(default_factory=list)
    # The source's own detection guidance (hecate_agent.core.detection_guidance
    # GuidanceItem dicts). Items routed to Sigma with a template become
    # deterministic rules citing the guidance; the rest steer the prompt.
    detection_guidance: List[Dict[str, Any]] = field(default_factory=list)
    # Verified primary-source artifacts (SourceArtifact dicts). Two-pass
    # generation: pass one turns them into Sigma-ready literals
    # (hecate_agent.core.query_literals); pass two, the model, may use only
    # those in file, process, command-line and registry fields.
    source_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    # Commands the source shows being run (hecate_agent.core.command_rules
    # candidates): each becomes a deterministic process_creation rule.
    observed_commands: List[Dict[str, Any]] = field(default_factory=list)
    # A2: review each model-drafted rule against the hypothesis and the source
    # passages, and list behaviours no rule covers. Off unless asked: it costs
    # one model call per model rule plus one.
    review_rules: bool = False

    def query_literals(self) -> List[Dict[str, Any]]:
        from hecate_agent.core.query_literals import literals_from_artifacts

        return [lit.to_dict() for lit in literals_from_artifacts(self.source_artifacts, self.platforms)]


@dataclass
class SigmaRule:
    """One generated rule plus the provenance an operator needs to judge it."""

    logsource_category: str
    title: str
    rule_yaml: str
    techniques: List[str] = field(default_factory=list)
    level: str = "medium"
    #: "model" for a rule the model drafted, "deterministic" for one built from
    #: indicators, guidance or verified artifacts. Only model rules are reviewed.
    origin: str = "model"

    @property
    def filename(self) -> str:
        slug = "".join(c if c.isalnum() else "_" for c in self.title.lower())
        slug = "_".join(part for part in slug.split("_") if part)[:60]
        return f"{self.logsource_category}__{slug or 'rule'}.yml"


#: Files the operating system and its administrators also write. An actor's change to one is
#: real, but the path alone cannot tell it from routine use: every deterministic file rule was
#: "high", including one for root's crontab, which fires on any edit of it.
_SHARED_SYSTEM_FILE_RE = re.compile(
    r"(?i)(^|/)(var/spool/cron/(crontabs/)?[\w.-]+|etc/(crontab|rc\.local|passwd|shadow|sudoers|hosts|profile|environment"
    r"|ld\.so\.preload)|\.ssh/authorized_keys|\.(bashrc|zshrc|bash_profile|zprofile|profile))$"
)


def _behaviour_techniques(behaviour: str, hunt_techniques: List[str]) -> List[str]:
    """The hunt's techniques that the rule's own command, path or guidance text shows.

    Deterministic rules shipped untagged. A tag is given only when the
    behaviour catalog matches the text the rule was built from and the hunt
    already maps that technique, so a tag never adds a mapping: ``xattr -d
    com.apple.quarantine`` is T1553.001, a file under ``/etc/cron.d`` T1053.003.
    Indicator sweeps stay untagged: matching an address is not a technique.
    """
    if not behaviour.strip():
        return []
    from hecate_agent.core.technique_evidence import map_behaviours

    supplied = {t.upper() for t in hunt_techniques}
    found = {e.technique_id.upper() for e in map_behaviours([("rule", behaviour)]) if e.status == "observed"}
    return sorted(found & supplied)


def rule_filenames(rules: List[SigmaRule]) -> List[str]:
    """A distinct file name for each rule, in order: a repeat gets a numbered suffix.

    Titles are cut to 60 characters and stripped of punctuation, so different
    rules can share a name. The Redis botnet replay built rules for
    /etc/cron.d/.redis-miner, /etc/cron.d/redis-miner and
    /etc/cron.hourly/redis-miner; each overwrote the last and one reached disk.
    """
    seen: Dict[str, int] = {}
    names: List[str] = []
    for rule in rules:
        name = rule.filename
        seen[name] = seen.get(name, 0) + 1
        names.append(name if seen[name] == 1 else f"{name[:-4]}_{seen[name]}.yml")
    return names


@dataclass
class SigmaGenerationOutput:
    """Output from Sigma rule generation."""

    rules: List[SigmaRule] = field(default_factory=list)
    logsources_considered: List[str] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    omitted: List[str] = field(default_factory=list)
    #: Behaviours the rule reviewer found no rule for, each with its verified quote.
    review_gaps: List[Dict[str, str]] = field(default_factory=list)


def _select_for_logsource(
    built: List[SigmaRule], logsource: str, problems: List[str]
) -> Tuple[Optional[SigmaRule], List[str], List[str]]:
    """Pick the rule written for the requested category, noting rejections and omitted sources.

    A rule written for a different category than the one asked for is not the
    rule this iteration needed; relabelling it would file process telemetry
    under DNS.
    """
    match = None
    rejections = list(problems)
    omitted: List[str] = []
    for rule in built:
        if match is None and rule.logsource_category == logsource:
            match = rule
        elif rule.logsource_category != logsource:
            rejections.append(f"{logsource}: model returned a {rule.logsource_category} rule instead")

    if match is None and not rejections:
        omitted.append(f"{logsource}: no rule returned")
    return match, rejections, omitted


#: Fragments that mark a detection value as scaffolding rather than a real
#: observable. Three sources, all seen in drafted rules:
#:
#: * this module's own prompt example, echoed back ("known-good", "FieldName",
#:   the bare literal "value");
#: * textbook fillers the model reaches for when it has no indicator to use
#:   ("bad_command", "%appdata%\\malicious", "\\malicious-ai-tool.exe");
#: * RFC 2606 reserved names written into a C2 pattern (".c2.example.com").
#:
#: Matched case-insensitively as substrings, because the model wraps them --
#: the prompt's "known-good" came back as "known-good-script.exe".
_PLACEHOLDER_SUBSTRINGS = (
    "known-good",
    "bad_command",
    "fieldname",
    "example.com",
    "example.org",
    "example.net",
    "example.test",
    "yourdomain",
    "your-domain",
    "placeholder",
    "changeme",
    "malicious",
    "evil.",
    "lorem",
    "foo.bar",
    "<value>",
    "<name>",
    # Template paths. H-0018's rule matched `C:\path\to\malware.ps1`, which
    # the hypothesis model had written into the draft's observables.
    "\\path\\to\\",
    "/path/to/",
)

#: A stand-in file name: nothing but a generic word and an extension.
#: `malware.ps1`, `rat.exe`, `evil.dll` name no file a hunter could find.
_PLACEHOLDER_FILE_RE = re.compile(
    r"(?:^|[\\/])(?:malware|malicious|rat|evil|badfile|payload)\.(?:exe|dll|ps1|bin|sh|bat|vbs|js|msi)$",
    re.IGNORECASE,
)

#: Placeholders only when they are the entire value. As substrings these
#: appear inside legitimate paths and hostnames.
#: The generic nouns are here too: H-0009's file rule matched
#: ``TargetFilename|contains: malware``, a word no real file path is made of.
_PLACEHOLDER_EXACT = frozenset(
    {
        "value", "string", "name", "n/a", "none", "null", "-", "todo", "tbd",
        "malware", "payload", "backdoor", "attacker", "suspicious", "exploit", "c2",
    }
)  # fmt: skip


def _detection_values(detection: Dict[str, Any]) -> List[str]:
    """Every scalar a detection block would actually match on."""
    values: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif node is not None and not isinstance(node, bool):
            values.append(str(node))

    for key, block in detection.items():
        if key != "condition":
            walk(block)
    return values


def _impossible_ipv4(value: str) -> bool:
    """True for a dotted-quad-shaped value with an out-of-range octet.

    "123.456.789" cannot match anything: it is invented, not observed.
    Partial prefixes ("192.168.") are left alone -- those are a legitimate
    `|contains` idiom.
    """
    parts = value.strip().rstrip(".").split(".")
    if len(parts) < 3 or not all(part.isdigit() for part in parts):
        return False
    return any(int(part) > 255 for part in parts)


#: Ranges reserved for documentation (RFC 5737, RFC 3849). Nothing routes
#: them, so a rule matching one matches nothing: H-0016's rerun kept
#: ``DestinationIp|cidr: 198.51.100.0/24`` because the invented-IP check
#: exempts CIDR ranges, which are otherwise how behaviour is written.
_DOCUMENTATION_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")


def _documentation_address(value: str) -> bool:
    """True for an address or CIDR range inside a documentation range."""
    import ipaddress

    text = value.strip().strip("[]")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return any(
        network.version == doc.version and network.subnet_of(doc)  # type: ignore[arg-type]
        for doc in (ipaddress.ip_network(n) for n in _DOCUMENTATION_NETS)
    )


#: A bare snake_case identifier -- "signed_binary_path", "bad_command" --
#: is a description of what a value should be, not a value. Real detection
#: content carries a separator: a path has "\\" or "/", a filename or domain
#: has ".", a flag has "-" or "=". This catches the stand-ins the model
#: invents fresh, which no denylist of known placeholders can cover; it was
#: added after a live run produced "signed_binary_path" past the denylist.
_SNAKE_PLACEHOLDER_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")


#: Set once, the first time pySigma is found missing, so the warning is
#: emitted a single time per process rather than per rule.
_PYSIGMA_WARNED = False


def _pysigma_problem(rule_yaml: str) -> Optional[str]:
    """Parse a rendered rule with pySigma; return why it is not valid Sigma.

    The structural checks above catch what a rule needs to be *coherent* --
    a condition that names its selections, a category we recognise. They say
    nothing about whether the result is Sigma, and the model reliably invents
    syntax that is valid YAML and meaningless to a Sigma backend: a
    query-DSL ``$or:`` key, a nonexistent ``|in`` modifier, a detection whose
    every block is empty. Each of those shipped in the corpus, each looked
    like a rule, and none of them would ever match. pySigma is the reference
    parser, so it is the honest arbiter of "is this Sigma".

    Returns ``None`` when pySigma is not installed, after warning once. That
    is a deliberate fallback rather than a hard failure -- the extra is
    optional and drafting should not stop without it -- but it is *loud*,
    because a validator that silently passes everything is worse than none.
    """
    global _PYSIGMA_WARNED
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        if not _PYSIGMA_WARNED:
            _PYSIGMA_WARNED = True
            logger.warning(
                "pysigma is not installed, so generated rules are NOT being validated as "
                "Sigma -- only structurally checked. Install it with: pip install -e '.[sigma]'"
            )
        return None

    try:
        SigmaCollection.from_yaml(rule_yaml)
    except Exception as exc:  # pySigma raises a family of SigmaError subclasses
        return f"not valid Sigma ({type(exc).__name__}: {str(exc)[:160]})"
    return None


#: Parent processes a browser-borne delivery hunt must not exclude. Narrow on
#: purpose: this is the one self-defeating exclusion actually observed, where a
#: hunt about a poisoned search result delivering a macOS stealer filtered out
#: `ParentImage|contains: /Applications/Safari.app` -- the exact parent the
#: hypothesis predicts. The rule was valid Sigma and passed every structural
#: check while excluding its own primary scenario.
_BROWSER_PARENTS = (
    "safari",
    "chrome",
    "firefox",
    "msedge",
    "microsoftedge",
    "brave",
    "opera",
    "chromium",
)

#: Hypothesis language that means "the browser is the delivery path". Only when
#: one of these is present does excluding a browser parent become a defect
#: rather than a reasonable noise filter.
_BROWSER_DELIVERY_TERMS = (
    "seo",
    "search result",
    "search engine",
    "poisoned search",
    "drive-by",
    "driveby",
    "malvertis",
    "download",
    "browser",
    "watering hole",
)


def _strip_empty_filters(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Drop filter blocks that match nothing, and the condition terms naming them.

    Repaired rather than rejected. `filter: {}` with a `condition` of
    "selection and not filter" is a no-op that reads to a reviewer as a
    deliberate exclusion, but the selection around it can be perfectly good --
    and a rejected rule is not retried, so refusing the whole rule costs the
    draft its entire detection section over a cosmetic defect.
    """
    empty = [key for key, block in detection.items() if key != "condition" and isinstance(block, dict) and not block]
    if not empty:
        return detection

    cleaned = {key: block for key, block in detection.items() if key not in empty}
    condition = str(cleaned.get("condition", ""))
    for name in empty:
        quoted = re.escape(name)
        # Longest form first: "x and not filter" must not leave a dangling "not".
        condition = re.sub(rf"\s+and\s+not\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\s+and\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\bnot\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\b{quoted}\b", "", condition)
    condition = re.sub(r"\s+", " ", condition).strip()
    if condition:
        cleaned["condition"] = condition
    return cleaned


#: Fields whose value is a full path, so an exact match on a bare filename
#: can never succeed: Sysmon's Image is C:\\...\\nvidia-sysruntime.exe, never
#: nvidia-sysruntime.exe.
_FULL_PATH_FIELDS = frozenset({"image", "parentimage", "targetfilename", "imageloaded"})


def _anchor_bare_filenames(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite `Image: name.exe` as `Image|endswith: \\name.exe`.

    Repaired rather than rejected, for the same reason as empty filters: the
    rule's intent is unambiguous and a rejected rule is not retried. Observed
    on H-0002's regeneration, where the rule's one specific value -- the
    masquerading filename from research -- sat in exactly this form.
    """

    def bare(value: Any) -> bool:
        return isinstance(value, str) and bool(value) and not any(c in value for c in "\\/*")

    def repair_block(block: Any) -> Any:
        if isinstance(block, list):
            return [repair_block(item) for item in block]
        if not isinstance(block, dict):
            return block
        repaired: Dict[str, Any] = {}
        for key, value in block.items():
            values = value if isinstance(value, list) else [value]
            if key.lower() in _FULL_PATH_FIELDS and values and all(bare(v) for v in values):
                anchored = ["\\" + v for v in values]
                repaired[f"{key}|endswith"] = anchored if isinstance(value, list) else anchored[0]
            else:
                repaired[key] = value
        return repaired

    return {key: (block if key == "condition" else repair_block(block)) for key, block in detection.items()}


def _complete_indicator_lists(detection: Dict[str, Any], supplied: Dict[str, List[str]]) -> Dict[str, Any]:
    """Widen a field matching some supplied indicators to all of that type.

    The model reliably picks one example and stops: H-0004's CTI carried four
    C2 IPs and both its network and authentication rules matched only
    ``166.88.134.62``. Which value it picked is arbitrary, and a hunt that
    checks one of four addresses misses three quarters of the evidence it was
    handed. Repaired rather than rejected -- the rule's intent (match these
    indicators in this field) is unambiguous.

    Only selections are widened, never a block the condition negates, and only
    a field whose every value is an exact supplied indicator: ``|endswith``
    on a path, or a value the model wrote itself, is left alone.
    """
    by_value: Dict[str, str] = {}
    for itype, values in (supplied or {}).items():
        for value in values:
            by_value.setdefault(str(value).strip().lower(), itype)
    if not by_value:
        return detection

    negated = _negated_blocks(detection, str(detection.get("condition", "")))

    def widen(block: Dict[str, Any]) -> Dict[str, Any]:
        widened: Dict[str, Any] = {}
        for key, value in block.items():
            values = value if isinstance(value, list) else [value]
            types = {by_value.get(str(v).strip().lower()) for v in values}
            if values and None not in types:
                full: List[str] = []
                for itype in sorted(t for t in types if t):
                    full.extend(str(v) for v in supplied[itype])
                full = list(dict.fromkeys([*map(str, values), *full]))
                widened[key] = full if len(full) > 1 else full[0]
            else:
                widened[key] = value
        return widened

    return {
        name: (widen(block) if name != "condition" and name not in negated and isinstance(block, dict) else block)
        for name, block in detection.items()
    }


#: Fields that hold a network address, not a name. The model fills whatever
#: indicator it has into whatever field it picked, so a hunt whose only
#: indicators were domains produced `IpAddress|endswith: .jeetbot.cc` and
#: `IpAddress|contains: telegram.org`. Both are valid Sigma, pass every other
#: check, and can never match anything.
_IP_FIELDS = frozenset({"ipaddress", "destinationip", "sourceip", "srcip", "dstip", "clientip", "serverip"})

#: Fields that hold a port number.
_PORT_FIELDS = frozenset({"destinationport", "sourceport", "srcport", "dstport"})


#: Fields that hold a file path and nothing else.
_FILENAME_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "originalfilename"})

#: A command-line switch: "-ExecutionPolicy", "--output", or a short "/c"
#: after whitespace. H-0018's file_event rule matched `TargetFilename|contains:
#: -ExecutionPolicy Bypass -File`, which no file name ever contains.
_SWITCH_RE = re.compile(r"(?:^|\s)(?:--?[A-Za-z][\w-]*|/[A-Za-z]{1,3})(?=\s|$)")


def _looks_like_address(value: str) -> bool:
    """Whether `value` could be part of an IP address or CIDR range.

    Deliberately permissive about fragments: `192.168.` and `.133` are
    legitimate `contains`/`endswith` idioms and this module already treats
    them as such. What it rejects is a value that is not an address at all.
    """
    cleaned = value.strip()
    if not cleaned:
        return False
    if ":" in cleaned:
        # IPv6, which is the only form allowed to carry letters.
        return all(c in "0123456789abcdefABCDEF:./" for c in cleaned)
    return all(c in "0123456789./" for c in cleaned)


def _field_type_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a value that cannot occur in the field it is matched against.

    A type mismatch is the one rule defect that needs no judgement: an address
    field holding a hostname matches nothing on any backend, in any
    environment, forever. Caught here rather than left to review because it
    looks exactly like a working rule.
    """
    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            base = str(field_name).split("|")[0].strip().lower()
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                text = str(value)
                if base in _IP_FIELDS and not _looks_like_address(text):
                    return (
                        f"{field_name} holds a network address, but the detection matches "
                        f"on {text!r}; a hostname in an address field never matches"
                    )
                if base == "targetobject" and "/" in text and "\\" not in text:
                    return (
                        f"{field_name} holds a Windows registry path, but the detection matches on {text!r}, a Unix file path"
                    )
                if base in _PORT_FIELDS and not text.strip().lstrip("-").isdigit():
                    return f"{field_name} holds a port number, but the detection matches on {text!r}"
                if base in _FILENAME_FIELDS and _SWITCH_RE.search(text):
                    return (
                        f"{field_name} holds a file path, but the detection matches on {text!r}, "
                        "which carries command-line switches; those belong in CommandLine"
                    )
                if base not in ["hashes", "md5", "sha1", "sha256", "imphash"]:
                    cleaned = text.strip().lower()
                    if len(cleaned) in (32, 40, 64) and _HEX_RE.match(cleaned):
                        if not ("=" in cleaned or "-" in cleaned):
                            return f"{field_name} is not a hash field, but the detection matches on a {len(cleaned)}-character hex string {cleaned!r} (a file hash)"
    return None


def _partial_indicator_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]], category: str) -> Optional[str]:
    """Reject a rule that reproduces a supplied indicator only in part.

    Targets fragmentation, not absence. A behavioural rule that uses no
    indicator at all is legitimate and often worth more than one matching a
    single hash -- the prompt asks for exactly that where generalising is
    right, and an earlier version of this check that demanded an indicator
    rejected every rule on three consecutive live cycles, leaving drafts with
    no detection section at all.

    What is actually wrong is a *fragment*. The drafted DNS rule turned the
    supplied `domainlify.net` into `QueryName|endswith: .net` plus
    `QueryName|contains: domainlify`. That matches every .net domain, silently
    widens the rule far past its evidence, and leaves no complete indicator for
    the grounding audit to find, so the hunt was graded as carrying no CTI
    evidence at all.

    Only indicator types this log source can match are considered, via the same
    map that chose the log source. A value that is itself a complete supplied
    indicator always passes, including a hostname that also appears inside a
    supplied URL.
    """
    matchable: List[str] = []
    for indicator_type, values in (supplied or {}).items():
        categories = _INDICATOR_LOGSOURCES.get(str(indicator_type).lower().strip(), set())
        if category in categories:
            matchable.extend(str(v).strip().lower() for v in values if str(v).strip())

    if not matchable:
        return None
    complete = set(matchable)

    from urllib.parse import urlsplit

    for item in list(matchable):
        if "://" in item:
            try:
                parsed = urlsplit(item)
                if parsed.hostname:
                    complete.add(parsed.hostname.lower())
                if parsed.port:
                    complete.add(str(parsed.port))
                if parsed.path and len(parsed.path) >= 4:
                    complete.add(parsed.path.lower())
                    complete.add(parsed.path.lstrip("/").lower())
            except Exception:
                pass

    for value in _detection_values(detection):
        cleaned = value.strip()
        lowered = cleaned.lower()
        # Short values are ordinary rule vocabulary ("exe", "tmp") and collide
        # with indicator substrings by accident.
        if len(lowered) < 4 or lowered in complete:
            continue
        # Port numbers in network connections are not indicator fragments.
        if category == "network_connection" and cleaned.isdigit() and len(cleaned) <= 5:
            continue
        for indicator in matchable:
            if lowered != indicator and lowered in indicator:
                return (
                    f"detection matches on {cleaned!r}, a fragment of the supplied "
                    f"indicator {indicator!r}; match the indicator in full or "
                    f"describe the behaviour instead"
                )
    return None


def _self_defeating_filter_problem(detection: Dict[str, Any], hypothesis: str) -> Optional[str]:
    """Reject an exclusion that removes the hunt's own stated attack path.

    Also rejects an empty filter block: `filter: {}` referenced by a condition
    is a no-op that reads as a deliberate exclusion to whoever reviews it.
    """
    lowered_hypothesis = (hypothesis or "").lower()

    for key, block in detection.items():
        if key == "condition" or not key.lower().startswith("filter"):
            continue
        if not any(term in lowered_hypothesis for term in _BROWSER_DELIVERY_TERMS):
            continue
        for value in _detection_values({key: block}):
            lowered = value.lower()
            for browser in _BROWSER_PARENTS:
                if browser in lowered:
                    return (
                        f"{key!r} excludes {value!r}, but the hypothesis describes "
                        "browser-borne delivery -- this filters out the rule's own "
                        "primary scenario"
                    )
    return None


#: Fields recording whether a binary's signature is trusted, and the values
#: that mean it is not. Excluding those values keeps only trusted activity.
_SIGNATURE_FIELDS = frozenset({"signed", "signaturestatus", "signature_status", "signaturevalid"})
_UNTRUSTED_SIGNATURE_VALUES = frozenset({"false", "0", "unsigned", "invalid", "expired", "revoked", "untrusted"})


def _excluded_threat_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]]) -> Optional[str]:
    """Reject a rule whose exclusion removes the very thing it hunts.

    Two shapes, both from the 26 Sep reruns and both valid Sigma:

    - An exclusion of the untrusted case. H-0013's rule was ``ImageLoaded|endswith:
      \\mscoree.dll`` and ``not`` ``Signed: false`` -- so it matched only signed
      loads of mscoree.dll, the legitimate ones, and never the malicious DLL.
    - An exclusion of the intel's own indicators. H-0012's filter dropped any
      event whose ``OriginalFileName`` matched the pulse's two delivery domains.
    """
    negated = _negated_blocks(detection, str(detection.get("condition", "")))
    indicators = [str(v).strip().lower() for values in supplied.values() for v in values]
    indicators = [i for i in indicators if len(i) >= 6]
    for key in sorted(negated):
        block = detection.get(key)
        if not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            if str(field_name).split("|")[0].strip().lower() not in _SIGNATURE_FIELDS:
                continue
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                if str(value).strip().lower() in _UNTRUSTED_SIGNATURE_VALUES:
                    return (
                        f"the condition excludes {key!r} ({field_name}: {value}), so the rule "
                        "matches only trusted binaries and never the untrusted one it hunts"
                    )
        for value in _detection_values({key: block}):
            lowered = value.lower()
            for indicator in indicators:
                if indicator in lowered or indicator.replace(".", "\\.") in lowered:
                    return (
                        f"the condition excludes {key!r}, which matches the supplied indicator "
                        f"{indicator!r}; the rule would ignore the intel's own evidence"
                    )
    return None


#: A match value that is nothing but a file extension, after wildcards.
_EXTENSION_ONLY_RE = re.compile(r"^\.?[a-z0-9]{1,5}$")


def _nonspecific(value: str) -> bool:
    """A match value that names no particular thing: a bare extension, wildcard or switch.

    A lone switch is H-0010's ``CommandLine|contains: -enc``, which matches
    every process on the host that takes an ``-enc*`` argument. Paired with
    an image (``powershell.exe``) it is a real rule, and passes.
    """
    stripped = value.strip().strip("*").strip()
    if not stripped or set(stripped) <= set("\\/.:*"):
        return True
    if _SWITCH_RE.fullmatch(stripped):
        return True
    return bool(_EXTENSION_ONLY_RE.match(stripped.lower())) and (stripped.startswith(".") or value.strip().startswith("*"))


def _negated_blocks(detection: Dict[str, Any], condition: str) -> Set[str]:
    """Names of detection blocks the condition excludes with `not`."""
    negated: Set[str] = set()
    for match in re.finditer(r"\bnot\s+(?:(?:1|all)\s+of\s+)?([\w*]+)", condition):
        pattern = re.compile("^" + re.escape(match.group(1)).replace("\\*", ".*") + "$")
        negated.update(key for key in detection if key != "condition" and pattern.match(key))
    return negated


#: A complete dotted-quad IPv4 address, optionally with a port, and nothing else.
_FULL_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")


def _invented_ip_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]], observables: List[str]) -> Optional[str]:
    """Reject a selection matching an exact IPv4 address no intel supplied.

    An address is an indicator: it can only have come from the intelligence.
    The model invents well-formed ones -- "1.2.3.4" reached a live phishing
    hunt, "8.8.8.8" a DNS-exfiltration one -- and they pass every other check,
    because nothing about them is malformed. So an exact address must be a
    supplied indicator or appear in an observable the draft named.

    Only selections are judged. An exclusion such as ``not 127.0.0.1`` is
    ordinary rule-writing, and partial prefixes or CIDR ranges describe
    behaviour rather than claim an indicator.
    """
    known = " ".join([str(v) for values in (supplied or {}).values() for v in values] + list(observables or []))
    negated = _negated_blocks(detection, str(detection.get("condition", "")))
    for name, block in detection.items():
        if name == "condition" or name in negated:
            continue
        for value in _detection_values({name: block}):
            cleaned = value.strip()
            if not _FULL_IPV4_RE.match(cleaned):
                continue
            address = cleaned.split(":", 1)[0]
            if re.search(r"(?<![\d.])" + re.escape(address) + r"(?![\d])", known):
                continue
            return (
                f"detection matches the address {address!r}, which no supplied indicator "
                "or observable names; an invented IP matches nothing the intel describes"
            )
    return None


#: Fields whose value is a host name. Judged by field, not by value shape:
#: "update.bin" and "svchost.exe" look like domains and are filenames.
_HOST_FIELDS = frozenset(
    {
        "queryname",
        "destinationhostname",
        "sourcehostname",
        "hostname",
        "targethostname",
        "dnsquery",
        "cs-host",
        "r-dns",
    }
)
#: Fields whose value is a URL; the host part is judged.
_URL_FIELDS = frozenset({"url", "uri", "c-uri", "cs-uri", "requesturl", "request_url"})

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_URL_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?([^/:?#\s]+)", re.IGNORECASE)
_SECOND_LEVEL_SUFFIXES = frozenset({"co", "com", "net", "org", "gov", "ac", "edu"})


def _registered_name(domain: str) -> str:
    """``telegram`` for ``api.telegram.org``; ``example`` for ``www.example.co.uk``."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL_SUFFIXES and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else ""


def _invented_hash_problem(detection: dict, supplied: dict) -> str | None:
    """Reject a selection matching a specific file hash no intel supplied."""
    import re

    known = " ".join(
        " ".join(map(str, v)).lower()
        for k, v in supplied.items()
        if "hash" in k.lower() or k.lower() in ("md5", "sha1", "sha256", "imphash")
    )
    for value in _detection_values(detection):
        cleaned = value.strip().lower()
        if len(cleaned) in (32, 40, 64) and re.match(r"^[0-9a-f]+$", cleaned):
            if cleaned not in known:
                return f"detection matches the hash {cleaned!r}, which no supplied indicator names; an invented hash matches nothing the intel describes"
    return None


def _invented_domain_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]], context: List[str]) -> Optional[str]:
    """Reject a selection matching a domain the intelligence never names.

    The domain counterpart of ``_invented_ip_problem``. A host is accepted
    when the whole name appears in a supplied indicator or the draft's own
    text, or when its registered name does ("telegram" vouches for
    api.telegram.org in a hunt about a Telegram-controlled backdoor): abusing
    a real service is behaviour worth hunting, not an invented indicator.
    What fails is a name nothing mentions -- "malicious-c2.net".

    Only host and URL fields of selections are judged, so filenames that look
    like domains, exclusion filters, and bare TLD fragments (".xyz", left to
    the partial-indicator check) all pass.
    """
    known = " ".join(
        [str(v) for values in (supplied or {}).values() for v in values] + [str(c) for c in (context or []) if c]
    ).lower()
    negated = _negated_blocks(detection, str(detection.get("condition", "")))
    for name, block in detection.items():
        if name == "condition" or name in negated or not isinstance(block, dict):
            continue
        for field_name, raw in block.items():
            base = str(field_name).split("|")[0].strip().lower()
            if base not in _HOST_FIELDS and base not in _URL_FIELDS:
                continue
            for value in raw if isinstance(raw, list) else [raw]:
                text = str(value).strip().lower()
                if base in _URL_FIELDS:
                    match = _URL_HOST_RE.match(text)
                    text = match.group(1) if match else ""
                host = text.lstrip("*").lstrip(".")
                if not _DOMAIN_RE.match(host):
                    continue
                if re.search(r"(?<![a-z0-9-])" + re.escape(host) + r"(?![a-z0-9-])", known):
                    continue
                registered = _registered_name(host)
                if len(registered) >= 3 and re.search(r"(?<![a-z0-9])" + re.escape(registered) + r"(?![a-z0-9])", known):
                    continue
                return (
                    f"detection matches the host {host!r}, which no supplied indicator or "
                    "part of the draft names; an invented domain matches nothing the intel describes"
                )
    return None


def _breadth_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a rule whose selections match only extensions or wildcards.

    Observed on H-0002: `Image|endswith: .exe` minus one filter matched every
    process on the host. Structurally valid, so nothing else stopped it, and it
    reached review looking like a real rule. A count threshold in the condition
    makes volume the signal, so aggregated rules are left alone.

    A block is an exclusion only if the condition negates it. The model
    regularly names a second positive block "filter" ("selection and filter",
    seen on H-0002's regeneration), and that block narrows the rule.

    Judged across all selections together: one specific value anywhere is
    enough. That misses a broad selection OR-ed with a specific one, which is
    the price of not parsing conditions.
    """
    condition = str(detection.get("condition", ""))
    if "|" in condition:
        return None
    negated = _negated_blocks(detection, condition)
    values = [
        value
        for key, block in detection.items()
        if key != "condition" and key not in negated
        for value in _detection_values({key: block})
    ]
    if values and all(_nonspecific(v) for v in values):
        shown = ", ".join(sorted({v.strip() for v in values}))
        return f"selections match only {shown!r}, which names no particular file, process or host"
    return None


_FLAT_OR_RE = re.compile(
    r"^\s*(?:(?:1|any) of (?P<glob>[\w*]+)|(?P<names>\w+(?:\s+or\s+\w+)+))(?:\s+and\s+not\s+(?P<filter>\w+))?\s*$"
)


def _or_branch_breadth_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a flat OR with one branch that matches almost anything.

    `_breadth_problem` judges all selections together, so ``selection_ioc or
    selection_any_exe`` passed on the IOC branch while the other matched every
    ``.exe``. In an OR each branch fires alone, so each must be specific alone.
    Only flat conditions are parsed ("a or b", "1 of selection*", optionally
    "and not filter"); anything nested is left to the reviewer.
    """
    match = _FLAT_OR_RE.match(str(detection.get("condition", "")))
    if not match:
        return None
    names = [k for k in detection if k != "condition"]
    if match.group("glob"):
        pattern = re.compile("^" + re.escape(match.group("glob")).replace("\\*", ".*") + "$")
        branches = [n for n in names if pattern.match(str(n))]
    else:
        wanted = re.split(r"\s+or\s+", match.group("names"))
        branches = [n for n in names if str(n) in wanted]
    for name in branches:
        values = _detection_values({name: detection[name]})
        if values and all(_nonspecific(v) for v in values):
            shown = ", ".join(sorted({v.strip() for v in values}))
            return f"OR-ed selection {name!r} matches only {shown!r} and fires on its own for any such event"
    return None


def _hash_role_problem(detection: Dict[str, Any], records: List[Dict[str, Any]], category: str) -> Optional[str]:
    """A published hash matched in an event where a file of that role never appears.

    H-0618's image_load rule matched the Go loader's hash; the source types it
    as an executable, which runs as a process and is never loaded as a module.
    Same placements as the deterministic IOC rules.
    """
    from hecate_agent.core.provenance import HASH_TYPES, IndicatorRecord, placements

    typed = [IndicatorRecord.from_dict(r) for r in records]
    typed = [r for r in typed if r.type in HASH_TYPES and r.role != "unknown"]
    if not typed:
        return None
    for _, block in _blocks_of(detection):
        for key, raw in block.items():
            if str(key).split("|")[0].strip().lower() != "hashes":
                continue
            for value in raw if isinstance(raw, list) else [raw]:
                lowered = str(value).lower()
                for record in typed:
                    if record.value.lower() in lowered and f"{category}.Hashes" not in placements(record):
                        where = ", ".join(placements(record)) or "no event this rule can see"
                        return (
                            f"Hashes matches {record.value[:16]}…, which the source identifies as {record.role}; "
                            f"a {record.role} is never seen in {category}. It belongs in {where}"
                        )
    return None


def _reversed_guidance_chain_problem(detection: Dict[str, Any], guidance: List[Dict[str, Any]]) -> Optional[str]:
    """A model rule whose parent/child pair reverses a chain the source's guidance gives.

    The source said resume executable -> cmd.exe -> Word; replay after replay
    the model wrote Word -> cmd.exe, even with the guidance in its prompt.
    """
    parents = [str(v).lower() for b in _blocks_of(detection) for k, raw in b[1].items()
               if str(k).split("|")[0].lower() == "parentimage" for v in (raw if isinstance(raw, list) else [raw])]  # fmt: skip
    images = [str(v).lower() for b in _blocks_of(detection) for k, raw in b[1].items()
              if str(k).split("|")[0].lower() == "image" for v in (raw if isinstance(raw, list) else [raw])]  # fmt: skip
    if not parents or not images:
        return None
    for item in guidance:
        for candidate in item.get("candidates") or []:
            selection = (candidate.get("detection") or {}).get("selection") or {}
            parent, child = selection.get("ParentImage|endswith"), selection.get("Image|endswith")
            if not parent or not child:
                continue
            parent, child = str(parent).lower(), str(child).lower()
            if any(p.endswith(child) for p in parents) and any(i.endswith(parent) for i in images):
                return (
                    f"the rule has {child.lstrip(chr(92))} starting {parent.lstrip(chr(92))}, but the source's guidance "
                    f'says the reverse: "{item.get("text", "")}"'
                )
    return None


def _literal_problem(detection: Dict[str, Any], literals: List[Dict[str, Any]]) -> Optional[str]:
    """Pass two may match only pass one's values in file, process, command-line and registry fields."""
    from hecate_agent.core.query_literals import ungrounded_value

    value = ungrounded_value(detection, literals)
    if not value:
        return None
    return (
        f"{value!r} is not a value the source gives; in file, process, command-line and registry fields use only "
        "the EXACT VALUES FROM THE SOURCE listed (whole, or a part of one) and standard system binaries"
    )


def rule_provenance(detection: Dict[str, Any], input_data: "SigmaGenerationInput") -> List[Dict[str, Any]]:
    """Where each published indicator a rule matches came from.

    A rule file travels without its hunt: exported to a SIEM, the Go loader's
    hash in it no longer says it is the loader, from which report, with what
    confidence. Each indicator a rule matches is listed with its role, status,
    confidence, source and the verbatim passage that typed it; a feed value
    the primary source never described is marked as coming from the feed.
    """
    from hecate_agent.core.provenance import IndicatorRecord, url_parts

    values = [str(v).lower() for v in _detection_values(detection)]
    if not values:
        return []

    def matched(value: str, kind: str) -> bool:
        needles = [value.lower()]
        if kind == "url":
            # By path: the host is the address record's, and matching it would
            # attach every staging URL to the network rule as well.
            host, _port, path = url_parts(value)
            needles = [path.lower()] if path and path != "/" else [host.lower()]
        return any(n and any(n in v for v in values) for n in needles)

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for record in (IndicatorRecord.from_dict(r) for r in input_data.indicator_records):
        if record.value.lower() in seen or not matched(record.value, record.type):
            continue
        seen.add(record.value.lower())
        entry: Dict[str, Any] = {
            "value": record.value,
            "type": record.type,
            "role": record.role,
            "status": record.status,
            "confidence": record.confidence,
            "source": record.source,
        }
        if record.evidence:
            entry["evidence"] = " ".join(record.evidence.split())[:200]
        out.append(entry)
    for kind, feed_values in input_data.indicators.items():
        for value in feed_values:
            if str(value).lower() in seen or not matched(str(value), kind):
                continue
            seen.add(str(value).lower())
            out.append({"value": str(value), "type": kind, "role": "unknown", "status": "unknown", "source": "cti feed"})
    return out


def _blocks_of(detection: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    for name, block in detection.items():
        if name == "condition":
            continue
        for item in block if isinstance(block, list) else [block]:
            if isinstance(item, dict):
                out.append((str(name), item))
    return out


def _placeholder_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]]) -> Optional[str]:
    """Reject a rule whose detection matches on scaffolding.

    Such a rule is valid Sigma and passes every structural check, so nothing
    else stops it: it reaches the operator looking exactly like a real rule
    and matches nothing. That costs review time on a hunt whose whole point
    is to be reviewed.

    Values the source CTI actually supplied are never rejected. If the
    intelligence really names "malicious-update.example.com", that is an
    observable, and the guard must not second-guess the evidence.
    """
    from_cti = {str(v).lower() for values in supplied.values() for v in values}

    for value in _detection_values(detection):
        cleaned = value.strip()
        if not cleaned:
            return "detection matches on an empty value"
        lowered = cleaned.lower()
        if any(lowered == indicator or lowered in indicator for indicator in from_cti):
            continue
        if lowered in _PLACEHOLDER_EXACT:
            return f"detection matches on the placeholder {cleaned!r}"
        for fragment in _PLACEHOLDER_SUBSTRINGS:
            if fragment in lowered:
                return f"detection matches on {cleaned!r}, which contains the placeholder {fragment!r}"
        if _impossible_ipv4(cleaned):
            return f"detection matches on {cleaned!r}, which is not a valid IPv4 address"
        if _documentation_address(cleaned):
            return f"detection matches on {cleaned!r}, a range reserved for documentation examples"
        if _SNAKE_PLACEHOLDER_RE.match(cleaned):
            return f"detection matches on {cleaned!r}, which describes a value rather than being one"
        if _PLACEHOLDER_FILE_RE.search(cleaned):
            return f"detection matches on {cleaned!r}, a stand-in file name rather than one the intel names"
    return None


_MODIFIER_IN_VALUE_RE = re.compile(
    r"^\s*\|\s*(?:contains|startswith|endswith|re|all|cidr|base64|base64offset|windash|wide|utf16le|exists)\b",
    re.IGNORECASE,
)


def _modifier_in_value_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a selection whose modifier was written into the value.

    Observed on H-0012: ``CommandLine: "|contains: '0928d3...'"``. Valid YAML
    and valid Sigma, so pySigma accepts it, but it is an exact match on a
    string that begins with a pipe, and it matches nothing anywhere.
    """
    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                if isinstance(value, str) and _MODIFIER_IN_VALUE_RE.match(value):
                    return (
                        f"{field_name} carries its modifier inside the value ({value.strip()!r}); "
                        f"a modifier belongs on the field name, as in {field_name}|contains"
                    )
    return None


_SCALAR_EVENT_FIELDS = frozenset(
    {
        "destinationip",
        "sourceip",
        "ipaddress",
        "destinationhostname",
        "sourcehostname",
        "destinationport",
        "sourceport",
        "image",
        "parentimage",
        "originalfilename",
        "targetfilename",
        "user",
        "username",
        "computername",
    }
)


def _impossible_modifier_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject rules where |all modifier creates a mathematically impossible condition.

    Observed on LLM-generated rules: ``DestinationIp|all: [IP1, IP2]`` or
    ``DestinationHostname|all: [H1, H2]``. A single event cannot equal multiple
    distinct scalar values simultaneously.
    """
    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            parts = [p.strip().lower() for p in str(field_name).split("|")]
            base = parts[0]
            modifiers = set(parts[1:])
            if "all" in modifiers:
                has_substring = any(m in ("contains", "startswith", "endswith", "re") for m in modifiers)
                values = raw_value if isinstance(raw_value, list) else [raw_value]
                distinct = set(str(v).strip() for v in values if str(v).strip())
                if base in _SCALAR_EVENT_FIELDS and not has_substring:
                    return (
                        f"{field_name} uses '|all' for exact matching on scalar field {base!r}; "
                        "a single event cannot have multiple exact values simultaneously. "
                        "Use standard list OR matching without '|all'."
                    )
                if base in ("destinationip", "sourceip", "destinationport", "sourceport", "ipaddress") and len(distinct) > 1:
                    return (
                        f"{field_name} matches multiple distinct values with '|all' on {base!r}; "
                        "a single network event cannot match multiple addresses/ports simultaneously."
                    )
    return None


#: Fields that name the executable a process was started from.
_PROCESS_IMAGE_FIELDS = frozenset({"image", "parentimage", "originalfilename"})
_LIBRARY_SUFFIXES = (".dll", ".sys", ".ocx", ".drv")
#: A script's process is its interpreter: `powershell.exe` for a .ps1,
#: `wscript.exe` for a .vbs, `mshta.exe` for a .hta, `/bin/sh` for a .sh.
#: H-0018's rerun kept ``Image|endswith: .ps1`` under ``ParentImage: teams.exe``.
_SCRIPT_SUFFIXES = (".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".sh", ".py")


def _library_as_process_problem(detection: Dict[str, Any], category: str) -> Optional[str]:
    """Reject a process_creation rule whose process image is a library or script.

    Observed on H-0013: ``Image|endswith: mscoree.dll`` for a DLL-hijacking
    hunt. A DLL or driver is never the image of a process, so the rule matched
    nothing while reading as the hunt's one detection. The load is visible in
    image_load, as ``ImageLoaded``.
    """
    if category != "process_creation":
        return None
    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            if str(field_name).split("|")[0].strip().lower() not in _PROCESS_IMAGE_FIELDS:
                continue
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                lowered = str(value).strip().lower()
                if lowered.endswith(_LIBRARY_SUFFIXES):
                    return (
                        f"{field_name} matches {str(value).strip()!r}, but a library or driver is never "
                        "a process image; a load belongs in image_load as ImageLoaded"
                    )
                if lowered.endswith(_SCRIPT_SUFFIXES):
                    return (
                        f"{field_name} matches {str(value).strip()!r}, but a script is never a process image; "
                        "match its interpreter in Image and the script in CommandLine"
                    )
    return None


def _network_selections(records: List[Any]) -> Dict[str, Any]:
    """One selection per address or host and port, so each channel stays distinguishable.

    H-0618's host served HTTP staging on 50813 and a raw-TCP channel on 50812;
    an address with no port the source names gets one port-free selection.
    """
    selections: Dict[str, Any] = {}
    for index, record in enumerate(records, start=1):
        field_name = "DestinationIp" if record.type in ("ipv4", "ipv6") else "DestinationHostname"
        ports: List[Optional[int]] = list(record.ports) or [None]
        for port in ports:
            block: Dict[str, Any] = {field_name: record.value}
            if port is not None:
                block["DestinationPort"] = port
            selections[f"selection_{index}_{port or 'any'}"] = block
    return selections


def _platform_legit_filters(platforms: Optional[List[str]]) -> List[str]:
    """Return platform-appropriate legitimate binaries to filter for dual-use network rules."""
    plats = [str(p).lower() for p in (platforms or [])]
    is_win = not plats or any("win" in p for p in plats)
    is_linux = any("linux" in p for p in plats)
    is_mac = any("mac" in p or "darwin" in p for p in plats)

    filters: List[str] = []
    if is_win:
        filters.extend(
            [
                "\\chrome.exe",
                "\\msedge.exe",
                "\\firefox.exe",
                "\\brave.exe",
                "\\AWSCLIV2.exe",
                "\\amazon-ssm-agent.exe",
            ]
        )
    if is_linux:
        filters.extend(
            [
                "/chrome",
                "/google-chrome",
                "/firefox",
                "/brave",
                "/aws",
                "/amazon-ssm-agent",
            ]
        )
    if is_mac:
        filters.extend(
            [
                "/Google Chrome",
                "/Microsoft Edge",
                "/Firefox",
                "/Brave Browser",
                "/aws",
            ]
        )
    return filters or [
        "\\chrome.exe",
        "\\msedge.exe",
        "\\firefox.exe",
        "\\brave.exe",
        "\\AWSCLIV2.exe",
        "\\amazon-ssm-agent.exe",
    ]


class SigmaGeneratorAgent(LLMAgent[SigmaGenerationInput, SigmaGenerationOutput]):
    """Drafts Sigma rules covering each log source a hunt applies to."""

    def execute(self, input_data: SigmaGenerationInput) -> AgentResult[SigmaGenerationOutput]:
        start = time.monotonic()
        self._reset_llm_usage()
        platforms = list(input_data.platforms)
        from hecate_agent.core.command_rules import LINUX_MARKERS

        if LINUX_MARKERS.search(input_data.threat_intel or "") and "linux" not in [p.lower() for p in platforms]:
            platforms.append("linux")

        logsources = input_data.logsources or applicable_logsources(
            input_data.techniques,
            list(input_data.indicators.keys()),
        )
        logsources = _platform_consistent_logsources(logsources, platforms)

        if not self.llm_enabled:
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(logsources_considered=logsources),
                error="Sigma generation requires an LLM; no provider is configured.",
                warnings=[],
                metadata={
                    "duration_ms": int((time.monotonic() - start) * 1000),
                    **self._llm_usage_metadata(),
                },
            )

        rules: List[SigmaRule] = []
        rejected: List[str] = []
        warnings: List[str] = []

        # One call per log source rather than one call for all of them. The
        # combined prompt asked for six rules in a single response, which on a
        # 4096-token context is close enough to the ceiling that a truncated
        # reply loses every rule at once -- the first live run produced six
        # rules of which none survived validation. Per-source, each response is
        # short, a failure costs one rule instead of all six, and the field
        # guidance can be narrowed to the category actually being written.
        from concurrent.futures import ThreadPoolExecutor

        omitted: List[str] = []

        with ThreadPoolExecutor(max_workers=min(len(logsources) or 1, 6)) as executor:
            futures = {
                executor.submit(self._generate_for_logsource, input_data, logsource): logsource for logsource in logsources
            }
            for future in futures:
                source_name = futures[future]
                rule, rule_problems, rule_omitted = future.result()
                rejected.extend(rule_problems)
                omitted.extend(rule_omitted)
                if rule is not None:
                    rules.append(rule)
                elif rule_problems:
                    warnings.append(f"rejected rule: {source_name}: {'; '.join(rule_problems)}")

        # Built from the indicators alone, with no model call. On the first
        # live cycle with the fixed pipeline, a pulse carrying ten file hashes
        # produced no rule that used any of them: the model's file_event rule
        # matched only '.ps1' and was rejected, and its process rule was
        # behavioural. Exact hashes are the one thing a rule can be written
        # from without judgement, so they no longer depend on the model.
        # The same now holds for domains and addresses: both DNS rules in the
        # 25 Sep review were rejected (the model matched '.com' and '.xyz'),
        # leaving hunts with supplied C2 domains no DNS coverage at all.
        for ioc_rule, ioc_problem in [
            *self._written_file_rules(input_data),
            *self._command_rules(input_data),
            *self._guidance_rules(input_data),
            *self._ioc_rules(input_data),
            *self._cloud_control_plane_rules(input_data),
        ]:
            if ioc_rule is not None:
                rules.append(ioc_rule)
            elif ioc_problem:
                rejected.append(ioc_problem)

        review_gaps: List[Dict[str, str]] = []
        if input_data.review_rules and rules:
            rules, review_rejected, review_gaps, review_warnings = self._review_rules(rules, input_data)
            rejected.extend(review_rejected)
            warnings.extend(review_warnings)

        if not rules:
            all_reasons = rejected or omitted or ["no log source produced a valid rule"]
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(
                    logsources_considered=logsources,
                    rejected=rejected or omitted,
                    omitted=omitted,
                ),
                error="no log source produced a valid rule: " + "; ".join(all_reasons),
                warnings=warnings,
                metadata={
                    "duration_ms": int((time.monotonic() - start) * 1000),
                    **self._llm_usage_metadata(),
                },
            )

        warnings.extend(f"rejected rule: {r}" for r in rejected if not any(w.endswith(r) for w in warnings))
        provider = self._get_provider()
        return AgentResult(
            success=True,
            data=SigmaGenerationOutput(
                rules=rules, logsources_considered=logsources, rejected=rejected, omitted=omitted, review_gaps=review_gaps
            ),
            error=None,
            warnings=warnings,
            metadata={
                "llm_provider": provider.provider_name,
                "llm_model": getattr(provider, "model", getattr(provider, "model_id", "unknown")),
                "duration_ms": int((time.monotonic() - start) * 1000),
                **self._llm_usage_metadata(),
            },
        )

    @staticmethod
    def _source_passages(input_data: SigmaGenerationInput) -> List[str]:
        """The verified source text the reviewer judges against: artifact and indicator evidence, and guidance."""
        passages: List[str] = []
        texts = [
            *(str(a.get("evidence", "")) for a in input_data.source_artifacts),
            *(str(g.get("text", "")) for g in input_data.detection_guidance),
            *(str(r.get("evidence", "")) for r in input_data.indicator_records),
        ]
        if input_data.indicators:
            for kind, vals in input_data.indicators.items():
                if vals:
                    texts.append(f"Indicators ({kind}): {', '.join(str(v) for v in vals)}")
        if input_data.threat_intel:
            from hecate_agent.core.source_evidence import chunk_text

            texts.extend(chunk_text(input_data.threat_intel, size=300, overlap=50))

        for text in texts:
            if not text or text == "cti":
                continue
            text = " ".join(text.split())[:300]
            if len(text) >= 12 and text not in passages:
                passages.append(text)
        return passages[:25]

    def _review_rules(
        self, rules: List[SigmaRule], input_data: SigmaGenerationInput
    ) -> Tuple[List[SigmaRule], List[str], List[Dict[str, str]], List[str]]:
        """A2: review model rules; drop one only for a contradiction quoted verbatim from the source."""
        from hecate_agent.agents.llm.rule_reviewer import RuleReviewer

        reviewer = RuleReviewer(
            lambda prompt, validate: self._call_llm_with_retry(
                prompt, validate, max_retries=1, max_tokens=1024, temperature=0.0
            )
        )
        passages = self._source_passages(input_data)
        kept: List[SigmaRule] = []
        rejected: List[str] = []
        warnings: List[str] = []
        for rule in rules:
            if rule.origin != "model":
                kept.append(rule)
                continue
            try:
                review = reviewer.review(rule.rule_yaml, input_data.hypothesis, passages)
            except Exception as exc:  # noqa: BLE001 - a failed review keeps the rule, unreviewed
                warnings.append(f"rule review failed for {rule.title!r}: {exc}")
                kept.append(rule)
                continue
            if review.verdict == "reject" and review.verified:
                rejected.append(
                    f'{rule.logsource_category}: reviewer: {review.contradiction} (source: "{review.quote[:160]}")'
                )
                continue
            document = yaml.safe_load(rule.rule_yaml)
            note: Dict[str, Any] = {"verdict": review.verdict}
            if review.issues:
                note["issues"] = review.issues
            if review.contradiction:
                note["unverified_contradiction"] = review.contradiction
            document["hecate_review"] = note
            rule.rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)
            kept.append(rule)
        gaps: List[Dict[str, str]] = []
        try:
            gaps = reviewer.gaps(
                [
                    {
                        "title": r.title,
                        "description": str(yaml.safe_load(r.rule_yaml).get("description", "")),
                        "detection": yaml.safe_dump(yaml.safe_load(r.rule_yaml).get("detection") or {}),
                    }
                    for r in kept
                ],
                input_data.hypothesis,
                passages,
            )
        except Exception as exc:  # noqa: BLE001 - coverage is advice, never fatal
            warnings.append(f"coverage review failed: {exc}")
        return kept, rejected, gaps, warnings

    def _command_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """A command the source quotes being run becomes a process rule: the program and its distinctive argument.

        The ClickFix report quoted ``xattr -d com.apple.quarantine`` and
        ``launchctl bootstrap ...``; the model turned them into at most one generic rule.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for candidate in input_data.observed_commands:
            cat = str(candidate.get("category", "process_creation"))
            title = str(candidate.get("title", ""))
            cand_platform = candidate.get("platform")
            if not cand_platform:
                det = candidate.get("detection") or {}
                sel = det.get("selection") or {}
                img = str(sel.get("Image|endswith", ""))
                cmd_str = str(candidate.get("command", ""))
                if img.startswith("/") or any(
                    u in cmd_str or u in img for u in ("nsenter", "bpftool", "bash", "sh", "kprobe")
                ):
                    cand_platform = "linux"
            if not title.startswith(("Command", "File", "Scheduled")):
                title = (
                    f"Command the source shows being run: {title}"
                    if cat == "process_creation"
                    else f"File created by command: {title}"
                )
            preamble = (
                "Deterministic rule built from a command quoted in the primary source, with no model involvement. "
                if cat == "process_creation"
                else "Deterministic rule built for artifact written by a command quoted in the primary source, with no model involvement. "
            )
            results.append(
                self._ioc_rule(
                    input_data,
                    category=cat,
                    label="observed command" if cat == "process_creation" else "written file",
                    title=title[:120],
                    description=f'The source shows this command being run: "{candidate.get("command", "")}".',
                    detection=dict(candidate.get("detection") or {}),
                    falsepositives="Administrators or software running the same command or creating the task for legitimate reasons",
                    preamble=preamble,
                    level=str(candidate.get("level", "medium")),
                    author="hecate (auto-generated from commands quoted in the source - requires analyst review)",
                    behaviour=str(
                        candidate.get("behaviour") or f"{candidate.get('title', '')} {candidate.get('command', '')}"
                    ),
                    rule_platform=cand_platform,
                )
            )
        return results

    def _written_file_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Pass two, mechanically: a file the source says the malware writes becomes a file_event rule.

        The A1 replay's model wrote the decoy rule with pass one's wildcard,
        then dropped its directory and filtered out C:\\Windows\\Temp\\, where the
        decoy is written. Mapping a written path to TargetFilename needs no judgement.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for literal in input_data.query_literals():
            if not literal.get("written") or "file_event.TargetFilename" not in (literal.get("fields") or []):
                continue
            sigma, how = str(literal["sigma"]), str(literal.get("match", "exact"))
            if "/" not in sigma and "\\" not in sigma:
                # A file event records a full path, and a bare name says nothing of where: the
                # Redis botnet replay built rules for SAM.save and fleet.b64, files in the
                # operator's own directory. The name stays a literal the model may use.
                continue
            key = "TargetFilename|endswith" if how == "endswith" else "TargetFilename"
            name = sigma.replace("/", "\\").rsplit("\\", 1)[-1]
            shared = bool(_SHARED_SYSTEM_FILE_RE.search(sigma))
            results.append(
                self._ioc_rule(
                    input_data,
                    category="file_event",
                    label="written file",
                    title=f"File the source says the malware writes: {name}"[:120],
                    description=f"The source reports the malware writing this file ({literal.get('role', '')}): "
                    f'"{literal.get("evidence", "")}".'
                    + (
                        ' The report elided part of the name; "*" stands for the missing characters.'
                        if how == "wildcard"
                        else ""
                    )
                    + (
                        " The operating system and its administrators write this file too, so a match is a lead"
                        " to review, not a detection on its own."
                        if shared
                        else ""
                    ),
                    detection={"selection": {key: sigma}, "condition": "selection"},
                    falsepositives=(
                        "Routine administration: this is a standard system file that legitimate changes also write"
                        if shared
                        else "A legitimate file with the same name and location"
                    ),
                    preamble="Deterministic rule built from a file path verified in the primary source, "
                    "with no model involvement. ",
                    level="low" if shared else "high",
                    author="hecate (auto-generated from verified source artifacts - requires analyst review)",
                    behaviour=sigma,
                )
            )
        return results

    def _guidance_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Rules the source's detection guidance specifies, built without the model.

        H-0618's source said to hunt for resume-themed executables launching
        cmd.exe and then Word, and for %TEMP%\\log_de.log. The model, asked for
        behaviour instead, wrote Word launching cmd.exe. Each rule quotes the
        guidance it implements, and passes the same semantic gate as any other.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for item in input_data.detection_guidance:
            if item.get("route") != "sigma":
                continue
            quoted = str(item.get("text", ""))
            for candidate in item.get("candidates") or []:
                category = str(candidate.get("category", ""))
                if input_data.platforms and "Windows" not in input_data.platforms and "\\" in str(candidate):
                    results.append((None, f"{category} (guidance {item.get('id')}): Windows paths on a non-Windows hunt"))
                    continue
                results.append(
                    self._ioc_rule(
                        input_data,
                        category=category,
                        label=f"guidance {item.get('id')}",
                        title=f"Source guidance {item.get('id')}: {candidate.get('title', '')}"[:120],
                        description=f'The source advises hunting for: "{quoted}". Scope: {candidate.get("note", "")}.',
                        detection=dict(candidate.get("detection") or {}),
                        falsepositives="Legitimate activity that matches the guidance; tune against the environment",
                        preamble="Deterministic rule built from the detection guidance the source published, "
                        "with no model involvement. ",
                        level="medium",
                        behaviour=quoted,
                        author="hecate (auto-generated from source detection guidance - requires analyst review)",
                        references=[str(item.get("source", ""))] if item.get("source") else [],
                    )
                )
        return results

    def _cloud_control_plane_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Deterministic control plane detection rules for cloud/identity intrusions.

        Identifies OAuth application consent abuse, illicit app registrations, and
        AWS STS role assumptions described in the threat intelligence or hypothesis.
        """
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        text = f"{input_data.threat_intel or ''} {input_data.hypothesis or ''} {input_data.justification or ''}"

        # 1. OAuth consent grants & illicit app role assignment (Stage 1 / Entra ID)
        oauth_match = re.search(
            r"(?i)\b(consent|oauth|approleassignment|service\s*principal|app\s*registration|directory\.readwrite\.all|mail\.readwrite)\b",
            text,
        )
        has_oauth_technique = any(t.upper().startswith(("T1550.001", "T1098.003", "T1528")) for t in input_data.techniques)
        if oauth_match or has_oauth_technique:
            detection: Dict[str, Any] = {
                "selection": {
                    "eventName": [
                        "Consent to application",
                        "Add app role assignment to service principal",
                        "Add service principal",
                        "Add service principal credentials",
                    ]
                },
                "condition": "selection",
            }
            perms = []
            for perm in (
                "Directory.ReadWrite.All",
                "Mail.ReadWrite",
                "User.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
            ):
                if perm.lower() in text.lower():
                    perms.append(perm)
            if perms:
                detection["selection"]["permissions|contains"] = perms

            # Extract specific app worker/diagnostics name if mentioned
            app_matches = re.findall(r"\b([A-Za-z0-9_\-\.]+Worker|[A-Za-z0-9_\-\.]+Diagnostics[A-Za-z0-9_\-\.]*)\b", text)
            if app_matches:
                detection["selection"]["appDisplayName|contains"] = list(dict.fromkeys(app_matches[:3]))

            results.append(
                self._ioc_rule(
                    input_data,
                    category="identity_audit",
                    label="cloud identity OAuth consent abuse",
                    title="Suspicious OAuth application consent grant or app role assignment",
                    description=(
                        "Detects application consent grants or high-privilege service principal role assignments "
                        "commonly abused during initial access and persistence in cloud identity tenants."
                    ),
                    detection=detection,
                    falsepositives="Legitimate tenant administrator consenting to enterprise applications or configuring service principals",
                    preamble="Deterministic cloud identity rule built for control-plane tradecraft, with no model involvement. ",
                    level="high",
                    behaviour="OAuth consent grant and service principal role assignment",
                    techniques=["T1550.001", "T1098.003"],
                )
            )

        # 2. AWS STS AssumeRole / cloud privilege escalation
        sts_match = re.search(
            r"(?i)\b(assumerole|sts:assumerole|assumerolewithsaml|assumerolewithwebidentity|aws\s+sts)\b", text
        )
        has_sts_technique = (
            any(t.upper().startswith(("T1078.004", "T1550")) for t in input_data.techniques) and "aws" in text.lower()
        )
        if sts_match or has_sts_technique:
            detection_sts: Dict[str, Any] = {
                "selection": {
                    "eventSource": "sts.amazonaws.com",
                    "eventName": [
                        "AssumeRole",
                        "AssumeRoleWithSAML",
                        "AssumeRoleWithWebIdentity",
                    ],
                },
                "condition": "selection",
            }
            results.append(
                self._ioc_rule(
                    input_data,
                    category="cloud_audit",
                    label="cloud audit AWS STS AssumeRole",
                    title="Suspicious AWS STS AssumeRole or cross-account role assumption",
                    description=(
                        "Detects AWS Security Token Service (STS) AssumeRole API calls indicative of cross-account "
                        "access or temporary credential acquisition by an adversary."
                    ),
                    detection=detection_sts,
                    falsepositives="Legitimate cross-account administration, CI/CD pipelines, or federated IAM access",
                    preamble="Deterministic cloud audit rule built for control-plane tradecraft, with no model involvement. ",
                    level="medium",
                    behaviour="AWS STS AssumeRole credential acquisition",
                    techniques=["T1078.004", "T1550"],
                )
            )

        return results

    def _ioc_rules(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """Rules built from the supplied indicators alone, with no model call.

        Typed indicator records, when supplied, decide the placements; see
        :meth:`_ioc_rules_from_records`. Without them every indicator is
        placed as before.

        One per kind the intel carries: file hashes (process_creation, via
        Sysmon's ``Hashes`` field and SigmaHQ's ``ALGO=value`` convention),
        domains and hosts (dns_query), and addresses (network_connection).
        """
        if input_data.indicator_records:
            return self._ioc_rules_from_records(input_data)
        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        hashes = hash_selectors(input_data.indicators)
        if hashes:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="process_creation",
                    label="hash IOC",
                    title="Execution of a file hash named in the source intelligence",
                    description="Matches a process whose image hash is one the source published.",
                    detection={"selection": {"Hashes|contains": hashes}, "condition": "selection"},
                    falsepositives="None expected for exact hashes; confirm the sensor records the listed algorithms",
                )
            )
        addresses, names, suffixes = network_selectors(input_data.indicators)
        from hecate_agent.core.provenance import is_dual_use

        direct_addresses = [a for a in addresses if not is_dual_use(a)]
        dual_addresses = [a for a in addresses if is_dual_use(a)]
        direct_names = [n for n in names if not is_dual_use(n)]
        dual_names = [n for n in names if is_dual_use(n)]
        direct_suffixes = [s for s in suffixes if not is_dual_use(s.lstrip("."))]
        dual_suffixes = [s for s in suffixes if is_dual_use(s.lstrip("."))]

        if direct_names:
            detection: Dict[str, Any] = {"selection_exact": {"QueryName": direct_names}}
            if direct_suffixes:
                detection["selection_subdomain"] = {"QueryName|endswith": direct_suffixes}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="dns_query",
                    label="domain IOC",
                    title="DNS lookup of a domain named in the source intelligence",
                    # Subdomains only when a suffix selection exists: hostnames stay exact.
                    description="Matches a DNS query for a domain or host the source published"
                    + (", or a subdomain of a published domain." if direct_suffixes else "."),
                    detection=detection,
                    falsepositives="Security tooling or analysts resolving the indicators themselves",
                )
            )
        if direct_addresses or direct_names:
            detection = {}
            if direct_addresses:
                detection["selection_address"] = {"DestinationIp": direct_addresses}
            if direct_names:
                detection["selection_host"] = {"DestinationHostname": direct_names}
            if direct_suffixes:
                detection["selection_subdomain"] = {"DestinationHostname|endswith": direct_suffixes}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="network IOC",
                    title="Connection to an address or host named in the source intelligence",
                    description=(
                        "Matches an outbound connection to an address the source published, "
                        "or to a host whose name it published."
                    ),
                    detection=detection,
                    falsepositives="Shared hosting or CDN addresses reused by unrelated sites",
                )
            )
        if dual_addresses or dual_names:
            candidate_procs = self._find_initiating_processes(input_data)
            dual_detection: Dict[str, Any] = {}
            if dual_addresses:
                dual_detection["selection_dest_ip"] = {"DestinationIp": dual_addresses}
            if dual_names:
                dual_detection["selection_dest_host"] = {"DestinationHostname": dual_names}
            if dual_suffixes:
                dual_detection["selection_dest_subdomain"] = {"DestinationHostname|endswith": dual_suffixes}
            if candidate_procs:
                dual_detection["selection_process"] = {"Image|endswith": candidate_procs}
                dual_detection["condition"] = "(1 of selection_dest_*) and selection_process"
            else:
                dual_detection["filter_legit"] = {"Image|endswith": _platform_legit_filters(input_data.platforms)}
                dual_detection["condition"] = "(1 of selection_dest_*) and not filter_legit"
            techs = [
                t
                for t in ("T1567.002", "T1567", "T1071.001", "T1071")
                if any(t.lower() == it.lower() for it in input_data.techniques)
            ]
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="dual-use network IOC",
                    title="Outbound Connection to Dual-Use Cloud Endpoint by Observed Staging/Exfiltration Process",
                    description=(
                        "Matches an outbound network connection to a dual-use cloud storage or SaaS endpoint "
                        "published in intelligence, bound to the observed suspicious/staging process to avoid "
                        "enterprise alert storms."
                    ),
                    detection=dual_detection,
                    falsepositives="Legitimate administrative synchronization or automated cloud storage jobs using the specified binary",
                    level="high",
                    references=input_data.references,
                    behaviour="exfiltration to cloud storage",
                    techniques=techs or None,
                )
            )
        return results

    def _find_initiating_processes(self, input_data: SigmaGenerationInput) -> List[str]:
        """Find candidate non-system executables tied to exfiltration, staging, or network activity."""
        from hecate_agent.core.query_literals import SYSTEM_IMAGES

        staging_keywords = re.compile(
            r"\b(s3|cloud|storage|rclone|sync|exfiltrat\w*|upload\w*|aws|blob|bucket|transfer)\b", re.I
        )
        procs: List[str] = []

        # 1. Look in threat intel text for binaries near staging/cloud keywords
        for line in (input_data.threat_intel or "").splitlines():
            if staging_keywords.search(line):
                for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", line, re.I):
                    name = match.group(1).lower()
                    if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                        procs.append(f"\\{name}")

        # 2. Look in observed commands
        for cmd_dict in input_data.observed_commands:
            cmd = str(cmd_dict.get("command", "")).strip()
            if staging_keywords.search(cmd):
                for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", cmd, re.I):
                    name = match.group(1).lower()
                    if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                        procs.append(f"\\{name}")

        # 3. Look in query literals
        for lit in input_data.query_literals():
            if "process_creation.Image" in lit.get("fields", []):
                val = str(lit.get("value", "")).strip()
                clean = val.split("\\")[-1].split("/")[-1].lower()
                if clean.endswith(".exe") and clean not in SYSTEM_IMAGES:
                    entry = f"\\{clean}"
                    if entry not in procs:
                        procs.append(entry)

        # 4. Fallback to any non-system .exe in threat intel if none found near keywords
        if not procs:
            for match in re.finditer(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", input_data.threat_intel or "", re.I):
                name = match.group(1).lower()
                if name not in SYSTEM_IMAGES and f"\\{name}" not in procs:
                    procs.append(f"\\{name}")

        return procs

    def _ioc_rules_from_records(self, input_data: SigmaGenerationInput) -> List[Tuple[Optional[SigmaRule], Optional[str]]]:
        """IOC rules from typed records: each indicator only where its role can be observed.

        A hash reaches a process rule only as an executable (or an unreviewed
        hash), a library only an image-load rule; archives, documents, network
        content and in-memory payloads get none. Historical indicators get no
        rule at all. Each address is paired with the ports the source ties to
        it, one selection per port, so HTTP staging and a raw-TCP channel on
        the same host stay distinguishable. URL paths go to proxy logs, the
        only telemetry that records them. Dual-use cloud and SaaS indicators
        (AWS S3, Azure Blob, etc.) are bound to initiating suspicious processes
        rather than swept bare.
        """
        from hecate_agent.core.provenance import IndicatorRecord, hash_label, placements, url_parts

        records = [IndicatorRecord.from_dict(r) for r in input_data.indicator_records]
        historical_values = {
            str(r.value).strip().lower() for r in records if r.status == "historical" or r.role in ("historical", "target")
        }
        placed = [(r, [] if str(r.value).strip().lower() in historical_values else placements(r)) for r in records]

        def values_for(placement: str) -> List[IndicatorRecord]:
            return [r for r, where in placed if placement in where]

        results: List[Tuple[Optional[SigmaRule], Optional[str]]] = []
        for category, label, what in (
            ("process_creation", "hash IOC", "a process whose image hash is an executable the source published"),
            ("image_load", "library hash IOC", "a loaded library whose hash the source published"),
        ):
            hashes = [f"{hash_label(r.type)}={r.value}" for r in values_for(f"{category}.Hashes")]
            if hashes:
                results.append(
                    self._ioc_rule(
                        input_data,
                        category=category,
                        label=label,
                        title=f"{'Execution' if category == 'process_creation' else 'Load'} of a file hash named in the source intelligence",
                        description=f"Matches {what}. Hashes of archives, documents, network content and "
                        "in-memory payloads are excluded: no process image carries them.",
                        detection={"selection": {"Hashes|contains": hashes}, "condition": "selection"},
                        falsepositives="None expected for exact hashes; confirm the sensor records the listed algorithms",
                    )
                )

        names = values_for("dns_query.QueryName")
        if names:
            detection: Dict[str, Any] = {"selection_exact": {"QueryName": [r.value for r in names]}}
            domains = ["." + r.value for r in names if r.type == "domain"]
            if domains:
                detection["selection_subdomain"] = {"QueryName|endswith": domains}
            detection["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="dns_query",
                    label="domain IOC",
                    title="DNS lookup of a domain named in the source intelligence",
                    description="Matches a DNS query for a current domain or host the source published"
                    + (", or a subdomain of a published domain." if domains else ".")
                    + " Indicators the source marks historical are excluded.",
                    detection=detection,
                    falsepositives="Security tooling or analysts resolving the indicators themselves",
                )
            )

        network = _network_selections([*values_for("network_connection.DestinationIp"), *names])
        if network:
            network["condition"] = "1 of selection_*"
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="network IOC",
                    title="Connection to an address or host named in the source intelligence",
                    description="Matches an outbound connection to a current address or host the source published, "
                    "on the ports the source ties to it where it names them. Indicators the source marks "
                    "historical are excluded.",
                    detection=network,
                    falsepositives="Shared hosting or CDN addresses reused by unrelated sites",
                )
            )

        # Addresses the source names as where the attack came from. H-0830's
        # exploitation "Source IPs" went into an outbound DestinationIp sweep
        # that could never see them: they are the client in web logs and the
        # source of an inbound connection.
        inbound = sorted({r.value for r in values_for("webserver.c-ip")})
        if inbound:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="webserver",
                    label="inbound address IOC",
                    title="Web request from an address the source names as an attack source",
                    description="Matches a web or reverse-proxy access log entry whose client address the source "
                    "published as the origin of exploitation or scanning. Indicators the source marks historical "
                    "are excluded.",
                    detection={"selection": {"c-ip": inbound}, "condition": "selection"},
                    falsepositives="Addresses reassigned since the report, or shared egress (VPN, carrier NAT)",
                )
            )
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="inbound address IOC",
                    title="Inbound connection from an address the source names as an attack source",
                    description="Matches a connection accepted from an address the source published as the "
                    "origin of exploitation or scanning. Indicators the source marks historical are excluded.",
                    detection={
                        "selection": {"SourceIp": inbound, "Initiated": "false"},
                        "condition": "selection",
                    },
                    falsepositives="Addresses reassigned since the report, or shared egress (VPN, carrier NAT)",
                )
            )

        dual = values_for("network_connection.dual_use")
        dual_ips = [r.value for r in dual if r.type in ("ipv4", "ipv6")]
        dual_hosts = [r.value for r in dual if r.type in ("domain", "hostname")]
        # Only addresses and hosts can select a connection. H-0830's dual-use
        # set was four URL paths, and the rule shipped a condition naming
        # selection_dest_* with no such selection in it.
        if dual_ips or dual_hosts:
            candidate_procs = self._find_initiating_processes(input_data)
            dual_detection: Dict[str, Any] = {}
            if dual_ips:
                dual_detection["selection_dest_ip"] = {"DestinationIp": dual_ips}
            if dual_hosts:
                dual_detection["selection_dest_host"] = {"DestinationHostname": dual_hosts}
                domain_suffixes = ["." + r.value for r in dual if r.type == "domain" or r.value.startswith("s3.")]
                if domain_suffixes:
                    dual_detection["selection_dest_subdomain"] = {"DestinationHostname|endswith": sorted(set(domain_suffixes))}

            if candidate_procs:
                dual_detection["selection_process"] = {"Image|endswith": candidate_procs}
                dual_detection["condition"] = "(1 of selection_dest_*) and selection_process"
            else:
                dual_detection["filter_legit"] = {"Image|endswith": _platform_legit_filters(input_data.platforms)}
                dual_detection["condition"] = "(1 of selection_dest_*) and not filter_legit"

            techs = [
                t
                for t in ("T1567.002", "T1567", "T1071.001", "T1071")
                if any(t.lower() == it.lower() for it in input_data.techniques)
            ]
            results.append(
                self._ioc_rule(
                    input_data,
                    category="network_connection",
                    label="dual-use network IOC",
                    title="Outbound Connection to Dual-Use Cloud Endpoint by Observed Staging/Exfiltration Process",
                    description=(
                        "Matches an outbound network connection to a dual-use cloud storage or SaaS endpoint "
                        "published in intelligence, bound to the observed suspicious/staging process to avoid "
                        "enterprise alert storms."
                    ),
                    detection=dual_detection,
                    falsepositives="Legitimate administrative synchronization or automated cloud storage jobs using the specified binary",
                    level="high",
                    references=input_data.references,
                    behaviour="exfiltration to cloud storage",
                    techniques=techs or None,
                )
            )

        paths = sorted({path for r in values_for("proxy.c-uri") for path in [url_parts(r.value)[2]] if path and path != "/"})
        if paths:
            results.append(
                self._ioc_rule(
                    input_data,
                    category="proxy",
                    label="URL IOC",
                    title="Request for a URL path named in the source intelligence",
                    description="Matches a proxy or web request for a current URL path the source published. "
                    "URL paths appear only in proxy and web logs, not in endpoint file or process events.",
                    detection={"selection": {"c-uri|contains": paths}, "condition": "selection"},
                    falsepositives="Other sites serving a file at the same path",
                )
            )
        return results

    def _ioc_rule(
        self,
        input_data: SigmaGenerationInput,
        *,
        category: str,
        label: str,
        title: str,
        description: str,
        detection: Dict[str, Any],
        falsepositives: str,
        preamble: str = (
            "Deterministic IOC rule built from the indicators the source intelligence published, with no model involvement. "
        ),
        level: str = "high",
        author: str = "hecate (auto-generated from source indicators - requires analyst review)",
        references: Optional[List[str]] = None,
        behaviour: str = "",
        techniques: Optional[List[str]] = None,
        rule_platform: Optional[str] = None,
    ) -> Tuple[Optional[SigmaRule], Optional[str]]:
        """Render and validate one deterministic rule: IOC sweeps and the source's own detection guidance."""
        detection, _ = repair_sigma_semantics(detection)
        # The same semantic gate as a model rule: a template change that put a
        # field in the wrong category would otherwise ship on every hunt.
        problem = semantic_problem(detection, category, description)
        if problem:
            return None, f"{category} ({label}): {problem}"
        rule_techniques = techniques if techniques is not None else _behaviour_techniques(behaviour, input_data.techniques)
        if category in HOST_SENSOR_LOGSOURCES and appliance_only(input_data.platforms):
            # Kept, because the artifact is real, but a reviewer must know no
            # sensor on the device will raise it.
            description += (
                " This hunt is scoped to appliances, which rarely run a host sensor: use this as a forensic "
                "check on the device, or where file-integrity or EDR coverage exists for it."
            )
        document: Dict[str, Any] = {
            "title": title,
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": preamble + description,
            "references": list(dict.fromkeys([*input_data.references, *(references or [])])),
            "author": author,
            "date": date.today().isoformat(),
            "tags": [f"attack.{t.lower()}" for t in rule_techniques],
            "logsource": self._logsource_block(category, input_data.platforms, rule_platform=rule_platform),
            "detection": detection,
            "falsepositives": [falsepositives],
            "level": level,
        }
        provenance = rule_provenance(detection, input_data)
        if provenance:
            document["hecate_provenance"] = provenance
        if input_data.hunt_id:
            document["hunt_id"] = input_data.hunt_id
        rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)
        problem = _pysigma_problem(rule_yaml)
        if problem:
            return None, f"{category} ({label}): {problem}"
        return (
            SigmaRule(
                logsource_category=category,
                title=title,
                rule_yaml=rule_yaml,
                level=level,
                techniques=rule_techniques,
                origin="deterministic",
            ),
            None,
        )

    def _generate_for_logsource(
        self, input_data: SigmaGenerationInput, logsource: str
    ) -> Tuple[Optional[SigmaRule], List[str], List[str]]:
        """Draft one rule for one log source.

        Returns ``(rule_or_None, problems, omitted)`` rather than raising, so one log
        source failing -- a timeout, a truncated reply, an unusable rule --
        costs only its own rule and the rest of the hunt still gets coverage.
        Problems are reported even alongside a successful rule: a response
        carrying one good rule and one malformed sibling is worth a warning.
        """

        def validate_json(text: str) -> Optional[str]:
            try:
                payload = self._parse_json_response(text)
            except ValueError as exc:
                return str(exc)
            if not isinstance(payload.get("rules"), list):
                return "response must contain a 'rules' array"
            if not payload["rules"]:
                # Model explicitly determined no valid rule can be drafted without hallucinating
                return None

            problems = []
            for raw in payload["rules"]:
                rule, problem = self._build_rule(raw, input_data)
                if problem:
                    problems.append(problem)
                elif rule and rule.logsource_category == logsource:
                    if input_data.review_rules:
                        from hecate_agent.agents.llm.rule_reviewer import RuleReviewer

                        reviewer = RuleReviewer(
                            lambda prompt, validate: self._call_llm_with_retry(
                                prompt, validate, max_retries=1, max_tokens=1024, temperature=0.0
                            )
                        )
                        passages = SigmaGeneratorAgent._source_passages(input_data)
                        try:
                            review = reviewer.review(rule.rule_yaml, input_data.hypothesis, passages)
                            if review.verdict == "revise" and review.issues:
                                problems.append(
                                    "The rule requires revision. Please fix these issues and try again:\n"
                                    + "\n".join(f"- {i}" for i in review.issues)
                                )
                                continue
                            elif review.verdict == "reject":
                                msg = f"The rule was rejected by review: {review.contradiction or '; '.join(review.issues)}"
                                if review.quote:
                                    msg += f" (source: '{review.quote[:160]}')"
                                msg += f'. Fix these issues, or return {{"rules": []}} if {logsource} is not supported by the evidence.'
                                problems.append(msg)
                                continue
                        except Exception as exc:
                            logger.warning("rule review failed during generation: %s", exc)
                    return None  # We successfully built the requested rule!

            if problems:
                return "Your generated rules failed validation. Fix these errors:\n" + "\n".join(f"- {p}" for p in problems)
            return f"No valid rule was generated for the requested log source category '{logsource}'. If this category is unsupported, return {{\"rules\": []}}."

        try:
            # Low temperature: detection logic is not a place for invention.
            # A creative sample here means a field name that does not exist
            # in the target telemetry, which fails silently at conversion.
            output_text = self._call_llm_with_retry(
                self._build_prompt(input_data, logsource),
                validate_json,
                max_retries=3,
                temperature=0.1,
            )
            raw_rules = self._parse_json_response(output_text).get("rules", [])
        except Exception as exc:  # noqa: BLE001 - reported per log source, not fatal
            return None, [f"{logsource}: {exc}"], []

        built, problems = self._collect_rules(raw_rules, input_data)
        return _select_for_logsource(built, logsource, problems)

    def _collect_rules(self, raw_rules: Any, input_data: SigmaGenerationInput) -> Tuple[List[SigmaRule], List[str]]:
        """Build every proposed rule, keeping the reason each rejection failed."""
        rules: List[SigmaRule] = []
        rejected: List[str] = []
        for raw in raw_rules or []:
            rule, problem = self._build_rule(raw, input_data)
            if rule is None:
                rejected.append(problem or "unknown validation failure")
            else:
                rules.append(rule)
        return rules, rejected

    # --- Rule construction -----------------------------------------------------

    def _build_rule(self, raw: Any, input_data: SigmaGenerationInput) -> Tuple[Optional[SigmaRule], Optional[str]]:
        """Validate one model-proposed rule and render it to YAML.

        Returns ``(None, reason)`` for anything that fails, so the caller can
        report exactly what was dropped rather than emitting a rule an
        operator would have to debug at conversion time.
        """
        if not isinstance(raw, dict):
            return None, "rule is not an object"

        category = str(raw.get("logsource_category", "")).strip().lower()
        if category not in VALID_LOGSOURCE_CATEGORIES:
            return None, f"unknown logsource_category {category!r}"

        title = str(raw.get("title", "")).strip()
        if not title:
            return None, f"{category}: title is empty"

        detection, problem = self._normalise_detection(raw)
        if problem:
            return None, f"{category}: {problem}"
        detection = _anchor_bare_filenames(_strip_empty_filters(detection))
        detection = _complete_indicator_lists(detection, input_data.indicators)
        detection, _ = repair_sigma_semantics(detection)
        problem = self._validate_detection(detection)
        if problem:
            return None, f"{category}: {problem}"
        literals = input_data.query_literals()
        # Each check sees a structurally valid rule; the first to object wins.
        checks = (
            lambda d: _placeholder_problem(d, input_data.indicators),
            lambda d: _invented_ip_problem(d, input_data.indicators, input_data.observables),
            lambda d: _invented_hash_problem(d, input_data.indicators),
            lambda d: _invented_domain_problem(
                d,
                input_data.indicators,
                [
                    input_data.hypothesis,
                    input_data.justification,
                    *input_data.observables,
                    *input_data.references,
                ],
            ),
            lambda d: _partial_indicator_problem(d, input_data.indicators, category),
            lambda d: _self_defeating_filter_problem(d, input_data.hypothesis),
            lambda d: _excluded_threat_problem(d, input_data.indicators),
            _modifier_in_value_problem,
            _impossible_modifier_problem,
            lambda d: _library_as_process_problem(d, category),
            _field_type_problem,
            _breadth_problem,
            _or_branch_breadth_problem,
            lambda d: _hash_role_problem(d, input_data.indicator_records, category),
            lambda d: _literal_problem(d, literals),
            lambda d: _reversed_guidance_chain_problem(d, input_data.detection_guidance),
            lambda d: semantic_problem(
                d,
                category,
                str(raw.get("description", "")),
                [
                    *input_data.observables,
                    *(v for values in input_data.indicators.values() for v in values),
                    *(str(r.get("value", "")) for r in input_data.indicator_records),
                ],
            ),
        )
        for check in checks:
            problem = check(detection)
            if problem:
                return None, f"{category}: {problem}"

        level = str(raw.get("level", "medium")).strip().lower()
        if level not in VALID_LEVELS:
            level = "medium"

        techniques = self._rule_techniques(raw, input_data, category)
        rule_platform: Optional[str] = raw.get("logsource_product")
        if not rule_platform:
            for _, block in blocks(detection):
                for k, v in block.items():
                    if base_field(k).lower() in ("image", "parentimage", "commandline"):
                        raw_vals = v if isinstance(v, list) else [v]
                        if any(
                            str(x).startswith("/") or any(u in str(x) for u in ("/bin/", "/usr/", "nsenter", "bpftool"))
                            for x in raw_vals
                        ):
                            rule_platform = "linux"
                            break
                if rule_platform:
                    break

        document: Dict[str, Any] = {
            "title": title[:120],
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": str(raw.get("description", "")).strip()
            or f"Auto-drafted for hunt {input_data.hunt_id or '(unassigned)'}.",
            "references": list(input_data.references),
            "author": "hecate (auto-generated draft - requires analyst review)",
            "date": date.today().isoformat(),
            "tags": [f"attack.{t.lower()}" for t in techniques],
            "logsource": self._logsource_block(category, input_data.platforms, rule_platform=rule_platform),
            "detection": detection,
            "falsepositives": self._falsepositives(raw),
            "level": level,
        }
        provenance = rule_provenance(detection, input_data)
        if provenance:
            document["hecate_provenance"] = provenance
        if input_data.hunt_id:
            # Not Sigma's `related:`. That field relates a rule to *other Sigma
            # rules* and its `id` must be a UUID, so putting a hunt id there
            # made every rule we emitted fail to parse -- all 17 in the corpus,
            # with `SigmaRelatedError: Sigma related identifier must be an
            # UUID`. A custom key carries the same link and stays valid.
            document["hunt_id"] = input_data.hunt_id

        rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)

        # Last gate, on the rendered rule rather than the model's JSON: this is
        # the artifact an operator would actually run.
        problem = _pysigma_problem(rule_yaml)
        if problem:
            return None, f"{category}: {problem}"

        return (
            SigmaRule(
                logsource_category=category,
                title=title[:120],
                rule_yaml=rule_yaml,
                techniques=techniques,
                level=level,
            ),
            None,
        )

    @staticmethod
    def _normalise_detection(raw: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
        """Repair the two placements models get wrong, and only those.

        Observed on every rule of a real run: the model emits
        ``detection: {selection: {...}}`` and omits ``condition`` entirely.
        With exactly one selection block the intended condition has one
        possible value -- its name -- so inferring it is reading the rule as
        written, not guessing. With two or more blocks the operator (and/or/
        not) genuinely is unknown, so those are still rejected rather than
        silently wired up as an AND that nobody wrote.

        A ``condition`` placed at the rule's top level instead of inside
        ``detection`` is likewise moved rather than discarded -- the content
        is right, the nesting is not.
        """
        detection = raw.get("detection")
        if not isinstance(detection, dict):
            return detection, None  # let _validate_detection report the shape

        detection = dict(detection)
        for k, v in list(detection.items()):
            if k != "condition" and isinstance(v, dict) and "condition" in v:
                cond = v.pop("condition")
                if not detection.get("condition") and isinstance(cond, str) and cond.strip():
                    detection["condition"] = cond.strip()

        if not detection.get("condition"):
            top_level = raw.get("condition")
            if isinstance(top_level, str) and top_level.strip():
                detection["condition"] = top_level.strip()
            else:
                blocks = [k for k in detection if k != "condition"]
                if len(blocks) == 1:
                    detection["condition"] = blocks[0]
                elif len(blocks) > 1:
                    return detection, (
                        "detection omits 'condition' and defines "
                        f"{len(blocks)} selection blocks, so the intended "
                        "operator between them is unknowable"
                    )
        detection, repairs = repair_sigma_semantics(detection)
        if repairs:
            logger.info("Repaired Sigma detection semantics: %s", "; ".join(repairs))
        return detection, None

    @staticmethod
    def _validate_detection(detection: Any) -> Optional[str]:
        """Check the one part of a Sigma rule that silently misbehaves.

        A condition naming a selection that was never defined is still valid
        YAML and still looks like a rule; pySigma rejects it much later, by
        which time the hunt has been reviewed and approved around it.
        """
        if not isinstance(detection, dict):
            return "detection must be an object"
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            return "detection.condition must be a non-empty string"

        selections = [k for k in detection if k != "condition"]
        if not selections:
            return "detection defines no selection blocks"
        for name in selections:
            if not isinstance(detection[name], (dict, list)):
                return f"selection {name!r} must be a mapping or list"

        return SigmaGeneratorAgent._unresolved_condition_token(condition, selections)

    @staticmethod
    def _unresolved_condition_token(condition: str, selections: List[str]) -> Optional[str]:
        """Report the first condition token that names no defined block.

        A Sigma condition may carry an aggregation after a pipe:
        ``selection | count() by TargetUserName > 25``. Everything right of
        the pipe is aggregation grammar, not selection names, and splitting
        the whole string on whitespace read ``count()``, ``>`` and ``25`` as
        undefined selections -- so every volume-based rule the model produced
        was discarded before pySigma ever saw it. Volume is how Sigma
        expresses "an unusual number of", which is exactly what a
        credential-stuffing or brute-force hunt needs.
        """
        search, pipe, aggregation = condition.partition("|")
        problem = SigmaGeneratorAgent._unresolved_search_token(search, selections)
        if problem:
            return problem
        if pipe:
            return SigmaGeneratorAgent._aggregation_problem(aggregation, selections)
        return None

    @staticmethod
    def _unresolved_search_token(search: str, selections: List[str]) -> Optional[str]:
        """Validate the search half of a condition against the defined blocks."""
        keywords = {"and", "or", "not", "of", "them", "all", "1", "any", "selection"}
        tokens = {token.strip("()") for token in search.replace("(", " ").replace(")", " ").split()}
        for token in tokens:
            if not token or token in keywords or token.isdigit():
                continue
            if token.endswith("*"):
                if not any(sel.startswith(token[:-1]) for sel in selections):
                    return f"condition references undefined selection pattern {token!r}"
                continue
            if token not in selections:
                return f"condition references undefined selection {token!r}"
        return None

    @staticmethod
    def _aggregation_problem(aggregation: str, selections: List[str]) -> Optional[str]:
        """Validate the aggregation half of a condition.

        Checked rather than waved through: a malformed aggregation is still
        valid YAML and still looks like a threshold, so it would reach a
        reviewer as though it counted something.
        """
        text = aggregation.strip()
        if not text:
            return "condition ends in '|' with no aggregation"

        # `near` takes a search expression, not a numeric comparison.
        if text.startswith("near "):
            return SigmaGeneratorAgent._unresolved_search_token(text[len("near ") :], selections)

        match = _AGGREGATION_RE.match(text)
        if not match:
            return (
                f"aggregation {text!r} is not a Sigma aggregation; expected e.g. "
                "'count() > 25' or 'count(DestinationIp) by User > 10'"
            )
        return None

    @staticmethod
    def _logsource_block(category: str, platforms: List[str], rule_platform: Optional[str] = None) -> Dict[str, str]:
        block: Dict[str, str] = {"category": category}
        if category in ("proxy", "webserver", "cloud_audit", "identity_audit"):
            return block  # network-appliance and cloud control-plane logs have no endpoint OS product
        if rule_platform in ("linux", "unix"):
            block["product"] = "linux"
            return block
        if rule_platform == "windows":
            block["product"] = "windows"
            return block
        # Sigma's `product` is an OS, not a vendor. Only set it when the hunt
        # is genuinely single-platform; a multi-platform hunt pinned to one
        # product would silently stop matching the others.
        windows_only = [p for p in platforms if p.lower() == "windows"]
        if platforms and len(set(p.lower() for p in platforms)) == 1 and windows_only:
            block["product"] = "windows"
        return block

    @staticmethod
    def _falsepositives(raw: Dict[str, Any]) -> List[str]:
        values = raw.get("falsepositives")
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            return ["Unknown - analyst must establish a baseline before use"]
        return [str(v).strip() for v in values if str(v).strip()][:6]

    @staticmethod
    def _rule_techniques(raw: Dict[str, Any], input_data: SigmaGenerationInput, category: str = "") -> List[str]:
        """Prefer the techniques the CTI actually asserted.

        A model asked to tag its own rule tends to restate the one technique
        it wrote prose about. Intersecting against the hunt's technique list
        keeps sub-technique precision (T1059.003, not T1059) when the source
        supplied it.
        """
        declared = raw.get("techniques") or raw.get("tags") or []
        if isinstance(declared, str):
            declared = [declared]
        cleaned = []
        for item in declared:
            token = str(item).upper().replace("ATTACK.", "").strip()
            if token.startswith("T") and token[1:2].isdigit():
                cleaned.append(token)

        # Keep only techniques the source actually asserted. A real run tagged
        # a rule "T1047.002", which does not exist -- T1047 has no such
        # sub-technique. Intersecting against the supplied list makes an
        # invented ID impossible without needing the ATT&CK matrix here.
        supplied = {t.upper() for t in input_data.techniques}
        if not supplied:
            # Nothing to intersect against, so the model's tags are its own
            # unchecked guesses. H-0014 had no techniques and its rule came
            # back tagged T1059.003 (Windows Command Shell) on a Linux hunt.
            # Untagged is honest; a guessed tag reads as a mapping.
            return []

        grounded = [t for t in cleaned if t in supplied]
        if grounded:
            return sorted(set(grounded))

        # Nothing the model proposed survived. Falling back to every supplied
        # technique tagged a DLL side-loading rule with all fifteen the event
        # carried, exfiltration and registry persistence included. Narrow to
        # the ones actually observable in this rule's own log source.
        if category:
            relevant = sorted(
                t
                for t in supplied
                if any(t.startswith(prefix) and category in sources for prefix, sources in _TECHNIQUE_LOGSOURCES.items())
            )
            if relevant:
                return relevant
        return sorted(supplied)

    # --- Prompt ----------------------------------------------------------------

    def _relevant_techniques_for_prompt(self, techniques: list[str], logsource: str) -> list[str]:
        relevant = []
        for t in techniques:
            norm = t.upper().strip()
            for prefix, sources in _TECHNIQUE_LOGSOURCES.items():
                if norm.startswith(prefix) and logsource in sources:
                    relevant.append(t)
                    break
        return relevant or techniques

    def _build_prompt(self, input_data: SigmaGenerationInput, logsource: str) -> str:
        indicator_block = self._render_indicators(input_data.indicators)
        observable_block = "\n".join(f"  - {o}" for o in input_data.observables[:10]) or "(none)"
        literals = input_data.query_literals()
        if literals:
            from hecate_agent.core.query_literals import render_literals

            # Two-pass generation: the values were extracted and verified first;
            # the rule only maps them onto fields. Model-written observables
            # are left out, since they are where invented strings came from.
            literal_block = (
                "EXACT VALUES FROM THE SOURCE (verified against the report; the ONLY file, process, command-line "
                "and registry values you may match, whole or in part, besides standard system binaries such as "
                "\\cmd.exe):\n" + render_literals(literals) + "\n"
            )
        else:
            literal_block = (
                "OBSERVABLES THE HUNT DRAFT NAMED (from research; unverified, use where they fit):\n" + observable_block + "\n"
            )
        techniques = ", ".join(self._relevant_techniques_for_prompt(input_data.techniques, logsource)) or "(none supplied)"
        platforms = ", ".join(input_data.platforms) or "(unspecified)"
        fields = _LOGSOURCE_FIELDS.get(logsource, "(use the standard Sigma fields for this category)")
        covered = [
            str(c.get("title", "")) for c in input_data.observed_commands if c.get("category", "process_creation") == logsource
        ]
        already_covered = ""
        if covered:
            already_covered = (
                f"\nNOTE: Deterministic rules already cover these specific actions for {logsource}: "
                f"{', '.join(covered)}. Do NOT duplicate them. Focus on other distinct behaviors, "
                f"scripting hosts (e.g. wscript, cscript), or process relationships described in the intelligence and hypothesis.\n"
            )

        threat_intel_block = ""
        if input_data.threat_intel:
            intel_text = input_data.threat_intel.strip()
            if len(intel_text) > 2000:
                intel_text = intel_text[:2000].rsplit("\n", 1)[0] + "\n..."
            threat_intel_block = f"\nSOURCE INTELLIGENCE SUMMARY / TRADECRAFT:\n{intel_text}\n"

        return f"""You are a detection engineer drafting one Sigma rule for a threat hunt.

HUNT HYPOTHESIS:
{input_data.hypothesis}

JUSTIFICATION:
{input_data.justification or "(none supplied)"}
{threat_intel_block}
ATT&CK TECHNIQUES: {techniques}
PLATFORMS: {platforms}

INDICATORS FROM THE SOURCE INTELLIGENCE:
{indicator_block}

{literal_block}
{self._render_guidance(input_data)}{self._render_telemetry_examples(input_data)}{already_covered}
Write EXACTLY ONE rule, for this Sigma log source category and no other:
    {logsource}

Fields available in {logsource}: {fields}\nStandard Sigma Modifiers available: `|contains`, `|endswith`, `|startswith`, `|all`, `|re`, `|cidr`. Do NOT invent modifiers like `|in` or `|regex`.

RULES OF THE TASK:
1. Return JSON only. Do NOT write YAML - the caller renders it.
2. IRONCLAD DETECTION LOGIC: Never use placeholder paths or exact threat tracking names inside registry keys or execution paths. Malware developers do not name their artifacts after their industry marketing names. Do NOT invent strings.
3. STRICT LOG SOURCE MAPPING: File events are ONLY for disk writes. Do NOT put process arguments in file events. Process creation events are for executions. Do not mix them.
4. Use only field names that exist in {logsource}. Match the value to the field's type: an address field (IpAddress, DestinationIp) takes an IP or CIDR, never a hostname, and a port field takes a number. Never place a file hash into a command-line or filename field; hashes belong ONLY in a `Hashes` field. If your only indicator is a domain and this log source has no name field for it, write a behavioural rule instead.
5. Prioritize BEHAVIORAL rules (relationships and sequences) over simple indicator matches.
   For example, a rule that looks for `ParentImage|endswith: \\winword.exe` spawning
   `Image|endswith: \\cmd.exe` is a high-quality, generic behavioral rule that works
   everywhere. Using no indicator at all is completely fine, and often preferred,
   when the behaviour itself is the better rule.
6. If you DO use a specific indicator, reproduce it WHOLE in one match value. Never
   split one into fragments: "bad.example.net" written as `|endswith: .net` plus
   `|contains: bad` matches every .net domain, loses the evidence, and is rejected.
   A selection that matches only a file extension (`|endswith: .exe`) or a wildcard
   matches every file of that type and is rejected.
7. Every `detection` MUST contain a `condition` key. It is not optional, and
   it may only name selection blocks you defined in the same rule. If you
   define both a selection and a filter, say so explicitly, e.g.
   "selection and not filter".
8. When the hypothesis is about an unusual *number* of events -- brute force,
   credential stuffing, password spraying, beaconing, mass enumeration -- put
   the threshold in the condition with an aggregation, or the rule fires on a
   single ordinary event. Sigma writes it as
   "selection | count() > 25" or "selection | count(IpAddress) by TargetUserName > 10".
   Only use one when volume is what makes the behaviour suspicious.
9. A `filter` must never exclude the attack path the hypothesis describes.
   On a hunt about malware delivered through the browser, excluding the
   browser as the parent process removes the very thing being hunted. An
   empty filter block is rejected: omit it instead.
10. Give realistic falsepositives. "None" is never a correct answer.
11. The JSON below shows the *shape* only. Its values are placeholders, not
   examples to copy: "FieldName", "value" and "known-good" must never appear
   in what you return, and a rule matching on them is rejected. Neither may
   invented stand-ins of your own -- "bad_command", "malicious.exe",
   "evil.com" or anything under example.com. Every value you emit must be an
   indicator from above, or a real path, process or registry key.
12. HYPOTHESIS AND ATTACK CHAIN ALIGNMENT: Your detection logic MUST hunt for the specific behaviors described in the HUNT HYPOTHESIS, ATT&CK TECHNIQUES, or the broader attack lifecycle in the SOURCE INTELLIGENCE (e.g. initial access, container breakouts, defense evasion, privilege escalation, execution, lateral movement, or exfiltration). Do not invent unrelated TTPs not present in the intelligence or techniques list. If neither the hypothesis, techniques, nor intelligence contain observable behaviors for {logsource}, return an empty rules array: {{"rules": []}}.
13. PREVENT TTP CONFLATION: If the hypothesis or intelligence mentions multiple distinct behaviors (e.g., Scheduled Tasks AND Registry Run Keys), ensure your rule focuses ONLY on the behavior that matches the current log source category. Do not mix the names, titles, or logic of distinct TTPs into a single rule.
14. RESPECT THE PLATFORMS: If the PLATFORMS above are strictly non-Windows (e.g., Linux or macOS), you MUST NOT use Windows file paths (like C:\\ or System32) and you MUST NOT assume Windows-specific process names. Ensure your conditions fit the actual OS.
15. HANDLING ELISIONS: If the source intelligence gives you a partial or redacted string (e.g., `powershell -e JAB...`, `[REDACTED]`, or `C:\\temp\\...\\malware.exe`), DO NOT include the literal ellipsis `...` or `[REDACTED]` in your match value. Instead, use a substring match modifier (like `|contains` or `|startswith`) on the specific known portion of the string.
16. NO EXTERNAL THREAT-ACTOR KNOWLEDGE: Do NOT use or extrapolate from pre-trained knowledge about named threat groups, campaigns, or malware families (e.g., "SocGholish", "APT28"). You must strictly restrict detection logic to behaviors, mechanisms, and indicators explicitly given in the HUNT HYPOTHESIS, INDICATORS, and SOURCE PASSAGES. If a behavior, domain, IP, or file artifact is not explicitly stated in the prompt, assume it does not exist.
17. DUAL-USE CLOUD/SAAS DESTINATIONS: If writing a network connection or DNS query rule involving public cloud storage or SaaS endpoints (e.g. AWS S3 amazonaws.com, Azure Blob blob.core.windows.net, Google Drive, Discord, Telegram), NEVER match the destination as a bare standalone indicator: it causes severe alert storms in enterprise environments. You MUST bind the network connection to the specific initiating process or utility (e.g., Image|endswith: \\svchost_sync.exe or \\rclone.exe) using a combined condition: "(1 of selection_dest_*) and selection_process", or filter legitimate software/browsers.
18. SPOOFED AND IMPERSONATED DOMAINS: If matching a domain or host that mimics legitimate brands, services, or companies (e.g. `hub.zoom.com.kg`, `login.microsoft.com.attacker.top`), NEVER use `|contains` on the impersonated brand name (e.g., `DestinationHostname|contains: zoom.com` or `microsoft.com`). Doing so matches all legitimate enterprise traffic to that brand and will be rejected. You MUST match the attacker's indicator using exact match (`DestinationHostname: hub.zoom.com.kg`) or suffix match on the actual malicious registrable domain (`DestinationHostname|endswith: .zoom.com.kg`).
Return JSON with a single entry in "rules", or an empty list if this log source category has no supporting evidence in the hypothesis or intelligence:
{{
  "rules": [
    {{
      "logsource_category": "{logsource}",
      "title": "Short specific title",
      "description": "What this detects and why it matters",
      "techniques": ["T1059.003"],
      "detection": {{
        "selection": {{"FieldName|endswith": "value"}},
        "filter": {{"FieldName|contains": "known-good"}},
        "condition": "selection and not filter"
      }},
      "falsepositives": ["Administrative scripting"],
      "level": "medium"
    }}
  ]
}}
If no behavior or indicator matches {logsource}, return:
{{"rules": []}}"""

    @staticmethod
    def _render_telemetry_examples(input_data: SigmaGenerationInput) -> str:
        """A3: where the internals this hunt names really appear, on its platforms."""
        from hecate_agent.core.telemetry_examples import render_examples

        text = "\n".join(
            [
                input_data.hypothesis,
                input_data.justification,
                *(str(g.get("text", "")) for g in input_data.detection_guidance),
                *(str(a.get("evidence", "")) for a in input_data.source_artifacts),
            ]
        )
        return render_examples(text, input_data.platforms)

    @staticmethod
    def _render_guidance(input_data: SigmaGenerationInput) -> str:
        """The source's detection guidance, so a model rule agrees with it (chain direction above all)."""
        lines = [f'  - "{str(g.get("text", ""))[:240]}"' for g in input_data.detection_guidance if g.get("route") == "sigma"]
        if not lines:
            return ""
        return (
            "THE SOURCE'S OWN DETECTION GUIDANCE (rules implementing it are already drafted; write a rule for "
            "something else, and never contradict it, e.g. by reversing a parent/child chain):\n" + "\n".join(lines) + "\n"
        )

    @staticmethod
    def _render_indicators(indicators: Dict[str, List[str]]) -> str:
        if not indicators:
            return "(none supplied - generalise from the hypothesis and techniques)"
        lines = []
        for itype in sorted(indicators):
            values = [str(v) for v in indicators[itype]][:10]
            if values:
                lines.append(f"  {itype}: {', '.join(values)}")
        return "\n".join(lines) or "(none supplied)"
