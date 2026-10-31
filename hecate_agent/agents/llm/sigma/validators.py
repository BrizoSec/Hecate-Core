"""Rule validation, sanity checks, and semantic problem detectors for Sigma rules."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import yaml

from hecate_agent.agents.llm.sigma.logsources import (
    _HEX_RE,
    _INDICATOR_LOGSOURCES,
    _LOGSOURCE_FIELDS as _LOGSOURCE_FIELDS,
    _DOMAIN_RE,
    _URL_HOST_RE,
)
from hecate_agent.agents.llm.sigma.models import SigmaRule

if TYPE_CHECKING:
    from hecate_agent.agents.llm.sigma.models import SigmaGenerationInput

logger = logging.getLogger(__name__)


def _select_for_logsource(
    built: List[SigmaRule], logsource: str, problems: List[str]
) -> Tuple[Optional[SigmaRule], List[str], List[str]]:
    """Pick the rule written for the requested category, noting rejections and omitted sources."""
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
    "\\path\\to\\",
    "/path/to/",
)

_PLACEHOLDER_FILE_RE = re.compile(
    r"(?:^|[\\/])(?:malware|malicious|rat|evil|badfile|payload)\.(?:exe|dll|ps1|bin|sh|bat|vbs|js|msi)$",
    re.IGNORECASE,
)

_PLACEHOLDER_EXACT = frozenset(
    {
        "value", "string", "name", "n/a", "none", "null", "-", "todo", "tbd",
        "malware", "payload", "backdoor", "attacker", "suspicious", "exploit", "c2",
    }
)


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
    """True for a dotted-quad-shaped value with an out-of-range octet."""
    parts = value.strip().rstrip(".").split(".")
    if len(parts) < 3 or not all(part.isdigit() for part in parts):
        return False
    return any(int(part) > 255 for part in parts)


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


_SNAKE_PLACEHOLDER_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")

_GENERIC_DESCRIPTOR_WORDS = frozenset(
    {
        "signed", "binary", "path", "target", "process", "name", "bad", "command",
        "cmd", "image", "file", "filename", "folder", "directory", "dir", "parent",
        "child", "host", "hostname", "ip", "address", "port", "url", "domain",
        "user", "username", "account", "group", "hash", "md5", "sha1", "sha256",
        "imphash", "payload", "malware", "malicious", "c2", "attacker", "victim",
        "endpoint", "server", "client", "agent", "tool", "script", "executable",
        "exe", "dll", "argument", "parameter", "param", "value", "string",
        "placeholder", "variable", "var", "data", "sample", "example", "test",
        "dummy", "suspicious", "unknown", "arbitrary", "random", "temporary", "temp",
    }
)


def _is_snake_placeholder(value: str) -> bool:
    """Whether value looks like a generic description invented by the model."""
    if not _SNAKE_PLACEHOLDER_RE.match(value):
        return False
    lowered = value.lower()
    _PROGRAMMATIC_PREFIXES = (
        "wp_", "wp_ajax_", "admin_", "action_", "api_", "hook_", "mod_",
        "plugin_", "route_", "func_", "get_", "set_", "do_", "on_", "handle_",
        "dispatch_", "sys_", "proc_",
    )
    if any(lowered.startswith(prefix) for prefix in _PROGRAMMATIC_PREFIXES):
        return False
    parts = lowered.split("_")
    if len(parts) >= 4 and len(lowered) >= 20:
        return False
    if all(p in _GENERIC_DESCRIPTOR_WORDS for p in parts):
        return True
    if len(parts) <= 3 and any(p in _GENERIC_DESCRIPTOR_WORDS for p in parts):
        non_generic = [p for p in parts if p not in _GENERIC_DESCRIPTOR_WORDS]
        if not non_generic or all(len(p) <= 3 for p in non_generic):
            return True
    return False


_PYSIGMA_WARNED = False


def _pysigma_problem(rule_yaml: str) -> Optional[str]:
    """Parse a rendered rule with pySigma; return why it is not valid Sigma."""
    global _PYSIGMA_WARNED
    import sys

    sg = sys.modules.get("hecate_agent.agents.llm.sigma_generator")
    if sg is not None and hasattr(sg, "_PYSIGMA_WARNED"):
        if not getattr(sg, "_PYSIGMA_WARNED"):
            _PYSIGMA_WARNED = False

    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        if not _PYSIGMA_WARNED:
            _PYSIGMA_WARNED = True
            if sg is not None:
                try:
                    setattr(sg, "_PYSIGMA_WARNED", True)
                except Exception:
                    pass
            logger.warning(
                "pysigma is not installed, so generated rules are NOT being validated as "
                "Sigma -- only structurally checked. Install it with: pip install -e '.[sigma]'"
            )
        return None

    try:
        SigmaCollection.from_yaml(rule_yaml)
    except Exception as exc:
        return f"not valid Sigma ({type(exc).__name__}: {str(exc)[:160]})"
    return None


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
    """Drop filter blocks that match nothing, and the condition terms naming them."""
    empty = [key for key, block in detection.items() if key != "condition" and isinstance(block, dict) and not block]
    if not empty:
        return detection

    cleaned = {key: block for key, block in detection.items() if key not in empty}
    condition = str(cleaned.get("condition", ""))
    for name in empty:
        quoted = re.escape(name)
        condition = re.sub(rf"\s+and\s+not\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\s+and\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\bnot\s+{quoted}\b", "", condition)
        condition = re.sub(rf"\b{quoted}\b", "", condition)
    condition = re.sub(r"\s+", " ", condition).strip()
    if condition:
        cleaned["condition"] = condition
    return cleaned


_FULL_PATH_FIELDS = frozenset({"image", "parentimage", "targetfilename", "imageloaded"})


def _anchor_bare_filenames(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite `Image: name.exe` as `Image|endswith: \\name.exe`."""

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
    """Widen a field matching some supplied indicators to all of that type."""
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


_IP_FIELDS = frozenset({"ipaddress", "destinationip", "sourceip", "srcip", "dstip", "clientip", "serverip"})
_PORT_FIELDS = frozenset({"destinationport", "sourceport", "srcport", "dstport"})
_FILENAME_FIELDS = frozenset({"targetfilename", "image", "parentimage", "imageloaded", "originalfilename"})
_SWITCH_RE = re.compile(r"(?:^|\s)(?:--?[A-Za-z][\w-]*|/[A-Za-z]{1,3})(?=\s|$)")


def _looks_like_address(value: str, is_regex: bool = False) -> bool:
    """Whether `value` could be part of an IP address, CIDR range, or address regex."""
    cleaned = value.strip()
    if not cleaned:
        return False

    if is_regex:
        try:
            re.compile(cleaned)
        except re.error:
            return False
        stripped = re.sub(r"[\^$\\()\[\]?*+{}\-|\s]", "", cleaned)
        if not stripped:
            return True
        if ":" in stripped:
            return all(c in "0123456789abcdefABCDEF:./" for c in stripped)
        return all(c in "0123456789./" for c in stripped)

    if ":" in cleaned:
        return all(c in "0123456789abcdefABCDEF:./" for c in cleaned)
    return all(c in "0123456789./" for c in cleaned)


def _field_type_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a value that cannot occur in the field it is matched against."""
    for block_name, block in detection.items():
        if block_name == "condition" or not isinstance(block, dict):
            continue
        for field_name, raw_value in block.items():
            field_str = str(field_name)
            parts = field_str.split("|")
            base = parts[0].strip().lower()
            modifiers = [p.strip().lower() for p in parts[1:]]
            is_regex = "re" in modifiers
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            for value in values:
                text = str(value)
                if base in _IP_FIELDS and not _looks_like_address(text, is_regex=is_regex):
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
    """Reject a rule that reproduces a supplied indicator only in part."""
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
        if len(lowered) < 4 or lowered in complete:
            continue
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
    """Reject an exclusion that removes the hunt's own stated attack path."""
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


_SIGNATURE_FIELDS = frozenset({"signed", "signaturestatus", "signature_status", "signaturevalid"})
_UNTRUSTED_SIGNATURE_VALUES = frozenset({"false", "0", "unsigned", "invalid", "expired", "revoked", "untrusted"})


def _excluded_threat_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]]) -> Optional[str]:
    """Reject a rule whose exclusion removes the very thing it hunts."""
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


_EXTENSION_ONLY_RE = re.compile(r"^\.?[a-z0-9]{1,5}$")


def _nonspecific(value: str) -> bool:
    """A match value that names no particular thing: a bare extension, wildcard or switch."""
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


_FULL_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")


def _invented_ip_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]], observables: List[str]) -> Optional[str]:
    """Reject a selection matching an exact IPv4 address no intel supplied."""
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
_URL_FIELDS = frozenset({"url", "uri", "c-uri", "cs-uri", "requesturl", "request_url"})
_SECOND_LEVEL_SUFFIXES = frozenset({"co", "com", "net", "org", "gov", "ac", "edu"})


def _registered_name(domain: str) -> str:
    """``telegram`` for ``api.telegram.org``; ``example`` for ``www.example.co.uk``."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL_SUFFIXES and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else ""


def _invented_hash_problem(detection: dict, supplied: dict) -> str | None:
    """Reject a selection matching a specific file hash no intel supplied."""
    known = " ".join(
        " ".join(map(str, v)).lower()
        for k, v in supplied.items()
        if "hash" in k.lower() or k.lower() in ("md5", "sha1", "sha256", "imphash")
    )
    for value in _detection_values(detection):
        cleaned = value.strip().lower()
        if len(cleaned) in (32, 40, 64) and re.match(r"^[0-9a-f]+$", cleaned):
            if cleaned not in known:
                return (
                    f"detection matches hash {cleaned!r}, which is absent from the supplied routable indicators; "
                    "verify source extraction, provenance and file role before using it in this telemetry"
                )
    return None


def _invented_domain_problem(detection: Dict[str, Any], supplied: Dict[str, List[str]], context: List[str]) -> Optional[str]:
    """Reject a selection matching a domain the intelligence never names."""
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
    """Reject a rule whose selections match only extensions or wildcards."""
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
    """Reject a flat OR with one branch that matches almost anything."""
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
    """A published hash matched in an event where a file of that role never appears."""
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


def _network_role_problem(detection: Dict[str, Any], records: List[Dict[str, Any]]) -> Optional[str]:
    """Prevent model drafts from reintroducing network indicators routing excluded."""
    from hecate_agent.core.provenance import NETWORK_TYPES, IndicatorRecord, scoped_placements, url_parts

    typed = [IndicatorRecord.from_dict(r) for r in records]
    blocked = [r for r, where in scoped_placements(typed) if r.type in NETWORK_TYPES and not where]
    host_fields = {"queryname", "destinationhostname", "destinationip", "sourceip", "cs-host", "c-ip"}
    for name, block in _blocks_of(detection):
        if re.search(rf"\bnot\s+{re.escape(name)}\b", str(detection.get("condition", "")), re.I):
            continue
        for key, raw in block.items():
            field = str(key).split("|")[0].lower()
            if field not in host_fields and field != "c-uri":
                continue
            for value in raw if isinstance(raw, list) else [raw]:
                value = str(value).lower().strip("*").rstrip(".")
                for record in blocked:
                    host = url_parts(record.value)[0] if record.type == "url" else record.value.lower().rstrip(".")
                    matches = (field in host_fields and (value == host or value.endswith("." + host))) or (
                        field == "c-uri" and record.type == "url" and value == record.value.lower()
                    )
                    if matches:
                        return (
                            f"{record.value!r} is excluded by source role/status or historical domain scope; "
                            "establish its current infrastructure role before using it as an alert indicator"
                        )
    return None


def _reversed_guidance_chain_problem(detection: Dict[str, Any], guidance: List[Dict[str, Any]]) -> Optional[str]:
    """A model rule whose parent/child pair reverses a chain the source's guidance gives."""
    parents = [str(v).lower() for b in _blocks_of(detection) for k, raw in b[1].items()
               if str(k).split("|")[0].lower() == "parentimage" for v in (raw if isinstance(raw, list) else [raw])]
    images = [str(v).lower() for b in _blocks_of(detection) for k, raw in b[1].items()
              if str(k).split("|")[0].lower() == "image" for v in (raw if isinstance(raw, list) else [raw])]
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
    """Where each published indicator a rule matches came from."""
    from hecate_agent.core.provenance import IndicatorRecord, url_parts

    values = [str(v).lower() for v in _detection_values(detection)]
    if not values:
        return []

    def matched(value: str, kind: str) -> bool:
        needles = [value.lower()]
        if kind == "url":
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
    """Reject a rule whose detection matches on scaffolding."""
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
        if _is_snake_placeholder(cleaned):
            return f"detection matches on {cleaned!r}, which describes a value rather than being one"
        if _PLACEHOLDER_FILE_RE.search(cleaned):
            return f"detection matches on {cleaned!r}, a stand-in file name rather than one the intel names"
    return None


_MODIFIER_IN_VALUE_RE = re.compile(
    r"^\s*\|\s*(?:contains|startswith|endswith|re|all|cidr|base64|base64offset|windash|wide|utf16le|exists)\b",
    re.IGNORECASE,
)


def _modifier_in_value_problem(detection: Dict[str, Any]) -> Optional[str]:
    """Reject a selection whose modifier was written into the value."""
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
    """Reject rules where |all modifier creates a mathematically impossible condition."""
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


_PROCESS_IMAGE_FIELDS = frozenset({"image", "parentimage", "originalfilename"})
_LIBRARY_SUFFIXES = (".dll", ".sys", ".ocx", ".drv")
_SCRIPT_SUFFIXES = (".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".sh", ".py")


def _library_as_process_problem(detection: Dict[str, Any], category: str) -> Optional[str]:
    """Reject a process_creation rule whose process image is a library or script."""
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
    """One selection per address or host and port, so each channel stays distinguishable."""
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


_PLATFORM_DIAGNOSTIC_RE = re.compile(
    r"\b(?:run|runs|running|operating system|os is|platform is)\s+(?:an?\s+)?(?P<os>freebsd|bsd|linux|windows|macos|darwin|esxi)\b"
    r"|(?:specifies|targets?)\s+[`']?logsource:\s*product:\s*(?:\w+)[`']?.*?(?:runs|is)\s+(?P<os2>freebsd|bsd|linux|windows|macos|esxi)",
    re.IGNORECASE,
)


def _remediate_platform_contradiction(
    rule_yaml_str: str, contradiction: str
) -> Optional[Tuple[str, str, str]]:
    """If reviewer rejected rule due to platform mismatch, return (updated_yaml, old_product, new_product)."""
    if not contradiction:
        return None
    m = _PLATFORM_DIAGNOSTIC_RE.search(contradiction)
    if not m:
        return None
    new_os = (m.group("os") or m.group("os2") or "").lower()
    if not new_os:
        return None
    if new_os == "darwin":
        new_os = "macos"
    elif new_os == "bsd":
        new_os = "freebsd"

    try:
        doc = yaml.safe_load(rule_yaml_str)
        if not isinstance(doc, dict):
            return None
        logsource = doc.get("logsource")
        if not isinstance(logsource, dict):
            return None
        old_prod = str(logsource.get("product") or "").lower()
        if old_prod == new_os:
            return None

        logsource["product"] = new_os
        doc["logsource"] = logsource
        doc["hecate_review"] = {
            "verdict": "remediated",
            "remediation": f"Platform auto-remediated from {old_prod or 'unspecified'} to {new_os} based on reviewer diagnosis",
            "original_contradiction": contradiction,
        }
        remediated_yaml = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)
        return remediated_yaml, old_prod, new_os
    except Exception:
        return None
