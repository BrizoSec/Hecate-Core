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
}

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
    "T1547": {"registry_event"},
    "T1543": {"registry_event", "process_creation"},
    "T1112": {"registry_event"},
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
        return ["process_creation"]
    # Stable order so a rerun on identical input yields identical filenames.
    return sorted(found)


@dataclass
class SigmaGenerationInput:
    """Input for Sigma rule generation."""

    hypothesis: str
    hunt_id: str = ""
    justification: str = ""
    techniques: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    # attribute type -> concrete values from the source CTI, e.g.
    # {"hostname": ["api.wiresguard.com"], "filename": ["...svchost.exe"]}.
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    # Explicit override; when empty the log sources are derived.
    logsources: List[str] = field(default_factory=list)


@dataclass
class SigmaRule:
    """One generated rule plus the provenance an operator needs to judge it."""

    logsource_category: str
    title: str
    rule_yaml: str
    techniques: List[str] = field(default_factory=list)
    level: str = "medium"

    @property
    def filename(self) -> str:
        slug = "".join(c if c.isalnum() else "_" for c in self.title.lower())
        slug = "_".join(part for part in slug.split("_") if part)[:60]
        return f"{self.logsource_category}__{slug or 'rule'}.yml"


@dataclass
class SigmaGenerationOutput:
    """Output from Sigma rule generation."""

    rules: List[SigmaRule] = field(default_factory=list)
    logsources_considered: List[str] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)


def _select_for_logsource(
    built: List[SigmaRule], logsource: str, problems: List[str]
) -> Tuple[Optional[SigmaRule], List[str]]:
    """Pick the rule written for the requested category, noting the rest.

    A rule written for a different category than the one asked for is not the
    rule this iteration needed; relabelling it would file process telemetry
    under DNS.
    """
    match = None
    for rule in built:
        if match is None and rule.logsource_category == logsource:
            match = rule
        elif rule.logsource_category != logsource:
            problems.append(f"{logsource}: model returned a {rule.logsource_category} rule instead")

    if match is None and not problems:
        problems.append(f"{logsource}: no rule returned")
    return match, problems


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
)

#: Placeholders only when they are the entire value. As substrings these
#: appear inside legitimate paths and hostnames.
_PLACEHOLDER_EXACT = frozenset({"value", "string", "name", "n/a", "none", "null", "-", "todo", "tbd"})


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
        if _SNAKE_PLACEHOLDER_RE.match(cleaned):
            return f"detection matches on {cleaned!r}, which describes a value rather than being one"
    return None


class SigmaGeneratorAgent(LLMAgent[SigmaGenerationInput, SigmaGenerationOutput]):
    """Drafts Sigma rules covering each log source a hunt applies to."""

    def execute(self, input_data: SigmaGenerationInput) -> AgentResult[SigmaGenerationOutput]:
        start = time.monotonic()
        logsources = input_data.logsources or applicable_logsources(
            input_data.techniques,
            list(input_data.indicators.keys()),
        )

        if not self.llm_enabled:
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(logsources_considered=logsources),
                error="Sigma generation requires an LLM; no provider is configured.",
                warnings=[],
                metadata={"duration_ms": int((time.monotonic() - start) * 1000)},
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
        for logsource in logsources:
            rule, problems = self._generate_for_logsource(input_data, logsource)
            rejected.extend(problems)
            if rule is None:
                warnings.append(f"no valid rule generated for log source '{logsource}'")
            else:
                rules.append(rule)

        if not rules:
            return AgentResult(
                success=False,
                data=SigmaGenerationOutput(logsources_considered=logsources, rejected=rejected),
                error="no log source produced a valid rule: " + "; ".join(rejected),
                warnings=warnings,
                metadata={"duration_ms": int((time.monotonic() - start) * 1000)},
            )

        warnings.extend(f"rejected rule: {r}" for r in rejected)
        provider = self._get_provider()
        return AgentResult(
            success=True,
            data=SigmaGenerationOutput(rules=rules, logsources_considered=logsources, rejected=rejected),
            error=None,
            warnings=warnings,
            metadata={
                "llm_provider": provider.provider_name,
                "llm_model": getattr(provider, "model", getattr(provider, "model_id", "unknown")),
                "llm_calls": len(logsources),
                "duration_ms": int((time.monotonic() - start) * 1000),
            },
        )

    def _generate_for_logsource(
        self, input_data: SigmaGenerationInput, logsource: str
    ) -> Tuple[Optional[SigmaRule], List[str]]:
        """Draft one rule for one log source.

        Returns ``(rule_or_None, problems)`` rather than raising, so one log
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
            if not isinstance(payload.get("rules"), list) or not payload["rules"]:
                return "response must contain a non-empty 'rules' array"
            return None

        try:
            # Low temperature: detection logic is not a place for invention.
            # A creative sample here means a field name that does not exist
            # in the target telemetry, which fails silently at conversion.
            output_text = self._call_llm_with_retry(
                self._build_prompt(input_data, logsource),
                validate_json,
                max_retries=2,
                temperature=0.1,
            )
            raw_rules = self._parse_json_response(output_text).get("rules", [])
        except Exception as exc:  # noqa: BLE001 - reported per log source, not fatal
            return None, [f"{logsource}: {exc}"]

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
        problem = self._validate_detection(detection)
        if problem:
            return None, f"{category}: {problem}"
        problem = _placeholder_problem(detection, input_data.indicators)
        if problem:
            return None, f"{category}: {problem}"

        level = str(raw.get("level", "medium")).strip().lower()
        if level not in VALID_LEVELS:
            level = "medium"

        techniques = self._rule_techniques(raw, input_data, category)
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
            "logsource": self._logsource_block(category, input_data.platforms),
            "detection": detection,
            "falsepositives": self._falsepositives(raw),
            "level": level,
        }
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
        """Report the first condition token that names no defined block."""
        keywords = {"and", "or", "not", "of", "them", "all", "1", "any", "selection"}
        tokens = {token.strip("()|") for token in condition.replace("(", " ").replace(")", " ").split()}
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
    def _logsource_block(category: str, platforms: List[str]) -> Dict[str, str]:
        block: Dict[str, str] = {"category": category}
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
            return sorted(set(cleaned))

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

    def _build_prompt(self, input_data: SigmaGenerationInput, logsource: str) -> str:
        indicator_block = self._render_indicators(input_data.indicators)
        techniques = ", ".join(input_data.techniques) or "(none supplied)"
        platforms = ", ".join(input_data.platforms) or "(unspecified)"
        fields = _LOGSOURCE_FIELDS.get(logsource, "(use the standard Sigma fields for this category)")

        return f"""You are a detection engineer drafting one Sigma rule for a threat hunt.

HUNT HYPOTHESIS:
{input_data.hypothesis}

JUSTIFICATION:
{input_data.justification or "(none supplied)"}

ATT&CK TECHNIQUES: {techniques}
PLATFORMS: {platforms}

INDICATORS FROM THE SOURCE INTELLIGENCE:
{indicator_block}

Write EXACTLY ONE rule, for this Sigma log source category and no other:
    {logsource}

Fields available in {logsource}: {fields}

RULES OF THE TASK:
1. Return JSON only. Do NOT write YAML - the caller renders it.
2. Use only field names that exist in {logsource}. A field borrowed from
   another category matches nothing and fails silently at conversion.
3. Prefer the concrete indicators above over generic patterns. A rule that
   matches the actual C2 hostnames or the actual masquerading path is worth
   more than one matching "suspicious command line".
4. Where you must generalise, express the *behaviour* the hypothesis
   describes, not a restatement of the indicator list.
5. Every `detection` MUST contain a `condition` key. It is not optional, and
   it may only name selection blocks you defined in the same rule. If you
   define both a selection and a filter, say so explicitly, e.g.
   "selection and not filter".
6. Give realistic falsepositives. "None" is never a correct answer.
7. The JSON below shows the *shape* only. Its values are placeholders, not
   examples to copy: "FieldName", "value" and "known-good" must never appear
   in what you return, and a rule matching on them is rejected. Neither may
   invented stand-ins of your own -- "bad_command", "malicious.exe",
   "evil.com" or anything under example.com. Every value you emit must be an
   indicator from above, or a real path, process or registry key.

Return exactly this JSON shape, with a single entry in "rules":
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
}}"""

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
