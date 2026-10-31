"""Data models for Sigma rule generation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Files the operating system and its administrators also write. An actor's change to one is
#: real, but the path alone cannot tell it from routine use: every deterministic file rule was
#: "high", including one for root's crontab, which fires on any edit of it.
_SHARED_SYSTEM_FILE_RE = re.compile(
    r"(?i)(^|/)(var/spool/cron/(crontabs/)?[\w.-]+|etc/(crontab|rc\.local|passwd|shadow|sudoers|hosts|profile|environment"
    r"|ld\.so\.preload)|\.ssh/authorized_keys|\.(bashrc|zshrc|bash_profile|zprofile|profile))$"
)


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
    reference_candidates: List[Dict[str, Any]] = field(default_factory=list)
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
