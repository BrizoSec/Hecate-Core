"""Quality gates for the LangGraph path, matching the ones Hecate-Runner applies.

The Runner drops model-picked techniques no source describes, parks an item
left with nothing to hunt, and audits every draft's claims against the
source. The graph wrote H-0000 with none of that: T1078 and T1546 on a Teams
vishing report that names neither. These functions carry the same checks,
built on ``grounding`` (the Runner's module, kept here because the Runner
depends on Hecate-Core and not the other way round).
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from hecate_agent.core.grounding import (
    GroundingReport,
    TechniqueFact,
    audit_draft,
    render_grounding_section,
    technique_lacks_evidence,
)

logger = logging.getLogger(__name__)

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
#: Research documents cite retrieved pages; a page title is not evidence
#: ("OAuth Traps" once kept T1546.005 Trap on a Teams vishing hunt).
_LINK_RE = re.compile(r"\[[^\]]*\]\([^)]*\)|https?://\S+")
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: Looks a technique up in ATT&CK: returns ``{"found": bool, "name": str, ...}``.
Lookup = Callable[[str], Dict[str, object]]
#: Techniques whose names the text uses as a phrase: ``[(id, name), ...]``.
Candidates = Callable[[str], List[Tuple[str, str]]]


def strip_links(text: str) -> str:
    return _LINK_RE.sub(" ", text or "")


def has_indicators(*texts: str) -> bool:
    """True when the intel publishes a hash or IP address, i.e. an indicator sweep is still possible."""
    return any(_HASH_RE.search(t or "") or _IPV4_RE.search(t or "") for t in texts)


@dataclass
class TechniqueDecision:
    kept: List[str] = field(default_factory=list)
    dropped_unevidenced: List[str] = field(default_factory=list)
    dropped_unknown: List[str] = field(default_factory=list)
    wording_matched: List[str] = field(default_factory=list)
    facts: Dict[str, TechniqueFact] = field(default_factory=dict)


def _technique_names(technique_id: str, meta: Dict[str, object], lookup: Lookup) -> Tuple[str, ...]:
    names = [str(meta.get("name") or "")]
    if "." in technique_id:
        try:
            names.append(str(lookup(technique_id.split(".")[0]).get("name") or ""))
        except Exception:  # the parent name only widens the evidence check
            pass
    return tuple(n for n in names if n)


def filter_techniques(
    techniques: List[str],
    *,
    cti_text: str,
    research_text: str,
    lookup: Lookup,
    candidates: Candidates,
) -> TechniqueDecision:
    """Keep the techniques the intel supports; drop model picks no source describes.

    A technique the CTI names by ID, or whose name the CTI's own wording uses,
    is never dropped. Wording matches are also added, as the Runner does,
    because the model reliably ignores them when they are only offered.
    """
    decision = TechniqueDecision()
    asserted = {t.upper() for t in _TECHNIQUE_ID_RE.findall(cti_text or "")}
    try:
        matched = candidates("\n".join([cti_text or "", strip_links(research_text)]))
    except Exception as e:  # candidates are an aid; never fatal
        logger.warning(f"Candidate technique matching failed ({e}); continuing without it")
        matched = []
    decision.wording_matched = [tid.upper() for tid, _ in matched]
    shielded = asserted | set(decision.wording_matched)

    ordered: List[str] = []
    for technique in [*sorted(asserted), *decision.wording_matched, *techniques]:
        upper = str(technique).strip().upper()
        if upper and upper not in ordered:
            ordered.append(upper)

    evidence_research = strip_links(research_text)
    for technique_id in ordered:
        try:
            meta = lookup(technique_id)
        except Exception as e:  # ATT&CK data unavailable: cannot judge, so keep
            logger.warning(f"Could not look up {technique_id} ({e}); keeping it unjudged")
            decision.kept.append(technique_id)
            continue
        if not meta.get("found"):
            decision.dropped_unknown.append(technique_id)
            decision.facts[technique_id] = TechniqueFact(valid=False)
            continue
        names = _technique_names(technique_id, meta, lookup)
        decision.facts[technique_id] = TechniqueFact(valid=True, names=names)
        shielded_here = technique_id in shielded or technique_id.split(".")[0] in shielded
        if not shielded_here and technique_lacks_evidence(technique_id, names, cti_text, evidence_research):
            decision.dropped_unevidenced.append(f"{technique_id} {names[0] if names else ''}".strip())
            continue
        decision.kept.append(technique_id)
    return decision


def park_reason(kept_techniques: List[str], *texts: str) -> Optional[str]:
    """Why a draft should not be written, or None when there is something to hunt."""
    if kept_techniques or has_indicators(*texts):
        return None
    return "no ATT&CK technique survived grounding and the intel names no indicators"


def audit(
    *,
    draft_text: str,
    cti_text: str,
    research_text: str,
    facts: Dict[str, TechniqueFact],
    wording_matched: List[str],
) -> Tuple[GroundingReport, str]:
    """Audit a rendered draft against its sources; return the report and its markdown section."""
    report = audit_draft(
        draft_text=draft_text,
        cti_text=cti_text,
        research_text=strip_links(research_text),
        cti_techniques=sorted({t.upper() for t in _TECHNIQUE_ID_RE.findall(cti_text or "")}),
        technique_facts=facts,
        matched_techniques=wording_matched,
    )
    return report, render_grounding_section(report)
