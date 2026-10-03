"""Score a drafted hunt against a reviewed gold set.

A gold set (``evals/gold/*.yaml``) is the reviewed answer for one piece of CTI:
which techniques the source shows in use, which it rules out, the platform,
what each indicator is and where it may appear in a rule, statements the prose
must and must not make, and the detections a correct hunt contains. Scoring a
draft against it turns "this looks better" into a number that is comparable
across pipeline changes, because nothing here calls a model.

Every positive and every negative item is one check. Technique recall is also
reported on its own, always with its denominator: the gold set's reviewed list
of observed techniques, not whatever the draft happened to propose.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import yaml

# Shared with the Sigma generator, which rejects what this scores. H-0618's
# ``Image|contains: MySQL_LOG.txt`` is a non-executable image.
from hecate_agent.core.sigma_semantics import IMAGE_FIELDS as _IMAGE_FIELDS
from hecate_agent.core.sigma_semantics import NON_EXECUTABLE as _NON_EXECUTABLE
from hecate_agent.core.sigma_semantics import SIGMA_FIELDS
from hecate_agent.core.sigma_semantics import SUFFIX_CLAIM_RE as _SUFFIX_CLAIM_RE

SCHEMA = "hecate-gold/1"

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


@dataclass
class Check:
    dimension: str
    id: str
    passed: bool
    detail: str = ""


@dataclass
class GoldReport:
    case_id: str
    draft: str
    checks: List[Check] = field(default_factory=list)
    technique_hits: List[str] = field(default_factory=list)
    technique_denominator: int = 0
    acceptable_found: List[str] = field(default_factory=list)
    unreviewed_techniques: List[str] = field(default_factory=list)
    rules_scored: int = 0
    rules_source: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def score(self) -> float:
        return self.passed / self.total if self.total else 0.0

    @property
    def technique_recall(self) -> float:
        return len(self.technique_hits) / self.technique_denominator if self.technique_denominator else 0.0

    def dimensions(self) -> Dict[str, Tuple[int, int]]:
        """Dimension -> (passed, total), in the order checks were added."""
        out: Dict[str, Tuple[int, int]] = {}
        for check in self.checks:
            passed, total = out.get(check.dimension, (0, 0))
            out[check.dimension] = (passed + int(check.passed), total + 1)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "draft": self.draft,
            "score": round(self.score, 4),
            "passed": self.passed,
            "total": self.total,
            "technique_recall": {
                "hits": len(self.technique_hits),
                "denominator": self.technique_denominator,
                "value": round(self.technique_recall, 4),
                "matched": self.technique_hits,
            },
            "acceptable_found": self.acceptable_found,
            "unreviewed_techniques": self.unreviewed_techniques,
            "rules_scored": self.rules_scored,
            "rules_source": self.rules_source,
            "dimensions": {k: {"passed": p, "total": t} for k, (p, t) in self.dimensions().items()},
            "checks": [c.__dict__ for c in self.checks],
        }


# --- Loading ---------------------------------------------------------------------------------


def load_gold(path: Path) -> Dict[str, Any]:
    gold = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(gold, dict) or gold.get("schema") != SCHEMA:
        raise ValueError(f"{path} is not a {SCHEMA} gold set")
    return gold


def _split_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    if text.startswith("---"):
        _, front, body = text.split("---", 2)
        return yaml.safe_load(front) or {}, body
    return {}, text


def _prose(body: str) -> str:
    """The draft's own writing: without rule YAML, the quoted source CTI, or the grounding and evidence tables.

    The Primary Source Evidence table quotes the report verbatim. On the Redis
    botnet case its row for a file from a separate, historical directory
    ("deploy_meterpreter.sh Downloads and installs meterpreter.elf") was read
    as the draft claiming Meterpreter was installed.
    """
    body = _FENCE_RE.sub("", body)
    body = re.sub(r"(?ms)^### (Grounding|Primary Source Evidence)\b.*?(?=^### |^## |\Z)", "", body)
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(">"))


def _load_rules(draft_path: Path, hunt_id: str, body: str, queries_dir: Optional[Path]) -> Tuple[List[Dict[str, Any]], str]:
    """Rule files from queries/<hunt_id>/ when present, else the YAML blocks embedded in the draft."""
    if queries_dir is None:
        # hunts/<year>/<quarter>/<id>.md -> <workspace>/queries/<id>
        workspace = draft_path.resolve().parents[3] if len(draft_path.resolve().parents) > 3 else draft_path.parent
        queries_dir = workspace / "queries" / hunt_id
    files = sorted(queries_dir.glob("*.yml")) if queries_dir.is_dir() else []
    if files:
        return [yaml.safe_load(f.read_text(encoding="utf-8")) or {} for f in files], str(queries_dir)
    blocks = [yaml.safe_load(b) for b in re.findall(r"```yaml\n(.*?)```", body, re.DOTALL)]
    return [b for b in blocks if isinstance(b, dict) and "detection" in b], "embedded in draft"


# --- Rule inspection -------------------------------------------------------------------------


def _category(rule: Dict[str, Any]) -> str:
    return str((rule.get("logsource") or {}).get("category", "")).strip().lower()


def _blocks(rule: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    """Each selection map of a rule; a list of maps is OR-ed, so each map is its own block."""
    for name, block in (rule.get("detection") or {}).items():
        if name == "condition":
            continue
        for item in block if isinstance(block, list) else [block]:
            if isinstance(item, dict):
                yield item


def _values(raw: Any) -> List[str]:
    return [str(v) for v in raw] if isinstance(raw, list) else [str(raw)]


def _base(key: str) -> str:
    return str(key).split("|")[0].strip()


def _block_matches(block: Dict[str, Any], requirements: List[Dict[str, str]]) -> bool:
    for need in requirements:
        pattern = re.compile(need["value"])
        if not any(
            _base(key).lower() == need["field"].lower() and any(pattern.search(v) for v in _values(raw))
            for key, raw in block.items()
        ):
            return False
    return True


def _placed(rules: List[Dict[str, Any]], placement: str, value: str) -> bool:
    category, _, fld = placement.partition(".")
    needle = value.lower()
    for rule in rules:
        if _category(rule) != category.lower():
            continue
        for block in _blocks(rule):
            for key, raw in block.items():
                if _base(key).lower() == fld.lower() and any(needle in v.lower() for v in _values(raw)):
                    return True
    return False


def _rule_violations(rules: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Semantic defects any rule can have, whatever the case: field, image and description checks."""
    found: Dict[str, List[str]] = {"field-outside-category": [], "non-executable-image": [], "description-overclaims": []}
    for rule in rules:
        title = str(rule.get("title", "untitled"))
        category = _category(rule)
        allowed = {f.lower() for f in SIGMA_FIELDS.get(category, ())}
        has_suffix_logic = False
        for block in _blocks(rule):
            for key, raw in block.items():
                base = _base(key)
                modifiers = str(key).lower().split("|")[1:]
                if allowed and base.lower() not in allowed:
                    found["field-outside-category"].append(f"{title}: {base} is not a {category} field")
                for value in _values(raw):
                    if base.lower() in _IMAGE_FIELDS and value.strip("*").lower().endswith(_NON_EXECUTABLE):
                        found["non-executable-image"].append(f"{title}: {base} = {value!r}")
                    if value.startswith(("*", ".")):
                        has_suffix_logic = True
                if {"endswith", "contains"} & set(modifiers):
                    has_suffix_logic = True
        if _SUFFIX_CLAIM_RE.search(str(rule.get("description", ""))) and not has_suffix_logic:
            found["description-overclaims"].append(
                f"{title}: description promises subdomain/suffix matching; selection is exact"
            )
    return found


# --- Technique matching ----------------------------------------------------------------------


def _satisfies(draft_id: str, expected: Dict[str, Any]) -> bool:
    want = str(expected["id"]).upper()
    have = draft_id.upper()
    if have == want or have.startswith(want + "."):
        return True
    return bool(expected.get("accept_parent")) and "." in want and have == want.split(".")[0]


# --- Scoring ---------------------------------------------------------------------------------


def _score_techniques(report: GoldReport, gold: Dict[str, Any], drafted: List[str]) -> None:
    """Recall over the reviewed denominator, plus mappings the source rules out."""
    tech = gold.get("techniques") or {}
    observed = tech.get("observed") or []
    report.technique_denominator = len(observed)
    for expected in observed:
        match = next((d for d in drafted if _satisfies(d, expected)), None)
        if match:
            report.technique_hits.append(str(expected["id"]))
        detail = f"matched by {match}" if match else "not mapped"
        report.checks.append(Check("techniques", f"observed {expected['id']}", bool(match), detail))
    forbidden_ids = {str(b["id"]).upper() for b in tech.get("forbidden") or []}
    for bad in tech.get("forbidden") or []:
        bad_id = str(bad["id"]).upper()
        hit = any(d == bad_id or d.startswith(bad_id + ".") for d in drafted)
        report.checks.append(Check("techniques", f"forbidden {bad['id']}", not hit, bad.get("reason", "") if hit else ""))
    acceptable = {str(t).upper() for t in tech.get("acceptable") or []}
    for d in drafted:
        if any(_satisfies(d, e) for e in observed) or d in forbidden_ids or d.split(".")[0] in forbidden_ids:
            continue
        (report.acceptable_found if d in acceptable else report.unreviewed_techniques).append(d)


def _score_platform(report: GoldReport, gold: Dict[str, Any], drafted: List[str]) -> None:
    platforms = {p.lower() for p in drafted}
    plat = gold.get("platform") or {}
    for p in plat.get("expected") or []:
        report.checks.append(Check("platform", f"includes {p}", p.lower() in platforms))
    for p in plat.get("forbidden") or []:
        listed = p.lower() in platforms
        report.checks.append(Check("platform", f"excludes {p}", not listed, "unsupported by the sample" if listed else ""))


def _score_claims(report: GoldReport, gold: Dict[str, Any], prose: str) -> None:
    """Checked against the draft's own prose only."""
    claims = gold.get("claims") or {}
    for c in claims.get("required") or []:
        report.checks.append(Check("claims", f"states {c['id']}", bool(re.search(c["pattern"], prose))))
    for c in claims.get("forbidden") or []:
        m = re.search(c["pattern"], prose)
        detail = f"{m.group(0)!r}: {c.get('reason', '')}" if m else ""
        report.checks.append(Check("claims", f"avoids {c['id']}", m is None, detail))


def _score_indicators(report: GoldReport, gold: Dict[str, Any], rules: List[Dict[str, Any]]) -> None:
    """Where each artifact must, and must not, appear in a rule."""
    for ind in gold.get("indicators") or []:
        value = str(ind["value"])
        for placement in ind.get("expect") or []:
            report.checks.append(Check("indicators", f"{ind['role']} in {placement}", _placed(rules, placement, value)))
        for placement in ind.get("forbid") or []:
            placed = _placed(rules, placement, value)
            detail = f"{value} ({ind.get('status', '')})" if placed else ""
            report.checks.append(Check("indicators", f"{ind['role']} not in {placement}", not placed, detail))


def _score_detections(report: GoldReport, gold: Dict[str, Any], rules: List[Dict[str, Any]]) -> None:
    """Each expected detection, with same-selection-block AND semantics."""
    for det in gold.get("detections") or []:
        ok = any(
            _category(rule) == alt["category"].lower() and any(_block_matches(b, alt["require"]) for b in _blocks(rule))
            for alt in det.get("any_of") or []
            for rule in rules
        )
        report.checks.append(Check("detections", det["id"], ok, "" if ok else det.get("description", "")))


def score_draft(gold: Dict[str, Any], draft_path: Path, queries_dir: Optional[Path] = None) -> GoldReport:
    """Score one drafted hunt, and the rules drafted with it, against a gold set."""
    draft_path = Path(draft_path)
    front, body = _split_frontmatter(draft_path.read_text(encoding="utf-8"))
    hunt_id = str(front.get("hunt_id") or draft_path.stem)
    rules, rules_source = _load_rules(draft_path, hunt_id, body, queries_dir)
    report = GoldReport(
        case_id=str(gold.get("case_id")), draft=str(draft_path), rules_scored=len(rules), rules_source=rules_source
    )
    _score_techniques(report, gold, [str(t).upper() for t in front.get("techniques") or []])
    _score_platform(report, gold, [str(p) for p in front.get("platform") or []])
    _score_claims(report, gold, _prose(body))
    _score_indicators(report, gold, rules)
    _score_detections(report, gold, rules)
    for kind, hits in _rule_violations(rules).items():
        report.checks.append(Check("rule semantics", f"no {kind}", not hits, "; ".join(hits)))
    return report
