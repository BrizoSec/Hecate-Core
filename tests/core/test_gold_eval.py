"""Gold-set scoring: every positive and negative check, and the H-0618 baseline."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from click.testing import CliRunner

from hecate_agent.core.gold_eval import load_gold, score_draft

REPO = Path(__file__).resolve().parents[2]
GOLD = REPO / "evals" / "gold" / "vshell-fake-resume.yaml"
FIXTURE = REPO / "tests" / "fixtures" / "gold" / "vshell-fake-resume"

GOLD_MIN: Dict[str, Any] = {
    "schema": "hecate-gold/1",
    "case_id": "unit",
    "platform": {"expected": ["Windows"], "forbidden": ["Linux"]},
    "techniques": {
        "observed": [
            {"id": "T1059.003"},
            {"id": "T1497.001", "accept_parent": True},
            {"id": "T1573"},
        ],
        "acceptable": ["T1027"],
        "forbidden": [{"id": "T1113", "reason": "capability only"}],
    },
    "claims": {
        "required": [{"id": "xor", "pattern": "0x99"}],
        "forbidden": [{"id": "persistence", "pattern": "(?i)enables persistence", "reason": "not observed"}],
    },
    "indicators": [
        {"value": "aa" * 32, "role": "loader", "expect": ["process_creation.Hashes"]},
        {"value": "bb" * 32, "role": "shellcode", "forbid": ["process_creation.Hashes"]},
        {"value": "old.example.net", "role": "historical", "forbid": ["dns_query.QueryName"]},
    ],
    "detections": [
        {
            "id": "c2-port",
            "any_of": [
                {
                    "category": "network_connection",
                    "require": [
                        {"field": "DestinationIp", "value": "^10\\.1\\.1\\.1$"},
                        {"field": "DestinationPort", "value": "^50812$"},
                    ],
                }
            ],
        }
    ],
}


def _draft(
    tmp_path: Path,
    *,
    techniques: List[str],
    platform: List[str],
    body: str = "",
    rules: Optional[List[str]] = None,
) -> Path:
    """A workspace-shaped draft: hunts/2026/Q3/H-0900.md with rules in queries/H-0900/."""
    hunt = tmp_path / "hunts" / "2026" / "Q3" / "H-0900.md"
    hunt.parent.mkdir(parents=True)
    hunt.write_text(
        "---\nhunt_id: H-0900\n" f"platform: {json.dumps(platform)}\ntechniques: {json.dumps(techniques)}\n---\n\n{body}\n",
        encoding="utf-8",
    )
    if rules is not None:
        qdir = tmp_path / "queries" / "H-0900"
        qdir.mkdir(parents=True)
        for i, rule in enumerate(rules):
            (qdir / f"r{i}.yml").write_text(rule, encoding="utf-8")
    return hunt


def _check(report: Any, check_id: str) -> Any:
    return next(c for c in report.checks if c.id == check_id)


def _rule(category: str, detection: str, description: str = "x") -> str:
    return f"title: {category} rule\ndescription: {description}\nlogsource:\n  category: {category}\ndetection:\n{detection}"


# --- Techniques and the recall denominator ---------------------------------------------------


def test_recall_is_reported_over_the_gold_denominator(tmp_path: Path) -> None:
    draft = _draft(tmp_path, techniques=["T1059.003", "T1113", "T1027", "T1999"], platform=["Windows"])
    report = score_draft(GOLD_MIN, draft)
    assert report.technique_denominator == 3
    assert report.technique_hits == ["T1059.003"]
    assert _check(report, "forbidden T1113").passed is False
    assert report.acceptable_found == ["T1027"]
    assert report.unreviewed_techniques == ["T1999"]


def test_sub_technique_satisfies_a_parent_but_a_parent_needs_accept_parent(tmp_path: Path) -> None:
    draft = _draft(tmp_path, techniques=["T1573.001", "T1497"], platform=["Windows"])
    report = score_draft(GOLD_MIN, draft)
    assert set(report.technique_hits) == {"T1573", "T1497.001"}

    strict = json.loads(json.dumps(GOLD_MIN))
    strict["techniques"]["observed"][1].pop("accept_parent")
    assert "T1497.001" not in score_draft(strict, draft).technique_hits


# --- Platform and claims ---------------------------------------------------------------------


def test_platform_expected_and_forbidden(tmp_path: Path) -> None:
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Linux", "Windows"]))
    assert _check(report, "includes Windows").passed is True
    assert _check(report, "excludes Linux").passed is False


def test_claims_ignore_the_quoted_cti_rule_yaml_and_grounding(tmp_path: Path) -> None:
    """The source CTI must not satisfy or violate a claim on the draft's behalf."""
    body = (
        "> Source says XOR key 0x99 and it enables persistence\n\n"
        "```yaml\ndescription: enables persistence 0x99\n```\n\n"
        "### Grounding\n\n| `0x99` | indicator |\n\n### Next\n\nPlain prose.\n"
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], body=body))
    assert _check(report, "states xor").passed is False
    assert _check(report, "avoids persistence").passed is True


def test_claims_ignore_passages_quoted_in_the_evidence_table(tmp_path: Path) -> None:
    """A verbatim source passage in the evidence table is the report's wording, not the draft's."""
    body = (
        "### Primary Source Evidence\n\n| `kit.sh` | file_path | unknown | historical | "
        '"XOR key 0x99; it enables persistence" |\n\n### Justification\n\nPlain prose.\n'
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], body=body))
    assert _check(report, "states xor").passed is False
    assert _check(report, "avoids persistence").passed is True


def test_claims_in_the_drafts_own_prose_count(tmp_path: Path) -> None:
    body = "The payload is XOR-decoded with 0x99, which enables persistence."
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], body=body))
    assert _check(report, "states xor").passed is True
    assert _check(report, "avoids persistence").passed is False


# --- Indicator roles -------------------------------------------------------------------------


def test_indicators_are_placed_only_where_their_role_allows(tmp_path: Path) -> None:
    hashes = _rule(
        "process_creation",
        f"  selection:\n    Hashes|contains:\n    - SHA256={'aa' * 32}\n    - SHA256={'bb' * 32}\n  condition: selection",
    )
    dns = _rule("dns_query", "  selection:\n    QueryName: old.example.net\n  condition: selection")
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], rules=[hashes, dns]))
    assert _check(report, "loader in process_creation.Hashes").passed is True
    assert _check(report, "shellcode not in process_creation.Hashes").passed is False
    assert _check(report, "historical not in dns_query.QueryName").passed is False


# --- Detections: same selection block is an AND ----------------------------------------------


def test_a_detection_needs_every_field_in_one_selection_block(tmp_path: Path) -> None:
    together = _rule(
        "network_connection",
        "  selection:\n    DestinationIp: 10.1.1.1\n    DestinationPort: 50812\n  condition: selection",
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], rules=[together]))
    assert _check(report, "c2-port").passed is True


def test_fields_split_across_or_ed_blocks_do_not_satisfy_a_detection(tmp_path: Path) -> None:
    split = _rule(
        "network_connection",
        "  sel_ip:\n    DestinationIp: 10.1.1.1\n  sel_port:\n    DestinationPort: 50812\n  condition: 1 of sel_*",
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], rules=[split]))
    assert _check(report, "c2-port").passed is False


# --- Rule semantics --------------------------------------------------------------------------


def test_rule_semantic_defects_are_each_a_failed_check(tmp_path: Path) -> None:
    bad_file = _rule(
        "file_event",
        "  selection:\n    Hashes|contains: abc\n    Image|contains: MySQL_LOG.txt\n  condition: selection",
    )
    overclaim = _rule(
        "dns_query",
        "  selection:\n    QueryName:\n    - a.example.org\n  condition: selection",
        description="Matches the domain or a subdomain of it",
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], rules=[bad_file, overclaim]))
    assert _check(report, "no field-outside-category").passed is False
    assert _check(report, "no non-executable-image").passed is False
    assert _check(report, "no description-overclaims").passed is False


def test_a_clean_rule_has_no_semantic_defects(tmp_path: Path) -> None:
    clean = _rule(
        "dns_query",
        "  selection:\n    QueryName|endswith: .example.org\n  condition: selection",
        description="Matches any subdomain of example.org",
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], rules=[clean]))
    assert all(c.passed for c in report.checks if c.dimension == "rule semantics")


def test_rules_embedded_in_the_draft_are_scored_when_no_rule_files_exist(tmp_path: Path) -> None:
    body = (
        "```yaml\n"
        + _rule(
            "network_connection",
            "  selection:\n    DestinationIp: 10.1.1.1\n    DestinationPort: 50812\n  condition: selection",
        )
        + "\n```\n"
    )
    report = score_draft(GOLD_MIN, _draft(tmp_path, techniques=[], platform=["Windows"], body=body))
    assert report.rules_source == "embedded in draft"
    assert _check(report, "c2-port").passed is True


def test_a_file_that_is_not_a_gold_set_is_rejected(tmp_path: Path) -> None:
    other = tmp_path / "x.yaml"
    other.write_text("schema: something-else\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_gold(other)


# --- The real gold set, and the H-0618 baseline ----------------------------------------------


def test_the_vshell_gold_set_is_well_formed() -> None:
    gold = load_gold(GOLD)
    observed = [t["id"] for t in gold["techniques"]["observed"]]
    assert len(observed) == len(set(observed)) == 11
    assert all(t.get("evidence") for t in gold["techniques"]["observed"])
    assert "T1113" in {t["id"] for t in gold["techniques"]["forbidden"]}
    assert len(gold["source"]["cti"].strip()) == 2194  # the exact CTI the pipeline received


def test_h0618_baseline_score_is_locked() -> None:
    """The draft reviewed in docs/H-0618_DEEP_DIVE.md. A change to the scorer or
    the gold set that moves these numbers must be deliberate."""
    report = score_draft(load_gold(GOLD), FIXTURE / "hunts" / "2026" / "Q3" / "H-0618.md.txt")
    assert (report.passed, report.total) == (24, 72)
    assert (report.technique_hits, report.technique_denominator) == (["T1036"], 11)
    assert report.rules_scored == 4
    assert report.dimensions() == {
        "techniques": (7, 18),
        "platform": (6, 7),
        "claims": (3, 13),
        "indicators": (6, 24),
        "detections": (2, 7),
        "rule semantics": (0, 3),
    }


def test_cli_json_and_fail_under() -> None:
    from hecate_agent.commands.eval import eval_gold_cmd

    draft = str(FIXTURE / "hunts" / "2026" / "Q3" / "H-0618.md.txt")
    result = CliRunner().invoke(eval_gold_cmd, [str(GOLD), draft, "--output", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["technique_recall"] == {"hits": 1, "denominator": 11, "value": 0.0909, "matched": ["T1036"]}

    assert CliRunner().invoke(eval_gold_cmd, [str(GOLD), draft, "--fail-under", "0.6"]).exit_code == 1
    assert CliRunner().invoke(eval_gold_cmd, [str(GOLD), draft, "--fail-under", "0.3"]).exit_code == 0


def test_the_macos_gold_set_is_well_formed() -> None:
    """The second case: written from the Huntress report before any pipeline run on it."""
    gold = load_gold(REPO / "evals" / "gold" / "macos-clickfix-stealer.yaml")
    assert gold["platform"]["expected"] == ["macOS"]
    assert len(gold["techniques"]["observed"]) == 12
    assert gold["source"]["cti"].startswith("OTX Pulse: Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam")
    observed = {t["id"] for t in gold["techniques"]["observed"]}
    forbidden = {t["id"] for t in gold["techniques"]["forbidden"]}
    assert not observed & forbidden and not observed & set(gold["techniques"]["acceptable"])
