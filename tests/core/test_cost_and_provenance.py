"""Cost and provenance quality gates (deep-dive item #11)."""

from typing import Any, Dict, List

import pytest
import yaml

from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchOutput, ResearchSkillOutput
from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent, rule_provenance
from hecate_agent.commands.research import _generate_research_markdown
from hecate_agent.core.cost_tracker import format_cost, summarize_cost

QWEN = "qwen3:30b-a3b-instruct-2507-q4_K_M"
REPORT = "https://report.example/vshell"
LOADER = "81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30"
RECORDS: List[Dict[str, Any]] = [
    {
        "value": LOADER,
        "type": "sha256",
        "role": "executable",
        "status": "active",
        "confidence": "unknown",
        "source": REPORT,
        "evidence": f"Go loader SHA-256 {LOADER}",
    },
    {
        "value": "38.207.178.192",
        "type": "ipv4",
        "role": "c2",
        "status": "active",
        "confidence": "high",
        "source": REPORT,
        "evidence": "HIGH confidence 38.207.178[.]192:50812 SNOWLIGHT check-in",
        "ports": [50812],
    },
    {
        "value": "http://38.207.178.192:50813/MySQL_LOG.txt",
        "type": "url",
        "role": "download",
        "status": "active",
        "confidence": "high",
        "source": REPORT,
        "evidence": "downloads a real Word document from http://38.207.178[.]192:50813/MySQL_LOG.txt",
    },
    {"value": "pan.qlam.cc", "type": "hostname", "role": "historical", "status": "historical", "source": REPORT},
]


# --- Cost ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("models", "calls", "tokens_in", "tokens_out", "cost", "expected", "basis"),
    [
        ([QWEN], 4, 14815, 1954, 0.0, None, "not priced: local model"),
        (["claude-sonnet-4-5"], 2, 0, 0, 0.0, None, "unknown: the provider reported no token usage"),
        (["claude-sonnet-4-5"], 2, 1000, 500, 0.0105, 0.0105, "estimated from token usage and list prices"),
        (["brand-new-model"], 1, 1000, 1000, 0.018, 0.018, "estimated with fallback pricing"),
        ([], 0, 0, 0, 0.0, 0.0, "no model calls"),
    ],
)
def test_zero_is_only_reported_when_it_is_known(models, calls, tokens_in, tokens_out, cost, expected, basis) -> None:  # type: ignore
    value, why = summarize_cost(models, calls, tokens_in, tokens_out, cost)
    assert value == expected and why.startswith(basis)


def test_agent_usage_reports_a_local_models_cost_as_unknown() -> None:
    agent = HuntResearcherAgent(llm_enabled=False)
    agent._log_llm_metrics("hunt-researcher", QWEN, 14815, 1954, 0.0, 1000)
    usage = agent._llm_usage_metadata()
    assert usage["estimated_cost_usd"] is None
    assert "no per-token price" in usage["cost_basis"]


def _skill(name: str) -> ResearchSkillOutput:
    return ResearchSkillOutput(skill_name=name, summary="s", key_findings=[], sources=[], confidence=0.5)


def test_the_research_document_says_unknown_not_zero() -> None:
    """R-0616 printed "Total Cost: $0.0000" for four calls to a local model."""
    _, basis = summarize_cost([QWEN], 4, 14815, 1954, 0.0)
    output = ResearchOutput(
        research_id="R-0001",
        topic="t",
        mitre_techniques=[],
        system_research=_skill("system_research"),
        adversary_tradecraft=_skill("adversary_tradecraft"),
        telemetry_mapping=_skill("telemetry_mapping"),
        related_work=_skill("related_work"),
        synthesis=_skill("synthesis"),
        llm_calls=4,
        input_tokens=14815,
        output_tokens=1954,
        total_cost_usd=None,
        cost_basis=basis,
    )
    appendix = _generate_research_markdown(output).split("## Appendix: Research Metrics", 1)[1]
    assert "- Tokens: 14,815 input, 1,954 output" in appendix
    assert f"- Total Cost: unknown (not priced: local model ({QWEN})" in appendix
    assert "$0.0000" not in appendix


def test_format_cost() -> None:
    assert format_cost(None, "x") == "unknown (x)"
    assert format_cost(0.0123, "list prices") == "$0.0123 (list prices)"


# --- Provenance ------------------------------------------------------------------------------


def _input(**kwargs: Any) -> SigmaGenerationInput:
    return SigmaGenerationInput(hypothesis="x", platforms=["Windows"], hunt_id="H-0001", references=[REPORT], **kwargs)


def test_every_ioc_rule_says_where_its_indicators_came_from() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._ioc_rules_from_records(_input(indicator_records=RECORDS))
    provenance = {rule.logsource_category: yaml.safe_load(rule.rule_yaml)["hecate_provenance"] for rule, _ in built if rule}
    assert [(e["value"], e["role"], e["source"]) for e in provenance["process_creation"]] == [(LOADER, "executable", REPORT)]
    assert provenance["process_creation"][0]["evidence"] == f"Go loader SHA-256 {LOADER}"
    assert [e["value"] for e in provenance["network_connection"]] == ["38.207.178.192"]
    # The URL is traced by its path, not re-attached to the network rule by its host.
    assert [e["value"] for e in provenance["proxy"]] == ["http://38.207.178.192:50813/MySQL_LOG.txt"]
    assert all("pan.qlam.cc" not in str(p) for p in provenance.values())  # historical: no rule, no entry


def test_a_feed_value_the_source_never_described_is_marked_as_from_the_feed() -> None:
    detection = {"selection": {"DestinationIp": ["203.0.114.9"]}, "condition": "selection"}
    (entry,) = rule_provenance(detection, _input(indicators={"ipv4": ["203.0.114.9"]}))
    assert entry == {"value": "203.0.114.9", "type": "ipv4", "role": "unknown", "status": "unknown", "source": "cti feed"}


def test_a_model_rule_matching_a_published_hash_carries_its_provenance() -> None:
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    raw = {
        "logsource_category": "process_creation",
        "title": "Resume loader launching cmd.exe",
        "description": "The loader starts cmd.exe",
        "techniques": [],
        "detection": {
            "selection": {"Hashes|contains": f"SHA256={LOADER}", "Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
        "level": "high",
    }
    rule, problem = agent._build_rule(raw, _input(indicator_records=RECORDS, indicators={"sha256": [LOADER]}))
    assert problem is None and rule is not None
    (entry,) = yaml.safe_load(rule.rule_yaml)["hecate_provenance"]
    assert entry["value"] == LOADER and entry["role"] == "executable"
