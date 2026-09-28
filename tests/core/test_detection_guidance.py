"""The source's detection guidance as cited, routed candidate analytics (deep-dive item #8)."""

from typing import Any, Dict, List

import pytest

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.detection_guidance import classify, extract_guidance, sigma_candidates
from hecate_agent.core.sigma_semantics import semantic_problem

#: The VShell report's detection section as page extraction returns it: every
#: inline element on its own line, lone commas included.
SCRAPED = """final paragraph of the analysis.
detection and hunting
⌗
network
⌗
Block or investigate:
38.207.178[.]192:50812
38.207.178[.]192:50813
High-signal SNOWLIGHT check-in:
77 33 32 20 20 20 c6 7c 33 38 2e 32 30 37 2e 31
37 38 2e 31 39 32 00 00 00 00 00 00 00 00 00 00
This is
w32
, network-order port
50812
, the ASCII IP and zero-filled fields.
endpoint
⌗
Hunt for:
%TEMP%\\log_de.log
Resume-themed executables launching
cmd.exe
and then Word
AllocADsMem
or
ReallocADsMem
followed by
VirtualProtect
and
CreateThread
Processes allocating tens of megabytes as executable memory immediately after a large raw TCP receive
Outbound TCP beginning with six-byte architecture tags such as
w32
,
w64
or
a64
iocs
⌗
Go loader SHA-256
81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30
"""

REPORT = "https://report.example/vshell"


def _by_text() -> Dict[str, Any]:
    return {g.text: g for g in extract_guidance(SCRAPED, REPORT)}


def test_items_are_rebuilt_whole_and_the_ioc_list_is_not_guidance() -> None:
    assert list(_by_text()) == [
        "38.207.178.192:50812",
        "38.207.178.192:50813",
        "High-signal SNOWLIGHT check-in: 77 33 32 20 20 20 c6 7c 33 38 2e 32 30 37 2e 31 37 38 2e 31 39 32 00 00 00 00 00 00 "
        "00 00 00 00 This is w32, network-order port 50812, the ASCII IP and zero-filled fields.",
        "%TEMP%\\log_de.log",
        "Resume-themed executables launching cmd.exe and then Word",
        "AllocADsMem or ReallocADsMem followed by VirtualProtect and CreateThread",
        "Processes allocating tens of megabytes as executable memory immediately after a large raw TCP receive",
        "Outbound TCP beginning with six-byte architecture tags such as w32, w64 or a64",
    ]


@pytest.mark.parametrize(
    ("text", "route"),
    [
        ("38.207.178.192:50812", "indicator"),
        ("%TEMP%\\log_de.log", "sigma"),
        ("Resume-themed executables launching cmd.exe and then Word", "sigma"),
        ("AllocADsMem or ReallocADsMem followed by VirtualProtect and CreateThread", "edr"),
        ("Processes allocating tens of megabytes as executable memory immediately after a large raw TCP receive", "edr"),
        ("Go binaries with an invalid or hash-mismatched certificate and document-style names", "edr"),
        ("Outbound TCP beginning with six-byte architecture tags such as w32, w64 or a64", "network-content"),
        ("Talk to the help desk about odd logins", "review"),
    ],
)
def test_each_item_is_routed_to_the_telemetry_that_can_see_it(text: str, route: str) -> None:
    assert classify(text)["route"] == route


def test_every_item_cites_the_source_and_keeps_its_section() -> None:
    items = extract_guidance(SCRAPED, REPORT)
    assert all(g.source == REPORT for g in items)
    assert _by_text()["%TEMP%\\log_de.log"].section == "endpoint"
    assert _by_text()["%TEMP%\\log_de.log"].lead == "Hunt for"


def test_a_report_without_a_detection_section_has_no_guidance() -> None:
    assert extract_guidance("An analysis with IOCs only.\niocs\n1.2.3.4\n", REPORT) == []


def test_a_launch_chain_becomes_one_rule_per_event_in_the_sources_direction() -> None:
    """H-0618's model wrote Word launching cmd.exe; the source says the reverse."""
    candidates = sigma_candidates("Resume-themed executables launching cmd.exe and then Word")
    assert [c["detection"]["selection"] for c in candidates] == [
        {"ParentImage|contains": "resume", "Image|endswith": "\\cmd.exe"},
        {"ParentImage|endswith": "\\cmd.exe", "Image|endswith": "\\winword.exe"},
    ]
    assert "correlation" in candidates[1]["note"]


def test_a_file_under_an_environment_variable_matches_what_follows_it() -> None:
    (candidate,) = sigma_candidates("%TEMP%\\log_de.log")
    assert candidate["category"] == "file_event"
    assert candidate["detection"]["selection"] == {"TargetFilename|endswith": "\\log_de.log"}
    assert "EDR file-access" in candidate["note"]


def test_every_candidate_passes_the_semantic_gate() -> None:
    for item in extract_guidance(SCRAPED, REPORT):
        for c in item.candidates:
            assert semantic_problem(c["detection"], c["category"], item.text) is None


def _input(guidance: List[Dict[str, Any]], platforms: List[str]) -> SigmaGenerationInput:
    return SigmaGenerationInput(hypothesis="x", platforms=platforms, detection_guidance=guidance, hunt_id="H-0001")


def test_guidance_rules_quote_and_cite_the_source() -> None:
    guidance = [g.to_dict() for g in extract_guidance(SCRAPED, REPORT)]
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._guidance_rules(_input(guidance, ["Windows"]))
    rules = [r for r, problem in built if r is not None]
    assert len(rules) == 3 and all(problem is None for _, problem in built)
    chain = next(r for r in rules if "launching winword.exe" in r.title)
    assert chain.title == "Source guidance G5: cmd.exe launching winword.exe"
    assert '"Resume-themed executables launching cmd.exe and then Word"' in chain.rule_yaml
    assert REPORT in chain.rule_yaml and "level: medium" in chain.rule_yaml


def test_windows_guidance_is_not_drafted_for_a_non_windows_hunt() -> None:
    guidance = [g.to_dict() for g in extract_guidance(SCRAPED, REPORT)]
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    built = agent._guidance_rules(_input(guidance, ["Linux"]))
    assert built and all(rule is None and "non-Windows" in str(problem) for rule, problem in built)


def test_the_prompt_carries_the_guidance_so_a_model_rule_does_not_contradict_it() -> None:
    guidance = [g.to_dict() for g in extract_guidance(SCRAPED, REPORT)]
    block = SigmaGeneratorAgent._render_guidance(_input(guidance, ["Windows"]))
    assert '"Resume-themed executables launching cmd.exe and then Word"' in block
    assert "reversing a parent/child chain" in block
    assert "AllocADsMem" not in block  # EDR guidance is not offered as a Sigma target


def test_a_model_rule_may_not_reverse_the_guidance_chain() -> None:
    """Replay after replay the model wrote Word launching cmd.exe; the source says cmd.exe launches Word."""
    guidance = [g.to_dict() for g in extract_guidance(SCRAPED, REPORT)]
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    raw = {
        "logsource_category": "process_creation",
        "title": "Word spawning cmd",
        "description": "Detects Word starting cmd.exe",
        "detection": {
            "selection": {"ParentImage|endswith": "\\winword.exe", "Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
    }
    rule, problem = agent._build_rule(raw, _input(guidance, ["Windows"]))
    assert rule is None and "the source's guidance says the reverse" in str(problem)
    raw["detection"]["selection"] = {"ParentImage|endswith": "\\cmd.exe", "Image|endswith": "\\winword.exe"}
    raw["description"] = "Detects cmd.exe starting Word"
    rule, problem = agent._build_rule(raw, _input(guidance, ["Windows"]))
    assert problem is None and rule is not None
