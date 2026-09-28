"""Behaviour-to-technique mapping, gated on observed use (deep-dive item #4)."""

from pathlib import Path
from typing import Dict

import pytest
import yaml

from hecate_agent.core.technique_evidence import map_behaviours, sentence_status, sentences, technique_support

GOLD = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"


def _observed(text: str) -> Dict[str, str]:
    return {e.technique_id: e.passage for e in map_behaviours([("cti", text)]) if e.status == "observed"}


@pytest.mark.parametrize(
    ("sentence", "technique"),
    [
        ("The loader checks for a sandbox and needs at least four logical processors.", "T1497.001"),
        ("It verifies a ten-second sleep timer before continuing.", "T1497.003"),
        ("The stager XOR-decodes the payload with key 0x99.", "T1140"),
        ("It downloads 4.65 MB of data from the server.", "T1105"),
        ("A Chinese-language executable disguised as a resume was sent to researchers.", "T1204.002"),
        ("The executable launches cmd.exe, which opens Word.", "T1059.003"),
        ("It connects over a raw TCP channel to the operator.", "T1095"),
        ("Frames use AES-GCM with a 12-byte nonce.", "T1573"),
        ("The loader uses HTTP staging on port 50813.", "T1071.001"),
        ("It allocates memory, copies the downloaded bytes, marks them executable, creates a thread and waits.", "T1620"),
        ("A scheduled task named MicrosoftIME keeps it running.", "T1053.005"),
        ("The payload is injected into explorer via process hollowing.", "T1055.012"),
    ],
)
def test_described_behaviour_maps_to_its_technique(sentence: str, technique: str) -> None:
    assert technique in _observed(sentence)


def test_a_capability_list_is_not_observed_use() -> None:
    """H-0618: T1113 came from what VShell offers, not what the intrusion did."""
    text = "The RAT provides operators with command execution, file access, screen capture and lateral movement capabilities."
    evidence = {e.technique_id: e.status for e in map_behaviours([("cti", text)])}
    assert evidence == {"T1113": "capability"}


@pytest.mark.parametrize(
    "sentence",
    [
        "Give an operator quiet access to the workstation: command execution and screen capture.",
        "Public VShell analysis documents: screenshot capture and interactive screen access.",
    ],
)
def test_purpose_and_documentation_framing_is_capability(sentence: str) -> None:
    assert sentence_status(sentence) == "capability"


def test_a_feature_list_after_enabling_is_capability() -> None:
    """H-0618 replay: independent research's feature list mapped T1113 as observed."""
    text = (
        "The final payload is a fileless VShell RAT, executed entirely in memory without persistence, "
        "enabling command execution, file access, screen capture, and lateral movement."
    )
    assert "T1113" not in _observed(text)


def test_a_negation_rules_the_behaviour_out() -> None:
    assert "T1113" not in _observed("Not observed: an operator taking a screen capture.")


def test_another_actors_tradecraft_is_context_not_evidence() -> None:
    text = "UAT-8302 used Windows SNOWLIGHT, government intrusions, sideloading and different malware; no lure match."
    assert map_behaviours([("primary source", text)]) == []


def test_a_bare_fileless_label_does_not_establish_reflective_loading() -> None:
    assert "T1620" not in _observed("It launches a fileless VShell RAT.")


def test_label_lines_are_not_evidence() -> None:
    text = "OTX Pulse: A fake resume installed VShell\nTags: sandbox evasion, fileless execution\nDescription: prose."
    assert _observed(text) == {}


def test_scraped_inline_elements_are_rejoined_into_sentences() -> None:
    assert sentences("The sandbox showed the executable launching\ncmd.exe\n, opening a DOCX.") == [
        "The sandbox showed the executable launching cmd.exe, opening a DOCX."
    ]


def test_an_observed_passage_outranks_a_capability_one() -> None:
    text = "VShell offers screen capture. In this intrusion the operator took a screen capture of the desktop."
    evidence = map_behaviours([("cti", text)])
    assert [(e.technique_id, e.status) for e in evidence] == [("T1113", "observed")]
    assert evidence[0].passage.startswith("In this intrusion")


def test_technique_support_by_name_reports_capability_only_mentions() -> None:
    text = "The tool offers credential dumping and keylogging to its operators."
    support = technique_support("T1056.001", ["Keylogging"], text)
    assert support is not None and support.status == "capability"
    assert technique_support("T1056.001", ["Keylogging"], "Nothing relevant here.") is None


def test_the_vshell_cti_maps_only_observed_techniques() -> None:
    """On the OTX blurb alone: six gold techniques, none forbidden, T1113 capability only."""
    gold = yaml.safe_load(GOLD.read_text(encoding="utf-8"))
    evidence = map_behaviours([("cti", gold["source"]["cti"])])
    observed = {e.technique_id for e in evidence if e.status == "observed"}
    expected = {t["id"] for t in gold["techniques"]["observed"]}
    forbidden = {t["id"] for t in gold["techniques"]["forbidden"]}
    assert observed == {"T1036", "T1105", "T1140", "T1204.002", "T1497.001", "T1497.003"}
    assert observed <= expected and not observed & forbidden
    assert {e.technique_id for e in evidence if e.status == "capability"} == {"T1113"}
    assert all(e.passage for e in evidence)
