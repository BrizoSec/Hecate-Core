"""Observable and claim audit (deep-dive item #7)."""

import re
from pathlib import Path

import pytest
import yaml

from hecate_agent.core.claim_audit import audit_observables, audit_prose, soften_capability_claims

GOLD = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"
OBSERVED = {"T1036", "T1204.002", "T1497.001", "T1105", "T1140", "T1620", "T1573"}


@pytest.mark.parametrize(
    ("observable", "reason"),
    [
        ("<unknown executable name>", "placeholder"),
        ("Registry value [populate from report]", "placeholder"),
        ("Internal file transfers of files with similar SHA256 hashes", "similar hash"),
        ("process.cmd_line contains the sleep timer logic", "command line"),
        ("Command line shows CPU checks before the payload runs", "command line"),
        ("process.name: memfd_create", "API or system call"),
        ("file.name = VirtualAlloc", "API or system call"),
    ],
)
def test_an_unobservable_entry_is_removed_with_its_reason(observable: str, reason: str) -> None:
    kept, findings = audit_observables([observable], "observables")
    assert kept == []
    assert findings[0].action == "removed" and reason in findings[0].reason


@pytest.mark.parametrize(
    "observable",
    [
        "network_endpoint.port: 50812",
        "简历.exe launching cmd.exe, which opens a DOCX",
        "Outbound HTTP to 45.94.31.110 on port 50813",
        "process.cmd_line contains cmd.exe /c start",
    ],
)
def test_a_concrete_observable_is_kept(observable: str) -> None:
    assert audit_observables([observable], "observables") == ([observable], [])


def test_unsupported_persistence_is_softened_in_place() -> None:
    text, findings = soften_capability_claims("The chain enables persistent, stealthy access.", "justification", OBSERVED)
    assert text == "The chain could enable persistent (capability; not observed in the source), stealthy access."
    assert [(f.action, f.text) for f in findings] == [("softened", "enables persistent")]


def test_an_observed_persistence_technique_supports_the_claim() -> None:
    text = "A scheduled task maintains persistence."
    assert soften_capability_claims(text, "justification", OBSERVED | {"T1053.005"}) == (text, [])


def test_an_already_hedged_claim_is_left_alone() -> None:
    text = "Operators may later establish persistence on the host."
    assert soften_capability_claims(text, "justification", OBSERVED) == (text, [])


@pytest.mark.parametrize(
    ("claim", "label"),
    [
        ("The RAT enables exfiltration of documents.", "exfiltration"),
        ("Access allows lateral movement to file servers.", "lateral movement"),
        ("The implant performs credential dumping.", "credential theft"),
    ],
)
def test_other_capability_claims_are_softened(claim: str, label: str) -> None:
    text, findings = soften_capability_claims(claim, "behavior", OBSERVED)
    assert text.count("could ") == 1 and findings[0].reason.startswith(label)


def test_fileless_is_corrected_only_when_the_loader_is_on_disk() -> None:
    fields = {"behavior": "Fileless execution via Go loader with sandbox evasion"}
    corrected, findings = audit_prose(fields, OBSERVED, on_disk_executable=True)
    assert corrected["behavior"] == "In-memory execution via Go loader with sandbox evasion"
    assert findings[0].action == "corrected"
    assert audit_prose(fields, OBSERVED, on_disk_executable=False) == (fields, [])


def test_the_h0618_prose_passes_the_gold_claim_checks_after_the_audit() -> None:
    """The three claims the #1-#4 replay failed, as the model wrote them."""
    fields = {
        "hypothesis": "Adversaries use a fileless execution chain via a Go loader with sandbox evasion.",
        "justification": "Fileless execution via the SNOWLIGHT stager enables persistent, stealthy access.",
        "behavior": "Fileless execution via Go loader with sandbox evasion",
    }
    forbidden = {c["id"]: c["pattern"] for c in yaml.safe_load(GOLD.read_text(encoding="utf-8"))["claims"]["forbidden"]}
    before = " ".join(fields.values())
    after = " ".join(audit_prose(fields, OBSERVED, on_disk_executable=True)[0].values())
    for claim in ("persistence-as-fact", "fileless-go-loader"):
        assert re.search(forbidden[claim], before) and not re.search(forbidden[claim], after)


def test_a_participle_is_softened_as_a_participle() -> None:
    """H-0618 replay: "..., enabling ... lateral movement" became "..., could enable ..."."""
    text, _ = soften_capability_claims(
        "It delivers VShell via sleep timers, enabling file access and lateral movement.", "hypothesis", OBSERVED
    )
    assert "sleep timers, potentially enabling file access and lateral movement (capability;" in text


def test_an_infinitive_is_softened_as_an_infinitive() -> None:
    """H-0618 replay: "... to achieve persistent access" became "to could achieve"."""
    text, _ = soften_capability_claims("It targets universities to achieve persistent access.", "hypothesis", OBSERVED)
    assert "to potentially achieve persistent (capability;" in text


def test_a_bare_api_name_is_not_an_observable() -> None:
    """The A3 replay listed "Beep" on its own as something suspicious to look for."""
    kept, findings = audit_observables(["Beep", "cmd.exe"], "observables")
    assert kept == ["cmd.exe"] and "only EDR API telemetry" in findings[0].reason


def test_values_the_pipeline_knows_are_unobservable_are_removed_with_the_reason() -> None:
    memory_only = "c666ac4f1a1b8df7ccfe8b19705279acd8b7eb7a4d0b3802bb3465064883ab25"
    kept, findings = audit_observables(
        [memory_only.upper(), "personal_resume.exe", "cmd.exe"],
        "observables",
        {memory_only: "exists only in memory", "personal_resume.exe": "the source does not tie it to this intrusion"},
    )
    assert kept == ["cmd.exe"]
    assert [f.reason for f in findings] == ["exists only in memory", "the source does not tie it to this intrusion"]
