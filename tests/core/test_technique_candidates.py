"""Deterministic ATT&CK candidates from a report's own wording."""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional

import pytest

from hecate_agent.core import attack_matrix
from hecate_agent.core.attack_matrix import FallbackProvider, TechniqueInfo
from hecate_agent.core.technique_candidates import candidate_techniques, format_candidates


def _t(tid: str, name: str, tactic: str) -> TechniqueInfo:
    return TechniqueInfo(id=tid, name=name, tactic_shortnames=[tactic])


_TECHNIQUES: Dict[str, TechniqueInfo] = {
    t["id"]: t
    for t in [
        _t("T1036", "Masquerading", "stealth"),
        _t("T1113", "Screen Capture", "collection"),
        _t("T1546.002", "Screensaver", "persistence"),
        _t("T1569.003", "Systemctl", "execution"),
        _t("T1124", "System Time Discovery", "discovery"),
        _t("T1207", "Rogue Domain Controller", "stealth"),
        _t("T1547.006", "Kernel Modules and Extensions", "persistence"),
        _t("T1583.001", "Domains", "resource-development"),
        _t("T1587.001", "Malware", "resource-development"),
        _t("T1127.001", "MSBuild", "stealth"),
    ]
}


class _FakeMatrix(FallbackProvider):
    def get_sorted_tactic_keys(self) -> List[str]:
        return sorted({t["tactic_shortnames"][0] for t in _TECHNIQUES.values()})

    def get_technique_by_id(self, technique_id: str) -> Optional[TechniqueInfo]:
        return _TECHNIQUES.get(technique_id.upper())

    def get_techniques_for_tactic(self, tactic_key: str) -> List[TechniqueInfo]:
        return [t for t in _TECHNIQUES.values() if tactic_key in t["tactic_shortnames"]]


@pytest.fixture(autouse=True)
def fake_matrix() -> Iterator[None]:
    attack_matrix.reset_provider(_FakeMatrix())
    yield
    attack_matrix.reset_provider(None)


def _ids(text: str) -> List[str]:
    return [tid for tid, _ in candidate_techniques(text)]


def test_a_named_behavior_is_proposed() -> None:
    """H-0002: LabubaRAT "masquerades as NVIDIA software" got T1027.004."""
    ids = _ids("LabubaRAT masquerades as NVIDIA software and supports screen capture.")
    assert "T1036" in ids
    assert "T1113" in ids


def test_words_that_merely_share_a_prefix_are_not_a_match() -> None:
    """A six-letter stem let Screensaver match "screen capture" and
    Systemctl match "system"."""
    ids = _ids("Supports screen capture and system reconnaissance.")
    assert "T1546.002" not in ids
    assert "T1569.003" not in ids


def test_a_name_must_appear_as_a_phrase_not_as_scattered_words() -> None:
    """ "discovered ... time" is not System Time Discovery; "domains" and
    "remote control" are not Rogue Domain Controller (H-0007)."""
    ids = _ids(
        "Researchers discovered the system at the time. Typosquatted provider "
        "domains delivered backdoors for remote control. Go modules and Chrome extensions."
    )
    assert "T1124" not in ids
    assert "T1207" not in ids
    assert "T1547.006" not in ids


def test_pre_intrusion_tactics_are_not_matched_on_everyday_nouns() -> None:
    assert "T1587.001" not in _ids("The malware was delivered by email.")


def test_report_wording_names_a_technique_its_title_never_uses() -> None:
    ids = _ids("It abused legitimate Microsoft build utilities via MSBuild from typosquatted domains.")
    assert ids[:2] == ["T1127.001", "T1583.001"]


def test_commentary_yields_no_candidates() -> None:
    """H-0006: an opinion post about AI guardrails."""
    assert _ids("Frontier AI models are restrictive; defenders face a safety penalty.") == []


def test_unreadable_attack_data_yields_nothing_rather_than_raising() -> None:
    class Broken(_FakeMatrix):
        def get_sorted_tactic_keys(self) -> List[str]:
            raise RuntimeError("stix unavailable")

    attack_matrix.reset_provider(Broken())
    assert candidate_techniques("masquerading") == []


def test_format_candidates() -> None:
    assert format_candidates([]) is None
    assert format_candidates([("T1036", "Masquerading")]) == "  T1036: Masquerading"
