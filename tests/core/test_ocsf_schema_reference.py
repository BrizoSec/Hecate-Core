"""The OCSF reference must be real OCSF, and must reach the model.

`hunt_researcher` injects this file into the telemetry-mapping prompt, which
decides what data sources a hunt targets. Before it existed the researcher
recorded "field findings are based on model recall" and produced
`process_name`, `registry_key`, `event_id` under a heading claiming they were
OCSF fields.

The file is generated from <https://schema.ocsf.io> and checked in; nothing
fetches at runtime. These tests guard the two ways it can quietly stop
working: drifting from the real schema, and not being loaded at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent
from hecate_agent.core.workspace import knowledge_file

REFERENCE = Path(__file__).resolve().parents[2] / "knowledge" / "OCSF_SCHEMA_REFERENCE.md"

#: Budget the loader truncates at. A reference longer than this is silently
#: cut mid-table, so the classes at the end would never reach the model.
_LOADER_BUDGET = 5000


@pytest.fixture(scope="module")
def text() -> str:
    if not REFERENCE.exists():
        pytest.fail(f"{REFERENCE} is missing; the researcher falls back to model recall without it")
    return REFERENCE.read_text(encoding="utf-8")


class TestItFitsAndLoads:
    def test_it_fits_inside_the_loader_budget(self, text: str) -> None:
        """_load_ocsf_schema() truncates at 5,000 chars with no warning."""
        assert len(text) <= _LOADER_BUDGET, (
            f"{len(text)} chars: the tail would be cut off before reaching the model"
        )

    def test_the_researcher_loads_it(self, monkeypatch, tmp_path) -> None:
        workspace = REFERENCE.parents[1]
        monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
        monkeypatch.chdir(tmp_path)  # not the workspace, as the orchestrator runs it
        loaded = HuntResearcherAgent()._load_ocsf_schema()
        assert "not found" not in loaded
        assert "process" in loaded

    def test_a_missing_file_degrades_rather_than_crashes(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
        assert HuntResearcherAgent()._load_ocsf_schema() == "OCSF schema reference not found"

    def test_the_workspace_copy_is_the_one_resolved(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("HECATE_WORKSPACE", str(REFERENCE.parents[1]))
        assert knowledge_file("OCSF_SCHEMA_REFERENCE.md") == REFERENCE


class TestItIsAFieldDictionaryNotExamples:
    """Injected next to "now produce your answer". Worked examples here would
    be copied, exactly as the prompt's own `ClickHouse` and `Windows
    domain-joined endpoints` examples were, and the hunting-knowledge base's
    `PowerShell download cradle` after them."""

    @pytest.mark.parametrize(
        "leak", ["powershell", "download cradle", "clickhouse", "domain-joined", "wget", "curl"]
    )
    def test_it_carries_no_copyable_tradecraft(self, text: str, leak: str) -> None:
        assert leak not in text.lower()

    def test_it_states_that_it_is_not_evidence(self, text: str) -> None:
        assert "not evidence" in text.lower() or "not a set of examples" in text.lower()

    def test_it_declares_its_provenance(self, text: str) -> None:
        assert "schema.ocsf.io" in text


class TestTheFieldNamesAreRealOCSF:
    def test_the_hunting_classes_are_present(self, text: str) -> None:
        for cls in (
            "process_activity",
            "network_activity",
            "dns_activity",
            "file_activity",
            "module_activity",
            "authentication",
            "registry_key_activity",
        ):
            assert cls in text, f"{cls} missing"

    def test_class_uids_match_the_schema(self, text: str) -> None:
        """UIDs are stable identifiers; a wrong one is a silent lie."""
        for cls, uid in (
            ("process_activity", "1007"),
            ("network_activity", "4001"),
            ("dns_activity", "4003"),
            ("file_activity", "1001"),
            ("authentication", "3002"),
            ("registry_key_activity", "201001"),
        ):
            assert re.search(rf"`{cls}`\s*\|\s*{uid}\b", text), f"{cls} should be uid {uid}"

    def test_the_corrections_table_names_the_real_mistakes(self, text: str) -> None:
        """These are the inventions actually observed in generated research."""
        for wrong in ("process_name", "registry_key", "event_id", "process.command_line"):
            assert wrong in text
        assert "process.cmd_line" in text

    def test_it_does_not_claim_population_rates(self, text: str) -> None:
        """The estate is unmeasured; the prompt forbids stating rates, so the
        reference must not imply it carries them."""
        assert "population rate" not in text.lower()


@pytest.mark.network
class TestItHasNotDriftedFromTheLiveSchema:
    """Opt-in: `pytest -m network`. Catches the file going stale against a
    later OCSF release rather than assuming it stays correct forever."""

    def test_every_documented_process_field_still_exists(self, text: str) -> None:
        httpx = pytest.importorskip("httpx")
        try:
            attrs = httpx.get("https://schema.ocsf.io/api/objects/process", timeout=20).json()[
                "attributes"
            ]
        except Exception as exc:  # noqa: BLE001 - network flakiness is not a defect
            pytest.skip(f"schema.ocsf.io unreachable: {exc}")
        block = text.split("### `process`")[1].split("###")[0]
        for field in re.findall(r"^\| `([a-z_]+)` \|", block, re.M):
            assert field in attrs, f"process.{field} is no longer in the OCSF schema"
