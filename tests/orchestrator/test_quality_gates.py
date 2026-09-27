"""The Runner's quality gates on the LangGraph path: technique filter, park, grounding audit."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from hecate_agent.orchestrator import graph, quality

ATTACK = {
    "T1078": "Valid Accounts",
    "T1546": "Event Triggered Execution",
    "T1566": "Phishing",
    "T1219": "Remote Access Tools",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1092": "Communication Through Removable Media",
}

TEAMS = (
    "RSS: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams\n"
    "Summary: attackers use voice phishing in Microsoft Teams to get users to run PowerShell "
    "and install remote access tools."
)


def lookup(technique_id: str) -> Dict[str, Any]:
    name = ATTACK.get(technique_id.upper())
    return {"found": True, "name": name} if name else {"found": False}


def no_candidates(text: str) -> List:
    return []


def test_model_picks_no_source_describes_are_dropped():
    """H-0000: T1078 and T1546 on a Teams vishing report that names neither."""
    decision = quality.filter_techniques(
        ["T1078", "T1546", "T1566", "T1059.001"],
        cti_text=TEAMS,
        research_text="",
        lookup=lookup,
        candidates=no_candidates,
    )
    assert decision.kept == ["T1566", "T1059.001"]
    assert decision.dropped_unevidenced == ["T1078 Valid Accounts", "T1546 Event Triggered Execution"]


def test_an_invented_id_is_dropped_as_unknown():
    decision = quality.filter_techniques(
        ["T9999", "T1566"], cti_text=TEAMS, research_text="", lookup=lookup, candidates=no_candidates
    )
    assert decision.kept == ["T1566"]
    assert decision.dropped_unknown == ["T9999"]


def test_techniques_the_intel_names_or_words_are_kept_and_added():
    decision = quality.filter_techniques(
        [],
        cti_text=TEAMS + "\nMITRE ATT&CK Techniques: T1078",
        research_text="",
        lookup=lookup,
        candidates=lambda text: [("T1219", "Remote Access Tools")],
    )
    assert decision.kept == ["T1078", "T1219"]


def test_research_link_titles_are_not_evidence():
    research = "- [Removable media and C2 communication round-up](https://example.test/x)"
    decision = quality.filter_techniques(
        ["T1092"], cti_text="Tox C2.", research_text=research, lookup=lookup, candidates=no_candidates
    )
    assert decision.kept == []


def test_attack_data_unavailable_keeps_techniques_unjudged():
    def broken(technique_id: str) -> Dict[str, Any]:
        raise RuntimeError("stix_unavailable")

    decision = quality.filter_techniques(["T1078"], cti_text=TEAMS, research_text="", lookup=broken, candidates=no_candidates)
    assert decision.kept == ["T1078"]


@pytest.mark.parametrize(
    ("kept", "text", "parked"),
    [
        ([], "commentary about AI in the SOC", True),
        ([], "hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc", False),
        ([], "C2 at 104.225.153.141", False),
        (["T1566"], "commentary", False),
    ],
)
def test_park_reason(kept, text, parked):
    assert (quality.park_reason(kept, text) is not None) is parked


# --- The compiled graph ---------------------------------------------------------------------


def _run(
    monkeypatch,
    tmp_path: Path,
    *,
    threat_intel: str,
    model_techniques: List[str],
    rules: List[str],
    hunt_id: str = "H-0901",
):
    """Run the whole graph with the model steps stubbed; return (final state, MISP calls)."""
    research = tmp_path / "R-0001.md"
    research.write_text("Research on the Teams vishing campaign.")
    monkeypatch.setattr(
        graph,
        "generate_research",
        lambda **kw: (SimpleNamespace(research_id="R-0001", mitre_techniques=[]), research),
    )
    monkeypatch.setattr(
        graph,
        "generate_hypothesis",
        lambda **kw: SimpleNamespace(
            hypothesis="Adversaries use Teams vishing to run PowerShell",
            justification="",
            expected_observables=[],
            mitre_techniques=model_techniques,
        ),
    )
    monkeypatch.setattr(
        graph,
        "generate_sigma",
        lambda **kw: (SimpleNamespace(rules=[SimpleNamespace(rule_yaml=r) for r in rules]), []),
    )
    monkeypatch.setattr(graph, "_lookup", lookup)
    monkeypatch.setattr(graph, "_candidates", no_candidates)
    monkeypatch.setattr(graph, "enrichment_agent", lambda state: {})
    monkeypatch.setattr(graph, "artifact_extractor_agent", lambda state: {})
    published: List[Any] = []
    import hecate_agent.orchestrator.misp_publisher as mp

    monkeypatch.setattr(mp, "publish_hunt_to_misp", lambda *a: published.append(a) or "ok")

    workflow = graph.StateGraph(graph.HuntState)
    for name in (
        "research",
        "artifact_extractor",
        "enrichment",
        "hypothesis",
        "technique_filter",
        "allocate_hunt_id",
        "sigma_drafter",
        "grounding_audit",
        "hunt_writer",
        "misp_publisher",
    ):
        workflow.add_node(name, getattr(graph, f"{name}_agent"))
    # Same topology as graph.workflow, rebuilt so the stubs above are the nodes that run.
    workflow.set_entry_point("artifact_extractor")
    chain = [
        "artifact_extractor",
        "research",
        "enrichment",
        "hypothesis",
        "technique_filter",
        "allocate_hunt_id",
        "sigma_drafter",
        "grounding_audit",
        "hunt_writer",
    ]
    for a, b in zip(chain, chain[1:]):
        workflow.add_conditional_edges(a, graph.route_errors, {"next": b, graph.END: graph.END})
    workflow.add_conditional_edges("hunt_writer", graph.route_publish, {"next": "misp_publisher", graph.END: graph.END})
    workflow.add_conditional_edges("misp_publisher", graph.route_errors, {"next": graph.END, graph.END: graph.END})
    state = workflow.compile().invoke(
        {
            "topic": "Teams Vishing",
            "threat_intel": threat_intel,
            "workspace_path": str(tmp_path),
            **({"hunt_id": hunt_id} if hunt_id else {}),
        }
    )
    return state, published


def test_graph_drops_unevidenced_techniques_and_records_them(monkeypatch, tmp_path):
    state, published = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1078", "T1566"], rules=[])
    assert state["mitre_techniques"] == ["T1566"]
    draft = Path(state["draft_path"]).read_text(encoding="utf-8")
    assert "T1078" in draft and "Dropped before drafting" in draft
    assert "techniques: ['T1566']" in draft
    assert "# Grounding" in draft
    assert len(published) == 1


def test_graph_halts_when_nothing_is_left_to_hunt(monkeypatch, tmp_path):
    state, published = _run(
        monkeypatch, tmp_path, threat_intel="Opinion piece on AI SOCs.", model_techniques=["T1078"], rules=[]
    )
    assert "no ATT&CK technique" in state["halted"]
    assert state.get("draft_path") is None
    assert not list(tmp_path.rglob("H-*.md"))
    assert published == []


def test_graph_does_not_publish_a_draft_with_unsupported_claims(monkeypatch, tmp_path):
    rule = (
        "title: x\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n"
        "    DestinationIp: 203.0.113.99\n  condition: selection\n"
    )
    state, published = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1566"], rules=[rule])
    assert state["grounding_unsupported"] >= 1
    assert "trace to no source" in Path(state["draft_path"]).read_text(encoding="utf-8")
    assert published == []


def test_the_real_graph_runs_the_gates_in_order():
    edges = {(e.source, e.target) for e in graph.workflow.compile().get_graph().edges}
    for pair in [
        ("hypothesis", "technique_filter"),
        ("technique_filter", "allocate_hunt_id"),
        ("allocate_hunt_id", "sigma_drafter"),
        ("sigma_drafter", "grounding_audit"),
        ("grounding_audit", "hunt_writer"),
        ("hunt_writer", "misp_publisher"),
    ]:
        assert pair in edges, pair
    assert ("hypothesis", "sigma_drafter") not in edges
    assert ("technique_filter", "sigma_drafter") not in edges
    assert ("sigma_drafter", "hunt_writer") not in edges


# --- Hunt IDs: no more H-0000 overwrites -------------------------------------------------------


def test_each_run_gets_the_next_id_from_the_shared_counter(monkeypatch, tmp_path):
    hunts = tmp_path / "hunts"
    hunts.mkdir()
    (hunts / ".hunt_id_counter").write_text("41\n")
    first, _ = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1566"], rules=[], hunt_id="")
    second, _ = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1566"], rules=[], hunt_id="")
    assert (first["hunt_id"], second["hunt_id"]) == ("H-0042", "H-0043")
    assert Path(first["draft_path"]).name == "H-0042.md"
    assert Path(second["draft_path"]).exists() and Path(first["draft_path"]).exists()
    assert (hunts / ".hunt_id_counter").read_text().strip() == "43"


def test_the_writer_never_overwrites_an_existing_hunt(monkeypatch, tmp_path):
    first, _ = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1566"], rules=[], hunt_id="H-0901")
    before = Path(first["draft_path"]).read_text(encoding="utf-8")
    second, published = _run(monkeypatch, tmp_path, threat_intel=TEAMS, model_techniques=["T1566"], rules=[], hunt_id="H-0901")
    assert any("already exists" in e for e in second["errors"])
    assert Path(first["draft_path"]).read_text(encoding="utf-8") == before
    assert published == []


def test_a_halted_run_does_not_spend_an_id(monkeypatch, tmp_path):
    state, _ = _run(monkeypatch, tmp_path, threat_intel="Opinion piece.", model_techniques=["T1078"], rules=[], hunt_id="")
    assert state["halted"]
    assert not (tmp_path / "hunts" / ".hunt_id_counter").exists()


def test_approval_pauses_before_the_id_is_allocated(tmp_path):
    compiled = graph.compile_graph(db_path=str(tmp_path / "cp.sqlite"))
    assert list(compiled.interrupt_before_nodes) == ["allocate_hunt_id"]
