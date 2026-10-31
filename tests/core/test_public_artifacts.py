from pathlib import Path

import pytest

from hecate_agent.commands._hunt_lifecycle import _build_export_dict
from hecate_agent.core.public_artifacts import public_hunt_record


def test_public_projection_never_copies_sessions_evidence_or_validation_claims(monkeypatch):
    private = {
        "frontmatter": {
            "hunt_id": "H-0001", "title": "Reviewed title", "status": "planning",
            "hunter": "private-operator", "customer": "private-customer",
            "true_positives": 5, "bas_verification": {"status": "verified_true_positive"},
        },
        "content": "private raw report", "file_path": "/private/workspace/hunt.md",
        "lock_sections": {"CHECK": "private query results"},
    }
    monkeypatch.setattr(
        "hecate_agent.commands._hunt_lifecycle._load_sessions_for_hunt",
        lambda *a: (_ for _ in ()).throw(AssertionError("Public export must not read sessions")),
    )
    projected = _build_export_dict(private, Path("private-sessions"), True, False, True)
    assert projected == public_hunt_record(private)
    assert projected["metadata"] == {"hunt_id": "H-0001", "title": "Reviewed title", "status": "planning"}
    assert projected["validation_scope"] == "not_provided"
    assert projected["release_state"] == "requires_review"
    assert "private" not in str(projected)


def test_legacy_core_writer_cannot_bypass_runner_policy(monkeypatch):
    from hecate_agent.orchestrator.misp_publisher import publish_hunt_to_misp

    monkeypatch.setattr(
        "httpx.post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Direct external write"))
    )
    with pytest.raises(RuntimeError, match="retired"):
        publish_hunt_to_misp("Test", "Not a reviewed finding", ["candidate.example"])
