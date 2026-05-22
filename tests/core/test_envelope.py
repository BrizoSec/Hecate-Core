"""Tests for the envelope-reduction response contract reference impl."""

from pathlib import Path

import pytest

from athf.core.envelope import build_envelope


def test_under_threshold_returns_inline(tmp_path: Path) -> None:
    env = build_envelope("hello", persist_dir=tmp_path)

    assert env["persisted"] is False
    assert env["path"] == ""
    assert env["byte_count"] == 5
    assert env["preview"] == "hello"
    assert env["metadata"] == {}


def test_at_threshold_boundary_inline(tmp_path: Path) -> None:
    payload = "a" * 2048
    env = build_envelope(payload, threshold=2048, persist_dir=tmp_path)

    assert env["persisted"] is False
    assert env["byte_count"] == 2048
    assert env["path"] == ""
    # No file written below threshold.
    assert list(tmp_path.iterdir()) == []


def test_over_threshold_persists_to_disk(tmp_path: Path) -> None:
    payload = "x" * 3000
    env = build_envelope(
        payload,
        threshold=2048,
        persist_dir=tmp_path,
        artifact_name="big.txt",
    )

    assert env["persisted"] is True
    assert env["byte_count"] == 3000
    artifact = Path(env["path"])
    assert artifact.is_absolute()
    assert artifact.exists()
    assert artifact.read_text(encoding="utf-8") == payload


def test_persist_dir_is_created_when_missing(tmp_path: Path) -> None:
    target = tmp_path / "does-not-exist-yet"
    payload = "x" * 4096
    env = build_envelope(
        payload,
        threshold=2048,
        persist_dir=target,
        artifact_name="result.json",
    )

    assert env["persisted"] is True
    assert target.is_dir()
    assert Path(env["path"]).parent.resolve() == target.resolve()


def test_gate_b_requires_persist_dir_and_artifact_name(tmp_path: Path) -> None:
    payload = "x" * 3000
    with pytest.raises(ValueError):
        build_envelope(payload, threshold=2048)
    with pytest.raises(ValueError):
        build_envelope(payload, threshold=2048, persist_dir=tmp_path)
    with pytest.raises(ValueError):
        build_envelope(payload, threshold=2048, artifact_name="x.txt")


def test_parent_artifact_forces_persistence_regardless_of_size(tmp_path: Path) -> None:
    artifact = tmp_path / "R-0042.md"
    artifact.write_text("# R-0042\n", encoding="utf-8")

    env = build_envelope(
        "Adversaries run native discovery commands post-access.",
        parent_artifact="R-0042",
        path=str(artifact),
    )

    assert env["persisted"] is True
    assert env["path"] == str(artifact.resolve())
    assert env["byte_count"] > 0
    # Helper does not rewrite the artifact when parent_artifact is set.
    assert artifact.read_text(encoding="utf-8") == "# R-0042\n"


def test_parent_artifact_requires_path() -> None:
    with pytest.raises(ValueError):
        build_envelope("payload", parent_artifact="R-0042")


def test_path_is_made_absolute_for_gate_a(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    artifact = Path("nested/R-0001.md")
    artifact.parent.mkdir()
    artifact.write_text("body", encoding="utf-8")

    env = build_envelope(
        "preview-source",
        parent_artifact="R-0001",
        path=str(artifact),
    )

    assert Path(env["path"]).is_absolute()
    assert env["path"] == str(artifact.resolve())


def test_metadata_is_preserved(tmp_path: Path) -> None:
    env = build_envelope(
        "ok",
        persist_dir=tmp_path,
        metadata={"row_count": 1000, "columns": ["time", "host"]},
    )

    assert env["metadata"] == {"row_count": 1000, "columns": ["time", "host"]}


def test_explicit_preview_overrides_default(tmp_path: Path) -> None:
    env = build_envelope(
        "ignored as preview source",
        preview="custom preview",
        persist_dir=tmp_path,
    )

    assert env["preview"] == "custom preview"


def test_default_preview_collapses_whitespace_and_truncates(tmp_path: Path) -> None:
    payload = "line1\n  line2\t\tline3 " + ("z" * 500)
    env = build_envelope(payload, persist_dir=tmp_path, artifact_name="x.txt")

    assert "\n" not in env["preview"]
    assert "\t" not in env["preview"]
    assert len(env["preview"]) <= 200
    assert env["preview"].endswith("...")


def test_non_string_payload_is_json_serialized(tmp_path: Path) -> None:
    payload = {"rows": [{"a": 1}, {"a": 2}]}
    env = build_envelope(payload, threshold=10, persist_dir=tmp_path, artifact_name="r.json")

    assert env["persisted"] is True
    body = Path(env["path"]).read_text(encoding="utf-8")
    assert '"rows"' in body
    assert env["byte_count"] == len(body.encode("utf-8"))
