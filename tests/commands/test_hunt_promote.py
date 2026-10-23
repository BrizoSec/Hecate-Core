"""Tests for hecate-agent hunt promote command with --output sigma / spl / kql."""

from pathlib import Path
from click.testing import CliRunner

from hecate_agent.commands.hunt import hunt
from hecate_agent.commands.demo import demo


def test_hunt_promote_sigma(tmp_path: Path, monkeypatch):
    """hecate-agent hunt promote --hunt H-0001 --output sigma exports validated logic to Sigma rule."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    # Seed demo workspace
    init_res = runner.invoke(demo, ["init"])
    assert init_res.exit_code == 0

    # Promote to Sigma
    res = runner.invoke(hunt, ["promote", "--hunt", "H-0001", "--output", "sigma"])
    assert res.exit_code == 0
    assert "Promoted H-0001 to Sigma Detection Rule" in res.output

    dest_rule = tmp_path / "detections" / "H-0001.yml"
    assert dest_rule.exists()
    content = dest_rule.read_text()
    assert "title: LSASS Memory Credential Dumping" in content
    assert "attack.credential_access" in content
    assert "attack.t1003.001" in content
    assert "logsource:" in content
    assert "detection:" in content


def test_hunt_promote_spl(tmp_path: Path, monkeypatch):
    """hecate-agent hunt promote --hunt H-0001 --output spl exports SPL snippet."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(demo, ["init"])
    res = runner.invoke(hunt, ["promote", "--hunt", "H-0001", "--output", "spl"])
    assert res.exit_code == 0
    assert "Promoted H-0001 to Splunk Query Snippet" in res.output

    dest_spl = tmp_path / "queries" / "H-0001.spl"
    assert dest_spl.exists()
    assert "index=sysmon EventCode=10" in dest_spl.read_text()


def test_hunt_promote_kql(tmp_path: Path, monkeypatch):
    """hecate-agent hunt promote --hunt H-0001 --output kql exports KQL snippet."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(demo, ["init"])
    res = runner.invoke(hunt, ["promote", "--hunt", "H-0001", "--output", "kql"])
    assert res.exit_code == 0
    assert "Promoted H-0001 to KQL Query Snippet" in res.output

    dest_kql = tmp_path / "queries" / "H-0001.kql"
    assert dest_kql.exists()
    assert "Promoted KQL Query from H-0001" in dest_kql.read_text()


def test_hunt_promote_custom_dest(tmp_path: Path, monkeypatch):
    """hecate-agent hunt promote with --out writes to custom path."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(demo, ["init"])
    custom_dest = tmp_path / "my_rules" / "lsass.yml"
    res = runner.invoke(hunt, ["promote", "--hunt", "H-0001", "--output", "sigma", "--out", str(custom_dest)])
    assert res.exit_code == 0
    assert custom_dest.exists()
