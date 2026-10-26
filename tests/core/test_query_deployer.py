"""Unit tests for multi-target query deployer across all 6 SIEM/EDR platforms (Milestone 4)."""

import unittest.mock as mock

from hecate_agent.api import deploy_transpiled_query
from hecate_agent.core.query_deployer import DeploymentPayload, QueryDeployer


class TestQueryDeployer:
    def test_deploy_dry_run_all_six_targets(self):
        deployer = QueryDeployer()

        queries = {
            QueryDeployer.TARGET_SENTINEL: "W3CIISLog | where 'cs-uri-stem' contains '/admin'",
            QueryDeployer.TARGET_CROWDSTRIKE: '"cs-uri-stem"=/\\/admin/i',
            QueryDeployer.TARGET_RAPID7: "where(uri_path=*/admin*)",
            QueryDeployer.TARGET_SENTINELONE: 'EventType = "Process Creation" AND (EndpointOS = "windows")',
            QueryDeployer.TARGET_SPLUNK: '"cs-uri-stem"="*/admin*"',
            QueryDeployer.TARGET_ELASTIC: 'any where cs-uri-stem:"*/admin*"',
        }

        for target, q_text in queries.items():
            payload = DeploymentPayload(
                hunt_id="H-0868",
                rule_title="Admin Endpoint Access",
                target=target,
                dialect=target.split("_")[-1],
                query=q_text,
                techniques=["T1190"],
                tags=["cve-2026-8732"],
            )

            res = deployer.deploy(payload, dry_run=True)
            assert res.ok is True
            assert res.target == target
            assert res.status == "dry_run"
            assert res.dry_run is True
            assert res.remote_id is not None
            assert "Validated" in res.detail
            assert res.request_summary != {}

    def test_deploy_empty_query_rejected(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Empty Query",
            target="sentinel_kql",
            dialect="kql",
            query="   ",
        )
        res = deployer.deploy(payload, dry_run=True)
        assert res.ok is False
        assert res.status == "error"
        assert "Cannot deploy empty query" in res.detail

    def test_deploy_unsupported_target_skipped(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Test",
            target="unsupported_siem",
            dialect="txt",
            query="foo=bar",
        )
        res = deployer.deploy(payload, dry_run=True)
        assert res.status == "skipped"
        assert "Unsupported deployment target" in res.detail

    def test_deploy_live_mocked_network(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Mocked Live Test",
            target=QueryDeployer.TARGET_ELASTIC,
            dialect="eql",
            query='any where process.name == "cmd.exe"',
            techniques=["T1059.003"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"id": "rule-12345"}

        with (
            mock.patch.dict(
                "os.environ",
                {"ELASTIC_URL": "https://kibana.example.com", "ELASTIC_API_KEY": "secret-key"},
            ),
            mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.dry_run is False
            assert res.remote_id == "rule-12345"
            assert mock_post.called

    def test_api_deploy_transpiled_query(self):
        result = deploy_transpiled_query(
            target="splunk_spl",
            query='Image="*\\cmd.exe"',
            hunt_id="H-0868",
            title="Splunk Test Rule",
            dry_run=True,
        )
        assert result["status"] == "dry_run"
        assert result["target"] == "splunk_spl"
        assert result["ok"] is True
        assert "Validated Splunk Saved Search" in result["detail"]
