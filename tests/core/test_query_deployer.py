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

    def test_deploy_splunk_ssl_verification(self, monkeypatch):
        monkeypatch.delenv("SPLUNK_VERIFY_SSL", raising=False)
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Splunk SSL Test",
            target=QueryDeployer.TARGET_SPLUNK,
            dialect="spl",
            query="index=main EventCode=1",
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200

        with (
            mock.patch.dict(
                "os.environ",
                {"SPLUNK_HOST": "https://splunk.example.com:8089", "SPLUNK_TOKEN": "secret-token"},
            ),
            mock.patch("httpx.Client") as mock_client_cls,
        ):
            mock_client_instance = mock.MagicMock()
            mock_client_instance.__enter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = fake_resp
            mock_client_cls.return_value = mock_client_instance

            # Default: SPLUNK_VERIFY_SSL not set -> verify=True
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            mock_client_cls.assert_called_with(timeout=deployer.timeout_sec, verify=True)

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_HOST": "https://splunk.example.com:8089",
                    "SPLUNK_TOKEN": "secret-token",
                    "SPLUNK_VERIFY_SSL": "false",
                },
            ),
            mock.patch("httpx.Client") as mock_client_cls,
        ):
            mock_client_instance = mock.MagicMock()
            mock_client_instance.__enter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = fake_resp
            mock_client_cls.return_value = mock_client_instance

            # Explicit SPLUNK_VERIFY_SSL=false -> verify=False
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            mock_client_cls.assert_called_with(timeout=deployer.timeout_sec, verify=False)

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
        assert "headers" in result["request_summary"]
        assert result["request_summary"]["headers"]["Authorization"] == "Bearer ***"

    def test_contract_sentinel_deployment(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Admin Console Access",
            target=QueryDeployer.TARGET_SENTINEL,
            dialect="kql",
            query="DeviceProcessEvents | where ProcessCommandLine contains 'whoami'",
            techniques=["T1033"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 201

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SENTINEL_WORKSPACE_ID": "ws-1234",
                    "SENTINEL_SUBSCRIPTION_ID": "sub-5678",
                    "SENTINEL_RESOURCE_GROUP": "rg-sec",
                    "SENTINEL_BEARER_TOKEN": "azure-token-xyz",
                },
            ),
            mock.patch("httpx.Client.put", return_value=fake_resp) as mock_put,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.ok is True
            assert mock_put.called
            call_args, call_kwargs = mock_put.call_args
            assert "https://management.azure.com/subscriptions/sub-5678" in call_args[0]
            assert "providers/Microsoft.OperationalInsights/workspaces/ws-1234" in call_args[0]
            assert call_kwargs["headers"]["Authorization"] == "Bearer azure-token-xyz"
            assert call_kwargs["json"]["properties"]["query"] == payload.query

        # Error case: 401 Unauthorized
        err_resp = mock.MagicMock()
        err_resp.status_code = 401
        err_resp.raise_for_status.side_effect = Exception("401 Unauthorized")
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SENTINEL_WORKSPACE_ID": "ws-1234",
                    "SENTINEL_SUBSCRIPTION_ID": "sub-5678",
                    "SENTINEL_RESOURCE_GROUP": "rg-sec",
                    "SENTINEL_BEARER_TOKEN": "expired-token",
                },
            ),
            mock.patch("httpx.Client.put", return_value=err_resp),
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "error"
            assert res.ok is False
            assert "401 Unauthorized" in res.detail

    def test_contract_crowdstrike_deployment(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Suspicious Falcon Query",
            target=QueryDeployer.TARGET_CROWDSTRIKE,
            dialect="cql",
            query="CommandLine=/mimikatz/i",
            techniques=["T1003.001"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"id": "cql-query-999"}

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "FALCON_BASE_URL": "https://api.us-2.crowdstrike.com",
                    "FALCON_LOGSCALE_REPO": "hunting-repo",
                    "FALCON_API_TOKEN": "falcon-token-abc",
                },
            ),
            mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.remote_id == "cql-query-999"
            assert mock_post.called
            call_args, call_kwargs = mock_post.call_args
            assert call_args[0] == "https://api.us-2.crowdstrike.com/api/v1/repositories/hunting-repo/queries"
            assert call_kwargs["headers"]["Authorization"] == "Bearer falcon-token-abc"
            assert call_kwargs["json"]["queryString"] == payload.query

        # Error case: 429 Rate Limit
        err_resp = mock.MagicMock()
        err_resp.status_code = 429
        err_resp.raise_for_status.side_effect = Exception("429 Too Many Requests")
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "FALCON_BASE_URL": "https://api.us-2.crowdstrike.com",
                    "FALCON_LOGSCALE_REPO": "hunting-repo",
                    "FALCON_API_TOKEN": "falcon-token-abc",
                },
            ),
            mock.patch("httpx.Client.post", return_value=err_resp),
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "error"
            assert "429 Too Many Requests" in res.detail

    def test_contract_rapid7_deployment(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Rapid7 Investigation Query",
            target=QueryDeployer.TARGET_RAPID7,
            dialect="leql",
            query="where(process.name=cmd.exe)",
            techniques=["T1059.003"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"saved_query": {"id": "r7-sq-44"}}

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "RAPID7_API_KEY": "r7-api-key-test",
                    "RAPID7_REGION": "eu",
                },
            ),
            mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.remote_id == "r7-sq-44"
            call_args, call_kwargs = mock_post.call_args
            assert call_args[0] == "https://eu.rest.logs.insight.rapid7.com/management/saved_queries"
            assert call_kwargs["headers"]["x-api-key"] == "r7-api-key-test"
            assert call_kwargs["json"]["saved_query"]["leql"]["statement"] == payload.query

    def test_contract_sentinelone_deployment(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="SentinelOne S1QL Rule",
            target=QueryDeployer.TARGET_SENTINELONE,
            dialect="s1ql",
            query='EventType = "Process Creation" AND (EndpointOS = "windows")',
            techniques=["T1059"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"data": {"id": "s1-query-77"}}

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SENTINELONE_URL": "https://euce1.sentinelone.net",
                    "SENTINELONE_API_TOKEN": "s1-token-secret",
                },
            ),
            mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.remote_id == "s1-query-77"
            call_args, call_kwargs = mock_post.call_args
            assert call_args[0] == "https://euce1.sentinelone.net/web/api/v2.1/dv/saved-queries"
            assert call_kwargs["headers"]["Authorization"] == "ApiToken s1-token-secret"
            assert call_kwargs["json"]["data"]["query"] == payload.query
