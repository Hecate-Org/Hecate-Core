"""Unit tests for multi-target query deployer across all 6 SIEM/EDR platforms (Milestone 4)."""

import unittest.mock as mock

from hecate_agent.api import (
    deploy_transpiled_query,
    sync_transpiled_query,
    undeploy_transpiled_query,
)
from hecate_agent.core.query_deployer import (
    DeploymentPayload,
    QueryDeployer,
    SyncResult,
    UndeploymentPayload,
    UndeploymentResult,
)


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

    def test_contract_splunk_deployment(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Splunk Discovery Query",
            target=QueryDeployer.TARGET_SPLUNK,
            dialect="spl",
            query='Image="*/whoami.exe"',
            techniques=["T1033"],
        )

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 201

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "splunk-token-xyz",
                },
            ),
            mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.remote_id.startswith("Hecate_H-0868_")
            call_args, call_kwargs = mock_post.call_args
            assert call_args[0] == "https://splunk.corp.local:8089/servicesNS/nobody/search/saved/searches"
            assert call_kwargs["headers"]["Authorization"] == "Bearer splunk-token-xyz"
            assert call_kwargs["data"]["search"] == 'search Image="*/whoami.exe"'

    def test_contract_splunk_deployment_idempotent_409(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Existing Splunk Query",
            target=QueryDeployer.TARGET_SPLUNK,
            dialect="spl",
            query='Image="*/net.exe"',
            techniques=["T1087"],
        )

        resp_409 = mock.MagicMock()
        resp_409.status_code = 409

        resp_200 = mock.MagicMock()
        resp_200.status_code = 200

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_PASSWORD": "SecretPassword!",
                },
            ),
            mock.patch("httpx.Client.post", side_effect=[resp_409, resp_200]) as mock_post,
        ):
            res = deployer.deploy(payload, dry_run=False)
            assert res.status == "deployed"
            assert res.remote_id.startswith("Hecate_H-0868_")
            assert mock_post.call_count == 2
            second_call_url = mock_post.call_args_list[1][0][0]
            assert "saved/searches/Hecate_H-0868_" in second_call_url

    def test_compute_remote_id_determinism(self):
        title = "Privilege Escalation via Sudo"
        query = 'CommandLine="*sudo -i*"'
        id_splunk = QueryDeployer.compute_remote_id("splunk_spl", "H-0042", title, query)
        assert id_splunk.startswith("Hecate_H-0042_Privilege_Escalation_via_Sudo_")
        # Assert same inputs generate same remote_id
        assert id_splunk == QueryDeployer.compute_remote_id("splunk_spl", "H-0042", title, query)

        id_sentinel = QueryDeployer.compute_remote_id("sentinel_kql", "H-0042", title, query)
        assert id_sentinel.startswith("hecate_h_0042_privilege_escalation_via_sudo")

        id_elastic = QueryDeployer.compute_remote_id("elastic_eql", "H-0042", title, query)
        assert id_elastic.startswith("hecate-h-0042-privilege-escalation-via-sudo")

    def test_undeploy_dry_run_all_six_targets(self):
        deployer = QueryDeployer()
        for target in QueryDeployer.SUPPORTED_TARGETS:
            payload = UndeploymentPayload(
                hunt_id="H-0868",
                rule_title="Admin Endpoint Access",
                target=target,
                query="index=* cs-uri-stem=/admin",
            )
            res = deployer.undeploy(payload, dry_run=True)
            assert res.ok is True
            assert res.target == target
            assert res.status == "dry_run"
            assert res.dry_run is True
            assert res.remote_id is not None
            assert res.request_summary.get("method") == "DELETE"

    def test_undeploy_unsupported_target_skipped(self):
        deployer = QueryDeployer()
        payload = UndeploymentPayload(
            hunt_id="H-0868",
            rule_title="Test",
            target="unsupported_siem",
        )
        res = deployer.undeploy(payload, dry_run=True)
        assert res.status == "skipped"
        assert "Unsupported deployment target" in res.detail

    def test_undeploy_splunk_live_200_and_404(self):
        deployer = QueryDeployer()
        payload = UndeploymentPayload(
            hunt_id="H-0868",
            rule_title="Live Splunk Query",
            target=QueryDeployer.TARGET_SPLUNK,
            query='Image="*/whoami.exe"',
        )

        resp_200 = mock.MagicMock()
        resp_200.status_code = 200

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "valid-token",
                },
            ),
            mock.patch("httpx.Client.delete", return_value=resp_200) as mock_delete,
        ):
            res = deployer.undeploy(payload, dry_run=False)
            assert res.ok is True
            assert res.status == "undeployed"
            assert "Successfully deleted" in res.detail
            call_url = mock_delete.call_args[0][0]
            assert "saved/searches/Hecate_H-0868_" in call_url

        # Test 404 idempotent teardown
        resp_404 = mock.MagicMock()
        resp_404.status_code = 404

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "valid-token",
                },
            ),
            mock.patch("httpx.Client.delete", return_value=resp_404),
        ):
            res_404 = deployer.undeploy(payload, dry_run=False)
            assert res_404.ok is True
            assert res_404.status == "not_found"
            assert "was not found" in res_404.detail

    def test_sync_dry_run_all_six_targets(self):
        deployer = QueryDeployer()
        for target in QueryDeployer.SUPPORTED_TARGETS:
            payload = DeploymentPayload(
                hunt_id="H-0868",
                rule_title="Sync Check Query",
                target=target,
                dialect=target.split("_")[-1],
                query="index=* admin_access",
            )
            res = deployer.sync(payload, dry_run=True)
            assert res.ok is True
            assert res.target == target
            assert res.status == "dry_run"
            assert res.dry_run is True
            assert res.remote_id is not None
            assert res.request_summary.get("method") == "GET"

    def test_sync_splunk_in_sync_and_drift_and_missing(self):
        deployer = QueryDeployer()
        payload = DeploymentPayload(
            hunt_id="H-0868",
            rule_title="Sync Splunk Query",
            target=QueryDeployer.TARGET_SPLUNK,
            dialect="spl",
            query='Image="*/whoami.exe"',
        )

        # 1. Test In-Sync
        resp_in_sync = mock.MagicMock()
        resp_in_sync.status_code = 200
        resp_in_sync.json.return_value = {
            "entry": [{"content": {"search": 'search Image="*/whoami.exe"'}}]
        }

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "valid-token",
                },
            ),
            mock.patch("httpx.Client.get", return_value=resp_in_sync),
        ):
            res = deployer.sync(payload, dry_run=False)
            assert res.ok is True
            assert res.status == "in_sync"
            assert res.drift_diff is None
            assert "is in sync" in res.detail

        # 2. Test Drift Detected
        resp_drift = mock.MagicMock()
        resp_drift.status_code = 200
        resp_drift.json.return_value = {
            "entry": [{"content": {"search": 'search Image="*/whoami.exe" | head 10'}}]
        }

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "valid-token",
                },
            ),
            mock.patch("httpx.Client.get", return_value=resp_drift),
        ):
            res_drift = deployer.sync(payload, dry_run=False)
            assert res_drift.ok is False
            assert res_drift.status == "drift_detected"
            assert res_drift.drift_diff is not None
            assert "- Local:" in res_drift.drift_diff
            assert "+ Remote:" in res_drift.drift_diff
            assert "has drifted" in res_drift.detail

        # 3. Test Missing Remote
        resp_missing = mock.MagicMock()
        resp_missing.status_code = 404

        with (
            mock.patch.dict(
                "os.environ",
                {
                    "SPLUNK_URL": "https://splunk.corp.local:8089",
                    "SPLUNK_TOKEN": "valid-token",
                },
            ),
            mock.patch("httpx.Client.get", return_value=resp_missing),
        ):
            res_missing = deployer.sync(payload, dry_run=False)
            assert res_missing.ok is False
            assert res_missing.status == "missing_remote"
            assert "does not exist in Splunk" in res_missing.detail

    def test_api_undeploy_and_sync_transpiled_query(self):
        res_undeploy = undeploy_transpiled_query(
            target="splunk_spl",
            hunt_id="H-0868",
            title="API Teardown Test",
            query='Image="*/id.exe"',
            dry_run=True,
        )
        assert res_undeploy["ok"] is True
        assert res_undeploy["status"] == "dry_run"
        assert res_undeploy["remote_id"].startswith("Hecate_H-0868_")

        res_sync = sync_transpiled_query(
            target="splunk_spl",
            query='Image="*/id.exe"',
            hunt_id="H-0868",
            title="API Sync Test",
            dry_run=True,
        )
        assert res_sync["ok"] is True
        assert res_sync["status"] == "dry_run"
        assert res_sync["remote_id"].startswith("Hecate_H-0868_")
