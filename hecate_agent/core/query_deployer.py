"""Multi-target SIEM and EDR live query deployment and API push engine.

Pushes validated, transpiled hunting queries directly into enterprise SIEM & EDR platforms
via their native REST APIs:
- Microsoft Sentinel (Saved Searches API)
- CrowdStrike Falcon (LogScale Saved Queries API)
- Splunk Enterprise / Cloud (REST Saved Searches API)
- Elastic Security (Kibana Detection Engine Rules API)
- Rapid7 InsightIDR (Log Search Saved Queries API)
- SentinelOne (Deep Visibility Saved Queries API)

Includes safe dry-run simulation mode, payload schema validation, environment-based credential
discovery, and fault-isolated error handling.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar, Dict, List, Optional
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DeploymentPayload:
    """A search query and associated metadata to be deployed to a target SIEM or EDR."""

    hunt_id: str
    rule_title: str
    target: str
    dialect: str
    query: str
    description: str = ""
    severity: str = "high"
    techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    author: str = "hecate"


@dataclass
class DeploymentResult:
    """The outcome of a query deployment attempt."""

    target: str
    status: str  # "deployed" | "dry_run" | "skipped" | "error"
    remote_id: Optional[str] = None
    detail: str = ""
    request_summary: Dict[str, Any] = field(default_factory=dict)
    deployed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    dry_run: bool = True

    @property
    def ok(self) -> bool:
        return self.status in {"deployed", "dry_run"}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        return d


@dataclass
class UndeploymentPayload:
    """A target query and associated metadata to be undeployed from a target SIEM or EDR."""

    hunt_id: str
    rule_title: str
    target: str
    remote_id: Optional[str] = None
    query: str = ""


@dataclass
class UndeploymentResult:
    """The outcome of a query undeployment/teardown attempt."""

    target: str
    status: str  # "undeployed" | "not_found" | "dry_run" | "skipped" | "error"
    remote_id: Optional[str] = None
    detail: str = ""
    request_summary: Dict[str, Any] = field(default_factory=dict)
    undeployed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    dry_run: bool = True

    @property
    def ok(self) -> bool:
        return self.status in {"undeployed", "not_found", "dry_run"}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        return d


@dataclass
class SyncResult:
    """The outcome of verifying synchronization and detecting drift against a target SIEM."""

    target: str
    status: str  # "in_sync" | "drift_detected" | "missing_remote" | "dry_run" | "skipped" | "error"
    remote_id: Optional[str] = None
    local_query: str = ""
    remote_query: Optional[str] = None
    detail: str = ""
    drift_diff: Optional[str] = None
    request_summary: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    dry_run: bool = True

    @property
    def ok(self) -> bool:
        return self.status in {"in_sync", "dry_run"}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        return d


class QueryDeployer:
    """Manages direct API deployment of transpiled queries across enterprise SIEMs/EDRs."""

    TARGET_SENTINEL = "sentinel_kql"
    TARGET_CROWDSTRIKE = "crowdstrike_cql"
    TARGET_RAPID7 = "rapid7_leql"
    TARGET_SENTINELONE = "sentinelone_s1ql"
    TARGET_SPLUNK = "splunk_spl"
    TARGET_ELASTIC = "elastic_eql"

    SUPPORTED_TARGETS: ClassVar[List[str]] = [
        TARGET_SENTINEL,
        TARGET_CROWDSTRIKE,
        TARGET_RAPID7,
        TARGET_SENTINELONE,
        TARGET_SPLUNK,
        TARGET_ELASTIC,
    ]

    def __init__(self, timeout_sec: float = 30.0) -> None:
        self.timeout_sec = timeout_sec
        try:
            from dotenv import load_dotenv

            load_dotenv(override=False)
            ws = os.getenv("HECATE_WORKSPACE")
            if ws and os.path.isdir(ws):
                load_dotenv(os.path.join(ws, ".env"), override=False)
        except ImportError:
            pass

    def deploy(
        self,
        payload: DeploymentPayload,
        dry_run: bool = True,
    ) -> DeploymentResult:
        """Deploy a transpiled query to its target platform.

        Args:
            payload: The deployment payload including target, query, and hunt metadata.
            dry_run: When True, simulates the API request and validates payload structure
                     without making external network calls. Defaults to True.

        Returns:
            DeploymentResult detailing status, remote ID or dry-run payload.
        """
        target = payload.target.lower()

        if target not in self.SUPPORTED_TARGETS:
            return DeploymentResult(
                target=target,
                status="skipped",
                detail=f"Unsupported deployment target '{target}'",
                dry_run=dry_run,
            )

        if not payload.query or not payload.query.strip():
            return DeploymentResult(
                target=target,
                status="error",
                detail="Cannot deploy empty query",
                dry_run=dry_run,
            )

        try:
            if target == self.TARGET_SENTINEL:
                return self._deploy_sentinel(payload, dry_run=dry_run)
            if target == self.TARGET_CROWDSTRIKE:
                return self._deploy_crowdstrike(payload, dry_run=dry_run)
            if target == self.TARGET_RAPID7:
                return self._deploy_rapid7(payload, dry_run=dry_run)
            if target == self.TARGET_SENTINELONE:
                return self._deploy_sentinelone(payload, dry_run=dry_run)
            if target == self.TARGET_SPLUNK:
                return self._deploy_splunk(payload, dry_run=dry_run)
            if target == self.TARGET_ELASTIC:
                return self._deploy_elastic(payload, dry_run=dry_run)
        except Exception as exc:
            logger.warning("Deployment failed unexpectedly for %s: %s", target, exc)
            return DeploymentResult(
                target=target,
                status="error",
                detail=f"Deployment exception: {exc}",
                dry_run=dry_run,
            )

        return DeploymentResult(
            target=target,
            status="skipped",
            detail=f"No dispatcher implemented for {target}",
            dry_run=dry_run,
        )

    @classmethod
    def compute_remote_id(
        cls,
        target: str,
        hunt_id: str,
        rule_title: str,
        query: str = "",
    ) -> str:
        """Compute the deterministic remote identifier for a query on a target platform."""
        tgt = target.lower()
        if tgt == cls.TARGET_SPLUNK:
            title_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", rule_title).strip("_")
            q_hash = hashlib.sha256(f"{rule_title}:{query}".encode()).hexdigest()[:6]
            return f"Hecate_{hunt_id}_{title_slug[:30]}_{q_hash}"
        if tgt == cls.TARGET_SENTINEL:
            slug = "".join(c if c.isalnum() else "_" for c in rule_title.lower())[:40]
            clean_hunt = hunt_id.lower().replace("-", "_")
            return f"hecate_{clean_hunt}_{slug}".strip("_")
        if tgt == cls.TARGET_ELASTIC:
            rule_slug = "".join(c if c.isalnum() else "-" for c in rule_title.lower())[:30]
            return f"hecate-{hunt_id.lower()}-{rule_slug}"
        if tgt == cls.TARGET_CROWDSTRIKE:
            return f"cql_{hunt_id.lower()}"
        if tgt == cls.TARGET_RAPID7:
            return f"r7_{hunt_id.lower()}"
        if tgt == cls.TARGET_SENTINELONE:
            return f"s1_{hunt_id.lower()}"
        return f"{tgt}_{hunt_id.lower()}"

    def undeploy(
        self,
        payload: UndeploymentPayload,
        dry_run: bool = True,
    ) -> UndeploymentResult:
        """Undeploy/remove a search query from its target platform.

        Args:
            payload: The undeployment payload including target, hunt metadata, and optional remote_id.
            dry_run: When True, simulates the API teardown request without making external network calls.

        Returns:
            UndeploymentResult detailing teardown status.
        """
        target = payload.target.lower()

        if target not in self.SUPPORTED_TARGETS:
            return UndeploymentResult(
                target=target,
                status="skipped",
                detail=f"Unsupported deployment target '{target}'",
                dry_run=dry_run,
            )

        try:
            if target == self.TARGET_SENTINEL:
                return self._undeploy_sentinel(payload, dry_run=dry_run)
            if target == self.TARGET_CROWDSTRIKE:
                return self._undeploy_crowdstrike(payload, dry_run=dry_run)
            if target == self.TARGET_RAPID7:
                return self._undeploy_rapid7(payload, dry_run=dry_run)
            if target == self.TARGET_SENTINELONE:
                return self._undeploy_sentinelone(payload, dry_run=dry_run)
            if target == self.TARGET_SPLUNK:
                return self._undeploy_splunk(payload, dry_run=dry_run)
            if target == self.TARGET_ELASTIC:
                return self._undeploy_elastic(payload, dry_run=dry_run)
        except Exception as exc:
            logger.warning("Undeployment failed unexpectedly for %s: %s", target, exc)
            return UndeploymentResult(
                target=target,
                status="error",
                detail=f"Undeployment exception: {exc}",
                dry_run=dry_run,
            )

        return UndeploymentResult(
            target=target,
            status="skipped",
            detail=f"No teardown dispatcher implemented for {target}",
            dry_run=dry_run,
        )

    def sync(
        self,
        payload: DeploymentPayload,
        dry_run: bool = True,
    ) -> SyncResult:
        """Verify synchronization and detect drift for a query on its target platform.

        Args:
            payload: The deployment payload representing current local state.
            dry_run: When True, simulates the sync check without making network calls.

        Returns:
            SyncResult detailing sync status and drift diff if any.
        """
        target = payload.target.lower()

        if target not in self.SUPPORTED_TARGETS:
            return SyncResult(
                target=target,
                status="skipped",
                detail=f"Unsupported target '{target}'",
                dry_run=dry_run,
            )

        try:
            if target == self.TARGET_SENTINEL:
                return self._sync_sentinel(payload, dry_run=dry_run)
            if target == self.TARGET_CROWDSTRIKE:
                return self._sync_crowdstrike(payload, dry_run=dry_run)
            if target == self.TARGET_RAPID7:
                return self._sync_rapid7(payload, dry_run=dry_run)
            if target == self.TARGET_SENTINELONE:
                return self._sync_sentinelone(payload, dry_run=dry_run)
            if target == self.TARGET_SPLUNK:
                return self._sync_splunk(payload, dry_run=dry_run)
            if target == self.TARGET_ELASTIC:
                return self._sync_elastic(payload, dry_run=dry_run)
        except Exception as exc:
            logger.warning("Sync check failed unexpectedly for %s: %s", target, exc)
            return SyncResult(
                target=target,
                status="error",
                detail=f"Sync exception: {exc}",
                dry_run=dry_run,
            )

        return SyncResult(
            target=target,
            status="skipped",
            detail=f"No sync dispatcher implemented for {target}",
            dry_run=dry_run,
        )

    def _deploy_sentinel(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to Microsoft Sentinel as a Log Analytics Saved Search."""
        workspace_id = os.getenv("SENTINEL_WORKSPACE_ID")
        sub_id = os.getenv("SENTINEL_SUBSCRIPTION_ID")
        rg = os.getenv("SENTINEL_RESOURCE_GROUP")
        token = os.getenv("SENTINEL_BEARER_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")

        search_id = self.compute_remote_id(
            self.TARGET_SENTINEL, payload.hunt_id, payload.rule_title, payload.query
        )
        display_name = f"[{payload.hunt_id}] {payload.rule_title}"

        endpoint = (
            f"https://management.azure.com/subscriptions/{sub_id or 'SUB_ID'}/resourceGroups/"
            f"{rg or 'RG'}/providers/Microsoft.OperationalInsights/workspaces/{workspace_id or 'WORKSPACE_ID'}/"
            f"savedSearches/{search_id}?api-version=2020-08-01"
        )
        body = {
            "properties": {
                "category": "Hecate Autonomous Threat Hunts",
                "displayName": display_name,
                "query": payload.query.strip(),
                "tags": [
                    {"name": "HuntId", "value": payload.hunt_id},
                    {"name": "ManagedBy", "value": "Hecate"},
                ]
                + [{"name": "Technique", "value": t} for t in payload.techniques],
            }
        }

        req_summary = {
            "method": "PUT",
            "url": endpoint,
            "headers": {"Authorization": "Bearer ***", "Content-Type": "application/json"},
            "body": body,
        }

        if dry_run or not (workspace_id and sub_id and rg and token):
            reason = "dry_run mode" if dry_run else "missing Sentinel credentials (WORKSPACE_ID/SUB_ID/RG/TOKEN)"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_id,
                detail=f"Validated Sentinel Saved Search payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.put(endpoint, json=body, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=search_id,
                detail=f"Successfully deployed Saved Search to Microsoft Sentinel ({resp.status_code})",
                request_summary=req_summary,
                dry_run=False,
            )

    def _deploy_crowdstrike(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to CrowdStrike Falcon / LogScale Saved Queries API."""
        base_url = (os.getenv("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
        repo = os.getenv("FALCON_LOGSCALE_REPO") or "default"
        token = os.getenv("FALCON_API_TOKEN") or os.getenv("FALCON_BEARER_TOKEN")

        endpoint = f"{base_url}/api/v1/repositories/{repo}/queries"
        name = f"[{payload.hunt_id}] {payload.rule_title}"
        body = {
            "name": name,
            "queryString": payload.query.strip(),
            "description": f"Hecate threat hunt {payload.hunt_id} query ({', '.join(payload.techniques)})",
        }
        req_summary = {
            "method": "POST",
            "url": endpoint,
            "headers": {"Authorization": "Bearer ***", "Content-Type": "application/json"},
            "body": body,
        }

        if dry_run or not token:
            reason = "dry_run mode" if dry_run else "missing FALCON_API_TOKEN credentials"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=self.compute_remote_id(
                    self.TARGET_CROWDSTRIKE, payload.hunt_id, payload.rule_title, payload.query
                ),
                detail=f"Validated Falcon LogScale Query payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.post(endpoint, json=body, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            data = resp.json()
            remote_id = data.get("id") or str(resp.status_code)
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=remote_id,
                detail="Successfully deployed query to CrowdStrike Falcon LogScale",
                request_summary=req_summary,
                dry_run=False,
            )

    def _deploy_rapid7(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to Rapid7 InsightIDR Log Search Saved Queries API."""
        api_key = os.getenv("RAPID7_API_KEY")
        region = (os.getenv("RAPID7_REGION") or "us").lower()

        endpoint = f"https://{region}.rest.logs.insight.rapid7.com/management/saved_queries"
        name = f"[{payload.hunt_id}] {payload.rule_title}"
        body = {
            "saved_query": {
                "name": name,
                "leql": {"statement": payload.query.strip()},
            }
        }
        req_summary = {
            "method": "POST",
            "url": endpoint,
            "headers": {"x-api-key": "***", "Content-Type": "application/json"},
            "body": body,
        }

        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing RAPID7_API_KEY credentials"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=self.compute_remote_id(
                    self.TARGET_RAPID7, payload.hunt_id, payload.rule_title, payload.query
                ),
                detail=f"Validated Rapid7 InsightIDR LEQL payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.post(endpoint, json=body, headers={"x-api-key": api_key})
            resp.raise_for_status()
            data = resp.json()
            remote_id = data.get("saved_query", {}).get("id") or str(resp.status_code)
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=remote_id,
                detail="Successfully deployed Saved Query to Rapid7 InsightIDR",
                request_summary=req_summary,
                dry_run=False,
            )

    def _deploy_sentinelone(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to SentinelOne Deep Visibility Saved Queries API."""
        s1_url = (os.getenv("SENTINELONE_URL") or "https://usea1.sentinelone.net").rstrip("/")
        api_token = os.getenv("SENTINELONE_API_TOKEN")

        endpoint = f"{s1_url}/web/api/v2.1/dv/saved-queries"
        name = f"[{payload.hunt_id}] {payload.rule_title}"
        body = {
            "data": {
                "name": name,
                "query": payload.query.strip(),
                "description": f"Hecate hunt {payload.hunt_id} for {', '.join(payload.techniques)}",
            }
        }
        req_summary = {
            "method": "POST",
            "url": endpoint,
            "headers": {"Authorization": "ApiToken ***", "Content-Type": "application/json"},
            "body": body,
        }

        if dry_run or not api_token:
            reason = "dry_run mode" if dry_run else "missing SENTINELONE_API_TOKEN credentials"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=self.compute_remote_id(
                    self.TARGET_SENTINELONE, payload.hunt_id, payload.rule_title, payload.query
                ),
                detail=f"Validated SentinelOne Deep Visibility payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.post(endpoint, json=body, headers={"Authorization": f"ApiToken {api_token}"})
            resp.raise_for_status()
            data = resp.json()
            remote_id = data.get("data", {}).get("id") or str(resp.status_code)
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=remote_id,
                detail="Successfully deployed Saved Query to SentinelOne Deep Visibility",
                request_summary=req_summary,
                dry_run=False,
            )

    def _deploy_splunk(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to Splunk Enterprise / Cloud REST Saved Searches API."""
        splunk_url = (os.getenv("SPLUNK_URL") or os.getenv("SPLUNK_HOST") or "https://localhost:8089").rstrip("/")
        if not splunk_url.startswith(("http://", "https://")):
            splunk_url = f"https://{splunk_url}"
        token = os.getenv("SPLUNK_TOKEN") or os.getenv("SPLUNK_API_TOKEN")
        password = os.getenv("SPLUNK_PASSWORD")
        app = os.getenv("SPLUNK_APP") or "search"
        user = os.getenv("SPLUNK_USER") or "nobody"

        # Construct unique, URL-safe search name using slug + query hash to prevent collisions
        search_name = self.compute_remote_id(
            self.TARGET_SPLUNK, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{splunk_url}/servicesNS/{user}/{app}/saved/searches"

        # Format search string if not already starting with search
        search_query = payload.query.strip()
        if not search_query.startswith("|") and not search_query.startswith("search "):
            search_query = f"search {search_query}"

        data = {
            "name": search_name,
            "search": search_query,
            "description": f"Hecate Hunt {payload.hunt_id}: {payload.rule_title}",
            "is_scheduled": "0",
            "output_mode": "json",
        }

        auth_header = None
        if token:
            auth_header = token if token.startswith(("Bearer ", "Basic ", "Splunk ")) else f"Bearer {token}"
        elif password:
            import base64

            auth_user = os.getenv("SPLUNK_AUTH_USER") or os.getenv("SPLUNK_USERNAME") or "admin"
            b64_creds = base64.b64encode(f"{auth_user}:{password}".encode()).decode()
            auth_header = f"Basic {b64_creds}"

        req_summary = {
            "method": "POST",
            "url": endpoint,
            "headers": {
                "Authorization": "Basic ***" if (password and not token) else "Bearer ***",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "form_data": data,
        }

        if dry_run or not auth_header:
            reason = "dry_run mode" if dry_run else "missing SPLUNK_TOKEN or SPLUNK_PASSWORD credentials"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_name,
                detail=f"Validated Splunk Saved Search payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        with httpx.Client(timeout=self.timeout_sec, verify=verify_ssl) as client:
            resp = client.post(endpoint, data=data, headers={"Authorization": auth_header})
            if resp.status_code == 409:
                # Saved search already exists — update it idempotently
                update_url = f"{endpoint}/{quote_plus(search_name)}"
                update_data = {
                    "search": search_query,
                    "description": f"Hecate Hunt {payload.hunt_id}: {payload.rule_title}",
                    "output_mode": "json",
                }
                resp = client.post(update_url, data=update_data, headers={"Authorization": auth_header})
            resp.raise_for_status()
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=search_name,
                detail="Successfully deployed Saved Search to Splunk Enterprise/Cloud",
                request_summary=req_summary,
                dry_run=False,
            )

    def _deploy_elastic(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to Elastic Security Detection Engine Rules API."""
        elastic_url = (os.getenv("ELASTIC_URL") or os.getenv("KIBANA_URL") or "https://localhost:5601").rstrip("/")
        api_key = os.getenv("ELASTIC_API_KEY")

        endpoint = f"{elastic_url}/api/detection_engine/rules"
        rule_id = self.compute_remote_id(
            self.TARGET_ELASTIC, payload.hunt_id, payload.rule_title, payload.query
        )
        name = f"[{payload.hunt_id}] {payload.rule_title}"

        body = {
            "rule_id": rule_id,
            "name": name,
            "type": "eql",
            "language": "eql",
            "query": payload.query.strip(),
            "severity": payload.severity.lower()
            if payload.severity.lower() in {"low", "medium", "high", "critical"}
            else "high",
            "risk_score": 73 if payload.severity == "high" else 47,
            "description": f"Hecate threat hunt {payload.hunt_id} detection rule ({payload.rule_title})",
            "tags": ["hecate", payload.hunt_id] + payload.techniques,
            "enabled": False,
        }
        req_summary = {
            "method": "POST",
            "url": endpoint,
            "headers": {"Authorization": "ApiKey ***", "kbn-xsrf": "true", "Content-Type": "application/json"},
            "body": body,
        }

        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing ELASTIC_API_KEY credentials"
            return DeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=rule_id,
                detail=f"Validated Elastic Detection Engine Rule payload ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.post(
                endpoint,
                json=body,
                headers={"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"},
            )
            resp.raise_for_status()
            data = resp.json()
            remote_id = data.get("id") or rule_id
            return DeploymentResult(
                target=payload.target,
                status="deployed",
                remote_id=remote_id,
                detail="Successfully deployed Detection Rule to Elastic Security",
                request_summary=req_summary,
                dry_run=False,
            )

    def _undeploy_sentinel(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete Saved Search from Microsoft Sentinel."""
        workspace_id = os.getenv("SENTINEL_WORKSPACE_ID")
        sub_id = os.getenv("SENTINEL_SUBSCRIPTION_ID")
        rg = os.getenv("SENTINEL_RESOURCE_GROUP")
        token = os.getenv("SENTINEL_BEARER_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")

        search_id = payload.remote_id or self.compute_remote_id(
            self.TARGET_SENTINEL, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = (
            f"https://management.azure.com/subscriptions/{sub_id or 'SUB_ID'}/resourceGroups/"
            f"{rg or 'RG'}/providers/Microsoft.OperationalInsights/workspaces/{workspace_id or 'WORKSPACE_ID'}/"
            f"savedSearches/{search_id}?api-version=2020-08-01"
        )
        req_summary = {
            "method": "DELETE",
            "url": endpoint,
            "headers": {"Authorization": "Bearer ***"},
        }
        if dry_run or not (workspace_id and sub_id and rg and token):
            reason = "dry_run mode" if dry_run else "missing Sentinel credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_id,
                detail=f"Validated Sentinel Saved Search undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.delete(endpoint, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=search_id,
                    detail=f"Saved Search '{search_id}' not found in Microsoft Sentinel",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=search_id,
                detail=f"Successfully deleted Saved Search '{search_id}' from Microsoft Sentinel",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_sentinel(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against Microsoft Sentinel."""
        workspace_id = os.getenv("SENTINEL_WORKSPACE_ID")
        sub_id = os.getenv("SENTINEL_SUBSCRIPTION_ID")
        rg = os.getenv("SENTINEL_RESOURCE_GROUP")
        token = os.getenv("SENTINEL_BEARER_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")

        search_id = self.compute_remote_id(self.TARGET_SENTINEL, payload.hunt_id, payload.rule_title, payload.query)
        endpoint = (
            f"https://management.azure.com/subscriptions/{sub_id or 'SUB_ID'}/resourceGroups/"
            f"{rg or 'RG'}/providers/Microsoft.OperationalInsights/workspaces/{workspace_id or 'WORKSPACE_ID'}/"
            f"savedSearches/{search_id}?api-version=2020-08-01"
        )
        req_summary = {"method": "GET", "url": endpoint, "headers": {"Authorization": "Bearer ***"}}

        if dry_run or not (workspace_id and sub_id and rg and token):
            reason = "dry_run mode" if dry_run else "missing Sentinel credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_id,
                local_query=payload.query,
                detail=f"Validated Sentinel sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=search_id,
                    local_query=payload.query,
                    detail=f"Saved Search '{search_id}' does not exist in Microsoft Sentinel",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            remote_query = resp.json().get("properties", {}).get("query", "").strip()
            if remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=search_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{search_id}' is in sync with local query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=search_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Query drift detected for '{search_id}'",
                    drift_diff=f"- Local:  {payload.query.strip()}\n+ Remote: {remote_query}",
                    request_summary=req_summary,
                    dry_run=False,
                )

    def _undeploy_crowdstrike(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete saved query from CrowdStrike Falcon LogScale."""
        base_url = (os.getenv("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
        repo = os.getenv("FALCON_LOGSCALE_REPO") or "default"
        token = os.getenv("FALCON_API_TOKEN") or os.getenv("FALCON_BEARER_TOKEN")

        remote_id = payload.remote_id or self.compute_remote_id(
            self.TARGET_CROWDSTRIKE, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{base_url}/api/v1/repositories/{repo}/queries/{remote_id}"
        req_summary = {"method": "DELETE", "url": endpoint, "headers": {"Authorization": "Bearer ***"}}

        if dry_run or not token:
            reason = "dry_run mode" if dry_run else "missing FALCON_API_TOKEN credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                detail=f"Validated Falcon LogScale undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.delete(endpoint, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=remote_id,
                    detail=f"LogScale query '{remote_id}' not found",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=remote_id,
                detail=f"Successfully deleted query '{remote_id}' from Falcon LogScale",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_crowdstrike(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against CrowdStrike Falcon LogScale."""
        base_url = (os.getenv("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
        repo = os.getenv("FALCON_LOGSCALE_REPO") or "default"
        token = os.getenv("FALCON_API_TOKEN") or os.getenv("FALCON_BEARER_TOKEN")

        remote_id = self.compute_remote_id(self.TARGET_CROWDSTRIKE, payload.hunt_id, payload.rule_title, payload.query)
        endpoint = f"{base_url}/api/v1/repositories/{repo}/queries/{remote_id}"
        req_summary = {"method": "GET", "url": endpoint, "headers": {"Authorization": "Bearer ***"}}

        if dry_run or not token:
            reason = "dry_run mode" if dry_run else "missing FALCON_API_TOKEN credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                local_query=payload.query,
                detail=f"Validated Falcon LogScale sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=remote_id,
                    local_query=payload.query,
                    detail=f"Falcon LogScale query '{remote_id}' does not exist",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            remote_query = resp.json().get("queryString", "").strip()
            if remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{remote_id}' is in sync with local query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Query drift detected for '{remote_id}'",
                    drift_diff=f"- Local:  {payload.query.strip()}\n+ Remote: {remote_query}",
                    request_summary=req_summary,
                    dry_run=False,
                )

    def _undeploy_rapid7(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete saved query from Rapid7 InsightIDR."""
        api_key = os.getenv("RAPID7_API_KEY")
        region = (os.getenv("RAPID7_REGION") or "us").lower()

        remote_id = payload.remote_id or self.compute_remote_id(
            self.TARGET_RAPID7, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"https://{region}.rest.logs.insight.rapid7.com/management/saved_queries/{remote_id}"
        req_summary = {"method": "DELETE", "url": endpoint, "headers": {"x-api-key": "***"}}

        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing RAPID7_API_KEY credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                detail=f"Validated Rapid7 InsightIDR undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.delete(endpoint, headers={"x-api-key": api_key})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=remote_id,
                    detail=f"Saved query '{remote_id}' not found in Rapid7 InsightIDR",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=remote_id,
                detail=f"Successfully deleted query '{remote_id}' from Rapid7 InsightIDR",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_rapid7(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against Rapid7 InsightIDR."""
        api_key = os.getenv("RAPID7_API_KEY")
        region = (os.getenv("RAPID7_REGION") or "us").lower()

        remote_id = self.compute_remote_id(self.TARGET_RAPID7, payload.hunt_id, payload.rule_title, payload.query)
        endpoint = f"https://{region}.rest.logs.insight.rapid7.com/management/saved_queries/{remote_id}"
        req_summary = {"method": "GET", "url": endpoint, "headers": {"x-api-key": "***"}}

        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing RAPID7_API_KEY credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                local_query=payload.query,
                detail=f"Validated Rapid7 sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.get(endpoint, headers={"x-api-key": api_key})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=remote_id,
                    local_query=payload.query,
                    detail=f"Rapid7 saved query '{remote_id}' does not exist",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            remote_query = resp.json().get("saved_query", {}).get("leql", {}).get("statement", "").strip()
            if remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{remote_id}' is in sync with local query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Query drift detected for '{remote_id}'",
                    drift_diff=f"- Local:  {payload.query.strip()}\n+ Remote: {remote_query}",
                    request_summary=req_summary,
                    dry_run=False,
                )

    def _undeploy_sentinelone(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete saved query from SentinelOne Deep Visibility."""
        s1_url = (os.getenv("SENTINELONE_URL") or "https://usea1.sentinelone.net").rstrip("/")
        api_token = os.getenv("SENTINELONE_API_TOKEN")

        remote_id = payload.remote_id or self.compute_remote_id(
            self.TARGET_SENTINELONE, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{s1_url}/web/api/v2.1/dv/saved-queries/{remote_id}"
        req_summary = {"method": "DELETE", "url": endpoint, "headers": {"Authorization": "ApiToken ***"}}

        if dry_run or not api_token:
            reason = "dry_run mode" if dry_run else "missing SENTINELONE_API_TOKEN credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                detail=f"Validated SentinelOne Deep Visibility undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.delete(endpoint, headers={"Authorization": f"ApiToken {api_token}"})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=remote_id,
                    detail=f"Saved query '{remote_id}' not found in SentinelOne",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=remote_id,
                detail=f"Successfully deleted query '{remote_id}' from SentinelOne",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_sentinelone(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against SentinelOne Deep Visibility."""
        s1_url = (os.getenv("SENTINELONE_URL") or "https://usea1.sentinelone.net").rstrip("/")
        api_token = os.getenv("SENTINELONE_API_TOKEN")

        remote_id = self.compute_remote_id(self.TARGET_SENTINELONE, payload.hunt_id, payload.rule_title, payload.query)
        endpoint = f"{s1_url}/web/api/v2.1/dv/saved-queries/{remote_id}"
        req_summary = {"method": "GET", "url": endpoint, "headers": {"Authorization": "ApiToken ***"}}

        if dry_run or not api_token:
            reason = "dry_run mode" if dry_run else "missing SENTINELONE_API_TOKEN credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=remote_id,
                local_query=payload.query,
                detail=f"Validated SentinelOne sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.get(endpoint, headers={"Authorization": f"ApiToken {api_token}"})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=remote_id,
                    local_query=payload.query,
                    detail=f"SentinelOne saved query '{remote_id}' does not exist",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            remote_query = resp.json().get("data", {}).get("query", "").strip()
            if remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{remote_id}' is in sync with local query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=remote_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Query drift detected for '{remote_id}'",
                    drift_diff=f"- Local:  {payload.query.strip()}\n+ Remote: {remote_query}",
                    request_summary=req_summary,
                    dry_run=False,
                )

    def _undeploy_splunk(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete Saved Search from Splunk REST API."""
        splunk_url = (os.getenv("SPLUNK_URL") or os.getenv("SPLUNK_HOST") or "https://localhost:8089").rstrip("/")
        if not splunk_url.startswith(("http://", "https://")):
            splunk_url = f"https://{splunk_url}"
        token = os.getenv("SPLUNK_TOKEN") or os.getenv("SPLUNK_API_TOKEN")
        password = os.getenv("SPLUNK_PASSWORD")
        app = os.getenv("SPLUNK_APP") or "search"
        user = os.getenv("SPLUNK_USER") or "nobody"

        search_name = payload.remote_id or self.compute_remote_id(
            self.TARGET_SPLUNK, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{splunk_url}/servicesNS/{user}/{app}/saved/searches/{quote_plus(search_name)}"

        auth_header = None
        if token:
            auth_header = token if token.startswith(("Bearer ", "Basic ", "Splunk ")) else f"Bearer {token}"
        elif password:
            import base64

            auth_user = os.getenv("SPLUNK_AUTH_USER") or os.getenv("SPLUNK_USERNAME") or "admin"
            b64_creds = base64.b64encode(f"{auth_user}:{password}".encode()).decode()
            auth_header = f"Basic {b64_creds}"

        req_summary = {
            "method": "DELETE",
            "url": endpoint,
            "headers": {
                "Authorization": "Basic ***" if (password and not token) else "Bearer ***",
            },
        }

        if dry_run or not auth_header:
            reason = "dry_run mode" if dry_run else "missing SPLUNK_TOKEN or SPLUNK_PASSWORD credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_name,
                detail=f"Validated Splunk Saved Search undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        with httpx.Client(timeout=self.timeout_sec, verify=verify_ssl) as client:
            resp = client.delete(endpoint, headers={"Authorization": auth_header})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=search_name,
                    detail=f"Saved Search '{search_name}' was not found in Splunk (already removed)",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=search_name,
                detail=f"Successfully deleted Saved Search '{search_name}' from Splunk",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_splunk(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against Splunk REST API."""
        splunk_url = (os.getenv("SPLUNK_URL") or os.getenv("SPLUNK_HOST") or "https://localhost:8089").rstrip("/")
        if not splunk_url.startswith(("http://", "https://")):
            splunk_url = f"https://{splunk_url}"
        token = os.getenv("SPLUNK_TOKEN") or os.getenv("SPLUNK_API_TOKEN")
        password = os.getenv("SPLUNK_PASSWORD")
        app = os.getenv("SPLUNK_APP") or "search"
        user = os.getenv("SPLUNK_USER") or "nobody"

        search_name = self.compute_remote_id(
            self.TARGET_SPLUNK, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{splunk_url}/servicesNS/{user}/{app}/saved/searches/{quote_plus(search_name)}?output_mode=json"

        auth_header = None
        if token:
            auth_header = token if token.startswith(("Bearer ", "Basic ", "Splunk ")) else f"Bearer {token}"
        elif password:
            import base64

            auth_user = os.getenv("SPLUNK_AUTH_USER") or os.getenv("SPLUNK_USERNAME") or "admin"
            b64_creds = base64.b64encode(f"{auth_user}:{password}".encode()).decode()
            auth_header = f"Basic {b64_creds}"

        req_summary = {
            "method": "GET",
            "url": endpoint,
            "headers": {
                "Authorization": "Basic ***" if (password and not token) else "Bearer ***",
            },
        }

        if dry_run or not auth_header:
            reason = "dry_run mode" if dry_run else "missing SPLUNK_TOKEN or SPLUNK_PASSWORD credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=search_name,
                local_query=payload.query,
                detail=f"Validated Splunk sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        with httpx.Client(timeout=self.timeout_sec, verify=verify_ssl) as client:
            resp = client.get(endpoint, headers={"Authorization": auth_header})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=search_name,
                    local_query=payload.query,
                    detail=f"Saved Search '{search_name}' does not exist in Splunk",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("entry", [])
            if not entries:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=search_name,
                    local_query=payload.query,
                    detail=f"No entry found for Saved Search '{search_name}'",
                    request_summary=req_summary,
                    dry_run=False,
                )

            remote_query = entries[0].get("content", {}).get("search", "").strip()

            expected_query = payload.query.strip()
            if not expected_query.startswith("|") and not expected_query.startswith("search "):
                expected_query = f"search {expected_query}"

            if remote_query == expected_query or remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=search_name,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{search_name}' is in sync with local transpiled query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                drift_diff = f"- Local:  {expected_query}\n+ Remote: {remote_query}"
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=search_name,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{search_name}' has drifted from local transpiled query",
                    drift_diff=drift_diff,
                    request_summary=req_summary,
                    dry_run=False,
                )

    def _undeploy_elastic(self, payload: UndeploymentPayload, dry_run: bool) -> UndeploymentResult:
        """Teardown/delete Detection Rule from Elastic Security."""
        elastic_url = (os.getenv("ELASTIC_URL") or os.getenv("KIBANA_URL") or "https://localhost:5601").rstrip("/")
        api_key = os.getenv("ELASTIC_API_KEY")

        rule_id = payload.remote_id or self.compute_remote_id(
            self.TARGET_ELASTIC, payload.hunt_id, payload.rule_title, payload.query
        )
        endpoint = f"{elastic_url}/api/detection_engine/rules?rule_id={rule_id}"
        req_summary = {
            "method": "DELETE",
            "url": endpoint,
            "headers": {"Authorization": "ApiKey ***", "kbn-xsrf": "true"},
        }
        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing ELASTIC_API_KEY credentials"
            return UndeploymentResult(
                target=payload.target,
                status="dry_run",
                remote_id=rule_id,
                detail=f"Validated Elastic Detection Engine Rule undeploy contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.delete(endpoint, headers={"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"})
            if resp.status_code == 404:
                return UndeploymentResult(
                    target=payload.target,
                    status="not_found",
                    remote_id=rule_id,
                    detail=f"Detection Rule '{rule_id}' not found in Elastic Security",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            return UndeploymentResult(
                target=payload.target,
                status="undeployed",
                remote_id=rule_id,
                detail=f"Successfully deleted Detection Rule '{rule_id}' from Elastic Security",
                request_summary=req_summary,
                dry_run=False,
            )

    def _sync_elastic(self, payload: DeploymentPayload, dry_run: bool) -> SyncResult:
        """Verify synchronization and drift against Elastic Security Detection Engine."""
        elastic_url = (os.getenv("ELASTIC_URL") or os.getenv("KIBANA_URL") or "https://localhost:5601").rstrip("/")
        api_key = os.getenv("ELASTIC_API_KEY")

        rule_id = self.compute_remote_id(self.TARGET_ELASTIC, payload.hunt_id, payload.rule_title, payload.query)
        endpoint = f"{elastic_url}/api/detection_engine/rules?rule_id={rule_id}"
        req_summary = {"method": "GET", "url": endpoint, "headers": {"Authorization": "ApiKey ***", "kbn-xsrf": "true"}}

        if dry_run or not api_key:
            reason = "dry_run mode" if dry_run else "missing ELASTIC_API_KEY credentials"
            return SyncResult(
                target=payload.target,
                status="dry_run",
                remote_id=rule_id,
                local_query=payload.query,
                detail=f"Validated Elastic sync check contract ({reason})",
                request_summary=req_summary,
                dry_run=True,
            )

        with httpx.Client(timeout=self.timeout_sec) as client:
            resp = client.get(endpoint, headers={"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"})
            if resp.status_code == 404:
                return SyncResult(
                    target=payload.target,
                    status="missing_remote",
                    remote_id=rule_id,
                    local_query=payload.query,
                    detail=f"Detection Rule '{rule_id}' does not exist in Elastic Security",
                    request_summary=req_summary,
                    dry_run=False,
                )
            resp.raise_for_status()
            remote_query = resp.json().get("query", "").strip()
            if remote_query == payload.query.strip():
                return SyncResult(
                    target=payload.target,
                    status="in_sync",
                    remote_id=rule_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Remote query '{rule_id}' is in sync with local query",
                    request_summary=req_summary,
                    dry_run=False,
                )
            else:
                return SyncResult(
                    target=payload.target,
                    status="drift_detected",
                    remote_id=rule_id,
                    local_query=payload.query,
                    remote_query=remote_query,
                    detail=f"Query drift detected for '{rule_id}'",
                    drift_diff=f"- Local:  {payload.query.strip()}\n+ Remote: {remote_query}",
                    request_summary=req_summary,
                    dry_run=False,
                )
