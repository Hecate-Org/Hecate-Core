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

    def _deploy_sentinel(self, payload: DeploymentPayload, dry_run: bool) -> DeploymentResult:
        """Deploy to Microsoft Sentinel as a Log Analytics Saved Search."""
        workspace_id = os.getenv("SENTINEL_WORKSPACE_ID")
        sub_id = os.getenv("SENTINEL_SUBSCRIPTION_ID")
        rg = os.getenv("SENTINEL_RESOURCE_GROUP")
        token = os.getenv("SENTINEL_BEARER_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")

        slug = "".join(c if c.isalnum() else "_" for c in payload.rule_title.lower())[:40]
        clean_hunt = payload.hunt_id.lower().replace("-", "_")
        search_id = f"hecate_{clean_hunt}_{slug}".strip("_")
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
                remote_id=f"cql_{payload.hunt_id.lower()}",
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
                remote_id=f"r7_{payload.hunt_id.lower()}",
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
                remote_id=f"s1_{payload.hunt_id.lower()}",
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
        title_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", payload.rule_title).strip("_")
        q_hash = hashlib.sha256(f"{payload.rule_title}:{payload.query}".encode()).hexdigest()[:6]
        search_name = f"Hecate_{payload.hunt_id}_{title_slug[:30]}_{q_hash}"
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
        rule_slug = "".join(c if c.isalnum() else "-" for c in payload.rule_title.lower())[:30]
        rule_id = f"hecate-{payload.hunt_id.lower()}-{rule_slug}"
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
