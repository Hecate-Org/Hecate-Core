"""URLScan.io scanning, sandboxed detonation, and web lure payload provider."""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import httpx
import yaml

from hecate_agent.core.sigma_semantics import semantic_problem

logger = logging.getLogger(__name__)


def _setting(name: str, default: str = "") -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment._setting(name, default)


def _misp_verify_tls() -> bool:
    from hecate_agent.orchestrator import enrichment
    return enrichment._misp_verify_tls()


def refang(value: str) -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment.refang(value)


def _get_apex_domain(domain: str) -> str:
    from hecate_agent.orchestrator import enrichment
    return enrichment._get_apex_domain(domain)


def _sleep(seconds: float) -> None:
    from hecate_agent.orchestrator import enrichment
    enrichment.time.sleep(seconds)


def _get_known_publishers() -> Set[str]:
    from hecate_agent.orchestrator import enrichment
    return getattr(enrichment, "_KNOWN_PUBLISHER_DOMAINS", set())


_URLSCAN_CACHE: Dict[str, Tuple[float, str]] = {}


_URLSCAN_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_web_lure_payloads(text: str) -> List[Dict[str, str]]:
    """Inspect HTML/DOM/script contents to detect ClickFix, fake CAPTCHA, and clipboard injection lures."""
    results: List[Dict[str, str]] = []
    if not text:
        return results

    # 1. Direct clipboard writing literals: navigator.clipboard.writeText("...")
    direct_matches = re.finditer(
        r"""navigator\.clipboard\.writeText\(\s*(["'`])((?:\\.|(?!\1).)*)\1\s*\)""",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    for dm in direct_matches:
        raw = dm.group(2).replace(r"\"", '"').replace(r"\'", "'").strip()
        if raw and len(raw) >= 4:
            results.append({"command": raw, "source": "clipboard_writeText", "lure": "direct_clipboard_injection"})

    # 2. Variable-based clipboard writing: const cmd = "..."; navigator.clipboard.writeText(cmd);
    var_matches = re.finditer(
        r"""navigator\.clipboard\.writeText\(\s*([a-zA-Z0-9_$]+)\s*\)""",
        text,
        re.IGNORECASE,
    )
    for vm in var_matches:
        var_name = vm.group(1)
        if var_name.lower() not in {"data", "event", "e"}:
            var_def = re.search(
                rf"""(?:const|let|var)\s+{re.escape(var_name)}\s*=\s*(["'`])((?:\\.|(?!\1).)*)\1""",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            if var_def:
                raw = var_def.group(2).replace(r"\"", '"').replace(r"\'", "'").strip()
                if raw and len(raw) >= 4 and not any(r["command"] == raw for r in results):
                    results.append(
                        {"command": raw, "source": f"clipboard_var({var_name})", "lure": "variable_clipboard_injection"}
                    )

    # 3. Fake CAPTCHA / Human verification prompt
    has_captcha_prompt = bool(
        re.search(
            r"""(verify\s+you\s+are\s+human|cloudflare\s+human\s+verification|robot\s+check|press\s+(?:win(?:dows)?(?:\s*key)?\s*\+\s*r|ctrl\s*\+\s*v|cmd\s*\+\s*v|terminal))""",
            text,
            re.IGNORECASE,
        )
    )

    # 4. Known command execution patterns in scripts
    cmd_patterns = [
        (
            "powershell",
            re.compile(
                r"""(?:powershell(?:\.exe)?|pwsh)\s+(?:-[a-zA-Z0-9_\-]+\s+)*(?:-[eE](?:nc(?:odedcommand)?)?|iex|invoke-expression)\s+["'`]?([^"'`\n;]+)""",
                re.IGNORECASE,
            ),
        ),
        (
            "bash",
            re.compile(
                r"""(?:curl|wget)\s+-[sSfLkA-Za-z0-9\-_./:=?&]+\s+https?://[^\s;&"'`]+(?:\s*\|\s*(?:ba)?sh\b)?""",
                re.IGNORECASE,
            ),
        ),
        ("mshta", re.compile(r"""mshta(?:\.exe)?\s+https?://[^\s;&"'`]+""", re.IGNORECASE)),
        ("osascript", re.compile(r"""osascript\s+-e\s+["']([^"']+)["']""", re.IGNORECASE)),
    ]
    for ctype, pat in cmd_patterns:
        for match in pat.finditer(text):
            cmd = match.group(0).strip().rstrip("\\")
            if len(cmd) >= 8 and not any(r["command"] == cmd for r in results):
                results.append(
                    {
                        "command": cmd,
                        "source": ctype,
                        "lure": "fake_captcha_lure" if has_captcha_prompt else "embedded_script",
                    }
                )

    return results


def query_urlscan_url(url: str, check_lures: bool = True) -> str:
    """Query URLScan.io API for recent scan verdicts, hosted infrastructure, redirect chains, and DOM lure scripts."""
    clean_url = url.strip()
    now = time.monotonic()
    cached = _URLSCAN_CACHE.get(f"url:{clean_url}")
    if cached and (now - cached[0] < _URLSCAN_CACHE_TTL):
        return cached[1]

    api_url = "https://urlscan.io/api/v1/search/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    query = f'page.url.keyword:"{clean_url}" OR page.url:"{clean_url}"'
    params: Dict[str, str | int] = {"q": query, "size": 1}

    try:
        resp = httpx.get(api_url, headers=headers, params=params, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                res = "Not indexed on URLScan.io."
                _URLSCAN_CACHE[f"url:{clean_url}"] = (now, res)
                return res

            r0 = results[0]
            verdicts = r0.get("verdicts", {})
            overall = verdicts.get("overall", {})
            malicious = overall.get("malicious", False)
            score = overall.get("score", 0)
            categories = overall.get("categories", [])
            brands = overall.get("brands", [])
            tags = overall.get("tags", [])

            page = r0.get("page", {})
            p_ip = page.get("ip", "unknown")
            p_asn = page.get("asn", "")
            p_asnname = page.get("asnname", "")
            p_country = page.get("country", "")
            p_title = page.get("title", "")

            result_url = r0.get("result", "")

            status_str = f"Malicious (Score: {score}/100)" if malicious else f"Benign/Neutral (Score: {score}/100)"
            parts = [f"Status: {status_str}"]

            if tags:
                parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
            if brands:
                parts.append(f"Target Brand: {', '.join(str(b) for b in brands[:3])}")

            host_parts = [p_ip]
            if p_asn:
                host_parts.append(f"{p_asn} {p_asnname}".strip())
            if p_country:
                host_parts.append(p_country)
            parts.append(f"Host: {' | '.join(host_parts)}")

            if p_title:
                parts.append(f"Title: {p_title[:45]}")

            if check_lures:
                text_corpus = f"{p_title} {' '.join(str(t) for t in tags)} {' '.join(str(c) for c in categories)}"
                lures = extract_web_lure_payloads(text_corpus)
                if lures:
                    parts.append(f"Lure: {lures[0]['command'][:60]}")

            if result_url:
                parts.append(f"Scan: {result_url}")

            res = " | ".join(parts)
            _URLSCAN_CACHE[f"url:{clean_url}"] = (now, res)
            return res
        elif resp.status_code == 429:
            return "URLScan.io rate limit exceeded."
        elif resp.status_code in (401, 403):
            return "URLScan.io Auth Error (check URLSCAN_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLScan.io: {e}"


def query_urlscan_domain(domain: str) -> str:
    """Query URLScan.io API for recent domain scan verdicts, lure activity, and IP/ASN hosting info."""
    clean_domain = domain.strip().lower()
    now = time.monotonic()
    cached = _URLSCAN_CACHE.get(f"domain:{clean_domain}")
    if cached and (now - cached[0] < _URLSCAN_CACHE_TTL):
        return cached[1]

    api_url = "https://urlscan.io/api/v1/search/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    query = f'page.domain:"{clean_domain}"'
    params: Dict[str, str | int] = {"q": query, "size": 1}

    try:
        resp = httpx.get(api_url, headers=headers, params=params, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                res = "Not indexed on URLScan.io."
                _URLSCAN_CACHE[f"domain:{clean_domain}"] = (now, res)
                return res

            r0 = results[0]
            verdicts = r0.get("verdicts", {})
            overall = verdicts.get("overall", {})
            malicious = overall.get("malicious", False)
            score = overall.get("score", 0)
            brands = overall.get("brands", [])
            tags = overall.get("tags", [])

            page = r0.get("page", {})
            p_ip = page.get("ip", "unknown")
            p_asn = page.get("asn", "")
            p_asnname = page.get("asnname", "")
            p_country = page.get("country", "")
            p_title = page.get("title", "")

            result_url = r0.get("result", "")

            status_str = f"Malicious (Score: {score}/100)" if malicious else f"Benign/Neutral (Score: {score}/100)"
            parts = [f"Status: {status_str}"]

            if tags:
                parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
            if brands:
                parts.append(f"Target Brand: {', '.join(str(b) for b in brands[:3])}")

            host_parts = [p_ip]
            if p_asn:
                host_parts.append(f"{p_asn} {p_asnname}".strip())
            if p_country:
                host_parts.append(p_country)
            parts.append(f"Host: {' | '.join(host_parts)}")

            if p_title:
                parts.append(f"Title: {p_title[:45]}")

            if result_url:
                parts.append(f"Scan: {result_url}")

            res = " | ".join(parts)
            _URLSCAN_CACHE[f"domain:{clean_domain}"] = (now, res)
            return res
        elif resp.status_code == 429:
            return "URLScan.io rate limit exceeded."
        elif resp.status_code in (401, 403):
            return "URLScan.io Auth Error (check URLSCAN_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLScan.io: {e}"


def submit_urlscan_detonation(
    url: str,
    visibility: str = "unlisted",
    poll: bool = False,
    max_wait_seconds: float = 30.0,
) -> Dict[str, Any]:
    """Submit a suspicious URL for live browser detonation on URLScan.io.

    Returns the submission record or polls for full DOM and network telemetry if poll=True.
    """
    clean_url = url.strip()
    key = _setting("URLSCAN_API_KEY")
    if not key:
        return {
            "status": "error",
            "message": "URLScan API key required for live detonation (set URLSCAN_API_KEY).",
        }

    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": key, "Content-Type": "application/json"}
    payload = {"url": clean_url, "visibility": visibility}

    try:
        resp = httpx.post(api_url, headers=headers, json=payload, timeout=15.0)
        if resp.status_code in (200, 201):
            data = resp.json()
            scan_uuid = data.get("uuid")
            if poll and scan_uuid:
                return poll_urlscan_result(scan_uuid, max_wait_seconds=max_wait_seconds)
            return {
                "status": "submitted",
                "uuid": scan_uuid,
                "result": data.get("result", ""),
                "api": data.get("api", ""),
                "message": data.get("message", "Submission successful"),
            }
        elif resp.status_code == 429:
            return {"status": "rate_limited", "message": "URLScan.io rate limit exceeded."}
        elif resp.status_code in (400, 401, 403):
            return {"status": "error", "message": f"URLScan.io HTTP {resp.status_code}: {resp.text}"}
        return {"status": "error", "message": f"URLScan.io returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Error submitting to URLScan.io: {e}"}


def poll_urlscan_result(
    uuid_str: str,
    max_wait_seconds: float = 30.0,
    poll_interval: float = 2.0,
) -> Dict[str, Any]:
    """Poll URLScan.io result endpoint until scan completes or timeout expires."""
    clean_uuid = uuid_str.strip()
    if "urlscan.io" in clean_uuid:
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", clean_uuid, re.IGNORECASE)
        if m:
            clean_uuid = m.group(1)
        else:
            clean_uuid = clean_uuid.rstrip("/").split("/")[-1]

    api_url = f"https://urlscan.io/api/v1/result/{clean_uuid}/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    start_time = time.monotonic()
    while time.monotonic() - start_time < max_wait_seconds:
        try:
            resp = httpx.get(api_url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = cast(Dict[str, Any], resp.json())
                data["status"] = "ready"
                return data
            elif resp.status_code == 404:
                # Detonation still in execution
                _sleep(poll_interval)
                continue
            elif resp.status_code == 429:
                return {"status": "rate_limited", "uuid": clean_uuid, "message": "URLScan.io rate limit exceeded."}
            else:
                return {"status": "error", "uuid": clean_uuid, "message": f"HTTP {resp.status_code}"}
        except Exception:
            _sleep(poll_interval)

    return {"status": "pending", "uuid": clean_uuid, "message": f"Scan pending or timed out after {max_wait_seconds}s"}


def extract_http_transactions(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse data.requests from URLScan result to extract network transactions and payload downloads."""
    data = scan_result.get("data", {})
    raw_requests = data.get("requests") if isinstance(data, dict) else None
    if not isinstance(raw_requests, list):
        raw_requests = scan_result.get("requests", [])
    if not isinstance(raw_requests, list):
        return []

    transactions: List[Dict[str, Any]] = []
    payload_extensions = (
        ".exe",
        ".dll",
        ".dmg",
        ".pkg",
        ".iso",
        ".zip",
        ".rar",
        ".7z",
        ".tar.gz",
        ".ps1",
        ".bat",
        ".cmd",
        ".sh",
        ".vbs",
        ".js",
        ".msi",
        ".scr",
        ".bin",
        ".app",
        ".apk",
    )
    payload_mime_types = (
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-apple-diskimage",
        "application/zip",
        "application/x-rar",
        "application/x-7z-compressed",
        "application/x-sh",
        "application/x-powershell",
        "text/x-shellscript",
        "text/x-python",
    )

    for item in raw_requests:
        if not isinstance(item, dict):
            continue

        req_obj = item.get("request", {})
        if isinstance(req_obj, dict) and "request" in req_obj and isinstance(req_obj["request"], dict):
            req_info = req_obj.get("request", {})
        elif isinstance(req_obj, dict):
            req_info = req_obj
        else:
            req_info = {}

        resp_obj = item.get("response", {})
        if isinstance(resp_obj, dict) and "response" in resp_obj and isinstance(resp_obj["response"], dict):
            resp_info = resp_obj.get("response", {})
        elif isinstance(resp_obj, dict):
            resp_info = resp_obj
        else:
            resp_info = {}

        req_url = req_info.get("url") or item.get("url", "")
        if not req_url or not isinstance(req_url, str):
            continue

        method = str(req_info.get("method") or "GET").upper()
        req_headers = req_info.get("headers") or {}
        resp_headers = resp_info.get("headers") or {}
        status = resp_info.get("status")
        mime_type = str(
            resp_info.get("mimeType") or resp_headers.get("content-type") or resp_headers.get("Content-Type") or ""
        )
        remote_ip = str(resp_info.get("remoteIPAddress") or item.get("ip") or "").strip()
        remote_port = resp_info.get("remotePort")

        parsed = urllib.parse.urlsplit(req_url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        if not remote_port:
            remote_port = 443 if parsed.scheme == "https" else 80

        is_payload = False
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in payload_extensions):
            is_payload = True
        elif any(pm in mime_type.lower() for pm in payload_mime_types):
            is_payload = True

        transactions.append(
            {
                "url": req_url,
                "method": method,
                "host": host,
                "path": path,
                "status": status,
                "mime_type": mime_type,
                "remote_ip": remote_ip,
                "remote_port": int(remote_port) if remote_port else 80,
                "headers": {"request": req_headers, "response": resp_headers},
                "is_payload": is_payload,
            }
        )

    return transactions


def generate_transaction_sigma_rules(
    transactions: List[Dict[str, Any]],
    hunt_id: Optional[str] = None,
    title_prefix: str = "Suspicious Web Lure Detonation",
) -> List[Dict[str, Any]]:
    """Generate validated Sigma rules for 'proxy' and 'network_connection' log sources from HTTP transactions."""
    if not transactions:
        return []

    rules: List[Dict[str, Any]] = []

    # Priority to payload transactions if observed, else fallback to all
    payload_txs = [tx for tx in transactions if tx.get("is_payload")]
    target_txs = payload_txs if payload_txs else transactions

    # 1. Web Proxy Rule
    hosts = sorted({tx["host"] for tx in target_txs if tx.get("host")})
    paths = sorted({tx["path"] for tx in target_txs if tx.get("path") and tx["path"] != "/"})

    if hosts or paths:
        proxy_selection: Dict[str, Any] = {}
        if hosts:
            proxy_selection["cs-host"] = hosts if len(hosts) > 1 else hosts[0]
        if paths:
            payload_exts = sorted(
                {
                    f".{p.split('.')[-1].lower()}"
                    for p in paths
                    if "." in p
                    and p.split(".")[-1].lower() in ("exe", "dll", "dmg", "pkg", "zip", "iso", "ps1", "sh", "bat", "vbs", "js")
                }
            )
            if payload_exts:
                proxy_selection["c-uri-stem|endswith"] = payload_exts if len(payload_exts) > 1 else payload_exts[0]
            else:
                proxy_selection["c-uri-stem"] = paths if len(paths) > 1 else paths[0]

        proxy_desc = "Detects web proxy requests to adversary staging domains, lure paths, or weaponized payload downloads captured during live detonation."
        proxy_problem = semantic_problem({"selection": proxy_selection, "condition": "selection"}, "proxy", proxy_desc)
        if not proxy_problem:
            proxy_doc: Dict[str, Any] = {
                "title": f"{title_prefix} - Web Proxy Staging and Payload Delivery",
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": proxy_desc,
                "references": ["https://urlscan.io"],
                "author": "hecate (auto-generated from urlscan detonation)",
                "date": date.today().isoformat(),
                "tags": ["attack.initial_access", "attack.t1189", "attack.t1204"],
                "logsource": {"category": "proxy"},
                "detection": {
                    "selection": proxy_selection,
                    "condition": "selection",
                },
                "falsepositives": ["Legitimate downloads from CDN or multi-tenant hosting with identical naming conventions"],
                "level": "high",
            }
            if hunt_id:
                proxy_doc["hunt_id"] = hunt_id
            proxy_doc["rule_yaml"] = yaml.safe_dump(proxy_doc, sort_keys=False, allow_unicode=True, width=100)
            rules.append(proxy_doc)

    # 2. Network Connection Rule
    ips = sorted(
        {
            tx["remote_ip"]
            for tx in target_txs
            if tx.get("remote_ip") and not tx["remote_ip"].startswith(("127.", "10.", "192.168.", "172.16.", "0.0.0.0"))
        }
    )
    ports = sorted({tx["remote_port"] for tx in target_txs if tx.get("remote_port")})

    if ips:
        net_selection: Dict[str, Any] = {"DestinationIp": ips if len(ips) > 1 else ips[0]}
        if ports and ports != [80] and ports != [443] and ports != [80, 443]:
            net_selection["DestinationPort"] = ports if len(ports) > 1 else ports[0]

        net_desc = "Detects network connections to remote IP addresses associated with malicious web lures and staging infrastructure."
        net_problem = semantic_problem({"selection": net_selection, "condition": "selection"}, "network_connection", net_desc)
        if not net_problem:
            net_doc: Dict[str, Any] = {
                "title": f"{title_prefix} - Outbound Connection to Lure Infrastructure",
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": net_desc,
                "references": ["https://urlscan.io"],
                "author": "hecate (auto-generated from urlscan detonation)",
                "date": date.today().isoformat(),
                "tags": ["attack.command_and_control", "attack.t1105"],
                "logsource": {"category": "network_connection"},
                "detection": {
                    "selection": net_selection,
                    "condition": "selection",
                },
                "falsepositives": ["Shared cloud or reverse proxy IP addresses serving multiple distinct organizations"],
                "level": "high",
            }
            if hunt_id:
                net_doc["hunt_id"] = hunt_id
            net_doc["rule_yaml"] = yaml.safe_dump(net_doc, sort_keys=False, allow_unicode=True, width=100)
            rules.append(net_doc)

    return rules


