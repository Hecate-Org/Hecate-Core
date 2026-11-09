"""Unit tests for multi-target Sigma transpiler (MDE KQL, CrowdStrike CQL, Rapid7 LEQL)."""

import pytest

from hecate_agent.core.sigma_transpiler import (
    PYSIGMA_AVAILABLE,
    SigmaTranspiler,
)


@pytest.fixture
def sample_process_creation_rule() -> str:
    return """
title: Detection of Daemon Tools Lite Service Execution via DTHelper.exe
id: 1ad689ca-013c-4b3b-98ee-1a8f34a7e809
status: experimental
description: Detects DTHelper.exe service execution
references:
  - https://vulncheck.com/cve/CVE-2026-8398
author: hecate
date: '2026-10-26'
tags:
  - attack.t1190
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\DTHelper.exe'
    CommandLine|contains: '--service'
  condition: selection
falsepositives:
  - Legitimate administrative maintenance
level: high
"""


@pytest.fixture
def sample_network_rule() -> str:
    return """
title: Outbound Connection to Malicious IP
id: 2bd689ca-013c-4b3b-98ee-1a8f34a7e810
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '168.138.40.244'
    DestinationPort: 443
  condition: selection
level: high
"""


@pytest.mark.skipif(not PYSIGMA_AVAILABLE, reason="pySigma not installed in environment")
class TestSigmaTranspiler:
    @pytest.mark.parametrize("initiated", [True, False])
    def test_mde_rejects_silently_dropped_network_direction(self, initiated):
        import yaml

        rule = yaml.safe_dump({"title": "Directional network test", "logsource": {
            "category": "network_connection", "product": "windows"}, "detection": {
                "selection": {"Image|endswith": r"\wscript.exe", "Initiated": initiated},
                "condition": "selection"}})
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert not result.success and result.query is None
        assert "Initiated direction predicate" in result.error_message

    @pytest.mark.parametrize("cidr", ["::/0", "fc00::/7"])
    def test_mde_rejects_ipv6_in_cidr_filters(self, cidr):
        import yaml

        rule = yaml.safe_dump({"title": "Mixed address family test", "logsource": {
            "category": "network_connection", "product": "windows"}, "detection": {
                "selection": {"Image|endswith": r"\wscript.exe"},
                "private": {"DestinationIp|cidr": ["10.0.0.0/8", cidr]},
                "condition": "selection and not private"}})
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert not result.success and result.query is None
        assert "cannot preserve IPv6" in result.error_message

    def test_mde_still_converts_ipv4_only_cidr(self):
        rule = """title: IPv4 network
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert result.success, result.error_message
        assert 'ipv4_is_in_range(RemoteIP, "10.0.0.0/8")' in result.query

    def test_proxy_eql_maps_user_agent_and_rejects_unknown_fields(self):
        rule = """title: WebDAV redirector
logsource:
  category: proxy
detection:
  selection:
    c-useragent|startswith: Microsoft-WebDAV-MiniRedir/
  condition: selection
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_ELASTIC])[SigmaTranspiler.TARGET_ELASTIC]
        assert result.success, result.error_message
        assert "user_agent.original" in result.query and "c-useragent" not in result.query
        assert "Microsoft-WebDAV-MiniRedir/*" in result.query
        unmapped = rule.replace("c-useragent|startswith", "UnmappedProxyField|startswith")
        result = SigmaTranspiler().transpile(unmapped, [SigmaTranspiler.TARGET_ELASTIC])[SigmaTranspiler.TARGET_ELASTIC]
        assert not result.success and result.query is None
        assert "Proxy ECS mapping does not support field" in result.error_message

    def test_linux_eql_maps_file_paths_to_ecs(self):
        rule = """title: Preload file
id: c5da0b47-4dbb-4d3e-a23d-f59701709122
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename: /etc/ld.so.preload
  condition: selection
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_ELASTIC])[SigmaTranspiler.TARGET_ELASTIC]
        assert result.success
        assert 'file.path' in result.query and 'TargetFilename' not in result.query
        unmapped = rule.replace("TargetFilename: /etc/ld.so.preload", "Hashes: SHA256=abc")
        result = SigmaTranspiler().transpile(unmapped, [SigmaTranspiler.TARGET_ELASTIC])[SigmaTranspiler.TARGET_ELASTIC]
        assert not result.success
        assert "Linux ECS mapping does not support field" in result.error_message

    def test_http_kql_requires_real_column_mappings(self):
        rule = """title: Metrics endpoint
id: c5da0b47-4dbb-4d3e-a23d-f59701709123
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: /api/v1/metrics
  condition: selection
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert not result.success
        assert "explicit deployed table and field mapping" in result.error_message

    def test_leql_preserves_path_and_wildcard_matching(self):
        import re
        from sigma.conversion.state import ConversionState
        from sigma.types import SigmaString
        from hecate_agent.core.sigma_transpiler import InsightIDRBackend

        backend = InsightIDRBackend()
        for value, positive, negative in [
            (r"*\\Temp\\*", r"C:\Users\Alice\Temp\sample.js", r"C:\Users\Alice\Templates\sample.js"),
            ("*scheduled task*", "Create scheduled task", "Create scheduled job"),
            ("example.com", "EXAMPLE.COM", "exampleXcom"),
            ("/api/v1/*", "/api/v1/repos", "/api/v2/repos"),
        ]:
            encoded = backend.convert_value_str(SigmaString(value), ConversionState())
            assert encoded.startswith("/^") and encoded.endswith("$/i")
            pattern = encoded[1:-2]
            assert re.search(pattern, positive, re.I)
            assert not re.search(pattern, negative, re.I)

    def test_dns_kql_uses_sentinel_asim_and_preserves_boolean_condition(self):
        rule = """
title: DNS domain and subdomain lookup
id: c5da0b47-4dbb-4d3e-a23d-f59701709124
logsource:
  category: dns_query
  product: windows
detection:
  exact:
    QueryName: example.com
  subdomain:
    QueryName|endswith: .example.com
  exclusion:
    QueryName: approved.example.com
  condition: (exact or subdomain) and not exclusion
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert result.success, result.error_message
        assert result.query.startswith("_Im_Dns | where ")
        assert 'DnsQuery in~ ("example.com")' in result.query
        assert 'DnsQuery endswith ".example.com"' in result.query
        assert 'not(DnsQuery =~ "approved.example.com")' in result.query
        assert "DeviceEvents" not in result.query

    def test_dns_kql_rejects_fields_without_an_asim_mapping(self):
        rule = """
title: DNS with an unsupported field
id: c5da0b47-4dbb-4d3e-a23d-f59701709125
logsource:
  category: dns_query
detection:
  selection:
    QueryName: example.com
    UnknownDnsField: value
  condition: selection
"""
        result = SigmaTranspiler().transpile(rule, [SigmaTranspiler.TARGET_MDE])[SigmaTranspiler.TARGET_MDE]
        assert not result.success
        assert "UnknownDnsField" in result.error_message

    def test_transpile_process_creation_all_targets(self, sample_process_creation_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_process_creation_rule)

        assert SigmaTranspiler.TARGET_MDE in results
        assert SigmaTranspiler.TARGET_CROWDSTRIKE in results
        assert SigmaTranspiler.TARGET_RAPID7 in results
        assert SigmaTranspiler.TARGET_SENTINELONE in results
        assert SigmaTranspiler.TARGET_SPLUNK in results
        assert SigmaTranspiler.TARGET_ELASTIC in results

        # 1. Microsoft Defender / Sentinel KQL
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is True
        assert mde.dialect == "kql"
        assert mde.file_extension == ".kql"
        assert "DeviceProcessEvents" in mde.query
        assert "DTHelper.exe" in mde.query

        # 2. CrowdStrike Falcon CQL
        cs = results[SigmaTranspiler.TARGET_CROWDSTRIKE]
        assert cs.success is True
        assert cs.dialect == "cql"
        assert cs.file_extension == ".cql"
        assert "ProcessRollup2" in cs.query or "DTHelper" in cs.query

        # 3. Rapid7 InsightIDR LEQL
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert r7.dialect == "leql"
        assert r7.file_extension == ".leql"
        assert r7.query.startswith("where(")
        assert r"DTHelper\.exe" in r7.query

        # 4. SentinelOne S1QL
        s1 = results[SigmaTranspiler.TARGET_SENTINELONE]
        assert s1.success is True
        assert s1.dialect == "s1ql"
        assert s1.file_extension == ".s1ql"
        assert "Process Creation" in s1.query
        assert "DTHelper.exe" in s1.query

        # 5. Splunk SPL
        sp = results[SigmaTranspiler.TARGET_SPLUNK]
        assert sp.success is True
        assert sp.dialect == "spl"
        assert sp.file_extension == ".spl"
        assert "DTHelper.exe" in sp.query

        # 6. Elastic EQL
        eq = results[SigmaTranspiler.TARGET_ELASTIC]
        assert eq.success is True
        assert eq.dialect == "eql"
        assert eq.file_extension == ".eql"
        assert "process.executable.caseless" in eq.query
        assert "DTHelper.exe" in eq.query

    def test_transpile_network_connection(self, sample_network_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_network_rule)

        # MDE KQL should target DeviceNetworkEvents
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is True
        assert "DeviceNetworkEvents" in mde.query
        assert "168.138.40.244" in mde.query

        # Rapid7 should query destination_ip / port
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert "where(" in r7.query
        assert r"168\.138\.40\.244" in r7.query

        # SentinelOne should query DstIP / DstPort
        s1 = results[SigmaTranspiler.TARGET_SENTINELONE]
        assert s1.success is True
        assert "168.138.40.244" in s1.query
        assert "443" in s1.query

        # Splunk should query DestinationIp / DestinationPort
        sp = results[SigmaTranspiler.TARGET_SPLUNK]
        assert sp.success is True
        assert "168.138.40.244" in sp.query

        # Elastic should query destination.ip / destination.port
        eq = results[SigmaTranspiler.TARGET_ELASTIC]
        assert eq.success is True
        assert "168.138.40.244" in eq.query

    def test_normalize_rule_adds_windows_product_if_missing(self):
        rule_without_product = """
title: Test Process Rule
id: 3ad689ca-013c-4b3b-98ee-1a8f34a7e811
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\malware.exe'
  condition: selection
"""
        normalized = SigmaTranspiler.normalize_rule_for_backends(rule_without_product)
        assert "product: windows" in normalized

        transpiler = SigmaTranspiler()
        results = transpiler.transpile(rule_without_product)
        # Should succeed for MDE, CrowdStrike, and Rapid7 despite original missing product: windows
        assert results[SigmaTranspiler.TARGET_MDE].success is True
        assert results[SigmaTranspiler.TARGET_CROWDSTRIKE].success is True
        assert results[SigmaTranspiler.TARGET_RAPID7].success is True

    def test_normalize_rule_infers_linux_from_unix_paths(self):
        rule_without_product = """
title: Node launching sh
id: 287970fb-1f86-4536-b929-cde93d7ccdfb
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    ParentImage|endswith: /node
    ParentCommandLine|contains: node-red
    Image|endswith: /sh
  condition: selection
"""
        normalized = SigmaTranspiler.normalize_rule_for_backends(rule_without_product)
        assert "product: linux" in normalized

        s1 = SigmaTranspiler().transpile(rule_without_product).get(SigmaTranspiler.TARGET_SENTINELONE)
        if s1 is not None and s1.success:
            assert 'EndpointOS = "windows"' not in s1.query

    def test_normalize_rule_leaves_web_paths_without_os(self):
        rule = """
title: POST flows
id: 0131dcf2-509b-4c42-bcad-e02ea5271995
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
    cs-uri-stem: /flows
  condition: selection
"""
        assert "product" not in SigmaTranspiler.normalize_rule_for_backends(rule)

    def test_format_markdown_queries(self, sample_process_creation_rule):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(sample_process_creation_rule)
        markdown = transpiler.format_markdown_queries(results)

        assert "##### Native EDR & SIEM Queries" in markdown
        assert "Microsoft Defender / Microsoft Sentinel (KQL)" in markdown
        assert "CrowdStrike Falcon" in markdown
        assert "Rapid7 InsightIDR" in markdown
        assert "SentinelOne" in markdown
        assert "Splunk" in markdown
        assert "Elastic Security" in markdown
        assert "```kql" in markdown
        assert "```cql" in markdown
        assert "```spl" in markdown
        assert "```eql" in markdown
        assert "```text" in markdown
        assert "where(" in markdown

    def test_transpile_invalid_rule_graceful_error(self):
        transpiler = SigmaTranspiler()
        results = transpiler.transpile("this is not valid sigma yaml: [unclosed")
        for target, res in results.items():
            assert res.success is False
            assert res.query is None
            assert res.error_message is not None

    def test_webserver_fields_do_not_fall_back_to_unmapped_kql(self):
        web_rule = """
title: Webserver Access Rule
id: 4ad689ca-013c-4b3b-98ee-1a8f34a7e812
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: '/api/v1/admin'
    sc-status: 200
  condition: selection
level: medium
"""
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(web_rule)
        mde = results[SigmaTranspiler.TARGET_MDE]
        assert mde.success is False
        assert "explicit deployed table and field mapping" in mde.error_message
        assert mde.query is None
        r7 = results[SigmaTranspiler.TARGET_RAPID7]
        assert r7.success is True
        assert r"\/api\/v1\/admin" in r7.query
        cs = results[SigmaTranspiler.TARGET_CROWDSTRIKE]
        assert cs.success is True
        assert "api" in cs.query and "admin" in cs.query
        sp = results[SigmaTranspiler.TARGET_SPLUNK]
        assert sp.success is True
        assert "/api/v1/admin" in sp.query
        eq = results[SigmaTranspiler.TARGET_ELASTIC]
        assert eq.success is True
        assert "/api/v1/admin" in eq.query
        # SentinelOne is endpoint-focused and gracefully reports conversion error for webserver
        s1 = results[SigmaTranspiler.TARGET_SENTINELONE]
        assert s1.success is False
        assert s1.query is None
        assert s1.error_message is not None

    def test_backend_caching_and_clear_cache(self, sample_process_creation_rule):
        SigmaTranspiler.clear_cache()
        from hecate_agent.core.sigma_transpiler import _BACKEND_CACHE

        assert len(_BACKEND_CACHE) == 0

        transpiler = SigmaTranspiler()
        res1 = transpiler.transpile(sample_process_creation_rule)
        cache_size_after_first = len(_BACKEND_CACHE)
        assert cache_size_after_first > 0

        # Second transpile reuses cached backends
        res2 = transpiler.transpile(sample_process_creation_rule)
        assert len(_BACKEND_CACHE) == cache_size_after_first

        for target in SigmaTranspiler.SUPPORTED_TARGETS:
            assert res1[target].query == res2[target].query
            assert res1[target].success == res2[target].success

        # clear_cache clears the dictionary
        SigmaTranspiler.clear_cache()
        assert len(_BACKEND_CACHE) == 0
