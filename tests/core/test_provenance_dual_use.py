"""Tests for dual-use cloud/SaaS indicator detection and placement."""

from hecate_agent.core.provenance import (
    IndicatorRecord,
    is_dual_use,
    placements,
    records_from_cti,
)


def test_is_dual_use_matches_cloud_storage_and_saas():
    # S3 domains and IPs
    assert is_dual_use("s3.us-east-1.amazonaws.com") is True
    assert is_dual_use("bucket.s3.amazonaws.com") is True
    assert is_dual_use("52.216.148.130") is True

    # Azure Blob
    assert is_dual_use("mydata.blob.core.windows.net") is True
    assert is_dual_use("cdn.azureedge.net") is True

    # Google Cloud
    assert is_dual_use("storage.googleapis.com") is True
    assert is_dual_use("drive.google.com") is True

    # File sharing & SaaS
    assert is_dual_use("dropbox.com") is True
    assert is_dual_use("discord.com") is True
    assert is_dual_use("api.telegram.org") is True
    assert is_dual_use("raw.githubusercontent.com") is True

    # Evidence mentioning dual-use or cloud storage
    assert is_dual_use("1.2.3.4", "AWS S3 Ingestion Endpoint - Dual Use") is True
    assert is_dual_use("10.0.0.1", "exfiltration to dual-use cloud storage") is True

    # Standard adversary C2 domains and IPs should NOT match
    assert is_dual_use("194.26.29.112") is False
    assert is_dual_use("185.196.8.44") is False
    assert is_dual_use("auth-telemetry-verify.com") is False
    assert is_dual_use("graph-api-worker.net") is False
    assert is_dual_use("evil-c2.org") is False


def test_dual_use_indicators_placement_is_not_bare():
    # Dual use IP routes to network_connection.dual_use, not bare DestinationIp
    s3_ip = IndicatorRecord(value="52.216.148.130", type="ipv4")
    assert placements(s3_ip) == ["network_connection.dual_use"]

    # Dual use domain routes to network_connection.dual_use, not bare dns_query.QueryName
    s3_host = IndicatorRecord(value="s3.us-east-1.amazonaws.com", type="hostname")
    assert placements(s3_host) == ["network_connection.dual_use"]

    # Normal C2 IP and domain route to standard bare telemetry
    c2_ip = IndicatorRecord(value="194.26.29.112", type="ipv4")
    assert placements(c2_ip) == ["network_connection.DestinationIp"]

    c2_host = IndicatorRecord(value="auth-telemetry-verify.com", type="domain")
    assert "dns_query.QueryName" in placements(c2_host)
    assert "network_connection.DestinationHostname" in placements(c2_host)


def test_records_from_cti_sets_dual_use_role():
    records = records_from_cti({
        "ipv4": ["52.216.148.130", "194.26.29.112"],
        "domain": ["s3.us-east-1.amazonaws.com", "c2.example.org"],
    })
    roles = {r.value: r.role for r in records}
    assert roles["52.216.148.130"] == "dual_use"
    assert roles["s3.us-east-1.amazonaws.com"] == "dual_use"
    assert roles["194.26.29.112"] == "unknown"
    assert roles["c2.example.org"] == "unknown"


def test_a_dual_use_url_path_is_not_a_connection_target():
    """H-0830's dual-use set was four NetScaler login paths; routed to the
    network rule they produced a condition with no selection behind it."""
    bare = IndicatorRecord(value="/vpn/index.html", type="url", role="dual_use")
    full = IndicatorRecord(value="https://s3.amazonaws.com/bucket/stage.bin", type="url", role="dual_use")
    assert placements(bare) == []
    assert placements(full) == ["proxy.c-uri"]


def test_a_version_number_is_not_an_address():
    """H-0830's source listed the NetScaler build 13.1.37.283."""
    records = records_from_cti({"ipv4": ["13.1.37.283", "209.141.43.95"]})
    assert [r.value for r in records] == ["209.141.43.95"]


def test_shell_syntax_after_a_url_is_not_part_of_it():
    """The source's fetch command left ";chmod${IFS}755" on the download URL."""
    records = records_from_cti(
        {"url": ["http://209.141.43[.]95/files/kw2-freebsd-x64-s11;chmod${IFS}755", "http://h.example/a?x=1&y=2"]}
    )
    assert [r.value for r in records] == ["http://209.141.43.95/files/kw2-freebsd-x64-s11", "http://h.example/a?x=1&y=2"]


def test_an_inbound_address_is_a_source_never_a_destination():
    inbound = IndicatorRecord(value="45.153.212.101", type="ipv4", role="inbound")
    assert placements(inbound) == ["webserver.c-ip", "network_connection.SourceIp"]
    assert placements(IndicatorRecord(value="scanner.example", type="domain", role="inbound")) == []


def test_private_ips_classified_as_target_with_no_outbound_placements():
    """RFC 1918 private IPs are internal lateral movement targets, never outbound C2 destinations."""
    from hecate_agent.core.provenance import merge_records

    records = records_from_cti({
        "ipv4": ["10.0.0.45", "192.168.1.100", "172.16.5.20", "194.26.29.112"],
    })
    roles = {r.value: r.role for r in records}
    assert roles["10.0.0.45"] == "target"
    assert roles["192.168.1.100"] == "target"
    assert roles["172.16.5.20"] == "target"
    assert roles["194.26.29.112"] == "unknown"

    # Verify placements: private IPs get no outbound destination rules
    assert placements(records[0]) == []
    assert placements(records[1]) == []
    assert placements(records[2]) == []
    assert placements(records[3]) == ["network_connection.DestinationIp"]

    # Verify merge_records maintains target role for private IPs
    merged = merge_records([], [IndicatorRecord(value="10.0.0.45", type="ipv4")])
    assert merged[0].role == "target"
    assert placements(merged[0]) == []



def test_the_sources_own_page_and_links_beneath_it_get_no_rule() -> None:
    """H-0020 swept proxy logs for the PoC repository, taken from its README's stars badge."""
    from hecate_agent.core.provenance import IndicatorRecord, mark_source_pages, placements

    repo = "https://github.com/al4n4n/CVE-2026-58115"
    records = [
        IndicatorRecord(value=repo, type="url"),
        IndicatorRecord(value=repo + "/stargazers", type="url"),
        IndicatorRecord(value="github.com", type="hostname"),
        IndicatorRecord(value="https://github.com/al4n4n/other-tool/raw/main/x.sh", type="url"),
        IndicatorRecord(value="https://github.com/al4n4n/CVE-2026-58115-fork", type="url"),
    ]
    marked = mark_source_pages(records, [repo + "/", ""])
    assert marked == [repo, repo + "/stargazers", "github.com"]
    assert [bool(placements(r)) for r in records] == [False, False, False, True, True]


def test_a_source_url_without_a_path_marks_nothing() -> None:
    from hecate_agent.core.provenance import IndicatorRecord, mark_source_pages

    records = [IndicatorRecord(value="evil.example.com", type="domain")]
    assert mark_source_pages(records, ["https://evil.example.com"]) == []


def test_documentation_placeholder_hosts_get_no_rule() -> None:
    """H-0023's only rules matched the README's "--target https://artifactory.client.example.com:8082"."""
    from hecate_agent.core.provenance import IndicatorRecord, mark_placeholders, placements

    records = [
        IndicatorRecord(value="artifactory.client.example.com", type="domain", source="cti"),
        IndicatorRecord(value="hxxps://artifactory[.]client[.]example[.]com:8082/api", type="url", source="cti"),
        IndicatorRecord(value="example.org", type="hostname", source="cti"),
        IndicatorRecord(value="example.com.evil.site", type="domain", source="cti"),
        IndicatorRecord(value="notexample.com", type="domain", source="cti"),
    ]
    marked = mark_placeholders(records)
    assert marked == [r.value for r in records[:3]]
    assert [bool(placements(r)) for r in records] == [False, False, False, True, True]


def test_feed_hashes_of_the_wrong_length_are_dropped() -> None:
    """H-0022's rule carried a 39-character SHA1 and a 63-character SHA256."""
    from hecate_agent.core.provenance import records_from_cti

    good_sha1 = "212f3cdc038d100232cef73ebc26f6e903b91498"
    records = records_from_cti(
        {
            "FileHash-SHA1": [good_sha1, good_sha1.replace("e9", "9")],
            "FileHash-SHA256": ["3f2f48525cf082672e38808480e214775e03dd943ff2df8617265aad96a5eaa"],
            "FileHash-MD5": ["0e00adb0a5ca285b838af623c753b6ff", "zz00adb0a5ca285b838af623c753b6ff"],
        }
    )
    assert [r.value for r in records] == [good_sha1, "0e00adb0a5ca285b838af623c753b6ff"]
