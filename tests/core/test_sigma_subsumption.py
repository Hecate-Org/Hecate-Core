"""Unit tests for AST-level Semantic Subsumption and Deduplication Analyzer."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from hecate_agent.cli import cli
from hecate_agent.core.sigma_subsumption import (
    ConjunctionAST,
    CorpusDedupReport,
    FieldConstraint,
    SigmaDeduplicator,
    SigmaRuleAST,
    SubsumptionEngine,
    SubsumptionRelation,
    _scalar_subsumes,
)


# -----------------------------------------------------------------------------
# 1. Scalar Subsumption Tests
# -----------------------------------------------------------------------------


def test_scalar_exact_subsumption() -> None:
    # Exact matches: case-insensitive
    assert _scalar_subsumes("whoami.exe", [], "whoami.exe", []) is True
    assert _scalar_subsumes("whoami.exe", [], "WHOAMI.EXE", []) is True
    assert _scalar_subsumes("whoami.exe", [], "cmd.exe", []) is False


def test_scalar_contains_subsumption() -> None:
    # contains(val_a) subsumes contains(val_b) when val_a is a substring of val_b
    assert _scalar_subsumes("mimikatz", ["contains"], "mimikatz.exe", ["contains"]) is True
    assert _scalar_subsumes("mimi", ["contains"], "mimikatz", ["contains"]) is True
    assert _scalar_subsumes("mimikatz.exe", ["contains"], "mimikatz", ["contains"]) is False

    # contains(val_a) subsumes exact(val_b) when val_a in val_b
    assert _scalar_subsumes("svchost", ["contains"], "c:\\windows\\system32\\svchost.exe", []) is True

    # contains(val_a) subsumes startswith and endswith
    assert _scalar_subsumes("svc", ["contains"], "svchost", ["startswith"]) is True
    assert _scalar_subsumes("host", ["contains"], "svchost", ["endswith"]) is True


def test_scalar_startswith_and_endswith_subsumption() -> None:
    # startswith: shorter prefix subsumes longer prefix
    assert _scalar_subsumes("c:\\temp\\", ["startswith"], "c:\\temp\\malware\\", ["startswith"]) is True
    assert _scalar_subsumes("c:\\temp\\", ["startswith"], "c:\\temp\\payload.exe", []) is True
    assert _scalar_subsumes("c:\\temp\\malware\\", ["startswith"], "c:\\temp\\", ["startswith"]) is False

    # endswith: shorter suffix subsumes longer suffix
    assert _scalar_subsumes("\\powershell.exe", ["endswith"], "\\v1.0\\powershell.exe", ["endswith"]) is True
    assert _scalar_subsumes("\\powershell.exe", ["endswith"], "c:\\windows\\system32\\powershell.exe", []) is True
    assert _scalar_subsumes("\\v1.0\\powershell.exe", ["endswith"], "\\powershell.exe", ["endswith"]) is False


def test_scalar_cidr_subsumption() -> None:
    # CIDR network subsumption
    assert _scalar_subsumes("192.168.0.0/16", ["cidr"], "192.168.1.0/24", ["cidr"]) is True
    assert _scalar_subsumes("10.0.0.0/8", ["cidr"], "10.1.2.3", []) is True
    assert _scalar_subsumes("192.168.1.0/24", ["cidr"], "192.168.0.0/16", ["cidr"]) is False


def test_scalar_numeric_subsumption() -> None:
    # Greater-than: > 100 subsumes > 200
    assert _scalar_subsumes("100", ["gt"], "200", ["gt"]) is True
    assert _scalar_subsumes("200", ["gt"], "100", ["gt"]) is False

    # Less-than: < 500 subsumes < 300
    assert _scalar_subsumes("500", ["lt"], "300", ["lt"]) is True
    assert _scalar_subsumes("300", ["lt"], "500", ["lt"]) is False


# -----------------------------------------------------------------------------
# 2. FieldConstraint Subsumption Tests
# -----------------------------------------------------------------------------


def test_field_constraint_wildcard_canonicalization() -> None:
    # Wildcard '*\\cmd.exe' should canonicalize to endswith
    c1 = FieldConstraint.from_raw("Image", "*\\cmd.exe")
    c2 = FieldConstraint.from_raw("Image|endswith", "\\cmd.exe")
    assert c1 == c2
    assert c1.subsumes(c2) and c2.subsumes(c1)

    # '*mimikatz*' should canonicalize to contains
    c3 = FieldConstraint.from_raw("CommandLine", "*mimikatz*")
    c4 = FieldConstraint.from_raw("CommandLine|contains", "mimikatz")
    assert c3 == c4


def test_field_constraint_windash_normalization() -> None:
    c1 = FieldConstraint.from_raw("CommandLine|contains|windash", "cmd /c whoami")
    c2 = FieldConstraint.from_raw("CommandLine|contains|windash", "cmd -c whoami")
    assert c1.values == c2.values
    assert c1.subsumes(c2) and c2.subsumes(c1)


def test_field_constraint_or_value_lists() -> None:
    # Broader OR list subsumes narrower OR list
    c_broad = FieldConstraint.from_raw("TargetFilename|endswith", ["\\malware.dll", "\\payload.exe", "\\beacon.dll"])
    c_narrow = FieldConstraint.from_raw("TargetFilename|endswith", ["\\malware.dll", "\\payload.exe"])
    assert c_broad.subsumes(c_narrow) is True
    assert c_narrow.subsumes(c_broad) is False


def test_field_constraint_and_all_lists() -> None:
    # In an AND-list (|all), requiring fewer substrings subsumes requiring more substrings
    c_broad = FieldConstraint.from_raw("CommandLine|contains|all", ["mimikatz"])
    c_narrow = FieldConstraint.from_raw("CommandLine|contains|all", ["mimikatz", "privilege::debug"])
    assert c_broad.subsumes(c_narrow) is True
    assert c_narrow.subsumes(c_broad) is False


# -----------------------------------------------------------------------------
# 3. ConjunctionAST Subsumption Tests
# -----------------------------------------------------------------------------


def test_conjunction_ast_subsumption() -> None:
    # Rule A: Image: powershell.exe
    conj_a = ConjunctionAST.from_dict({"Image|endswith": "\\powershell.exe"})
    # Rule B: Image: powershell.exe AND CommandLine contains: -enc
    conj_b = ConjunctionAST.from_dict({
        "Image|endswith": "\\powershell.exe",
        "CommandLine|contains": "-enc",
    })

    # Rule A is broader (subsumes Rule B)
    assert conj_a.subsumes(conj_b) is True
    assert conj_b.subsumes(conj_a) is False

    # Incompatible conjunctions
    conj_c = ConjunctionAST.from_dict({"Image|endswith": "\\cmd.exe"})
    assert conj_a.subsumes(conj_c) is False
    assert conj_c.subsumes(conj_a) is False


# -----------------------------------------------------------------------------
# 4. SigmaRuleAST & Engine Subsumption Tests
# -----------------------------------------------------------------------------


def test_subsumption_engine_equivalent_rules() -> None:
    rule_dict_1 = {
        "id": "11111111-1111-1111-1111-111111111111",
        "title": "Whoami Execution (Wildcard)",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image": "*\\whoami.exe"},
            "condition": "selection",
        },
    }
    rule_dict_2 = {
        "id": "22222222-2222-2222-2222-222222222222",
        "title": "Whoami Execution (Endswith)",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_whoami": {"Image|endswith": "\\whoami.exe"},
            "condition": "selection_whoami",
        },
    }

    r1 = SigmaRuleAST.from_dict(rule_dict_1)
    r2 = SigmaRuleAST.from_dict(rule_dict_2)

    engine = SubsumptionEngine()
    res = engine.compare(r1, r2)
    assert res.relation == SubsumptionRelation.EQUIVALENT
    assert res.overlap_score == 1.0


def test_subsumption_engine_strict_subsumption() -> None:
    rule_broad = {
        "id": "aaaa-aaaa",
        "title": "PowerShell Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection",
        },
    }
    rule_narrow = {
        "id": "bbbb-bbbb",
        "title": "Encoded PowerShell Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": "-enc",
            },
            "condition": "selection",
        },
    }

    r_broad = SigmaRuleAST.from_dict(rule_broad)
    r_narrow = SigmaRuleAST.from_dict(rule_narrow)

    engine = SubsumptionEngine()
    res = engine.compare(r_broad, r_narrow)
    assert res.relation == SubsumptionRelation.SUBSUMES

    res_rev = engine.compare(r_narrow, r_broad)
    assert res_rev.relation == SubsumptionRelation.SUBSUMED_BY


def test_subsumption_engine_disjoint_categories() -> None:
    rule_proc = {
        "id": "proc-01",
        "title": "Process Rule",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    }
    rule_dns = {
        "id": "dns-01",
        "title": "DNS Rule",
        "logsource": {"category": "dns_query"},
        "detection": {"selection": {"QueryName|contains": "evil.com"}, "condition": "selection"},
    }

    r_proc = SigmaRuleAST.from_dict(rule_proc)
    r_dns = SigmaRuleAST.from_dict(rule_dns)

    engine = SubsumptionEngine()
    res = engine.compare(r_proc, r_dns)
    assert res.relation == SubsumptionRelation.DISJOINT
    assert "Different log source categories" in res.explanation


def test_subsumption_engine_overlapping_rules() -> None:
    rule_1 = {
        "id": "net-01",
        "title": "C2 Beaconing via S3",
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {
                "DestinationHostname|endswith": ".s3.amazonaws.com",
                "DestinationPort": 443,
            },
            "condition": "selection",
        },
    }
    rule_2 = {
        "id": "net-02",
        "title": "C2 Beaconing via Azure Blob",
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {
                "DestinationHostname|endswith": ".blob.core.windows.net",
                "DestinationPort": 443,
            },
            "condition": "selection",
        },
    }

    r1 = SigmaRuleAST.from_dict(rule_1)
    r2 = SigmaRuleAST.from_dict(rule_2)

    engine = SubsumptionEngine(overlap_threshold=0.3)
    res = engine.compare(r1, r2)
    assert res.relation == SubsumptionRelation.OVERLAPPING
    assert "destinationport" in res.shared_fields


# -----------------------------------------------------------------------------
# 5. Internal Redundancy Audit Tests
# -----------------------------------------------------------------------------


def test_audit_internal_redundancy() -> None:
    # Rule has 1 of selection* where selection_broad subsumes selection_narrow
    rule_redundant = {
        "id": "intern-01",
        "title": "Internally Redundant Rule",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection_broad": {"Image|endswith": "\\powershell.exe"},
            "selection_narrow": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": "-enc",
            },
            "condition": "1 of selection*",
        },
    }
    r = SigmaRuleAST.from_dict(rule_redundant)
    dedup = SigmaDeduplicator()
    issues = dedup.audit_internal_redundancy(r)
    assert len(issues) == 1
    assert "subsumes clause" in issues[0] and "dead/redundant" in issues[0]


# -----------------------------------------------------------------------------
# 6. Corpus Deduplication & Check Candidate Tests
# -----------------------------------------------------------------------------


def test_corpus_deduplication_and_check_candidate() -> None:
    rule_broad = SigmaRuleAST.from_dict({
        "id": "r-01",
        "title": "Broad PowerShell Execution",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
    })
    rule_narrow = SigmaRuleAST.from_dict({
        "id": "r-02",
        "title": "Encoded PowerShell Execution",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    })
    rule_unrelated = SigmaRuleAST.from_dict({
        "id": "r-03",
        "title": "DNS Lookup of C2",
        "logsource": {"category": "dns_query"},
        "detection": {"selection": {"QueryName|endswith": ".evil.com"}, "condition": "selection"},
    })

    corpus = [rule_broad, rule_unrelated]
    dedup = SigmaDeduplicator()

    # Checking candidate narrow rule against corpus: should find that it is SUBSUMED_BY r-01
    matches = dedup.check_candidate(rule_narrow, corpus)
    assert len(matches) == 1
    assert matches[0].relation == SubsumptionRelation.SUBSUMED_BY
    assert matches[0].rule_b_id == "r-01"

    # Full corpus report
    report = dedup.analyze_corpus([rule_broad, rule_narrow, rule_unrelated])
    assert report.total_rules == 3
    assert len(report.subsumptions) == 1
    assert report.has_issues is True


# -----------------------------------------------------------------------------
# 7. CLI End-to-End Tests
# -----------------------------------------------------------------------------


def test_cli_hunt_dedup_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["hunt", "dedup", "--help"])
    assert result.exit_code == 0
    assert "Analyze Sigma detection rules for duplicates, subsumptions, and redundancies" in result.output


def test_cli_hunt_dedup_json_output(tmp_path: Path) -> None:
    # Create two test rules in tmp directory
    rule_file_1 = tmp_path / "rule1.yml"
    rule_file_1.write_text("""
title: Test Rule 1
id: 11111111-1111-1111-1111-111111111111
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
""")
    rule_file_2 = tmp_path / "rule2.yml"
    rule_file_2.write_text("""
title: Test Rule 2 (Subsumed)
id: 22222222-2222-2222-2222-222222222222
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
    CommandLine|contains: '/all'
  condition: selection
""")

    runner = CliRunner()
    res = runner.invoke(cli, ["hunt", "dedup", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0
    import json
    data = json.loads(res.output)
    assert data["total_rules"] == 2
    assert data["subsumption_count"] == 1
    assert data["subsumptions"][0]["relation"] == "SUBSUMES"


def test_cli_hunt_dedup_check_flag(tmp_path: Path) -> None:
    corpus_file = tmp_path / "corpus_rule.yml"
    corpus_file.write_text("""
title: Generic Whoami Detection
id: c000-0000
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
""")

    candidate_file = tmp_path / "candidate_rule.yml"
    candidate_file.write_text("""
title: Whoami All
id: c111-1111
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
    CommandLine|contains: '/all'
  condition: selection
""")

    runner = CliRunner()
    res = runner.invoke(cli, ["hunt", "dedup", str(tmp_path), "--check", str(candidate_file)])
    assert res.exit_code == 0
    assert "SUBSUMED_BY" in res.output
    assert "Generic Whoami Detection" in res.output
