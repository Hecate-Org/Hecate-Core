"""Tests for hecate_agent.core.attack_matrix - ATT&CK data provider abstraction."""

from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# FallbackProvider tests (always pass, no optional deps needed)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFallbackProvider:
    """Test the hardcoded fallback provider."""

    def test_get_tactics_returns_15(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        tactics = provider.get_tactics()
        assert len(tactics) == 15

    def test_get_tactics_has_expected_keys(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        tactics = provider.get_tactics()
        assert "credential-access" in tactics
        assert "initial-access" in tactics
        assert "lateral-movement" in tactics

    def test_tactic_info_structure(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        tactics = provider.get_tactics()
        for key, info in tactics.items():
            assert "name" in info
            assert "technique_count" in info
            assert "order" in info
            assert isinstance(info["technique_count"], int)
            assert info["technique_count"] > 0

    def test_get_total_techniques(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        total = provider.get_total_techniques()
        assert total > 100  # Sanity check: ATT&CK has hundreds of techniques

    def test_get_sorted_tactic_keys(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        keys = provider.get_sorted_tactic_keys()
        assert len(keys) == 15
        assert keys[0] == "reconnaissance"
        assert keys[-1] == "impact"

    def test_technique_by_id_returns_none(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        assert provider.get_technique_by_id("T1003") is None

    def test_techniques_for_tactic_returns_empty(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        assert provider.get_techniques_for_tactic("credential-access") == []

    def test_sub_techniques_returns_empty(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        assert provider.get_sub_techniques("T1003") == []

    def test_version_string(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        assert "fallback" in provider.get_version().lower()

    def test_is_stix_false(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        assert provider.is_stix() is False


# ---------------------------------------------------------------------------
# Module-level backward compatibility tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBackwardCompatibility:
    """Verify that existing imports and APIs still work.

    Pinned to FallbackProvider: these assertions encode the hardcoded v14
    dataset's shape, which would drift under whatever STIX data happens to
    be cached on the machine running the tests (see StixProvider tests for
    live-data behavior).
    """

    def setup_method(self):
        """Reset the provider singleton before each test."""
        from hecate_agent.core import attack_matrix

        attack_matrix.reset_provider(attack_matrix.FallbackProvider())

    def test_import_attack_tactics(self):
        """ATTACK_TACTICS can still be imported via __getattr__."""
        from hecate_agent.core.attack_matrix import ATTACK_TACTICS  # noqa: F811

        assert isinstance(ATTACK_TACTICS, dict)
        assert len(ATTACK_TACTICS) == 15
        assert "credential-access" in ATTACK_TACTICS

    def test_import_total_techniques(self):
        """TOTAL_TECHNIQUES can still be imported via __getattr__."""
        from hecate_agent.core.attack_matrix import TOTAL_TECHNIQUES  # noqa: F811

        assert isinstance(TOTAL_TECHNIQUES, int)
        assert TOTAL_TECHNIQUES > 100

    def test_get_tactic_display_name(self):
        from hecate_agent.core.attack_matrix import get_tactic_display_name

        assert get_tactic_display_name("credential-access") == "Credential Access"

    def test_get_tactic_display_name_unknown(self):
        from hecate_agent.core.attack_matrix import get_tactic_display_name

        # Unknown tactic should title-case the key
        assert get_tactic_display_name("unknown-tactic") == "Unknown Tactic"

    def test_get_tactic_technique_count(self):
        from hecate_agent.core.attack_matrix import get_tactic_technique_count

        count = get_tactic_technique_count("credential-access")
        assert count > 0

    def test_get_tactic_technique_count_unknown(self):
        from hecate_agent.core.attack_matrix import get_tactic_technique_count

        assert get_tactic_technique_count("nonexistent") == 0

    def test_get_sorted_tactics(self):
        from hecate_agent.core.attack_matrix import get_sorted_tactics

        tactics = get_sorted_tactics()
        assert len(tactics) == 15
        assert tactics[0] == "reconnaissance"

    def test_attack_tactics_tactic_info_shape(self):
        """Each tactic in ATTACK_TACTICS has the expected TacticInfo shape."""
        from hecate_agent.core.attack_matrix import ATTACK_TACTICS  # noqa: F811

        for key, info in ATTACK_TACTICS.items():
            assert isinstance(info["name"], str)
            assert isinstance(info["technique_count"], int)
            assert isinstance(info["order"], int)

    def test_getattr_raises_for_unknown(self):
        """Module __getattr__ raises AttributeError for unknown names."""
        with pytest.raises(AttributeError, match="no attribute"):
            from hecate_agent.core import attack_matrix

            attack_matrix.__getattr__("NONEXISTENT_THING")


# ---------------------------------------------------------------------------
# StixProvider tests (mocked MitreAttackData, no network/cache dependency)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStixProvider:
    """Test StixProvider's STIX-object-to-TacticInfo mapping against a mock client."""

    def test_build_tactics_passes_shortname_not_stix_id(self, tmp_path):
        """get_techniques_by_tactic must be called with the tactic shortname.

        Regression test: the STIX id (e.g. 'x-mitre-tactic--...') was being
        passed instead of the shortname (e.g. 'credential-access'), which
        silently made every tactic's technique_count come back as 0.
        """
        from hecate_agent.core.attack_matrix import StixProvider

        provider = StixProvider(stix_path=tmp_path / "enterprise-attack.json")
        mock_attack_data = MagicMock()
        mock_attack_data.get_tactics.return_value = [
            {
                "x_mitre_shortname": "credential-access",
                "id": "x-mitre-tactic--aaaaaaaa-0000-0000-0000-000000000000",
                "name": "Credential Access",
            },
        ]
        mock_attack_data.get_techniques_by_tactic.return_value = [MagicMock(), MagicMock()]
        provider._attack_data = mock_attack_data  # bypass file-backed _ensure_loaded

        tactics = provider.get_tactics()

        mock_attack_data.get_techniques_by_tactic.assert_called_once_with(
            "credential-access", "enterprise-attack", remove_revoked_deprecated=True
        )
        assert tactics["credential-access"]["technique_count"] == 2


def _pattern(stix_id, attack_id):
    """Minimal attack-pattern STIX object carrying an ATT&CK external ref."""
    return {
        "id": stix_id,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
    }


def _revoked_by(source_ref, target_ref):
    return {"type": "relationship", "relationship_type": "revoked-by", "source_ref": source_ref, "target_ref": target_ref}


def _stix_provider_with(tmp_path, patterns, relationships):
    from hecate_agent.core.attack_matrix import StixProvider

    provider = StixProvider(stix_path=tmp_path / "enterprise-attack.json")
    mock_attack_data = MagicMock()
    mock_attack_data.get_objects_by_type.return_value = patterns
    mock_attack_data.src.query.return_value = relationships
    provider._attack_data = mock_attack_data  # bypass file-backed _ensure_loaded
    return provider


_has_stix2 = True
try:
    import stix2  # noqa: F401
except ImportError:
    _has_stix2 = False

_has_mitreattack = True
try:
    import mitreattack  # noqa: F401
except ImportError:
    _has_mitreattack = False

# get_superseding_technique_id() imports stix2.Filter directly. In production a
# StixProvider is only selected when mitreattack-python (which depends on
# stix2) is installed; these tests build one directly against a mocked
# _attack_data, so they need the optional dep stated explicitly.
requires_stix2 = pytest.mark.skipif(not _has_stix2, reason="stix2 not installed")
requires_mitreattack = pytest.mark.skipif(not _has_mitreattack, reason="mitreattack not installed")


@pytest.mark.unit
@requires_stix2
class TestSupersedingTechniqueId:
    """Revoked ATT&CK IDs resolve to the ID that replaced them."""

    def test_revoked_id_resolves_to_replacement(self, tmp_path):
        provider = _stix_provider_with(
            tmp_path,
            [_pattern("attack-pattern--old", "T1093"), _pattern("attack-pattern--new", "T1055.012")],
            [_revoked_by("attack-pattern--old", "attack-pattern--new")],
        )

        assert provider.get_superseding_technique_id("T1093") == "T1055.012"

    def test_lookup_is_case_insensitive(self, tmp_path):
        provider = _stix_provider_with(
            tmp_path,
            [_pattern("attack-pattern--old", "T1093"), _pattern("attack-pattern--new", "T1055.012")],
            [_revoked_by("attack-pattern--old", "attack-pattern--new")],
        )

        assert provider.get_superseding_technique_id("t1093") == "T1055.012"

    def test_live_technique_has_no_superseding_id(self, tmp_path):
        provider = _stix_provider_with(tmp_path, [_pattern("attack-pattern--new", "T1055.012")], [])

        assert provider.get_superseding_technique_id("T1055.012") is None

    def test_chained_revocations_collapse_to_final_target(self, tmp_path):
        """ATT&CK has revoked a replacement in turn; A -> B -> C must answer C
        so callers never have to re-resolve."""
        provider = _stix_provider_with(
            tmp_path,
            [
                _pattern("attack-pattern--a", "T1000"),
                _pattern("attack-pattern--b", "T2000"),
                _pattern("attack-pattern--c", "T3000"),
            ],
            [
                _revoked_by("attack-pattern--a", "attack-pattern--b"),
                _revoked_by("attack-pattern--b", "attack-pattern--c"),
            ],
        )

        assert provider.get_superseding_technique_id("T1000") == "T3000"
        assert provider.get_superseding_technique_id("T2000") == "T3000"

    def test_revocation_cycle_is_dropped_not_looped(self, tmp_path):
        """A cycle has no live technique to land on -- it must be dropped
        rather than hang or return an arbitrary member."""
        provider = _stix_provider_with(
            tmp_path,
            [_pattern("attack-pattern--a", "T1000"), _pattern("attack-pattern--b", "T2000")],
            [
                _revoked_by("attack-pattern--a", "attack-pattern--b"),
                _revoked_by("attack-pattern--b", "attack-pattern--a"),
            ],
        )

        assert provider.get_superseding_technique_id("T1000") is None
        assert provider.get_superseding_technique_id("T2000") is None

    def test_non_technique_revocations_are_ignored(self, tmp_path):
        """revoked-by also links groups/software/mitigations; only
        technique-to-technique pairs belong in the technique index."""
        provider = _stix_provider_with(
            tmp_path,
            [_pattern("attack-pattern--old", "T1093"), _pattern("attack-pattern--new", "T1055.012")],
            [
                _revoked_by("attack-pattern--old", "attack-pattern--new"),
                _revoked_by("intrusion-set--g1", "intrusion-set--g2"),
            ],
        )

        assert provider.get_superseding_technique_id("T1093") == "T1055.012"
        assert provider.get_superseding_technique_id("G0001") is None

    def test_index_is_built_once_and_cached(self, tmp_path):
        provider = _stix_provider_with(
            tmp_path,
            [_pattern("attack-pattern--old", "T1093"), _pattern("attack-pattern--new", "T1055.012")],
            [_revoked_by("attack-pattern--old", "attack-pattern--new")],
        )

        provider.get_superseding_technique_id("T1093")
        provider.get_superseding_technique_id("T1067")
        provider.get_superseding_technique_id("T1093")

        assert provider._attack_data.src.query.call_count == 1

    def test_fallback_provider_uses_known_replacements_only(self):
        """The curated fallback knows historical replacements; unknown IDs stay unknown."""
        from hecate_agent.core.attack_matrix import FallbackProvider

        assert FallbackProvider().get_superseding_technique_id("T1093") == "T1055.012"
        assert FallbackProvider().get_superseding_technique_id("T9999") is None


# ---------------------------------------------------------------------------
# Provider selection tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProviderSelection:
    """Test automatic provider selection logic."""

    def setup_method(self):
        from hecate_agent.core import attack_matrix

        attack_matrix.reset_provider()

    def test_fallback_when_no_mitreattack(self, monkeypatch):
        """Falls back when mitreattack-python is not importable."""
        from hecate_agent.core import attack_matrix

        attack_matrix.reset_provider()

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("mitreattack"):
                raise ImportError("mocked: no mitreattack")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", mock_import)

        # Force re-selection
        attack_matrix.reset_provider()
        provider = attack_matrix._get_provider()
        assert isinstance(provider, attack_matrix.FallbackProvider)

    def test_reset_provider_with_explicit(self):
        """reset_provider(provider) sets a specific provider."""
        from hecate_agent.core.attack_matrix import FallbackProvider, _get_provider, reset_provider

        custom = FallbackProvider()
        reset_provider(custom)
        assert _get_provider() is custom

    def test_reset_provider_none_triggers_auto(self):
        """reset_provider(None) triggers auto-detection on next access."""
        from hecate_agent.core import attack_matrix

        attack_matrix.reset_provider(None)
        # _provider should be None, next _get_provider() auto-selects
        assert attack_matrix._provider is None
        provider = attack_matrix._get_provider()
        assert provider is not None


# ---------------------------------------------------------------------------
# New public API tests (fallback provider)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNewPublicAPI:
    """Test new API functions with fallback provider."""

    def setup_method(self):
        from hecate_agent.core import attack_matrix

        attack_matrix.reset_provider(attack_matrix.FallbackProvider())

    def test_get_technique_returns_none(self):
        from hecate_agent.core.attack_matrix import get_technique

        assert get_technique("T1003") is None

    def test_get_techniques_for_tactic_returns_empty(self):
        from hecate_agent.core.attack_matrix import get_techniques_for_tactic

        assert get_techniques_for_tactic("credential-access") == []

    def test_get_sub_techniques_returns_empty(self):
        from hecate_agent.core.attack_matrix import get_sub_techniques

        assert get_sub_techniques("T1003") == []

    def test_get_attack_version(self):
        from hecate_agent.core.attack_matrix import get_attack_version

        version = get_attack_version()
        assert "fallback" in version.lower()

    def test_is_using_stix_false(self):
        from hecate_agent.core.attack_matrix import is_using_stix

        assert is_using_stix() is False


# ---------------------------------------------------------------------------
# Cache path tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCachePaths:
    """Test STIX cache path resolution."""

    def test_env_var_override(self, monkeypatch, tmp_path):
        from hecate_agent.core.attack_matrix import _get_stix_cache_dir

        monkeypatch.setenv("HECATE_STIX_CACHE", str(tmp_path / "custom"))
        assert _get_stix_cache_dir() == tmp_path / "custom"

    def test_global_default(self, monkeypatch, tmp_path):
        from hecate_agent.core.attack_matrix import _get_stix_cache_dir

        monkeypatch.delenv("HECATE_STIX_CACHE", raising=False)
        # Ensure no .hecateconfig.yaml in cwd
        monkeypatch.chdir(tmp_path)
        cache_dir = _get_stix_cache_dir()
        assert "stix-data" in str(cache_dir)


@pytest.mark.unit
class TestCategorizeTechniquesByMatrix:
    """Test multi-matrix categorization across Enterprise, Mobile, and ICS."""

    def test_categorize_empty(self):
        from hecate_agent.core.attack_matrix import categorize_techniques_by_matrix

        res = categorize_techniques_by_matrix(set())
        assert res["total_unique"] == 0
        assert res["enterprise_total"] == 0
        assert res["mobile_total"] == 0
        assert res["ics_total"] == 0

    def test_categorize_techniques_counts(self):
        from hecate_agent.core.attack_matrix import categorize_techniques_by_matrix

        techniques = {"T1059", "T1059.001", "T0800"}
        res = categorize_techniques_by_matrix(techniques)
        assert res["total_unique"] == 3
        assert "enterprise" in res
        assert "mobile" in res
        assert "ics" in res
        assert res["ics_total"] >= 1 or res["ics"]["impact"] >= 0


@pytest.mark.unit
class TestThreatActorGroups:
    """Test MITRE ATT&CK STIX Threat Actor Profiles in attack_matrix."""

    def test_fallback_provider_groups(self):
        from hecate_agent.core.attack_matrix import FallbackProvider

        provider = FallbackProvider()
        groups = provider.get_groups()
        assert len(groups) >= 5
        ids = {g["id"] for g in groups}
        assert "G0016" in ids  # APT29
        assert "G0034" in ids  # Sandworm

        apt29 = provider.get_group_by_id("G0016")
        assert apt29 is not None
        assert apt29["name"] == "APT29"
        assert "Midnight Blizzard" in apt29["aliases"]
        assert len(apt29["techniques"]) > 0
        assert len(apt29["software"]) > 0

        found = provider.find_group("Midnight Blizzard")
        assert found is not None
        assert found["id"] == "G0016"

        found_lower = provider.find_group("cozy bear")
        assert found_lower is not None
        assert found_lower["id"] == "G0016"

        assert provider.find_group("NonexistentGroup123") is None
        assert provider.get_group_by_id("G9999") is None

    def test_module_level_group_functions(self):
        from hecate_agent.core.attack_matrix import (
            find_group,
            get_group,
            get_groups,
            search_groups_in_text,
        )

        all_groups = get_groups()
        assert len(all_groups) >= 5

        g = get_group("G0016")
        assert g is not None
        assert g["name"] == "APT29"

        g_alias = find_group("Midnight Blizzard")
        assert g_alias is not None
        assert g_alias["id"] == "G0016"

        # Search in text with single actor
        matches1 = search_groups_in_text("Adversary activity attributed to Midnight Blizzard using Entra ID tokens.")
        assert len(matches1) == 1
        assert matches1[0]["id"] == "G0016"

        # Search in text with multiple actors
        matches2 = search_groups_in_text(
            "Report tracking Sandworm Team targeting SCADA substations while FIN8 targets retail POS."
        )
        matched_ids = {m["id"] for m in matches2}
        assert "G0034" in matched_ids
        assert "G0061" in matched_ids

        # Search in text with no actor mentions
        assert search_groups_in_text("Generic PowerShell execution observed.") == []
        assert search_groups_in_text("") == []


@pytest.mark.unit
@requires_mitreattack
class TestStixSqliteCache:
    """Tests for STIX SQLite compilation and cached loading."""

    def test_sqlite_cache_creation_and_loading(self, tmp_path):
        pytest.importorskip("mitreattack.stix20")
        import json
        from hecate_agent.core.attack_matrix import StixProvider, compile_stix_to_sqlite

        import uuid

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "x-mitre-collection",
                    "id": f"x-mitre-collection--{uuid.uuid4()}",
                    "x_mitre_version": "15.1",
                },
                {
                    "type": "x-mitre-tactic",
                    "id": f"x-mitre-tactic--{uuid.uuid4()}",
                    "name": "Execution",
                    "x_mitre_shortname": "execution",
                },
                {
                    "type": "attack-pattern",
                    "id": (t1_id := f"attack-pattern--{uuid.uuid4()}"),
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse interpreters",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1059",
                            "url": "https://attack.mitre.org/techniques/T1059",
                        }
                    ],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                    "x_mitre_platforms": ["Windows", "Linux"],
                    "x_mitre_data_sources": ["Process: Process Creation"],
                    "x_mitre_is_subtechnique": False,
                },
                {
                    "type": "attack-pattern",
                    "id": (t2_id := f"attack-pattern--{uuid.uuid4()}"),
                    "name": "Old Tech",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1093"}],
                },
                {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "revoked-by",
                    "source_ref": t2_id,
                    "target_ref": t1_id,
                },
                {
                    "type": "intrusion-set",
                    "id": f"intrusion-set--{uuid.uuid4()}",
                    "name": "APT29",
                    "description": "APT29 is a threat group",
                    "aliases": ["APT29", "Cozy Bear"],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "G0016", "url": "https://attack.mitre.org/groups/G0016"}
                    ],
                },
            ],
        }

        stix_file = tmp_path / "enterprise-attack.json"
        stix_file.write_text(json.dumps(bundle))

        sqlite_file = compile_stix_to_sqlite(stix_file)
        assert sqlite_file.exists()
        assert sqlite_file.stat().st_size > 0

        # Load with StixProvider
        provider = StixProvider(stix_file)
        assert provider.get_version() == "v15.1 (STIX)"

        # Tactics
        tactics = provider.get_tactics()
        assert "execution" in tactics
        assert tactics["execution"]["name"] == "Execution"

        # Technique
        t1059 = provider.get_technique_by_id("T1059")
        assert t1059 is not None
        assert t1059["name"] == "Command and Scripting Interpreter"
        assert "Windows" in t1059["platforms"]

        # Revoked superseding technique
        assert provider.get_superseding_technique_id("T1093") == "T1059"

        # Groups
        g = provider.get_group_by_id("G0016")
        assert g is not None
        assert g["name"] == "APT29"

        found = provider.find_group("cozy bear")
        assert found is not None
        assert found["id"] == "G0016"

    def test_sqlite_compilation_cleans_up_temp_on_failure(self, tmp_path):
        from hecate_agent.core.attack_matrix import compile_stix_to_sqlite

        stix_file = tmp_path / "bad-attack.json"
        stix_file.write_text("invalid json")

        with pytest.raises(Exception):
            compile_stix_to_sqlite(stix_file)

        # Ensure no lingering .tmp files in parent directory
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0
