"""Coverage for HuntResearcherAgent.execute() and the skill methods it
orchestrates (skills 1-5, the search-client branches, and the small pure
helpers) -- these were largely untested even though hunt_researcher.py is
the module this session's web-search/grounding fixes live in.

test_hunt_researcher_grounding.py and test_hunt_researcher_reliability.py
already cover technique-grounding and the specific confidence/extraction
bugs they were each written for; this file covers the rest of the module's
control flow: the ThreadPoolExecutor-driven execute() happy path, each
skill's web-search-client-present branch, the LLM-disabled fallback in each
skill, skill 4's similarity-search branches, and the OCSF/environment
file-loading branches.
"""

from __future__ import annotations

import importlib
import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import logging

import pytest

from hecate_agent.agents.llm.hunt_researcher import HuntResearcherAgent, ResearchInput
from hecate_agent.core.llm_provider import LLMProvider, LLMResponse
from hecate_agent.core.web_search import SearchResponse, SearchResult

# hecate_agent/commands/__init__.py binds the click Command `similar` as the
# `similar` attribute of the package, shadowing the submodule of the same
# name. importlib.import_module is the only form that reliably returns the
# module itself, so patch against this handle rather than a dotted string.
_similar_mod = importlib.import_module("hecate_agent.commands.similar")


class CapturingProvider(LLMProvider):
    """Returns the same canned JSON for every prompt -- every skill's LLM
    call expects a {"summary": ..., "key_findings": [...]} shape, so one
    canned response satisfies all of them."""

    def __init__(self, response_json: Optional[Dict[str, Any]] = None):
        self.prompts: List[str] = []
        self.response_json = response_json or {"summary": "ok summary", "key_findings": ["finding one"]}
        self.model = "fake-model"

    @property
    def provider_name(self) -> str:
        return "fake"

    def complete(self, messages: List[Dict[str, str]], max_tokens: int = 4096, temperature: float = 0.7) -> LLMResponse:
        self.prompts.append(messages[0]["content"])
        return LLMResponse(
            text=json.dumps(self.response_json),
            input_tokens=10,
            output_tokens=10,
            model=self.model,
            duration_ms=1,
            cost_usd=0.001,
        )


def _fake_search_response(n: int = 3) -> SearchResponse:
    return SearchResponse(
        query="fake query",
        results=[
            SearchResult(title=f"Result {i}", url=f"https://example.com/{i}", content="x" * 250, score=0.9) for i in range(n)
        ],
        answer="A fake AI-generated answer summary.",
    )


@pytest.fixture
def fake_search_client() -> Any:
    client = type(
        "FakeSearchClient",
        (),
        {
            "search_system_internals": lambda self, topic, depth: _fake_search_response(),
            "search_adversary_tradecraft": lambda self, topic, technique, depth: _fake_search_response(),
        },
    )()
    return client


@pytest.mark.unit
class TestExecuteHappyPath:
    def test_execute_end_to_end_with_search_and_similar_hunts(
        self, fake_search_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key="fake-key")
        monkeypatch.setattr(agent, "_get_search_client", lambda: fake_search_client)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(
                patch.object(
                    _similar_mod,
                    "_find_similar_hunts",
                    return_value=[
                        {"hunt_id": "H-0001", "title": "Related hunt", "status": "completed", "similarity_score": 0.42}
                    ],
                )
            )
            # Real STIX lookup (mitreattack-python parsing the ~50MB
            # enterprise-attack.json) is a genuinely slow cold load and
            # irrelevant to what this test covers -- mock it out, same as
            # test_hunt_researcher_grounding.py does.
            stack.enter_context(patch("hecate_agent.core.attack_matrix.get_technique", return_value=None))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0099"

            result = agent.execute(ResearchInput(topic="ValleyRAT", mitre_technique="T1574.001"))

        assert result.success is True
        assert result.data is not None
        assert result.data.research_id == "R-0099"
        assert result.data.web_searches_performed == 2  # skill 1 + skill 2
        assert result.data.llm_calls == 4  # skills 1, 2, 3, 5 each call the LLM once; skill 4 doesn't use the LLM
        assert result.data.related_work.sources[0]["url"] == "hunts/H-0001.md"
        assert result.metadata["research_id"] == "R-0099"
        assert result.data.max_input_tokens == 10
        assert result.data.input_token_samples == result.data.llm_calls
        assert result.data.input_token_samples == len(provider.prompts)

    def test_execute_without_search_client_skips_web_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key=None)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0001"
            result = agent.execute(ResearchInput(topic="Some topic"))

        assert result.success is True
        assert result.data.web_searches_performed == 0  # type: ignore

    def test_execute_reuses_a_caller_supplied_research_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`hecate-agent research new` allocates an ID for its "Starting Research:"
        banner and passes it in. Allocation persists a high-water mark, so
        allocating a second one here would both leave a permanent gap in the
        numbering and make the banner name a document never written."""
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key=None)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            result = agent.execute(ResearchInput(topic="Some topic", research_id="R-0500"))

        assert result.success is True
        assert result.data is not None
        assert result.data.research_id == "R-0500"
        assert result.metadata["research_id"] == "R-0500"
        mock_manager_cls.return_value.get_next_research_id.assert_not_called()

    def test_source_context_reaches_every_llm_skill(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The topic is a search label. Research built from it alone never saw
        the report it was about: a PolinRider pulse describing Git history
        rewriting and font-file payloads was researched from its headline."""
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key=None)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0001"
            result = agent.execute(
                ResearchInput(
                    topic="PolinRider",
                    source_context="Operators hid payloads in font files and rewrote Git history.",
                )
            )

        assert result.success is True
        assert len(provider.prompts) == 4
        assert all("hid payloads in font files" in prompt for prompt in provider.prompts)

    def test_no_source_context_adds_no_source_section(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key=None)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0001"
            agent.execute(ResearchInput(topic="Some topic"))

        assert not any("Source Intelligence" in prompt for prompt in provider.prompts)

    def test_a_cve_the_source_cites_survives_the_unsupported_cve_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = CapturingProvider(
            {"summary": "s", "key_findings": ["Initial access exploits CVE-2026-4021."]}
        )
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key=None)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0001"
            result = agent.execute(
                ResearchInput(topic="Some topic", source_context="The actor exploited CVE-2026-4021.")
            )

        assert "Initial access exploits CVE-2026-4021." in result.data.adversary_tradecraft.key_findings  # type: ignore

    def test_execute_web_search_disabled_flag_skips_all_search(
        self, fake_search_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider, tavily_api_key="fake-key")
        monkeypatch.setattr(agent, "_get_search_client", lambda: fake_search_client)

        with ExitStack() as stack:
            mock_manager_cls = stack.enter_context(patch("hecate_agent.core.research_manager.ResearchManager"))
            stack.enter_context(patch.object(_similar_mod, "_find_similar_hunts", return_value=[]))
            mock_manager_cls.return_value.get_next_research_id.return_value = "R-0001"
            result = agent.execute(ResearchInput(topic="Some topic", web_search_enabled=False))

        # Skill 1 (system research) used to always try search regardless of
        # this flag -- only skill 2 (tradecraft) checked it. A caller
        # disabling web search specifically because there's nothing real to
        # search for (e.g. hecate-runner, for narrative-free CTI) would
        # still have skill 1 search anyway. Both skills must respect it now.
        assert result.data.web_searches_performed == 0  # type: ignore

    def test_execute_catches_unexpected_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = CapturingProvider()
        agent = HuntResearcherAgent(llm_enabled=True, provider=provider)
        monkeypatch.setattr(agent, "_get_search_client", lambda: None)

        with patch("hecate_agent.core.research_manager.ResearchManager", side_effect=RuntimeError("db unavailable")):
            result = agent.execute(ResearchInput(topic="Some topic"))

        assert result.success is False
        assert result.data is None
        assert "db unavailable" in result.error  # type: ignore


@pytest.mark.unit
class TestSkillSearchClientBranches:
    def test_skill_1_search_results_become_sources(self, fake_search_client: Any) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        agent._search_client = fake_search_client

        output = agent._skill_1_system_research("ValleyRAT", "advanced", True)

        assert len(output.sources) == 3
        assert output.sources[0]["title"] == "Result 0"
        assert agent._web_searches == 1

    def test_skill_1_respects_web_search_disabled(self, fake_search_client: Any) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        agent._search_client = fake_search_client

        output = agent._skill_1_system_research("ValleyRAT", "advanced", False)

        assert output.sources == []
        assert agent._web_searches == 0

    def test_skill_1_search_error_is_swallowed(self) -> None:
        broken_client = type(
            "BrokenClient",
            (),
            {"search_system_internals": lambda self, topic, depth: (_ for _ in ()).throw(RuntimeError("boom"))},
        )()
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        agent._search_client = broken_client

        output = agent._skill_1_system_research("ValleyRAT", "advanced", True)

        assert output.sources == []  # error caught, not raised

    def test_skill_1_llm_disabled_uses_fallback_text(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())
        agent._search_client = None

        output = agent._skill_1_system_research("ValleyRAT", "advanced", True)

        assert "requires LLM for detailed analysis" in output.summary
        assert output.key_findings == ["LLM disabled - manual research required"]

    def test_skill_2_search_results_become_sources(self, fake_search_client: Any) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        agent._search_client = fake_search_client

        output = agent._skill_2_adversary_tradecraft("ValleyRAT", "T1574.001", "advanced", True)

        assert len(output.sources) == 3
        assert agent._web_searches == 1

    def test_skill_2_search_error_is_swallowed(self) -> None:
        broken_client = type(
            "BrokenClient",
            (),
            {"search_adversary_tradecraft": lambda self, topic, technique, depth: (_ for _ in ()).throw(RuntimeError("boom"))},
        )()
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        agent._search_client = broken_client

        output = agent._skill_2_adversary_tradecraft("ValleyRAT", None, "advanced", True)

        assert output.sources == []  # error caught, not raised

    def test_skill_2_llm_disabled_uses_fallback_text(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())
        agent._search_client = None

        output = agent._skill_2_adversary_tradecraft("ValleyRAT", None, "advanced", True)

        assert "requires LLM for" in output.summary
        assert output.key_findings == ["LLM disabled - manual research required"]

    def test_get_search_client_constructs_real_client_when_key_present(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider(), tavily_api_key="fake-key")

        client = agent._get_search_client()

        from hecate_agent.core.web_search import TavilySearchClient

        assert isinstance(client, TavilySearchClient)
        # Cached, not rebuilt on a second call.
        assert agent._get_search_client() is client

    def test_get_search_client_none_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The constructor falls back to os.getenv("TAVILY_API_KEY") when the
        # argument is None, so "without key" has to mean the environment too --
        # otherwise this passes only where no .env happens to be loaded, and
        # any test importing hecate_agent.cli (which calls load_dotenv() at import)
        # silently turns it red. Mirrors tests/core/test_web_search.py.
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider(), tavily_api_key=None)
        assert agent._get_search_client() is None


@pytest.mark.unit
class TestSkill3TelemetryMapping:
    def test_llm_disabled_uses_fallback_findings(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        output = agent._skill_3_telemetry_mapping("ValleyRAT", None)

        assert "requires LLM for" in output.summary
        assert any("OCSF_SCHEMA_REFERENCE" in f for f in output.key_findings)

    def test_loads_real_ocsf_schema_and_environment_files_when_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        knowledge = tmp_path / "knowledge"
        knowledge.mkdir()
        (knowledge / "OCSF_SCHEMA_REFERENCE.md").write_text("# schema content")
        (knowledge / "environment.md").write_text("# environment content")
        # Knowledge files resolve against the workspace, not the working
        # directory. Pin it explicitly: an exported HECATE_WORKSPACE would
        # otherwise send these loaders at the real workspace.
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())
        output = agent._skill_3_telemetry_mapping("ValleyRAT", None)

        # schema_available=True path -> higher confidence and the
        # "Internal schema documentation" source snippet, not the
        # "not found" fallback text.
        assert output.confidence == 0.4 or output.confidence == 0.9  # LLM disabled path forces via _llm_call_failed check
        assert "Canonical OCSF field names" in output.sources[0]["snippet"]

    def test_missing_ocsf_files_use_not_found_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))  # no knowledge/ dir here
        monkeypatch.chdir(tmp_path)
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        output = agent._skill_3_telemetry_mapping("ValleyRAT", None)

        assert "Schema file not found" in output.sources[0]["snippet"]


@pytest.mark.unit
class TestSkill4RelatedWork:
    def test_finds_similar_hunts(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        with patch.object(
            _similar_mod,
            "_find_similar_hunts",
            return_value=[{"hunt_id": "H-0602", "title": "AI evasion draft", "status": "planning", "similarity_score": 0.31}],
        ):
            output = agent._skill_4_related_work("Some topic")

        assert output.sources[0]["url"] == "hunts/H-0602.md"
        assert "H-0602" in output.key_findings[0]
        assert "Found 1 related hunts" in output.summary

    def test_no_similar_hunts_found(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        with patch.object(_similar_mod, "_find_similar_hunts", return_value=[]):
            output = agent._skill_4_related_work("Some topic")

        assert output.sources == []
        assert "No related hunts found" in output.summary

    def test_similarity_search_exception_degrades_gracefully(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        with patch.object(_similar_mod, "_find_similar_hunts", side_effect=RuntimeError("index unavailable")):
            output = agent._skill_4_related_work("Some topic")

        assert output.sources == []
        assert output.key_findings == ["Similarity search failed - related-hunt coverage was NOT checked"]

    def test_similarity_unavailable_is_not_reported_as_no_results(self) -> None:
        """A search that could not run must not read as a search that found nothing.

        The model treats this line as evidence about how novel the topic is,
        so collapsing the two states told it the opposite of the truth
        whenever scikit-learn was missing.
        """
        agent = HuntResearcherAgent(llm_enabled=True, provider=CapturingProvider())
        with patch.object(
            _similar_mod,
            "_find_similar_hunts",
            side_effect=_similar_mod.SimilarityUnavailable("scikit-learn is required"),
        ):
            output = agent._skill_4_related_work("Some topic")

        assert output.sources == []
        assert output.key_findings == [
            "Similarity search unavailable - related-hunt coverage was NOT checked"
        ]
        # The distinction is the point: it must not claim an empty result.
        assert "No similar hunts found" not in output.key_findings[0]


@pytest.mark.unit
class TestSkill5Synthesis:
    def test_llm_disabled_uses_fallback_findings(self) -> None:
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        output = agent._skill_5_synthesis("Some topic", None, skills=[])

        assert output.summary == "Research synthesis for Some topic"
        assert output.key_findings == [
            "LLM disabled - manual synthesis required",
            "Review individual skill outputs for findings",
        ]
        assert output.sources == []


@pytest.mark.unit
class TestWebSearchFailureIsReported:
    """Grounding stayed off unnoticed because the search call was wrapped in a
    bare `except Exception: pass`. The client built fine and the key was set,
    so every upstream check looked healthy while every search returned 403."""

    def test_a_failing_search_is_logged_not_swallowed(self, caplog) -> None:  # type: ignore
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        class Failing:
            def search_system_internals(self, *a, **k):
                raise RuntimeError("exceeds your plan's set usage limit")

        with patch.object(agent, "_get_search_client", return_value=Failing()):
            with caplog.at_level(logging.WARNING):
                agent._skill_1_system_research("Some topic", "advanced", True)

        assert "UNGROUNDED" in caplog.text
        assert "usage limit" in caplog.text

    def test_it_is_reported_once_per_agent(self, caplog) -> None:  # type: ignore
        """Called per skill; a traceback per skill buries the first one."""
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        class Failing:
            def search_system_internals(self, *a, **k):
                raise RuntimeError("boom")

        with patch.object(agent, "_get_search_client", return_value=Failing()):
            with caplog.at_level(logging.WARNING):
                agent._skill_1_system_research("T1", "advanced", True)
                agent._skill_1_system_research("T2", "advanced", True)

        assert caplog.text.count("UNGROUNDED") == 1

    def test_research_still_completes(self, caplog) -> None:  # type: ignore
        """Reported, not fatal: an ungrounded document is still worth more than
        no document, as long as the degradation is visible."""
        agent = HuntResearcherAgent(llm_enabled=False, provider=CapturingProvider())

        class Failing:
            def search_system_internals(self, *a, **k):
                raise RuntimeError("boom")

        with patch.object(agent, "_get_search_client", return_value=Failing()):
            output = agent._skill_1_system_research("Some topic", "advanced", True)

        assert output is not None
