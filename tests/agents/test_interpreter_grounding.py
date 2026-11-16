"""Production grounding must distinguish real but source-unsupported sibling IDs."""

import pytest

from hecate_agent.agents.llm.hypothesis_generator import (
    HypothesisGenerationInput,
    HypothesisGenerationOutput,
    HypothesisGeneratorAgent,
)
from hecate_agent.core import attack_matrix


class InterpreterMatrix(attack_matrix.FallbackProvider):
    techniques = {
        "T1059.002": {"id": "T1059.002", "name": "AppleScript", "tactic_shortnames": ["execution"]},
        "T1059.007": {"id": "T1059.007", "name": "JavaScript", "tactic_shortnames": ["execution"]},
    }

    def get_technique_by_id(self, technique_id):
        return self.techniques.get(technique_id)

    def get_sorted_tactic_keys(self):
        return ["execution"]

    def get_techniques_for_tactic(self, tactic_key):
        return list(self.techniques.values()) if tactic_key == "execution" else []


@pytest.mark.parametrize(
    "text,correct,wrong",
    [
        ("The loader executed AppleScript on macOS.", "T1059.002", "T1059.007"),
        ("The loader executed JavaScript using Node.js.", "T1059.007", "T1059.002"),
    ],
)
def test_production_offers_grounded_identity_and_filters_wrong_sibling(monkeypatch, text, correct, wrong):
    monkeypatch.setattr(attack_matrix, "_provider", InterpreterMatrix())
    agent = HypothesisGeneratorAgent()
    source = HypothesisGenerationInput(threat_intel=text, past_hunts=[], environment={})
    context = agent._candidate_section(source)
    assert correct in context
    assert wrong not in context
    output = HypothesisGenerationOutput(
        hypothesis="Observed interpreter execution",
        justification="Source observation",
        mitre_techniques=[wrong, correct],
        data_sources=["process events"],
        expected_observables=["interpreter execution"],
        known_false_positives=[],
        time_range_suggestion="1 day",
    )
    filtered, warnings = agent._apply_technique_validation(output, source)
    assert filtered.mitre_techniques == [correct]
    assert any(wrong in warning for warning in warnings)
