"""Tests for athf.agents.llm.hypothesis_generator - LLM-powered hypothesis generation."""

import json
from unittest.mock import MagicMock, patch

import pytest

from athf.agents.llm.hypothesis_generator import (
    HypothesisGenerationInput,
    HypothesisGenerationOutput,
    HypothesisGeneratorAgent,
    ResearchContext,
)
from athf.core.llm_provider import LLMProvider, LLMResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HYPOTHESIS_JSON = json.dumps(
    {
        "hypothesis": "Adversaries use credential dumping to steal hashes on Windows endpoints",
        "justification": "Common post-exploitation technique in enterprise environments",
        "mitre_techniques": ["T1003.001"],
        "data_sources": ["EDR telemetry"],
        "expected_observables": ["LSASS memory access"],
        "known_false_positives": ["AV scanners accessing LSASS"],
        "time_range_suggestion": "7 days (standard baseline)",
        "actor": "Generic post-exploitation toolkit",
        "behavior": "LSASS memory access via comsvcs.dll MiniDump",
        "location": "Windows domain-joined endpoints",
        "evidence": "EDR process telemetry - process.name, parent.process.name",
    }
)

# Deliberately omits actor/behavior/location/evidence -- covers a model that
# doesn't follow the ABLE portion of the schema (or predates the prompt
# change) without discarding an otherwise-good response.
VALID_HYPOTHESIS_JSON_WITHOUT_ABLE = json.dumps(
    {
        "hypothesis": "Adversaries use credential dumping to steal hashes on Windows endpoints",
        "justification": "Common post-exploitation technique in enterprise environments",
        "mitre_techniques": ["T1003.001"],
        "data_sources": ["EDR telemetry"],
        "expected_observables": ["LSASS memory access"],
        "known_false_positives": ["AV scanners accessing LSASS"],
        "time_range_suggestion": "7 days (standard baseline)",
    }
)


class MockProvider(LLMProvider):
    """A deterministic mock provider for testing."""

    def __init__(self, response_text):
        self.response_text = response_text
        self.calls = []

    @property
    def provider_name(self):
        return "mock"

    def complete(self, messages, max_tokens=4096, temperature=0.7):
        self.calls.append({"messages": messages, "max_tokens": max_tokens})
        return LLMResponse(
            text=self.response_text,
            input_tokens=100,
            output_tokens=50,
            model="mock-model",
            duration_ms=100,
            cost_usd=0.001,
        )


def _make_input(threat_intel="Credential dumping via LSASS"):
    """Build a minimal HypothesisGenerationInput."""
    return HypothesisGenerationInput(
        threat_intel=threat_intel,
        past_hunts=[],
        environment={"data_sources": ["EDR"]},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHypothesisGeneratorAgent:
    """Test the HypothesisGeneratorAgent."""

    def test_execute_with_mock_provider(self):
        """Valid JSON from the provider produces a HypothesisGenerationOutput."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        result = agent.execute(_make_input())

        assert result.success is True
        assert result.data is not None
        assert isinstance(result.data, HypothesisGenerationOutput)
        assert result.data.hypothesis.startswith("Adversaries use")
        assert "T1003.001" in result.data.mitre_techniques
        assert len(mock.calls) >= 1

    def test_execute_parses_able_scoping_fields(self):
        """A response that includes ABLE fields surfaces them on the output."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        result = agent.execute(_make_input())

        assert result.success is True
        assert result.data.actor == "Generic post-exploitation toolkit"
        assert result.data.behavior == "LSASS memory access via comsvcs.dll MiniDump"
        assert result.data.location == "Windows domain-joined endpoints"
        assert result.data.evidence == "EDR process telemetry - process.name, parent.process.name"

    def test_execute_defaults_able_fields_when_model_omits_them(self):
        """Regression test: HypothesisGenerationOutput(**output_data) used to
        have no defaults for actor/behavior/location/evidence, so a model
        that didn't include them (e.g. hadn't seen the updated prompt, or
        just didn't follow it) raised a TypeError that discarded the whole
        response -- hypothesis, techniques, everything -- and forced a
        fallback to the much lower-quality template generator, just because
        four new optional fields were missing."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON_WITHOUT_ABLE)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        result = agent.execute(_make_input())

        assert result.success is True
        assert result.metadata.get("fallback") is not True  # real LLM response, not template fallback
        assert result.data.hypothesis.startswith("Adversaries use")
        assert result.data.actor == ""
        assert result.data.behavior == ""
        assert result.data.location == ""
        assert result.data.evidence == ""

    def test_execute_preserves_able_fields_after_invalid_technique_rebuild(self):
        """Regression test: the output gets manually rebuilt (dropping
        invalid technique IDs) after ATT&CK validation. That rebuild must
        carry ABLE fields forward too, not silently drop them."""
        response = json.dumps(
            {
                "hypothesis": "Adversaries use credential dumping to steal hashes",
                "justification": "test",
                "mitre_techniques": ["T1003.001", "T9999.999"],  # T9999.999 doesn't exist
                "data_sources": ["EDR telemetry"],
                "expected_observables": ["LSASS memory access"],
                "known_false_positives": [],
                "time_range_suggestion": "7 days",
                "actor": "Test actor",
                "behavior": "Test behavior",
                "location": "Test location",
                "evidence": "Test evidence",
            }
        )
        mock = MockProvider(response)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        with patch("athf.core.attack_matrix._get_provider") as mock_get_provider:
            mock_stix = MagicMock()
            mock_stix.is_stix.return_value = True
            mock_get_provider.return_value = mock_stix
            with patch("athf.core.attack_matrix.get_technique") as mock_get_technique:
                mock_get_technique.side_effect = lambda tid: {"name": tid} if tid == "T1003.001" else None
                result = agent.execute(_make_input())

        assert result.success is True
        assert result.data.mitre_techniques == ["T1003.001"]  # invalid ID dropped
        assert result.data.actor == "Test actor"
        assert result.data.behavior == "Test behavior"
        assert result.data.location == "Test location"
        assert result.data.evidence == "Test evidence"

    def test_execute_invalid_json_retries(self):
        """Provider returns garbage first, valid JSON second -- retry works."""
        call_count = 0
        original_text = "not json at all"

        class RetryProvider(LLMProvider):
            @property
            def provider_name(self):
                return "retry-mock"

            def complete(self, messages, max_tokens=4096, temperature=0.7):
                nonlocal call_count
                call_count += 1
                text = original_text if call_count == 1 else VALID_HYPOTHESIS_JSON
                return LLMResponse(
                    text=text,
                    input_tokens=100,
                    output_tokens=50,
                    model="retry-model",
                    duration_ms=100,
                    cost_usd=0.001,
                )

        agent = HypothesisGeneratorAgent(provider=RetryProvider(), llm_enabled=True)
        result = agent.execute(_make_input())

        assert result.success is True
        assert result.data is not None
        assert call_count >= 2  # At least one retry happened

    def test_execute_fallback_on_error(self):
        """Provider that always raises falls back to template generation."""

        class ErrorProvider(LLMProvider):
            @property
            def provider_name(self):
                return "error-mock"

            def complete(self, messages, max_tokens=4096, temperature=0.7):
                raise RuntimeError("LLM is down")

        agent = HypothesisGeneratorAgent(provider=ErrorProvider(), llm_enabled=True)
        result = agent.execute(_make_input())

        # Template fallback should still succeed
        assert result.success is True
        assert result.data is not None
        assert result.metadata.get("fallback") is True

    def test_execute_no_llm(self):
        """Agent with llm_enabled=False uses template generation directly."""
        agent = HypothesisGeneratorAgent(llm_enabled=False)
        result = agent.execute(_make_input())

        assert result.success is True
        assert result.data is not None
        assert "Template-generated" in result.data.justification
        assert result.metadata.get("fallback") is True
        # Template fallback has no grounded basis for ABLE scoping -- must
        # come back empty (a human fills it in), not a fabricated guess.
        assert result.data.actor == ""
        assert result.data.behavior == ""
        assert result.data.location == ""
        assert result.data.evidence == ""

    def test_build_prompt_includes_threat_intel(self):
        """The built prompt contains the threat_intel text."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        input_data = _make_input(threat_intel="Pass-the-Hash lateral movement")
        prompt = agent._build_prompt(input_data)

        assert "Pass-the-Hash lateral movement" in prompt

    def test_build_prompt_includes_able_scoping_instructions(self):
        """The prompt asks for Actor/Behavior/Location/Evidence and includes
        them in the JSON schema example."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        prompt = agent._build_prompt(_make_input())

        assert "ABLE scoping" in prompt
        assert '"actor":' in prompt
        assert '"behavior":' in prompt
        assert '"location":' in prompt
        assert '"evidence":' in prompt

    def test_build_prompt_includes_research_context(self):
        """When ResearchContext is provided, it appears in the prompt."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        research = ResearchContext(
            research_id="R-0001",
            topic="Kerberoasting",
            mitre_techniques=["T1558.003"],
            recommended_hypothesis="Adversaries use Kerberoasting to extract service tickets",
            gaps_identified=["No SPN audit logging"],
            data_source_availability={"Windows Security": True},
            estimated_hunt_complexity="medium",
            adversary_tradecraft_findings=["Rubeus usage"],
            telemetry_mapping_findings=["Event 4769"],
            system_research_summary="Kerberos ticket granting overview",
            adversary_tradecraft_summary="Common Kerberoasting tools",
            telemetry_mapping_summary="Windows event 4769 mapping",
        )

        input_data = HypothesisGenerationInput(
            threat_intel="Kerberoasting detection",
            past_hunts=[],
            environment={"data_sources": ["Windows Security"]},
            research=research,
        )

        prompt = agent._build_prompt(input_data)

        assert "R-0001" in prompt
        assert "Kerberoasting" in prompt
        assert "T1558.003" in prompt
        assert "Rubeus usage" in prompt
        assert "Event 4769" in prompt
        assert "No SPN audit logging" in prompt


@pytest.mark.unit
class TestHypothesisGeneratorDuration:
    """Test wall-clock duration tracking in execute()."""

    def test_execute_returns_duration_ms(self):
        """LLM path includes duration_ms in metadata."""
        mock = MockProvider(VALID_HYPOTHESIS_JSON)
        agent = HypothesisGeneratorAgent(provider=mock, llm_enabled=True)

        result = agent.execute(_make_input())

        assert result.success is True
        assert "duration_ms" in result.metadata
        assert isinstance(result.metadata["duration_ms"], int)
        assert result.metadata["duration_ms"] >= 0

    def test_template_fallback_includes_duration_ms(self):
        """Template fallback (no LLM) also includes duration_ms."""
        agent = HypothesisGeneratorAgent(llm_enabled=False)
        result = agent.execute(_make_input())

        assert result.success is True
        assert "duration_ms" in result.metadata
        assert isinstance(result.metadata["duration_ms"], int)

    def test_error_fallback_includes_duration_ms(self):
        """Error fallback path also includes duration_ms."""

        class ErrorProvider(LLMProvider):
            @property
            def provider_name(self):
                return "error-mock"

            def complete(self, messages, max_tokens=4096, temperature=0.7):
                raise RuntimeError("LLM is down")

        agent = HypothesisGeneratorAgent(provider=ErrorProvider(), llm_enabled=True)
        result = agent.execute(_make_input())

        assert result.success is True
        assert "duration_ms" in result.metadata
        assert isinstance(result.metadata["duration_ms"], int)
