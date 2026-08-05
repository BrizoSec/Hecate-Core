"""Hypothesis generator agent - LLM-powered hypothesis generation."""

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from athf.agents.base import AgentResult, LLMAgent


@dataclass
class ResearchContext:
    """Structured research context for hypothesis generation."""

    research_id: str
    topic: str
    mitre_techniques: List[str]
    recommended_hypothesis: Optional[str]
    gaps_identified: List[str]
    data_source_availability: Dict[str, bool]
    estimated_hunt_complexity: str
    adversary_tradecraft_findings: List[str]
    telemetry_mapping_findings: List[str]
    system_research_summary: str
    adversary_tradecraft_summary: str
    telemetry_mapping_summary: str


@dataclass
class HypothesisGenerationInput:
    """Input for hypothesis generation."""

    threat_intel: str  # User-provided threat context
    past_hunts: List[Dict[str, Any]]  # Similar past hunts for context
    environment: Dict[str, Any]  # Data sources, platforms, etc.
    research: Optional[ResearchContext] = None


@dataclass
class HypothesisGenerationOutput:
    """Output from hypothesis generation."""

    hypothesis: str
    justification: str
    mitre_techniques: List[str]
    data_sources: List[str]
    expected_observables: List[str]
    known_false_positives: List[str]
    time_range_suggestion: str
    # ABLE scoping (see templates/HUNT_LOCK.md) -- defaulted to "" rather
    # than required so a model that omits one of these four (unlike the
    # longer-established fields above, which every provider we've tested
    # against reliably returns) degrades to an empty field a human fills
    # in, not a TypeError that discards an otherwise-good hypothesis and
    # forces the low-quality template fallback for the whole response.
    actor: str = ""
    behavior: str = ""
    location: str = ""
    evidence: str = ""


class HypothesisGeneratorAgent(LLMAgent[HypothesisGenerationInput, HypothesisGenerationOutput]):
    """Generates hunt hypotheses using an LLM provider.

    Uses the provider-agnostic LLM abstraction for context-aware hypothesis
    generation with fallback to template-based generation when LLM is disabled.

    Features:
    - TTP-focused hypothesis generation
    - MITRE ATT&CK technique mapping
    - Data source validation
    - False positive prediction
    - Cost tracking (via provider layer)
    """

    def execute(self, input_data: HypothesisGenerationInput) -> AgentResult[HypothesisGenerationOutput]:
        """Generate hypothesis using LLM.

        Measures wall-clock time for the entire execution (including retries,
        prompt building, and JSON parsing) and includes it in metadata as
        ``duration_ms``.

        Args:
            input_data: Hypothesis generation input

        Returns:
            AgentResult with hypothesis output or error
        """
        start = time.monotonic()

        if not self.llm_enabled:
            result = self._template_generate(input_data)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            result.metadata["duration_ms"] = elapsed_ms
            return result

        try:
            prompt = self._build_prompt(input_data)

            def validate_json(text: str) -> Optional[str]:
                try:
                    self._parse_json_response(text)
                    return None
                except ValueError as e:
                    return str(e)

            output_text = self._call_llm_with_retry(prompt, validate_json, max_retries=2)
            output_data = self._parse_json_response(output_text)
            output = HypothesisGenerationOutput(**output_data)

            # Validate technique IDs against the real ATT&CK matrix
            warnings: List[str] = []
            valid_techniques, invalid_techniques = self._validate_techniques(output.mitre_techniques)
            if invalid_techniques:
                warnings.append(
                    "Removed {} unrecognised ATT&CK ID(s): {}".format(len(invalid_techniques), ", ".join(invalid_techniques))
                )
                output = HypothesisGenerationOutput(
                    hypothesis=output.hypothesis,
                    justification=output.justification,
                    mitre_techniques=valid_techniques,
                    data_sources=output.data_sources,
                    expected_observables=output.expected_observables,
                    known_false_positives=output.known_false_positives,
                    time_range_suggestion=output.time_range_suggestion,
                    actor=output.actor,
                    behavior=output.behavior,
                    location=output.location,
                    evidence=output.evidence,
                )

            provider = self._get_provider()
            model_name = getattr(
                provider,
                "model",
                getattr(provider, "model_id", "unknown"),
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            metadata = {
                "llm_provider": provider.provider_name,
                "llm_model": model_name,
                "duration_ms": elapsed_ms,
            }

            return AgentResult(
                success=True,
                data=output,
                error=None,
                warnings=warnings,
                metadata=metadata,
            )

        except Exception as e:
            result = self._template_generate(input_data, error=str(e))
            elapsed_ms = int((time.monotonic() - start) * 1000)
            result.metadata["duration_ms"] = elapsed_ms
            return result

    def _technique_grounding(self, techniques: List[str]) -> str:
        """Inject real ATT&CK names and descriptions for a list of technique IDs.

        Prevents the model from recalling technique identity from memory, which
        has a ~30% error rate on smaller models (measured via eval harness).
        Returns an empty string if STIX data is unavailable or no IDs given.
        """
        if not techniques:
            return ""
        lines = []
        try:
            from athf.core.attack_matrix import get_technique

            for tid in techniques:
                info = get_technique(tid)
                if info:
                    name = info.get("name", tid)
                    desc = (info.get("description") or "").strip()[:300]
                    lines.append('  {}: "{}" — {}'.format(tid, name, desc))
        except Exception:
            return ""
        if not lines:
            return ""
        return "**ATT&CK Ground Truth (use these exact names):**\n" + "\n".join(lines) + "\n\n"

    def _extract_techniques_from_text(self, text: str) -> List[str]:
        """Extract T-code strings from free text."""
        import re

        return re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)

    def _validate_techniques(self, techniques: List[str]) -> Tuple[List[str], List[str]]:
        """Check each technique ID against the real ATT&CK matrix.

        Returns (valid_techniques, invalid_techniques).
        Skips validation and passes through unchanged when STIX data is not
        installed (FallbackProvider has no technique data).
        """
        valid: List[str] = []
        invalid: List[str] = []
        try:
            from athf.core.attack_matrix import _get_provider, get_technique

            provider = _get_provider()
            # FallbackProvider has no technique data — skip validation rather
            # than incorrectly flagging every ID as invalid.
            if not provider.is_stix():
                return techniques, []

            for tid in techniques:
                (valid if get_technique(tid) is not None else invalid).append(tid)
        except Exception:
            return techniques, []
        return valid, invalid

    def _build_prompt(self, input_data: HypothesisGenerationInput) -> str:
        """Build LLM prompt for hypothesis generation.

        Args:
            input_data: Hypothesis generation input

        Returns:
            Formatted prompt string
        """
        # Collect any T-codes mentioned in inputs and inject real ATT&CK context
        mentioned = self._extract_techniques_from_text(input_data.threat_intel)
        if input_data.research:
            mentioned += list(input_data.research.mitre_techniques)
        grounding = self._technique_grounding(list(dict.fromkeys(mentioned)))

        return (
            "You are a threat hunting expert. Generate a hunt hypothesis "
            "based on the following:\n\n"
            "{grounding}"
            "**Threat Intel:**\n"
            "{threat_intel}\n\n"
            "**Past Similar Hunts:**\n"
            "{past_hunts}\n\n"
            "**Available Environment:**\n"
            "{environment}\n\n"
            "{research_section}"
            "Generate a hypothesis following this format:\n"
            '- Hypothesis: "Adversaries use [behavior] to [goal] on [target]"\n'
            "- Justification: Why this hypothesis is valuable\n"
            "- MITRE Techniques: Only include real ATT&CK technique IDs you are certain exist.\n"
            "- Data Sources: Which data sources to query\n"
            "- Expected Observables: What we expect to find\n"
            "- Known False Positives: Common benign patterns\n"
            "- Time Range: Suggested time window with justification\n\n"
            "Also provide ABLE scoping (Actor, Behavior, Location, Evidence) "
            "-- ATHF's standard hunt-scoping framework. Base every ABLE field "
            "strictly on the threat intel and research context given above; "
            'leave a field empty ("") rather than invent specifics -- a '
            "named actor, a specific system, a fabricated log field -- that "
            "isn't actually supported by what you were given:\n"
            "- Actor: The threat actor or malware family this hunt targets "
            "(optional -- empty string if the intel doesn't name one).\n"
            "- Behavior: The specific TTP or behavior pattern to hunt for, "
            "more concrete/actionable than the hypothesis's own [behavior] "
            "clause.\n"
            "- Location: The systems, networks, or environments to hunt in "
            '(e.g. "Windows domain-joined endpoints", "AWS CloudTrail '
            'across all accounts") -- must be consistent with the '
            "environment/data sources given above, not a platform absent "
            "from them.\n"
            "- Evidence: The specific data sources and key fields a hunter "
            "would actually query to test this hypothesis.\n\n"
            "**IMPORTANT:** Return your response as a JSON object matching "
            "this schema:\n"
            "{{\n"
            '  "hypothesis": "string",\n'
            '  "justification": "string",\n'
            '  "mitre_techniques": ["T1234.001", "T5678.002"],\n'
            '  "data_sources": '
            '["ClickHouse nocsf_unified_events", "CloudTrail"],\n'
            '  "expected_observables": '
            '["Process execution", "Network connections"],\n'
            '  "known_false_positives": '
            '["Legitimate software", "Administrative tools"],\n'
            '  "time_range_suggestion": "7 days (justification)",\n'
            '  "actor": "string (or empty string if unknown)",\n'
            '  "behavior": "string",\n'
            '  "location": "string",\n'
            '  "evidence": "string"\n'
            "}}\n"
        ).format(
            grounding=grounding,
            threat_intel=input_data.threat_intel,
            past_hunts=json.dumps(input_data.past_hunts, indent=2),
            environment=json.dumps(input_data.environment, indent=2),
            research_section=self._build_research_section(input_data.research),
        )

    def _build_research_section(self, research: Optional[ResearchContext]) -> str:
        """Build the research context section for the prompt.

        Args:
            research: Optional research context

        Returns:
            Formatted research section string, or empty string if no research
        """
        if research is None:
            return ""

        lines = [
            "**Research Context:**",
            "- Research ID: {}".format(research.research_id),
            "- Topic: {}".format(research.topic),
            "- Techniques: {}".format(", ".join(research.mitre_techniques)),
            "",
            "Adversary Tradecraft: {}".format(research.adversary_tradecraft_summary),
        ]

        if research.adversary_tradecraft_findings:
            lines.append("Key findings:")
            for finding in research.adversary_tradecraft_findings:
                lines.append("  - {}".format(finding))

        lines.append("")
        lines.append("Telemetry Mapping: {}".format(research.telemetry_mapping_summary))

        if research.telemetry_mapping_findings:
            lines.append("Key fields:")
            for finding in research.telemetry_mapping_findings:
                lines.append("  - {}".format(finding))

        if research.data_source_availability:
            lines.append("")
            lines.append("Data Source Availability:")
            for source, available in research.data_source_availability.items():
                status = "Available" if available else "Unavailable"
                lines.append("  - {}: {}".format(source, status))

        if research.gaps_identified:
            lines.append("")
            lines.append("Gaps Identified:")
            for gap in research.gaps_identified:
                lines.append("  - {}".format(gap))

        if research.recommended_hypothesis:
            lines.append("")
            lines.append("Recommended Hypothesis from Research: {}".format(research.recommended_hypothesis))

        lines.append("")
        return "\n".join(lines) + "\n"

    def _template_generate(
        self,
        input_data: HypothesisGenerationInput,
        error: Optional[str] = None,
    ) -> AgentResult[HypothesisGenerationOutput]:
        """Fallback template-based generation (no LLM).

        Args:
            input_data: Hypothesis generation input
            error: Optional error message from LLM attempt

        Returns:
            AgentResult with template-generated hypothesis
        """
        # Use research recommended hypothesis if available
        if input_data.research and input_data.research.recommended_hypothesis:
            hypothesis = input_data.research.recommended_hypothesis
            mitre_techniques = list(input_data.research.mitre_techniques)
        else:
            hypothesis = "Investigate suspicious activity related to: " "{}".format(input_data.threat_intel[:100])
            mitre_techniques = []

        output = HypothesisGenerationOutput(
            hypothesis=hypothesis,
            justification=("Template-generated hypothesis (LLM disabled or failed)"),
            mitre_techniques=mitre_techniques,
            data_sources=["EDR telemetry", "SIEM logs"],
            expected_observables=[
                "Process execution",
                "Network connections",
            ],
            known_false_positives=[
                "Legitimate software updates",
                "Administrative tools",
            ],
            time_range_suggestion="7 days (standard baseline)",
        )

        warnings = ["LLM disabled - using template generation"]
        if error:
            warnings.append("LLM error: {}".format(error))

        return AgentResult(
            success=True,
            data=output,
            error=None,
            warnings=warnings,
            metadata={"fallback": True},
        )
