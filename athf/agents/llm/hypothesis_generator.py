"""Hypothesis generator agent - LLM-powered hypothesis generation."""

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

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


class HypothesisGeneratorAgent(LLMAgent[HypothesisGenerationInput, HypothesisGenerationOutput]):
    """Generates hunt hypotheses using Claude.

    Uses Claude API for context-aware hypothesis generation with fallback
    to template-based generation when LLM is disabled.

    Features:
    - TTP-focused hypothesis generation
    - MITRE ATT&CK technique mapping
    - Data source validation
    - False positive prediction
    - Cost tracking
    """

    def execute(self, input_data: HypothesisGenerationInput) -> AgentResult[HypothesisGenerationOutput]:
        """Generate hypothesis using LLM.

        Args:
            input_data: Hypothesis generation input

        Returns:
            AgentResult with hypothesis output or error
        """
        if not self.llm_enabled:
            # Fallback to template-based generation
            return self._template_generate(input_data)

        # Use AWS Bedrock Claude API
        try:
            client = self._get_llm_client()

            prompt = self._build_prompt(input_data)

            # Bedrock model ID - using cross-region inference profile for Claude Sonnet 4.5
            # Cross-region inference profiles provide better availability and automatic failover
            model_id = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

            # Prepare request body for Bedrock
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            }

            # Invoke model via Bedrock (with timing)
            start_time = time.time()
            response = client.invoke_model(modelId=model_id, body=json.dumps(request_body))
            duration_ms = int((time.time() - start_time) * 1000)

            # Parse Bedrock response
            response_body = json.loads(response["body"].read())

            # Extract text from response
            output_text = response_body["content"][0]["text"]

            # Try to extract JSON from markdown code blocks if present
            if "```json" in output_text:
                json_start = output_text.find("```json") + 7
                json_end = output_text.find("```", json_start)
                output_text = output_text[json_start:json_end].strip()
            elif "```" in output_text:
                json_start = output_text.find("```") + 3
                json_end = output_text.find("```", json_start)
                output_text = output_text[json_start:json_end].strip()

            # Parse JSON with better error handling
            try:
                output_data = json.loads(output_text)
            except json.JSONDecodeError as e:
                # If JSON parsing fails, log the actual response for debugging
                raise ValueError(
                    f"Failed to parse JSON response from Claude. "
                    f"Error: {e}. "
                    f"Response text (first 1500 chars): {output_text[:1500]}"
                )

            output = HypothesisGenerationOutput(**output_data)

            # Extract usage metrics from Bedrock response
            usage = response_body.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            cost_usd = self._calculate_cost_bedrock(input_tokens, output_tokens)

            # Log metrics to centralized tracker
            self._log_llm_metrics(
                agent_name="hypothesis-generator",
                model_id=model_id,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost_usd,
                duration_ms=duration_ms,
            )

            return AgentResult(
                success=True,
                data=output,
                error=None,
                warnings=[],
                metadata={
                    "llm_model": model_id,
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "cost_usd": cost_usd,
                    "duration_ms": duration_ms,
                },
            )

        except Exception as e:
            # Fall back to template generation
            return self._template_generate(input_data, error=str(e))

    def _build_prompt(self, input_data: HypothesisGenerationInput) -> str:
        """Build Claude prompt for hypothesis generation.

        Args:
            input_data: Hypothesis generation input

        Returns:
            Formatted prompt string
        """
        return f"""You are a threat hunting expert. Generate a hunt hypothesis based on the following:

**Threat Intel:**
{input_data.threat_intel}

**Past Similar Hunts:**
{json.dumps(input_data.past_hunts, indent=2)}

**Available Environment:**
{json.dumps(input_data.environment, indent=2)}

{self._build_research_section(input_data.research)}Generate a hypothesis following this format:
- Hypothesis: "Adversaries use [behavior] to [goal] on [target]"
- Justification: Why this hypothesis is valuable
- MITRE Techniques: Relevant ATT&CK techniques (e.g., T1003.001)
- Data Sources: Which data sources to query
- Expected Observables: What we expect to find
- Known False Positives: Common benign patterns
- Time Range: Suggested time window with justification

**IMPORTANT:** Return your response as a JSON object matching this schema:
{{
  "hypothesis": "string",
  "justification": "string",
  "mitre_techniques": ["T1234.001", "T5678.002"],
  "data_sources": ["ClickHouse nocsf_unified_events", "CloudTrail"],
  "expected_observables": ["Process execution", "Network connections"],
  "known_false_positives": ["Legitimate software", "Administrative tools"],
  "time_range_suggestion": "7 days (justification)"
}}
"""

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
            f"- Research ID: {research.research_id}",
            f"- Topic: {research.topic}",
            f"- Techniques: {', '.join(research.mitre_techniques)}",
            "",
            f"Adversary Tradecraft: {research.adversary_tradecraft_summary}",
        ]

        if research.adversary_tradecraft_findings:
            lines.append("Key findings:")
            for finding in research.adversary_tradecraft_findings:
                lines.append(f"  - {finding}")

        lines.append("")
        lines.append(f"Telemetry Mapping: {research.telemetry_mapping_summary}")

        if research.telemetry_mapping_findings:
            lines.append("Key fields:")
            for finding in research.telemetry_mapping_findings:
                lines.append(f"  - {finding}")

        if research.data_source_availability:
            lines.append("")
            lines.append("Data Source Availability:")
            for source, available in research.data_source_availability.items():
                status = "Available" if available else "Unavailable"
                lines.append(f"  - {source}: {status}")

        if research.gaps_identified:
            lines.append("")
            lines.append("Gaps Identified:")
            for gap in research.gaps_identified:
                lines.append(f"  - {gap}")

        if research.recommended_hypothesis:
            lines.append("")
            lines.append(f"Recommended Hypothesis from Research: {research.recommended_hypothesis}")

        lines.append("")
        return "\n".join(lines) + "\n"

    def _template_generate(
        self, input_data: HypothesisGenerationInput, error: Optional[str] = None
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
            hypothesis = f"Investigate suspicious activity related to: {input_data.threat_intel[:100]}"
            mitre_techniques = []

        # Simple template logic
        output = HypothesisGenerationOutput(
            hypothesis=hypothesis,
            justification="Template-generated hypothesis (LLM disabled or failed)",
            mitre_techniques=mitre_techniques,
            data_sources=["EDR telemetry", "SIEM logs"],
            expected_observables=["Process execution", "Network connections"],
            known_false_positives=["Legitimate software updates", "Administrative tools"],
            time_range_suggestion="7 days (standard baseline)",
        )

        warnings = ["LLM disabled - using template generation"]
        if error:
            warnings.append(f"LLM error: {error}")

        return AgentResult(
            success=True,
            data=output,
            error=None,
            warnings=warnings,
            metadata={"fallback": True},
        )

    def _calculate_cost_bedrock(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate AWS Bedrock Claude cost.

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Cost in USD
        """
        # Claude Sonnet 4.5 on Bedrock pricing (as of January 2025)
        input_cost_per_1k = 0.003
        output_cost_per_1k = 0.015

        input_cost = (input_tokens / 1000) * input_cost_per_1k
        output_cost = (output_tokens / 1000) * output_cost_per_1k

        return round(input_cost + output_cost, 4)
