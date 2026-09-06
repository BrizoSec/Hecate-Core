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
    # True when `threat_intel` is a bare indicator list (a ThreatFox/Maltrail
    # style feed dump: domains, IPs, URLs, hashes) with no prose describing
    # how any of it was used. Such a source is genuine threat intel -- unlike
    # the marketing case `is_threat_report` covers -- but it evidences no
    # delivery mechanism, actor, malware family or technique, so the prompt
    # has to stop the model supplying those from background knowledge.
    # Set by the caller, which knows its own source formats; defaults False
    # so callers passing free prose are unaffected.
    intel_is_indicator_only: bool = False


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
    # Self-assessed grounding: does the threat intel actually describe
    # observed/reported adversary behavior, or is it vendor/product
    # marketing, compliance news, or other non-incident content the model
    # still produced a plausible-sounding hypothesis and "Adversary
    # Tradecraft"-shaped narrative for anyway? Defaults to True (assume
    # legitimate) so a model that doesn't support this field -- or omits it
    # -- doesn't retroactively flag every prior hunt as low-confidence.
    is_threat_report: bool = True
    low_confidence_reason: str = ""
    # Self-assessed backstop for the indicator-only case, mirroring
    # is_threat_report above. `HypothesisGenerationInput` has a caller-set
    # flag for this, but only a caller that knows its own source formats can
    # set it -- a direct CLI or MCP caller passing a raw feed dump gets no
    # such protection, so the model is asked to recognise the case itself.
    # Defaults False (assume real narrative) so a model that omits the field
    # keeps the normal behavior-hypothesis path.
    is_indicator_only: bool = False


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
            # A caller that set the flag knows its own source formats; its
            # statement of fact outranks the model's self-assessment, which
            # exists only for callers that can't say (see the field's note).
            if input_data.intel_is_indicator_only:
                output_data["is_indicator_only"] = True
            output = HypothesisGenerationOutput(**output_data)

            # Validate technique IDs against the real ATT&CK matrix
            output, warnings = self._apply_technique_validation(output)

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

    def _apply_technique_validation(
        self, output: HypothesisGenerationOutput
    ) -> Tuple[HypothesisGenerationOutput, List[str]]:
        """Reconcile the model's ATT&CK IDs with the real matrix.

        Returns the output (rebuilt with the corrected technique list when
        anything changed) and any warnings describing what changed.
        """
        warnings: List[str] = []
        valid, remapped, invalid = self._validate_techniques(output.mitre_techniques)

        if remapped:
            warnings.append(
                "Remapped {} deprecated ATT&CK ID(s) to their current equivalent: {}".format(
                    len(remapped),
                    ", ".join("{} -> {}".format(old, new) for old, new in remapped),
                )
            )
        if invalid:
            warnings.append(
                "Removed {} unrecognised ATT&CK ID(s): {}".format(len(invalid), ", ".join(invalid))
            )
        if not (remapped or invalid):
            return output, warnings

        # Rebuilt field-by-field rather than mutated: every field must be
        # carried forward explicitly, so a newly added one that's forgotten
        # here shows up as a test failure instead of silently reverting to
        # its default on any hypothesis that had a technique corrected.
        return (
            HypothesisGenerationOutput(
                hypothesis=output.hypothesis,
                justification=output.justification,
                mitre_techniques=valid,
                data_sources=output.data_sources,
                expected_observables=output.expected_observables,
                known_false_positives=output.known_false_positives,
                time_range_suggestion=output.time_range_suggestion,
                actor=output.actor,
                behavior=output.behavior,
                location=output.location,
                evidence=output.evidence,
                is_threat_report=output.is_threat_report,
                low_confidence_reason=output.low_confidence_reason,
                is_indicator_only=output.is_indicator_only,
            ),
            warnings,
        )

    def _validate_techniques(
        self, techniques: List[str]
    ) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
        """Check each technique ID against the real ATT&CK matrix.

        Returns (valid_techniques, remapped, invalid_techniques), where
        `remapped` holds (old_id, new_id) pairs for IDs ATT&CK has revoked
        but still maps to a current replacement, and `valid_techniques`
        carries the replacements in place of the originals.

        Remapping matters because a revoked ID is not the same failure as a
        made-up one: a model trained on years of threat reporting routinely
        names a real behavior by its pre-restructure ID (T1093 for Process
        Hollowing, T1067 for Bootkit). Dropping those discarded a correct
        call and, when it emptied the list, left the hunt with no ATT&CK
        mapping at all. A genuinely fabricated ID (e.g. T1065.003, a
        sub-technique that never existed) has no successor and is still
        rejected here.

        Skips validation and passes through unchanged when STIX data is not
        installed (FallbackProvider has no technique data).
        """
        valid: List[str] = []
        remapped: List[Tuple[str, str]] = []
        invalid: List[str] = []
        try:
            from athf.core.attack_matrix import _get_provider, get_superseding_technique_id, get_technique

            provider = _get_provider()
            # FallbackProvider has no technique data — skip validation rather
            # than incorrectly flagging every ID as invalid.
            if not provider.is_stix():
                return techniques, [], []

            for tid in techniques:
                if get_technique(tid) is not None:
                    resolved = tid
                else:
                    successor = get_superseding_technique_id(tid)
                    if successor is None:
                        invalid.append(tid)
                        continue
                    remapped.append((tid, successor))
                    resolved = successor
                # A model that emitted both the old and new ID for the same
                # technique must not leave a duplicate behind after remapping.
                if resolved not in valid:
                    valid.append(resolved)
        except Exception:
            return techniques, [], []
        return valid, remapped, invalid

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

        # Placed directly after the intel and before the step-1 assessment:
        # it's a fact about the input the model needs while reading it, not
        # a judgement it should try to make for itself.
        indicator_only_note = (
            (
                "**This source is an indicator list, not a narrative "
                "report.** It is a feed dump of indicators (domains, IPs, "
                "URLs, file hashes) with no prose describing how any of "
                "them was used. Feeds like this are genuine threat intel, "
                "so treat step 1 accordingly -- but they carry no evidence "
                "about delivery mechanism, actor identity, malware family, "
                "post-compromise activity, or any ATT&CK technique. Do not "
                "supply those from background knowledge: naming phishing "
                "as the delivery vector, or credential theft and lateral "
                "movement as follow-on activity, is fabrication when the "
                "source is a list of domains. Keep the hypothesis to what "
                "the data supports -- that these indicators appear in the "
                "environment's own telemetry -- and leave "
                '"mitre_techniques" empty unless the source names a '
                "technique explicitly. An empty technique list is the "
                "correct answer here, not a gap to fill.\n\n"
            )
            if input_data.intel_is_indicator_only
            # Backstop for callers that can't set the flag (direct CLI, MCP):
            # ask the model to recognise the case itself. Deliberately not
            # used when the caller *has* flagged it -- a definite statement
            # of fact beats asking the model to re-derive it.
            else (
                "**Before anything else, check what kind of source this "
                "is.** If the threat intel above is a bare indicator list -- "
                "a feed dump of domains, IPs, URLs or file hashes (ThreatFox, "
                "Maltrail and similar) with no prose describing how any of "
                "them was used -- then it evidences no delivery mechanism, "
                "actor identity, malware family, post-compromise activity or "
                "ATT&CK technique. In that case set \"is_indicator_only\" "
                "true in your JSON, write the hypothesis as indicator "
                "presence (\"Indicators published in [source] appear in "
                "[telemetry] on [target]\") rather than adversary behavior, "
                "and leave \"mitre_techniques\" empty -- naming phishing as "
                "the delivery vector, or credential theft and lateral "
                "movement as follow-on activity, is fabrication when the "
                "source is a list of domains. If the intel does contain real "
                "narrative, set it false and continue normally.\n\n"
            )
        )

        # The default template has a [behavior] slot the model is obliged to
        # fill. Against an indicator list there is no evidenced behavior to
        # put in it, so the template itself was driving the invention it is
        # asked above not to commit -- give it a shape that fits the source.
        hypothesis_format = (
            (
                '- Hypothesis: "Indicators published in [source] appear in '
                '[telemetry] on [target]" -- describe indicator presence, '
                "not adversary behavior you cannot evidence.\n"
            )
            if input_data.intel_is_indicator_only
            else '- Hypothesis: "Adversaries use [behavior] to [goal] on [target]"\n'
        )

        return (
            "You are a threat hunting expert.\n\n"
            "{grounding}"
            "**Threat Intel:**\n"
            "{threat_intel}\n\n"
            "{indicator_only_note}"
            "**Step 1 -- assess the threat intel above before doing "
            "anything else:** does it actually describe adversary behavior "
            "that was observed or reported -- an attack, campaign, TTP, or "
            "IOC -- or is it vendor/product marketing, a compliance "
            "announcement, a feature release, or other content that "
            "doesn't describe anything an adversary did? Do not let a "
            "well-written vendor blog post read as a genuine incident "
            "report just because it uses security-adjacent terminology -- "
            "if no adversary is described doing something, it isn't a "
            "threat report. For example: an announcement introducing a new "
            "product integration or feature that happens to mention "
            "credentials, MFA, or billing data only because that's what "
            "the product itself accesses -- not because any adversary was "
            "observed abusing them -- is marketing, not a threat report, "
            "even though every sentence in it could plausibly appear in "
            "one. Decide this now, before drafting anything below, and "
            "record it as \"is_threat_report\" in your JSON response.\n\n"
            "**Step 2 -- generate the hunt hypothesis.** If step 1 "
            "concluded this is not a genuine threat report, still produce "
            "your best-effort hypothesis below (mark it as speculative in "
            "the justification, and give a one-sentence "
            '"low_confidence_reason" explaining what kind of content it '
            "actually is) -- but do not invent an adversary, a specific "
            "attack technique, or named tooling (e.g. a phishing-proxy "
            "kit, a named malware family) that the source material never "
            "mentioned, just to make the hypothesis sound concrete. A "
            "hypothesis honestly built on thin, non-adversarial source "
            "material is more useful than a fabricated one that reads as "
            "credible.\n\n"
            "**Past Similar Hunts:**\n"
            "{past_hunts}\n\n"
            "**Available Environment:**\n"
            "{environment}\n\n"
            "{research_section}"
            "Generate a hypothesis following this format:\n"
            "{hypothesis_format}"
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
            '  "evidence": "string",\n'
            '  "is_threat_report": true,\n'
            '  "low_confidence_reason": "string (only if is_threat_report is false)",\n'
            '  "is_indicator_only": false\n'
            "}}\n"
        ).format(
            grounding=grounding,
            threat_intel=input_data.threat_intel,
            indicator_only_note=indicator_only_note,
            hypothesis_format=hypothesis_format,
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
