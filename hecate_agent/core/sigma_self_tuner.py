"""Autonomous Detection Self-Tuning Engine (The Purple-Team Engine).

Iteratively refines candidate Sigma rules against adversary emulation telemetry
and benign system background noise until achieving 100% True-Positive capture
with 0% False Positives.

Closed-Loop Tuning Workflow:
1. Evaluate candidate rule against intrusion events (emulation) and baseline events (benign noise).
2. Check if rule is already perfect (100% recall, 0% FP).
3. If noisy (FP > 0), diagnose the firing selections and synthesize precise exclusion filters
   based on legitimate binary images, parent processes, or service accounts.
4. If missing attacks (FN > 0), diagnose the failing constraints and expand selection criteria
   or repair overly narrow field values.
5. Validate semantic integrity against `sigma_semantics.semantic_problem`.
6. Iterate until convergence or maximum iterations reached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import yaml

from hecate_agent.core.emulation_runner import EmulationResult
from hecate_agent.core.llm_provider import LLMProvider
from hecate_agent.core.sigma_evaluator import EvaluationReport, SigmaEvaluator
from hecate_agent.core.sigma_semantics import semantic_problem

logger = logging.getLogger(__name__)


@dataclass
class TuningIteration:
    """A single step in the self-tuning feedback loop."""

    iteration: int
    rule_yaml: str
    metrics: EvaluationReport
    actions_taken: List[str] = field(default_factory=list)


@dataclass
class SelfTuningReport:
    """Full summary of the self-tuning feedback loop execution."""

    initial_rule: str
    final_rule: str
    initial_metrics: EvaluationReport
    final_metrics: EvaluationReport
    history: List[TuningIteration] = field(default_factory=list)
    converged: bool = False
    total_iterations: int = 0

    @property
    def is_perfect(self) -> bool:
        """Whether the tuned rule achieved 100% recall with 0% noise."""
        return self.final_metrics.is_perfect

    @property
    def precision_improved(self) -> bool:
        """Whether precision improved through tuning."""
        return self.final_metrics.precision > self.initial_metrics.precision

    @property
    def recall_improved(self) -> bool:
        """Whether recall improved through tuning."""
        return self.final_metrics.recall > self.initial_metrics.recall

    def summary(self) -> str:
        """Format an executive purple-team tuning summary."""
        init_p = f"{self.initial_metrics.precision * 100:.1f}%"
        init_r = f"{self.initial_metrics.recall * 100:.1f}%"
        final_p = f"{self.final_metrics.precision * 100:.1f}%"
        final_r = f"{self.final_metrics.recall * 100:.1f}%"

        lines = [
            f"=== 🎯 Purple-Team Self-Tuning Engine: {self.final_metrics.rule_title} ===",
            f"  Status: {'CONVERGED (100% TP, 0% FP)' if self.converged else 'COMPLETED (Best Effort)'}",
            f"  Iterations: {self.total_iterations}",
            f"  Initial Metrics: Precision={init_p}, Recall={init_r} (TP={self.initial_metrics.true_positives}, FP={self.initial_metrics.false_positives}, FN={self.initial_metrics.false_negatives})",
            f"  Final Metrics:   Precision={final_p}, Recall={final_r} (TP={self.final_metrics.true_positives}, FP={self.final_metrics.false_positives}, FN={self.final_metrics.false_negatives})",
        ]
        if self.history:
            lines.append("  Tuning Actions Applied:")
            for step in self.history:
                for act in step.actions_taken:
                    lines.append(f"    - Iteration {step.iteration}: {act}")
        return "\n".join(lines)


class SigmaSelfTuner:
    """Self-tuning engine that autonomously optimizes Sigma detection rules."""

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        max_iterations: int = 3,
        strict_semantics: bool = True,
    ) -> None:
        self.llm_provider = llm_provider
        self.max_iterations = max_iterations
        self.strict_semantics = strict_semantics

    def _normalize_rule_dict(self, rule: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert YAML string or dict into a clean Python dictionary."""
        if isinstance(rule, dict):
            return dict(rule)
        try:
            parsed = yaml.safe_load(rule)
            return dict(parsed) if isinstance(parsed, dict) else {}
        except Exception as exc:
            logger.error("Failed to parse rule YAML: %s", exc)
            return {}

    def _synthesize_filter_for_fp(
        self,
        fp_events: List[Dict[str, Any]],
        intrusion_events: Sequence[Dict[str, Any]],
        current_detection: Dict[str, Any],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Synthesize a filter block targeting baseline FP events without excluding attacks."""
        if not fp_events:
            return None

        # Candidate discriminator fields in priority order
        discriminator_fields = ("Image", "User", "ParentImage", "CurrentDirectory")

        # Gather values used in intrusion events so we NEVER filter them
        intrusion_values: Dict[str, Set[str]] = {}
        for ev in intrusion_events:
            for f in discriminator_fields:
                val = ev.get(f)
                if val:
                    intrusion_values.setdefault(f, set()).add(str(val).lower())

        filter_constraints: Dict[str, Any] = {}

        # Look for baseline properties absent in all intrusion events
        for f in discriminator_fields:
            fp_vals = {str(ev[f]) for ev in fp_events if f in ev and ev[f]}
            safe_fp_vals = [v for v in fp_vals if v.lower() not in intrusion_values.get(f, set())]

            if safe_fp_vals:
                if len(safe_fp_vals) == 1:
                    filter_constraints[f] = safe_fp_vals[0]
                else:
                    filter_constraints[f] = sorted(safe_fp_vals)
                break  # Use the highest-priority differentiating field

        if not filter_constraints:
            return None

        # Generate a unique filter name
        filter_num = 1
        filter_name = "filter_legitimate"
        while filter_name in current_detection:
            filter_num += 1
            filter_name = f"filter_legitimate_{filter_num}"

        return filter_name, filter_constraints

    def _repair_rule_for_fn(
        self,
        rule_dict: Dict[str, Any],
        missed_events: List[Dict[str, Any]],
    ) -> List[str]:
        """Repair overly restrictive selections causing false negatives."""
        actions: List[str] = []
        detection = rule_dict.get("detection", {})

        for name, block in list(detection.items()):
            if name.lower() in ("condition", "timeframe") or not isinstance(block, dict):
                continue

            for key, val in list(block.items()):
                field_base = key.split("|")[0].strip()

                # If the rule has an Image constraint that missed the executed binary
                if field_base.lower() in ("image", "commandline"):
                    observed_vals = {str(ev[field_base]) for ev in missed_events if field_base in ev and ev[field_base]}
                    if observed_vals:
                        curr_vals = val if isinstance(val, list) else [val]
                        new_vals = list(curr_vals)
                        for obs in observed_vals:
                            if obs not in new_vals:
                                new_vals.append(obs)
                                actions.append(f"Expanded {key} to include observed value '{obs}'")
                        block[key] = new_vals if len(new_vals) > 1 else new_vals[0]

        return actions

    def _refine_programmatic(
        self,
        current_rule_dict: Dict[str, Any],
        report: EvaluationReport,
        intrusion_events: Sequence[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Programmatically refine the rule logic using diagnostic traces."""
        refined_dict = yaml.safe_load(yaml.dump(current_rule_dict))
        actions: List[str] = []
        detection = refined_dict.setdefault("detection", {})

        # 1. Address False Positives by adding an exclusion filter
        if report.false_positives > 0:
            res = self._synthesize_filter_for_fp(
                report.false_positive_events,
                intrusion_events,
                detection,
            )
            if res:
                filter_name, filter_block = res
                detection[filter_name] = filter_block

                # Update condition to include filter
                cond = str(detection.get("condition", "selection"))
                if "not " in cond:
                    new_cond = f"{cond} and not {filter_name}"
                else:
                    new_cond = f"({cond}) and not {filter_name}"
                detection["condition"] = new_cond
                actions.append(f"Added exclusion filter '{filter_name}' targeting {list(filter_block.keys())}")

        # 2. Address False Negatives by repairing overly restrictive constraints
        if report.false_negatives > 0:
            fn_actions = self._repair_rule_for_fn(refined_dict, report.missed_events)
            actions.extend(fn_actions)

        return refined_dict, actions

    def tune(
        self,
        rule: Union[str, Dict[str, Any]],
        intrusion_events: Sequence[Dict[str, Any]],
        baseline_events: Sequence[Dict[str, Any]],
    ) -> SelfTuningReport:
        """Run the autonomous detection self-tuning loop until convergence."""
        current_dict = self._normalize_rule_dict(rule)
        initial_yaml = yaml.dump(current_dict, sort_keys=False)

        # Baseline evaluation
        initial_eval = SigmaEvaluator.evaluate_rule(current_dict, intrusion_events, baseline_events)
        history: List[TuningIteration] = []

        best_dict = current_dict
        best_eval = initial_eval
        best_yaml = initial_yaml

        # If already perfect, return early
        if initial_eval.is_perfect:
            return SelfTuningReport(
                initial_rule=initial_yaml,
                final_rule=initial_yaml,
                initial_metrics=initial_eval,
                final_metrics=initial_eval,
                converged=True,
                total_iterations=0,
            )

        for i in range(1, self.max_iterations + 1):
            # Attempt refinement
            refined_dict, actions = self._refine_programmatic(best_dict, best_eval, intrusion_events)
            refined_yaml = yaml.dump(refined_dict, sort_keys=False)

            # Check semantic validity
            if self.strict_semantics:
                category = refined_dict.get("logsource", {}).get("category", "")
                sem_err = semantic_problem(refined_dict.get("detection", {}), category)
                if sem_err:
                    logger.warning("Refined rule failed semantic validation: %s", sem_err)
                    actions.append(f"Semantic validation warning: {sem_err}")

            # Re-evaluate refined rule
            new_eval = SigmaEvaluator.evaluate_rule(refined_dict, intrusion_events, baseline_events)
            iteration_step = TuningIteration(
                iteration=i,
                rule_yaml=refined_yaml,
                metrics=new_eval,
                actions_taken=actions,
            )
            history.append(iteration_step)

            # Accept if precision or recall improved without regressing the other
            improved = (new_eval.precision >= best_eval.precision and new_eval.recall >= best_eval.recall) and (
                new_eval.precision > best_eval.precision or new_eval.recall > best_eval.recall
            )

            if improved or new_eval.is_perfect:
                best_dict = refined_dict
                best_yaml = refined_yaml
                best_eval = new_eval

            if best_eval.is_perfect:
                break

        return SelfTuningReport(
            initial_rule=initial_yaml,
            final_rule=best_yaml,
            initial_metrics=initial_eval,
            final_metrics=best_eval,
            history=history,
            converged=best_eval.is_perfect,
            total_iterations=len(history),
        )

    def tune_emulation(
        self,
        rule: Union[str, Dict[str, Any]],
        emulation_result: EmulationResult,
        baseline_events: Sequence[Dict[str, Any]],
    ) -> SelfTuningReport:
        """Run self-tuning directly on telemetry harvested from an EmulationResult."""
        return self.tune(
            rule=rule,
            intrusion_events=emulation_result.events,
            baseline_events=baseline_events,
        )
