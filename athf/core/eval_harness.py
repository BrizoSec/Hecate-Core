"""Model-quality eval harness: known-answer fixtures for spot-checking LLM providers.

Not a general benchmark. A small set of unambiguous, grep-able checks — mostly
MITRE ATT&CK technique-ID recall — that catch confident hallucination before
it reaches a production model swap. This scripts the same kind of manual spot
check that caught a 7B model confidently mislabeling T1003.001 as "System
Information Discovery" instead of "OS Credential Dumping: LSASS Memory".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

from athf.core.llm_provider import LLMProvider


@dataclass(frozen=True)
class Fixture:
    id: str
    category: str
    prompt: str
    keywords: List[str]
    match_mode: Literal["any", "all"] = "any"
    description: str = ""


FIXTURES: List[Fixture] = [
    Fixture(
        id="T1003.001",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1003.001? Answer in one sentence.",
        keywords=["lsass"],
        description="OS Credential Dumping: LSASS Memory",
    ),
    Fixture(
        id="T1059.001",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1059.001? Answer in one sentence.",
        keywords=["powershell"],
        description="Command and Scripting Interpreter: PowerShell",
    ),
    Fixture(
        id="T1053.005",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1053.005? Answer in one sentence.",
        # "any" of these: models correctly describe this as "Task Scheduler" /
        # "schtasks" as often as the literal phrase "scheduled task".
        keywords=["scheduled task", "task scheduler", "schtasks"],
        description="Scheduled Task/Job: Scheduled Task",
    ),
    Fixture(
        id="T1078",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1078? Answer in one sentence.",
        keywords=["valid account"],
        description="Valid Accounts",
    ),
    Fixture(
        id="T1566.001",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1566.001? Answer in one sentence.",
        keywords=["spearphishing", "attachment"],
        match_mode="all",
        description="Phishing: Spearphishing Attachment",
    ),
    Fixture(
        id="T1021.001",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1021.001? Answer in one sentence.",
        keywords=["remote desktop", "rdp"],
        description="Remote Services: Remote Desktop Protocol",
    ),
    Fixture(
        id="T1055",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1055? Answer in one sentence.",
        keywords=["process injection"],
        description="Process Injection",
    ),
    Fixture(
        id="T1071.001",
        category="mitre-technique",
        prompt="What is MITRE ATT&CK technique T1071.001? Answer in one sentence.",
        keywords=["web protocol", "http", "https"],
        description="Application Layer Protocol: Web Protocols",
    ),
    Fixture(
        id="pyramid-of-pain",
        category="concept",
        prompt="In threat hunting, what sits at the top of the Pyramid of Pain and why does it matter?",
        keywords=["ttp", "tactics, techniques"],
        description="TTPs are the hardest artifact for adversaries to change",
    ),
    Fixture(
        id="lolbin",
        category="concept",
        prompt="What does the term LOLBin mean in endpoint security?",
        keywords=["living off the land", "lolbin"],
        description="Living-off-the-land binary",
    ),
]


def build_grounded_fixtures(fixtures: Optional[List[Fixture]] = None) -> List[Fixture]:
    """STIX-grounded variants of the mitre-technique fixtures.

    The default fixtures test cold recall: "what is T1003.001?" answered
    from the model's own training data, with nothing to check its work
    against. This variant instead supplies MITRE's own technique name and
    description (via ``athf attack lookup``'s data source, no LLM involved)
    as context and asks the model to summarize it in one sentence.

    The point isn't to make the eval easier — it's to separate two different
    questions that "athf eval" collapses into one score: (1) does the model
    *know* this fact unaided, and (2) can the model correctly *use* a fact
    it's been handed. A hunt pipeline that looks up known technique IDs via
    STIX before prompting (rather than trusting the model's memory) only
    needs a model that's good at (2). If grounded fixtures score dramatically
    higher than cold ones on the same model, that is a strong argument for
    fixing the prompt/retrieval path rather than chasing a bigger model.
    """
    from athf.core.attack_matrix import get_technique

    source = fixtures if fixtures is not None else FIXTURES
    grounded: List[Fixture] = []
    for base in source:
        if base.category != "mitre-technique":
            continue
        info = get_technique(base.id)
        if info is None:
            continue  # no STIX data for this ID (e.g. fallback provider) — skip rather than fake it
        description = (info.get("description") or "").strip()[:400]
        name = info.get("name", base.id)
        prompt = (
            f'Here is MITRE ATT&CK technique {base.id} ("{name}"):\n'
            f'"{description}"\n\n'
            "Summarize what this technique is in one sentence."
        )
        grounded.append(
            Fixture(
                id=f"{base.id}-grounded",
                category="mitre-technique-grounded",
                prompt=prompt,
                keywords=base.keywords,
                match_mode=base.match_mode,
                description=base.description,
            )
        )
    return grounded


@dataclass
class FixtureResult:
    fixture: Fixture
    passed: bool
    response_text: str
    duration_ms: int
    error: Optional[str] = None


@dataclass
class EvalReport:
    provider_name: str
    model: str
    results: List[FixtureResult] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def total_duration_ms(self) -> int:
        return sum(r.duration_ms for r in self.results)

    @property
    def score(self) -> float:
        return self.passed_count / self.total_count if self.total_count else 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "provider": self.provider_name,
            "model": self.model,
            "score": round(self.score, 3),
            "passed": self.passed_count,
            "total": self.total_count,
            "duration_ms": self.total_duration_ms,
            "results": [
                {
                    "id": r.fixture.id,
                    "category": r.fixture.category,
                    "description": r.fixture.description,
                    "passed": r.passed,
                    "duration_ms": r.duration_ms,
                    "response_text": r.response_text,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


def _fixture_passes(fixture: Fixture, response_text: str) -> bool:
    lowered = response_text.lower()
    hits = [kw for kw in fixture.keywords if kw.lower() in lowered]
    if fixture.match_mode == "all":
        return len(hits) == len(fixture.keywords)
    return len(hits) > 0


def run_eval(
    provider: LLMProvider,
    fixtures: Optional[List[Fixture]] = None,
    max_tokens: int = 200,
    temperature: float = 0.0,
) -> EvalReport:
    """Run each fixture prompt against the provider and score the response.

    Defaults to temperature 0.0: this measures whether the model *knows* the
    fact, not whether sampling got lucky. A higher temperature makes results
    non-reproducible run to run, which defeats the point of a regression gate.

    A single fixture erroring (timeout, connection failure) is recorded as a
    failure rather than aborting the whole run — one bad question shouldn't
    hide the pass/fail signal from the rest of the set.
    """
    resolved_fixtures = fixtures if fixtures is not None else FIXTURES
    report = EvalReport(
        provider_name=provider.provider_name,
        model=getattr(provider, "model", "unknown"),
    )

    for fixture in resolved_fixtures:
        start = time.monotonic()
        try:
            response = provider.complete(
                messages=[{"role": "user", "content": fixture.prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            report.results.append(
                FixtureResult(
                    fixture=fixture,
                    passed=_fixture_passes(fixture, response.text),
                    response_text=response.text,
                    duration_ms=duration_ms,
                )
            )
        except Exception as exc:  # noqa: BLE001 — isolate one fixture's failure from the run
            duration_ms = int((time.monotonic() - start) * 1000)
            report.results.append(
                FixtureResult(
                    fixture=fixture,
                    passed=False,
                    response_text="",
                    duration_ms=duration_ms,
                    error=str(exc),
                )
            )

    return report
