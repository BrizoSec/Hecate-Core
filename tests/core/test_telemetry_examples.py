"""OS-specific telemetry examples in the prompts (deep-dive appendix A3)."""

from pathlib import Path
from typing import List

import pytest
import yaml

from hecate_agent.agents.llm.hypothesis_generator import HypothesisGenerationInput, HypothesisGeneratorAgent
from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.telemetry_examples import GENERAL_RULE, render_examples, select_examples

GOLD = Path(__file__).resolve().parents[2] / "evals" / "gold" / "vshell-fake-resume.yaml"
#: The parts of the VShell report that name OS internals, as page extraction returns them.
VSHELL = (
    "The loader checks for a sandbox and calls Beep for a ten-second sleep timer. "
    "It uses AllocADsMem and ReallocADsMem, then VirtualProtect and CreateThread to run the stager. "
    "It reflectively runs a 1,454-byte Windows SNOWLIGHT stager. "
    "The stager exits if %TEMP%\\log_de.log already exists. "
    "The final payload runs in memory without persistence. "
    "UNC5174 used sideloading and different malware."
)


def _concepts(text: str, platforms: List[str] = []) -> List[str]:
    return [e.concept.split(" (")[0] for e in select_examples(text, platforms)]


def test_the_vshell_report_gets_exactly_its_three_internals() -> None:
    assert _concepts(VSHELL, ["Windows"]) == [
        "Win32 API calls",
        "reflective or in-memory loading",
        "%TEMP% and other environment variables",
    ]


def test_negated_and_other_actor_mentions_add_no_example() -> None:
    """ "without persistence" and another actor's "sideloading" are not this specimen."""
    concepts = _concepts(VSHELL, ["Windows"])
    assert "Run-key persistence" not in concepts and "DLL side-loading" not in concepts


def test_a_windows_sample_gets_no_linux_example_even_when_fileless() -> None:
    """The review's confusion: memfd_create offered for a Windows chain."""
    assert not [e for e in select_examples(VSHELL + " A fileless stager.", ["Windows"]) if e.platform != "Windows"]


def test_a_linux_sample_gets_the_memfd_example() -> None:
    text = "The dropper calls memfd_create and executes the payload from /proc/self/fd/3."
    assert _concepts(text, ["Linux"]) == ["memfd_create", "/proc/self/fd/N execution"]


def test_nothing_relevant_renders_nothing() -> None:
    assert render_examples("A phishing email linked to a credential page.") == ""


def test_the_block_states_the_general_rule_and_where_each_appears() -> None:
    block = render_examples(VSHELL, ["Windows"])
    assert block.startswith("HOW OS INTERNALS APPEAR IN TELEMETRY") and GENERAL_RULE in block
    assert "Never as image_load, which records only modules loaded from a file on disk." in block


@pytest.mark.parametrize("prompt_of", ["hypothesis", "sigma"])
def test_the_prompts_carry_the_examples(prompt_of: str) -> None:
    cti = yaml.safe_load(GOLD.read_text(encoding="utf-8"))["source"]["cti"] + "\n" + VSHELL
    if prompt_of == "hypothesis":
        agent = HypothesisGeneratorAgent(llm_enabled=False)
        prompt = agent._build_prompt(HypothesisGenerationInput(threat_intel=cti, past_hunts=[], environment={}))
    else:
        agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
        prompt = agent._build_prompt(SigmaGenerationInput(hypothesis=VSHELL, platforms=["Windows"]), "process_creation")
    assert "HOW OS INTERNALS APPEAR IN TELEMETRY" in prompt
    assert "Win32 API calls (VirtualAlloc, VirtualProtect, CreateThread, Beep, AllocADsMem)" in prompt
