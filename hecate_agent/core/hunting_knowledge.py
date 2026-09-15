"""Feed `knowledge/hunting-knowledge.md` into the agents that need it.

The knowledge base is the project's "brain": five sections of hunting
tradecraft, and it states its own routing in *Using This Knowledge Base* --
Sections 1, 2 and 5 before generating a hypothesis, Section 3 for pivots,
Section 4 for analytical rigour. Nothing was reading it. It reached the AI
context export and the MCP search tools and stopped there, so 95 KB of
tradecraft never influenced a draft.

It is too large to pass whole: the three hypothesis-stage sections alone are
63 KB, which would crowd out the CTI on a local model. So sections are
selected per agent and truncated to a budget, on a heading boundary rather
than mid-sentence, and the prompt is told when that has happened -- a model
handed a knowledge base cut off mid-example should know it is partial.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from hecate_agent.core.workspace import knowledge_file

#: Off by default, and deliberately so.
#:
#: Wiring the knowledge base in is correct -- the document states its own
#: routing and nothing was reading it -- but injecting it at the hypothesis
#: stage measurably degraded output. Given Linux Redis cryptomining CTI, the
#: model returned "Adversaries use PowerShell to download and execute
#: malicious scripts", with `T1059.004` (Unix Shell) under a PowerShell
#: hypothesis and no mention of Redis, cron or XMRig.
#:
#: The cause is proximity, not size. The agent is asked to emit a hypothesis
#: in a fixed schema and handed 12 KB of well-formed example hypotheses --
#: 'Good: "PowerShell downloads from temp directories..."' -- so it copies
#: the nearest one. Trimming the budget lowers the odds without changing the
#: shape of the mistake, and the examples cannot simply be stripped: Section
#: 2 *is* a TTP-to-observable catalogue, and Section 1 teaches through
#: Good/Bad pairs.
#:
#: It is also not measurable yet. While research runs ungrounded (G7) and the
#: estate profile is still the template (G1), no change in output can be
#: attributed to this. Revisit once both are fixed, then compare the same CTI
#: with the flag on and off.
_ENABLE_ENV_VAR = "HECATE_HUNTING_KNOWLEDGE"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_enabled() -> bool:
    """Whether tradecraft should be injected into agent prompts."""
    return os.environ.get(_ENABLE_ENV_VAR, "").strip().lower() in _TRUTHY


_FILENAME = "hunting-knowledge.md"

#: Section number -> the heading it appears under. Numbers rather than full
#: titles so a wording change in the document does not silently unwire an
#: agent; the number is the stable part.
_SECTION_PREFIX = "Section {n}:"

#: What each stage of the pipeline is told to read, per the knowledge base's
#: own "Using This Knowledge Base" section.
HYPOTHESIS_SECTIONS = (1, 2, 5)
RESEARCH_SECTIONS = (4, 5)
PIVOT_SECTIONS = (3,)


def _split_sections(text: str) -> Dict[int, str]:
    """Map section number -> that section's text, including its heading."""
    sections: Dict[int, str] = {}
    for match in re.finditer(r"^## (Section (\d+):[^\n]*)\n", text, re.M):
        number = int(match.group(2))
        start = match.start()
        following = re.search(r"^## ", text[match.end() :], re.M)
        end = match.end() + following.start() if following else len(text)
        sections[number] = text[start:end].rstrip()
    return sections


def _truncate_on_heading(text: str, max_chars: int) -> str:
    """Cut to a budget at the last subheading that fits, not mid-sentence."""
    if len(text) <= max_chars:
        return text
    window = text[:max_chars]
    last_heading = window.rfind("\n###")
    if last_heading > max_chars // 2:
        window = window[:last_heading]
    return window.rstrip()


def load_sections(
    numbers: Sequence[int],
    max_chars: int,
    *,
    workspace: Optional[Path] = None,
) -> str:
    """Selected sections of the knowledge base, within a character budget.

    Returns "" when the file is absent -- callers omit the block entirely
    rather than telling the model about knowledge it was not given.
    """
    path = knowledge_file(_FILENAME, workspace)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""

    available = _split_sections(text)
    wanted = [available[n] for n in numbers if n in available]
    if not wanted:
        return ""

    # Share the budget evenly, then let earlier sections use what later ones
    # did not need -- Section 1 is the densest and is listed first.
    per_section = max(max_chars // len(wanted), 800)
    parts: List[str] = []
    spent = 0
    for section in wanted:
        room = min(per_section + (max_chars - spent - per_section * (len(wanted) - len(parts))), max_chars - spent)
        room = max(room, 0)
        if room < 400:
            break
        rendered = _truncate_on_heading(section, room)
        parts.append(rendered)
        spent += len(rendered)

    body = "\n\n".join(parts)
    if len(body) < sum(len(s) for s in wanted):
        body += "\n\n[Knowledge base excerpted to fit this prompt; sections above may be partial.]"
    return body
