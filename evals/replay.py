"""Replay one gold case through a real Runner cycle in a scratch workspace, then score the draft.

    cd ../Hecate-Runner
    .venv/bin/python ../Hecate-Core/evals/replay.py redis-cryptomining-botnet
    .venv/bin/python ../Hecate-Core/evals/replay.py vshell-fake-resume --workspace /tmp/gold-vshell --json score.json

Run it with the Runner's interpreter: it imports ``hecate_runner``. The item is
built from the case's saved OTX pulse (``evals/pulses/<case>.json``), so it
carries the feed's indicator list as a live cycle would, and its text is the
gold set's ``source.cti``. The file-queue recipe in ``evals/README.md`` passes
the text only.

Nothing outside the scratch workspace is written. The workspace is a blank
copy of this one (configuration, knowledge and templates, no hunts) and is
kept afterwards so the draft, rules and log can be read. The cycle fetches the
report the case links to and calls the workspace's configured model.
"""

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import yaml

CORE = Path(__file__).resolve().parents[1]
GOLD_DIR = CORE / "evals" / "gold"
PULSE_DIR = CORE / "evals" / "pulses"
#: What a blank workspace needs from this one.
WORKSPACE_FILES = (".hecate", ".hecateconfig.yaml", "knowledge", "templates", "AGENTS.md")


def cases() -> List[str]:
    return sorted(p.stem for p in GOLD_DIR.glob("*.yaml") if (PULSE_DIR / f"{p.stem}.json").exists())


def build_workspace(workspace: Path) -> None:
    """A blank copy of this workspace: its configuration, no hunts, research or rules."""
    for name in ("hunts", "research", "queries", "cti_queue", "logs"):
        (workspace / name).mkdir(parents=True, exist_ok=True)
    for name in WORKSPACE_FILES:
        source, target = CORE / name, workspace / name
        if not source.exists() or target.exists():
            continue
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    env = workspace / ".env"
    if (CORE / ".env").exists() and not env.exists():
        env.symlink_to(CORE / ".env")
    (workspace / "hunts" / ".hunt_id_counter").write_text("0\n")
    (workspace / "research" / ".research_id_counter").write_text('{\n  "R-": 0\n}')


def run_cycle(case: str, workspace: Path, runner: Path) -> Any:
    """One Runner cycle on the case's item; returns the Runner's result."""
    os.environ["HECATE_WORKSPACE"] = str(workspace)
    os.environ["HECATE_BIN"] = str(CORE / ".venv" / "bin" / "hecate-agent")
    os.chdir(runner)  # the Runner reads its settings from the .env beside it

    from hecate_runner.config import Settings
    from hecate_runner.cti.otx import _pulse_to_cti_item
    from hecate_runner.cti.single import SingleItemProvider
    from hecate_runner.hecate_client import HecateClient
    from hecate_runner.orchestrator import Orchestrator

    item = _pulse_to_cti_item(json.loads((PULSE_DIR / f"{case}.json").read_text()))
    item.content = yaml.safe_load((GOLD_DIR / f"{case}.yaml").read_text())["source"]["cti"].strip()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(workspace / "logs" / "orchestrator.log"), logging.StreamHandler(sys.stderr)],
    )
    for noisy in ("httpx", "httpcore", "LiteLLM", "litellm"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    settings = Settings()
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=SingleItemProvider(item)).run_once()


def score(case: str, draft: Path, queries: Path) -> Dict[str, Any]:
    from hecate_agent.core.gold_eval import load_gold, score_draft

    report: Dict[str, Any] = score_draft(load_gold(GOLD_DIR / f"{case}.yaml"), draft, queries).to_dict()
    return report


def summarise(case: str, report: Dict[str, Any]) -> str:
    recall = report["technique_recall"]
    lines = [
        f"{case}: {report['passed']}/{report['total']} checks, technique recall {recall['hits']}/{recall['denominator']}",
        "  " + ", ".join(f"{name} {d['passed']}/{d['total']}" for name, d in report["dimensions"].items()),
    ]
    for check in report["checks"]:
        if not check["passed"]:
            lines.append(f"  FAIL {check['dimension']} | {check['id']} | {(check.get('detail') or '')[:160]}")
    if report.get("unreviewed_techniques"):
        lines.append(f"  unreviewed techniques: {', '.join(report['unreviewed_techniques'])}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("case", choices=cases())
    parser.add_argument("--workspace", type=Path, help="scratch workspace to create (default: a new temporary directory)")
    parser.add_argument("--runner", type=Path, default=CORE.parent / "Hecate-Runner", help="the Hecate-Runner checkout")
    parser.add_argument("--json", type=Path, help="also write the full score report here")
    args = parser.parse_args()

    json_path = args.json.resolve() if args.json else None  # before the cycle changes directory
    workspace = (args.workspace or Path(tempfile.mkdtemp(prefix=f"hecate-gold-{args.case}-"))).resolve()
    if args.workspace and any((workspace / "hunts").glob("*/*/H-*.md")):
        parser.error(f"{workspace} already holds a drafted hunt; give a fresh directory")
    build_workspace(workspace)
    result = run_cycle(args.case, workspace, args.runner.resolve())
    print(f"workspace: {workspace}")
    print(f"result: {result.outcome} {result.hunt_id or ''}")
    if not result.draft_path:
        print("no draft was written; see logs/orchestrator.log in the workspace")
        return 1
    report = score(args.case, Path(result.draft_path), workspace / "queries" / str(result.hunt_id))
    if json_path:
        json_path.write_text(json.dumps(report, indent=1))
    print(f"draft: {result.draft_path}")
    print(summarise(args.case, report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
