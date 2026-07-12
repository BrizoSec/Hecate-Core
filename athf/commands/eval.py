"""Model-quality eval harness CLI — scripted known-answer spot checks.

Replaces manually asking a model "what is T1003.001?" and eyeballing the
answer with a repeatable command, so a model swap (or provider swap) can be
checked for confident hallucination before it goes into production.
"""

import json
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

console = Console()

EVAL_EPILOG = """
\b
Examples:
  # Eval the currently configured provider/model
  athf eval

  # Eval a specific model without changing your .env
  athf eval --provider ollama --model qwen2.5:14b-instruct-q4_K_M

  # Compare two models by running each and diffing the score
  athf eval --model qwen2.5:7b-instruct-q4_K_M --output json > 7b.json
  athf eval --model qwen2.5:14b-instruct-q4_K_M --output json > 14b.json

  # Isolate "does the model know this fact" from "can it use a fact it's
  # handed" — grounds the same technique fixtures with real STIX data
  # instead of asking the model to recall them cold
  athf eval --grounded

\b
What it checks:
  A small set of unambiguous, known-answer fixtures (mostly MITRE ATT&CK
  technique-ID recall) that catch confident hallucination — e.g. a model
  answering "System Information Discovery" for T1003.001 instead of
  "OS Credential Dumping: LSASS Memory". Not a general capability benchmark.
"""


@click.command(name="eval", epilog=EVAL_EPILOG)
@click.option("--provider", help="Override the configured LLM provider (e.g. ollama, litellm, bedrock)")
@click.option("--model", help="Override the configured model")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option(
    "--temperature",
    type=float,
    default=0.0,
    help="Sampling temperature. Defaults to 0.0 (deterministic) so results are reproducible run to run.",
)
@click.option(
    "--grounded",
    is_flag=True,
    help=(
        "Test STIX-grounded MITRE technique fixtures instead of cold recall — hands the model "
        "the real technique name/description and asks it to summarize, instead of asking it to "
        "recall the fact unaided. Separates 'does the model know this' from 'can it use a fact "
        "it's given', which points at whether to fix retrieval/prompting vs. chase a bigger model."
    ),
)
def eval_cmd(
    provider: Optional[str], model: Optional[str], output_format: str, temperature: float, grounded: bool
) -> None:
    """Run known-answer fixtures against an LLM provider and score the result."""
    from athf.core.eval_harness import build_grounded_fixtures, run_eval
    from athf.core.llm_provider import create_provider

    config = {}
    if provider:
        config["provider"] = provider
    if model:
        config["model"] = model

    try:
        llm_provider = create_provider(config or None)
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]Could not create LLM provider: {exc}[/red]")
        raise click.Abort()

    fixtures = build_grounded_fixtures() if grounded else None

    if output_format == "table":
        mode = "grounded (STIX-fed)" if grounded else "cold recall"
        console.print(
            f"\n[bold cyan]Running eval:[/bold cyan] {llm_provider.provider_name} / "
            f"{getattr(llm_provider, 'model', 'unknown')} [dim]({mode})[/dim]"
        )
        console.print("[dim]This makes one LLM call per fixture — may take a few minutes on a local model.[/dim]\n")

    report = run_eval(llm_provider, fixtures=fixtures, temperature=temperature)

    if output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2), soft_wrap=True)
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Fixture", style="cyan", no_wrap=True)
    table.add_column("Category", style="dim")
    table.add_column("Result")
    table.add_column("Duration", justify="right", style="dim")
    table.add_column("Notes", style="dim")

    for r in report.results:
        result_str = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        notes = r.error or (r.response_text[:60] + "..." if len(r.response_text) > 60 else r.response_text)
        table.add_row(r.fixture.id, r.fixture.category, result_str, f"{r.duration_ms / 1000:.1f}s", notes)

    console.print(table)
    console.print(
        f"\n[bold]Score:[/bold] {report.passed_count}/{report.total_count} "
        f"({report.score * 100:.0f}%)  [dim]({report.total_duration_ms / 1000:.1f}s total)[/dim]"
    )

    if report.score < 1.0:
        console.print("\n[yellow]Failed fixtures:[/yellow]")
        for r in report.results:
            if not r.passed:
                console.print(f"  [red]✗[/red] {r.fixture.id} ({r.fixture.description})")
                if r.error:
                    console.print(f"      error: {r.error}")
                else:
                    console.print(f"      got: {r.response_text[:150]}")
