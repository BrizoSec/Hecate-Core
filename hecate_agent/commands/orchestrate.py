import os
import click
from rich.console import Console
from hecate_agent.orchestrator.graph import hecate_graph

console = Console()

@click.group()
def orchestrate() -> None:
    """EXPERIMENTAL: a LangGraph drafting graph with a human approval step.

    This is not the pipeline the scheduled Runner uses and it is not scored
    against the gold cases: it has no source evidence, claim audit, platform
    scoping or rule review. To draft a hunt from intelligence you supply
    through the evaluated pipeline, use `hecate-runner draft`.
    """
    pass


_EXPERIMENTAL_NOTE = (
    "[yellow]Experimental:[/yellow] this graph is not the evaluated pipeline. "
    "Use [bold]hecate-runner draft[/bold] for a hunt drafted the way scheduled ones are."
)

@orchestrate.command()
@click.option('--topic', required=True, help="Hunt topic (e.g., 'PowerShell Downloads')")
@click.option('--threat-intel', required=True, help="Threat intelligence text or file path")
@click.option('--thread-id', required=True, help="Unique ID for this hunt thread")
@click.option('--workspace', type=click.Path(exists=True), help="Path to workspace")
def start(topic: str, threat_intel: str, thread_id: str, workspace: str) -> None:
    """Start a new agentic hunt."""
    config = {"configurable": {"thread_id": thread_id}}
    
    if os.path.exists(threat_intel):
        with open(threat_intel, 'r') as f:
            threat_intel = f.read()

    initial_state = {
        "topic": topic,
        "threat_intel": threat_intel,
        "workspace_path": workspace,
    }
    
    console.print(_EXPERIMENTAL_NOTE)
    console.print(f"[bold green]Starting Agentic Pipeline for Thread:[/bold green] {thread_id}")
    for event in hecate_graph.stream(initial_state, config=config):
        for key in event.keys():
            console.print(f"✅ Node [bold cyan]{key}[/bold cyan] completed.")
            
    state = hecate_graph.get_state(config)
    if state.next:
        console.print(f"\n[bold yellow]Pipeline paused! Waiting on human approval for node:[/bold yellow] {state.next}")
        console.print(f"Run `hecate-agent orchestrate resume --thread-id {thread_id}` to review and approve.")
    else:
        console.print("[bold green]Pipeline finished successfully![/bold green]")

@orchestrate.command()
@click.option('--thread-id', required=True, help="Unique ID for this hunt thread")
def resume(thread_id: str) -> None:
    """Review paused state and approve to resume."""
    config = {"configurable": {"thread_id": thread_id}}
    state = hecate_graph.get_state(config)
    
    if not state.next:
        console.print(f"[bold red]Thread {thread_id} is not currently paused or does not exist.[/bold red]")
        return
        
    console.print(f"\n[bold yellow]--- PENDING APPROVAL FOR: {state.next} ---[/bold yellow]")
    
    hypothesis = state.values.get("hypothesis")
    if hypothesis:
        console.print("\n[bold]Current Hypothesis:[/bold]")
        console.print(hypothesis)
    
    choice = click.prompt(
        "\nDo you want to (A)pprove, (E)dit Hypothesis, or (R)eject?", 
        type=click.Choice(['A', 'E', 'R'], case_sensitive=False)
    )
    
    if choice.upper() == 'E':
        new_text = click.edit(hypothesis)
        if new_text:
            hecate_graph.update_state(config, {"hypothesis": new_text})
            console.print("[green]Hypothesis updated![/green]")
        else:
            console.print("[yellow]Edit cancelled. Proceeding with original...[/yellow]")
            
    elif choice.upper() == 'R':
        console.print("[red]Hunt rejected. Canceling pipeline.[/red]")
        return
        
    console.print("\n[bold green]Approving and Resuming Pipeline...[/bold green]")
    for event in hecate_graph.stream(None, config=config):
        for key in event.keys():
            console.print(f"✅ Node [bold cyan]{key}[/bold cyan] completed.")
            
    console.print("[bold green]Pipeline finished successfully![/bold green]")

@orchestrate.command()
def inbox() -> None:
    """List all agentic hunts waiting for human approval."""
    import sqlite3
    db_path = "hecate_checkpoints.sqlite"
    if not os.path.exists(db_path):
        console.print("[yellow]No LangGraph database found. The inbox is empty.[/yellow]")
        return
        
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        # Checkpoints table tracks the state of every thread
        c.execute("SELECT DISTINCT thread_id FROM checkpoints")
        threads = [row[0] for row in c.fetchall()]
    except Exception as e:
        console.print(f"[red]Could not query database: {e}[/red]")
        return
        
    pending_count = 0
    console.print("\n[bold cyan]=== HUMAN-IN-THE-LOOP INBOX ===[/bold cyan]")
    
    for thread_id in threads:
        config = {"configurable": {"thread_id": thread_id}}
        state = hecate_graph.get_state(config)
        
        # If it has a 'next' step, it is paused!
        if state.next:
            pending_count += 1
            topic = state.values.get("topic", "Unknown Topic")
            console.print(f"📌 [bold yellow]{thread_id}[/bold yellow] - {topic}")
            console.print(f"   Waiting at Node: [magenta]{state.next[0]}[/magenta]")
            console.print(f"   Command: [dim]hecate-agent orchestrate resume --thread-id '{thread_id}'[/dim]\n")
            
    if pending_count == 0:
        console.print("[green]Your inbox is empty! All hunts are fully processed.[/green]\n")
    else:
        console.print(f"[bold]{pending_count} hunt(s) require your approval.[/bold]\n")
