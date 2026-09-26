import os
import click
from rich.console import Console
from hecate_agent.orchestrator.graph import hecate_graph

console = Console()

@click.group()
def orchestrate() -> None:
    """LangGraph Agentic Orchestrator commands (Human-in-the-Loop)."""
    pass

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
