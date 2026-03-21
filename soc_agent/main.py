"""MAPSEC SOC Agent — CLI entry point.

Usage:
    python -m soc_agent.main investigate alerts/sample_alert.json --verbose
    python -m soc_agent.main ingest           # ingest playbooks + threat actor profiles
    python -m soc_agent.main chat <thread-id> # resume an investigation interactively
"""

import json
import uuid
import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from soc_agent.graph.state import SOCState, Alert

app = typer.Typer(
    name="mapsec-soc",
    help="MAPSEC Multi-Agent SOC Analyst — investigate security alerts with AI.",
)
console = Console()


def _build_graph():
    """Build the LangGraph pipeline (lazy import to keep CLI fast)."""
    from soc_agent.graph.graph_builder import build_soc_graph
    return build_soc_graph()


@app.command()
def investigate(
    alert_file: str = typer.Argument(..., help="Path to JSON alert file"),
    thread_id: str = typer.Option(None, "--thread-id", "-t", help="Resume existing investigation"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show agent-level details"),
):
    """Investigate a security alert using the multi-agent SOC pipeline."""
    investigation_id = thread_id or str(uuid.uuid4())[:12]

    # Load alert
    try:
        with open(alert_file) as f:
            raw_data = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to load alert file: {e}[/red]")
        raise typer.Exit(1)

    alert = Alert(
        alert_id=raw_data.get("id", str(uuid.uuid4())[:8]),
        source=raw_data.get("source", "manual"),
        raw_data=raw_data.get("data", raw_data),
        timestamp=raw_data.get("timestamp", ""),
        description=raw_data.get("description", ""),
    )

    initial_state: SOCState = {
        "messages": [],
        "raw_alert": alert,
        "severity": None,
        "triage_complete": False,
        "triage_summary": "",
        "extracted_iocs": [],
        "enrichment_complete": False,
        "threat_context": None,
        "opensearch_hits": [],
        "hunt_complete": False,
        "correlation": None,
        "correlation_complete": False,
        "retrieved_playbooks": [],
        "retrieved_past_incidents": [],
        "final_report": None,
        "misp_event_id": None,
        "report_complete": False,
        "iteration_count": 0,
        "next_agent": "",
        "error_log": [],
        "investigation_id": investigation_id,
    }

    config = {"configurable": {"thread_id": investigation_id}}

    console.print(Panel(
        f"[bold]Investigation: {investigation_id}[/bold]\n"
        f"Alert: {alert.alert_id} | Source: {alert.source}",
        title="MAPSEC SOC Agent",
        border_style="cyan",
    ))

    graph = _build_graph()

    # Stream events for real-time visibility
    for event in graph.stream(initial_state, config=config, stream_mode="updates"):
        node_name = list(event.keys())[0]
        node_data = event[node_name]

        if node_name == "supervisor":
            next_ag = node_data.get("next_agent", "?")
            iteration = node_data.get("iteration_count", 0)
            if next_ag == "END":
                console.print(f"  [dim]Supervisor (iter {iteration}): Investigation complete[/dim]")
            else:
                console.print(f"  [cyan]Supervisor (iter {iteration}): → {next_ag}[/cyan]")
        else:
            status_parts = []
            if node_name == "triage" and node_data.get("severity"):
                sev = node_data["severity"]
                status_parts.append(f"Severity: {sev.level} ({sev.score})")
                ioc_count = len(node_data.get("extracted_iocs", []))
                status_parts.append(f"IOCs: {ioc_count}")
            elif node_name == "ioc_enrichment":
                iocs = node_data.get("extracted_iocs", [])
                confirmed = sum(1 for i in iocs if i.malicious)
                status_parts.append(f"Enriched {len(iocs)} IOCs ({confirmed} confirmed malicious)")
            elif node_name == "threat_hunter":
                hits = len(node_data.get("opensearch_hits", []))
                status_parts.append(f"{hits} key findings in logs")
            elif node_name == "correlation":
                corr = node_data.get("correlation")
                if corr:
                    status_parts.append(
                        f"Campaign: {'Yes' if corr.is_campaign else 'No'} "
                        f"(confidence: {corr.campaign_confidence:.0%})"
                    )
            elif node_name == "reporting":
                status_parts.append(f"MISP Event: {node_data.get('misp_event_id', 'N/A')}")

            status = " | ".join(status_parts) if status_parts else "done"
            console.print(f"  [green]{node_name}[/green]: {status}")

            if verbose and node_data.get("messages"):
                for msg in node_data["messages"][-2:]:
                    if hasattr(msg, "content") and msg.content:
                        text = msg.content[:300]
                        console.print(f"    [dim]{text}...[/dim]" if len(msg.content) > 300 else f"    [dim]{text}[/dim]")

    # Print final report
    final_state = graph.get_state(config)
    report = final_state.values.get("final_report")
    if report:
        console.print()
        console.print(Panel(Markdown(report), title="Incident Report", border_style="green"))
    else:
        console.print("[yellow]No final report was generated.[/yellow]")

    misp_id = final_state.values.get("misp_event_id")
    if misp_id:
        console.print(f"\n[bold green]MISP Event ID: {misp_id}[/bold green]")

    errors = final_state.values.get("error_log", [])
    if errors:
        console.print(f"\n[yellow]Errors during investigation:[/yellow]")
        for err in errors:
            console.print(f"  - {err}")


@app.command()
def ingest():
    """Ingest playbooks and threat actor profiles into the vector database."""
    from soc_agent.vector_store.ingestion import ingest_all

    console.print("[cyan]Ingesting data into ChromaDB...[/cyan]")
    counts = ingest_all()
    for collection, count in counts.items():
        console.print(f"  {collection}: {count} documents")
    console.print("[green]Ingestion complete.[/green]")


@app.command()
def chat(
    thread_id: str = typer.Argument(..., help="Investigation thread ID to continue"),
):
    """Interactively ask follow-up questions about an existing investigation."""
    from langchain_core.messages import HumanMessage

    graph = _build_graph()
    config = {"configurable": {"thread_id": thread_id}}

    # Check if the investigation exists
    state = graph.get_state(config)
    if not state.values:
        console.print(f"[red]No investigation found with thread ID: {thread_id}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Resuming investigation: {thread_id}[/cyan]")
    console.print("[dim]Type 'quit' to exit. Ask any question about the investigation.[/dim]\n")

    while True:
        question = console.input("[bold]You:[/bold] ")
        if question.strip().lower() in ("quit", "exit", "q"):
            break

        # Add the question to the investigation state and re-run
        graph.update_state(
            config,
            {"messages": [HumanMessage(content=question)]},
        )

        for event in graph.stream(None, config=config, stream_mode="updates"):
            node_name = list(event.keys())[0]
            if node_name != "supervisor":
                console.print(f"  [green]{node_name}[/green]: processing...")

        final_state = graph.get_state(config)
        messages = final_state.values.get("messages", [])
        if messages:
            last = messages[-1]
            if hasattr(last, "content"):
                console.print(f"\n[bold]Agent:[/bold] {last.content}\n")


if __name__ == "__main__":
    app()
