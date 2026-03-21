"""Assemble and compile the LangGraph StateGraph for the SOC agent pipeline.

Architecture:
  START → supervisor → (conditional routing) → agent → supervisor → ... → END

The supervisor node decides which agent runs next. All agents report back
to the supervisor after each execution. The supervisor can loop agents
(e.g., re-run enrichment after hunting reveals new IOCs).
"""

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from soc_agent.graph.state import SOCState
from soc_agent.graph.supervisor import supervisor_node
from soc_agent.agents.triage import triage_node
from soc_agent.agents.ioc_enrichment import ioc_enrichment_node
from soc_agent.agents.threat_hunter import threat_hunter_node
from soc_agent.agents.correlation import correlation_node
from soc_agent.agents.reporting import reporting_node


def _route_from_supervisor(state: SOCState) -> str:
    """Read the supervisor's routing decision from state."""
    next_agent = state.get("next_agent", "END")
    if next_agent == "END":
        return END
    return next_agent


def build_soc_graph(checkpointer=None):
    """Build and compile the SOC investigation graph.

    Args:
        checkpointer: LangGraph checkpointer for session persistence.
                      Defaults to MemorySaver (in-process).

    Returns:
        Compiled StateGraph ready for invocation.
    """
    builder = StateGraph(SOCState)

    # Register all nodes
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("triage", triage_node)
    builder.add_node("ioc_enrichment", ioc_enrichment_node)
    builder.add_node("threat_hunter", threat_hunter_node)
    builder.add_node("correlation", correlation_node)
    builder.add_node("reporting", reporting_node)

    # Entry point: always start with supervisor
    builder.add_edge(START, "supervisor")

    # Supervisor routes to the next agent (or END)
    builder.add_conditional_edges(
        "supervisor",
        _route_from_supervisor,
        {
            "triage": "triage",
            "ioc_enrichment": "ioc_enrichment",
            "threat_hunter": "threat_hunter",
            "correlation": "correlation",
            "reporting": "reporting",
            END: END,
        },
    )

    # All agents report back to supervisor after execution
    for agent_name in ["triage", "ioc_enrichment", "threat_hunter", "correlation", "reporting"]:
        builder.add_edge(agent_name, "supervisor")

    # Compile with checkpointer for session memory
    if checkpointer is None:
        checkpointer = MemorySaver()

    return builder.compile(checkpointer=checkpointer)
