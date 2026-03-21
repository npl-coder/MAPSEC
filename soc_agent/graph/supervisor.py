"""Supervisor node: manages agent routing and can override default pipeline order.

The supervisor inspects the current state and decides which agent should run next.
It uses a combination of deterministic flag checks (default pipeline) and an LLM
call to handle edge cases (e.g., re-running enrichment after new IOCs are found).
"""

import json
from langchain_core.messages import SystemMessage, HumanMessage
from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState
from soc_agent.config.settings import settings


def supervisor_node(state: SOCState) -> dict:
    """LangGraph node: decide what to do next.

    The supervisor increments the iteration counter, checks for completion,
    and optionally consults the LLM for complex routing decisions.
    """
    iteration = state.get("iteration_count", 0) + 1

    # Hard guard against infinite loops
    if iteration > settings.MAX_ITERATIONS:
        return {
            "iteration_count": iteration,
            "next_agent": "END",
            "error_log": [f"Max iterations ({settings.MAX_ITERATIONS}) reached — forcing END."],
        }

    # Determine default next agent based on pipeline completion flags
    default_next = _get_default_next(state)

    # For straightforward cases, skip the LLM call entirely
    if default_next in ("triage", "END"):
        return {
            "iteration_count": iteration,
            "next_agent": default_next,
        }

    # For later stages, use the LLM to review progress and potentially override
    override = _llm_review(state, default_next, iteration)

    return {
        "iteration_count": iteration,
        "next_agent": override or default_next,
    }


def _get_default_next(state: SOCState) -> str:
    """Deterministic pipeline: triage → enrichment → hunt → correlation → reporting → END."""
    if not state.get("triage_complete"):
        return "triage"
    if not state.get("enrichment_complete"):
        return "ioc_enrichment"
    if not state.get("hunt_complete"):
        return "threat_hunter"
    if not state.get("correlation_complete"):
        return "correlation"
    if not state.get("report_complete"):
        return "reporting"
    return "END"


def _llm_review(state: SOCState, default_next: str, iteration: int) -> str | None:
    """Ask the LLM if the default route is correct or if we should loop back.

    Returns None to accept default, or an agent name to override.
    """
    try:
        llm = get_llm()

        status_summary = (
            f"Iteration: {iteration}/{settings.MAX_ITERATIONS}\n"
            f"Triage: {'done' if state.get('triage_complete') else 'pending'}\n"
            f"Enrichment: {'done' if state.get('enrichment_complete') else 'pending'}\n"
            f"Threat Hunt: {'done' if state.get('hunt_complete') else 'pending'}\n"
            f"Correlation: {'done' if state.get('correlation_complete') else 'pending'}\n"
            f"Report: {'done' if state.get('report_complete') else 'pending'}\n"
            f"IOCs found: {len(state.get('extracted_iocs', []))}\n"
            f"OpenSearch hits: {len(state.get('opensearch_hits', []))}\n"
            f"Errors: {state.get('error_log', [])}\n"
            f"Default next agent: {default_next}"
        )

        severity = state.get("severity")
        if severity:
            status_summary += f"\nSeverity: {severity.level} ({severity.score})"

        response = llm.invoke([
            SystemMessage(content=(
                "You are the SOC investigation supervisor. Review the investigation status below. "
                "Respond with ONLY a JSON object: "
                '{"next_agent": "<agent_name>", "reason": "<brief reason>"}. '
                "Valid agents: triage, ioc_enrichment, threat_hunter, correlation, reporting, END. "
                "Usually accept the default. Override ONLY if: "
                "1) The threat hunter found new IOCs that need enrichment → ioc_enrichment "
                "2) Enrichment revealed a critical finding that changes the hunt scope → threat_hunter "
                "3) Investigation is stuck with errors → END "
                "If the default is fine, return it unchanged."
            )),
            HumanMessage(content=status_summary),
        ])

        text = response.content.strip()
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            parsed = json.loads(text[json_start:json_end])
            override = parsed.get("next_agent", "")
            if override in ("triage", "ioc_enrichment", "threat_hunter", "correlation", "reporting", "END"):
                if override != default_next:
                    return override
    except Exception:
        pass  # If LLM fails, just use the default route

    return None
