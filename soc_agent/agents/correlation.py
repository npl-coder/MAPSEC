"""Correlation Agent: synthesizes findings to detect campaigns and attribute threats."""

import json
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState, CorrelationResult
from soc_agent.tools.opensearch_tools import opensearch_aggregate
from soc_agent.tools.misp_tools import misp_search_events, misp_list_galaxy_clusters
from soc_agent.vector_store.retriever import (
    retrieve_similar_incidents,
    retrieve_threat_actor_profile,
    retrieve_ioc_context,
)

CORRELATION_SYSTEM_PROMPT = """You are a Threat Correlation Analyst. Your job is to synthesize ALL findings
from the Triage, Enrichment, and Threat Hunter agents to answer:

1. **Is this part of a campaign?** Correlate IOCs, techniques, and timing.
2. **Have we seen this before?** Use retrieve_similar_incidents and retrieve_ioc_context.
3. **Who is behind this?** Match TTPs to known threat actors using retrieve_threat_actor_profile.
4. **What's the full attack timeline?** Order all events chronologically.
5. **What's the blast radius?** Use opensearch_aggregate to find affected hosts/users.
6. **What MISP events are related?** Check for overlapping indicators.

Build an attack timeline and calculate a campaign confidence score (0.0-1.0).

Output a JSON block:
```json
{
  "correlation_summary": "This appears to be a Lazarus Group campaign...",
  "is_campaign": true,
  "campaign_confidence": 0.85,
  "threat_actor_attribution": "Lazarus Group",
  "attack_timeline": [
    {"timestamp": "2026-03-14T02:15:00Z", "event": "Initial connection from C2", "host": "10.0.0.50"},
    {"timestamp": "2026-03-14T02:17:00Z", "event": "Lateral movement via SMB", "host": "10.0.0.67"}
  ],
  "correlated_alert_ids": [],
  "similar_past_incidents": [{"incident_id": "...", "similarity": 0.91}],
  "kill_chain_mapping": {
    "initial_access": "External C2 connection",
    "lateral_movement": "SMB + PsExec",
    "command_and_control": "DNS tunneling"
  }
}
```
"""

CORRELATION_TOOLS = [
    opensearch_aggregate,
    misp_search_events,
    misp_list_galaxy_clusters,
    retrieve_similar_incidents,
    retrieve_threat_actor_profile,
    retrieve_ioc_context,
]


def _build_correlation_agent():
    return create_react_agent(
        get_llm(),
        CORRELATION_TOOLS,
        prompt=CORRELATION_SYSTEM_PROMPT,
    )


def correlation_node(state: SOCState) -> dict:
    """LangGraph node: correlate all findings into a coherent picture."""
    agent = _build_correlation_agent()

    # Compile context from all previous agent outputs
    context_parts = []

    context_parts.append(f"## Triage Summary\n{state.get('triage_summary', 'N/A')}")

    severity = state.get("severity")
    if severity:
        context_parts.append(f"Severity: {severity.level} ({severity.score})")

    iocs = state.get("extracted_iocs", [])
    if iocs:
        context_parts.append("\n## Enriched IOCs")
        for ioc in iocs:
            context_parts.append(
                f"- {ioc.value} (type={ioc.ioc_type}, malicious={ioc.malicious}, "
                f"confidence={ioc.confidence}, techniques={ioc.mitre_techniques})"
            )
            if ioc.enrichment_data:
                context_parts.append(f"  Enrichment: {json.dumps(ioc.enrichment_data, default=str)}")

    tc = state.get("threat_context")
    if tc:
        context_parts.append(f"\n## Threat Context")
        context_parts.append(f"MITRE techniques: {tc.mitre_techniques}")
        context_parts.append(f"Threat actors: {tc.threat_actors}")
        context_parts.append(f"Malware families: {tc.malware_families}")
        context_parts.append(f"Kill chain phase: {tc.kill_chain_phase}")
        context_parts.append(f"Summary: {tc.attack_summary}")

    os_hits = state.get("opensearch_hits", [])
    if os_hits:
        context_parts.append(f"\n## OpenSearch Findings ({len(os_hits)} key events)")
        for hit in os_hits[:10]:
            context_parts.append(f"- {json.dumps(hit, default=str)}")

    playbooks = state.get("retrieved_playbooks", [])
    if playbooks:
        context_parts.append(f"\n## Matched Playbooks: {playbooks}")

    result = agent.invoke({
        "messages": [HumanMessage(
            content=f"Correlate these investigation findings:\n\n{chr(10).join(context_parts)}"
        )]
    })

    last_msg = result["messages"][-1]
    raw_content = last_msg.content if isinstance(last_msg, AIMessage) else str(last_msg)
    if isinstance(raw_content, list):
        content = "\n".join(
            block.get("text", str(block)) if isinstance(block, dict) else str(block)
            for block in raw_content
        )
    else:
        content = raw_content

    correlation = None
    past_incidents = []

    try:
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            parsed = json.loads(content[json_start:json_end])
            correlation = CorrelationResult(
                pattern_description=parsed.get("correlation_summary", ""),
                is_campaign=parsed.get("is_campaign", False),
                campaign_confidence=parsed.get("campaign_confidence", 0.0),
                threat_actor_attribution=parsed.get("threat_actor_attribution", ""),
                attack_timeline=parsed.get("attack_timeline", []),
                correlated_alert_ids=parsed.get("correlated_alert_ids", []),
                similar_past_incidents=parsed.get("similar_past_incidents", []),
            )
            past_incidents = parsed.get("similar_past_incidents", [])
    except (json.JSONDecodeError, KeyError):
        pass

    return {
        "correlation_complete": True,
        "correlation": correlation,
        "retrieved_past_incidents": past_incidents,
        "messages": result["messages"],
    }
