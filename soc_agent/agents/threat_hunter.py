"""Threat Hunter Agent: hunts through OpenSearch logs for related activity."""

import json
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState, ThreatContext
from soc_agent.tools.opensearch_tools import (
    opensearch_search_logs,
    opensearch_aggregate,
    opensearch_list_indices,
)
from soc_agent.tools.misp_tools import misp_get_event_galaxies, misp_search_events
from soc_agent.tools.mitre_attack import lookup_mitre_technique
from soc_agent.vector_store.retriever import retrieve_similar_incidents

THREAT_HUNTER_SYSTEM_PROMPT = """You are a Threat Hunter. Given enriched IOCs and alert context:

1. First, list available OpenSearch indices using opensearch_list_indices to understand what data is available.
2. Formulate targeted OpenSearch queries to find related log activity.
   - Search for IOC values (IPs, domains, hashes) across relevant indices.
   - Search across multiple time windows: 1h, 24h, 7d as needed.
3. Look for lateral movement patterns: same source IP across multiple destinations.
4. Look for persistence indicators: scheduled tasks, service creation, registry modifications.
5. Use opensearch_aggregate to find top talking IPs, most-hit ports, unusual user-agents.
6. Check MISP for related events and MITRE ATT&CK galaxy mappings.
7. Retrieve similar past incidents from the knowledge base.

After investigation, output a JSON block:
```json
{
  "hunt_summary": "Description of what was found in the logs",
  "opensearch_hit_count": 1247,
  "affected_hosts": ["10.0.0.50", "10.0.0.67"],
  "threat_context": {
    "mitre_techniques": ["T1021.002", "T1071.004"],
    "threat_actors": ["Lazarus Group"],
    "malware_families": [],
    "kill_chain_phase": "lateral-movement",
    "attack_summary": "Lateral movement via SMB from external C2"
  },
  "key_findings": [
    {"timestamp": "...", "description": "...", "source_index": "..."}
  ]
}
```

Document ALL log evidence with timestamps and source index names.
"""

THREAT_HUNTER_TOOLS = [
    opensearch_search_logs,
    opensearch_aggregate,
    opensearch_list_indices,
    misp_get_event_galaxies,
    misp_search_events,
    lookup_mitre_technique,
    retrieve_similar_incidents,
]


def _build_threat_hunter_agent():
    return create_react_agent(
        get_llm(),
        THREAT_HUNTER_TOOLS,
        prompt=THREAT_HUNTER_SYSTEM_PROMPT,
    )


def threat_hunter_node(state: SOCState) -> dict:
    """LangGraph node: hunt across logs for threat activity."""
    agent = _build_threat_hunter_agent()

    # Build context from previous agents' findings
    iocs = state.get("extracted_iocs", [])
    triage_summary = state.get("triage_summary", "")
    severity = state.get("severity")

    context_parts = [f"Triage Summary: {triage_summary}"]
    if severity:
        context_parts.append(f"Severity: {severity.level} ({severity.score})")

    if iocs:
        context_parts.append("\nEnriched IOCs:")
        for ioc in iocs:
            parts = [f"  - {ioc.value} (type: {ioc.ioc_type})"]
            if ioc.malicious is not None:
                parts.append(f"malicious={ioc.malicious}")
            if ioc.enrichment_data:
                parts.append(f"enrichment={json.dumps(ioc.enrichment_data, default=str)}")
            context_parts.append(" ".join(parts))

    alert = state["raw_alert"]
    context_parts.append(f"\nOriginal alert data:\n{json.dumps(alert.raw_data, indent=2, default=str)}")

    result = agent.invoke({
        "messages": [HumanMessage(
            content=f"Hunt for threat activity based on these findings:\n\n{'chr(10)'.join(context_parts)}"
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

    threat_context = None
    opensearch_hits = []

    try:
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            parsed = json.loads(content[json_start:json_end])

            tc_data = parsed.get("threat_context", {})
            threat_context = ThreatContext(
                mitre_techniques=tc_data.get("mitre_techniques", []),
                threat_actors=tc_data.get("threat_actors", []),
                malware_families=tc_data.get("malware_families", []),
                kill_chain_phase=tc_data.get("kill_chain_phase"),
                attack_summary=tc_data.get("attack_summary", ""),
            )

            opensearch_hits = parsed.get("key_findings", [])
    except (json.JSONDecodeError, KeyError):
        pass

    return {
        "hunt_complete": True,
        "threat_context": threat_context,
        "opensearch_hits": opensearch_hits,
        "messages": result["messages"],
    }
