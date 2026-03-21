"""IOC Enrichment Agent: enriches each IOC from multiple intelligence sources."""

import json
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState, IOC
from soc_agent.tools.misp_tools import (
    misp_get_threat_details,
    misp_search_events,
    misp_add_sighting,
)
from soc_agent.tools.external_enrichment import (
    virustotal_lookup,
    abuseipdb_lookup,
    shodan_lookup,
)
from soc_agent.tools.mitre_attack import lookup_mitre_technique
from soc_agent.vector_store.retriever import retrieve_ioc_context

ENRICHMENT_SYSTEM_PROMPT = """You are an IOC Enrichment Specialist. For each IOC provided:

1. Query VirusTotal for reputation scores (IPs use ioc_type='ip', domains use 'domain', hashes use 'hash').
2. For IP addresses: query AbuseIPDB for abuse confidence score and Shodan for open ports/services.
3. Get full threat context from MISP using misp_get_threat_details.
4. Check if similar IOCs exist in the knowledge base using retrieve_ioc_context.
5. If an IOC is confirmed malicious (VT malicious ratio > 0.3 OR AbuseIPDB confidence > 50), note it.
6. For any MITRE technique IDs found in MISP data, look up details with lookup_mitre_technique.

After processing ALL IOCs, output a JSON block:
```json
{
  "enriched_iocs": [
    {
      "value": "185.220.101.45",
      "ioc_type": "ip-dst",
      "malicious": true,
      "confidence": 0.95,
      "enrichment_summary": "Known TOR exit node, VT 67/90 malicious, AbuseIPDB 98%",
      "mitre_techniques": ["T1071.004"],
      "enrichment_data": {
        "virustotal": {"malicious_ratio": 0.74},
        "abuseipdb": {"abuse_confidence": 98},
        "shodan": {"ports": [80, 443, 9050]},
        "misp": {"event_ids": ["42"], "threat_level": "1"}
      }
    }
  ]
}
```

Be thorough — each IOC should have a complete profile before you finish.
"""

ENRICHMENT_TOOLS = [
    misp_get_threat_details,
    misp_search_events,
    misp_add_sighting,
    virustotal_lookup,
    abuseipdb_lookup,
    shodan_lookup,
    lookup_mitre_technique,
    retrieve_ioc_context,
]


def _build_enrichment_agent():
    return create_react_agent(
        get_llm(),
        ENRICHMENT_TOOLS,
        prompt=ENRICHMENT_SYSTEM_PROMPT,
    )


def ioc_enrichment_node(state: SOCState) -> dict:
    """LangGraph node: enrich all extracted IOCs."""
    agent = _build_enrichment_agent()

    iocs = state.get("extracted_iocs", [])
    if not iocs:
        return {
            "enrichment_complete": True,
            "messages": [],
        }

    ioc_list_text = "\n".join(
        f"- {ioc.value} (type: {ioc.ioc_type}, confidence: {ioc.confidence})"
        for ioc in iocs
    )

    result = agent.invoke({
        "messages": [HumanMessage(
            content=f"Enrich the following IOCs:\n\n{ioc_list_text}"
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

    enriched_iocs = list(iocs)  # start from existing IOCs

    try:
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            parsed = json.loads(content[json_start:json_end])
            enriched_list = parsed.get("enriched_iocs", [])

            # Update existing IOCs with enrichment data
            enriched_map = {e["value"]: e for e in enriched_list}
            updated_iocs = []
            for ioc in enriched_iocs:
                if ioc.value in enriched_map:
                    e = enriched_map[ioc.value]
                    updated_iocs.append(IOC(
                        value=ioc.value,
                        ioc_type=ioc.ioc_type,
                        source=ioc.source,
                        confidence=e.get("confidence", ioc.confidence),
                        malicious=e.get("malicious", ioc.malicious),
                        enrichment_data=e.get("enrichment_data", {}),
                        misp_hit=e.get("enrichment_data", {}).get("misp"),
                        mitre_techniques=e.get("mitre_techniques", []),
                    ))
                else:
                    updated_iocs.append(ioc)
            enriched_iocs = updated_iocs
    except (json.JSONDecodeError, KeyError):
        pass

    return {
        "enrichment_complete": True,
        "extracted_iocs": enriched_iocs,
        "messages": result["messages"],
    }
