"""Triage Agent: classifies alerts, extracts IOCs, scores severity, retrieves playbooks."""

import json
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState, IOC, SeverityScore
from soc_agent.tools.misp_tools import misp_search_attribute, misp_search_ip
from soc_agent.tools.utility_tools import extract_iocs_from_text, compute_severity_score
from soc_agent.tools.mitre_attack import map_text_to_mitre_techniques
from soc_agent.vector_store.retriever import retrieve_playbook

TRIAGE_SYSTEM_PROMPT = """You are a SOC Triage Analyst — the first responder for security alerts.

Your job:
1. Read the raw alert data carefully.
2. Use extract_iocs_from_text to pull all IOCs (IPs, domains, hashes, URLs) from the alert.
3. For each extracted IOC, check it against MISP using misp_search_attribute or misp_search_ip.
4. Map the alert context to MITRE ATT&CK techniques using map_text_to_mitre_techniques.
5. Retrieve the most relevant SOC response playbook using retrieve_playbook.
6. Compute a severity score using compute_severity_score based on MISP hits and MITRE mapping.

At the end, output a JSON block with this structure:
```json
{
  "triage_summary": "Brief description of what this alert is about",
  "extracted_iocs": [{"value": "...", "ioc_type": "ip-dst", "confidence": 0.5, "malicious": null}],
  "severity": {"score": 7.5, "level": "HIGH", "factors": [...], "recommended_action": "..."},
  "mitre_techniques": ["T1021.002"],
  "playbook_name": "lateral_movement"
}
```

Be thorough but efficient. Do NOT investigate further — leave deep analysis for other agents.
"""

TRIAGE_TOOLS = [
    extract_iocs_from_text,
    misp_search_attribute,
    misp_search_ip,
    compute_severity_score,
    map_text_to_mitre_techniques,
    retrieve_playbook,
]


def _build_triage_agent():
    return create_react_agent(
        get_llm(),
        TRIAGE_TOOLS,
        prompt=TRIAGE_SYSTEM_PROMPT,
    )


def triage_node(state: SOCState) -> dict:
    """LangGraph node: run the triage agent on the raw alert."""
    agent = _build_triage_agent()

    alert = state["raw_alert"]
    alert_text = (
        f"Alert ID: {alert.alert_id}\n"
        f"Source: {alert.source}\n"
        f"Timestamp: {alert.timestamp}\n"
        f"Description: {alert.description}\n"
        f"Raw data:\n{json.dumps(alert.raw_data, indent=2, default=str)}"
    )

    result = agent.invoke({
        "messages": [HumanMessage(content=f"Triage this alert:\n\n{alert_text}")]
    })

    # Extract structured output from the last AI message
    last_msg = result["messages"][-1]
    raw_content = last_msg.content if isinstance(last_msg, AIMessage) else str(last_msg)
    # Some LLMs (e.g. Gemini) return content as a list of blocks — flatten to string
    if isinstance(raw_content, list):
        content = "\n".join(
            block.get("text", str(block)) if isinstance(block, dict) else str(block)
            for block in raw_content
        )
    else:
        content = raw_content

    # Try to parse structured JSON from the response
    iocs = []
    severity = None
    triage_summary = content
    playbooks = []

    try:
        # Find JSON block in the response
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            parsed = json.loads(content[json_start:json_end])
            triage_summary = parsed.get("triage_summary", content[:500])

            for ioc_data in parsed.get("extracted_iocs", []):
                iocs.append(IOC(
                    value=ioc_data.get("value", ""),
                    ioc_type=ioc_data.get("ioc_type", "unknown"),
                    source="triage",
                    confidence=ioc_data.get("confidence", 0.5),
                    malicious=ioc_data.get("malicious"),
                ))

            sev_data = parsed.get("severity", {})
            if sev_data:
                severity = SeverityScore(
                    score=sev_data.get("score", 5.0),
                    level=sev_data.get("level", "MEDIUM"),
                    factors=sev_data.get("factors", []),
                    recommended_action=sev_data.get("recommended_action", ""),
                )

            if parsed.get("playbook_name"):
                playbooks.append({"name": parsed["playbook_name"]})
    except (json.JSONDecodeError, KeyError):
        pass

    return {
        "triage_complete": True,
        "triage_summary": triage_summary,
        "extracted_iocs": iocs,
        "severity": severity,
        "retrieved_playbooks": playbooks,
        "messages": result["messages"],
    }
