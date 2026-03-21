"""Reporting Agent: generates incident report, creates MISP event, stores in vector DB."""

import json
from datetime import datetime, timezone
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

from soc_agent.agents._llm import get_llm
from soc_agent.graph.state import SOCState
from soc_agent.tools.misp_tools import (
    misp_add_event,
    misp_add_attribute,
    misp_add_tag,
    misp_publish_event,
)

REPORTING_SYSTEM_PROMPT = """You are a SOC Reporting Agent. Generate a comprehensive incident report
and create a MISP event documenting the investigation findings.

## Step 1: Create MISP Event
Use misp_add_event to create a new event with:
- info: Descriptive title (e.g. "Lazarus Campaign - SMB Lateral Movement 2026-03-14")
- threat_level_id: Based on severity (1=High, 2=Medium, 3=Low)
- analysis: 2 (Complete)

## Step 2: Add IOC Attributes
For each confirmed/suspected IOC, use misp_add_attribute:
- IPs → type "ip-dst", category "Network activity"
- Domains → type "domain", category "Network activity"
- Hashes → type "sha256"/"md5"/"sha1", category "Payload delivery"
- URLs → type "url", category "Network activity"

## Step 3: Add Tags
Use misp_add_tag for:
- TLP marking (e.g. "tlp:amber")
- Threat actor (e.g. "threat-actor:lazarus-group")
- MITRE techniques (e.g. "mitre-attack:T1021.002")

## Step 4: Generate Markdown Report
After creating the MISP event, write a full incident report in Markdown.

The report MUST include these sections:
1. **Executive Summary** — 2-3 sentence overview
2. **Severity & Classification** — Score, level, TLP
3. **IOC Summary** — Table of all indicators with type, source, confidence
4. **MITRE ATT&CK Mapping** — Techniques with descriptions
5. **Attack Timeline** — Chronological sequence of events
6. **Correlation & Attribution** — Campaign assessment, threat actor
7. **Affected Assets** — List of compromised/targeted hosts
8. **Recommended Actions** — Numbered remediation steps (from playbook)
9. **MISP Event Reference** — Event ID and link

Output the complete markdown report as your final message.
"""

REPORTING_TOOLS = [
    misp_add_event,
    misp_add_attribute,
    misp_add_tag,
    misp_publish_event,
]


def _build_reporting_agent():
    return create_react_agent(
        get_llm(),
        REPORTING_TOOLS,
        prompt=REPORTING_SYSTEM_PROMPT,
    )


def _compile_investigation_context(state: SOCState) -> str:
    """Build a comprehensive context string from all agent outputs."""
    parts = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts.append(f"Investigation ID: {state.get('investigation_id', 'N/A')}")
    parts.append(f"Report generated: {now}")

    alert = state["raw_alert"]
    parts.append(f"\n## Alert")
    parts.append(f"ID: {alert.alert_id} | Source: {alert.source} | Time: {alert.timestamp}")
    parts.append(f"Raw data: {json.dumps(alert.raw_data, indent=2, default=str)}")

    parts.append(f"\n## Triage")
    parts.append(state.get("triage_summary", "N/A"))

    severity = state.get("severity")
    if severity:
        parts.append(f"\n## Severity")
        parts.append(f"Score: {severity.score}/10 | Level: {severity.level}")
        parts.append(f"Factors: {severity.factors}")
        parts.append(f"Action: {severity.recommended_action}")

    iocs = state.get("extracted_iocs", [])
    if iocs:
        parts.append(f"\n## IOCs ({len(iocs)} total)")
        for ioc in iocs:
            parts.append(
                f"- {ioc.value} | type={ioc.ioc_type} | malicious={ioc.malicious} | "
                f"confidence={ioc.confidence} | techniques={ioc.mitre_techniques}"
            )

    tc = state.get("threat_context")
    if tc:
        parts.append(f"\n## Threat Context")
        parts.append(f"MITRE: {tc.mitre_techniques}")
        parts.append(f"Actors: {tc.threat_actors}")
        parts.append(f"Malware: {tc.malware_families}")
        parts.append(f"Kill chain: {tc.kill_chain_phase}")
        parts.append(f"Summary: {tc.attack_summary}")

    os_hits = state.get("opensearch_hits", [])
    if os_hits:
        parts.append(f"\n## Log Evidence ({len(os_hits)} findings)")
        for hit in os_hits[:15]:
            parts.append(f"- {json.dumps(hit, default=str)}")

    corr = state.get("correlation")
    if corr:
        parts.append(f"\n## Correlation")
        parts.append(f"Campaign: {corr.is_campaign} (confidence: {corr.campaign_confidence})")
        parts.append(f"Attribution: {corr.threat_actor_attribution}")
        parts.append(f"Pattern: {corr.pattern_description}")
        if corr.attack_timeline:
            parts.append("Timeline:")
            for event in corr.attack_timeline:
                parts.append(f"  {event.get('timestamp', '?')} - {event.get('event', '?')}")

    playbooks = state.get("retrieved_playbooks", [])
    if playbooks:
        parts.append(f"\n## Matched Playbooks: {playbooks}")

    return "\n".join(parts)


def reporting_node(state: SOCState) -> dict:
    """LangGraph node: generate report and create MISP event."""
    agent = _build_reporting_agent()

    context = _compile_investigation_context(state)

    result = agent.invoke({
        "messages": [HumanMessage(
            content=(
                f"Generate the incident report and create a MISP event based on "
                f"these investigation findings:\n\n{context}"
            )
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

    # Try to extract MISP event ID from tool call results
    misp_event_id = None
    for msg in result["messages"]:
        msg_content = msg.content if hasattr(msg, "content") else str(msg)
        if isinstance(msg_content, list):
            msg_content = "\n".join(
                b.get("text", str(b)) if isinstance(b, dict) else str(b)
                for b in msg_content
            )
        if isinstance(msg_content, str) and '"event_id"' in msg_content:
            try:
                parsed = json.loads(msg_content)
                if parsed.get("created") and parsed.get("event_id"):
                    misp_event_id = str(parsed["event_id"])
            except (json.JSONDecodeError, KeyError):
                pass

    # Store the report in ChromaDB for future RAG retrieval
    try:
        from soc_agent.vector_store.ingestion import ingest_incident_report

        severity = state.get("severity")
        corr = state.get("correlation")
        tc = state.get("threat_context")

        metadata = {
            "severity_level": severity.level if severity else "UNKNOWN",
            "severity_score": severity.score if severity else 0,
            "threat_actor": corr.threat_actor_attribution if corr else "",
            "is_campaign": corr.is_campaign if corr else False,
            "mitre_techniques": json.dumps(tc.mitre_techniques if tc else []),
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "misp_event_id": misp_event_id or "",
        }
        ingest_incident_report(
            report_text=content,
            incident_id=state.get("investigation_id", "unknown"),
            metadata=metadata,
        )
    except Exception:
        pass  # Non-critical: don't fail the report if ingestion fails

    return {
        "report_complete": True,
        "final_report": content,
        "misp_event_id": misp_event_id,
        "messages": result["messages"],
    }
