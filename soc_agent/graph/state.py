import operator
from typing import TypedDict, Annotated, Literal, Optional, Union
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Sub-models for structured data within the shared state
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    alert_id: str
    source: str  # "opensearch" | "misp" | "manual"
    raw_data: dict
    timestamp: str = ""
    description: str = ""


class IOC(BaseModel):
    value: str
    ioc_type: str  # "ip-dst", "domain", "sha256", "url", etc.
    source: str = "alert"
    confidence: float = 0.5
    malicious: Optional[bool] = None
    enrichment_data: dict = Field(default_factory=dict)
    misp_hit: Optional[Union[dict, str]] = None
    sighting_added: bool = False
    mitre_techniques: list[str] = Field(default_factory=list)


class ThreatContext(BaseModel):
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    related_misp_event_ids: list[str] = Field(default_factory=list)
    kill_chain_phase: Optional[str] = None
    attack_summary: str = ""


class CorrelationResult(BaseModel):
    correlated_alert_ids: list[str] = Field(default_factory=list)
    pattern_description: str = ""
    time_window_hours: int = 24
    is_campaign: bool = False
    campaign_confidence: float = 0.0
    threat_actor_attribution: str = ""
    attack_timeline: list[dict] = Field(default_factory=list)
    similar_past_incidents: list[dict] = Field(default_factory=list)


class SeverityScore(BaseModel):
    score: float  # 0.0 - 10.0
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    factors: list[str] = Field(default_factory=list)
    recommended_action: str = ""


# ---------------------------------------------------------------------------
# Main shared graph state
# ---------------------------------------------------------------------------

class SOCState(TypedDict):
    # Conversation messages (accumulated across all agents)
    messages: Annotated[list, add_messages]

    # Input alert
    raw_alert: Alert

    # Triage agent outputs
    severity: Optional[SeverityScore]
    triage_complete: bool
    triage_summary: str

    # IOC enrichment agent outputs
    extracted_iocs: list[IOC]
    enrichment_complete: bool

    # Threat hunter agent outputs
    threat_context: Optional[ThreatContext]
    opensearch_hits: list[dict]
    hunt_complete: bool

    # Correlation agent outputs
    correlation: Optional[CorrelationResult]
    correlation_complete: bool

    # RAG-retrieved context (populated by multiple agents)
    retrieved_playbooks: list[dict]
    retrieved_past_incidents: list[dict]

    # Reporting agent outputs
    final_report: Optional[str]
    misp_event_id: Optional[str]
    report_complete: bool

    # Supervisor control
    iteration_count: int
    next_agent: str
    error_log: Annotated[list[str], operator.add]
    investigation_id: str
