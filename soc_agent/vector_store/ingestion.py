"""Ingest playbooks, threat actor profiles, and incident reports into ChromaDB."""

import os
import json
import yaml
from langchain_core.documents import Document
from soc_agent.vector_store.chroma_store import (
    get_playbook_store,
    get_incident_store,
    get_ioc_store,
    get_threat_actor_store,
)
from soc_agent.config.settings import settings


def ingest_playbooks(playbooks_dir: str | None = None) -> int:
    """Load YAML playbooks from disk and add to the soc_playbooks collection.
    Returns the number of documents ingested."""
    playbooks_dir = playbooks_dir or settings.PLAYBOOKS_DIR
    if not os.path.isdir(playbooks_dir):
        return 0

    store = get_playbook_store()
    docs: list[Document] = []
    ids: list[str] = []

    for fname in os.listdir(playbooks_dir):
        if not fname.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(playbooks_dir, fname)
        with open(path) as f:
            playbook = yaml.safe_load(f)

        # Build a text representation of the playbook for embedding
        name = playbook.get("name", fname)
        text_parts = [f"Playbook: {name}"]
        if playbook.get("trigger_keywords"):
            text_parts.append(f"Triggers: {', '.join(playbook['trigger_keywords'])}")
        if playbook.get("severity_threshold"):
            text_parts.append(f"Severity threshold: {playbook['severity_threshold']}")
        if playbook.get("mitre_techniques"):
            text_parts.append(f"MITRE techniques: {', '.join(playbook['mitre_techniques'])}")

        for step in playbook.get("steps", []):
            text_parts.append(
                f"Step {step.get('id', '?')}: {step.get('description', '')} "
                f"(automated={step.get('automated', False)})"
            )
            if step.get("soc_instruction"):
                text_parts.append(f"  Instruction: {step['soc_instruction']}")

        doc = Document(
            page_content="\n".join(text_parts),
            metadata={
                "source": fname,
                "playbook_name": name,
                "severity_threshold": playbook.get("severity_threshold", ""),
                "mitre_techniques": json.dumps(playbook.get("mitre_techniques", [])),
            },
        )
        docs.append(doc)
        ids.append(f"playbook-{fname}")

    if docs:
        store.add_documents(docs, ids=ids)
    return len(docs)


def ingest_incident_report(
    report_text: str,
    incident_id: str,
    metadata: dict | None = None,
) -> None:
    """Store a completed investigation report for future RAG retrieval."""
    store = get_incident_store()
    meta = metadata or {}
    meta["incident_id"] = incident_id
    doc = Document(page_content=report_text, metadata=meta)
    store.add_documents([doc], ids=[f"incident-{incident_id}"])


def ingest_ioc_profile(
    ioc_value: str,
    ioc_type: str,
    profile_text: str,
    metadata: dict | None = None,
) -> None:
    """Store an enriched IOC profile for future correlation."""
    store = get_ioc_store()
    meta = metadata or {}
    meta.update({"ioc_value": ioc_value, "ioc_type": ioc_type})
    doc = Document(page_content=profile_text, metadata=meta)
    store.add_documents([doc], ids=[f"ioc-{ioc_type}-{ioc_value}"])


def ingest_threat_actor_profiles(profiles_dir: str | None = None) -> int:
    """Load threat actor profiles from JSON files. Returns count ingested."""
    profiles_dir = profiles_dir or os.path.join(
        os.path.dirname(__file__), "..", "data", "threat_actor_profiles"
    )
    if not os.path.isdir(profiles_dir):
        return 0

    store = get_threat_actor_store()
    docs: list[Document] = []
    ids: list[str] = []

    for fname in os.listdir(profiles_dir):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(profiles_dir, fname)
        with open(path) as f:
            profile = json.load(f)

        text = (
            f"Threat Actor: {profile.get('name', 'Unknown')}\n"
            f"Aliases: {', '.join(profile.get('aliases', []))}\n"
            f"Origin: {profile.get('origin', 'Unknown')}\n"
            f"Target sectors: {', '.join(profile.get('target_sectors', []))}\n"
            f"TTPs: {', '.join(profile.get('mitre_techniques', []))}\n"
            f"Description: {profile.get('description', '')}\n"
            f"Known malware: {', '.join(profile.get('known_malware', []))}\n"
            f"Infrastructure: {profile.get('infrastructure', '')}"
        )

        doc = Document(
            page_content=text,
            metadata={
                "actor_name": profile.get("name", ""),
                "origin": profile.get("origin", ""),
                "target_sectors": json.dumps(profile.get("target_sectors", [])),
            },
        )
        docs.append(doc)
        ids.append(f"actor-{profile.get('name', fname).lower().replace(' ', '-')}")

    if docs:
        store.add_documents(docs, ids=ids)
    return len(docs)


def ingest_all() -> dict[str, int]:
    """Run all ingestion pipelines. Returns counts per collection."""
    return {
        "playbooks": ingest_playbooks(),
        "threat_actors": ingest_threat_actor_profiles(),
    }
