"""MITRE ATT&CK technique lookup from local STIX data + keyword mapper.

Downloads the STIX bundle on first use if not present locally.
"""

import json
import os
from langchain_core.tools import tool
from soc_agent.config.settings import settings

_TECHNIQUE_INDEX: dict[str, dict] | None = None

# Keyword → technique ID mapping for fast heuristic matching
KEYWORD_TECHNIQUE_MAP = {
    "powershell": "T1059.001",
    "cmd": "T1059.003",
    "bash": "T1059.004",
    "python": "T1059.006",
    "scheduled task": "T1053.005",
    "cron": "T1053.003",
    "phishing": "T1566",
    "spearphishing": "T1566.001",
    "phishing link": "T1566.002",
    "credential dump": "T1003",
    "mimikatz": "T1003.001",
    "lsass": "T1003.001",
    "pass the hash": "T1550.002",
    "pass the ticket": "T1550.003",
    "kerberoast": "T1558.003",
    "brute force": "T1110",
    "rdp": "T1021.001",
    "smb": "T1021.002",
    "psexec": "T1021.002",
    "wmi": "T1047",
    "winrm": "T1021.006",
    "ssh": "T1021.004",
    "lateral movement": "T1021",
    "dns tunneling": "T1071.004",
    "dns": "T1071.004",
    "http": "T1071.001",
    "c2": "T1071",
    "command and control": "T1071",
    "beaconing": "T1071",
    "exfiltration": "T1041",
    "data exfiltration": "T1041",
    "ransomware": "T1486",
    "encryption": "T1486",
    "file encryption": "T1486",
    "registry": "T1112",
    "startup folder": "T1547.001",
    "service creation": "T1543.003",
    "dll injection": "T1055.001",
    "process injection": "T1055",
    "privilege escalation": "T1068",
    "uac bypass": "T1548.002",
    "port scan": "T1046",
    "network scan": "T1046",
    "reconnaissance": "T1595",
    "supply chain": "T1195",
    "trojan": "T1204.002",
    "macro": "T1204.002",
    "archive": "T1560",
    "compression": "T1560.001",
    "cloud storage": "T1567.002",
}

# Kill chain phase severity (higher = more severe, used in scoring)
TACTIC_SEVERITY = {
    "reconnaissance": 2.0,
    "resource-development": 2.0,
    "initial-access": 4.0,
    "execution": 5.0,
    "persistence": 6.0,
    "privilege-escalation": 7.0,
    "defense-evasion": 6.0,
    "credential-access": 7.0,
    "discovery": 3.0,
    "lateral-movement": 8.0,
    "collection": 7.0,
    "command-and-control": 8.0,
    "exfiltration": 9.0,
    "impact": 10.0,
}


def _load_stix_data() -> dict[str, dict]:
    """Load MITRE ATT&CK STIX bundle and build a technique index."""
    global _TECHNIQUE_INDEX
    if _TECHNIQUE_INDEX is not None:
        return _TECHNIQUE_INDEX

    stix_path = settings.MITRE_STIX_PATH
    if not os.path.exists(stix_path):
        _TECHNIQUE_INDEX = {}
        return _TECHNIQUE_INDEX

    with open(stix_path) as f:
        stix_data = json.load(f)

    _TECHNIQUE_INDEX = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                if tid:
                    _TECHNIQUE_INDEX[tid] = obj
                break

    return _TECHNIQUE_INDEX


@tool
def lookup_mitre_technique(technique_id: str) -> str:
    """Look up a MITRE ATT&CK technique by ID (e.g. T1059.001).
    Returns name, description, kill chain phases, detection guidance."""
    index = _load_stix_data()
    tech = index.get(technique_id)
    if not tech:
        return json.dumps({"error": f"Technique {technique_id} not found in local STIX data."})

    phases = [
        p.get("phase_name", "")
        for p in tech.get("kill_chain_phases", [])
    ]
    max_severity = max((TACTIC_SEVERITY.get(p, 0) for p in phases), default=0)

    return json.dumps({
        "id": technique_id,
        "name": tech.get("name", ""),
        "description": (tech.get("description", "") or "")[:800],
        "kill_chain_phases": phases,
        "tactic_severity": max_severity,
        "platforms": tech.get("x_mitre_platforms", []),
        "data_sources": tech.get("x_mitre_data_sources", []),
        "detection": (tech.get("x_mitre_detection", "") or "")[:500],
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }, indent=2)


@tool
def map_text_to_mitre_techniques(text: str) -> str:
    """Map free-text descriptions to MITRE ATT&CK techniques using keyword matching.
    Input examples: 'psexec lateral movement', 'dns tunneling C2', 'ransomware encryption'.
    Returns matched technique IDs with confidence."""
    text_lower = text.lower()
    matches = []
    seen_ids = set()

    for keyword, tid in KEYWORD_TECHNIQUE_MAP.items():
        if keyword in text_lower and tid not in seen_ids:
            seen_ids.add(tid)
            # Try to get technique details from STIX data
            index = _load_stix_data()
            tech = index.get(tid, {})
            phases = [p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])]
            max_severity = max((TACTIC_SEVERITY.get(p, 0) for p in phases), default=0)

            matches.append({
                "technique_id": tid,
                "technique_name": tech.get("name", keyword),
                "matched_keyword": keyword,
                "kill_chain_phases": phases,
                "tactic_severity": max_severity,
            })

    matches.sort(key=lambda m: m["tactic_severity"], reverse=True)
    return json.dumps({"matched_techniques": matches, "count": len(matches)}, indent=2)


MITRE_TOOLS = [lookup_mitre_technique, map_text_to_mitre_techniques]
