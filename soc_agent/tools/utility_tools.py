"""Utility tools: severity scoring, IOC extraction, time parsing."""

import json
import re
from langchain_core.tools import tool


# IOC type detection patterns
IOC_PATTERNS = {
    "ip-dst": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
}

# Domains to ignore in extraction
DOMAIN_WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "amazonaws.com", "cloudflare.com", "example.com", "localhost",
}


@tool
def extract_iocs_from_text(text: str) -> str:
    """Extract IOCs (IPs, domains, hashes, URLs, emails) from raw text.
    Returns a JSON object grouping IOCs by type."""
    results: dict[str, list[str]] = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        if ioc_type == "domain":
            matches = {
                m for m in matches
                if m not in DOMAIN_WHITELIST
                and not m.endswith(tuple(f".{d}" for d in DOMAIN_WHITELIST))
                and len(m.split(".")) >= 2
            }
        # Avoid hash-type collisions (sha256 superset of sha1 superset of md5)
        if ioc_type == "sha1":
            sha256_matches = set(IOC_PATTERNS["sha256"].findall(text))
            matches -= sha256_matches
        if ioc_type == "md5":
            sha1_matches = set(IOC_PATTERNS["sha1"].findall(text))
            sha256_matches = set(IOC_PATTERNS["sha256"].findall(text))
            matches -= sha1_matches | sha256_matches
        if matches:
            results[ioc_type] = sorted(matches)
    return json.dumps(results, indent=2)


@tool
def compute_severity_score(
    misp_threat_level: int = 4,
    virustotal_malicious_ratio: float = 0.0,
    abuseipdb_confidence: float = 0.0,
    mitre_tactic_severity: float = 0.0,
    asset_criticality: float = 5.0,
    ioc_count: int = 1,
) -> str:
    """Compute a multi-factor severity score (0-10) for an alert.

    Inputs:
      - misp_threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined
      - virustotal_malicious_ratio: 0.0-1.0 (malicious engines / total)
      - abuseipdb_confidence: 0-100 abuse confidence score
      - mitre_tactic_severity: 0-10 based on kill chain position
      - asset_criticality: 0-10 how critical the affected asset is
      - ioc_count: number of distinct IOCs found
    """
    factors = []

    # MISP threat level (weight: 0.25)
    misp_score = {1: 10.0, 2: 6.0, 3: 3.0, 4: 1.0}.get(misp_threat_level, 1.0)
    factors.append(f"MISP threat level {misp_threat_level} → {misp_score}/10")

    # VirusTotal (weight: 0.25)
    vt_score = virustotal_malicious_ratio * 10
    if vt_score > 0:
        factors.append(f"VirusTotal {virustotal_malicious_ratio:.0%} malicious → {vt_score:.1f}/10")

    # AbuseIPDB (weight: 0.15)
    abuse_score = (abuseipdb_confidence / 100) * 10
    if abuse_score > 0:
        factors.append(f"AbuseIPDB confidence {abuseipdb_confidence}% → {abuse_score:.1f}/10")

    # MITRE tactic (weight: 0.15)
    mitre_score = min(mitre_tactic_severity, 10.0)
    if mitre_score > 0:
        factors.append(f"MITRE tactic severity → {mitre_score:.1f}/10")

    # Asset criticality (weight: 0.10)
    asset_score = min(asset_criticality, 10.0)
    factors.append(f"Asset criticality → {asset_score:.1f}/10")

    # IOC volume bonus (weight: 0.10)
    volume_score = min(ioc_count * 2.0, 10.0)
    if ioc_count > 1:
        factors.append(f"IOC volume ({ioc_count} indicators) → {volume_score:.1f}/10")

    total = (
        misp_score * 0.25
        + vt_score * 0.25
        + abuse_score * 0.15
        + mitre_score * 0.15
        + asset_score * 0.10
        + volume_score * 0.10
    )
    total = round(min(total, 10.0), 2)

    if total >= 8:
        level = "CRITICAL"
        action = "Immediate incident response required. Isolate affected systems."
    elif total >= 6:
        level = "HIGH"
        action = "Escalate to senior analyst. Begin active investigation."
    elif total >= 3:
        level = "MEDIUM"
        action = "Investigate within 4 hours. Monitor for escalation."
    else:
        level = "LOW"
        action = "Log and monitor. Review during next shift."

    return json.dumps({
        "score": total,
        "level": level,
        "factors": factors,
        "recommended_action": action,
    }, indent=2)


UTILITY_TOOLS = [extract_iocs_from_text, compute_severity_score]
