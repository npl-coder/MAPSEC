"""LangChain @tool wrappers around the MISP MCP server handler functions.

Instead of spawning a subprocess, we import the handler functions directly
from misp_mcp_server.py and wrap them with LangChain's @tool decorator.
This keeps things simple and avoids MCP transport overhead.
"""

import json
import sys
import os

# Ensure the project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from langchain_core.tools import tool


def _call_misp(handler_name: str, **kwargs) -> str:
    """Call a MISP MCP server handler by name and return JSON string."""
    # Lazy import to avoid circular / env issues at module load time
    from misp_mcp_server import HANDLERS
    try:
        result = HANDLERS[handler_name](**kwargs)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Search / query tools (read-only)
# ---------------------------------------------------------------------------

@tool
def misp_search_attribute(value: str, attribute_type: str = "") -> str:
    """Search MISP for any attribute value — IP, domain, hash, URL, etc.
    Returns matching attributes with event IDs and IDS flag."""
    kwargs = {"value": value}
    if attribute_type:
        kwargs["type"] = attribute_type
    return _call_misp("search_attribute", **kwargs)


@tool
def misp_search_ip(ip: str) -> str:
    """Check if an IP address exists in MISP and whether it is flagged as malicious (IDS)."""
    return _call_misp("search_ip_in_misp", ip=ip)


@tool
def misp_get_threat_details(indicator: str) -> str:
    """Get full threat context for an indicator (IP/domain) from MISP events.
    Returns event info, threat level, tags, and comments for each match."""
    return _call_misp("get_threat_details", ip=indicator)


@tool
def misp_search_events(
    tags: str = "",
    attribute_type: str = "",
    value: str = "",
    last: str = "",
    limit: int = 20,
) -> str:
    """Search MISP events with filters. Use 'last' for time window (e.g. '7d', '30d').
    Tags can be comma-separated (e.g. 'tlp:white,apt')."""
    kwargs: dict = {"limit": limit}
    if tags:
        kwargs["tags"] = tags
    if attribute_type:
        kwargs["type"] = attribute_type
    if value:
        kwargs["value"] = value
    if last:
        kwargs["last"] = last
    return _call_misp("search_events", **kwargs)


@tool
def misp_get_event(event_id: str) -> str:
    """Get full event details by ID including all attributes and metadata."""
    return _call_misp("get_event", event_id=event_id)


@tool
def misp_get_event_indicators(event_id: str) -> str:
    """Get all IOCs for an event grouped by type (IPs, domains, hashes, URLs)."""
    return _call_misp("get_event_indicators", event_id=event_id)


@tool
def misp_list_events(limit: int = 10) -> str:
    """List the most recent MISP events with basic metadata."""
    return _call_misp("list_misp_events", limit=limit)


@tool
def misp_get_malicious_ips() -> str:
    """Get all malicious IP addresses from MISP that are marked for IDS export."""
    return _call_misp("get_malicious_ips")


@tool
def misp_get_malicious_domains() -> str:
    """Get all malicious domains from MISP that are marked for IDS export."""
    return _call_misp("get_malicious_domains")


@tool
def misp_get_malicious_hashes(hash_type: str = "all") -> str:
    """Get malicious file hashes from MISP. hash_type: 'md5', 'sha1', 'sha256', or 'all'."""
    return _call_misp("get_malicious_hashes", hash_type=hash_type)


@tool
def misp_get_event_galaxies(event_id: str) -> str:
    """Get MITRE ATT&CK mappings, malware families, and threat actor galaxies attached to an event."""
    return _call_misp("get_event_galaxies", event_id=event_id)


@tool
def misp_list_galaxy_clusters(galaxy: str = "", limit: int = 50) -> str:
    """List galaxy clusters (MITRE techniques, malware, threat actors) optionally filtered."""
    kwargs: dict = {"limit": limit}
    if galaxy:
        kwargs["galaxy"] = galaxy
    return _call_misp("list_galaxy_clusters", **kwargs)


# ---------------------------------------------------------------------------
# Write tools (create / modify MISP data)
# ---------------------------------------------------------------------------

@tool
def misp_add_event(
    info: str,
    threat_level_id: int = 4,
    analysis: int = 0,
    distribution: int = 0,
) -> str:
    """Create a new MISP event. threat_level: 1=High,2=Medium,3=Low,4=Undefined.
    analysis: 0=Initial,1=Ongoing,2=Complete."""
    return _call_misp(
        "add_event",
        info=info,
        threat_level_id=threat_level_id,
        analysis=analysis,
        distribution=distribution,
    )


@tool
def misp_add_attribute(
    event_id: str,
    attribute_type: str,
    value: str,
    category: str = "",
    to_ids: bool = True,
    comment: str = "",
) -> str:
    """Add an IOC attribute to an existing MISP event.
    Types: ip-dst, domain, sha256, url, md5, sha1, filename, etc."""
    return _call_misp(
        "add_attribute",
        event_id=event_id,
        type=attribute_type,
        value=value,
        category=category,
        to_ids=to_ids,
        comment=comment,
    )


@tool
def misp_add_tag(event_id: str, tag: str) -> str:
    """Add a tag to a MISP event (e.g. 'tlp:amber', 'mitre-attack:T1059')."""
    return _call_misp("add_tag_to_event", event_id=event_id, tag=tag)


@tool
def misp_add_sighting(attribute_id: str, sighting_type: int = 0) -> str:
    """Record a sighting of an attribute. type: 0=seen, 1=false-positive, 2=expiration."""
    return _call_misp("add_sighting", attribute_id=attribute_id, type=sighting_type)


@tool
def misp_publish_event(event_id: str) -> str:
    """Publish a MISP event to make it visible to the community."""
    return _call_misp("publish_event", event_id=event_id)


# ---------------------------------------------------------------------------
# Grouped tool lists for agent construction
# ---------------------------------------------------------------------------

MISP_READ_TOOLS = [
    misp_search_attribute,
    misp_search_ip,
    misp_get_threat_details,
    misp_search_events,
    misp_get_event,
    misp_get_event_indicators,
    misp_list_events,
    misp_get_malicious_ips,
    misp_get_malicious_domains,
    misp_get_malicious_hashes,
    misp_get_event_galaxies,
    misp_list_galaxy_clusters,
]

MISP_WRITE_TOOLS = [
    misp_add_event,
    misp_add_attribute,
    misp_add_tag,
    misp_add_sighting,
    misp_publish_event,
]

ALL_MISP_TOOLS = MISP_READ_TOOLS + MISP_WRITE_TOOLS
