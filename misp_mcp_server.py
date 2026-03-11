#!/usr/bin/env python3
"""
MISP MCP Server
Exposes MISP threat intelligence via MCP protocol for Claude.
Supports search, events, attributes, tags, sightings, publishing, and feeds.
"""
import asyncio
import json
import os
import requests
from typing import Any
from mcp.server import InitializationOptions, NotificationOptions, Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# MISP Configuration
MISP_URL = os.environ.get("MISP_URL", "https://misp.local")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")

session = requests.Session()
session.verify = False
session.headers.update({
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
})

server = Server("misp-mcp-server")


def _get(path: str, timeout: int = 30) -> dict:
    r = session.get(f"{MISP_URL}{path}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def _post(path: str, json_data: dict | None = None, timeout: int = 30) -> dict:
    r = session.post(f"{MISP_URL}{path}", json=json_data or {}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _delete(path: str, timeout: int = 30) -> dict:
    r = session.delete(f"{MISP_URL}{path}", timeout=timeout)
    r.raise_for_status()
    return r.json() if r.content else {}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[types.Tool] = [
    types.Tool(
        name="get_malicious_ips",
        description="Get all malicious IP addresses from MISP (ip-dst attributes marked for IDS).",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="get_malicious_domains",
        description="Get all malicious domains from MISP (domain attributes marked for IDS).",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="get_malicious_hashes",
        description="Get malicious file hashes (md5, sha1, sha256) from MISP marked for IDS.",
        inputSchema={
            "type": "object",
            "properties": {
                "hash_type": {
                    "type": "string",
                    "description": "Filter: md5, sha1, sha256, or 'all' (default)",
                    "default": "all",
                },
            },
        },
    ),
    types.Tool(
        name="search_ip_in_misp",
        description="Check if an IP is present in MISP and whether it is marked for IDS.",
        inputSchema={
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 or IPv6 address"}},
            "required": ["ip"],
        },
    ),
    types.Tool(
        name="search_attribute",
        description="Search for any attribute by value (IP, domain, hash, url, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Attribute value to search"},
                "type": {"type": "string", "description": "Optional: attribute type (e.g. ip-dst, domain, sha256)"},
            },
            "required": ["value"],
        },
    ),
    types.Tool(
        name="get_threat_details",
        description="Get full threat context for an indicator (IP/domain/etc.) from MISP events.",
        inputSchema={
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IP to get threat details for"}},
            "required": ["ip"],
        },
    ),
    types.Tool(
        name="list_misp_events",
        description="List MISP events (id, info, date, threat_level, published).",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max events to return", "default": 10},
            },
        },
    ),
    types.Tool(
        name="get_event",
        description="Get full event by ID including attributes and metadata.",
        inputSchema={
            "type": "object",
            "properties": {"event_id": {"type": "string", "description": "MISP event ID"}},
            "required": ["event_id"],
        },
    ),
    types.Tool(
        name="get_event_indicators",
        description="Get all IOCs for an event (IPs, domains, hashes, URLs) grouped by type.",
        inputSchema={
            "type": "object",
            "properties": {"event_id": {"type": "string", "description": "MISP event ID"}},
            "required": ["event_id"],
        },
    ),
    types.Tool(
        name="search_events",
        description="Search events with filters: tags, type, value, last (e.g. 7d), limit, page.",
        inputSchema={
            "type": "object",
            "properties": {
                "tags": {"type": "string", "description": "Comma-separated tags (e.g. tlp:white)"},
                "type": {"type": "string", "description": "Attribute type filter"},
                "value": {"type": "string", "description": "Attribute value substring"},
                "last": {"type": "string", "description": "Events from last period (e.g. 1d, 7d, 30d)"},
                "published": {"type": "boolean", "description": "Only published events"},
                "limit": {"type": "integer", "description": "Max results", "default": 20},
                "page": {"type": "integer", "description": "Page for pagination", "default": 1},
            },
        },
    ),
    types.Tool(
        name="search_attributes",
        description="Search attributes with filters: type, category, value, tags, to_ids, last.",
        inputSchema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "e.g. ip-dst, domain, sha256"},
                "category": {"type": "string", "description": "e.g. Network activity"},
                "value": {"type": "string", "description": "Value or substring"},
                "tags": {"type": "string", "description": "Comma-separated tags"},
                "to_ids": {"type": "boolean", "description": "Only attributes marked for IDS"},
                "last": {"type": "string", "description": "e.g. 7d"},
                "limit": {"type": "integer", "default": 50},
                "page": {"type": "integer", "default": 1},
            },
        },
    ),
    types.Tool(
        name="add_event",
        description="Create a new MISP event.",
        inputSchema={
            "type": "object",
            "properties": {
                "info": {"type": "string", "description": "Event title/info (required)"},
                "distribution": {"type": "integer", "description": "0=Your org, 1=Community, 2=Connected, 3=All", "default": 0},
                "threat_level_id": {"type": "integer", "description": "1=High, 2=Medium, 3=Low, 4=Undefined", "default": 4},
                "analysis": {"type": "integer", "description": "0=Initial, 1=Ongoing, 2=Complete", "default": 0},
            },
            "required": ["info"],
        },
    ),
    types.Tool(
        name="add_attribute",
        description="Add an attribute to an existing event.",
        inputSchema={
            "type": "object",
            "properties": {
                "event_id": {"type": "string", "description": "Event ID"},
                "type": {"type": "string", "description": "e.g. ip-dst, domain, sha256, url, comment"},
                "category": {"type": "string", "description": "e.g. Network activity, Payload delivery"},
                "value": {"type": "string", "description": "Attribute value"},
                "to_ids": {"type": "boolean", "description": "Exportable to IDS", "default": True},
                "comment": {"type": "string", "description": "Optional comment"},
            },
            "required": ["event_id", "type", "value"],
        },
    ),
    types.Tool(
        name="publish_event",
        description="Publish an event (make it visible to the community).",
        inputSchema={
            "type": "object",
            "properties": {"event_id": {"type": "string", "description": "Event ID to publish"}},
            "required": ["event_id"],
        },
    ),
    types.Tool(
        name="add_sighting",
        description="Add a sighting to an attribute (0=positive, 1=negative, 2=expiration).",
        inputSchema={
            "type": "object",
            "properties": {
                "attribute_id": {"type": "string", "description": "Attribute UUID or ID"},
                "type": {"type": "integer", "description": "0=positive, 1=negative, 2=expiration", "default": 0},
            },
            "required": ["attribute_id"],
        },
    ),
    types.Tool(
        name="add_tag_to_event",
        description="Add a tag to an event (e.g. tlp:white, malware:ransomware).",
        inputSchema={
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "tag": {"type": "string", "description": "Tag name (create if missing)"},
            },
            "required": ["event_id", "tag"],
        },
    ),
    types.Tool(
        name="list_tags",
        description="List available tags in MISP (taxonomies and free tags).",
        inputSchema={
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Filter tag name"},
                "limit": {"type": "integer", "default": 100},
            },
        },
    ),
    types.Tool(
        name="list_feeds",
        description="List configured MISP feeds (Cortex, MISP, custom).",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="list_galaxy_clusters",
        description="List galaxy clusters (e.g. malware, threat-actor) optionally by galaxy name.",
        inputSchema={
            "type": "object",
            "properties": {
                "galaxy": {"type": "string", "description": "e.g. mitre-attack-pattern, malware"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    types.Tool(
        name="get_event_galaxies",
        description="Get galaxy clusters (MITRE, malware, etc.) attached to an event.",
        inputSchema={
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
    ),
    types.Tool(
        name="delete_event",
        description="Delete an event by ID. Use with caution.",
        inputSchema={
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
    ),
]


def _run_get_malicious_ips() -> dict:
    data = _get("/attributes/search/type:ip-dst/to_ids:1")
    ips = {}
    for item in data.get("response", []):
        attr = item.get("Attribute", {})
        v = attr.get("value")
        if v:
            ips[v] = {"event_id": attr.get("event_id"), "comment": attr.get("comment", "")}
    return {"malicious_ips": ips, "total": len(ips)}


def _run_get_malicious_domains() -> dict:
    data = _get("/attributes/search/type:domain/to_ids:1")
    domains = {}
    for item in data.get("response", []):
        attr = item.get("Attribute", {})
        v = attr.get("value")
        if v:
            domains[v] = {"event_id": attr.get("event_id"), "comment": attr.get("comment", "")}
    return {"malicious_domains": domains, "total": len(domains)}


def _run_get_malicious_hashes(hash_type: str = "all") -> dict:
    types_map = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "all": None}
    t = types_map.get((hash_type or "all").lower())
    if t:
        data = _get(f"/attributes/search/type:{t}/to_ids:1")
        raw = data.get("response", [])
    else:
        data = _post("/attributes/restSearch", {"returnFormat": "json", "to_ids": True, "type": ["md5", "sha1", "sha256"], "limit": 200})
        raw = data.get("response", []) if isinstance(data.get("response"), list) else []
    hashes_list = []
    for item in raw:
        attr = item.get("Attribute", item) if isinstance(item, dict) else item
        if not isinstance(attr, dict):
            continue
        v = attr.get("value")
        if v:
            hashes_list.append({"value": v, "type": attr.get("type"), "event_id": attr.get("event_id")})
    return {"hashes": hashes_list, "total": len(hashes_list)}


def _run_search_ip(ip: str) -> dict:
    data = _get(f"/attributes/search/value:{ip}")
    findings = []
    for item in data.get("response", []):
        attr = item.get("Attribute", {})
        if attr.get("value") == ip:
            findings.append({"event_id": attr.get("event_id"), "type": attr.get("type"), "to_ids": bool(attr.get("to_ids")), "comment": attr.get("comment", "")})
    return {"ip": ip, "is_malicious": any(f.get("to_ids") for f in findings), "findings": findings}


def _run_search_attribute(value: str, attr_type: str | None = None) -> dict:
    path = f"/attributes/search/value:{value}"
    if attr_type:
        path += f"/type:{attr_type}"
    data = _get(path)
    results = []
    for item in data.get("response", []):
        attr = item.get("Attribute", {})
        results.append({"event_id": attr.get("event_id"), "id": attr.get("id"), "type": attr.get("type"), "value": attr.get("value"), "to_ids": bool(attr.get("to_ids")), "comment": attr.get("comment", "")})
    return {"value": value, "count": len(results), "attributes": results}


def _run_get_threat_details(ip: str) -> dict:
    data = _get(f"/attributes/search/value:{ip}")
    threat_info = []
    for item in data.get("response", []):
        attr = item.get("Attribute", {})
        if attr.get("value") != ip:
            continue
        eid = attr.get("event_id")
        ev = _get(f"/events/{eid}").get("Event", {})
        threat_info.append({
            "event_id": eid,
            "event_info": ev.get("info"),
            "threat_level_id": ev.get("threat_level_id"),
            "attribute_type": attr.get("type"),
            "to_ids": bool(attr.get("to_ids")),
            "comment": attr.get("comment", ""),
        })
    return {"ip": ip, "threat_details": threat_info}


def _run_list_events(limit: int = 10) -> dict:
    events = _get(f"/events/index/limit:{limit}")
    if not isinstance(events, list):
        events = events.get("response", events) or []
    event_list = [{"id": e.get("id"), "info": e.get("info"), "threat_level_id": e.get("threat_level_id"), "date": e.get("date"), "published": e.get("published")} for e in events[:limit]]
    return {"events": event_list, "total": len(event_list)}


def _run_get_event(event_id: str) -> dict:
    data = _get(f"/events/{event_id}")
    ev = data.get("Event", data)
    return {"event": ev, "event_id": event_id}


def _run_get_event_indicators(event_id: str) -> dict:
    data = _get(f"/events/{event_id}")
    ev = data.get("Event", {})
    indicators = {"ips": [], "domains": [], "hashes": [], "urls": [], "other": []}
    for attr in ev.get("Attribute", []):
        t = (attr.get("type") or "").lower()
        v = attr.get("value")
        rec = {"value": v, "to_ids": bool(attr.get("to_ids"))}
        if "ip" in t:
            indicators["ips"].append(rec)
        elif "domain" in t:
            indicators["domains"].append(rec)
        elif "hash" in t or "md5" in t or "sha" in t:
            indicators["hashes"].append(rec)
        elif "url" in t:
            indicators["urls"].append(rec)
        else:
            indicators["other"].append(rec)
    return {"event_id": event_id, "event_info": ev.get("info"), "indicators": indicators}


def _run_search_events(tags: str | None = None, type_: str | None = None, value: str | None = None, last: str | None = None, published: bool | None = None, limit: int = 20, page: int = 1) -> dict:
    body = {"returnFormat": "json", "limit": limit, "page": page}
    if tags:
        body["tags"] = [t.strip() for t in tags.split(",")]
    if type_:
        body["type"] = type_
    if value:
        body["value"] = value
    if last:
        body["last"] = last
    if published is not None:
        body["published"] = published
    data = _post("/events/restSearch", body)
    response = data.get("response", data) if isinstance(data, dict) else data
    events = response if isinstance(response, list) else []
    return {"events": events[:limit], "count": len(events)}


def _run_search_attributes(type_: str | None = None, category: str | None = None, value: str | None = None, tags: str | None = None, to_ids: bool | None = None, last: str | None = None, limit: int = 50, page: int = 1) -> dict:
    body = {"returnFormat": "json", "limit": limit, "page": page}
    if type_:
        body["type"] = type_
    if category:
        body["category"] = category
    if value:
        body["value"] = value
    if tags:
        body["tags"] = [t.strip() for t in tags.split(",")]
    if to_ids is not None:
        body["to_ids"] = to_ids
    if last:
        body["last"] = last
    data = _post("/attributes/restSearch", body)
    response = data.get("response", data) if isinstance(data, dict) else data
    attrs = response if isinstance(response, list) else []
    return {"attributes": attrs[:limit], "count": len(attrs)}


def _run_add_event(info: str, distribution: int = 0, threat_level_id: int = 4, analysis: int = 0) -> dict:
    body = {"Event": {"info": info, "distribution": distribution, "threat_level_id": threat_level_id, "analysis": analysis}}
    data = _post("/events/add", body)
    ev = (data.get("Event") or data) if isinstance(data, dict) else data
    return {"created": True, "event_id": ev.get("id"), "info": ev.get("info")}


def _run_add_attribute(event_id: str, attr_type: str, value: str, category: str = "", to_ids: bool = True, comment: str = "") -> dict:
    body = {"event_id": event_id, "type": attr_type, "value": value, "to_ids": to_ids}
    if category:
        body["category"] = category
    if comment:
        body["comment"] = comment
    data = _post("/attributes/add", body)
    attr = (data.get("Attribute") or data) if isinstance(data, dict) else data
    return {"created": True, "attribute_id": attr.get("id"), "event_id": event_id, "type": attr_type, "value": value}


def _run_publish_event(event_id: str) -> dict:
    _post(f"/events/publish/{event_id}")
    return {"published": True, "event_id": event_id}


def _run_add_sighting(attribute_id: str, sighting_type: int = 0) -> dict:
    _post("/sightings/add", {"id": attribute_id, "type": str(sighting_type)})
    return {"sighting_added": True, "attribute_id": attribute_id, "type": sighting_type}


def _run_add_tag_to_event(event_id: str, tag: str) -> dict:
    _post("/events/addTag", {"id": event_id, "tag": tag})
    return {"tag_added": True, "event_id": event_id, "tag": tag}


def _run_list_tags(search: str | None = None, limit: int = 100) -> dict:
    path = "/tags/index/limit:%d" % limit
    if search:
        path += f"/searchall:{search}"
    data = _get(path)
    tags = data if isinstance(data, list) else data.get("response", data.get("Tag", [])) or []
    if not isinstance(tags, list):
        tags = [tags]
    return {"tags": [t.get("name", t) if isinstance(t, dict) else t for t in tags[:limit]], "count": len(tags)}


def _run_list_feeds() -> dict:
    data = _get("/feeds/index")
    feeds = data if isinstance(data, list) else data.get("response", data.get("Feed", [])) or []
    if not isinstance(feeds, list):
        feeds = [feeds]
    return {"feeds": [{"id": f.get("id"), "name": f.get("name"), "provider": f.get("provider"), "enabled": f.get("enabled")} if isinstance(f, dict) else f for f in feeds], "count": len(feeds)}


def _run_list_galaxy_clusters(galaxy: str | None = None, limit: int = 50) -> dict:
    path = f"/galaxy_clusters/index/limit:{limit}"
    if galaxy:
        path += f"/searchall:{galaxy}"
    data = _get(path)
    clusters = data if isinstance(data, list) else data.get("response", data.get("GalaxyCluster", [])) or []
    if not isinstance(clusters, list):
        clusters = [clusters]
    return {"clusters": [{"id": c.get("id"), "value": c.get("value"), "description": c.get("description")} if isinstance(c, dict) else c for c in clusters[:limit]], "count": len(clusters)}


def _run_get_event_galaxies(event_id: str) -> dict:
    data = _get(f"/events/view/{event_id}/galaxy:1")
    ev = data.get("Event", {})
    galaxies = ev.get("Galaxy", []) or []
    return {"event_id": event_id, "galaxies": galaxies}


def _run_delete_event(event_id: str) -> dict:
    _delete(f"/events/{event_id}")
    return {"deleted": True, "event_id": event_id}


# ---------------------------------------------------------------------------
# Tool name -> handler mapping (kwargs from MCP arguments; "type" -> attr_type)
# ---------------------------------------------------------------------------

def _call_add_attribute(**kwargs: Any) -> dict:
    return _run_add_attribute(
        kwargs.get("event_id", ""),
        kwargs.get("type", ""),
        kwargs.get("value", ""),
        kwargs.get("category", ""),
        kwargs.get("to_ids", True),
        kwargs.get("comment", ""),
    )


def _call_add_sighting(**kwargs: Any) -> dict:
    return _run_add_sighting(kwargs.get("attribute_id", ""), kwargs.get("type", 0))


HANDLERS: dict[str, callable] = {
    "get_malicious_ips": lambda **_: _run_get_malicious_ips(),
    "get_malicious_domains": lambda **_: _run_get_malicious_domains(),
    "get_malicious_hashes": lambda hash_type="all", **_: _run_get_malicious_hashes(hash_type),
    "search_ip_in_misp": lambda ip, **_: _run_search_ip(ip),
    "search_attribute": lambda value, **kw: _run_search_attribute(value, kw.get("type")),
    "get_threat_details": lambda ip, **_: _run_get_threat_details(ip),
    "list_misp_events": lambda limit=10, **_: _run_list_events(limit),
    "get_event": lambda event_id, **_: _run_get_event(event_id),
    "get_event_indicators": lambda event_id, **_: _run_get_event_indicators(event_id),
    "search_events": lambda tags=None, type=None, value=None, last=None, published=None, limit=20, page=1, **_: _run_search_events(tags=tags, type_=type, value=value, last=last, published=published, limit=limit, page=page),
    "search_attributes": lambda type=None, category=None, value=None, tags=None, to_ids=None, last=None, limit=50, page=1, **_: _run_search_attributes(type_=type, category=category, value=value, tags=tags, to_ids=to_ids, last=last, limit=limit, page=page),
    "add_event": lambda info, distribution=0, threat_level_id=4, analysis=0, **_: _run_add_event(info, distribution, threat_level_id, analysis),
    "add_attribute": _call_add_attribute,
    "publish_event": lambda event_id, **_: _run_publish_event(event_id),
    "add_sighting": _call_add_sighting,
    "add_tag_to_event": lambda event_id, tag, **_: _run_add_tag_to_event(event_id, tag),
    "list_tags": lambda search=None, limit=100, **_: _run_list_tags(search, limit),
    "list_feeds": lambda **_: _run_list_feeds(),
    "list_galaxy_clusters": lambda galaxy=None, limit=50, **_: _run_list_galaxy_clusters(galaxy, limit),
    "get_event_galaxies": lambda event_id, **_: _run_get_event_galaxies(event_id),
    "delete_event": lambda event_id, **_: _run_delete_event(event_id),
}


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    if not MISP_API_KEY:
        return [types.TextContent(type="text", text="Error: MISP_API_KEY environment variable is not set.")]
    if name not in HANDLERS:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    try:
        result = HANDLERS[name](**arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
    except requests.HTTPError as e:
        try:
            err_body = e.response.text
        except Exception:
            err_body = str(e)
        return [types.TextContent(type="text", text=f"HTTP Error: {e.response.status_code} - {err_body}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="misp-mcp-server",
                server_version="1.0",
                capabilities=server.get_capabilities(
                    NotificationOptions(),
                    {},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
