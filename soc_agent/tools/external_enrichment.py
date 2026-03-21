"""External threat intelligence enrichment tools (VirusTotal, AbuseIPDB, Shodan).

All use free-tier APIs. If an API key is not configured, the tool returns
a helpful message instead of failing.
"""

import json
import httpx
from langchain_core.tools import tool
from soc_agent.config.settings import settings

_TIMEOUT = 15


def _no_key_msg(service: str) -> str:
    return json.dumps({
        "error": f"{service} API key not configured. Set {service.upper()}_API_KEY in .env",
        "data": None,
    })


@tool
def virustotal_lookup(ioc: str, ioc_type: str = "ip") -> str:
    """Query VirusTotal for reputation data on an IP, domain, or file hash.
    ioc_type: 'ip', 'domain', 'hash'. Free tier: 500 lookups/day."""
    if not settings.VIRUSTOTAL_API_KEY:
        return _no_key_msg("VirusTotal")

    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = endpoints.get(ioc_type)
    if not url:
        return json.dumps({"error": f"Unknown ioc_type: {ioc_type}"})

    try:
        resp = httpx.get(
            url,
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        analysis = data.get("last_analysis_stats", {})
        total = sum(analysis.values()) or 1
        malicious = analysis.get("malicious", 0)

        return json.dumps({
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malicious_count": malicious,
            "total_engines": total,
            "malicious_ratio": round(malicious / total, 3),
            "reputation": data.get("reputation", "N/A"),
            "tags": data.get("tags", []),
            "last_analysis_stats": analysis,
            "country": data.get("country", ""),
            "as_owner": data.get("as_owner", ""),
        }, indent=2)
    except httpx.HTTPStatusError as e:
        return json.dumps({"error": f"VT HTTP {e.response.status_code}", "ioc": ioc})
    except Exception as e:
        return json.dumps({"error": str(e), "ioc": ioc})


@tool
def abuseipdb_lookup(ip: str) -> str:
    """Query AbuseIPDB for IP abuse confidence score and report history.
    Free tier: 1000 checks/day."""
    if not settings.ABUSEIPDB_API_KEY:
        return _no_key_msg("AbuseIPDB")

    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return json.dumps({
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported_at": data.get("lastReportedAt", ""),
            "usage_type": data.get("usageType", ""),
        }, indent=2)
    except httpx.HTTPStatusError as e:
        return json.dumps({"error": f"AbuseIPDB HTTP {e.response.status_code}", "ip": ip})
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})


@tool
def shodan_lookup(ip: str) -> str:
    """Query Shodan for open ports, services, and banners on an IP.
    Provides infrastructure context for threat hunting."""
    if not settings.SHODAN_API_KEY:
        return _no_key_msg("Shodan")

    try:
        resp = httpx.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": settings.SHODAN_API_KEY},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        return json.dumps({
            "ip": ip,
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "os": data.get("os", ""),
            "organization": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "last_update": data.get("last_update", ""),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
        }, indent=2)
    except httpx.HTTPStatusError as e:
        return json.dumps({"error": f"Shodan HTTP {e.response.status_code}", "ip": ip})
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})


ENRICHMENT_TOOLS = [virustotal_lookup, abuseipdb_lookup, shodan_lookup]
