"""
Threat Intelligence — Phishara
================================
Uses multiple FREE sources — no VirusTotal needed.

Sources used:
  1. Google Safe Browsing v4  — Google's malware/phishing DB (free key, 10k/day)
  2. URLhaus (abuse.ch)       — Community malware URL database (no key needed)
  3. PhishTank               — Crowdsourced phishing database (no key needed)
  4. OpenPhish                — Live phishing feed (no key needed)
  5. DNS blocklists           — SURBL / URIBL domain reputation (no key needed)

To enable Google Safe Browsing, add to phishara/backend/.env:
  GOOGLE_SAFE_BROWSING_API_KEY=your_key
  Get it free at: https://console.cloud.google.com → Enable "Safe Browsing API" → Credentials → API Key
"""

import os
import dns.resolver
import httpx
from typing import Dict, Any, Tuple
from urllib.parse import urlparse
import tldextract


# ── Google Safe Browsing ──────────────────────────────────────────────────────

async def check_google_safe_browsing(url: str) -> Tuple[bool, str]:
    """Returns (is_flagged, threat_type). Free: 10,000 req/day."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return False, ""

    payload = {
        "client": {"clientId": "phishara", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=payload,
            )
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    types = [m.get("threatType", "") for m in matches]
                    return True, ",".join(types)
    except Exception:
        pass
    return False, ""


# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────

async def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    URLhaus is a free community database of malware distribution URLs.
    No API key required. https://urlhaus-api.abuse.ch/
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "is_listed":
                    return {
                        "found": True,
                        "threat": data.get("threat", "malware"),
                        "tags": data.get("tags") or [],
                        "date_added": data.get("date_added", ""),
                        "url_status": data.get("url_status", ""),
                    }
                return {"found": False}
    except Exception:
        pass
    return {"found": False, "error": "unavailable"}


# ── PhishTank ─────────────────────────────────────────────────────────────────

async def check_phishtank(url: str) -> Dict[str, Any]:
    """
    PhishTank is a free crowdsourced phishing database.
    No key required for basic lookups. https://www.phishtank.com/
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"},
                headers={"User-Agent": "phishara/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", {})
                if results.get("in_database") and results.get("valid"):
                    return {
                        "found": True,
                        "verified": results.get("verified", False),
                        "phish_id": results.get("phish_id", ""),
                    }
                return {"found": False}
    except Exception:
        pass
    return {"found": False, "error": "unavailable"}


# ── OpenPhish ─────────────────────────────────────────────────────────────────

_openphish_cache: set = set()
_openphish_loaded = False

async def check_openphish(url: str) -> bool:
    """
    OpenPhish publishes a free live feed of active phishing URLs.
    We load it once and check in-memory. https://openphish.com/
    """
    global _openphish_cache, _openphish_loaded
    if not _openphish_loaded:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get("https://openphish.com/feed.txt")
                if resp.status_code == 200:
                    _openphish_cache = set(resp.text.strip().splitlines())
                    _openphish_loaded = True
        except Exception:
            pass

    return url in _openphish_cache or any(url.startswith(u) for u in _openphish_cache)


# ── DNS Blocklist checks ──────────────────────────────────────────────────────

DNSBL_LISTS = [
    "multi.surbl.org",    # SURBL — spam/malware domains
    "dbl.spamhaus.org",   # Spamhaus Domain Block List
    "uribl.com",          # URIBL — URI reputation
]

def check_dns_blocklist(domain: str) -> Dict[str, Any]:
    """
    Check domain against DNS-based blocklists.
    These are free, no key needed, and very fast.
    """
    flagged_by = []
    ext = tldextract.extract(domain)
    lookup_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    for bl in DNSBL_LISTS:
        query = f"{lookup_domain}.{bl}"
        try:
            dns.resolver.resolve(query, "A")
            flagged_by.append(bl.split(".")[0].upper())  # e.g. "SURBL"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception:
            pass

    return {"flagged": len(flagged_by) > 0, "flagged_by": flagged_by}


# ── Combined check ────────────────────────────────────────────────────────────

async def run_all_checks(url: str) -> Dict[str, Any]:
    """
    Run all available threat intelligence checks and return combined results.
    Called from main.py scan endpoint.
    """
    import asyncio

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]

    # Run async checks in parallel
    gsb_task      = check_google_safe_browsing(url)
    urlhaus_task  = check_urlhaus(url)
    phishtank_task = check_phishtank(url)
    openphish_task = check_openphish(url)

    gsb_result, urlhaus_result, phishtank_result, openphish_result = await asyncio.gather(
        gsb_task, urlhaus_task, phishtank_task, openphish_task,
        return_exceptions=True
    )

    # DNS check is sync — run it directly
    dns_result = check_dns_blocklist(domain)

    # Normalise exception results
    if isinstance(gsb_result, Exception):       gsb_result = (False, "")
    if isinstance(urlhaus_result, Exception):   urlhaus_result = {"found": False}
    if isinstance(phishtank_result, Exception): phishtank_result = {"found": False}
    if isinstance(openphish_result, Exception): openphish_result = False

    gsb_flagged, gsb_threat_type = gsb_result

    return {
        "google_safe_browsing": gsb_flagged,
        "gsb_threat_type": gsb_threat_type,
        "urlhaus": urlhaus_result,
        "phishtank": phishtank_result,
        "openphish": openphish_result,
        "dns_blocklist": dns_result,
        # Convenience: is it flagged by ANY source?
        "any_flagged": (
            gsb_flagged
            or urlhaus_result.get("found", False)
            or phishtank_result.get("found", False)
            or openphish_result is True
            or dns_result.get("flagged", False)
        ),
        "sources_flagged": _sources_list(
            gsb_flagged, urlhaus_result, phishtank_result,
            openphish_result, dns_result
        ),
    }


def _sources_list(gsb, urlhaus, phishtank, openphish, dns) -> list:
    sources = []
    if gsb:
        sources.append("Google Safe Browsing")
    if urlhaus.get("found"):
        sources.append("URLhaus (abuse.ch)")
    if phishtank.get("found"):
        sources.append("PhishTank")
    if openphish is True:
        sources.append("OpenPhish")
    if dns.get("flagged"):
        sources.extend(dns.get("flagged_by", []))
    return sources


# Keep for backward compat
async def check_virustotal(url: str) -> Dict[str, Any]:
    return {"available": False, "positives": 0, "total": 0,
            "note": "VirusTotal removed — using free alternatives"}
