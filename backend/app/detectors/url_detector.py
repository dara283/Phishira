"""
URL Detector — Phishara
=======================
Detection layers (in order of reliability):
  1. VirusTotal API  — 70+ AV engines, most reliable. Free: 4 req/min.
  2. Google Safe Browsing API — Google's own malware/phishing DB. Free: 10k req/day.
  3. Heuristic scoring — domain age, TLD, keywords, SSL, redirects, forms.
     Used as fallback when API keys are not set, or to supplement them.

To enable real detection, add to phishara/backend/.env:
  VIRUSTOTAL_API_KEY=<your key from https://www.virustotal.com/gui/my-apikey>
  GOOGLE_SAFE_BROWSING_API_KEY=<your key from https://console.cloud.google.com>
"""

import re
import ssl
import socket
import hashlib
import httpx
import tldextract
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from urllib.parse import urlparse

# ── Heuristic data ────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "banking", "paypal",
    "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "netflix", "password", "credential", "wallet", "crypto", "bitcoin",
    "urgent", "suspended", "limited", "unusual", "activity", "click",
    "free", "prize", "winner", "congratulations", "ebay", "dhl", "fedex",
    "invoice", "refund", "support", "helpdesk", "webscr", "cmd=",
]

# TLDs heavily abused by phishing campaigns (data: APWG, Spamhaus)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom — most abused
    ".xyz", ".top", ".click", ".link",
    ".work", ".date", ".racing", ".win",
    ".download", ".stream", ".gdn",
}

# Brands commonly impersonated — if domain doesn't match, flag it
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "ebay": "ebay.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
}

# IP address in URL (e.g. http://192.168.1.1/login)
IP_IN_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# Homoglyph / typosquat patterns (e.g. paypa1, g00gle)
HOMOGLYPH = re.compile(r"(paypa[^l]|g[o0]{2}gle|micros[o0]ft|app[l1]e|faceb[o0]{2}k|amaz[o0]n)")


async def analyze_url(url: str) -> Dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    tld = f".{ext.suffix}" if ext.suffix else ""
    url_lower = url.lower()

    result: Dict[str, Any] = {
        "url": url,
        "domain": domain,
        "tld": tld,
        "subdomain": ext.subdomain,
        "is_https": parsed.scheme == "https",
        "url_length": len(url),
        "domain_age_days": None,
        "registrar": None,
        "country": None,
        "ip_address": None,
        "redirect_chain": [],
        "has_login_form": False,
        "suspicious_keywords": [],
        "ssl_valid": False,
        "forms": [],
        "external_requests": [],
        "brand_impersonation": None,
        "ip_in_url": bool(IP_IN_URL.match(url)),
        "homoglyph_detected": bool(HOMOGLYPH.search(url_lower)),
        "domain_risk": 0.0,
        "content_risk": 0.0,
        "api_behavior_risk": 0.0,
    }

    # ── Keyword scan ──────────────────────────────────────────────────────────
    result["suspicious_keywords"] = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    # ── Brand impersonation check ─────────────────────────────────────────────
    for brand, legit in BRAND_DOMAINS.items():
        if brand in url_lower and legit not in domain:
            result["brand_impersonation"] = brand
            break

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    try:
        w = whois.whois(domain)
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if cd:
                result["domain_age_days"] = (datetime.utcnow() - cd).days
        result["registrar"] = str(w.registrar) if w.registrar else None
        result["country"] = str(w.country) if w.country else None
    except Exception:
        pass

    # ── DNS / IP ──────────────────────────────────────────────────────────────
    try:
        result["ip_address"] = socket.gethostbyname(parsed.netloc.split(":")[0])
    except Exception:
        pass

    # ── SSL ───────────────────────────────────────────────────────────────────
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=parsed.netloc) as s:
                s.settimeout(5)
                s.connect((parsed.netloc, 443))
                result["ssl_valid"] = True
        except Exception:
            result["ssl_valid"] = False

    # ── Fetch page + redirect chain ───────────────────────────────────────────
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=12, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        ) as client:
            response = await client.get(url)

            for r in response.history:
                result["redirect_chain"].append({
                    "url": str(r.url), "status_code": r.status_code,
                    "headers": dict(r.headers)
                })
            result["redirect_chain"].append({
                "url": str(response.url), "status_code": response.status_code,
                "headers": dict(response.headers)
            })

            soup = BeautifulSoup(response.text, "lxml")

            # Forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                inputs = [{"name": i.get("name", ""), "type": i.get("type", "text")}
                          for i in form.find_all("input")]
                has_pw = any(i["type"] == "password" for i in inputs)
                result["forms"].append({
                    "action": action, "method": form.get("method", "get"),
                    "inputs": inputs, "has_password_field": has_pw
                })
                if has_pw:
                    result["has_login_form"] = True

            # External scripts
            for s in soup.find_all("script", src=True):
                src = s.get("src", "")
                if src and domain not in src:
                    result["external_requests"].append(src)

            # Page title / meta keywords for brand impersonation
            title = soup.find("title")
            if title and result["brand_impersonation"] is None:
                title_lower = title.get_text().lower()
                for brand, legit in BRAND_DOMAINS.items():
                    if brand in title_lower and legit not in domain:
                        result["brand_impersonation"] = brand
                        break

    except Exception as e:
        result["fetch_error"] = str(e)

    # ── Scores ────────────────────────────────────────────────────────────────
    result["domain_risk"] = _calc_domain_risk(result)
    result["content_risk"] = _calc_content_risk(result)
    result["api_behavior_risk"] = _calc_api_risk(result)

    return result


def _calc_domain_risk(r: Dict) -> float:
    score = 0.0

    if not r["is_https"]:
        score += 25                          # no encryption at all
    if not r["ssl_valid"] and r["is_https"]:
        score += 25                          # broken/self-signed cert

    age = r.get("domain_age_days")
    if age is not None:
        if age < 7:    score += 50           # brand new — very suspicious
        elif age < 30: score += 35
        elif age < 90: score += 20
        elif age < 180: score += 10
    else:
        score += 15                          # can't verify age — penalise

    if r["tld"] in SUSPICIOUS_TLDS:
        score += 30

    if r["ip_in_url"]:
        score += 40                          # IP address instead of domain name

    if r["homoglyph_detected"]:
        score += 35                          # typosquatting

    if r.get("brand_impersonation"):
        score += 45                          # pretending to be a known brand

    if r["url_length"] > 100:
        score += 10
    if r["url_length"] > 150:
        score += 10

    # Deep subdomain (e.g. paypal.com.evil.tk)
    sub = r.get("subdomain", "")
    if sub and len(sub.split(".")) >= 2:
        score += 20

    return min(score, 100.0)


def _calc_content_risk(r: Dict) -> float:
    score = 0.0

    score += min(len(r["suspicious_keywords"]) * 7, 35)

    if r["has_login_form"]:
        score += 30

    # Form submitting to external domain
    for form in r.get("forms", []):
        action = form.get("action", "")
        if action and action.startswith("http") and r["domain"] not in action:
            score += 30                      # credentials sent elsewhere

    hops = len(r.get("redirect_chain", []))
    if hops > 2: score += 10
    if hops > 4: score += 15
    if hops > 6: score += 15

    return min(score, 100.0)


def _calc_api_risk(r: Dict) -> float:
    score = 0.0
    score += min(len(r.get("external_requests", [])) * 4, 25)
    if len(r.get("redirect_chain", [])) > 5:
        score += 20
    return min(score, 100.0)


def compute_overall_score(
    domain_risk: float, content_risk: float, api_risk: float,
    ti: dict = None
) -> float:
    """
    Combine heuristic scores with free threat intelligence sources.
    Any confirmed hit from a real database immediately pushes score high.
    """
    ti = ti or {}
    heuristic = round((domain_risk * 0.45) + (content_risk * 0.40) + (api_risk * 0.15), 1)

    # Google Safe Browsing — authoritative, trust it fully
    if ti.get("google_safe_browsing"):
        gsb_type = ti.get("gsb_threat_type", "")
        base = 95.0 if "MALWARE" in gsb_type else 90.0
        return round(max(base, heuristic), 1)

    # URLhaus — confirmed malware distribution URL
    if ti.get("urlhaus", {}).get("found"):
        return round(max(92.0, heuristic), 1)

    # PhishTank — verified phishing
    if ti.get("phishtank", {}).get("found") and ti["phishtank"].get("verified"):
        return round(max(90.0, heuristic), 1)

    # OpenPhish — active phishing feed
    if ti.get("openphish"):
        return round(max(88.0, heuristic), 1)

    # DNS blocklist — domain reputation
    if ti.get("dns_blocklist", {}).get("flagged"):
        return round(max(75.0, heuristic), 1)

    return heuristic


def risk_level(score: float) -> str:
    if score < 20:  return "safe"
    if score < 40:  return "low"
    if score < 60:  return "medium"
    if score < 80:  return "high"
    return "critical"


def build_explanation(result: Dict, score: float) -> List[str]:
    reasons = []

    # ── Real threat database hits (most important) ────────────────────────────
    sources = result.get("sources_flagged", [])
    if sources:
        reasons.append(
            f"This link is in known scam/malware databases: {', '.join(sources)}"
        )

    if result.get("google_safe_browsing"):
        gsb_type = result.get("gsb_threat_type", "")
        label = "malware" if "MALWARE" in gsb_type else "phishing or a scam site"
        reasons.append(f"Google has confirmed this is {label} — do not visit it")

    urlhaus = result.get("urlhaus", {})
    if urlhaus.get("found"):
        threat = urlhaus.get("threat", "malware")
        reasons.append(f"This URL is listed on URLhaus as a {threat} distribution site")

    if result.get("phishtank", {}).get("found"):
        reasons.append("This URL has been reported as a phishing site on PhishTank")

    if result.get("openphish"):
        reasons.append("This URL is on the OpenPhish live phishing feed")

    dns_bl = result.get("dns_blocklist", {})
    if dns_bl.get("flagged"):
        bl_names = ", ".join(dns_bl.get("flagged_by", []))
        reasons.append(f"This domain is blocked by {bl_names} — known for spam or malware")

    # ── Heuristic findings ────────────────────────────────────────────────────
    if result.get("brand_impersonation"):
        brand = result["brand_impersonation"].capitalize()
        reasons.append(
            f"This site is pretending to be {brand} but it's not the real {brand} website"
        )

    if result.get("homoglyph_detected"):
        reasons.append(
            "The web address uses look-alike letters to trick you (e.g. 'paypa1' instead of 'paypal')"
        )

    if result.get("ip_in_url"):
        reasons.append(
            "The link uses a raw IP address instead of a website name — legitimate sites don't do this"
        )

    if not result.get("is_https"):
        reasons.append("This link is not secure — your information could be intercepted")

    if not result.get("ssl_valid") and result.get("is_https"):
        reasons.append("The security certificate is invalid — this site may be impersonating another")

    age = result.get("domain_age_days")
    if age is not None and age < 30:
        reasons.append(
            f"This website was only created {age} days ago — scammers often use brand-new sites"
        )
    elif age is not None and age < 90:
        reasons.append(f"This website is quite new ({age} days old) — treat it with caution")

    if result.get("tld") in SUSPICIOUS_TLDS:
        reasons.append(
            f"The website ending '{result['tld']}' is very commonly used in scam sites"
        )

    if result.get("has_login_form"):
        reasons.append(
            "This page asks for your username or password — make sure you fully trust it first"
        )

    kw = result.get("suspicious_keywords", [])
    if kw:
        reasons.append(f"The link contains words often used in scams: {', '.join(kw[:4])}")

    hops = len(result.get("redirect_chain", []))
    if hops > 4:
        reasons.append(
            f"You get bounced through {hops} different sites before reaching the destination — "
            "a common trick used by scammers"
        )

    if not reasons:
        reasons.append("Nothing suspicious was found — this looks safe to use")

    return reasons
