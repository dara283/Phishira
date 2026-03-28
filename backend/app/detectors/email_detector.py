"""
Email Text Detector — Phishara
================================
Takes the full text of an email (paste the whole thing in).
Extracts every link found in the text, scans each one,
and returns a verdict per link plus an overall email risk.
"""

import re
import dns.resolver
from typing import Dict, List, Any

# Regex to pull every URL out of raw text
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Words that create urgency / pressure — common in phishing emails
URGENCY_WORDS = [
    "urgent", "immediately", "verify", "confirm", "suspended",
    "unusual activity", "limited time", "act now", "click here",
    "your account", "has been locked", "update your", "expires",
    "congratulations", "you have won", "prize", "free gift",
    "invoice attached", "payment required", "refund", "overdue",
]

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "maildrop.cc",
    "trashmail.com", "dispostable.com", "spam4.me",
}


def extract_links(text: str) -> List[str]:
    """Pull all URLs out of raw email text."""
    links = URL_PATTERN.findall(text)
    # Normalise — add http:// to bare www. links
    normalised = []
    for link in links:
        link = link.rstrip(".,;:!?)")  # strip trailing punctuation
        if link.startswith("www."):
            link = "http://" + link
        normalised.append(link)
    return list(dict.fromkeys(normalised))  # deduplicate, preserve order


def analyze_email_text(text: str, sender: str = "") -> Dict[str, Any]:
    """
    Analyse the full text of an email.
    Returns extracted links, urgency signals, sender checks,
    and an overall risk assessment.
    The caller (main.py) will scan each link individually.
    """
    text_lower = text.lower()

    result: Dict[str, Any] = {
        "input_type": "email",
        "links_found": extract_links(text),
        "link_count": 0,
        "urgency_words_found": [],
        "sender": sender,
        "sender_domain": "",
        "sender_disposable": False,
        "sender_spf": False,
        "sender_dmarc": False,
        "domain_risk": 0.0,
        "content_risk": 0.0,
    }

    result["link_count"] = len(result["links_found"])

    # Urgency / pressure language
    result["urgency_words_found"] = [
        w for w in URGENCY_WORDS if w in text_lower
    ]

    # Sender domain checks (if sender provided)
    if sender and "@" in sender:
        domain = sender.split("@")[-1].lower().strip()
        result["sender_domain"] = domain
        result["sender_disposable"] = domain in DISPOSABLE_DOMAINS

        try:
            spf = dns.resolver.resolve(domain, "TXT")
            result["sender_spf"] = any("v=spf1" in str(r) for r in spf)
        except Exception:
            pass

        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            result["sender_dmarc"] = any("v=DMARC1" in str(r) for r in dmarc)
        except Exception:
            pass

    result["domain_risk"] = _calc_domain_risk(result)
    result["content_risk"] = _calc_content_risk(result)

    return result


def _calc_domain_risk(r: Dict) -> float:
    score = 0.0
    if r["sender_disposable"]:
        score += 50
    if r["sender_domain"] and not r["sender_spf"]:
        score += 15
    if r["sender_domain"] and not r["sender_dmarc"]:
        score += 10
    return min(score, 100.0)


def _calc_content_risk(r: Dict) -> float:
    score = 0.0
    score += min(len(r["urgency_words_found"]) * 10, 40)
    score += min(r["link_count"] * 5, 30)
    return min(score, 100.0)


def build_explanation(result: Dict, link_results: List[Dict] = None) -> List[str]:
    reasons = []

    # Link findings (most important)
    if link_results:
        dangerous = [lr for lr in link_results if lr.get("risk_level") in ("high", "critical")]
        suspicious = [lr for lr in link_results if lr.get("risk_level") in ("medium", "low")]
        if dangerous:
            reasons.append(
                f"{len(dangerous)} link(s) in this email are dangerous — "
                f"do not click: {', '.join(lr['url'] for lr in dangerous[:3])}"
            )
        if suspicious:
            reasons.append(
                f"{len(suspicious)} link(s) look suspicious and should be treated with caution"
            )

    if result["link_count"] == 0:
        reasons.append("No links were found in this email text")
    elif result["link_count"] > 5:
        reasons.append(
            f"This email contains {result['link_count']} links — "
            "a high number of links is common in phishing emails"
        )

    if result["urgency_words_found"]:
        sample = result["urgency_words_found"][:3]
        reasons.append(
            f"This email uses pressure language to make you act fast: "
            f"\"{', '.join(sample)}\" — a classic scam tactic"
        )

    if result["sender_disposable"]:
        reasons.append(
            "The sender is using a temporary, throwaway email address — "
            "legitimate companies don't do this"
        )

    if result["sender_domain"] and not result["sender_spf"]:
        reasons.append(
            "The sender's email domain has no anti-spoofing protection — "
            "anyone could fake emails from this address"
        )

    if not reasons:
        reasons.append("Nothing suspicious was found in this email")

    return reasons
