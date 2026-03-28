import re
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
from typing import Dict, List, Any

URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "verify", "confirm", "prize",
    "winner", "free", "click", "limited", "offer", "expires", "act now",
    "account", "blocked", "unusual", "activity", "bank", "otp", "code"
]


def analyze_phone(phone: str, message: str = "") -> Dict[str, Any]:
    result = {
        "phone": phone,
        "country": None,
        "carrier": None,
        "is_valid": False,
        "is_voip": False,
        "line_type": None,
        "spam_reports": 0,
        "links_found": [],
        "urgency_keywords": [],
        "domain_risk": 0.0,
        "content_risk": 0.0,
    }

    try:
        parsed = phonenumbers.parse(phone, None)
        result["is_valid"] = phonenumbers.is_valid_number(parsed)
        result["country"] = geocoder.description_for_number(parsed, "en")
        result["carrier"] = carrier.name_for_number(parsed, "en")

        ntype = number_type(parsed)
        result["line_type"] = str(ntype)
        result["is_voip"] = ntype in (
            PhoneNumberType.VOIP,
            PhoneNumberType.UNKNOWN,
        )
    except Exception as e:
        result["error"] = str(e)

    if message:
        msg_lower = message.lower()
        result["urgency_keywords"] = [kw for kw in URGENCY_KEYWORDS if kw in msg_lower]
        result["links_found"] = URL_PATTERN.findall(message)

    result["domain_risk"] = _calc_domain_risk(result)
    result["content_risk"] = _calc_content_risk(result)
    return result


def _calc_domain_risk(r: Dict) -> float:
    score = 0.0
    if not r["is_valid"]:
        score += 30
    if r["is_voip"]:
        score += 25
    return min(score, 100.0)


def _calc_content_risk(r: Dict) -> float:
    score = 0.0
    score += len(r["urgency_keywords"]) * 12
    score += min(len(r["links_found"]) * 10, 40)
    return min(score, 100.0)


def build_explanation(result: Dict) -> List[str]:
    reasons = []
    if not result.get("is_valid"):
        reasons.append("Phone number format is invalid")
    if result.get("is_voip"):
        reasons.append("Number appears to be VoIP — commonly used in scam calls")
    if result.get("urgency_keywords"):
        reasons.append(f"Urgency/threat language detected: {', '.join(result['urgency_keywords'][:5])}")
    if result.get("links_found"):
        reasons.append(f"{len(result['links_found'])} link(s) found in message")
    if not reasons:
        reasons.append("No major phishing indicators detected")
    return reasons
