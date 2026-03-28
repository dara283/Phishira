from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime


class ScanRequest(BaseModel):
    input_value: str
    input_type: str = "auto"  # auto, url, email, phone


class RedirectHop(BaseModel):
    url: str
    status_code: int
    headers: Dict[str, str] = {}


class URLAnalysisResult(BaseModel):
    url: str
    domain: str
    tld: str
    is_https: bool
    domain_age_days: Optional[int]
    registrar: Optional[str]
    country: Optional[str]
    ip_address: Optional[str]
    redirect_chain: List[RedirectHop] = []
    has_login_form: bool = False
    suspicious_keywords: List[str] = []
    ssl_valid: bool = False
    virustotal_positives: int = 0
    google_safe_browsing: bool = False
    domain_risk: float = 0.0
    content_risk: float = 0.0
    api_behavior_risk: float = 0.0
    forms: List[Dict[str, Any]] = []
    external_requests: List[str] = []


class EmailAnalysisResult(BaseModel):
    email: str
    domain: str
    is_disposable: bool = False
    domain_age_days: Optional[int]
    spf_valid: bool = False
    dmarc_valid: bool = False
    mx_valid: bool = False
    suspicious_keywords: List[str] = []
    links_found: List[str] = []


class PhoneAnalysisResult(BaseModel):
    phone: str
    country: Optional[str]
    carrier: Optional[str]
    is_valid: bool = False
    is_voip: bool = False
    spam_reports: int = 0
    links_found: List[str] = []


class ScanResponse(BaseModel):
    id: Optional[int]
    input_value: str
    input_type: str
    risk_score: float
    risk_level: str
    explanation: List[str]
    details: Dict[str, Any]
    created_at: datetime


class ScanHistoryItem(BaseModel):
    id: int
    input_value: str
    input_type: str
    risk_score: float
    risk_level: str
    created_at: datetime

    class Config:
        from_attributes = True
