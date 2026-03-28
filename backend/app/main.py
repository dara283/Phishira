import os
import re
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from .database import get_db, init_db, ScanRecord
from .models import ScanRequest, ScanResponse, ScanHistoryItem
from .detectors import url_detector, email_detector, threat_intel
from .detectors.headless_scanner import scan_page_behaviour
from .detectors.report_generator import generate_json_report, generate_pdf_report

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Phishara API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Input type detection
EMAIL_TEXT_RE = re.compile(r"https?://\S+|www\.\S+")  # has links = email text
EMAIL_ADDR_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def detect_input_type(value: str) -> str:
    v = value.strip()
    # Multi-line or contains links → treat as email text
    if "\n" in v or (len(v) > 100 and EMAIL_TEXT_RE.search(v)):
        return "email"
    if EMAIL_ADDR_RE.match(v):
        return "email"
    return "url"


@app.get("/health")
def health():
    return {"status": "ok", "service": "Phishara API"}


# ── Main scan endpoint ────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, request: Request, db: Session = Depends(get_db)):
    input_type = req.input_type if req.input_type != "auto" else detect_input_type(req.input_value)
    explanation = []
    details = {}
    risk_score = 0.0
    risk_lvl = "unknown"

    if input_type == "url":
        result = await url_detector.analyze_url(req.input_value)
        ti = await threat_intel.run_all_checks(req.input_value)
        result.update(ti)
        risk_score = url_detector.compute_overall_score(
            result["domain_risk"], result["content_risk"], result["api_behavior_risk"], ti
        )
        risk_lvl = url_detector.risk_level(risk_score)
        explanation = url_detector.build_explanation(result, risk_score)
        details = result

    elif input_type == "email":
        # Extract sender from first line if it looks like an email address
        lines = req.input_value.strip().split("\n")
        sender = ""
        for line in lines[:3]:
            line = line.strip()
            if "@" in line and len(line) < 80:
                import re as _re
                m = _re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', line)
                if m:
                    sender = m.group(0)
                    break

        email_result = email_detector.analyze_email_text(req.input_value, sender=sender)

        # Scan each extracted link individually against malware databases + heuristics
        link_results = []
        for link in email_result["links_found"][:10]:
            try:
                lr = await url_detector.analyze_url(link)
                ti = await threat_intel.run_all_checks(link)
                lr.update(ti)
                link_score = url_detector.compute_overall_score(
                    lr["domain_risk"], lr["content_risk"], lr["api_behavior_risk"], ti
                )
                link_results.append({
                    "url": link,
                    "risk_score": round(link_score, 1),
                    "risk_level": url_detector.risk_level(link_score),
                    "findings": url_detector.build_explanation(lr, link_score),
                    # Include key threat intel flags for display
                    "malware_db_hit": ti.get("any_flagged", False),
                    "sources_flagged": ti.get("sources_flagged", []),
                })
            except Exception as e:
                link_results.append({
                    "url": link, "risk_score": 0,
                    "risk_level": "unknown", "findings": [str(e)],
                    "malware_db_hit": False, "sources_flagged": [],
                })

        email_result["link_scan_results"] = link_results

        # Overall score = worst link score weighted with content risk
        max_link_score = max((lr["risk_score"] for lr in link_results), default=0.0)
        risk_score = round(min((max_link_score * 0.75) + (email_result["content_risk"] * 0.25), 100), 1)
        risk_lvl = url_detector.risk_level(risk_score)
        explanation = email_detector.build_explanation(email_result, link_results)
        details = email_result

    record = ScanRecord(
        input_value=req.input_value[:500],  # truncate long email texts for DB
        input_type=input_type,
        risk_score=risk_score,
        risk_level=risk_lvl,
        details=details,
        ip_address=request.client.host if request.client else None
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return ScanResponse(
        id=record.id,
        input_value=req.input_value[:500],
        input_type=input_type,
        risk_score=risk_score,
        risk_level=risk_lvl,
        explanation=explanation,
        details=details,
        created_at=record.created_at
    )


# ── Headless browser scan endpoint ───────────────────────────────────────────

class HeadlessScanRequest(BaseModel):
    url: str

@app.post("/api/scan/headless")
async def headless_scan(req: HeadlessScanRequest):
    """
    Opens the URL in a real headless browser and analyses page behaviour.
    Returns verdict: Safe | Suspicious | Dangerous
    """
    if not req.url.startswith(("http://", "https://")):
        req.url = "http://" + req.url
    result = await scan_page_behaviour(req.url)
    return result


# ── History / stats / reports ─────────────────────────────────────────────────

@app.get("/api/history", response_model=List[ScanHistoryItem])
def get_history(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    input_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    q = db.query(ScanRecord)
    if input_type:
        q = q.filter(ScanRecord.input_type == input_type)
    return q.order_by(ScanRecord.created_at.desc()).offset(offset).limit(limit).all()


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(ScanRecord).count()
    by_level = {lvl: db.query(ScanRecord).filter(ScanRecord.risk_level == lvl).count()
                for lvl in ["safe", "low", "medium", "high", "critical"]}
    by_type = {t: db.query(ScanRecord).filter(ScanRecord.input_type == t).count()
               for t in ["url", "email"]}
    return {"total": total, "by_level": by_level, "by_type": by_type}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@app.get("/api/report/{scan_id}")
def download_report(scan_id: int, fmt: str = Query("json"), db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = {
        "id": record.id,
        "input_value": record.input_value,
        "input_type": record.input_type,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "details": record.details,
        "created_at": str(record.created_at),
        "explanation": record.details.get("explanation", []) if record.details else []
    }

    if fmt == "pdf":
        return Response(
            content=generate_pdf_report(scan_data),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=phishara_report_{scan_id}.pdf"}
        )

    return Response(
        content=generate_json_report(scan_data),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=phishara_report_{scan_id}.json"}
    )
