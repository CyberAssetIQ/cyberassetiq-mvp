"""
CyberAssetIQ AI Guide Router
Matches the import and auth pattern of /app/api/routes/ai.py exactly.

Drop into: backend/api/routes/guide.py
Then register in backend/app.py (patch script handles this automatically).
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from services.ai_provider_service import AIProviderService
from services.guide_service import GuideService, GuideRequest, GuideResponse, WIZARD_STEPS

router = APIRouter(tags=["AI Guide"])

# Lazy singleton
_guide_service: Optional[GuideService] = None


def get_guide_service() -> GuideService:
    global _guide_service
    if _guide_service is None:
        try:
            ai_provider = AIProviderService()
            _guide_service = GuideService(ai_provider=ai_provider)
        except Exception:
            _guide_service = GuideService(ai_provider=None)
    return _guide_service


# ---------------------------------------------------------------------------
# POST /api/ai/guide
# ---------------------------------------------------------------------------

class GuideRequestBody(BaseModel):
    intent: str = ""
    step: int = 0
    free_text: str = ""
    context: dict = {}


@router.post("/guide", response_model=GuideResponse)
async def ai_guide(
    body: GuideRequestBody,
    db: Session = Depends(get_db),
):
    """
    AI Guide — returns step-by-step wizard instructions or copilot answers.
    Modes: wizard | copilot | escalate
    """
    service = get_guide_service()

    req = GuideRequest(
        intent=body.intent,
        step=body.step,
        free_text=body.free_text,
        context=body.context,
        tenant_id="tenant-001",
    )

    try:
        return await service.process(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Guide service error: {str(e)}")


# ---------------------------------------------------------------------------
# GET /api/ai/guide/intents
# ---------------------------------------------------------------------------

@router.get("/guide/intents")
async def list_guide_intents(db: Session = Depends(get_db)):
    """Returns all available wizard intents with step counts."""
    intent_labels = {
        "scan_vulnerabilities":   "Run a vulnerability scan",
        "connect_qualys":         "Connect Qualys",
        "connect_tenable":        "Connect Tenable / Nessus",
        "connect_rapid7":         "Connect Rapid7 InsightVM",
        "connect_splunk":         "Connect Splunk",
        "connect_qradar":         "Connect IBM QRadar",
        "connect_cyberark":       "Connect CyberArk PAM",
        "network_scan":           "Discover network assets",
        "collect_event_logs":     "Collect event logs",
        "cyber_essentials_audit": "Prepare for Cyber Essentials",
        "dark_web_check":         "Check dark web exposure",
    }
    return {
        "intents": [
            {"id": k, "label": intent_labels.get(k, k), "steps": len(v)}
            for k, v in WIZARD_STEPS.items()
        ]
    }
