"""
AI Log Ingestion Routes  (v2 - fixed)
Calls ai_ingestion_service batch methods directly.
"""
import logging
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.session import get_db
from services.ai_ingestion_service import AIIngestionService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["AI Ingestion"])


class WindowsEventPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"

class LinuxSyslogPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"

class FirewallEventPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"

class IdentityEventPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"

class CloudEventPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"

class GenericEventPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(...)
    tenant_id: Optional[str] = "tenant-001"


def _run(fn, *args, source_type="unknown"):
    try:
        result = fn(*args)
        return {**result, "source_type": source_type}
    except Exception as exc:
        logger.error("%s ingestion error: %s", source_type, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/windows")
def ingest_windows(payload: WindowsEventPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "windows"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_windows_events, payload.tenant_id or "tenant-001", payload.events, source_type="windows")

@router.post("/linux")
def ingest_linux(payload: LinuxSyslogPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "linux"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_linux_syslog, payload.tenant_id or "tenant-001", payload.events, source_type="linux")

@router.post("/firewall")
def ingest_firewall(payload: FirewallEventPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "firewall"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_firewall_events, payload.tenant_id or "tenant-001", payload.events, source_type="firewall")

@router.post("/identity")
def ingest_identity(payload: IdentityEventPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "identity"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_identity_events, payload.tenant_id or "tenant-001", payload.events, source_type="identity")

@router.post("/cloud")
def ingest_cloud(payload: CloudEventPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "cloud"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_cloud_events, payload.tenant_id or "tenant-001", payload.events, source_type="cloud")

@router.post("/events")
def ingest_generic(payload: GenericEventPayload, db: Session = Depends(get_db)):
    if not payload.events: return {"events_ingested": 0, "alerts_created": 0, "source_type": "generic"}
    svc = AIIngestionService(db=db)
    return _run(svc.ingest_generic_events, payload.tenant_id or "tenant-001", payload.events, source_type="generic")

@router.get("/status")
def ingest_status(db: Session = Depends(get_db)):
    from models.ai_event import AIEvent
    from models.ai_alert import AIAlert
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return {
        "events_last_24h": db.query(AIEvent).filter(AIEvent.created_at >= since).count(),
        "alerts_last_24h": db.query(AIAlert).filter(AIAlert.created_at >= since).count(),
        "total_events":    db.query(AIEvent).count(),
        "total_alerts":    db.query(AIAlert).count(),
        "supported_sources": ["windows", "linux", "firewall", "identity", "cloud", "generic"],
    }
