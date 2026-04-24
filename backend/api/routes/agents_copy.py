from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_auth
from db.session import get_db
from models.telemetry import (
    AssetSnapshotEvent, HeartbeatEvent, LocalFindingsEvent,
    SecurityPostureEvent, SoftwareInventoryEvent,
)
from schemas.agent import (
    AgentEnrollRequest, AgentEnrollResponse, AgentPolicyResponse,
    AssetSnapshotIn, HeartbeatIn, LocalFindingsIn,
    SecurityPostureIn, SoftwareInventoryIn, TelemetryAck,
)
from services.agent_service import (
    ensure_bootstrap_token, enroll_agent, get_active_policy, touch_agent_seen,
)

import asyncio as _asyncio
from integrations.dispatcher import dispatch_asset_change as _dispatch_asset
from services.merge_service import (
    merge_security_posture_into_asset,
    replace_software_inventory,
    upsert_canonical_asset_from_snapshot,
)

router = APIRouter()


@router.post("/enroll", response_model=AgentEnrollResponse)
def enroll(
    payload: AgentEnrollRequest,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Enroll a new agent. Requires a valid agent-role API key."""
    # Tenant from token must match request body
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    ensure_bootstrap_token(db, tenant_id=payload.tenant_id)
    try:
        agent_id, policy = enroll_agent(
            db=db,
            tenant_id=payload.tenant_id,
            enrollment_token=payload.enrollment_token,
            hostname=payload.hostname,
        )
        return AgentEnrollResponse(agent_id=agent_id, policy=policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{agent_id}/policy", response_model=AgentPolicyResponse)
def fetch_policy(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    policy = get_active_policy(db, tenant_id=auth.tenant_id, agent_id=agent_id)
    return AgentPolicyResponse(tenant_id=auth.tenant_id, agent_id=agent_id, policy=policy)


@router.post("/heartbeat", response_model=TelemetryAck)
def heartbeat(
    payload: HeartbeatIn,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    agent_id = payload.agent_id or auth.agent_id or "unknown-agent"
    event = HeartbeatEvent(
        tenant_id=payload.tenant_id,
        agent_id=agent_id,
        timestamp_epoch=payload.timestamp,
        payload_json=payload.model_dump(),
    )
    db.add(event)
    db.commit()
    touch_agent_seen(
        db, tenant_id=payload.tenant_id, agent_id=agent_id,
        last_seen_epoch=payload.timestamp, os_family=payload.platform,
        hostname=payload.hostname,
    )
    return TelemetryAck(tenant_id=payload.tenant_id, agent_id=agent_id, telemetry_type="heartbeat")


@router.post("/telemetry/asset_snapshot", response_model=TelemetryAck)
def ingest_asset_snapshot(
    payload: AssetSnapshotIn,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    event = AssetSnapshotEvent(
        tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        timestamp_epoch=payload.timestamp, payload_json=payload.model_dump(),
    )
    db.add(event)
    db.commit()
    upsert_canonical_asset_from_snapshot(db, payload.model_dump())
    touch_agent_seen(
        db, tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        last_seen_epoch=payload.timestamp, os_family=payload.asset.os_family,
        hostname=payload.asset.hostname,
    )
    try:
        _event = {
            "event_type": "asset_snapshot",
            "severity": 2,
            "asset_name": payload.asset.hostname if hasattr(payload, "asset") else payload.agent_id,
            "description": f"Asset snapshot received from {payload.agent_id}. OS: {payload.asset.os_family if hasattr(payload, 'asset') else 'unknown'}",
            "remediation_class": "informational",
            "ce_control": "A1",
            "ce_compliant": True,
            "tenant_id": payload.tenant_id,
            "agent_id": payload.agent_id,
        }
        _asyncio.run(_dispatch_asset(db, payload.tenant_id, _event))
    except Exception as _exc:
        import logging as _l; _l.getLogger(__name__).warning("Asset dispatch failed: %s", _exc)
    return TelemetryAck(tenant_id=payload.tenant_id, agent_id=payload.agent_id, telemetry_type="asset_snapshot")


@router.post("/telemetry/software_inventory", response_model=TelemetryAck)
def ingest_software_inventory(
    payload: SoftwareInventoryIn,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    event = SoftwareInventoryEvent(
        tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        timestamp_epoch=payload.timestamp, payload_json=payload.model_dump(),
    )
    db.add(event)
    db.commit()
    replace_software_inventory(
        db, tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        software_items=[item.model_dump() for item in payload.software],
    )
    touch_agent_seen(db, tenant_id=payload.tenant_id, agent_id=payload.agent_id, last_seen_epoch=payload.timestamp)
    return TelemetryAck(tenant_id=payload.tenant_id, agent_id=payload.agent_id, telemetry_type="software_inventory")


@router.post("/telemetry/security_posture", response_model=TelemetryAck)
def ingest_security_posture(
    payload: SecurityPostureIn,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    event = SecurityPostureEvent(
        tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        timestamp_epoch=payload.timestamp, payload_json=payload.model_dump(),
    )
    db.add(event)
    db.commit()
    merge_security_posture_into_asset(
        db, tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        security_posture=payload.security_posture, timestamp=payload.timestamp,
    )
    touch_agent_seen(db, tenant_id=payload.tenant_id, agent_id=payload.agent_id, last_seen_epoch=payload.timestamp)
    return TelemetryAck(tenant_id=payload.tenant_id, agent_id=payload.agent_id, telemetry_type="security_posture")


def _sanitise(obj):
    """Strip null bytes from strings — prevents psycopg2 UntranslatableCharacter errors."""
    if isinstance(obj, str):
        return obj.replace(chr(0), "")
    if isinstance(obj, dict):
        return {k: _sanitise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitise(i) for i in obj]
    return obj

@router.post("/telemetry/local_findings", response_model=TelemetryAck)
def ingest_local_findings(
    payload: LocalFindingsIn,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    clean_payload = _sanitise(payload.model_dump())
    event = LocalFindingsEvent(
        tenant_id=payload.tenant_id, agent_id=payload.agent_id,
        payload_json=clean_payload,
    )
    db.add(event)
    db.commit()
    touch_agent_seen(db, tenant_id=payload.tenant_id, agent_id=payload.agent_id)
    return TelemetryAck(tenant_id=payload.tenant_id, agent_id=payload.agent_id, telemetry_type="local_findings")
