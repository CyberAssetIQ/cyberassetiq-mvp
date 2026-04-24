from __future__ import annotations

"""
Agent management endpoints.
Provides visibility into enrolled agents — their status, last seen, and OS family.
"""

import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.agent import Agent, AgentEnrollmentToken, AgentPolicy
from models.auth import TenantAPIKey

router = APIRouter()

_STALE_THRESHOLD_SECONDS = 3600  # agent is "stale" if not seen in 1 hour


class CreateEnrollmentTokenRequest(BaseModel):
    label: str = Field(default="New token", max_length=128)


class RevokeTokenRequest(BaseModel):
    reason: str | None = Field(
        default=None,
        max_length=255,
        description="Reason for revoking this enrollment token (stored in audit log).",
    )


@router.get("/agents")
def list_agents(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    List all enrolled agents for this tenant with their current status.
    Status: active (seen recently), stale (not seen > 1h), unknown (never reported).
    """
    now = int(time.time())
    agents = (
        db.query(Agent)
        .filter(Agent.tenant_id == auth.tenant_id)
        .order_by(Agent.last_seen_epoch.desc().nullslast())
        .all()
    )
    result = []
    for a in agents:
        if a.last_seen_epoch is None:
            health = "unknown"
        elif now - a.last_seen_epoch < _STALE_THRESHOLD_SECONDS:
            health = "active"
        else:
            health = "stale"

        result.append({
            "agent_id": a.agent_id,
            "hostname": a.hostname,
            "os_family": a.os_family,
            "status": a.status,
            "health": health,
            "last_seen_epoch": a.last_seen_epoch,
            "last_seen_ago_seconds": (now - a.last_seen_epoch) if a.last_seen_epoch else None,
        })
    return result


@router.post("/agents/{agent_id}/decommission")
def decommission_agent(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Mark an agent as decommissioned so it no longer appears as active."""
    agent = db.query(Agent).filter(
        Agent.tenant_id == auth.tenant_id,
        Agent.agent_id == agent_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    agent.status = "decommissioned"
    db.commit()
    return {"agent_id": agent_id, "status": "decommissioned"}


@router.post("/enrollment-tokens")
def create_enrollment_token(
    payload: CreateEnrollmentTokenRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Create a new one-time enrollment token for this tenant.
    Share this token with the agent installer — it is consumed on first use.
    """
    label = payload.label or "New token"
    token_value = "enroll_" + secrets.token_urlsafe(24)
    token = AgentEnrollmentToken(
        tenant_id=auth.tenant_id,
        token_value=token_value,
        is_active=True,
        is_used=False,
        note=label,
    )
    db.add(token)
    db.commit()
    return {
        "token": token_value,
        "tenant_id": auth.tenant_id,
        "label": label,
        "note": "One-time use. Set CYBERASSETIQ_ENROLLMENT_TOKEN on the agent.",
    }


@router.get("/enrollment-tokens")
def list_enrollment_tokens(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List enrollment tokens for this tenant (active and used)."""
    tokens = (
        db.query(AgentEnrollmentToken)
        .filter(AgentEnrollmentToken.tenant_id == auth.tenant_id)
        .order_by(AgentEnrollmentToken.id.desc())
        .all()
    )
    return [
        {
            "id": t.id,
            "token_value": t.token_value,
            "note": t.note,
            "is_active": t.is_active,
            "is_used": t.is_used,
            "created_at": str(t.created_at),
            "revoked_at": str(t.revoked_at) if t.revoked_at else None,
            "revoked_by_key_id": t.revoked_by_key_id,
            "revocation_reason": t.revocation_reason,
        }
        for t in tokens
    ]


@router.get("/agents/{agent_id}")
def get_agent(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Retrieve details for a single enrolled agent."""
    now = int(time.time())
    agent = db.query(Agent).filter(
        Agent.tenant_id == auth.tenant_id,
        Agent.agent_id == agent_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    if agent.last_seen_epoch is None:
        health = "unknown"
    elif now - agent.last_seen_epoch < _STALE_THRESHOLD_SECONDS:
        health = "active"
    else:
        health = "stale"

    return {
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "os_family": agent.os_family,
        "status": agent.status,
        "health": health,
        "last_seen_epoch": agent.last_seen_epoch,
        "last_seen_ago_seconds": (now - agent.last_seen_epoch) if agent.last_seen_epoch else None,
    }


@router.patch("/enrollment-tokens/{token_id}")
def toggle_enrollment_token(
    token_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Toggle is_active on an enrollment token (disable/enable)."""
    token = (
        db.query(AgentEnrollmentToken)
        .filter(
            AgentEnrollmentToken.id == token_id,
            AgentEnrollmentToken.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    token.is_active = not token.is_active
    db.commit()
    return {"id": token.id, "is_active": token.is_active, "ok": True}


@router.delete("/enrollment-tokens/{token_id}")
def revoke_enrollment_token(
    token_id: int,
    payload: RevokeTokenRequest | None = None,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Revoke an enrollment token.
    The token is deactivated immediately; the record is RETAINED for audit purposes.
    Records who revoked it, when, and why.
    """
    token = db.query(AgentEnrollmentToken).filter(
        AgentEnrollmentToken.id == token_id,
        AgentEnrollmentToken.tenant_id == auth.tenant_id,
    ).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found.")
    if not token.is_active:
        raise HTTPException(status_code=400, detail="Token is already revoked.")
    token.is_active = False
    token.revoked_at = datetime.now(timezone.utc)
    token.revoked_by_key_id = auth.key_id
    token.revocation_reason = (payload.reason if payload else None) or "No reason provided"
    db.commit()
    return {
        "id": token_id,
        "status": "revoked",
        "note": token.note,
        "revoked_at": str(token.revoked_at),
        "revoked_by_key_id": token.revoked_by_key_id,
        "revocation_reason": token.revocation_reason,
    }

@router.patch("/keys/{key_id}")
def toggle_api_key(
    key_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Toggle is_active on an API key (disable/enable)."""
    key = (
        db.query(TenantAPIKey)
        .filter(
            TenantAPIKey.id == key_id,
            TenantAPIKey.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    # Prevent disabling the last active admin key
    if key.is_active and key.role == "admin":
        active_admins = db.query(TenantAPIKey).filter(
            TenantAPIKey.tenant_id == auth.tenant_id,
            TenantAPIKey.is_active == True,
            TenantAPIKey.role == "admin",
        ).count()
        if active_admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the last active admin key")
    key.is_active = not key.is_active
    db.commit()
    return {"id": key.id, "is_active": key.is_active, "ok": True}


# DELETE /keys/{key_id} is handled exclusively by keys.py (soft-revoke with audit trail)


@router.post("/agents/generate-id")
def generate_agent_id_endpoint(
    auth: AuthenticatedRequest = Depends(require_admin),
) -> dict:
    from services.agent_service import generate_agent_id
    return {"ok": True, "agent_id": generate_agent_id(auth.tenant_id)}


class ReassignPolicyRequest(BaseModel):
    policy: dict
    reason: str | None = None


@router.patch("/agents/{agent_id}/policy")
def reassign_agent_policy(
    agent_id: str,
    payload: ReassignPolicyRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    agent = db.query(Agent).filter(
        Agent.agent_id == agent_id,
        Agent.tenant_id == auth.tenant_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.status == "decommissioned":
        raise HTTPException(status_code=400, detail="Cannot reassign policy to a decommissioned agent.")
    if not payload.policy:
        raise HTTPException(status_code=400, detail="policy body cannot be empty.")
    db.query(AgentPolicy).filter(
        AgentPolicy.agent_id == agent_id,
        AgentPolicy.tenant_id == auth.tenant_id,
        AgentPolicy.is_active.is_(True),
    ).update({"is_active": False}, synchronize_session="fetch")
    new_policy = AgentPolicy(
        agent_fk=agent.id,
        agent_id=agent_id,
        tenant_id=auth.tenant_id,
        policy_json=payload.policy,
        is_active=True,
    )
    db.add(new_policy)
    db.commit()
    db.refresh(new_policy)
    return {"ok": True, "agent_id": agent_id, "policy": new_policy.policy_json}
