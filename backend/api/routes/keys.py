from __future__ import annotations

"""
API key management endpoints.
Allows tenant admins to create, list, and revoke/archive API keys.

Design principle: API keys are NEVER hard-deleted.
  - Revoke   = is_active=False + full audit trail (who, when, why)
  - Archive  = same as revoke; record is retained permanently for compliance
  - GET /keys returns active keys by default; ?include_archived=true returns all
"""

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, generate_api_key, require_admin
from db.session import get_db
from models.auth import TenantAPIKey
from models.agent import Agent

router = APIRouter()

VALID_ROLES = {"agent", "read", "admin"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    label: str
    role: str = "read"


class CreateKeyResponse(BaseModel):
    id: int
    label: str
    role: str
    plaintext_key: str  # shown ONCE — never stored
    note: str = "Save this key immediately. It cannot be retrieved again."


class RevokeKeyRequest(BaseModel):
    reason: str | None = Field(
        default=None,
        max_length=255,
        description="Optional reason for revoking/archiving this key (stored in audit log).",
    )


class KeySummary(BaseModel):
    id: int
    label: str | None
    role: str
    is_active: bool
    last_used_epoch: int | None
    created_at: str
    # Audit trail fields — populated when key is revoked/archived
    revoked_at: str | None = None
    revoked_by_key_id: int | None = None
    revocation_reason: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/keys", response_model=CreateKeyResponse)
def create_api_key(
    payload: CreateKeyRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> CreateKeyResponse:
    """
    Create a new API key for this tenant.
    The plaintext key is returned ONCE and never stored — save it immediately.
    Role must be one of: agent, read, admin.
    """
    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{payload.role}'. Must be one of: {sorted(VALID_ROLES)}",
        )

    plaintext, key_hash = generate_api_key()

    record = TenantAPIKey(
        tenant_id=auth.tenant_id,
        key_hash=key_hash,
        label=payload.label,
        role=payload.role,
        is_active=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return CreateKeyResponse(
        id=record.id,
        label=record.label or "",
        role=record.role,
        plaintext_key=plaintext,
    )


@router.get("/keys", response_model=list[KeySummary])
def list_api_keys(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
    include_archived: bool = Query(
        default=False,
        description="Set true to include revoked/archived keys in the response.",
    ),
) -> list[KeySummary]:
    """
    List API keys for this tenant.
    By default returns only active keys.
    Pass ?include_archived=true to include revoked/archived keys for audit review.
    Key hashes are never exposed.
    """
    query = db.query(TenantAPIKey).filter(TenantAPIKey.tenant_id == auth.tenant_id)
    if not include_archived:
        query = query.filter(TenantAPIKey.is_active.is_(True))
    records = query.order_by(TenantAPIKey.id.desc()).all()

    return [
        KeySummary(
            id=r.id,
            label=r.label,
            role=r.role,
            is_active=r.is_active,
            last_used_epoch=r.last_used_epoch,
            created_at=str(r.created_at),
            revoked_at=str(r.revoked_at) if r.revoked_at else None,
            revoked_by_key_id=r.revoked_by_key_id,
            revocation_reason=r.revocation_reason,
        )
        for r in records
    ]


@router.delete("/keys/{key_id}")
def revoke_api_key(
    key_id: int,
    payload: RevokeKeyRequest | None = None,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Revoke (archive) an API key.
    The key is deactivated immediately and can never authenticate again.
    The record is RETAINED for compliance and audit purposes — it is never deleted.

    Audit trail recorded:
      - revoked_at         : timestamp of revocation
      - revoked_by_key_id  : id of the API key whose holder performed this action
      - revocation_reason  : optional free-text reason
    """
    record = db.query(TenantAPIKey).filter(
        TenantAPIKey.id == key_id,
        TenantAPIKey.tenant_id == auth.tenant_id,
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Key not found.")

    if not record.is_active:
        raise HTTPException(status_code=400, detail="Key is already revoked/archived.")

    # Safety: prevent locking out the tenant entirely
    active_keys = db.query(TenantAPIKey).filter(
        TenantAPIKey.tenant_id == auth.tenant_id,
        TenantAPIKey.is_active.is_(True),
    ).count()

    if active_keys <= 1:
        raise HTTPException(
            status_code=400,
            detail="Cannot revoke the last active key — create a replacement first.",
        )

    # Soft revoke with full audit trail
    record.is_active = False
    record.revoked_at = datetime.now(timezone.utc)
    record.revoked_by_key_id = auth.key_id
    record.revocation_reason = (payload.reason if payload else None) or "No reason provided"

    db.commit()
    return {
        "id": key_id,
        "status": "revoked",
        "label": record.label,
        "revoked_at": str(record.revoked_at),
        "revoked_by_key_id": record.revoked_by_key_id,
        "revocation_reason": record.revocation_reason,
    }


class RotateKeyResponse(BaseModel):
    agent_id: str
    new_trust_key: str
    issued_at: str
    rotated_by_label: str
    note: str = "Save this key immediately - it cannot be retrieved again."


@router.post("/agents/{agent_id}/rotate-key", response_model=RotateKeyResponse)
def rotate_agent_trust_key(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RotateKeyResponse:
    agent = db.query(Agent).filter(
        Agent.agent_id == agent_id,
        Agent.tenant_id == auth.tenant_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.status == "decommissioned":
        raise HTTPException(status_code=400, detail="Cannot rotate key for a decommissioned agent.")
    new_key = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    rotated_by_label = getattr(auth, "key_label", None) or f"key_id:{auth.key_id}"
    agent.trust_key = new_key
    agent.trust_key_issued_at = now
    agent.trust_key_rotated_by = rotated_by_label
    db.commit()
    return RotateKeyResponse(
        agent_id=agent_id,
        new_trust_key=new_key,
        issued_at=str(now),
        rotated_by_label=rotated_by_label,
    )
