from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.verification import VerificationCredential, VerificationEvent
from services.posture_record_service import get_current_posture_version
from services.verification_service import issue_credential, log_verification_event

router = APIRouter(tags=["verification"])


class IssueCredentialBody(BaseModel):
    credential_type: str = Field(...)
    validity_days: int = Field(..., ge=1, le=365)


@router.post("/api/verification/issue")
def create_credential(
    body: IssueCredentialBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    version = get_current_posture_version(db, auth.tenant_id)
    if not version:
        raise HTTPException(status_code=404, detail="No posture version found. Build a posture record first.")
    credential = issue_credential(db, version, body.credential_type, body.validity_days)
    return {
        "id": credential.id,
        "credential_uuid": credential.credential_uuid,
        "credential_type": credential.credential_type,
        "verification_token": credential.verification_token,
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
        "status": credential.status,
        "public_summary": credential.public_summary_json,
    }


@router.get("/api/verification/credentials")
def list_credentials(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rows = db.query(VerificationCredential).filter(VerificationCredential.tenant_id == auth.tenant_id).order_by(VerificationCredential.id.desc()).all()
    return [{
        "id": row.id,
        "credential_uuid": row.credential_uuid,
        "credential_type": row.credential_type,
        "issued_at": row.issued_at,
        "expires_at": row.expires_at,
        "status": row.status,
        "public_summary": row.public_summary_json,
    } for row in rows]


@router.get("/api/verification/credentials/{credential_uuid}")
def get_credential(
    credential_uuid: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    row = db.query(VerificationCredential).filter(
        VerificationCredential.tenant_id == auth.tenant_id,
        VerificationCredential.credential_uuid == credential_uuid,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {
        "id": row.id,
        "credential_uuid": row.credential_uuid,
        "credential_type": row.credential_type,
        "claims": row.claims_json,
        "status": row.status,
        "signed_hash": row.signed_hash,
        "public_summary": row.public_summary_json,
    }


@router.get("/verify/{token}")
def public_verify(
    token: str,
    db: Session = Depends(get_db),
):
    row = db.query(VerificationCredential).filter(VerificationCredential.verification_token == token).first()
    if not row:
        raise HTTPException(status_code=404, detail="Verification token not found")
    now = datetime.now(timezone.utc)
    status = row.status
    expired = bool(row.expires_at and row.expires_at.replace(tzinfo=timezone.utc) < now)
    if expired:
        status = "expired"
    log_verification_event(db, row.id, status, metadata_json={"public": True, "token": token})
    if expired:
        raise HTTPException(
            status_code=410,
            detail={
                "credential_uuid": row.credential_uuid,
                "credential_type": row.credential_type,
                "status": status,
                "issued_at": row.issued_at.isoformat() if row.issued_at else None,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "trust_mark": row.trust_mark,
                "public_summary": row.public_summary_json,
                "claims": row.claims_json,
            },
        )
    return {
        "credential_uuid": row.credential_uuid,
        "credential_type": row.credential_type,
        "status": status,
        "issued_at": row.issued_at,
        "expires_at": row.expires_at,
        "trust_mark": row.trust_mark,
        "public_summary": row.public_summary_json,
        "claims": row.claims_json,
    }
