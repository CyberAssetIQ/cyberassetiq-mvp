from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.supply_chain import AssuranceRequest, AssuranceReview, SupplierAttestation
from models.verification import VerificationCredential

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.supply_chain_service import (
    build_buyer_dashboard,
    create_assurance_request,
    invite_supplier,
    register_buyer_account,
    review_assurance_request,
    submit_attestation,
)

router = APIRouter(prefix="/api/supply-chain", tags=["supply-chain"])


class BuyerCreateBody(BaseModel):
    name: str = Field(...)
    contact_email: str = Field(...)
    industry: str = Field(...)


class SupplierInviteBody(BaseModel):
    buyer_account_id: int = Field(...)
    supplier_tenant_id: str = Field(...)
    supplier_name: str = Field(...)
    tier: str = Field(...)
    criticality: str = Field(...)
    contract_ref: str = Field(...)


class AssuranceRequestBody(BaseModel):
    buyer_account_id: int = Field(...)
    supplier_tenant_id: str = Field(...)
    request_type: str = Field(...)
    requested_controls_json: dict = Field(...)
    due_in_days: int = Field(..., ge=1, le=120)


class AttestationBody(BaseModel):
    assurance_request_id: int = Field(...)
    attested_by: str = Field(...)
    attestation_text: str = Field(...)
    answers_json: dict = Field(...)


class ReviewBody(BaseModel):
    assurance_request_id: int = Field(...)
    buyer_account_id: int = Field(...)
    review_status: str = Field(...)
    review_notes: str = Field(...)
    reviewed_by: str = Field(...)


@router.post("/buyers")
def create_buyer(
    body: BuyerCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    data = register_buyer_account(db, body.name, body.contact_email, body.industry)
    account = data["account"]
    consumer = data["consumer"]
    return {
        "buyer_account_id": account.id,
        "consumer_id": consumer.id,
        "buyer_code": account.buyer_code,
        "industry": account.industry,
        "status": account.status,
    }


@router.post("/suppliers/invite")
def create_supplier_relationship(
    body: SupplierInviteBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rel = invite_supplier(db, body.buyer_account_id, body.supplier_tenant_id, body.supplier_name, body.tier, body.criticality, body.contract_ref)
    return {
        "id": rel.id,
        "supplier_tenant_id": rel.supplier_tenant_id,
        "supplier_name": rel.supplier_name,
        "relationship_status": rel.relationship_status,
        "tier": rel.tier,
        "criticality": rel.criticality,
    }


@router.get("/buyers/{buyer_account_id}/dashboard")
def buyer_dashboard(
    buyer_account_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    return build_buyer_dashboard(db, buyer_account_id)


@router.post("/requests")
def create_request(
    body: AssuranceRequestBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    req = create_assurance_request(db, body.buyer_account_id, body.supplier_tenant_id, body.request_type, body.requested_controls_json, body.due_in_days)
    return {
        "id": req.id,
        "buyer_account_id": req.buyer_account_id,
        "supplier_tenant_id": req.supplier_tenant_id,
        "request_type": req.request_type,
        "status": req.status,
        "requested_at": req.requested_at,
        "due_at": req.due_at,
        "latest_version_id": req.latest_version_id,
    }


@router.post("/attest")
def create_attestation(
    body: AttestationBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    att = submit_attestation(db, body.assurance_request_id, auth.tenant_id, body.attested_by, body.attestation_text, body.answers_json)
    return {
        "id": att.id,
        "assurance_request_id": att.assurance_request_id,
        "tenant_id": att.tenant_id,
        "attested_by": att.attested_by,
        "submitted_at": att.submitted_at,
    }


@router.post("/reviews")
def create_review(
    body: ReviewBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    review = review_assurance_request(db, body.assurance_request_id, body.buyer_account_id, body.review_status, body.review_notes, body.reviewed_by)
    return {
        "id": review.id,
        "assurance_request_id": review.assurance_request_id,
        "buyer_account_id": review.buyer_account_id,
        "review_status": review.review_status,
        "review_notes": review.review_notes,
        "reviewed_by": review.reviewed_by,
        "reviewed_at": review.reviewed_at,
    }


@router.get("/my-requests")
def my_requests(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rows = db.query(AssuranceRequest).filter(AssuranceRequest.supplier_tenant_id == auth.tenant_id).order_by(AssuranceRequest.id.desc()).all()
    return [{
        "id": row.id,
        "buyer_account_id": row.buyer_account_id,
        "supplier_tenant_id": row.supplier_tenant_id,
        "request_type": row.request_type,
        "requested_controls": row.requested_controls_json,
        "status": row.status,
        "requested_at": row.requested_at,
        "due_at": row.due_at,
        "completed_at": row.completed_at,
        "latest_version_id": row.latest_version_id,
    } for row in rows]


@router.get("/my-status")
def my_status(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    requests = db.query(AssuranceRequest).filter(AssuranceRequest.supplier_tenant_id == auth.tenant_id).order_by(AssuranceRequest.id.desc()).all()
    attestations = db.query(SupplierAttestation).filter(SupplierAttestation.tenant_id == auth.tenant_id).order_by(SupplierAttestation.id.desc()).limit(10).all()
    reviews = (
        db.query(AssuranceReview)
        .join(AssuranceRequest, AssuranceReview.assurance_request_id == AssuranceRequest.id)
        .filter(AssuranceRequest.supplier_tenant_id == auth.tenant_id)
        .order_by(AssuranceReview.id.desc())
        .limit(10)
        .all()
    )
    credential = db.query(VerificationCredential).filter(VerificationCredential.tenant_id == auth.tenant_id).order_by(VerificationCredential.id.desc()).first()
    return {
        "tenant_id": auth.tenant_id,
        "open_requests": sum(1 for r in requests if r.status in {"requested", "submitted", "in_review"}),
        "latest_request": ({
            "id": requests[0].id,
            "request_type": requests[0].request_type,
            "status": requests[0].status,
            "due_at": requests[0].due_at,
        } if requests else None),
        "latest_attestation": ({
            "id": attestations[0].id,
            "submitted_at": attestations[0].submitted_at,
            "attested_by": attestations[0].attested_by,
        } if attestations else None),
        "latest_review": ({
            "id": reviews[0].id,
            "review_status": reviews[0].review_status,
            "reviewed_at": reviews[0].reviewed_at,
            "reviewed_by": reviews[0].reviewed_by,
        } if reviews else None),
        "credential": ({
            "credential_uuid": credential.credential_uuid,
            "credential_type": credential.credential_type,
            "status": credential.status,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
            "public_summary": credential.public_summary_json,
        } if credential else None),
    }


@router.get("/credential/current")
def current_supplier_credential(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    credential = db.query(VerificationCredential).filter(VerificationCredential.tenant_id == auth.tenant_id).order_by(VerificationCredential.id.desc()).first()
    if not credential:
        return {"credential": None}
    return {
        "credential": {
            "id": credential.id,
            "credential_uuid": credential.credential_uuid,
            "credential_type": credential.credential_type,
            "status": credential.status,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
            "public_summary": credential.public_summary_json,
        }
    }
