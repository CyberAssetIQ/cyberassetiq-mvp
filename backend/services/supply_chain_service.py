from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.supply_chain import AssuranceRequest, AssuranceReview, BuyerAccount, SupplierAttestation, SupplierRelationship
from services.posture_record_service import create_posture_version, get_current_posture_version
from services.posture_sharing_service import create_access_grant, ensure_consumer


def register_buyer_account(db: Session, name: str, contact_email: str, industry: str) -> dict[str, Any]:
    consumer = ensure_consumer(
        db=db,
        consumer_type="buyer",
        name=name,
        external_org_id=f"BUYER-{name[:6].upper()}",
        contact_email=contact_email,
        metadata_json={"industry": industry, "channel": "supply-chain"},
    )
    account = db.query(BuyerAccount).filter(BuyerAccount.consumer_id == consumer.id).first()
    if not account:
        account = BuyerAccount(
            consumer_id=consumer.id,
            buyer_code=f"BUY-{consumer.id:05d}",
            industry=industry,
            status="active",
        )
        db.add(account)
        db.commit()
        db.refresh(account)
    return {"consumer": consumer, "account": account}


def invite_supplier(db: Session, buyer_account_id: int, supplier_tenant_id: str, supplier_name: str,
                    tier: str, criticality: str, contract_ref: str) -> SupplierRelationship:
    rel = SupplierRelationship(
        buyer_account_id=buyer_account_id,
        supplier_tenant_id=supplier_tenant_id,
        supplier_name=supplier_name,
        relationship_status="invited",
        tier=tier,
        criticality=criticality,
        contract_ref=contract_ref,
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return rel


def create_assurance_request(db: Session, buyer_account_id: int, supplier_tenant_id: str,
                             request_type: str, requested_controls_json: dict[str, Any],
                             due_in_days: int = 14) -> AssuranceRequest:
    buyer = db.query(BuyerAccount).filter(BuyerAccount.id == buyer_account_id).first()
    if not buyer:
        raise ValueError("Buyer account not found")
    create_access_grant(
        db=db,
        tenant_id=supplier_tenant_id,
        consumer_id=buyer.consumer_id,
        grant_type="supply_chain",
        access_level="standard",
        scope_json={
            "requested_controls": requested_controls_json,
            "buyer_use_case": "supplier-assurance",
            "required_views": ["current-posture", "verification-credential", "evidence-summary"],
        },
        expires_in_days=90,
    )
    version = get_current_posture_version(db, supplier_tenant_id)
    if not version:
        version = create_posture_version(db, supplier_tenant_id, generated_by="supply_chain_request")["version"]
    req = AssuranceRequest(
        buyer_account_id=buyer_account_id,
        supplier_tenant_id=supplier_tenant_id,
        request_type=request_type,
        requested_controls_json=requested_controls_json,
        status="requested",
        due_at=datetime.now(timezone.utc) + timedelta(days=due_in_days),
        latest_version_id=version.id,
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req


def submit_attestation(db: Session, assurance_request_id: int, tenant_id: str, attested_by: str,
                       attestation_text: str, answers_json: dict[str, Any]) -> SupplierAttestation:
    att = SupplierAttestation(
        assurance_request_id=assurance_request_id,
        tenant_id=tenant_id,
        attested_by=attested_by,
        attestation_text=attestation_text,
        answers_json=answers_json,
    )
    db.add(att)
    req = db.query(AssuranceRequest).filter(AssuranceRequest.id == assurance_request_id).first()
    if req:
        req.status = "submitted"
        req.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(att)
    return att


def review_assurance_request(db: Session, assurance_request_id: int, buyer_account_id: int,
                             review_status: str, review_notes: str, reviewed_by: str) -> AssuranceReview:
    review = AssuranceReview(
        assurance_request_id=assurance_request_id,
        buyer_account_id=buyer_account_id,
        review_status=review_status,
        review_notes=review_notes,
        reviewed_by=reviewed_by,
    )
    db.add(review)
    req = db.query(AssuranceRequest).filter(AssuranceRequest.id == assurance_request_id).first()
    if req:
        req.status = review_status
    db.commit()
    db.refresh(review)
    return review


def build_buyer_dashboard(db: Session, buyer_account_id: int) -> dict[str, Any]:
    rels = db.query(SupplierRelationship).filter(SupplierRelationship.buyer_account_id == buyer_account_id).all()
    rows = []
    for rel in rels:
        version = get_current_posture_version(db, rel.supplier_tenant_id)
        rows.append({
            "supplier_tenant_id": rel.supplier_tenant_id,
            "supplier_name": rel.supplier_name,
            "tier": rel.tier,
            "criticality": rel.criticality,
            "relationship_status": rel.relationship_status,
            "overall_score": getattr(version, "overall_score", None),
            "risk_band": getattr(version, "risk_band", None),
            "supply_chain_score": getattr(version, "supply_chain_score", None),
            "critical_findings_count": getattr(version, "critical_findings_count", None),
        })
    return {
        "buyer_account_id": buyer_account_id,
        "supplier_count": len(rows),
        "suppliers": rows,
    }
