from __future__ import annotations

import secrets
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.broker import BrokerAccount, BrokerClientLink, BrokerQuoteRequest, BrokerUser
from models.posture_sharing import PostureAccessGrant
from services.posture_record_service import create_posture_version, get_current_posture_version
from services.posture_sharing_service import create_access_grant, ensure_consumer


def register_broker_account(db: Session, name: str, contact_email: str, regulator_ref: str, plan: str) -> dict[str, Any]:
    consumer = ensure_consumer(
        db=db,
        consumer_type="broker",
        name=name,
        external_org_id=regulator_ref or secrets.token_hex(6),
        contact_email=contact_email,
        metadata_json={"plan": plan, "market_position": "broker-neutral"},
    )
    account = db.query(BrokerAccount).filter(BrokerAccount.consumer_id == consumer.id).first()
    if not account:
        account = BrokerAccount(
            consumer_id=consumer.id,
            broker_code=f"BRK-{consumer.id:05d}",
            regulator_ref=regulator_ref,
            plan=plan,
            status="active",
        )
        db.add(account)
        db.commit()
        db.refresh(account)
    return {"consumer": consumer, "account": account}


def add_broker_user(db: Session, broker_account_id: int, email: str, full_name: str, role: str) -> BrokerUser:
    user = BrokerUser(
        broker_account_id=broker_account_id,
        email=email,
        full_name=full_name,
        role=role,
        is_active=1,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def invite_client(db: Session, broker_account_id: int, tenant_id: str, client_name: str,
                  renewal_date: str, notes: str, access_level: str) -> dict[str, Any]:
    account = db.query(BrokerAccount).filter(BrokerAccount.id == broker_account_id).first()
    if not account:
        raise ValueError("Broker account not found")
    grant = create_access_grant(
        db=db,
        tenant_id=tenant_id,
        consumer_id=account.consumer_id,
        grant_type="insurance",
        access_level=access_level,
        scope_json={
            "products": ["insurance-summary", "quote-pack", "verified-posture"],
            "reason": "quotation-and-renewal",
            "fields": [
                "overall_score", "risk_band", "insurance_readiness_score", "compliance_score",
                "identity_score", "exposure_score", "resilience_score", "top_risks"
            ],
        },
        expires_in_days=60,
    )
    link = BrokerClientLink(
        broker_account_id=broker_account_id,
        tenant_id=tenant_id,
        client_name=client_name,
        relationship_status="invited",
        consent_grant_id=grant.id,
        renewal_date=renewal_date,
        notes=notes,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"grant": grant, "link": link}


def get_broker_portfolio(db: Session, broker_account_id: int) -> dict[str, Any]:
    links = db.query(BrokerClientLink).filter(BrokerClientLink.broker_account_id == broker_account_id).all()
    portfolio = []
    for link in links:
        version = get_current_posture_version(db, link.tenant_id)
        portfolio.append({
            "tenant_id": link.tenant_id,
            "client_name": link.client_name,
            "relationship_status": link.relationship_status,
            "renewal_date": link.renewal_date,
            "overall_score": getattr(version, "overall_score", None),
            "risk_band": getattr(version, "risk_band", None),
            "insurance_readiness_score": getattr(version, "insurance_readiness_score", None),
            "supply_chain_score": getattr(version, "supply_chain_score", None),
            "critical_findings_count": getattr(version, "critical_findings_count", None),
            "top_risks": getattr(version, "top_risks_json", []),
        })
    return {
        "broker_account_id": broker_account_id,
        "managed_clients": len(portfolio),
        "clients": portfolio,
    }


def build_quote_pack(db: Session, broker_account_id: int, tenant_id: str) -> dict[str, Any]:
    link = db.query(BrokerClientLink).filter(
        BrokerClientLink.broker_account_id == broker_account_id,
        BrokerClientLink.tenant_id == tenant_id,
    ).first()
    if not link:
        raise HTTPException(status_code=404, detail="Broker-client relationship not found")

    grant = None
    if link.consent_grant_id:
        grant = db.query(PostureAccessGrant).filter(PostureAccessGrant.id == link.consent_grant_id).first()
    if not grant or grant.status != "approved":
        raise HTTPException(status_code=403, detail="Access denied until tenant consent is approved")

    version = get_current_posture_version(db, tenant_id)
    if not version:
        created = create_posture_version(db, tenant_id, generated_by="broker_quote_pack")
        version = created["version"]
    return {
        "broker_account_id": broker_account_id,
        "tenant_id": tenant_id,
        "quote_ready": True,
        "pricing_signal": "improve_terms_possible" if version.insurance_readiness_score >= 75 else "improvement_required",
        "record_version": version.version_no,
        "overall_score": version.overall_score,
        "risk_band": version.risk_band,
        "insurance_readiness_score": version.insurance_readiness_score,
        "supply_chain_score": version.supply_chain_score,
        "critical_findings_count": version.critical_findings_count,
        "top_risks": version.top_risks_json,
        "controls": version.controls_json,
        "summary": version.summary_json,
    }


def create_quote_request(db: Session, broker_account_id: int, tenant_id: str, request_type: str) -> BrokerQuoteRequest:
    version = get_current_posture_version(db, tenant_id)
    req = BrokerQuoteRequest(
        broker_account_id=broker_account_id,
        tenant_id=tenant_id,
        request_type=request_type,
        status="requested",
        snapshot_version_id=getattr(version, "id", None),
        response_json=build_quote_pack(db, broker_account_id, tenant_id),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req
