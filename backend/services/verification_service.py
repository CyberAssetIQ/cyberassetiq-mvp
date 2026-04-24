from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.verification import VerificationCredential, VerificationEvent


DEFAULT_VALIDITY_DAYS = 30


def _sign_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_public_summary(version) -> dict[str, Any]:
    return {
        "tenant_id": version.tenant_id,
        "version_no": version.version_no,
        "overall_score": version.overall_score,
        "risk_band": version.risk_band,
        "insurance_readiness_score": version.insurance_readiness_score,
        "supply_chain_score": version.supply_chain_score,
        "compliance_score": version.compliance_score,
        "identity_score": version.identity_score,
        "exposure_score": version.exposure_score,
        "resilience_score": version.resilience_score,
        "asset_count": version.asset_count,
        "critical_findings_count": version.critical_findings_count,
        "top_risks": version.top_risks_json,
        "framework_alignment": version.controls_json.get("frameworks", []),
        "generated_at": version.generated_at.isoformat() if version.generated_at else None,
    }


def issue_credential(db: Session, version, credential_type: str, validity_days: int = DEFAULT_VALIDITY_DAYS):
    public_summary = build_public_summary(version)
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=validity_days)
    token = secrets.token_urlsafe(24)
    claims = {
        "credential_type": credential_type,
        "tenant_id": version.tenant_id,
        "version_id": version.id,
        "version_no": version.version_no,
        "risk_band": version.risk_band,
        "overall_score": version.overall_score,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    signed_hash = _sign_payload(claims | {"token": token})
    credential = VerificationCredential(
        tenant_id=version.tenant_id,
        posture_record_version_id=version.id,
        credential_uuid=str(uuid.uuid4()),
        credential_type=credential_type,
        expires_at=expires_at,
        status="valid",
        assurance_level="continuous-monitoring",
        trust_mark="CyberAssetIQ Verified",
        claims_json=claims,
        verification_token=token,
        signed_hash=signed_hash,
        public_summary_json=public_summary,
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return credential


def log_verification_event(db: Session, credential_id: int, verification_result: str,
                           verified_by_consumer_id: int | None = None,
                           metadata_json: dict[str, Any] | None = None):
    evt = VerificationEvent(
        credential_id=credential_id,
        verified_by_consumer_id=verified_by_consumer_id,
        verification_result=verification_result,
        metadata_json=metadata_json or {},
    )
    db.add(evt)
    db.commit()
    return evt
