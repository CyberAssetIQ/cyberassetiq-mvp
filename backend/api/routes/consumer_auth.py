"""api/routes/consumer_auth.py — External consumer API key management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db

router = APIRouter(prefix="/api/consumer-keys", tags=["Consumer API Keys"])


class IssueKeyBody(BaseModel):
    consumer_id: int = Field(..., description="ID of the registered posture consumer (broker or buyer)")
    label: str = Field(..., description="Descriptive label for this key (e.g. 'Marsh UK production key')")
    validity_days: int = Field(365, ge=1, le=730, description="Days until key expires (max 730)")
    permitted_tenant_ids: list[str] = Field(
        default_factory=list,
        description="Tenant IDs this consumer is permitted to query. Empty = use existing grants only."
    )


class RevokeKeyBody(BaseModel):
    consumer_id: int = Field(..., description="Consumer ID that owns the key")


@router.post("/issue")
def issue_consumer_api_key(
    body: IssueKeyBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Issue a new API key for an external consumer (broker or enterprise buyer).
    The key is shown exactly once in the response — it cannot be retrieved again.
    The consumer uses this key with X-Consumer-Key header to access permitted posture data.
    """
    from models.posture_sharing import PostureConsumer
    from services.consumer_api_key_service import issue_consumer_key

    consumer = db.query(PostureConsumer).filter(
        PostureConsumer.id == body.consumer_id,
    ).first()
    if not consumer:
        raise HTTPException(404, detail=f"Consumer {body.consumer_id} not found.")

    result = issue_consumer_key(
        db=db,
        consumer_id=body.consumer_id,
        label=body.label,
        validity_days=body.validity_days,
        permitted_tenant_ids=body.permitted_tenant_ids,
    )
    return result


@router.get("/consumer/{consumer_id}")
def list_consumer_api_keys(
    consumer_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """List all API keys for a consumer (without key values — keys are shown only on issue)."""
    from services.consumer_api_key_service import list_consumer_keys
    return list_consumer_keys(db, consumer_id)


@router.delete("/{key_id}")
def revoke_consumer_api_key(
    key_id: int,
    body: RevokeKeyBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Revoke a consumer API key immediately. The consumer will lose access on their next request."""
    from services.consumer_api_key_service import revoke_consumer_key

    revoked = revoke_consumer_key(db, key_id, body.consumer_id)
    if not revoked:
        raise HTTPException(404, detail="Key not found or does not belong to this consumer.")
    return {"status": "revoked", "key_id": key_id}


# ---------------------------------------------------------------------------
# Consumer-authenticated posture endpoint (uses X-Consumer-Key header)
# ---------------------------------------------------------------------------

@router.get("/posture/{tenant_id}")
def consumer_get_posture(
    tenant_id: str,
    x_consumer_key: str | None = None,
    db: Session = Depends(get_db),
):
    """
    External consumer endpoint — brokers and buyers call this with their own API key.
    Uses X-Consumer-Key header (not the tenant's X-API-Key).
    Returns the current posture record for the requested tenant, subject to access grant.
    """
    from fastapi import Header
    from services.consumer_api_key_service import resolve_consumer_auth
    from services.posture_record_service import get_current_posture_version

    if not x_consumer_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Consumer-Key header. External consumers must authenticate with their issued consumer API key.",
        )

    consumer_auth = resolve_consumer_auth(db, x_consumer_key, tenant_id)
    if not consumer_auth:
        raise HTTPException(
            status_code=403,
            detail="Invalid consumer key, key expired, or no approved access grant for this tenant.",
        )

    version = get_current_posture_version(db, tenant_id)
    if not version:
        raise HTTPException(404, detail="No posture record available for this tenant.")

    # Return scoped posture data — access_level determines depth
    access_level = consumer_auth.get("access_level", "standard")
    response = {
        "consumer": {
            "id": consumer_auth["consumer_id"],
            "name": consumer_auth["consumer_name"],
            "type": consumer_auth["consumer_type"],
            "access_level": access_level,
        },
        "tenant_id": tenant_id,
        "posture": {
            "version_no": version.version_no,
            "generated_at": version.generated_at,
            "overall_score": version.overall_score,
            "risk_band": version.risk_band,
            "insurance_readiness_score": version.insurance_readiness_score,
            "supply_chain_score": version.supply_chain_score,
            "compliance_score": version.compliance_score,
            "asset_count": version.asset_count,
            "critical_findings_count": version.critical_findings_count,
            "top_risks": version.top_risks_json,
            "controls": version.controls_json,
            "signed_hash": version.signed_hash,
            "framework_alignment": (
                version.controls_json.get("frameworks", [])
                if version.controls_json else []
            ),
        },
    }

    if access_level == "full":
        response["posture"]["score_breakdown"] = version.score_breakdown_json
        response["posture"]["evidence_summary"] = version.evidence_summary_json

    return response
