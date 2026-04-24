from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.darkweb import DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist
from schemas.darkweb import DarkWebRunRequest, DarkWebSourceItemIn, DarkWebWatchlistIn
from services.darkweb_service import add_source_item, run_darkweb_matching, upsert_watchlist
from services.darkweb_feeds import run_threat_intel_scan, auto_populate_watchlists, test_hibp_connection

router = APIRouter()


@router.post("/watchlists")
def create_watchlist(
    payload: DarkWebWatchlistIn,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    row = upsert_watchlist(db, payload.tenant_id, payload.watch_type, payload.watch_value, payload.label, payload.severity)
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "watch_type": row.watch_type,
        "watch_value": row.watch_value,
        "label": row.label,
        "severity": row.severity,
    }


@router.delete("/watchlists/{watchlist_id}")
def deactivate_watchlist(
    watchlist_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Deactivate a watchlist entry so it is no longer matched in future runs."""
    row = db.query(DarkWebWatchlist).filter(
        DarkWebWatchlist.id == watchlist_id,
        DarkWebWatchlist.tenant_id == auth.tenant_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Watchlist entry not found.")
    row.is_active = False
    db.commit()
    return {"id": watchlist_id, "status": "deactivated", "watch_value": row.watch_value}


@router.get("/watchlists")
def list_watchlists(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.query(DarkWebWatchlist).filter(DarkWebWatchlist.tenant_id == auth.tenant_id).order_by(DarkWebWatchlist.id.desc()).all()
    return [
        {
            "id": row.id,
            "watch_type": row.watch_type,
            "watch_value": row.watch_value,
            "label": row.label,
            "severity": row.severity,
            "is_active": row.is_active,
        }
        for row in rows
    ]


@router.post("/sources")
def add_source(
    payload: DarkWebSourceItemIn,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    row = add_source_item(
        db,
        tenant_id=payload.tenant_id,
        source_ref=payload.source_ref,
        content_text=payload.content_text,
        source_name=payload.source_name,
        source_type=payload.source_type,
        title=payload.title,
        metadata=payload.metadata,
    )
    return {"id": row.id, "source_ref": row.source_ref, "source_name": row.source_name, "title": row.title}


@router.get("/sources")
def list_sources(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.query(DarkWebSourceItem).filter(DarkWebSourceItem.tenant_id == auth.tenant_id).order_by(DarkWebSourceItem.id.desc()).all()
    return [
        {
            "id": row.id,
            "source_ref": row.source_ref,
            "source_name": row.source_name,
            "source_type": row.source_type,
            "title": row.title,
            "preview": (row.content_text or "")[:180],
        }
        for row in rows
    ]


@router.post("/run")
def run_matching(
    payload: DarkWebRunRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    return run_darkweb_matching(db, tenant_id=payload.tenant_id)


@router.get("/findings")
def list_findings(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.query(DarkWebFinding).filter(DarkWebFinding.tenant_id == auth.tenant_id).order_by(DarkWebFinding.id.desc()).all()
    return [
        {
            "id": row.id,
            "finding_type": row.finding_type,
            "matched_value": row.matched_value,
            "severity": row.severity,
            "status": row.status,
            "context_snippet": row.context_snippet,
            "source": (row.raw_metadata_json or {}).get("source_name"),
            "title": (row.raw_metadata_json or {}).get("title"),
            "linked_agent_ids": (row.raw_metadata_json or {}).get("linked_agent_ids", []),
            "linked_hostnames": (row.raw_metadata_json or {}).get("linked_hostnames", []),
            "linked_domains": (row.raw_metadata_json or {}).get("linked_domains", []),
            "linked_ips": (row.raw_metadata_json or {}).get("linked_ips", []),
            "link_strategies": (row.raw_metadata_json or {}).get("link_strategies", []),
        }
        for row in rows
    ]


@router.post("/threat-intel-scan")
def trigger_threat_intel_scan(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run all threat intelligence checks:
    - Shodan InternetDB (internet-facing IPs)
    - CISA KEV (known exploited CVEs in software inventory)
    - HaveIBeenPwned (domain breach checking, requires HIBP_API_KEY)
    Then runs the matching engine to correlate findings with assets.
    """
    return run_threat_intel_scan(db, tenant_id=auth.tenant_id)


@router.post("/auto-populate-watchlists")
def trigger_auto_populate(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Auto-create watchlist entries from discovered asset data
    (domains, email patterns, internet-facing IPs).
    """
    created = auto_populate_watchlists(db, tenant_id=auth.tenant_id)
    return {"status": "ok", "watchlist_entries_created": created, "tenant_id": auth.tenant_id}


@router.get("/test-hibp")
def hibp_test(
    auth: AuthenticatedRequest = Depends(require_read),
) -> dict:
    """
    Test HIBP connectivity using the free test API key.
    No paid subscription required — uses test account at hibp-integration-tests.com.
    """
    return test_hibp_connection()


@router.post("/check-hibp-email")
def check_email_hibp(
    email: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Check a specific email address against HIBP.
    Uses test key if no HIBP_API_KEY is set — only works for test accounts.
    Adds result as a dark web source item if breaches are found.
    """
    import os
    from services.darkweb_feeds import _check_hibp_email
    api_key = os.getenv("HIBP_API_KEY", "00000000000000000000000000000000")
    breaches = _check_hibp_email(email, api_key=api_key)

    if breaches:
        breach_names = [b.get("Name", b.get("Title", "?")) for b in breaches]
        content_text = (
            f"Email: {email}\n"
            f"Breaches found: {len(breaches)}\n"
            f"Breach names: {', '.join(breach_names)}\n\n"
        )
        for b in breaches[:5]:
            content_text += (
                f"[{b.get('Name')}] "
                f"Date: {b.get('BreachDate','?')} | "
                f"Accounts: {b.get('PwnCount',0):,} | "
                f"Data: {', '.join(b.get('DataClasses',[])[:4])}\n"
            )
        add_source_item(
            db,
            tenant_id=auth.tenant_id,
            source_ref=f"hibp-email-{email}",
            source_name="HaveIBeenPwned",
            source_type="breach_data",
            title=f"HIBP: {len(breaches)} breach(es) for {email}",
            content_text=content_text,
            metadata={"email": email, "breach_count": len(breaches), "source": "hibp"},
        )
        upsert_watchlist(
            db, auth.tenant_id,
            watch_type="email",
            watch_value=email,
            label=f"HIBP breached email: {email}",
            severity="high" if len(breaches) > 2 else "medium",
        )
        run_darkweb_matching(db, tenant_id=auth.tenant_id)

    return {
        "email":        email,
        "breach_count": len(breaches),
        "breaches":     [b.get("Name") for b in breaches],
        "status":       "found" if breaches else "clean",
    }
