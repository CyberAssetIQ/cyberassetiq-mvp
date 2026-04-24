from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from models.darkweb import DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist
from services.asset_correlation_service import _correlate_findings_metadata

logger = logging.getLogger(__name__)


def upsert_watchlist(
    db: Session,
    tenant_id: str,
    watch_type: str,
    watch_value: str,
    label: str | None = None,
    severity: str = "medium",
) -> DarkWebWatchlist:
    existing = db.query(DarkWebWatchlist).filter(
        DarkWebWatchlist.tenant_id == tenant_id,
        DarkWebWatchlist.watch_type == watch_type,
        DarkWebWatchlist.watch_value == watch_value,
    ).first()
    if existing:
        existing.label = label or existing.label
        existing.severity = severity or existing.severity
        existing.is_active = True
        db.commit()
        db.refresh(existing)
        return existing

    row = DarkWebWatchlist(
        tenant_id=tenant_id,
        watch_type=watch_type,
        watch_value=watch_value,
        label=label,
        severity=severity,
        is_active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def add_source_item(
    db: Session,
    tenant_id: str,
    source_ref: str,
    content_text: str,
    source_name: str | None = None,
    source_type: str | None = None,
    title: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> DarkWebSourceItem:
    existing = db.query(DarkWebSourceItem).filter(
        DarkWebSourceItem.tenant_id == tenant_id,
        DarkWebSourceItem.source_ref == source_ref,
    ).first()
    if existing:
        existing.content_text = content_text
        existing.source_name = source_name
        existing.source_type = source_type
        existing.title = title
        existing.raw_metadata_json = metadata or {}
        db.commit()
        db.refresh(existing)
        return existing

    row = DarkWebSourceItem(
        tenant_id=tenant_id,
        source_ref=source_ref,
        source_name=source_name,
        source_type=source_type,
        title=title,
        content_text=content_text,
        raw_metadata_json=metadata or {},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _snippet(text: str, start: int, end: int, radius: int = 60) -> str:
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    return text[s:e].replace("\n", " ")


def run_darkweb_matching(db: Session, tenant_id: str) -> dict[str, Any]:
    watchlists = db.query(DarkWebWatchlist).filter(
        DarkWebWatchlist.tenant_id == tenant_id,
        DarkWebWatchlist.is_active.is_(True),
    ).all()
    items = db.query(DarkWebSourceItem).filter(
        DarkWebSourceItem.tenant_id == tenant_id,
    ).all()

    # Build a set of (watchlist_id, source_item_id) pairs that will be produced
    # this run; any existing findings NOT in this set will be soft-deleted after.
    produced_pairs: set[tuple[int, int]] = set()

    finding_count = 0
    matched_sources = 0

    for item in items:
        item_matches = 0
        text = item.content_text or ""
        for watch in watchlists:
            value = watch.watch_value.strip()
            if not value:
                continue

            if watch.watch_type == "regex":
                try:
                    pattern = re.compile(value, re.IGNORECASE)
                except re.error:
                    logger.warning("Invalid regex watchlist pattern id=%s: %s", watch.id, value)
                    continue
            else:
                pattern = re.compile(re.escape(value), re.IGNORECASE)

            for match in list(pattern.finditer(text))[:20]:
                produced_pairs.add((watch.id, item.id))
                # Upsert: update if exists, insert if not
                existing = db.query(DarkWebFinding).filter(
                    DarkWebFinding.tenant_id == tenant_id,
                    DarkWebFinding.watchlist_id == watch.id,
                    DarkWebFinding.source_item_id == item.id,
                ).first()
                if existing:
                    existing.severity = watch.severity
                    existing.status = "open"
                    existing.context_snippet = _snippet(text, match.start(), match.end())
                    existing.raw_metadata_json = {
                        "source_ref": item.source_ref,
                        "source_name": item.source_name,
                        "title": item.title,
                    }
                else:
                    finding = DarkWebFinding(
                        tenant_id=tenant_id,
                        watchlist_id=watch.id,
                        source_item_id=item.id,
                        finding_type=watch.watch_type,
                        matched_value=watch.watch_value,
                        context_snippet=_snippet(text, match.start(), match.end()),
                        severity=watch.severity,
                        status="open",
                        raw_metadata_json={
                            "source_ref": item.source_ref,
                            "source_name": item.source_name,
                            "title": item.title,
                        },
                    )
                    db.add(finding)
                    finding_count += 1
                item_matches += 1
                break  # One finding per (watchlist, source) pair is enough

        if item_matches:
            matched_sources += 1

    # Mark findings whose watchlist or source is no longer active as resolved
    all_findings = db.query(DarkWebFinding).filter(
        DarkWebFinding.tenant_id == tenant_id,
        DarkWebFinding.status == "open",
    ).all()
    for f in all_findings:
        if f.watchlist_id is not None and f.source_item_id is not None:
            if (f.watchlist_id, f.source_item_id) not in produced_pairs:
                f.status = "resolved"

    db.commit()
    _correlate_findings_metadata(db, tenant_id)

    total_open = db.query(DarkWebFinding).filter(
        DarkWebFinding.tenant_id == tenant_id,
        DarkWebFinding.status == "open",
    ).count()

    return {
        "tenant_id": tenant_id,
        "watchlist_count": len(watchlists),
        "source_item_count": len(items),
        "finding_count": total_open,
        "matched_sources": matched_sources,
    }
