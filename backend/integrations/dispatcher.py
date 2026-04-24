"""
Integration Dispatcher
----------------------
Central routing layer. Given a CyberAssetIQ event and a tenant_id, the
dispatcher finds all enabled connectors for that tenant and fans the event
out to each one asynchronously.

Usage (from any CyberAssetIQ module):

    from integrations.dispatcher import dispatch_event

    await dispatch_event(
        db=db,
        tenant_id="tenant-001",
        event={
            "event_type": "cve_found",
            "severity": 8,
            "asset_name": "DESKTOP-A1B2",
            "asset_ip": "192.168.0.50",
            "cve_id": "CVE-2024-1234",
            "cvss_score": 8.1,
            "cvss_severity": "high",
            "description": "Critical CVE detected on endpoint.",
            "remediation_class": "approval_required",
            "remediation_action": "Apply KB5034441 patch via patch management module.",
            "ce_control": "A4",
            "ce_compliant": False,
            "secret_score": None,
            "tenant_id": "tenant-001",
        },
        categories=None,   # None = all categories; or ["siem", "itsm"] etc.
    )
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from models.integration_connector import IntegrationConnector
from integrations.base import BaseConnector, ConnectorError
from integrations.siem import SentinelConnector, SplunkConnector, QRadarConnector, ElasticConnector
from integrations.edr import CrowdStrikeConnector, DefenderConnector, SentinelOneConnector
from integrations.iam import EntraIDConnector, OktaConnector, InsightIDRConnector
from integrations.soar import XSOARConnector, TinesConnector, SplunkSOARConnector
from integrations.msp import ConnectWiseConnector, DattoRMMConnector, NableConnector
from integrations.itsm import JiraConnector, ServiceNowConnector, FreshserviceConnector

logger = logging.getLogger(__name__)

# Registry — connector_type string → connector class
CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = {
    # SIEM
    "sentinel":     SentinelConnector,
    "splunk":       SplunkConnector,
    "qradar":       QRadarConnector,
    "elastic":      ElasticConnector,
    # EDR
    "crowdstrike":  CrowdStrikeConnector,
    "defender":     DefenderConnector,
    "sentinelone":  SentinelOneConnector,
    # IAM
    "entraid":      EntraIDConnector,
    "okta":         OktaConnector,
    "insightidr":   InsightIDRConnector,
    # SOAR
    "xsoar":        XSOARConnector,
    "tines":        TinesConnector,
    "splunk_soar":  SplunkSOARConnector,
    # MSP
    "connectwise":  ConnectWiseConnector,
    "datto":        DattoRMMConnector,
    "nable":        NableConnector,
    # ITSM
    "jira":         JiraConnector,
    "servicenow":   ServiceNowConnector,
    "freshservice": FreshserviceConnector,
}


def get_connector(record: IntegrationConnector) -> BaseConnector | None:
    """Instantiate a connector from a DB record. Returns None if type unknown."""
    cls = CONNECTOR_REGISTRY.get(record.connector_type)
    if cls is None:
        logger.warning("Unknown connector type: %s", record.connector_type)
        return None
    return cls(config=record.config)


async def _send_to_connector(
    record: IntegrationConnector,
    event: dict[str, Any],
    db: Session,
) -> None:
    """Send event to one connector, update DB stats regardless of outcome."""
    connector = get_connector(record)
    if connector is None:
        return
    try:
        await connector.send_event(event)
        record.last_sent_at = datetime.utcnow()
        record.total_events_sent = (record.total_events_sent or 0) + 1
        db.commit()
        logger.info("Dispatched event to %s:%s", record.connector_type, record.name)
    except ConnectorError as exc:
        logger.error(
            "Connector %s:%s failed: %s",
            record.connector_type, record.name, exc
        )
    except Exception as exc:
        logger.exception(
            "Unexpected error dispatching to %s:%s: %s",
            record.connector_type, record.name, exc
        )


async def dispatch_event(
    db: Session,
    tenant_id: str,
    event: dict[str, Any],
    categories: list[str] | None = None,
) -> int:
    """
    Fan out a CyberAssetIQ event to all enabled connectors for the tenant.

    Args:
        db          — SQLAlchemy session
        tenant_id   — Tenant to look up connectors for
        event       — Normalised event dict (see module docstring)
        categories  — Optional filter, e.g. ["siem", "itsm"]. None = all.

    Returns:
        Number of connectors the event was dispatched to.
    """
    event.setdefault("tenant_id", tenant_id)

    query = db.query(IntegrationConnector).filter(
        IntegrationConnector.tenant_id == tenant_id,
        IntegrationConnector.enabled == True,
    )
    if categories:
        query = query.filter(IntegrationConnector.category.in_(categories))

    records = query.all()
    if not records:
        return 0

    # Fan out concurrently; each failure is isolated
    await asyncio.gather(
        *[_send_to_connector(record, event, db) for record in records],
        return_exceptions=True,
    )
    return len(records)


async def dispatch_critical_finding(
    db: Session,
    tenant_id: str,
    event: dict[str, Any],
) -> None:
    """
    Shortcut for high-severity findings — routes to SIEM + SOAR + ITSM only.
    Excludes EDR / IAM / MSP (those are enrichment paths, not alert paths).
    """
    await dispatch_event(
        db, tenant_id, event, categories=["siem", "soar", "itsm"]
    )


async def dispatch_asset_change(
    db: Session,
    tenant_id: str,
    event: dict[str, Any],
) -> None:
    """
    Asset inventory change — routes to SIEM + MSP for asset tracking.
    """
    await dispatch_event(
        db, tenant_id, event, categories=["siem", "msp"]
    )


async def dispatch_credential_leak(
    db: Session,
    tenant_id: str,
    event: dict[str, Any],
) -> None:
    """
    Credential / secret leak — routes to all categories:
    SIEM for logging, EDR for IOC creation, IAM for session revocation,
    SOAR for automated playbook, ITSM for ticket, MSP for client notification.
    """
    await dispatch_event(db, tenant_id, event, categories=None)
