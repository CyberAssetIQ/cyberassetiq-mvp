"""
AI Ingestion Service
Entry point for all external log and event data.
Normalises, persists as AIEvent, then runs detection pipeline.
"""
import logging
from typing import List, Dict, Any

from sqlalchemy.orm import Session

from models.ai_event import AIEvent
from services.ai_normalization_service import AINormalizationService, NormalisedEvent
from services.ai_detection_service import AIDetectionService

logger = logging.getLogger(__name__)
_normalizer = AINormalizationService()


class AIIngestionService:

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Public methods — one per source type
    # ------------------------------------------------------------------
    def ingest_windows_events(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        normalised = [_normalizer.normalize_windows_event(e) for e in events]
        return self._persist_and_detect(tenant_id, normalised)

    def ingest_linux_syslog(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        normalised = [_normalizer.normalize_syslog_event(e) for e in events]
        return self._persist_and_detect(tenant_id, normalised)

    def ingest_firewall_events(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        normalised = [_normalizer.normalize_firewall_event(e) for e in events]
        return self._persist_and_detect(tenant_id, normalised)

    def ingest_identity_events(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        normalised = [_normalizer.normalize_identity_event(e) for e in events]
        return self._persist_and_detect(tenant_id, normalised)

    def ingest_cloud_events(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        normalised = [_normalizer.normalize_cloud_event(e) for e in events]
        return self._persist_and_detect(tenant_id, normalised)

    def ingest_generic_events(self, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Generic ingest — caller must provide a 'source_type' field in each event.
        Automatically routes to the correct normaliser.
        """
        normalised = []
        for e in events:
            src = (e.get("source_type") or e.get("source") or "generic").lower()
            try:
                if src in ("windows", "winevent"):
                    normalised.append(_normalizer.normalize_windows_event(e))
                elif src in ("linux", "syslog"):
                    normalised.append(_normalizer.normalize_syslog_event(e))
                elif src in ("firewall", "fw", "palo_alto", "fortinet", "checkpoint"):
                    normalised.append(_normalizer.normalize_firewall_event(e))
                elif src in ("identity", "azure_ad", "entra", "okta", "ad"):
                    normalised.append(_normalizer.normalize_identity_event(e))
                elif src in ("cloud", "aws", "azure", "gcp"):
                    normalised.append(_normalizer.normalize_cloud_event(e))
                else:
                    normalised.append(self._normalise_generic(e))
            except Exception as ex:
                logger.warning("Failed to normalise event: %s — %s", e, ex)
        return self._persist_and_detect(tenant_id, normalised)

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------
    def _persist_and_detect(self, tenant_id: str, events: List[NormalisedEvent]) -> Dict[str, int]:
        persisted = 0
        alerts_created = 0
        detector = AIDetectionService(self.db)

        for ne in events:
            try:
                ev = AIEvent(
                    event_type=ne.event_type,
                    severity=ne.severity,
                    title=ne.title,
                    description=ne.description,
                    source=ne.source_type,
                    asset_name=ne.asset_name,
                    ip_address=ne.ip_address,
                    hostname=ne.hostname,
                    status="open",
                    risk_score=self._severity_to_score(ne.severity),
                    raw_payload=ne.raw_payload,
                    ai_summary=None,
                    tags=ne.tags,
                )
                self.db.add(ev)
                self.db.flush()   # populate ev.id without full commit

                # Run detection
                new_alerts = detector.analyse_event(ev)
                alerts_created += len(new_alerts)
                persisted += 1

            except Exception as ex:
                logger.error("Failed to persist AI event: %s", ex)

        try:
            self.db.commit()
        except Exception as ex:
            logger.error("Commit failed during AI ingestion: %s", ex)
            self.db.rollback()

        return {
            "events_ingested": persisted,
            "alerts_created": alerts_created,
        }

    def _normalise_generic(self, raw: dict) -> NormalisedEvent:
        """Minimal normalisation for unknown sources."""
        from services.ai_normalization_service import NormalisedEvent
        return NormalisedEvent(
            event_type=raw.get("event_type", "generic_event"),
            event_category=raw.get("category", "system"),
            severity=raw.get("severity", "low"),
            title=raw.get("title", raw.get("message", "Generic security event")[:255]),
            description=raw.get("description", raw.get("message", "")),
            source_type=raw.get("source_type", "generic"),
            source_name=raw.get("source_name"),
            user_ref=raw.get("user"),
            ip_address=raw.get("ip_address"),
            hostname=raw.get("hostname"),
            asset_name=raw.get("asset_name"),
            raw_payload=raw,
        )

    def _severity_to_score(self, severity: str) -> int:
        return {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 10}.get(
            (severity or "low").lower(), 25
        )
