"""
AI Baseline Service
Builds and queries statistical behavioural baselines from AI event history.
Used by AIDetectionService for Layer 2 anomaly detection.

Baseline types:
  login_times    — normal login hours for an asset/user (0-23)
  login_sources  — normal source IPs for an asset/user
  auth_volume    — normal authentication event count per hour

Baselines are rebuilt every 6 hours from the last 7 days of AIEvent data.
Minimum 10 observations required before a baseline is trusted.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import func

from models.ai_event import AIEvent
from models.ai_baseline import AIBaseline

logger = logging.getLogger(__name__)

# Minimum observations before we trust a baseline
MIN_OBSERVATIONS = 10

# How many days of history to use for baseline building
BASELINE_LOOKBACK_DAYS = 7

# Auth event types we track for volume baseline
AUTH_EVENT_TYPES = {
    "login_success", "login_failure", "explicit_logon",
    "admin_logon", "identity_event",
}


class AnomalyResult:
    """Result of an anomaly check against a baseline."""

    def __init__(
        self,
        is_anomalous: bool,
        anomaly_type: str,
        confidence: int,
        reason: str,
        baseline_exists: bool = True,
    ):
        self.is_anomalous = is_anomalous
        self.anomaly_type = anomaly_type
        self.confidence = confidence  # 0-100
        self.reason = reason
        self.baseline_exists = baseline_exists

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomalous": self.is_anomalous,
            "anomaly_type": self.anomaly_type,
            "confidence": self.confidence,
            "reason": self.reason,
            "baseline_exists": self.baseline_exists,
        }


class AIBaselineService:

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Public: check a new event for anomalies
    # ------------------------------------------------------------------

    def check_event(self, event: AIEvent) -> List[AnomalyResult]:
        """
        Check a new event against all applicable baselines.
        Returns list of AnomalyResult objects (may be empty if no anomalies).
        Called from AIDetectionService.analyse_event() as Layer 2.
        """
        results = []
        ev_type = (event.event_type or "").lower()
        entity  = event.hostname or event.ip_address or event.asset_name

        if not entity:
            return results

        # Only check auth-related events
        if ev_type not in AUTH_EVENT_TYPES:
            return results

        # Check 1 — off-hours login
        if event.created_at and ev_type in ("login_success", "explicit_logon", "admin_logon"):
            result = self._check_login_time(entity, event.created_at)
            if result:
                results.append(result)

        # Check 2 — unusual source IP
        if event.ip_address and ev_type == "login_success":
            result = self._check_login_source(entity, event.ip_address)
            if result:
                results.append(result)

        # Check 3 — auth volume spike
        if ev_type in AUTH_EVENT_TYPES:
            result = self._check_auth_volume(entity)
            if result:
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Public: rebuild all baselines for a tenant
    # ------------------------------------------------------------------

    def rebuild_baselines(self, tenant_id: str) -> Dict[str, int]:
        """
        Rebuild all baselines from the last 7 days of events.
        Called every 6 hours from the backend cleanup loop.
        Returns counts of baselines built per type.
        """
        since = datetime.now(timezone.utc) - timedelta(days=BASELINE_LOOKBACK_DAYS)
        counts = {"login_times": 0, "login_sources": 0, "auth_volume": 0}

        # Load recent auth events
        events = (
            self.db.query(AIEvent)
            .filter(
                AIEvent.created_at >= since,
                AIEvent.event_type.in_(list(AUTH_EVENT_TYPES)),
            )
            .all()
        )

        if not events:
            logger.info("Baseline rebuild: no events found for last %d days", BASELINE_LOOKBACK_DAYS)
            return counts

        logger.info("Baseline rebuild: processing %d events", len(events))

        # Group by entity (hostname or IP)
        by_entity: Dict[str, List[AIEvent]] = defaultdict(list)
        for ev in events:
            entity = ev.hostname or ev.ip_address or ev.asset_name
            if entity:
                by_entity[entity].append(ev)

        for entity, entity_events in by_entity.items():
            if len(entity_events) < MIN_OBSERVATIONS:
                continue

            # Build login_times baseline
            login_events = [
                e for e in entity_events
                if e.event_type in ("login_success", "explicit_logon", "admin_logon")
                and e.created_at
            ]
            if len(login_events) >= MIN_OBSERVATIONS:
                hours = [e.created_at.hour for e in login_events]
                hour_counts = Counter(hours)
                # Normal hours = those that appear in at least 10% of logins
                total = len(login_events)
                normal_hours = [
                    h for h, c in hour_counts.items()
                    if c / total >= 0.05  # at least 5% of logins
                ]
                self._upsert_baseline(
                    tenant_id=tenant_id,
                    entity_type="asset",
                    entity_ref=entity,
                    baseline_type="login_times",
                    data={
                        "normal_hours": sorted(normal_hours),
                        "hour_distribution": dict(hour_counts),
                        "total_logins": total,
                    },
                    observation_count=len(login_events),
                )
                counts["login_times"] += 1

            # Build login_sources baseline
            source_events = [
                e for e in entity_events
                if e.event_type == "login_success" and e.ip_address
            ]
            if len(source_events) >= MIN_OBSERVATIONS:
                ip_counts = Counter(e.ip_address for e in source_events)
                total = len(source_events)
                # Normal IPs = those seen in at least 10% of logins
                normal_ips = [
                    ip for ip, c in ip_counts.items()
                    if c / total >= 0.10
                ]
                self._upsert_baseline(
                    tenant_id=tenant_id,
                    entity_type="asset",
                    entity_ref=entity,
                    baseline_type="login_sources",
                    data={
                        "normal_ips": normal_ips,
                        "ip_distribution": dict(ip_counts),
                        "total_logins": total,
                    },
                    observation_count=len(source_events),
                )
                counts["login_sources"] += 1

            # Build auth_volume baseline
            # Count events per hour over the lookback window
            hour_buckets: Counter = Counter()
            for e in entity_events:
                if e.created_at:
                    bucket = e.created_at.strftime("%Y-%m-%d-%H")
                    hour_buckets[bucket] += 1

            if len(hour_buckets) >= 5:  # at least 5 hours of data
                volumes = list(hour_buckets.values())
                mean_vol = sum(volumes) / len(volumes)
                variance = sum((v - mean_vol) ** 2 for v in volumes) / len(volumes)
                std_dev = variance ** 0.5
                self._upsert_baseline(
                    tenant_id=tenant_id,
                    entity_type="asset",
                    entity_ref=entity,
                    baseline_type="auth_volume",
                    data={
                        "mean_per_hour": round(mean_vol, 2),
                        "std_dev": round(std_dev, 2),
                        "max_observed": max(volumes),
                        "min_observed": min(volumes),
                        "sample_hours": len(volumes),
                    },
                    observation_count=len(entity_events),
                )
                counts["auth_volume"] += 1

        try:
            self.db.commit()
        except Exception as exc:
            logger.error("Baseline commit failed: %s", exc)
            self.db.rollback()

        logger.info(
            "Baseline rebuild complete: %d login_times, %d login_sources, %d auth_volume baselines",
            counts["login_times"], counts["login_sources"], counts["auth_volume"],
        )
        return counts

    # ------------------------------------------------------------------
    # Anomaly checks
    # ------------------------------------------------------------------

    def _check_login_time(self, entity: str, event_time: datetime) -> Optional[AnomalyResult]:
        baseline = self._get_baseline(entity, "login_times")
        if not baseline:
            return None  # no baseline yet — can't flag

        normal_hours = baseline.baseline_json.get("normal_hours", [])
        if not normal_hours:
            return None

        hour = event_time.hour
        if hour in normal_hours:
            return None  # normal

        # Off-hours login — how far outside normal?
        total_logins = baseline.baseline_json.get("total_logins", 0)
        hour_dist = baseline.baseline_json.get("hour_distribution", {})
        hour_count = hour_dist.get(str(hour), 0)

        # Higher confidence if never seen at this hour
        confidence = 85 if hour_count == 0 else 60

        return AnomalyResult(
            is_anomalous=True,
            anomaly_type="off_hours_login",
            confidence=confidence,
            reason=(
                f"Login at {hour:02d}:00 is outside the normal hours "
                f"({self._format_hours(normal_hours)}) for {entity}. "
                + ("This hour has never been observed before." if hour_count == 0
                   else f"Only {hour_count} prior login(s) at this hour.")
            ),
        )

    def _check_login_source(self, entity: str, ip: str) -> Optional[AnomalyResult]:
        baseline = self._get_baseline(entity, "login_sources")
        if not baseline:
            return None

        normal_ips = baseline.baseline_json.get("normal_ips", [])
        if not normal_ips:
            return None

        if ip in normal_ips:
            return None  # normal source

        # Unknown source IP
        ip_dist = baseline.baseline_json.get("ip_distribution", {})
        prior_count = ip_dist.get(ip, 0)
        total = baseline.baseline_json.get("total_logins", 1)

        confidence = 80 if prior_count == 0 else 55

        return AnomalyResult(
            is_anomalous=True,
            anomaly_type="unusual_login_source",
            confidence=confidence,
            reason=(
                f"Login from {ip} is not a known source for {entity}. "
                f"Normal sources: {', '.join(normal_ips[:3])}{'...' if len(normal_ips) > 3 else ''}. "
                + ("This IP has never been seen before." if prior_count == 0
                   else f"Only seen {prior_count}/{total} times previously.")
            ),
        )

    def _check_auth_volume(self, entity: str) -> Optional[AnomalyResult]:
        baseline = self._get_baseline(entity, "auth_volume")
        if not baseline:
            return None

        mean = baseline.baseline_json.get("mean_per_hour", 0)
        std_dev = baseline.baseline_json.get("std_dev", 1)

        if mean == 0:
            return None

        # Count recent auth events in the last hour for this entity
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_count = (
            self.db.query(func.count(AIEvent.id))
            .filter(
                AIEvent.created_at >= since,
                AIEvent.event_type.in_(list(AUTH_EVENT_TYPES)),
                AIEvent.hostname == entity,
            )
            .scalar() or 0
        )

        # Anomaly if more than mean + 3 * std_dev
        threshold = mean + (3 * std_dev if std_dev > 0 else mean * 2)

        if recent_count <= threshold:
            return None

        confidence = min(90, int(70 + (recent_count - threshold) * 2))

        return AnomalyResult(
            is_anomalous=True,
            anomaly_type="auth_volume_spike",
            confidence=confidence,
            reason=(
                f"{recent_count} auth events in the last hour on {entity} — "
                f"significantly above the normal rate of {mean:.1f}/hour "
                f"(threshold: {threshold:.1f}). Possible brute force or scanning."
            ),
        )

    # ------------------------------------------------------------------
    # Baseline DB helpers
    # ------------------------------------------------------------------

    def _get_baseline(
        self, entity_ref: str, baseline_type: str
    ) -> Optional[AIBaseline]:
        return (
            self.db.query(AIBaseline)
            .filter(
                AIBaseline.entity_ref == entity_ref,
                AIBaseline.baseline_type == baseline_type,
            )
            .first()
        )

    def _upsert_baseline(
        self,
        tenant_id: str,
        entity_type: str,
        entity_ref: str,
        baseline_type: str,
        data: Dict[str, Any],
        observation_count: int,
    ) -> None:
        existing = (
            self.db.query(AIBaseline)
            .filter(
                AIBaseline.tenant_id == tenant_id,
                AIBaseline.entity_ref == entity_ref,
                AIBaseline.baseline_type == baseline_type,
            )
            .first()
        )
        if existing:
            existing.baseline_json = data
            existing.observation_count = observation_count
            existing.version = (existing.version or 1) + 1
        else:
            self.db.add(AIBaseline(
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_ref=entity_ref,
                baseline_type=baseline_type,
                baseline_json=data,
                observation_count=observation_count,
                version=1,
            ))

    @staticmethod
    def _format_hours(hours: List[int]) -> str:
        if not hours:
            return "none"
        if len(hours) <= 4:
            return ", ".join(f"{h:02d}:00" for h in sorted(hours))
        return f"{min(hours):02d}:00 – {max(hours):02d}:00"
