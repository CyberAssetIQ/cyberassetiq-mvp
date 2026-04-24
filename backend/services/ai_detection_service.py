"""
AI Detection Service
Rule-based detection engine. Analyses normalised AI events and creates AI alerts.
Hybrid approach: deterministic rules (Layer 1) + baseline anomaly checks (Layer 2).
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from models.ai_event import AIEvent
from models.ai_alert import AIAlert
from services.ai_mitre_service import AIMitreService
from services.ai_baseline_service import AIBaselineService

logger = logging.getLogger(__name__)
_mitre = AIMitreService()

# How many failed logins in a time window triggers brute-force detection
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 15

# Risk score for given severities
SEVERITY_SCORES = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 10}


class AIDetectionService:

    def __init__(self, db: Session):
        self.db = db
        self._baseline = AIBaselineService(db)

    # ------------------------------------------------------------------
    # Public entry point: analyse a single new event
    # ------------------------------------------------------------------
    def analyse_event(self, event: AIEvent) -> List[AIAlert]:
        """
        Run all applicable detection rules against a newly ingested event.
        Returns list of new AIAlert objects (already added to session, not committed).
        """
        alerts = []

        ev_type = (event.event_type or "").lower()
        severity = (event.severity or "low").lower()

        # Rule 1 — Log cleared (always critical)
        if ev_type == "log_cleared":
            alerts.append(self._make_alert(
                event=event,
                alert_type="log_cleared",
                title="Security audit log cleared",
                summary=(
                    "The Windows Security audit log was cleared. This is a known defence evasion technique "
                    "used by attackers to remove evidence of their activity."
                ),
                recommendation="Investigate immediately. Check who cleared the log. Review prior events from SIEM backups.",
                severity="critical",
                confidence=95,
            ))

        # Rule 2 — MFA disabled
        if ev_type == "mfa_disabled":
            alerts.append(self._make_alert(
                event=event,
                alert_type="mfa_disabled",
                title=f"MFA disabled for {event.ip_address or 'a user'}",
                summary="Multi-factor authentication was disabled for a user account. This significantly reduces account security and may indicate account compromise or insider threat.",
                recommendation="Verify this change was authorised. Re-enable MFA immediately if unplanned.",
                severity="high",
                confidence=90,
            ))

        # Rule 3 — New admin account
        if ev_type in ("account_created", "admin_logon") and severity in ("high", "critical"):
            alerts.append(self._make_alert(
                event=event,
                alert_type="admin_account_created",
                title="Privileged account activity detected",
                summary="A new account was created or an account received elevated privileges. This may indicate privilege escalation or an attacker establishing persistence.",
                recommendation="Verify the account creation was authorised. Review group memberships and role assignments.",
                severity="high",
                confidence=80,
            ))

        # Rule 4 — Brute force detection (time-window aggregation)
        if ev_type == "login_failure":
            brute_force_alert = self._check_brute_force(event)
            if brute_force_alert:
                alerts.append(brute_force_alert)

        # Rule 5 — Brute force then success (most dangerous pattern)
        if ev_type == "login_success":
            bf_success = self._check_brute_force_then_success(event)
            if bf_success:
                alerts.append(bf_success)

        # Rule 6 — External login to sensitive host
        if ev_type == "login_success" and event.ip_address and not self._is_internal(event.ip_address):
            alerts.append(self._make_alert(
                event=event,
                alert_type="external_login",
                title=f"Successful login from external IP {event.ip_address}",
                summary=f"A successful login occurred from an external IP address ({event.ip_address}). External logins to internal systems should be reviewed.",
                recommendation="Confirm this login is expected. Check if VPN was used. Review user activity after login.",
                severity="high",
                confidence=75,
            ))

        # Rule 7 — Suspicious PowerShell / script
        if ev_type in ("powershell_suspicious", "suspicious_script", "wmi_execution"):
            alerts.append(self._make_alert(
                event=event,
                alert_type="suspicious_script",
                title="Suspicious script or command execution",
                summary="A suspicious scripting engine or command-line execution was detected. This technique is widely used in attacks for initial execution, lateral movement and persistence.",
                recommendation="Review the executed command. Check parent process. Analyse for encoded or obfuscated payloads.",
                severity="high",
                confidence=80,
            ))

        # Rule 8 — Service installed
        if ev_type in ("service_install", "new_service"):
            alerts.append(self._make_alert(
                event=event,
                alert_type="new_service",
                title="New system service installed",
                summary="A new service was installed on a system. Attackers use service installation as a persistence mechanism.",
                recommendation="Verify the service is legitimate. Check the service binary path and publisher.",
                severity="medium",
                confidence=70,
            ))

        # Rule 9 — Scheduled task created
        if ev_type == "scheduled_task":
            alerts.append(self._make_alert(
                event=event,
                alert_type="scheduled_task",
                title="Scheduled task created or modified",
                summary="A scheduled task was created or modified. This is a common persistence technique.",
                recommendation="Review the task trigger, action, and running user. Delete if unauthorised.",
                severity="medium",
                confidence=65,
            ))

        # Rule 10 — Dangerous cloud operation
        if ev_type in ("cloud_dangerous_operation", "cloud_iam_change"):
            alerts.append(self._make_alert(
                event=event,
                alert_type="cloud_dangerous_operation",
                title=event.title or "Sensitive cloud operation detected",
                summary="A destructive or sensitive cloud operation was performed. This may indicate compromised cloud credentials or an insider threat.",
                recommendation="Verify the operation was authorised. Review CloudTrail/Activity Log. Check IAM changes.",
                severity="high",
                confidence=80,
            ))

        # Rule 11 — Credential exposure
        if ev_type == "api_key_exposure" or ev_type == "credential_exposure":
            alerts.append(self._make_alert(
                event=event,
                alert_type="credential_exposure",
                title="Credential or API key exposure detected",
                summary="A credential, API key, or secret was detected in an exposed location. Immediate revocation and rotation is required.",
                recommendation="Revoke the exposed credential immediately. Rotate all secrets. Audit what the credential had access to.",
                severity="critical",
                confidence=90,
            ))

        # ── Layer 2: Baseline anomaly detection ───────────────────────
        # Only runs if we have enough historical data (handled inside service)
        try:
            anomalies = self._baseline.check_event(event)
            for anomaly in anomalies:
                # Map anomaly type to alert severity
                severity = "high" if anomaly.confidence >= 80 else "medium"
                tactic, technique_id, technique_name = _mitre.map_detection(
                    anomaly.anomaly_type
                )
                alerts.append(self._make_alert(
                    event=event,
                    alert_type=anomaly.anomaly_type,
                    title=anomaly.reason[:120],
                    summary=anomaly.reason,
                    recommendation=(
                        "Review this activity and verify it is authorised. "
                        "If unexpected, treat as potential account compromise."
                    ),
                    severity=severity,
                    confidence=anomaly.confidence,
                ))
        except Exception as baseline_exc:
            logger.debug("Baseline check error (non-fatal): %s", baseline_exc)

        return alerts

    # ------------------------------------------------------------------
    # Brute force helpers
    # ------------------------------------------------------------------
    def _check_brute_force(self, event: AIEvent) -> Optional[AIAlert]:
        """Check if recent failed logins for same host cross the threshold."""
        since = datetime.now(timezone.utc) - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        count = (
            self.db.query(func.count(AIEvent.id))
            .filter(
                AIEvent.event_type == "login_failure",
                AIEvent.created_at >= since,
                AIEvent.hostname == event.hostname if event.hostname else AIEvent.ip_address == event.ip_address,
            )
            .scalar() or 0
        )
        if count >= BRUTE_FORCE_THRESHOLD:
            return self._make_alert(
                event=event,
                alert_type="brute_force",
                title=f"Brute force attack detected on {event.hostname or event.ip_address}",
                summary=f"{count} failed login attempts in {BRUTE_FORCE_WINDOW_MINUTES} minutes on {event.hostname or event.ip_address}. This pattern indicates a brute force or password spray attack.",
                recommendation="Block the source IP at the firewall. Enable account lockout policies. Review if any accounts were compromised.",
                severity="high",
                confidence=85,
            )
        return None

    def _check_brute_force_then_success(self, event: AIEvent) -> Optional[AIAlert]:
        """Detect: N failures followed by success (credential compromise)."""
        since = datetime.now(timezone.utc) - timedelta(minutes=30)
        fail_count = (
            self.db.query(func.count(AIEvent.id))
            .filter(
                AIEvent.event_type == "login_failure",
                AIEvent.created_at >= since,
                AIEvent.hostname == event.hostname if event.hostname else True,
            )
            .scalar() or 0
        )
        if fail_count >= BRUTE_FORCE_THRESHOLD:
            return self._make_alert(
                event=event,
                alert_type="brute_force_success",
                title=f"Brute force followed by successful login on {event.hostname or event.ip_address}",
                summary=f"{fail_count} failed login attempts preceded this successful login. This is the highest-confidence indicator of credential compromise.",
                recommendation="Immediately reset the compromised account password. Investigate all actions taken after login. Check for lateral movement.",
                severity="critical",
                confidence=92,
            )
        return None

    # ------------------------------------------------------------------
    # Helper: create AIAlert
    # ------------------------------------------------------------------
    def _make_alert(
        self,
        event: AIEvent,
        alert_type: str,
        title: str,
        summary: str,
        recommendation: str,
        severity: str,
        confidence: int,
    ) -> AIAlert:
        tactic, technique_id, technique_name = _mitre.map_detection(alert_type)
        risk_score = SEVERITY_SCORES.get(severity, 50) * (confidence / 100)

        alert = AIAlert(
            ai_event_id=event.id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            summary=summary,
            recommendation=recommendation,
            confidence=confidence,
            status="new",
            entities=[
                x for x in [event.hostname, event.ip_address, event.asset_name] if x
            ],
            evidence={
                "event_id": event.id,
                "event_type": event.event_type,
                "source": event.source,
                "risk_score": round(risk_score, 1),
                "mitre_tactic": tactic,
                "mitre_technique": f"{technique_id} — {technique_name}" if technique_id else None,
            },
            metadata_json={
                "alert_type": alert_type,
                "mitre_tactic": tactic,
                "mitre_technique_id": technique_id,
                "mitre_technique_name": technique_name,
                "risk_score": round(risk_score, 1),
            },
        )
        self.db.add(alert)
        return alert

    def _is_internal(self, ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
            or ip in ("127.0.0.1", "::1")
        )
