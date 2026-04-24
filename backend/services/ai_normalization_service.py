"""
AI Normalization Service
Converts raw logs from different sources into CyberAssetIQ's common AI event schema.
Supports: Windows Events, Linux Syslog, Firewall, Identity (Entra/Okta/AD), Cloud (Azure/AWS/GCP).
"""
import logging
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class NormalisedEvent:
    """Common event representation after normalisation."""
    def __init__(
        self,
        event_type: str,
        event_category: str,
        severity: str,
        title: str,
        description: str,
        source_type: str,
        source_name: Optional[str] = None,
        user_ref: Optional[str] = None,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        asset_name: Optional[str] = None,
        occurred_at: Optional[datetime] = None,
        raw_payload: Optional[dict] = None,
        tags: Optional[list] = None,
    ):
        self.event_type = event_type
        self.event_category = event_category
        self.severity = severity
        self.title = title
        self.description = description
        self.source_type = source_type
        self.source_name = source_name
        self.user_ref = user_ref
        self.ip_address = ip_address
        self.hostname = hostname
        self.asset_name = asset_name
        self.occurred_at = occurred_at or datetime.now(timezone.utc)
        self.raw_payload = raw_payload or {}
        self.tags = tags or []


class AINormalizationService:

    # ------------------------------------------------------------------
    # Windows Event Log
    # ------------------------------------------------------------------
    def normalize_windows_event(self, raw: dict) -> NormalisedEvent:
        event_id = str(raw.get("EventID", raw.get("event_id", "")))
        computer = raw.get("Computer", raw.get("hostname", ""))
        user = raw.get("SubjectUserName", raw.get("TargetUserName", raw.get("user", "")))
        ip = raw.get("IpAddress", raw.get("ip_address", ""))
        timestamp = self._parse_timestamp(raw.get("TimeCreated", raw.get("timestamp")))

        # Map Windows Event IDs to meaningful types
        mapping = {
            "4624": ("login_success",    "identity", "low",      "Successful Windows logon"),
            "4625": ("login_failure",    "identity", "medium",   "Failed Windows logon attempt"),
            "4720": ("account_created",  "identity", "medium",   "New user account created"),
            "4728": ("group_modified",   "identity", "medium",   "Member added to security-enabled global group"),
            "4732": ("group_modified",   "identity", "medium",   "Member added to security-enabled local group"),
            "4756": ("group_modified",   "identity", "medium",   "Member added to security-enabled universal group"),
            "4740": ("account_locked",   "identity", "high",     "User account locked out"),
            "4648": ("explicit_logon",   "identity", "medium",   "Logon using explicit credentials"),
            "4672": ("admin_logon",      "identity", "medium",   "Special privileges assigned"),
            "4697": ("service_install",  "execution","high",     "Service installed on system"),
            "4698": ("scheduled_task",   "persistence","medium", "Scheduled task created"),
            "4702": ("scheduled_task",   "persistence","medium", "Scheduled task updated"),
            "4688": ("process_start",    "execution","low",      "New process created"),
            "4689": ("process_end",      "execution","low",      "Process terminated"),
            "4719": ("policy_change",    "defense",  "high",     "System audit policy changed"),
            "4738": ("account_modified", "identity", "medium",   "User account changed"),
            "4776": ("credential_valid", "identity", "low",      "Credential validation attempt"),
            "4778": ("session_reconnect","identity", "low",      "Session reconnected"),
            "1102": ("log_cleared",      "defense",  "critical", "Audit log cleared"),
            "7045": ("service_install",  "execution","high",     "New service installed"),
        }

        ev_type, ev_cat, severity, title = mapping.get(
            event_id, ("windows_event", "system", "low", f"Windows Event {event_id}")
        )

        # Elevate failed logins
        if ev_type == "login_failure" and ip and not ip.startswith(("10.", "192.168.", "172.")):
            severity = "high"
            title = "Failed logon from external IP"

        description = (
            f"Event ID {event_id} on {computer}."
            + (f" User: {user}." if user else "")
            + (f" Source IP: {ip}." if ip else "")
        )

        return NormalisedEvent(
            event_type=ev_type,
            event_category=ev_cat,
            severity=severity,
            title=title,
            description=description,
            source_type="windows",
            source_name=computer,
            user_ref=user or None,
            ip_address=ip or None,
            hostname=computer or None,
            asset_name=computer or None,
            occurred_at=timestamp,
            raw_payload=raw,
            tags=["windows", f"event-{event_id}"],
        )

    # ------------------------------------------------------------------
    # Linux Syslog
    # ------------------------------------------------------------------
    def normalize_syslog_event(self, raw: dict) -> NormalisedEvent:
        message = raw.get("message", raw.get("msg", ""))
        hostname = raw.get("hostname", raw.get("host", ""))
        program = raw.get("program", raw.get("proc", ""))
        timestamp = self._parse_timestamp(raw.get("timestamp", raw.get("time")))

        msg_l = message.lower()

        if "failed password" in msg_l or "authentication failure" in msg_l:
            user = self._extract_user_syslog(message)
            ip = self._extract_ip(message)
            return NormalisedEvent(
                event_type="login_failure",
                event_category="identity",
                severity="medium",
                title="SSH authentication failure",
                description=message,
                source_type="linux",
                source_name=program,
                user_ref=user,
                ip_address=ip,
                hostname=hostname,
                asset_name=hostname,
                occurred_at=timestamp,
                raw_payload=raw,
                tags=["linux", "ssh", "auth"],
            )
        elif "accepted password" in msg_l or "accepted publickey" in msg_l:
            user = self._extract_user_syslog(message)
            ip = self._extract_ip(message)
            return NormalisedEvent(
                event_type="login_success",
                event_category="identity",
                severity="low",
                title="SSH login successful",
                description=message,
                source_type="linux",
                source_name=program,
                user_ref=user,
                ip_address=ip,
                hostname=hostname,
                asset_name=hostname,
                occurred_at=timestamp,
                raw_payload=raw,
                tags=["linux", "ssh", "auth"],
            )
        elif "sudo" in msg_l and ("command" in msg_l or "root" in msg_l):
            return NormalisedEvent(
                event_type="sudo_execution",
                event_category="privilege",
                severity="medium",
                title="Sudo command executed",
                description=message,
                source_type="linux",
                source_name=program,
                hostname=hostname,
                asset_name=hostname,
                occurred_at=timestamp,
                raw_payload=raw,
                tags=["linux", "sudo", "privilege"],
            )
        elif "segfault" in msg_l or "kernel" in msg_l:
            return NormalisedEvent(
                event_type="kernel_event",
                event_category="system",
                severity="low",
                title="Kernel / system event",
                description=message,
                source_type="linux",
                source_name=program,
                hostname=hostname,
                asset_name=hostname,
                occurred_at=timestamp,
                raw_payload=raw,
                tags=["linux", "kernel"],
            )

        return NormalisedEvent(
            event_type="syslog_event",
            event_category="system",
            severity="low",
            title=f"Syslog: {program or 'unknown'}",
            description=message,
            source_type="linux",
            source_name=program,
            hostname=hostname,
            asset_name=hostname,
            occurred_at=timestamp,
            raw_payload=raw,
            tags=["linux", "syslog"],
        )

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------
    def normalize_firewall_event(self, raw: dict) -> NormalisedEvent:
        action = raw.get("action", raw.get("rule_action", "unknown")).upper()
        src_ip = raw.get("src_ip", raw.get("source_ip", ""))
        dst_ip = raw.get("dst_ip", raw.get("dest_ip", ""))
        dst_port = raw.get("dst_port", raw.get("dest_port", ""))
        protocol = raw.get("protocol", raw.get("proto", ""))
        device = raw.get("device", raw.get("hostname", "firewall"))
        timestamp = self._parse_timestamp(raw.get("timestamp", raw.get("time")))

        is_blocked = action in ("DENY", "DROP", "BLOCK", "REJECT")
        is_external = src_ip and not self._is_rfc1918(src_ip)

        if is_blocked and is_external:
            severity = "medium"
            ev_type = "firewall_block_external"
            title = f"Firewall blocked inbound from {src_ip} to port {dst_port}"
        elif is_blocked:
            severity = "low"
            ev_type = "firewall_block"
            title = f"Firewall blocked traffic to port {dst_port}"
        else:
            severity = "low"
            ev_type = "firewall_allow"
            title = f"Firewall allowed traffic to port {dst_port}"

        return NormalisedEvent(
            event_type=ev_type,
            event_category="network",
            severity=severity,
            title=title,
            description=f"{action}: {src_ip} -> {dst_ip}:{dst_port}/{protocol}",
            source_type="firewall",
            source_name=device,
            ip_address=src_ip,
            occurred_at=timestamp,
            raw_payload=raw,
            tags=["firewall", action.lower()],
        )

    # ------------------------------------------------------------------
    # Identity (Entra ID / Okta / Active Directory)
    # ------------------------------------------------------------------
    def normalize_identity_event(self, raw: dict) -> NormalisedEvent:
        provider = raw.get("provider", raw.get("source", "identity")).lower()
        operation = raw.get("operation", raw.get("operationName", raw.get("event_type", ""))).lower()
        user = raw.get("user", raw.get("userPrincipalName", raw.get("actor", "")))
        ip = raw.get("ip", raw.get("ipAddress", raw.get("client_ip", "")))
        location = raw.get("location", raw.get("country", ""))
        result = raw.get("result", raw.get("resultType", "success")).lower()
        timestamp = self._parse_timestamp(raw.get("timestamp", raw.get("createdDateTime")))

        failed = result in ("failure", "failed", "error", "1", "50126", "50055")

        if "signin" in operation or "login" in operation or "authenticate" in operation:
            if failed:
                ev_type = "login_failure"
                severity = "medium"
                title = f"Identity sign-in failure for {user}"
            else:
                ev_type = "login_success"
                severity = "low"
                title = f"Identity sign-in success for {user}"
        elif "password" in operation and "reset" in operation:
            ev_type = "password_reset"
            severity = "medium"
            title = f"Password reset for {user}"
        elif "add member" in operation or "addmember" in operation:
            ev_type = "group_modified"
            severity = "medium"
            title = f"User added to group: {user}"
        elif "delete user" in operation or "removeuser" in operation:
            ev_type = "account_deleted"
            severity = "medium"
            title = f"User account deleted: {user}"
        elif "mfa" in operation and ("disable" in operation or "removed" in operation):
            ev_type = "mfa_disabled"
            severity = "high"
            title = f"MFA disabled for {user}"
        else:
            ev_type = "identity_event"
            severity = "low"
            title = f"Identity event ({operation}) for {user}"

        description = f"{provider.upper()} — {operation}. User: {user}. IP: {ip}. Location: {location}. Result: {result}."

        return NormalisedEvent(
            event_type=ev_type,
            event_category="identity",
            severity=severity,
            title=title,
            description=description,
            source_type="identity",
            source_name=provider,
            user_ref=user or None,
            ip_address=ip or None,
            occurred_at=timestamp,
            raw_payload=raw,
            tags=["identity", provider, ev_type],
        )

    # ------------------------------------------------------------------
    # Cloud (Azure / AWS / GCP)
    # ------------------------------------------------------------------
    def normalize_cloud_event(self, raw: dict) -> NormalisedEvent:
        provider = raw.get("provider", raw.get("cloud", "cloud")).lower()
        operation = raw.get("operationName", raw.get("eventName", raw.get("operation", ""))).lower()
        user = raw.get("caller", raw.get("userIdentity", raw.get("principal", {}))).get("arn", "") if isinstance(raw.get("userIdentity"), dict) else raw.get("caller", "")
        ip = raw.get("callerIpAddress", raw.get("sourceIPAddress", ""))
        timestamp = self._parse_timestamp(raw.get("time", raw.get("eventTime")))
        result = raw.get("resultType", raw.get("errorCode", "success"))
        failed = result not in ("", "success", "Success", None)

        severity = "low"
        ev_type = "cloud_event"
        title = f"Cloud operation: {operation}"

        dangerous_ops = [
            "delete", "destroy", "remove", "disable", "revoke", "detach",
            "createaccesskey", "deleteaccesskey", "putbucketpolicy", "putbucketacl",
            "createbucket", "deletebucket", "updateassumerolepolicy",
        ]
        op_clean = operation.replace("-", "").replace("_", "").lower()

        if any(d in op_clean for d in dangerous_ops):
            severity = "high"
            ev_type = "cloud_dangerous_operation"
            title = f"Sensitive cloud operation: {operation}"
        elif "iam" in op_clean or "role" in op_clean or "policy" in op_clean:
            severity = "medium"
            ev_type = "cloud_iam_change"
            title = f"Cloud IAM/policy change: {operation}"
        elif failed:
            severity = "medium"
            ev_type = "cloud_error"
            title = f"Cloud operation failed: {operation} ({result})"

        return NormalisedEvent(
            event_type=ev_type,
            event_category="cloud",
            severity=severity,
            title=title,
            description=f"{provider.upper()} — {operation}. User: {user}. IP: {ip}. Result: {result}.",
            source_type="cloud",
            source_name=provider,
            user_ref=user or None,
            ip_address=ip or None,
            occurred_at=timestamp,
            raw_payload=raw,
            tags=["cloud", provider, ev_type],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _parse_timestamp(self, ts) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def _extract_user_syslog(self, message: str) -> Optional[str]:
        m = re.search(r"user\s+(\S+)", message, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"for\s+(\S+)\s+from", message, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    def _extract_ip(self, message: str) -> Optional[str]:
        m = re.search(r"from\s+([\d.]+)", message)
        if m:
            return m.group(1)
        m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", message)
        if m:
            return m.group(1)
        return None

    def _is_rfc1918(self, ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
            or ip in ("127.0.0.1", "::1", "localhost")
        )
