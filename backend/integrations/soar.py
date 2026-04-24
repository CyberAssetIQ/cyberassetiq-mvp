"""
SOAR Connectors
---------------
Palo Alto XSOAR     — XSOAR REST API (create incidents with CyberAssetIQ context)
Tines               — Tines webhook (send-to-story endpoint)
Splunk SOAR         — Splunk SOAR (formerly Phantom) REST API

Key integration concept:
  CyberAssetIQ's remediation_class field drives playbook branching:
    auto_safe         → SOAR executes immediately
    approval_required → SOAR creates human approval task
    manual_only       → SOAR creates informational ticket only
    informational     → SOAR logs, no action required
"""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Any

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)

# Remediation class → SOAR severity/priority mapping
REMEDIATION_SEVERITY = {
    "informational": ("low", 1),
    "auto_safe": ("medium", 2),
    "approval_required": ("high", 3),
    "manual_only": ("critical", 4),
}


def _soar_payload(event: dict[str, Any]) -> dict:
    """Build a normalised SOAR incident payload from a CyberAssetIQ event."""
    rem_class = event.get("remediation_class", "informational")
    sev_label, sev_int = REMEDIATION_SEVERITY.get(rem_class, ("medium", 2))
    return {
        "name": f"[CyberAssetIQ] {event.get('event_type', 'Finding')} — {event.get('asset_name', 'Unknown')}",
        "severity": sev_label,
        "severity_int": sev_int,
        "description": event.get("description", ""),
        "occurred": datetime.utcnow().isoformat(),
        "details": {
            "tenant_id": event.get("tenant_id"),
            "asset_name": event.get("asset_name"),
            "asset_ip": event.get("asset_ip"),
            "cve_id": event.get("cve_id"),
            "cvss_score": event.get("cvss_score"),
            "ce_control": event.get("ce_control"),
            "ce_compliant": event.get("ce_compliant"),
            "secret_score": event.get("secret_score"),
            "remediation_class": rem_class,
            "remediation_action": event.get("remediation_action"),
            "source": "CyberAssetIQ v2.4",
        },
    }


# ======================================================================= #
# Palo Alto XSOAR                                                          #
# ======================================================================= #

class XSOARConnector(BaseConnector):
    """
    Palo Alto XSOAR (Cortex XSOAR) REST API.

    Creates XSOAR incidents from CyberAssetIQ findings.
    The remediation_class maps to XSOAR severity, driving playbook branching.

    Config keys:
      base_url   — e.g. https://xsoar.yourorg.com or https://api-xxx.crtx.eu.paloaltonetworks.com
      api_key    — XSOAR API key
      api_key_id — XSOAR API key ID (required for hosted/cloud XSOAR)
      incident_type — Optional XSOAR incident type name (default: CyberAssetIQ)
    """

    category = "soar"
    connector_type = "xsoar"

    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        api_key_id = self.config.get("api_key_id")
        if api_key_id:
            # XSOAR Cloud / Hosted authentication
            import hashlib, string, secrets as s
            nonce = "".join(s.choice(string.ascii_letters + string.digits) for _ in range(64))
            import time
            ts = str(int(time.time() * 1000))
            auth_str = f"{api_key_id}\n{nonce}\n{ts}"
            _hash = hashlib.sha256((self.config["api_key"] + auth_str).encode()).hexdigest()
            headers["x-xdr-nonce"] = nonce
            headers["x-xdr-timestamp"] = ts
            headers["x-xdr-auth-id"] = str(api_key_id)
            headers["x-xdr-hmac-sha256"] = _hash
        else:
            # On-prem XSOAR
            headers["Authorization"] = self.config["api_key"]
        return headers

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("base_url", "api_key")
        payload = _soar_payload(event)
        incident_payload = {
            "name": payload["name"],
            "type": self.config.get("incident_type", "CyberAssetIQ"),
            "severity": payload["severity_int"],
            "occurred": payload["occurred"],
            "details": str(payload["details"]),
            "CustomFields": payload["details"],
            "labels": [
                {"type": "asset", "value": event.get("asset_name", "")},
                {"type": "tenant", "value": event.get("tenant_id", "")},
                {"type": "remediation_class", "value": event.get("remediation_class", "")},
            ],
        }
        await self._post(
            f"{self.config['base_url'].rstrip('/')}/incident",
            incident_payload,
            headers=self._headers(),
        )
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("base_url", "api_key")
        try:
            resp = await self._get(
                f"{self.config['base_url'].rstrip('/')}/about",
                headers=self._headers(),
            )
            version = resp.json().get("demistoVersion", "unknown")
            return (True, f"XSOAR connected — version {version}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Tines                                                                    #
# ======================================================================= #

class TinesConnector(BaseConnector):
    """
    Tines webhook integration.

    Sends CyberAssetIQ events to a Tines 'Send to Story' webhook.
    The Tines story branches on `remediation_class` to implement the
    auto_safe / approval_required / manual_only playbook logic.

    Config keys:
      webhook_url — Tines 'Send to Story' webhook URL
                    (Tines → Actions → Webhook → Copy URL)
      secret      — Optional Tines webhook secret for HMAC validation
    """

    category = "soar"
    connector_type = "tines"

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("webhook_url")
        payload = {
            **_soar_payload(event),
            "source": "CyberAssetIQ",
            "raw_event": event,
        }
        headers = {"Content-Type": "application/json"}
        # Optionally sign the payload for Tines HMAC validation
        secret = self.config.get("secret")
        if secret:
            import hashlib, hmac as _hmac, json
            body = json.dumps(payload).encode()
            sig = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-CyberAssetIQ-Signature"] = f"sha256={sig}"

        await self._post(self.config["webhook_url"], payload, headers=headers)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("webhook_url")
        try:
            await self.send_event({
                "event_type": "ConnectionTest",
                "description": "CyberAssetIQ connectivity test",
                "remediation_class": "informational",
                "severity": 0,
            })
            return (True, "Tines webhook accepted test payload")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Splunk SOAR (formerly Phantom)                                           #
# ======================================================================= #

class SplunkSOARConnector(BaseConnector):
    """
    Splunk SOAR (Phantom) REST API.

    Creates SOAR containers (cases) and artifacts from CyberAssetIQ findings.
    Container severity maps from remediation_class, enabling playbook branching.

    Config keys:
      base_url   — e.g. https://phantom.yourorg.com
      auth_token — Phantom/SOAR REST API token (Administration > User Management)
      container_label — Optional label for containers (default: events)
    """

    category = "soar"
    connector_type = "splunk_soar"

    def _headers(self) -> dict:
        return {
            "ph-auth-token": self.config["auth_token"],
            "Content-Type": "application/json",
        }

    SEVERITY_MAP = {
        "informational": "low",
        "auto_safe": "medium",
        "approval_required": "high",
        "manual_only": "critical",
    }

    async def _create_container(self, event: dict[str, Any]) -> int:
        """Create a SOAR container (case) and return its ID."""
        rem_class = event.get("remediation_class", "informational")
        container = {
            "name": f"[CyberAssetIQ] {event.get('event_type', 'Finding')} — {event.get('asset_name', 'Unknown')}",
            "description": event.get("description", ""),
            "label": self.config.get("container_label", "events"),
            "severity": self.SEVERITY_MAP.get(rem_class, "medium"),
            "status": "new",
            "tags": ["cyberassetiq", event.get("tenant_id", ""), rem_class],
            "custom_fields": {
                "remediation_class": rem_class,
                "asset_name": event.get("asset_name"),
                "cve_id": event.get("cve_id"),
                "ce_control": event.get("ce_control"),
                "secret_score": event.get("secret_score"),
            },
        }
        resp = await self._post(
            f"{self.config['base_url'].rstrip('/')}/rest/container",
            container,
            headers=self._headers(),
        )
        return resp.json().get("id")

    async def _add_artifact(self, container_id: int, event: dict[str, Any]) -> None:
        """Add a structured artifact to the container."""
        cef = {
            "deviceAddress": event.get("asset_ip"),
            "deviceHostName": event.get("asset_name"),
            "message": event.get("description"),
            "cs1": event.get("cve_id"),
            "cs1Label": "CVE ID",
            "cs2": event.get("ce_control"),
            "cs2Label": "CE Control",
            "cfp1": event.get("secret_score"),
            "cfp1Label": "SecretScore",
            "cs3": event.get("remediation_class"),
            "cs3Label": "RemediationClass",
        }
        artifact = {
            "container_id": container_id,
            "name": "CyberAssetIQ Finding",
            "label": "artifact",
            "cef": {k: v for k, v in cef.items() if v is not None},
            "run_automation": event.get("remediation_class") == "auto_safe",
        }
        await self._post(
            f"{self.config['base_url'].rstrip('/')}/rest/artifact",
            artifact,
            headers=self._headers(),
        )

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("base_url", "auth_token")
        container_id = await self._create_container(event)
        if container_id:
            await self._add_artifact(container_id, event)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("base_url", "auth_token")
        try:
            resp = await self._get(
                f"{self.config['base_url'].rstrip('/')}/rest/version",
                headers=self._headers(),
            )
            version = resp.json().get("version", "unknown")
            return (True, f"Splunk SOAR connected — version {version}")
        except ConnectorError as exc:
            return (False, str(exc))
