"""
MSP / MSSP Connectors
----------------------
ConnectWise Manage  — PSA REST API (create service tickets + alerts)
Datto RMM           — Datto RMM API (device correlation + alert creation)
N-able N-central    — N-able REST API (device info + notification push)

Integration model:
  MSPs already live in ConnectWise/Datto/N-able all day.
  CyberAssetIQ pushes its composite health scores, CE status, and critical
  findings into those platforms so MSPs never need to context-switch.
"""

from __future__ import annotations
import base64
import logging
from datetime import datetime
from typing import Any

import httpx

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


# ======================================================================= #
# ConnectWise Manage                                                       #
# ======================================================================= #

class ConnectWiseConnector(BaseConnector):
    """
    ConnectWise Manage PSA — create service tickets and alerts from
    CyberAssetIQ findings.

    Config keys:
      site          — e.g. na.myconnectwise.net
      company_id    — ConnectWise company ID
      public_key    — API Member public key
      private_key   — API Member private key
      board_id      — Service board ID (integer) for new tickets
      company_rec_id — (optional) Company record ID to assign tickets
      priority_id   — (optional) Priority record ID (default: 3 = Medium)
    """

    category = "msp"
    connector_type = "connectwise"

    def _auth_header(self) -> str:
        creds = f"{self.config['company_id']}+{self.config['public_key']}:{self.config['private_key']}"
        encoded = base64.b64encode(creds.encode()).decode()
        return f"Basic {encoded}"

    def _headers(self) -> dict:
        return {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
            "clientId": self.config.get("client_id", "cyberassetiq"),
        }

    def _base(self) -> str:
        site = self.config["site"].replace("https://", "").strip("/")
        return f"https://{site}/v4_6_release/apis/3.0"

    def _severity_to_priority(self, event: dict) -> int:
        """Map CyberAssetIQ severity to ConnectWise Priority record ID."""
        sev = event.get("severity", 5)
        rem = event.get("remediation_class", "informational")
        if rem == "manual_only" or sev >= 9:
            return 1   # Priority 1 — Critical
        if rem == "approval_required" or sev >= 7:
            return 2   # Priority 2 — High
        if rem == "auto_safe" or sev >= 4:
            return 3   # Priority 3 — Medium
        return 4       # Priority 4 — Low

    async def create_ticket(self, event: dict[str, Any]) -> dict:
        self._require("site", "company_id", "public_key", "private_key", "board_id")
        summary = (
            f"[CyberAssetIQ] {event.get('event_type', 'Security Finding')} "
            f"— {event.get('asset_name', 'Unknown Asset')}"
        )
        initial_desc = (
            f"Finding from CyberAssetIQ\n\n"
            f"Asset: {event.get('asset_name', 'N/A')}\n"
            f"IP: {event.get('asset_ip', 'N/A')}\n"
            f"CVE: {event.get('cve_id', 'N/A')}\n"
            f"CE Control: {event.get('ce_control', 'N/A')}\n"
            f"CE Compliant: {event.get('ce_compliant', 'N/A')}\n"
            f"SecretScore: {event.get('secret_score', 'N/A')}\n"
            f"Remediation Class: {event.get('remediation_class', 'N/A')}\n"
            f"Remediation Action: {event.get('remediation_action', 'N/A')}\n\n"
            f"Description: {event.get('description', '')}\n"
            f"Tenant: {event.get('tenant_id', 'N/A')}\n"
            f"Raised at: {datetime.utcnow().isoformat()} UTC"
        )
        ticket = {
            "summary": summary[:100],
            "initialDescription": initial_desc,
            "board": {"id": int(self.config["board_id"])},
            "status": {"name": "New"},
            "priority": {"id": self._severity_to_priority(event)},
        }
        if self.config.get("company_rec_id"):
            ticket["company"] = {"id": int(self.config["company_rec_id"])}
        resp = await self._post(
            f"{self._base()}/service/tickets",
            ticket,
            headers=self._headers(),
        )
        return resp.json()

    async def send_event(self, event: dict[str, Any]) -> bool:
        await self.create_ticket(event)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("site", "company_id", "public_key", "private_key")
        try:
            resp = await self._get(
                f"{self._base()}/system/info",
                headers=self._headers(),
            )
            ver = resp.json().get("version", "unknown")
            return (True, f"ConnectWise Manage connected — version {ver}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Datto RMM                                                                #
# ======================================================================= #

class DattoRMMConnector(BaseConnector):
    """
    Datto RMM REST API.

    PULL: Device inventory for asset enrichment.
    PUSH: Create alerts on devices from CyberAssetIQ findings.

    Config keys:
      api_url     — e.g. https://pinotage-api.centrastage.net
      api_key     — Datto RMM API key
      api_secret  — Datto RMM API secret
    """

    category = "msp"
    connector_type = "datto"
    _token: str | None = None
    _token_expires: float = 0.0

    async def _get_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        self._require("api_url", "api_key", "api_secret")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self.config['api_url'].rstrip('/')}/auth/oauth/token",
                data={
                    "grant_type": "password",
                    "username": self.config["api_key"],
                    "password": self.config["api_secret"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code != 200:
            raise ConnectorError(f"Datto auth failed: {resp.text[:200]}")
        data = resp.json()
        self._token = data["access_token"]
        import time as t
        self._token_expires = t.time() + data.get("expires_in", 3599)
        return self._token

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def pull_devices(self) -> list[dict]:
        """Fetch all Datto RMM devices."""
        token = await self._get_token()
        devices = []
        url = f"{self.config['api_url'].rstrip('/')}/api/v2/account/devices"
        while url:
            resp = await self._get(url, headers=self._headers(token))
            data = resp.json()
            devices.extend(data.get("devices", []))
            url = data.get("pageDetails", {}).get("nextPageUrl")
            if len(devices) >= 2000:
                break
        return devices

    async def create_alert(self, device_uid: str, message: str, priority: str = "Default") -> bool:
        """Create a Datto RMM alert on a device."""
        token = await self._get_token()
        payload = {
            "resolved": False,
            "alertMessage": message[:500],
            "priority": priority,  # Default | High | Critical
        }
        await self._post(
            f"{self.config['api_url'].rstrip('/')}/api/v2/device/{device_uid}/alert",
            payload,
            headers=self._headers(token),
        )
        return True

    async def send_event(self, event: dict[str, Any]) -> bool:
        device_uid = event.get("datto_device_uid")
        if device_uid:
            rem = event.get("remediation_class", "informational")
            priority = "Critical" if rem in ("approval_required", "manual_only") else "Default"
            msg = (
                f"[CyberAssetIQ] {event.get('event_type', 'Finding')}: "
                f"{event.get('description', '')} | "
                f"CVE: {event.get('cve_id', 'N/A')} | "
                f"SecretScore: {event.get('secret_score', 'N/A')}"
            )
            await self.create_alert(device_uid, msg, priority)
        return True

    async def test(self) -> tuple[bool, str]:
        try:
            token = await self._get_token()
            resp = await self._get(
                f"{self.config['api_url'].rstrip('/')}/api/v2/account",
                headers=self._headers(token),
            )
            name = resp.json().get("name", "unknown")
            return (True, f"Datto RMM connected — account: {name}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# N-able N-central                                                         #
# ======================================================================= #

class NableConnector(BaseConnector):
    """
    N-able N-central REST API.

    PULL: Device/customer inventory.
    PUSH: Send notifications and custom service status from CyberAssetIQ findings.

    Config keys:
      base_url    — e.g. https://n-central.yourorg.com
      api_token   — N-central API token (Administration > API Access)
    """

    category = "msp"
    connector_type = "nable"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.config['api_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _base(self) -> str:
        return self.config["base_url"].rstrip("/")

    async def pull_customers(self) -> list[dict]:
        """Fetch N-central customers (maps to CyberAssetIQ tenants)."""
        self._require("base_url", "api_token")
        resp = await self._get(
            f"{self._base()}/api/customers",
            headers=self._headers(),
        )
        return resp.json().get("data", [])

    async def pull_devices(self, customer_id: str | None = None) -> list[dict]:
        """Fetch N-central devices, optionally filtered by customer."""
        self._require("base_url", "api_token")
        url = f"{self._base()}/api/devices"
        params = {}
        if customer_id:
            params["customerId"] = customer_id
        resp = await self._get(url, headers=self._headers(), params=params)
        return resp.json().get("data", [])

    async def send_notification(self, device_id: str, subject: str, body: str) -> bool:
        """Send a notification associated with a device."""
        self._require("base_url", "api_token")
        payload = {
            "deviceId": device_id,
            "subject": subject[:200],
            "body": body[:2000],
        }
        await self._post(
            f"{self._base()}/api/notifications",
            payload,
            headers=self._headers(),
        )
        return True

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("base_url", "api_token")
        device_id = event.get("nable_device_id")
        if device_id:
            subject = f"[CyberAssetIQ] {event.get('event_type', 'Finding')} — {event.get('asset_name', 'Unknown')}"
            body = (
                f"CyberAssetIQ Security Finding\n\n"
                f"CVE: {event.get('cve_id', 'N/A')}\n"
                f"CE Control: {event.get('ce_control', 'N/A')}\n"
                f"CE Compliant: {event.get('ce_compliant', 'N/A')}\n"
                f"SecretScore: {event.get('secret_score', 'N/A')}\n"
                f"Remediation: {event.get('remediation_class', 'N/A')} — {event.get('remediation_action', 'N/A')}\n\n"
                f"{event.get('description', '')}"
            )
            await self.send_notification(device_id, subject, body)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("base_url", "api_token")
        try:
            resp = await self._get(
                f"{self._base()}/api/server-info",
                headers=self._headers(),
            )
            version = resp.json().get("version", "unknown")
            return (True, f"N-able N-central connected — version {version}")
        except ConnectorError as exc:
            return (False, str(exc))
