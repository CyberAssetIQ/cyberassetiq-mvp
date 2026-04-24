"""
EDR / XDR Connectors
--------------------
CrowdStrike Falcon   — Falcon API (OAuth2)
Microsoft Defender   — Microsoft Graph Security API + MDE API
SentinelOne          — SentinelOne Management Console API

Integration model:
  PULL: Enrich CyberAssetIQ asset records from EDR device inventory
  PUSH: Send CVE findings + asset tags into EDR for detection enrichment
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


# ======================================================================= #
# CrowdStrike Falcon                                                       #
# ======================================================================= #

class CrowdStrikeConnector(BaseConnector):
    """
    CrowdStrike Falcon API integration.

    PULL: Query Falcon device inventory to enrich CyberAssetIQ asset records.
    PUSH: Create custom IOC entries for high-confidence credential leaks.
          Tag devices with CE compliance status via Host Group management.

    Config keys:
      client_id      — Falcon API client ID
      client_secret  — Falcon API client secret
      base_url       — e.g. https://api.crowdstrike.com (default)
                       EU: https://api.eu-1.crowdstrike.com
    """

    category = "edr"
    connector_type = "crowdstrike"
    _token: str | None = None
    _token_expires: float = 0.0

    def _base(self) -> str:
        return self.config.get("base_url", "https://api.crowdstrike.com").rstrip("/")

    async def _get_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        self._require("client_id", "client_secret")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self._base()}/oauth2/token",
                data={
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code != 201:
            raise ConnectorError(f"CrowdStrike auth failed: {resp.text[:200]}")
        data = resp.json()
        import time as t
        self._token = data["access_token"]
        self._token_expires = t.time() + data.get("expires_in", 1799)
        return self._token

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def pull_devices(self) -> list[dict]:
        """Return CrowdStrike device list for asset reconciliation."""
        token = await self._get_token()
        # Step 1: get device IDs
        resp = await self._get(
            f"{self._base()}/devices/queries/devices/v1",
            headers=self._auth_headers(token),
            params={"limit": 500},
        )
        ids = resp.json().get("resources", [])
        if not ids:
            return []
        # Step 2: get device details
        details_resp = await self._post(
            f"{self._base()}/devices/entities/devices/v2",
            {"ids": ids[:100]},  # max 100 per call
            headers=self._auth_headers(token),
        )
        return details_resp.json().get("resources", [])

    async def send_event(self, event: dict[str, Any]) -> bool:
        """
        Send a CyberAssetIQ finding to CrowdStrike.
        - Credential leak → create custom IOC (sha256 hash of exposed key)
        - CVE finding    → add note/tag to the device
        """
        token = await self._get_token()
        event_type = event.get("event_type", "")

        if "secret" in event_type.lower() or "credential" in event_type.lower():
            # Create a custom SHA256 IOC so CrowdStrike watches for the leaked value
            secret_value = event.get("secret_value", "")
            if secret_value:
                import hashlib
                sha = hashlib.sha256(secret_value.encode()).hexdigest()
                ioc_payload = {
                    "indicators": [{
                        "type": "sha256",
                        "value": sha,
                        "action": "detect",
                        "severity": "high",
                        "description": f"CyberAssetIQ: Leaked credential detected. Score={event.get('secret_score')}",
                        "tags": ["CyberAssetIQ", "credential-leak"],
                        "platforms": ["windows", "linux", "mac"],
                        "applied_globally": True,
                        "expiration": None,
                    }]
                }
                await self._post(
                    f"{self._base()}/iocs/entities/indicators/v1",
                    ioc_payload,
                    headers=self._auth_headers(token),
                )

        elif event.get("cve_id"):
            # Tag the device with the CVE for cross-platform correlation
            device_id = event.get("crowdstrike_device_id")
            if device_id:
                tag_payload = {
                    "action_parameters": [{"name": "tag", "value": f"CVE:{event['cve_id']}"}],
                    "ids": [device_id],
                }
                await self._post(
                    f"{self._base()}/devices/entities/devices/actions/v2?action_name=add_tag",
                    tag_payload,
                    headers=self._auth_headers(token),
                )
        return True

    async def test(self) -> tuple[bool, str]:
        try:
            token = await self._get_token()
            resp = await self._get(
                f"{self._base()}/sensors/combined/installers/v1",
                headers=self._auth_headers(token),
                params={"limit": 1},
            )
            return (True, "CrowdStrike Falcon API authenticated successfully")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Microsoft Defender for Endpoint                                          #
# ======================================================================= #

class DefenderConnector(BaseConnector):
    """
    Microsoft Defender for Endpoint via Microsoft Graph Security API.

    PULL: Machine inventory, software vulnerabilities (via TVM).
    PUSH: Create alerts / machine tags from CyberAssetIQ findings.

    Config keys:
      tenant_id     — Azure AD tenant ID
      client_id     — App registration client ID
      client_secret — App registration client secret
      (App needs: Machine.ReadWrite.All, SecurityEvents.ReadWrite.All)
    """

    category = "edr"
    connector_type = "defender"
    _token: str | None = None
    _token_expires: float = 0.0

    async def _get_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        self._require("tenant_id", "client_id", "client_secret")
        url = f"https://login.microsoftonline.com/{self.config['tenant_id']}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, data={
                "grant_type": "client_credentials",
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "scope": "https://api.securitycenter.microsoft.com/.default",
            })
        if resp.status_code != 200:
            raise ConnectorError(f"Defender auth failed: {resp.text[:200]}")
        data = resp.json()
        self._token = data["access_token"]
        import time as t
        self._token_expires = t.time() + data.get("expires_in", 3599)
        return self._token

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    MDE_BASE = "https://api.securitycenter.microsoft.com/api"

    async def pull_machines(self) -> list[dict]:
        """Fetch MDE machine inventory for asset enrichment."""
        token = await self._get_token()
        resp = await self._get(f"{self.MDE_BASE}/machines", headers=self._headers(token))
        return resp.json().get("value", [])

    async def pull_vulnerabilities(self) -> list[dict]:
        """Fetch TVM (Threat & Vulnerability Management) findings."""
        token = await self._get_token()
        resp = await self._get(
            f"{self.MDE_BASE}/vulnerabilities/machinesVulnerabilities",
            headers=self._headers(token),
        )
        return resp.json().get("value", [])

    async def send_event(self, event: dict[str, Any]) -> bool:
        token = await self._get_token()

        if event.get("asset_name") and event.get("cve_id"):
            # Tag the machine with CE compliance status
            machine_id = event.get("defender_machine_id")
            if machine_id:
                tag = f"CyberAssetIQ-{event.get('ce_compliant', 'unknown')}"
                await self._post(
                    f"{self.MDE_BASE}/machines/{machine_id}/tags",
                    {"Value": tag, "Action": "Add"},
                    headers=self._headers(token),
                )

        if event.get("secret_score", 0) >= 0.7:
            # Create a Defender security alert via Graph Security API
            # Requires separate Graph token scope
            alert_payload = {
                "description": f"CyberAssetIQ: High-confidence credential leak detected. SecretScore={event.get('secret_score')}",
                "severity": "high" if event.get("secret_score", 0) >= 0.85 else "medium",
                "status": "newAlert",
                "category": "CredentialAccess",
                "recommendedActions": "Revoke and rotate the exposed credential immediately.",
                "vendorInformation": {
                    "provider": "CyberAssetIQ",
                    "providerVersion": "2.4",
                    "subProvider": "SecretScore",
                    "vendor": "TotalIT Solutions",
                },
            }
            # Graph Security API alert creation
            graph_url = "https://graph.microsoft.com/v1.0/security/alerts"
            # Note: alert creation requires SecurityEvents.ReadWrite.All on Graph scope
            # This is a best-effort push; failure is non-fatal
            try:
                await self._post(graph_url, alert_payload, headers=self._headers(token))
            except ConnectorError:
                pass  # Graph alert creation is supplementary

        return True

    async def test(self) -> tuple[bool, str]:
        try:
            token = await self._get_token()
            resp = await self._get(
                f"{self.MDE_BASE}/machines",
                headers=self._headers(token),
                params={"$top": 1},
            )
            count = len(resp.json().get("value", []))
            return (True, f"Defender for Endpoint connected — {count}+ device(s) visible")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# SentinelOne                                                              #
# ======================================================================= #

class SentinelOneConnector(BaseConnector):
    """
    SentinelOne Management API integration.

    PULL: Agent/endpoint inventory.
    PUSH: Create threats / notes from CyberAssetIQ findings.
          Apply tags to agents for CE compliance tracking.

    Config keys:
      console_url  — e.g. https://usea1.sentinelone.net
      api_token    — Management API token (Settings > Users > API Token)
    """

    category = "edr"
    connector_type = "sentinelone"

    def _headers(self) -> dict:
        return {
            "Authorization": f"ApiToken {self.config['api_token']}",
            "Content-Type": "application/json",
        }

    def _base(self) -> str:
        return self.config["console_url"].rstrip("/")

    async def pull_agents(self) -> list[dict]:
        """Fetch SentinelOne agent inventory."""
        self._require("console_url", "api_token")
        resp = await self._get(
            f"{self._base()}/web/api/v2.1/agents",
            headers=self._headers(),
            params={"limit": 500, "isActive": "true"},
        )
        return resp.json().get("data", [])

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("console_url", "api_token")

        agent_id = event.get("s1_agent_id")
        if agent_id:
            # Add a note to the agent's threat timeline
            note_payload = {
                "data": {
                    "agentId": agent_id,
                    "text": (
                        f"[CyberAssetIQ] {event.get('event_type', 'Finding')}: "
                        f"{event.get('description', '')} "
                        f"| CVE: {event.get('cve_id', 'N/A')} "
                        f"| CE Control: {event.get('ce_control', 'N/A')} "
                        f"| SecretScore: {event.get('secret_score', 'N/A')}"
                    ),
                }
            }
            try:
                await self._post(
                    f"{self._base()}/web/api/v2.1/threats/notes",
                    note_payload,
                    headers=self._headers(),
                )
            except ConnectorError:
                pass  # Non-fatal if agent not found

        # Apply CE compliance tag to the agent
        if agent_id and "ce_compliant" in event:
            tag = "CE-Compliant" if event["ce_compliant"] else "CE-NonCompliant"
            tag_payload = {
                "data": {"tags": [tag]},
                "filter": {"ids": [agent_id]},
            }
            await self._post(
                f"{self._base()}/web/api/v2.1/agents/actions/add-tag",
                tag_payload,
                headers=self._headers(),
            )

        return True

    async def test(self) -> tuple[bool, str]:
        self._require("console_url", "api_token")
        try:
            resp = await self._get(
                f"{self._base()}/web/api/v2.1/system/status",
                headers=self._headers(),
            )
            health = resp.json().get("data", {}).get("health", "unknown")
            return (True, f"SentinelOne connected — system health: {health}")
        except ConnectorError as exc:
            return (False, str(exc))
