"""
IAM / IDR Connectors
---------------------
Entra ID (Azure AD)  — Microsoft Graph API (identity risk + sign-in events)
Okta                 — Okta System Log API + Risk Events API
InsightIDR           — Rapid7 InsightIDR REST API

Integration model:
  PULL (inbound): Consume identity events into CyberAssetIQ identity risk engine
  PUSH (outbound): Raise user risk levels / create IDR investigations from findings
"""

from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


# ======================================================================= #
# Microsoft Entra ID (Azure Active Directory)                             #
# ======================================================================= #

class EntraIDConnector(BaseConnector):
    """
    Microsoft Entra ID via Microsoft Graph API.

    PULL: Sign-in risk events, audit logs → CyberAssetIQ identity risk engine.
    PUSH: Dismiss/confirm risky user states from CyberAssetIQ findings.
          Create conditional access signals for high-risk assets.

    Config keys:
      tenant_id     — Azure AD tenant ID
      client_id     — App registration client ID
      client_secret — App registration client secret
      (Permissions needed: IdentityRiskEvent.Read.All, User.Read.All,
       RiskyUser.ReadWrite.All, AuditLog.Read.All)
    """

    category = "iam"
    connector_type = "entraid"
    _token: str | None = None
    _token_expires: float = 0.0

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    async def _get_token(self, scope: str = "https://graph.microsoft.com/.default") -> str:
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
                "scope": scope,
            })
        if resp.status_code != 200:
            raise ConnectorError(f"Entra ID auth failed: {resp.text[:200]}")
        data = resp.json()
        self._token = data["access_token"]
        import time as t
        self._token_expires = t.time() + data.get("expires_in", 3599)
        return self._token

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def pull_risky_users(self) -> list[dict]:
        """Fetch users currently flagged as risky by Entra ID Protection."""
        token = await self._get_token()
        resp = await self._get(
            f"{self.GRAPH_BASE}/identityProtection/riskyUsers",
            headers=self._headers(token),
            params={"$top": 100, "$filter": "riskState eq 'atRisk'"},
        )
        return resp.json().get("value", [])

    async def pull_sign_in_events(self, hours_back: int = 24) -> list[dict]:
        """Fetch recent sign-in audit log entries."""
        token = await self._get_token()
        since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        resp = await self._get(
            f"{self.GRAPH_BASE}/auditLogs/signIns",
            headers=self._headers(token),
            params={
                "$top": 200,
                "$filter": f"createdDateTime ge {since}",
                "$orderby": "createdDateTime desc",
            },
        )
        return resp.json().get("value", [])

    async def confirm_user_compromised(self, user_id: str) -> bool:
        """Mark a user as compromised in Entra ID Protection."""
        token = await self._get_token()
        await self._post(
            f"{self.GRAPH_BASE}/identityProtection/riskyUsers/confirmCompromised",
            {"userIds": [user_id]},
            headers=self._headers(token),
        )
        return True

    async def dismiss_user_risk(self, user_id: str) -> bool:
        """Dismiss risk for a user (after remediation confirmed in CyberAssetIQ)."""
        token = await self._get_token()
        await self._post(
            f"{self.GRAPH_BASE}/identityProtection/riskyUsers/dismiss",
            {"userIds": [user_id]},
            headers=self._headers(token),
        )
        return True

    async def send_event(self, event: dict[str, Any]) -> bool:
        """
        Map CyberAssetIQ identity findings to Entra ID actions.
        - High-risk credential leak → confirm user compromised
        - Resolved finding         → dismiss user risk
        """
        user_id = event.get("entra_user_id")
        if not user_id:
            return True  # No Entra user mapping — skip

        if event.get("secret_score", 0) >= 0.85 and event.get("event_type") == "credential_leak":
            await self.confirm_user_compromised(user_id)
        elif event.get("resolved"):
            await self.dismiss_user_risk(user_id)

        return True

    async def test(self) -> tuple[bool, str]:
        try:
            token = await self._get_token()
            resp = await self._get(
                f"{self.GRAPH_BASE}/organization",
                headers=self._headers(token),
                params={"$top": 1, "$select": "displayName"},
            )
            org = resp.json().get("value", [{}])[0].get("displayName", "unknown")
            return (True, f"Entra ID connected — tenant: {org}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Okta                                                                     #
# ======================================================================= #

class OktaConnector(BaseConnector):
    """
    Okta System Log + Identity Engine Risk API.

    PULL: System log events → CyberAssetIQ identity anomaly engine.
    PUSH: Revoke sessions / elevate risk scores via Policy Simulation API.

    Config keys:
      okta_domain  — e.g. yourorg.okta.com
      api_token    — Okta API token (Security > API > Tokens)
    """

    category = "iam"
    connector_type = "okta"

    def _headers(self) -> dict:
        return {
            "Authorization": f"SSWS {self.config['api_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _base(self) -> str:
        domain = self.config["okta_domain"].replace("https://", "").strip("/")
        return f"https://{domain}"

    async def pull_system_log(self, since_hours: int = 24) -> list[dict]:
        """Pull Okta system log events from the last N hours."""
        self._require("okta_domain", "api_token")
        since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        events = []
        url = f"{self._base()}/api/v1/logs"
        params = {"since": since, "limit": 200, "sortOrder": "DESCENDING"}
        while url:
            resp = await self._get(url, headers=self._headers(), params=params)
            data = resp.json()
            events.extend(data if isinstance(data, list) else [])
            # Pagination via Link header
            link = resp.headers.get("Link", "")
            url = None
            params = {}
            if 'rel="next"' in link:
                for part in link.split(","):
                    if 'rel="next"' in part:
                        url = part.split(";")[0].strip().strip("<>")
            if len(events) >= 1000:
                break
        return events

    async def revoke_user_sessions(self, user_id: str) -> bool:
        """Clear all active sessions for a user (e.g. after credential leak confirmed)."""
        self._require("okta_domain", "api_token")
        await self._post(
            f"{self._base()}/api/v1/users/{user_id}/sessions",
            {},
            headers={**self._headers(), "X-HTTP-Method-Override": "DELETE"},
        )
        return True

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("okta_domain", "api_token")
        user_id = event.get("okta_user_id")
        if user_id and event.get("secret_score", 0) >= 0.85:
            await self.revoke_user_sessions(user_id)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("okta_domain", "api_token")
        try:
            resp = await self._get(
                f"{self._base()}/api/v1/users/me",
                headers=self._headers(),
            )
            profile = resp.json().get("profile", {})
            name = f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()
            return (True, f"Okta connected — API token owner: {name or 'unknown'}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Rapid7 InsightIDR                                                        #
# ======================================================================= #

class InsightIDRConnector(BaseConnector):
    """
    Rapid7 InsightIDR REST API.

    PULL: Investigations, user activity.
    PUSH: Create investigation entries from CyberAssetIQ findings.

    Config keys:
      api_key  — InsightIDR API key (Settings > API Keys)
      region   — us, eu, ca, au, ap (default: us)
    """

    category = "iam"
    connector_type = "insightidr"

    def _base(self) -> str:
        region = self.config.get("region", "us")
        return f"https://{region}.api.insight.rapid7.com/idr/v1"

    def _headers(self) -> dict:
        return {
            "X-Api-Key": self.config["api_key"],
            "Content-Type": "application/json",
        }

    async def create_investigation(self, title: str, description: str, priority: str = "MEDIUM") -> dict:
        """Create an InsightIDR investigation from a CyberAssetIQ finding."""
        self._require("api_key")
        payload = {
            "title": title,
            "status": "OPEN",
            "priority": priority,  # LOW | MEDIUM | HIGH | CRITICAL
            "disposition": "UNDECIDED",
        }
        resp = await self._post(
            f"{self._base()}/investigations",
            payload,
            headers=self._headers(),
        )
        created = resp.json()
        # Add alert to the investigation
        if description and created.get("id"):
            await self._post(
                f"{self._base()}/investigations/{created['id']}/alerts",
                {
                    "detection_rule_rrn": None,
                    "alert_type": "CyberAssetIQ",
                    "alert_type_description": description,
                },
                headers=self._headers(),
            )
        return created

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("api_key")
        severity = event.get("severity", 5)
        priority_map = {range(0, 4): "LOW", range(4, 7): "MEDIUM", range(7, 9): "HIGH", range(9, 11): "CRITICAL"}
        priority = "MEDIUM"
        for r, p in priority_map.items():
            if severity in r:
                priority = p
                break

        title = f"[CyberAssetIQ] {event.get('event_type', 'Security Finding')} — {event.get('asset_name', 'Unknown Asset')}"
        desc = (
            f"CVE: {event.get('cve_id', 'N/A')} | "
            f"CE Control: {event.get('ce_control', 'N/A')} | "
            f"SecretScore: {event.get('secret_score', 'N/A')} | "
            f"Remediation: {event.get('remediation_class', 'N/A')} | "
            f"{event.get('description', '')}"
        )
        await self.create_investigation(title, desc, priority)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("api_key")
        try:
            resp = await self._get(
                f"{self._base()}/investigations",
                headers=self._headers(),
                params={"size": 1},
            )
            total = resp.json().get("metadata", {}).get("total_data", "?")
            return (True, f"InsightIDR connected — {total} existing investigations")
        except ConnectorError as exc:
            return (False, str(exc))
