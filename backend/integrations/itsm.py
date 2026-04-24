"""
ITSM / Ticketing Connectors
----------------------------
Jira Software / Jira Service Management  — Jira REST API v3
ServiceNow                               — ServiceNow Table API
Freshservice                             — Freshservice REST API

Integration model:
  Auto-create tickets when CyberAssetIQ raises:
    - Critical CVE findings
    - CE compliance failures
    - High-confidence credential leaks (SecretScore ≥ 0.7)
    - Patch management failures
  Ticket carries asset context, remediation class, and suggested action.
"""

from __future__ import annotations
import base64
import logging
from datetime import datetime
from typing import Any

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


def _ticket_body(event: dict[str, Any]) -> str:
    """Build a structured ticket description from a CyberAssetIQ event."""
    return (
        f"*Security finding raised by CyberAssetIQ*\n\n"
        f"*Asset:* {event.get('asset_name', 'N/A')}\n"
        f"*Asset IP:* {event.get('asset_ip', 'N/A')}\n"
        f"*Tenant:* {event.get('tenant_id', 'N/A')}\n"
        f"*Event Type:* {event.get('event_type', 'N/A')}\n\n"
        f"*CVE:* {event.get('cve_id', 'N/A')}\n"
        f"*CVSS Score:* {event.get('cvss_score', 'N/A')}\n"
        f"*CE Control:* {event.get('ce_control', 'N/A')}\n"
        f"*CE Compliant:* {event.get('ce_compliant', 'N/A')}\n"
        f"*SecretScore:* {event.get('secret_score', 'N/A')}\n\n"
        f"*Remediation Class:* {event.get('remediation_class', 'N/A')}\n"
        f"*Suggested Action:* {event.get('remediation_action', 'N/A')}\n\n"
        f"*Description:*\n{event.get('description', '')}\n\n"
        f"_Raised: {datetime.utcnow().isoformat()} UTC | Source: CyberAssetIQ v2.4_"
    )


# ======================================================================= #
# Jira                                                                     #
# ======================================================================= #

class JiraConnector(BaseConnector):
    """
    Jira Software / Jira Service Management REST API v3.

    Creates Jira issues from CyberAssetIQ findings.
    Supports both cloud (atlassian.net) and self-hosted Jira.

    Config keys:
      jira_url     — e.g. https://yourorg.atlassian.net or https://jira.internal.com
      email        — Jira user email (for cloud) or username (for server)
      api_token    — Jira API token (cloud) or password (server)
      project_key  — Jira project key, e.g. SEC or IT
      issue_type   — Optional issue type name (default: Task)
      label        — Optional label to add, e.g. CyberAssetIQ
    """

    category = "itsm"
    connector_type = "jira"

    def _headers(self) -> dict:
        creds = base64.b64encode(
            f"{self.config['email']}:{self.config['api_token']}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _base(self) -> str:
        return self.config["jira_url"].rstrip("/")

    def _priority_name(self, event: dict) -> str:
        rem = event.get("remediation_class", "informational")
        sev = event.get("severity", 5)
        if rem == "manual_only" or sev >= 9:
            return "Highest"
        if rem == "approval_required" or sev >= 7:
            return "High"
        if rem == "auto_safe" or sev >= 4:
            return "Medium"
        return "Low"

    async def create_issue(self, event: dict[str, Any]) -> dict:
        self._require("jira_url", "email", "api_token", "project_key")
        summary = (
            f"[CyberAssetIQ] {event.get('event_type', 'Finding')}: "
            f"{event.get('asset_name', 'Unknown Asset')}"
        )
        if event.get("cve_id"):
            summary += f" ({event['cve_id']})"

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.config["project_key"]},
                "summary": summary[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": _ticket_body(event)}],
                    }],
                },
                "issuetype": {"name": self.config.get("issue_type", "Task")},
                "priority": {"name": self._priority_name(event)},
            }
        }
        label = self.config.get("label", "CyberAssetIQ")
        if label:
            payload["fields"]["labels"] = [label, event.get("remediation_class", "")]

        resp = await self._post(
            f"{self._base()}/rest/api/3/issue",
            payload,
            headers=self._headers(),
        )
        return resp.json()

    async def send_event(self, event: dict[str, Any]) -> bool:
        await self.create_issue(event)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("jira_url", "email", "api_token")
        try:
            resp = await self._get(
                f"{self._base()}/rest/api/3/myself",
                headers=self._headers(),
            )
            name = resp.json().get("displayName", "unknown")
            return (True, f"Jira connected — authenticated as {name}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# ServiceNow                                                               #
# ======================================================================= #

class ServiceNowConnector(BaseConnector):
    """
    ServiceNow Table API — creates Incident or Security Incident records.

    Config keys:
      instance     — e.g. yourorg.service-now.com (no https://)
      username     — ServiceNow username
      password     — ServiceNow password
      table        — Table to create records in (default: incident)
                     Use x_cyberassetiq_finding for a custom scoped app table
      assignment_group — Optional sys_id of assignment group
      category     — Optional category (default: software)
    """

    category = "itsm"
    connector_type = "servicenow"

    def _headers(self) -> dict:
        creds = base64.b64encode(
            f"{self.config['username']}:{self.config['password']}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _base(self) -> str:
        instance = self.config["instance"].replace("https://", "").strip("/")
        return f"https://{instance}"

    URGENCY_MAP = {
        "informational": "3",     # Low
        "auto_safe": "3",
        "approval_required": "2", # Medium
        "manual_only": "1",       # High
    }

    IMPACT_MAP = {
        "informational": "3",
        "auto_safe": "2",
        "approval_required": "2",
        "manual_only": "1",
    }

    async def create_incident(self, event: dict[str, Any]) -> dict:
        self._require("instance", "username", "password")
        table = self.config.get("table", "incident")
        rem = event.get("remediation_class", "informational")
        payload: dict[str, Any] = {
            "short_description": (
                f"[CyberAssetIQ] {event.get('event_type', 'Finding')}: "
                f"{event.get('asset_name', 'Unknown')} "
                f"{'(' + event['cve_id'] + ')' if event.get('cve_id') else ''}"
            )[:160],
            "description": _ticket_body(event),
            "urgency": self.URGENCY_MAP.get(rem, "3"),
            "impact": self.IMPACT_MAP.get(rem, "3"),
            "category": self.config.get("category", "software"),
            "subcategory": "vulnerability",
            "caller_id": self.config.get("caller_id", ""),
            "work_notes": f"Auto-created by CyberAssetIQ. Remediation class: {rem}",
        }
        if self.config.get("assignment_group"):
            payload["assignment_group"] = self.config["assignment_group"]

        resp = await self._post(
            f"{self._base()}/api/now/table/{table}",
            payload,
            headers=self._headers(),
        )
        return resp.json().get("result", {})

    async def send_event(self, event: dict[str, Any]) -> bool:
        await self.create_incident(event)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("instance", "username", "password")
        try:
            resp = await self._get(
                f"{self._base()}/api/now/table/sys_user",
                headers=self._headers(),
                params={"sysparm_query": f"user_name={self.config['username']}", "sysparm_limit": "1"},
            )
            records = resp.json().get("result", [])
            name = records[0].get("name", "unknown") if records else "unknown"
            return (True, f"ServiceNow connected — user: {name}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Freshservice                                                             #
# ======================================================================= #

class FreshserviceConnector(BaseConnector):
    """
    Freshservice REST API — creates tickets from CyberAssetIQ findings.

    Config keys:
      domain       — e.g. yourorg.freshservice.com
      api_key      — Freshservice API key (Profile Settings > API Key)
      group_id     — Optional group ID to assign tickets
      responder_id — Optional agent ID to assign tickets
    """

    category = "itsm"
    connector_type = "freshservice"

    def _headers(self) -> dict:
        creds = base64.b64encode(f"{self.config['api_key']}:X".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        }

    def _base(self) -> str:
        domain = self.config["domain"].replace("https://", "").strip("/")
        return f"https://{domain}"

    PRIORITY_MAP = {
        "informational": 1,    # Low
        "auto_safe": 2,        # Medium
        "approval_required": 3, # High
        "manual_only": 4,      # Urgent
    }

    async def create_ticket(self, event: dict[str, Any]) -> dict:
        self._require("domain", "api_key")
        rem = event.get("remediation_class", "informational")
        subject = (
            f"[CyberAssetIQ] {event.get('event_type', 'Finding')}: "
            f"{event.get('asset_name', 'Unknown Asset')}"
        )
        payload: dict[str, Any] = {
            "subject": subject[:255],
            "description": _ticket_body(event).replace("\n", "<br>"),
            "priority": self.PRIORITY_MAP.get(rem, 2),
            "status": 2,   # Open
            "source": 13,  # API
            "type": "Incident",
            "tags": ["CyberAssetIQ", rem, event.get("tenant_id", "")],
            "custom_fields": {
                "cyberassetiq_cve": event.get("cve_id"),
                "cyberassetiq_ce_control": event.get("ce_control"),
                "cyberassetiq_score": str(event.get("secret_score", "")),
                "cyberassetiq_remediation": rem,
            },
        }
        if self.config.get("group_id"):
            payload["group_id"] = int(self.config["group_id"])
        if self.config.get("responder_id"):
            payload["responder_id"] = int(self.config["responder_id"])

        resp = await self._post(
            f"{self._base()}/api/v2/tickets",
            payload,
            headers=self._headers(),
        )
        return resp.json().get("ticket", {})

    async def send_event(self, event: dict[str, Any]) -> bool:
        await self.create_ticket(event)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("domain", "api_key")
        try:
            resp = await self._get(
                f"{self._base()}/api/v2/agents/me",
                headers=self._headers(),
            )
            agent = resp.json().get("agent", {})
            name = f"{agent.get('first_name', '')} {agent.get('last_name', '')}".strip()
            return (True, f"Freshservice connected — API key owner: {name or 'unknown'}")
        except ConnectorError as exc:
            return (False, str(exc))
