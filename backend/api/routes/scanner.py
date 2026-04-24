from __future__ import annotations

"""
CyberAssetIQ — Credential / Secret Scanner API

Accepts pasted text content, runs the same 35+ regex patterns used by
the agent's secret scanner, and returns structured findings with severity,
line number, context, and remediation recommendation.
"""

import re
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column

from api.deps import AuthenticatedRequest, require_read
import asyncio as _asyncio
from integrations.dispatcher import dispatch_credential_leak as _dispatch_secret

from db.session import get_db
from models.mixins import Base, TimestampMixin

router = APIRouter()

# ---------------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------------

class CredentialScan(TimestampMixin, Base):
    __tablename__ = "credential_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scan_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_length: Mapped[int] = mapped_column(default=0)
    finding_count: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    high_count: Mapped[int] = mapped_column(default=0)
    medium_count: Mapped[int] = mapped_column(default=0)
    low_count: Mapped[int] = mapped_column(default=0)
    findings_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


# ---------------------------------------------------------------------------
# Secret patterns — same library as agent/plugins/secret_scan.py
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, secret_type, severity)
    (re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Z0-9])"), "aws_access_key_id", "critical"),
    (re.compile(r"(?i)aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "aws_secret_access_key", "critical"),
    (re.compile(r"(?i)aws[_\-\s]*session[_\-\s]*token[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})"), "aws_session_token", "high"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "github_personal_access_token", "critical"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "github_oauth_token", "critical"),
    (re.compile(r"(ghs_|ghr_)[A-Za-z0-9]{36,}"), "github_app_token", "high"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{80,}"), "github_pat_v2", "critical"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key", "high"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]{50,}"), "google_oauth_token", "high"),
    (re.compile(r'"type":\s*"service_account"'), "google_service_account", "critical"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "stripe_secret_key", "critical"),
    (re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "stripe_restricted_key", "critical"),
    (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "stripe_publishable_key", "medium"),
    (re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"), "slack_bot_token", "critical"),
    (re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32,}"), "slack_user_token", "critical"),
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"), "slack_webhook", "high"),
    (re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "sendgrid_api_key", "critical"),
    (re.compile(r"sk-[A-Za-z0-9]{48}"), "openai_api_key", "critical"),
    (re.compile(r"sk-proj-[A-Za-z0-9_\-]{80,}"), "openai_project_key", "critical"),
    (re.compile(r"(?i)AccountKey=[A-Za-z0-9+/]{86}=="), "azure_storage_account_key", "critical"),
    (re.compile(r"(?i)(client[_\-]?secret|clientsecret)[\s]*[=:]\s*['\"]?([A-Za-z0-9~\-_.]{34,40})"), "azure_client_secret", "critical"),
    (re.compile(r"sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&.*sig=[A-Za-z0-9%/+=]+"), "azure_sas_token", "high"),
    (re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "gitlab_personal_access_token", "critical"),
    (re.compile(r"npm_[A-Za-z0-9]{36,}"), "npm_access_token", "high"),
    (re.compile(r"shpat_[A-Za-z0-9]{32,}"), "shopify_access_token", "critical"),
    (re.compile(r"key-[0-9a-zA-Z]{32}"), "mailgun_api_key", "high"),
    (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22,}"), "square_access_token", "critical"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private_key", "critical"),
    (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "pgp_private_key", "critical"),
    (re.compile(r"(?i)(api[_\-]?key|apikey|access[_\-]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,64})"), "generic_api_key", "medium"),
    (re.compile(r"(?i)(secret|client[_\-]?secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_~.]{20,64})"), "generic_secret", "medium"),
    (re.compile(r"(?i)(bearer|authorization:?\s*bearer)\s+([A-Za-z0-9\-\._~\+\/]{20,}={0,2})"), "bearer_token", "high"),
    (re.compile(r"(?i)(https?://[^:@\s]+:[^@\s]{8,}@)"), "password_in_url", "high"),
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_RECOMMENDATIONS: dict[str, str] = {
    "aws_access_key_id": "Revoke immediately in AWS IAM console. Rotate and store in AWS Secrets Manager.",
    "aws_secret_access_key": "Revoke immediately in AWS IAM. Use IAM roles instead of static keys.",
    "aws_session_token": "Session token is temporary but revoke the associated IAM credentials immediately.",
    "github_personal_access_token": "Revoke in GitHub Settings > Developer settings > Personal access tokens.",
    "github_oauth_token": "Revoke via GitHub OAuth app settings immediately.",
    "github_app_token": "Rotate via GitHub App settings. Review recent API activity.",
    "github_pat_v2": "Revoke in GitHub Settings > Developer settings > Fine-grained tokens.",
    "google_api_key": "Restrict and rotate in Google Cloud Console > APIs & Services > Credentials.",
    "google_oauth_token": "Revoke in Google Account > Security > Third-party apps.",
    "google_service_account": "Rotate service account key in Google Cloud IAM immediately.",
    "stripe_secret_key": "Revoke immediately in Stripe Dashboard > Developers > API Keys.",
    "stripe_restricted_key": "Revoke in Stripe Dashboard > Developers > API Keys.",
    "stripe_publishable_key": "Rotate in Stripe Dashboard. Publishable keys have limited scope but should still be rotated.",
    "slack_bot_token": "Revoke in Slack API console > Your Apps > OAuth & Permissions.",
    "slack_user_token": "Revoke in Slack API console > Your Apps > OAuth & Permissions.",
    "slack_webhook": "Revoke webhook URL in Slack App settings > Incoming Webhooks.",
    "sendgrid_api_key": "Revoke in SendGrid Settings > API Keys immediately.",
    "openai_api_key": "Revoke in OpenAI Platform > API Keys. Review usage for unexpected charges.",
    "openai_project_key": "Revoke in OpenAI Platform > API Keys immediately.",
    "azure_storage_account_key": "Rotate in Azure Portal > Storage Account > Access Keys.",
    "azure_client_secret": "Rotate in Azure Active Directory > App Registrations > Certificates & Secrets.",
    "azure_sas_token": "Revoke SAS token in Azure Portal. Generate a new one with minimal permissions.",
    "gitlab_personal_access_token": "Revoke in GitLab Profile > Access Tokens.",
    "npm_access_token": "Revoke in npmjs.com > Access Tokens.",
    "shopify_access_token": "Revoke in Shopify Partner Dashboard > Apps.",
    "mailgun_api_key": "Rotate in Mailgun Dashboard > Settings > API Keys.",
    "square_access_token": "Revoke in Square Developer Dashboard > Applications.",
    "private_key": "Private key exposed. Regenerate the key pair immediately and update all services using the old key.",
    "pgp_private_key": "PGP private key exposed. Revoke the key and generate a new key pair.",
    "generic_api_key": "Review and rotate if this is a live credential. Store secrets in a vault, not in code.",
    "generic_secret": "Review context and rotate if this is a live credential. Use environment variables.",
    "bearer_token": "Revoke this token immediately and re-authenticate to obtain a new one.",
    "password_in_url": "Remove password from URL immediately. Use environment variables or a secrets manager.",
}


def _scan_text(content: str) -> list[dict[str, Any]]:
    lines = content.splitlines()
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line_no, line in enumerate(lines, 1):
        for pattern, secret_type, severity in _PATTERNS:
            for match in pattern.finditer(line):
                # Deduplicate by secret_type + matched value
                val = match.group(0)[:80]
                key = f"{secret_type}:{val}"
                if key in seen:
                    continue
                seen.add(key)

                # Redact the actual secret for display
                redacted = re.sub(r"[A-Za-z0-9+/=_\-]{8,}", "***REDACTED***", val, count=1)

                findings.append({
                    "secret_type": secret_type,
                    "severity": severity,
                    "line_number": line_no,
                    "context": line.strip()[:200],
                    "redacted_preview": redacted,
                    "recommendation": _RECOMMENDATIONS.get(secret_type, "Rotate this credential immediately and store it securely."),
                })

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    return findings


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    scan_name: str | None = None
    source_label: str | None = None
    content: str


class ScanResult(BaseModel):
    scan_id: str
    scan_name: str | None
    source_label: str | None
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[dict]
    scanned_at: float


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResult)
def run_credential_scan(
    payload: ScanRequest,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> ScanResult:
    findings = _scan_text(payload.content)

    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")

    scan_id = f"scan_{uuid.uuid4().hex[:16]}"

    record = CredentialScan(
        tenant_id=auth.tenant_id,
        scan_id=scan_id,
        scan_name=payload.scan_name,
        source_label=payload.source_label,
        content_length=len(payload.content),
        finding_count=len(findings),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        findings_json=findings,
    )
    db.add(record)
    db.commit()

    try:
        if critical > 0 or high > 0:
            for _f in [f for f in findings if f["severity"] in ("critical", "high")]:
                _event = {
                    "event_type": "credential_leak",
                    "severity": 9 if _f["severity"] == "critical" else 7,
                    "description": f"Credential leak detected: {_f['secret_type']} found in {payload.source_label or payload.scan_name or 'scanned content'}. {_f['recommendation']}",
                    "secret_score": 0.9 if _f["severity"] == "critical" else 0.75,
                    "remediation_class": "manual_only" if _f["severity"] == "critical" else "approval_required",
                    "remediation_action": _f["recommendation"],
                    "tenant_id": auth.tenant_id,
                    "scan_id": scan_id,
                    "secret_type": _f["secret_type"],
                    "line_number": _f.get("line_number"),
                    "source_label": payload.source_label,
                }
                _asyncio.run(_dispatch_secret(db, auth.tenant_id, _event))
    except Exception as _exc:
        import logging as _l; _l.getLogger(__name__).warning("Secret dispatch failed: %s", _exc)

    return ScanResult(
        scan_id=scan_id,
        scan_name=payload.scan_name,
        source_label=payload.source_label,
        finding_count=len(findings),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        findings=findings,
        scanned_at=time.time(),
    )


@router.get("/scans")
def list_scans(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    scans = (
        db.query(CredentialScan)
        .filter(CredentialScan.tenant_id == auth.tenant_id)
        .order_by(CredentialScan.id.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": s.id,
            "scan_id": s.scan_id,
            "scan_name": s.scan_name or "Unnamed scan",
            "source_label": s.source_label,
            "finding_count": s.finding_count,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": getattr(s, "medium_count", 0) or 0,
            "low_count": getattr(s, "low_count", 0) or 0,
            "created_at": str(s.created_at),
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    scan = (
        db.query(CredentialScan)
        .filter(
            CredentialScan.tenant_id == auth.tenant_id,
            CredentialScan.scan_id == scan_id,
        )
        .first()
    )
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.scan_id,
        "scan_name": scan.scan_name,
        "source_label": scan.source_label,
        "finding_count": scan.finding_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": getattr(scan, "medium_count", 0) or 0,
        "low_count": getattr(scan, "low_count", 0) or 0,
        "findings": scan.findings_json or [],
        "created_at": str(scan.created_at),
    }
