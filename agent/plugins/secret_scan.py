from __future__ import annotations

"""
CyberAssetIQ Secret / Credential Scanner.

Scans file system paths for credential leaks using:
  1. 35+ regex patterns covering all major cloud providers and services
  2. ML-based confidence scoring (SecretScore classifier) to suppress false positives
  3. Context extraction for audit trail and explainability

False positive reduction target: 68.6% vs regex-only baseline.
"""

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 35+ pattern library
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern] = {
    # AWS
    "aws_access_key_id": re.compile(
        r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Z0-9])"
    ),
    "aws_secret_access_key": re.compile(
        r"(?i)aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"
    ),
    "aws_session_token": re.compile(
        r"(?i)aws[_\-\s]*session[_\-\s]*token[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})"
    ),
    # GitHub
    "github_personal_access_token": re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    "github_oauth_token": re.compile(r"gho_[A-Za-z0-9]{36,}"),
    "github_app_token": re.compile(r"(ghs_|ghr_)[A-Za-z0-9]{36,}"),
    "github_pat_v2": re.compile(r"github_pat_[A-Za-z0-9_]{80,}"),
    # Google
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth_token": re.compile(r"ya29\.[0-9A-Za-z\-_]{50,}"),
    "google_service_account": re.compile(r'"type":\s*"service_account"'),
    # Stripe
    "stripe_secret_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_restricted_key": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    "stripe_publishable_key": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    # Slack
    "slack_bot_token": re.compile(
        r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"
    ),
    "slack_user_token": re.compile(
        r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32,}"
    ),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"
    ),
    # SendGrid
    "sendgrid_api_key": re.compile(
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"
    ),
    # Twilio
    "twilio_account_sid": re.compile(r"AC[0-9a-fA-F]{32}"),
    "twilio_auth_token": re.compile(
        r"(?i)twilio[_\s]*auth[_\s]*token[\s]*[=:]\s*['\"]?([0-9a-fA-F]{32})"
    ),
    # OpenAI
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "openai_project_key": re.compile(r"sk-proj-[A-Za-z0-9_\-]{80,}"),
    # Azure
    "azure_storage_account_key": re.compile(
        r"(?i)AccountKey=[A-Za-z0-9+/]{86}=="
    ),
    "azure_client_secret": re.compile(
        r"(?i)(client[_\-]?secret|clientsecret)[\s]*[=:]\s*['\"]?([A-Za-z0-9~\-_.]{34,40})"
    ),
    "azure_sas_token": re.compile(
        r"sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&.*sig=[A-Za-z0-9%/+=]+"
    ),
    # GitLab
    "gitlab_personal_access_token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    # npm
    "npm_access_token": re.compile(r"npm_[A-Za-z0-9]{36,}"),
    # Shopify
    "shopify_access_token": re.compile(r"shpat_[A-Za-z0-9]{32,}"),
    "shopify_shared_secret": re.compile(r"shpss_[A-Za-z0-9]{32,}"),
    # Mailgun
    "mailgun_api_key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    # Square
    "square_access_token": re.compile(r"sq0atp-[0-9A-Za-z\-_]{22,}"),
    "square_client_secret": re.compile(r"sq0csp-[0-9A-Za-z\-_]{43,}"),
    # PEM private keys
    "rsa_private_key": re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "pgp_private_key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    # Generic (ML-filtered heavily)
    "generic_api_key": re.compile(
        r"(?i)(api[_\-]?key|apikey|access[_\-]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,64})"
    ),
    "generic_secret": re.compile(
        r"(?i)(secret|client[_\-]?secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_~.]{20,64})"
    ),
    "bearer_token": re.compile(
        r"(?i)(bearer|authorization:?\s*bearer)\s+([A-Za-z0-9\-\._~\+\/]{20,}={0,2})"
    ),
    "password_in_url": re.compile(r"(?i)(https?://[^:@\s]+:[^@\s]{8,}@)"),
}

_SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".lock", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".class",
})

_SKIP_DIRS = frozenset({
    # Dev artifacts
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "env", "dist", "build", "target", ".idea", ".vscode",
    ".terraform", "vendor", "bower_components",
    # Windows browser/app caches
    "Cache", "cache", "Code Cache", "GPUCache", "ShaderCache",
    "CachedData", "CachedExtensions", "CachedThemes",
    "BraveSoftware", "Google", "Mozilla", "Microsoft",
    "Packages", "WindowsApps", "SystemApps",
    # Windows system noise
    "Temp", "temp", "Tmp", "tmp",
    "CrashReports", "Crashpad", "crashes",
    "thumbnails", "Thumbnails",
    "History", "history",
    "Application Data",
})

_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_FILES_PER_SCAN = 50_000
_CONTEXT_WINDOW = 200


def get_scan_paths(platform: str) -> list[str]:
    """Return high-priority scan paths for the given OS platform string."""
    if platform == "Windows":
        home = os.path.expandvars("%USERPROFILE%")
        return [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]
    if platform == "Linux":
        return [
            os.path.expanduser("~"),
            "/etc",
            "/opt",
            "/srv",
            "/var/www",
            "/home",
        ]
    if platform == "Darwin":
        return [
            os.path.expanduser("~"),
            "/Applications",
            "/Library/Application Support",
            "/usr/local/etc",
        ]
    return []


def _extract_candidate(match: re.Match) -> str:
    groups = [g for g in match.groups() if g]
    return (groups[-1] if groups else match.group(0))[:120]


def _build_context(content: str, start: int, end: int) -> tuple[str, str]:
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    context_line = content[line_start:(line_end if line_end >= 0 else len(content))][:300]
    win_start = max(0, start - _CONTEXT_WINDOW // 2)
    win_end = min(len(content), end + _CONTEXT_WINDOW // 2)
    return context_line, content[win_start:win_end]


def scan_paths(paths: list[str], use_ml: bool = True) -> list[dict[str, Any]]:
    """
    Walk each path and scan files for credentials.
    Applies ML confidence scoring when available to suppress false positives.
    Returns a list of finding dicts.
    """
    ml_available = False
    if use_ml:
        try:
            from ml.model import is_true_secret
            from ml.features import FeatureContext
            ml_available = True
        except Exception:
            logger.debug("ML module unavailable — using regex-only mode.")

    findings: list[dict[str, Any]] = []
    regex_hits = 0
    ml_suppressed = 0
    files_scanned = 0

    for root_path in paths:
        if not os.path.exists(root_path):
            continue

        for root, dirs, files in os.walk(root_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]

            for file_name in files:
                if Path(file_name).suffix.lower() in _SKIP_EXTENSIONS:
                    continue

                if files_scanned >= _MAX_FILES_PER_SCAN:
                    logger.warning("Secret scan file cap (%d) reached — stopping early.", _MAX_FILES_PER_SCAN)
                    return findings
                files_scanned += 1
                full_path = os.path.join(root, file_name)
                try:
                    if os.path.getsize(full_path) > _MAX_FILE_BYTES:
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue

                for secret_type, pattern in SECRET_PATTERNS.items():
                    for match in pattern.finditer(content):
                        regex_hits += 1
                        candidate = _extract_candidate(match)
                        context_line, context_window = _build_context(
                            content, match.start(), match.end()
                        )

                        confidence = 0.75
                        ml_filtered = False

                        if ml_available:
                            from ml.model import is_true_secret
                            from ml.features import FeatureContext
                            ctx = FeatureContext(
                                candidate=candidate,
                                context_line=context_line,
                                context_window=context_window,
                                file_path=full_path,
                            )
                            is_real, confidence = is_true_secret(ctx)
                            if not is_real:
                                ml_suppressed += 1
                                ml_filtered = True
                                if confidence < 0.2:
                                    continue

                        findings.append({
                            "type": "secret_candidate",
                            "secret_type": secret_type,
                            "file_path": full_path,
                            "preview": candidate[:80],
                            "confidence": round(confidence, 3),
                            "ml_filtered": ml_filtered,
                            "context_preview": context_line[:200],
                        })

    if regex_hits > 0:
        logger.info(
            "Secret scan: %d regex hits → %d findings after ML filtering (%.1f%% suppressed)",
            regex_hits,
            len([f for f in findings if not f["ml_filtered"]]),
            100 * ml_suppressed / regex_hits,
        )

    return findings
