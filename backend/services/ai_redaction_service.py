"""
AI Redaction Service
Strips secrets, passwords, tokens and API keys from any text or dict
before it is sent to an LLM provider.
"""
import re
from typing import Any

# Patterns that match secrets we must never send to an LLM
_SECRET_PATTERNS = [
    # Generic high-entropy tokens (32+ hex chars)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), '[REDACTED_HEX_TOKEN]'),
    # Bearer tokens
    (re.compile(r'Bearer\s+\S+', re.IGNORECASE), 'Bearer [REDACTED]'),
    # Basic auth
    (re.compile(r'Basic\s+[A-Za-z0-9+/=]{10,}', re.IGNORECASE), 'Basic [REDACTED]'),
    # AWS keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
    # GitHub tokens
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), '[REDACTED_GITHUB_TOKEN]'),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'), '[REDACTED_GITHUB_PAT]'),
    # Stripe keys
    (re.compile(r'sk_live_[A-Za-z0-9]{24,}'), '[REDACTED_STRIPE_KEY]'),
    (re.compile(r'sk_test_[A-Za-z0-9]{24,}'), '[REDACTED_STRIPE_TEST_KEY]'),
    # Google API keys
    (re.compile(r'AIza[0-9A-Za-z-_]{35}'), '[REDACTED_GOOGLE_KEY]'),
    # Slack tokens
    (re.compile(r'xox[baprs]-[0-9A-Za-z-]+'), '[REDACTED_SLACK_TOKEN]'),
    # Private keys (PEM)
    (re.compile(r'-----BEGIN [A-Z ]+ KEY-----[\s\S]+?-----END [A-Z ]+ KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    # Passwords in key=value pairs
    (re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth)[=:"\s]+\S+'), r'\1=[REDACTED]'),
    # Connection strings with credentials
    (re.compile(r'(?i)(postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@'), r'\1://[REDACTED_CREDS]@'),
]

# JSON keys that should always be masked
_MASKED_KEYS = {
    'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
    'api_secret', 'private_key', 'auth_token', 'bearer', 'credential',
    'access_key', 'secret_key', 'client_secret', 'db_password', 'database_url',
}


def redact_text(text: str) -> str:
    """Apply all redaction patterns to a plain string."""
    if not text:
        return text
    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_dict(data: Any, depth: int = 0) -> Any:
    """
    Recursively redact a dict/list structure.
    Masks values for known sensitive keys and applies text redaction to strings.
    """
    if depth > 10:
        return '[REDACTED_DEEP_STRUCT]'

    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            if isinstance(k, str) and k.lower() in _MASKED_KEYS:
                clean[k] = '[REDACTED]'
            else:
                clean[k] = redact_dict(v, depth + 1)
        return clean

    if isinstance(data, list):
        return [redact_dict(item, depth + 1) for item in data]

    if isinstance(data, str):
        return redact_text(data)

    return data


def safe_truncate(text: str, max_chars: int = 4000) -> str:
    """Truncate text to avoid huge LLM prompts."""
    if not text or len(text) <= max_chars:
        return text
    return text[:max_chars] + f'\n... [truncated at {max_chars} chars]'
