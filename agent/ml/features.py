from __future__ import annotations

"""
Feature extraction for the SecretScore ML classifier.

Extracts 23 contextual features from a (candidate_string, surrounding_context,
file_path) triple. These are the exact features described in the CyberAssetIQ
business plan and MSc dissertation methodology.

Feature vector is deterministic and ordered — any change to ordering or
count is a breaking change that requires model retraining.
"""

import math
import os
import re
import string
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Feature names (used for logging and explainability)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "f01_shannon_entropy",
    "f02_char_class_diversity",
    "f03_candidate_length",
    "f04_sequential_char_ratio",
    "f05_repeating_char_ratio",
    "f06_is_high_risk_filename",
    "f07_is_source_code_file",
    "f08_is_config_file",
    "f09_keyword_distance_score",
    "f10_keyword_immediately_precedes",
    "f11_is_assignment_context",
    "f12_is_comment_line",
    "f13_is_test_or_example_path",
    "f14_has_placeholder_pattern",
    "f15_matches_known_prefix",
    "f16_starts_with_known_prefix",
    "f17_contains_url_component",
    "f18_consecutive_uppercase_ratio",
    "f19_alternating_case_ratio",
    "f20_hex_char_ratio",
    "f21_base64_char_ratio",
    "f22_has_internal_whitespace",
    "f23_is_in_vcs_directory",
]

assert len(FEATURE_NAMES) == 23


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HIGH_RISK_FILENAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.development",
    "credentials", "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml", "secret.json",
    "config.json", "config.yml", "config.yaml", "settings.py",
    "application.properties", "application.yml", "appsettings.json",
    "terraform.tfvars", "*.tfvars",
})

_SOURCE_CODE_EXTS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java",
    ".cs", ".php", ".cpp", ".c", ".h", ".swift", ".kt", ".rs",
    ".sh", ".bash", ".ps1", ".psm1",
})

_CONFIG_EXTS = frozenset({
    ".env", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".xml", ".plist",
})

_KNOWN_SECRET_PREFIXES = frozenset({
    "AKIA", "ASIA", "AROA", "AIPA", "ANPA", "ANVA", "APKA",   # AWS
    "ghp_", "gho_", "ghs_", "ghr_", "github_pat_",              # GitHub
    "sk-", "sk-proj-",                                           # OpenAI
    "xoxb-", "xoxp-", "xoxa-",                                  # Slack
    "SG.",                                                        # SendGrid
    "AC", "SK",                                                   # Twilio (prefix + 32 hex)
    "AIza",                                                       # Google API
    "rk_live_", "sk_live_", "pk_live_",                          # Stripe
    "EAA",                                                        # Facebook
    "ya29.",                                                      # Google OAuth
    "sq0atp-", "sq0csp-",                                         # Square
    "shpat_", "shpss_", "shpca_",                                 # Shopify
    "npm_",                                                       # npm
    "glpat-",                                                     # GitLab
})

_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?(?:api[_-]?)?key|example|placeholder|changeme|"
    r"xxx+|yyy+|zzz+|test|dummy|fake|sample|insert[_-]?here|"
    r"<[^>]+>|\$\{[^}]+\}|%\w+%|__\w+__)"
)

_KEYWORD_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|credential|"
    r"auth|private[_-]?key|access[_-]?key|client[_-]?secret|"
    r"bearer|authorization)"
)

_ASSIGNMENT_RE = re.compile(r"[=:]\s*['\"]?$")

_BASE64_CHARS = frozenset(string.ascii_letters + string.digits + "+/=")
_HEX_CHARS = frozenset(string.hexdigits)


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------

@dataclass
class FeatureContext:
    candidate: str
    context_line: str   # the full line the candidate appeared on
    context_window: str # up to 200 chars around the candidate in the file
    file_path: str


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _char_class_diversity(s: str) -> int:
    """Count of distinct character classes present (0–4): upper, lower, digit, symbol."""
    classes = 0
    if any(c.isupper() for c in s): classes += 1
    if any(c.islower() for c in s): classes += 1
    if any(c.isdigit() for c in s): classes += 1
    if any(c in string.punctuation for c in s): classes += 1
    return classes


def _sequential_char_ratio(s: str) -> float:
    """Fraction of characters that are part of sequential runs (abc, 123)."""
    if len(s) < 2:
        return 0.0
    sequential = 0
    for i in range(len(s) - 1):
        if ord(s[i + 1]) - ord(s[i]) == 1:
            sequential += 1
    return sequential / (len(s) - 1)


def _repeating_char_ratio(s: str) -> float:
    """Fraction of characters that are repeated from the previous character."""
    if len(s) < 2:
        return 0.0
    repeats = sum(1 for i in range(1, len(s)) if s[i] == s[i - 1])
    return repeats / (len(s) - 1)


def _keyword_distance_score(candidate: str, context_window: str) -> float:
    """
    Score based on proximity of a secret keyword to the candidate.
    Returns 1.0 if keyword is within 30 chars, 0.5 within 100, 0.0 otherwise.
    """
    pos = context_window.find(candidate)
    if pos < 0:
        return 0.0
    pre = context_window[:pos]
    match = _KEYWORD_RE.search(pre[-100:] if len(pre) > 100 else pre)
    if not match:
        return 0.0
    distance = len(pre) - match.end()
    if distance <= 30:
        return 1.0
    if distance <= 100:
        return 0.5
    return 0.2


def extract_features(ctx: FeatureContext) -> list[float]:
    s = ctx.candidate
    line = ctx.context_line
    path = ctx.file_path.replace("\\", "/")
    fname = os.path.basename(path).lower()
    ext = os.path.splitext(fname)[1].lower()
    path_lower = path.lower()

    f01 = _shannon_entropy(s) / 8.0  # normalised to [0,1] (max entropy ~8 bits/char)
    f02 = _char_class_diversity(s) / 4.0
    f03 = min(len(s) / 64.0, 1.0)
    f04 = _sequential_char_ratio(s)
    f05 = _repeating_char_ratio(s)
    f06 = 1.0 if (fname in _HIGH_RISK_FILENAMES or ext == ".env") else 0.0
    f07 = 1.0 if ext in _SOURCE_CODE_EXTS else 0.0
    f08 = 1.0 if ext in _CONFIG_EXTS else 0.0
    f09 = _keyword_distance_score(s, ctx.context_window)
    f10 = 1.0 if bool(_KEYWORD_RE.search(line[:line.find(s)] if s in line else "")) else 0.0
    f11 = 1.0 if bool(_ASSIGNMENT_RE.search(line[:line.find(s)] if s in line else "")) else 0.0
    f12 = 1.0 if line.lstrip().startswith(("#", "//", "*", "/*", "<!--")) else 0.0
    f13 = 1.0 if any(
        seg in path_lower for seg in ("/test", "/tests", "/spec", "/example",
                                      "/examples", "/fixture", "/mock", "/stub", "/demo")
    ) else 0.0
    f14 = 1.0 if bool(_PLACEHOLDER_RE.search(s)) else 0.0
    f15 = 1.0 if any(s.startswith(p) for p in _KNOWN_SECRET_PREFIXES) else 0.0
    # f16: case-insensitive prefix match (catches lowercase env vars)
    s_upper = s.upper()
    f16 = 1.0 if any(s_upper.startswith(p.upper()) for p in _KNOWN_SECRET_PREFIXES) else 0.0
    f17 = 1.0 if re.search(r"https?://|ftp://|s3://|gs://", s) else 0.0
    uppers = sum(1 for c in s if c.isupper())
    f18 = uppers / max(len(s), 1)
    alternating = sum(
        1 for i in range(1, len(s)) if s[i].isupper() != s[i - 1].isupper()
    )
    f19 = alternating / max(len(s) - 1, 1)
    f20 = sum(1 for c in s if c in _HEX_CHARS) / max(len(s), 1)
    f21 = sum(1 for c in s if c in _BASE64_CHARS) / max(len(s), 1)
    f22 = 1.0 if " " in s or "\t" in s else 0.0
    f23 = 1.0 if "/.git/" in path_lower or "\\.git\\" in path else 0.0

    features = [
        f01, f02, f03, f04, f05, f06, f07, f08, f09, f10,
        f11, f12, f13, f14, f15, f16, f17, f18, f19, f20,
        f21, f22, f23,
    ]
    assert len(features) == 23
    return features
