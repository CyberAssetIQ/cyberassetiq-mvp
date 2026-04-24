from __future__ import annotations

"""
Known API key prefix registry.

Used by the secret scanner and ML feature extractor to identify
vendor-specific credential formats with high precision.
"""

# Mapping of prefix → (vendor_name, expected_total_length_range)
# Used for F15/F16 feature computation and direct high-confidence flagging.
KNOWN_KEY_PREFIXES: dict[str, tuple[str, tuple[int, int]]] = {
    "AKIA": ("AWS Access Key ID", (20, 20)),
    "ASIA": ("AWS Temporary Access Key", (20, 20)),
    "ghp_": ("GitHub Personal Access Token", (40, 45)),
    "gho_": ("GitHub OAuth Token", (40, 45)),
    "ghs_": ("GitHub App Installation Token", (40, 45)),
    "ghr_": ("GitHub App Refresh Token", (40, 45)),
    "github_pat_": ("GitHub Fine-Grained PAT", (90, 110)),
    "AIza": ("Google API Key", (39, 39)),
    "ya29.": ("Google OAuth Access Token", (60, 200)),
    "sk-": ("OpenAI API Key", (51, 60)),
    "sk-proj-": ("OpenAI Project API Key", (90, 120)),
    "sk_live_": ("Stripe Secret Key", (32, 40)),
    "rk_live_": ("Stripe Restricted Key", (32, 40)),
    "pk_live_": ("Stripe Publishable Key", (32, 40)),
    "xoxb-": ("Slack Bot Token", (60, 80)),
    "xoxp-": ("Slack User Token", (70, 100)),
    "SG.": ("SendGrid API Key", (69, 69)),
    "glpat-": ("GitLab Personal Access Token", (26, 26)),
    "npm_": ("npm Access Token", (40, 50)),
    "shpat_": ("Shopify Access Token", (38, 38)),
    "sq0atp-": ("Square Access Token", (28, 32)),
    "sq0csp-": ("Square Client Secret", (48, 52)),
    "AC": ("Twilio Account SID", (34, 34)),
}


def identify_prefix(candidate: str) -> tuple[str, str] | None:
    """
    If the candidate starts with a known vendor prefix, return (vendor, prefix).
    Returns None if no match.
    """
    for prefix, (vendor, _) in KNOWN_KEY_PREFIXES.items():
        if candidate.startswith(prefix):
            return vendor, prefix
    return None


def is_known_prefix(candidate: str) -> bool:
    return identify_prefix(candidate) is not None
