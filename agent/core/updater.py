from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def check_for_updates(policy: dict) -> None:
    updater_policy = policy.get("updater", {})
    if not updater_policy.get("enabled", False):
        return

    logger.info("Updater enabled by policy, but self-update is not implemented in MVP.")
