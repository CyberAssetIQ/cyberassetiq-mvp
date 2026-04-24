from __future__ import annotations

import json
import os
import secrets
from typing import Any

from sqlalchemy.orm import Session

from models.agent import Agent, AgentEnrollmentToken, AgentPolicy


def _default_policy() -> dict[str, Any]:
    raw = os.getenv(
        "DEFAULT_POLICY_JSON",
        '{"collection":{"software":true,"security":true,"network":true,"secret_scan":false},"updater":{"enabled":false}}',
    )
    return json.loads(raw)


def generate_agent_id(tenant_id: str) -> str:
    suffix = secrets.token_hex(8)
    safe_tenant = tenant_id.replace(" ", "-").lower()
    return f"agent-{safe_tenant}-{suffix}"


def ensure_bootstrap_token(db: Session, tenant_id: str) -> str | None:
    """
    Create a random one-time bootstrap enrollment token if none exists for this tenant.
    Returns the plaintext token value on first creation, or None if one already exists.
    """
    existing = db.query(AgentEnrollmentToken).filter(
        AgentEnrollmentToken.tenant_id == tenant_id,
        AgentEnrollmentToken.is_active.is_(True),
        AgentEnrollmentToken.is_used.is_(False),
    ).first()
    if existing:
        return None

    token_value = "enroll_" + secrets.token_urlsafe(24)
    token = AgentEnrollmentToken(
        tenant_id=tenant_id,
        token_value=token_value,
        is_active=True,
        is_used=False,
        note="Bootstrap development token",
    )
    db.add(token)
    db.commit()
    return token_value


def enroll_agent(db: Session, tenant_id: str, enrollment_token: str, hostname: str) -> tuple[str, dict[str, Any]]:
    token = (
        db.query(AgentEnrollmentToken)
        .filter(
            AgentEnrollmentToken.tenant_id == tenant_id,
            AgentEnrollmentToken.token_value == enrollment_token,
            AgentEnrollmentToken.is_active.is_(True),
            AgentEnrollmentToken.is_used.is_(False),
        )
        .first()
    )
    if not token:
        raise ValueError("Invalid or already used enrollment token")

    agent_id = generate_agent_id(tenant_id)
    agent = Agent(
        tenant_id=tenant_id,
        agent_id=agent_id,
        hostname=hostname,
        status="active",
    )
    db.add(agent)
    db.flush()

    policy = AgentPolicy(
        agent_fk=agent.id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        policy_json=_default_policy(),
        is_active=True,
    )
    db.add(policy)

    token.is_used = True
    db.commit()

    return agent_id, policy.policy_json


def get_active_policy(db: Session, tenant_id: str, agent_id: str) -> dict[str, Any]:
    policy = (
        db.query(AgentPolicy)
        .filter(
            AgentPolicy.tenant_id == tenant_id,
            AgentPolicy.agent_id == agent_id,
            AgentPolicy.is_active.is_(True),
        )
        .order_by(AgentPolicy.id.desc())
        .first()
    )
    if not policy:
        return _default_policy()
    return policy.policy_json


def touch_agent_seen(db: Session, tenant_id: str, agent_id: str, last_seen_epoch: int | None = None, os_family: str | None = None, hostname: str | None = None) -> None:
    agent = db.query(Agent).filter(Agent.tenant_id == tenant_id, Agent.agent_id == agent_id).first()
    if not agent:
        agent = Agent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            hostname=hostname,
            os_family=os_family,
            status="active",
            last_seen_epoch=last_seen_epoch,
        )
        db.add(agent)
    else:
        if hostname:
            agent.hostname = hostname
        if os_family:
            agent.os_family = os_family
        if last_seen_epoch is not None:
            agent.last_seen_epoch = last_seen_epoch
    db.commit()
