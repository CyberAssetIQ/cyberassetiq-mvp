import textwrap

# ── 1. commands.py — quarantine + force-checkin ──────────────────────────────

commands_addition = textwrap.dedent("""

@router.post("/agents/{agent_id}/quarantine")
def quarantine_host(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    _, commands = create_scan_job(
        db=db,
        tenant_id=auth.tenant_id,
        agent_ids=[agent_id],
        job_type="isolate_host",
        requested_by=f"admin:key_id:{auth.key_id}",
        arguments={"reason": "Manual quarantine - admin initiated"},
        expires_epoch=None,
        priority="high",
    )
    cmd = commands[0]
    return {"ok": True, "agent_id": agent_id, "command_id": cmd.command_uuid, "status": cmd.status}


@router.post("/agents/{agent_id}/force-checkin")
def force_checkin(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    _, commands = create_scan_job(
        db=db,
        tenant_id=auth.tenant_id,
        agent_ids=[agent_id],
        job_type="force_checkin",
        requested_by=f"admin:key_id:{auth.key_id}",
        arguments={},
        expires_epoch=None,
        priority="high",
    )
    cmd = commands[0]
    return {"ok": True, "agent_id": agent_id, "command_id": cmd.command_uuid, "status": cmd.status}
""")

with open("/app/api/routes/commands.py", "a") as f:
    f.write(commands_addition)
print("commands.py patched")


# ── 2. manage.py — generate-id + reassign policy ─────────────────────────────

with open("/app/api/routes/manage.py", "r") as f:
    manage_content = f.read()

manage_content = manage_content.replace(
    "from models.agent import Agent, AgentEnrollmentToken",
    "from models.agent import Agent, AgentEnrollmentToken, AgentPolicy",
)

manage_addition = textwrap.dedent("""

@router.post("/agents/generate-id")
def generate_agent_id_endpoint(
    auth: AuthenticatedRequest = Depends(require_admin),
) -> dict:
    from services.agent_service import generate_agent_id
    return {"ok": True, "agent_id": generate_agent_id(auth.tenant_id)}


class ReassignPolicyRequest(BaseModel):
    policy: dict
    reason: str | None = None


@router.patch("/agents/{agent_id}/policy")
def reassign_agent_policy(
    agent_id: str,
    payload: ReassignPolicyRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    agent = db.query(Agent).filter(
        Agent.agent_id == agent_id,
        Agent.tenant_id == auth.tenant_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.status == "decommissioned":
        raise HTTPException(status_code=400, detail="Cannot reassign policy to a decommissioned agent.")
    if not payload.policy:
        raise HTTPException(status_code=400, detail="policy body cannot be empty.")
    db.query(AgentPolicy).filter(
        AgentPolicy.agent_id == agent_id,
        AgentPolicy.tenant_id == auth.tenant_id,
        AgentPolicy.is_active.is_(True),
    ).update({"is_active": False}, synchronize_session="fetch")
    new_policy = AgentPolicy(
        agent_fk=agent.id,
        agent_id=agent_id,
        tenant_id=auth.tenant_id,
        policy_json=payload.policy,
        is_active=True,
    )
    db.add(new_policy)
    db.commit()
    db.refresh(new_policy)
    return {"ok": True, "agent_id": agent_id, "policy": new_policy.policy_json}
""")

with open("/app/api/routes/manage.py", "w") as f:
    f.write(manage_content + manage_addition)
print("manage.py patched")


# ── 3. keys.py — rotate trust key ────────────────────────────────────────────

with open("/app/api/routes/keys.py", "r") as f:
    keys_content = f.read()

keys_content = keys_content.replace(
    "from models.auth import TenantAPIKey",
    "from models.auth import TenantAPIKey\nfrom models.agent import Agent",
)

keys_addition = textwrap.dedent("""

class RotateKeyResponse(BaseModel):
    agent_id: str
    new_trust_key: str
    issued_at: str
    rotated_by_label: str
    note: str = "Save this key immediately - it cannot be retrieved again."


@router.post("/agents/{agent_id}/rotate-key", response_model=RotateKeyResponse)
def rotate_agent_trust_key(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RotateKeyResponse:
    agent = db.query(Agent).filter(
        Agent.agent_id == agent_id,
        Agent.tenant_id == auth.tenant_id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.status == "decommissioned":
        raise HTTPException(status_code=400, detail="Cannot rotate key for a decommissioned agent.")
    new_key = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    rotated_by_label = getattr(auth, "key_label", None) or f"key_id:{auth.key_id}"
    agent.trust_key = new_key
    agent.trust_key_issued_at = now
    agent.trust_key_rotated_by = rotated_by_label
    db.commit()
    return RotateKeyResponse(
        agent_id=agent_id,
        new_trust_key=new_key,
        issued_at=str(now),
        rotated_by_label=rotated_by_label,
    )
""")

with open("/app/api/routes/keys.py", "w") as f:
    f.write(keys_content + keys_addition)
print("keys.py patched")


print("\nAll done. Restart the container now.")
