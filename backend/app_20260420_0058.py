from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


from api.routes.agents import router as agents_router
from api.routes.assets import router as assets_router
from api.routes.compliance import router as compliance_router
from api.routes.vulns import router as vulns_router
from api.routes.commands import router as commands_router
from api.routes.dashboard import router as dashboard_router
from api.routes.network import router as network_router
from api.routes.darkweb import router as darkweb_router
from api.routes.keys import router as keys_router
from api.routes.manage import router as manage_router
from api.routes.scanner import router as scanner_router
from api.routes.adversarial import router as adversarial_router
from api.routes.schedule_routes import router as schedules_router
from api.routes.network_extensions import router as network_extensions_router
from api.routes.ai import router as ai_router
from api.routes.ai_ingest import router as ai_ingest_router
from api.routes.ai_compliance import router as ai_compliance_router
from api.routes.insurance import router as insurance_router
from api.routes.training import router as training_router
from api.routes.patch import router as patch_router
from api.routes.notifications import router as notification_router
from api.routes.external import router as external_router
from api.routes.identity import router as identity_router
from api.routes.executive import router as executive_router
# ── Phase 1: Foundational Intelligence (additive — safe to revert) ──────────
from api.routes.drift import router as drift_router
from api.routes.criticality import router as criticality_router
from api.routes.risk_engine import router as risk_engine_router
# ── Phase 2: Strategic Differentiation (additive — safe to revert) ───────────
from api.routes.attack_graph import router as attack_graph_router
from api.routes.backup_resilience import router as backup_resilience_router
from api.routes.blast_radius import router as blast_radius_router
# ── Phase 3: Actionability (additive — safe to revert) ──────────────────────
from api.routes.remediation import router as remediation_router
from api.routes.shadow_it import router as shadow_it_router
# ── Phase 4: Modern Estate Coverage (additive — safe to revert) ─────────────
from api.routes.cloud_posture import router as cloud_posture_router
# ── Phase 5: Scale Channel (additive — safe to revert) ──────────────────────
from api.routes.msp import router as msp_router
from db.base import Base
from db.session import SessionLocal, engine
from models.schedules import ScanSchedule  # ensure table registered before create_all
from api.routes.integrations import router as integrations_router

from api.routes.posture import router as posture_router
from api.routes.posture_sharing import router as posture_sharing_router
from api.routes.brokers import router as brokers_router
from api.routes.supply_chain import router as supply_chain_router
from api.routes.verification import router as verification_router
from api.routes.ce_danzell import router as ce_danzell_router
from api.routes.caf import router as caf_router
from api.routes.csr_assessment import router as csr_assessment_router
from api.routes.consumer_auth import router as consumer_auth_router
from api.routes.billing import router as billing_router
from api.routes.users import router as users_router
from api.routes.incident_response import router as incident_response_router
from api.routes.agentic import router as agentic_router
from api.routes.guide import router as guide_router

logger = logging.getLogger("cyberassetiq.startup")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

_STALE_TIMEOUT_SECONDS = 600
_STALE_CLEANUP_INTERVAL = 120
_JOB_KEEP_COMPLETED = 20
_JOB_PURGE_INTERVAL = 300


async def _cleanup_loop() -> None:
    cleanup_log = logging.getLogger("cyberassetiq.cleanup")
    await asyncio.sleep(30)
    cleanup_log.warning(
        "Cleanup loop started — stale_timeout=%ds interval=%ds purge_keep=%d",
        _STALE_TIMEOUT_SECONDS, _STALE_CLEANUP_INTERVAL, _JOB_KEEP_COMPLETED,
    )
    purge_counter = 0

    while True:
        # --- stale command cancellation ---
        try:
            from datetime import datetime, timezone, timedelta
            from models.commands import AgentCommand
            from services.command_service import refresh_job_status

            cutoff = datetime.now(timezone.utc) - timedelta(seconds=_STALE_TIMEOUT_SECONDS)
            db = SessionLocal()
            try:
                stale = (
                    db.query(AgentCommand)
                    .filter(
                        AgentCommand.is_deleted.is_(False),
                        AgentCommand.status.in_(["queued", "dispatched", "acked", "running"]),
                        AgentCommand.created_at < cutoff,
                    )
                    .all()
                )
                if stale:
                    job_ids = set()
                    now = int(time.time())
                    for cmd in stale:
                        cmd.status = "cancelled"
                        cmd.completed_epoch = now
                        cmd.result_json = {"error": "auto-cancelled: exceeded stale timeout"}
                        if cmd.job_id:
                            job_ids.add(cmd.job_id)
                    for job_id in job_ids:
                        refresh_job_status(db, job_id)
                    db.commit()
                    cleanup_log.warning(
                        "Stale cleanup: cancelled %d command(s) across %d job(s): %s",
                        len(stale), len(job_ids), [c.command_uuid for c in stale],
                    )
                else:
                    cleanup_log.debug("Stale cleanup: nothing to cancel.")
            finally:
                db.close()
        except Exception as exc:
            cleanup_log.exception("Stale command cleanup error: %s", exc)

        # --- periodic job purge ---
        purge_counter += _STALE_CLEANUP_INTERVAL
        if purge_counter >= _JOB_PURGE_INTERVAL:
            purge_counter = 0
            try:
                from models.commands import ScanJob, AgentCommand
                db = SessionLocal()
                try:
                    old_jobs = (
                        db.query(ScanJob)
                        .filter(ScanJob.status.in_(["partial_failed", "cancelled", "failed"]))
                        .all()
                    )
                    purged = 0
                    for job in old_jobs:
                        db.query(AgentCommand).filter(
                            AgentCommand.job_id == job.id
                        ).delete(synchronize_session=False)
                        db.delete(job)
                        purged += 1

                    completed = (
                        db.query(ScanJob)
                        .filter(ScanJob.status == "completed")
                        .order_by(ScanJob.id.desc())
                        .all()
                    )
                    for old_job in completed[_JOB_KEEP_COMPLETED:]:
                        db.query(AgentCommand).filter(
                            AgentCommand.job_id == old_job.id
                        ).delete(synchronize_session=False)
                        db.delete(old_job)
                        purged += 1

                    if purged:
                        db.commit()
                        cleanup_log.warning(
                            "Job purge: removed %d old job(s). Keeping last %d completed.",
                            purged, _JOB_KEEP_COMPLETED,
                        )
                    else:
                        cleanup_log.debug("Job purge: nothing to remove.")
                finally:
                    db.close()
            except Exception as exc:
                cleanup_log.exception("Job purge error: %s", exc)

        await asyncio.sleep(_STALE_CLEANUP_INTERVAL)

        # --- 12-month compliance run purge (CE v3.2 retention policy) ---
        try:
            from services.compliance_service import purge_old_compliance_runs
            db = SessionLocal()
            try:
                purged = purge_old_compliance_runs(db)
                if purged:
                    cleanup_log.warning("Compliance purge: removed %d run(s) older than 12 months.", purged)
            finally:
                db.close()
        except Exception as exc:
            cleanup_log.exception("Compliance purge error: %s", exc)

        # --- AI baseline rebuild (every 6 hours) ---
        _baseline_counter = getattr(_cleanup_loop, "_baseline_counter", 0) + _STALE_CLEANUP_INTERVAL
        _cleanup_loop._baseline_counter = _baseline_counter
        if _baseline_counter >= 21600:  # 6 hours
            _cleanup_loop._baseline_counter = 0
            try:
                from services.ai_baseline_service import AIBaselineService
                import os as _os
                default_tenant = _os.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
                db = SessionLocal()
                try:
                    svc = AIBaselineService(db)
                    counts = svc.rebuild_baselines(default_tenant)
                    cleanup_log.warning(
                        "AI baselines rebuilt: %d login_times, %d login_sources, %d auth_volume",
                        counts.get("login_times", 0),
                        counts.get("login_sources", 0),
                        counts.get("auth_volume", 0),
                    )
                finally:
                    db.close()
            except Exception as exc:
                cleanup_log.exception("AI baseline rebuild error: %s", exc)


        # --- notification rule evaluation (every 5 minutes) ---
        try:
            import os as _os2
            from services.notification_service import evaluate_rules as _eval_rules
            _notif_tenant = _os2.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
            db = SessionLocal()
            try:
                _sent = _eval_rules(db, _notif_tenant)
                if _sent:
                    cleanup_log.warning("Notifications: sent %d alert(s)", _sent)
            finally:
                db.close()
        except Exception as exc:
            cleanup_log.exception("Notification evaluation error: %s", exc)


        # --- risk snapshot (every 6 hours) ---
        _snap_counter = getattr(_cleanup_loop, "_snap_counter", 0) + _STALE_CLEANUP_INTERVAL
        _cleanup_loop._snap_counter = _snap_counter
        if _snap_counter >= 21600:  # 6 hours
            _cleanup_loop._snap_counter = 0
            try:
                from services.executive_service import create_snapshot as _create_snap
                import os as _os3
                _snap_tenant = _os3.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
                db = SessionLocal()
                try:
                    _snap = _create_snap(db, _snap_tenant)
                    cleanup_log.warning("Risk snapshot saved: overall=%d", _snap.get("overall_score", 0))
                finally:
                    db.close()
            except Exception as exc:
                cleanup_log.exception("Risk snapshot error: %s", exc)

        # ── Phase 3-5: periodic background tasks ────────────────────────────

        # --- Shadow IT scan (every 6 hours) ---
        _shadow_counter = getattr(_cleanup_loop, "_shadow_counter", 0) + _STALE_CLEANUP_INTERVAL
        _cleanup_loop._shadow_counter = _shadow_counter
        if _shadow_counter >= 21600:  # 6 hours
            _cleanup_loop._shadow_counter = 0
            try:
                from services.shadow_it_service import run_full_scan as _shadow_scan
                import os as _os4
                _shadow_tenant = _os4.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
                db = SessionLocal()
                try:
                    result = _shadow_scan(db, _shadow_tenant)
                    cleanup_log.warning(
                        "Shadow IT scan: rogue_software=%d unknown_devices=%d",
                        result.get("rogue_software", {}).get("new_findings", 0),
                        result.get("unknown_devices", {}).get("new_findings", 0),
                    )
                finally:
                    db.close()
            except Exception as exc:
                cleanup_log.exception("Shadow IT scan error: %s", exc)

        # --- MSP health score refresh (every 12 hours) ---
        _msp_counter = getattr(_cleanup_loop, "_msp_counter", 0) + _STALE_CLEANUP_INTERVAL
        _cleanup_loop._msp_counter = _msp_counter
        if _msp_counter >= 43200:  # 12 hours
            _cleanup_loop._msp_counter = 0
            try:
                from services.msp_portfolio_service import refresh_all_tenants as _msp_refresh
                from models.msp import MSPAccount
                import os as _os5
                _msp_tenant = _os5.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
                db = SessionLocal()
                try:
                    msp = db.query(MSPAccount).filter(
                        MSPAccount.tenant_id == _msp_tenant,
                        MSPAccount.is_active == True,
                    ).first()
                    if msp:
                        result = _msp_refresh(db, _msp_tenant)
                        cleanup_log.warning(
                            "MSP health refresh: %d tenants updated",
                            result.get("refreshed", 0),
                        )
                finally:
                    db.close()
            except Exception as exc:
                cleanup_log.exception("MSP health refresh error: %s", exc)

        # --- scheduled scan execution ---
        try:
            import time as _time
            from models.schedules import ScanSchedule
            db = SessionLocal()
            try:
                now_epoch = int(_time.time())
                due = (
                    db.query(ScanSchedule)
                    .filter(
                        ScanSchedule.is_active == True,
                        ScanSchedule.next_run_epoch <= now_epoch,
                    )
                    .all()
                )
                for sched in due:
                    cleanup_log.warning(
                        "Schedule: running '%s' (%s) for tenant %s",
                        sched.name, sched.scan_type, sched.tenant_id,
                    )
                    sched.last_run_epoch = now_epoch
                    sched.last_status    = "running"
                    sched.next_run_epoch = now_epoch + sched.interval_hours * 3600
                    db.commit()

                    try:
                        result = {}
                        if sched.scan_type == "network_scan":
                            from services.network_scan_service import run_network_scan_job
                            target = sched.target or "192.168.0.0/24"
                            job, stored = run_network_scan_job(
                                db, sched.tenant_id, target, requested_by="scheduler"
                            )
                            result = {"discovered": len(stored), "target": target}

                        elif sched.scan_type == "vuln_scan":
                            from services.nvd_service import run_vuln_scan_for_tenant
                            result = run_vuln_scan_for_tenant(db, sched.tenant_id)

                        elif sched.scan_type == "threat_intel":
                            from services.darkweb_feeds import run_threat_intel_scan
                            result = run_threat_intel_scan(db, sched.tenant_id)

                        elif sched.scan_type == "agent_scan":
                            from services.command_service import create_scan_job
                            from models.agent import Agent
                            agents = (
                                db.query(Agent)
                                .filter(
                                    Agent.tenant_id == sched.tenant_id,
                                    Agent.status == "active",
                                )
                                .all()
                            )
                            agent_ids = [a.agent_id for a in agents]
                            if agent_ids:
                                job = create_scan_job(
                                    db, sched.tenant_id, agent_ids,
                                    job_type="run_scan_full",
                                    requested_by="scheduler",
                                )
                                result = {"agents_queued": len(agent_ids)}

                        elif sched.scan_type == "posture_rebuild":
                            from services.posture_record_service import create_posture_version
                            created = create_posture_version(
                                db, sched.tenant_id,
                                generated_by="scheduler",
                                issue_default_credential=True,
                            )
                            v = created["version"]
                            result = {
                                "version_id": v.id,
                                "version_no": v.version_no,
                                "overall_score": v.overall_score,
                                "risk_band": v.risk_band,
                            }
                            cleanup_log.warning(
                                "Posture rebuild: tenant=%s score=%d band=%s",
                                sched.tenant_id, v.overall_score, v.risk_band,
                            )

                        sched.last_status = "completed"
                        sched.last_result = result
                        db.commit()
                        cleanup_log.warning(
                            "Schedule: '%s' completed — %s",
                            sched.name, result,
                        )

                    except Exception as scan_exc:
                        sched.last_status = "failed"
                        sched.last_result = {"error": str(scan_exc)}
                        db.commit()
                        cleanup_log.exception(
                            "Schedule: '%s' failed: %s", sched.name, scan_exc
                        )
            finally:
                db.close()
        except Exception as exc:
            cleanup_log.exception("Scheduled scan loop error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    for _t in Base.metadata.sorted_tables:
        try:
            _t.create(engine, checkfirst=True)
        except Exception:
            pass

    import os
    from api.deps import ensure_bootstrap_key

    default_tenant = os.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
    db = SessionLocal()
    try:
        plaintext = ensure_bootstrap_key(db, default_tenant)
        if plaintext:
            border = "=" * 64
            logger.warning(border)
            logger.warning("CYBERASSETIQ BOOTSTRAP API KEY (shown once)")
            logger.warning("Tenant:  %s", default_tenant)
            logger.warning("API Key: %s", plaintext)
            logger.warning("Copy this key — it will NOT be shown again.")
            logger.warning(border)

        from services.agent_service import ensure_bootstrap_token
        enroll_token = ensure_bootstrap_token(db, default_tenant)
        if enroll_token:
            logger.warning("=" * 64)
            logger.warning("CYBERASSETIQ BOOTSTRAP ENROLLMENT TOKEN (shown once)")
            logger.warning("Tenant:  %s", default_tenant)
            logger.warning("Enroll Token: %s", enroll_token)
            logger.warning("Set CYBERASSETIQ_ENROLLMENT_TOKEN on the agent.")
            logger.warning("=" * 64)

        # ── Seed default posture_rebuild schedule if none exists ────────────
        try:
            import os as _os_seed
            _seed_tenant = _os_seed.getenv("CYBERASSETIQ_DEFAULT_TENANT", "dev-tenant")
            from models.schedules import ScanSchedule
            db = SessionLocal()
            try:
                existing_posture_sched = (
                    db.query(ScanSchedule)
                    .filter(
                        ScanSchedule.tenant_id == _seed_tenant,
                        ScanSchedule.scan_type == "posture_rebuild",
                        ScanSchedule.is_active == True,
                    )
                    .first()
                )
                if not existing_posture_sched:
                    import time as _t_seed
                    db.add(ScanSchedule(
                        tenant_id=_seed_tenant,
                        name="Daily Posture Rebuild",
                        scan_type="posture_rebuild",
                        target=None,
                        interval_hours=24,
                        is_active=True,
                        next_run_epoch=int(_t_seed.time()) + 3600,  # first run in 1 hour
                        config={},
                    ))
                    db.commit()
                    logger.warning("Seeded default daily posture rebuild schedule for tenant %s", _seed_tenant)
            finally:
                db.close()
        except Exception as _seed_exc:
            logger.warning("Could not seed posture rebuild schedule: %s", _seed_exc)

        # ── Phase 3: seed default remediation playbooks on startup ──────────
        try:
            from services.remediation_service import seed_default_playbooks
            seeded = seed_default_playbooks(db, default_tenant)
            if seeded:
                logger.warning("Remediation: seeded %d default playbooks for tenant %s",
                               seeded, default_tenant)
        except Exception as exc:
            logger.exception("Remediation playbook seed error: %s", exc)

    finally:
        db.close()

    task = asyncio.create_task(_cleanup_loop())
    logger.warning(
        "Background cleanup task started (stale=%ds purge_keep=%d)",
        _STALE_TIMEOUT_SECONDS, _JOB_KEEP_COMPLETED,
    )

    yield

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="CyberAssetIQ Backend",
    version="4.0.0",
    description=(
        "Asset discovery, silent agent scan orchestration, agentless network discovery, "
        "dark web exposure matching, CE v3.2 compliance mapping, CVE correlation, "
        "drift detection, criticality scoring, attack graph analysis, backup resilience, "
        "remediation automation, shadow IT detection, cloud posture, and MSP portfolio "
        "management for UK SMEs."
    ),
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "4.0.0"}


app.include_router(agents_router,      prefix="/api/agents",        tags=["agents"])
app.include_router(assets_router,      prefix="/api/assets",        tags=["assets"])
app.include_router(compliance_router,  prefix="/api/compliance",    tags=["compliance"])
app.include_router(vulns_router,       prefix="/api/vulns",         tags=["vulnerabilities"])
app.include_router(commands_router,    prefix="/api",               tags=["commands"])
app.include_router(dashboard_router,   prefix="/api/dashboard",     tags=["dashboard"])
app.include_router(network_router,     prefix="/api/network-scan",  tags=["network-scan"])
app.include_router(darkweb_router,     prefix="/api/darkweb",       tags=["darkweb"])
app.include_router(keys_router,        prefix="/api/admin",         tags=["admin"])
app.include_router(manage_router,      prefix="/api/admin",         tags=["admin"])
app.include_router(scanner_router,     prefix="/api/scanner",       tags=["Credential Scanner"])
app.include_router(adversarial_router, prefix="/api/adversarial",   tags=["Adversarial Lab"])
app.include_router(ai_router)
app.include_router(ai_ingest_router, prefix="/api/ai/ingest", tags=["ai-ingest"])
app.include_router(ai_compliance_router)
app.include_router(schedules_router,             prefix="/api/schedules",          tags=["schedules"])

app.include_router(insurance_router)
app.include_router(training_router)
app.include_router(patch_router)
app.include_router(notification_router)
app.include_router(external_router)
app.include_router(identity_router)
app.include_router(executive_router)
app.include_router(network_extensions_router,    prefix="/api/network-extensions", tags=["network-extensions"])

# ── Phase 1: Foundational Intelligence (additive — safe to revert) ──────────
app.include_router(drift_router,       prefix="/api/drift",       tags=["drift"])
app.include_router(criticality_router, prefix="/api/criticality", tags=["criticality"])
app.include_router(risk_engine_router, prefix="/api/risk",        tags=["risk-engine"])

# ── Phase 2: Strategic Differentiation (additive — safe to revert) ───────────
app.include_router(attack_graph_router,      prefix="/api/attack-graph",      tags=["attack-graph"])
app.include_router(backup_resilience_router, prefix="/api/backup",            tags=["backup-resilience"])
app.include_router(blast_radius_router,      prefix="/api/blast-radius",      tags=["blast-radius"])

# ── Phase 3: Actionability (additive — safe to revert) ──────────────────────
app.include_router(remediation_router, prefix="/api/remediation", tags=["remediation"])
app.include_router(shadow_it_router,   prefix="/api/shadow-it",   tags=["shadow-it"])

# ── Phase 4: Modern Estate Coverage (additive — safe to revert) ─────────────
app.include_router(cloud_posture_router, prefix="/api/cloud", tags=["cloud-posture"])

# ── Phase 5: Scale Channel (additive — safe to revert) ──────────────────────
app.include_router(msp_router, prefix="/api/msp", tags=["msp"])
app.include_router(integrations_router, prefix="/api/integrations", tags=["integrations"])
app.include_router(posture_router)
app.include_router(posture_sharing_router)
app.include_router(brokers_router)
app.include_router(supply_chain_router)
app.include_router(verification_router)
app.include_router(ce_danzell_router)
app.include_router(caf_router)
app.include_router(csr_assessment_router)
app.include_router(consumer_auth_router)
app.include_router(billing_router)
app.include_router(users_router)
app.include_router(incident_response_router)
app.include_router(agentic_router)
app.include_router(guide_router, prefix="/api/ai", tags=["AI Guide"])

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
