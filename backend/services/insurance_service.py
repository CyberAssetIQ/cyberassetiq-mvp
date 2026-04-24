from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.insurance")

RISKY_PORTS: dict[int, str] = {
    3389: "RDP — top ransomware entry point",
    23:   "Telnet — unencrypted remote access",
    21:   "FTP — unencrypted file transfer",
    5900: "VNC — unencrypted remote desktop",
    4444: "Common backdoor / C2 port",
    1433: "MSSQL — database exposed to network",
    3306: "MySQL — database exposed to network",
    5432: "PostgreSQL — database exposed to network",
}


def _band(score: int) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def _band_color(band: str) -> str:
    return {
        "Low":      "#1F7A4D",
        "Medium":   "#C7600A",
        "High":     "#B32D1F",
        "Critical": "#7B0000",
    }.get(band, "#333333")


def calculate_readiness(db: Session, tenant_id: str) -> dict[str, Any]:
    score = 100
    factors: list[dict] = []
    snapshot: dict[str, Any] = {}

    # ── 1. Critical & High CVEs ──────────────────────────────────────────────
    try:
        from models.telemetry import VulnerabilityFinding

        critical_cves = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "CRITICAL",
            VulnerabilityFinding.status == "open",
        ).count()

        high_cves = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "HIGH",
            VulnerabilityFinding.status == "open",
        ).count()

        snapshot["critical_cves"] = critical_cves
        snapshot["high_cves"] = high_cves

        if critical_cves > 0:
            deduct = min(critical_cves * 3, 15)
            score -= deduct
            factors.append({
                "factor": "Critical CVEs",
                "impact": -deduct,
                "detail": f"{critical_cves} open critical CVE(s) — max deduction capped at -15",
                "severity": "critical",
            })

        if high_cves > 0:
            deduct = min(high_cves, 10)
            score -= deduct
            factors.append({
                "factor": "High-Severity CVEs",
                "impact": -deduct,
                "detail": f"{high_cves} open high CVE(s) — max deduction capped at -10",
                "severity": "high",
            })

    except Exception as exc:
        logger.warning("CVE factor error: %s", exc)

    # ── 2. Cyber Essentials Compliance Score ─────────────────────────────────
    try:
        from models.compliance_run import ComplianceRun

        latest = (
            db.query(ComplianceRun)
            .filter(ComplianceRun.tenant_id == tenant_id)
            .order_by(desc(ComplianceRun.id))
            .first()
        )

        if latest is None:
            score -= 15
            snapshot["ce_score"] = None
            factors.append({
                "factor": "No CE Assessment Found",
                "impact": -15,
                "detail": "Underwriters typically require Cyber Essentials certification. No assessment detected.",
                "severity": "critical",
            })
        else:
            ce = latest.tenant_overall_score or 0
            snapshot["ce_score"] = round(ce, 1)

            if ce < 50:
                deduct = 20
                sev = "critical"
                label = "CE Compliance: Very Low"
                detail = f"CE score {ce:.0f}% — significantly below the 70% certification threshold."
            elif ce < 70:
                deduct = 10
                sev = "high"
                label = "CE Compliance: Below Threshold"
                detail = f"CE score {ce:.0f}% — below the 70% threshold required for certification."
            elif ce < 85:
                deduct = 3
                sev = "medium"
                label = "CE Compliance: Marginal"
                detail = f"CE score {ce:.0f}% — certified but with room for improvement."
            else:
                deduct = 0
                sev = "ok"
                label = "CE Compliance: Strong"
                detail = f"CE score {ce:.0f}% — strong compliance posture."

            score -= deduct
            factors.append({
                "factor": label,
                "impact": -deduct,
                "detail": detail,
                "severity": sev,
            })

    except Exception as exc:
        logger.warning("CE compliance factor error: %s", exc)

    # ── 3. Dark Web Exposure ─────────────────────────────────────────────────
    try:
        from models.darkweb import DarkWebFinding

        dw_active = db.query(DarkWebFinding).filter(
            DarkWebFinding.tenant_id == tenant_id,
            DarkWebFinding.status != "resolved",
        ).count()

        snapshot["darkweb_active"] = dw_active

        if dw_active > 0:
            deduct = min(dw_active * 5, 15)
            score -= deduct
            factors.append({
                "factor": "Dark Web Exposure",
                "impact": -deduct,
                "detail": f"{dw_active} active dark web finding(s) — credentials or data found in breach datasets.",
                "severity": "critical",
            })

    except Exception as exc:
        logger.warning("Dark web factor error: %s", exc)

    # ── 4. Credential / Secret Leaks (from endpoint agents) ──────────────────
    try:
        from models.telemetry import LocalFindingsEvent

        recent = (
            db.query(LocalFindingsEvent)
            .filter(LocalFindingsEvent.tenant_id == tenant_id)
            .order_by(desc(LocalFindingsEvent.created_at))
            .limit(20)
            .all()
        )

        critical_secrets = 0
        for evt in recent:
            try:
                findings = (
                    evt.payload_json
                    if isinstance(evt.payload_json, list)
                    else json.loads(evt.payload_json or "[]")
                )
                critical_secrets += sum(
                    1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH")
                )
            except Exception:
                pass

        snapshot["credential_leaks"] = critical_secrets

        if critical_secrets > 0:
            deduct = min(critical_secrets * 3, 10)
            score -= deduct
            factors.append({
                "factor": "Credential / Secret Leaks",
                "impact": -deduct,
                "detail": f"{critical_secrets} critical/high secret finding(s) detected by endpoint agents.",
                "severity": "critical",
            })

    except Exception as exc:
        logger.warning("Credential factor error: %s", exc)

    # ── 5. Risky Open Ports ───────────────────────────────────────────────────
    try:
        from models.network import NetworkDiscoveredAsset

        assets = (
            db.query(NetworkDiscoveredAsset)
            .filter(NetworkDiscoveredAsset.tenant_id == tenant_id)
            .all()
        )

        risky_found: dict[int, str] = {}
        for asset in assets:
            try:
                ports = (
                    asset.open_ports
                    if isinstance(asset.open_ports, list)
                    else json.loads(asset.open_ports or "[]")
                )
                for p in ports:
                    try:
                        port_num = int(p) if isinstance(p, (int, str)) else int(p.get("port", 0))
                    except (ValueError, TypeError):
                        continue
                    if port_num in RISKY_PORTS and port_num not in risky_found:
                        risky_found[port_num] = RISKY_PORTS[port_num]
            except Exception:
                pass

        snapshot["risky_ports"] = list(risky_found.keys())

        if risky_found:
            deduct = min(len(risky_found) * 5, 15)
            score -= deduct
            port_list = ", ".join(
                f"{p} ({desc.split(' — ')[0]})" for p, desc in list(risky_found.items())[:4]
            )
            factors.append({
                "factor": "Risky Services Exposed",
                "impact": -deduct,
                "detail": f"{len(risky_found)} risky service(s) detected on network: {port_list}",
                "severity": "high",
            })

    except Exception as exc:
        logger.warning("Risky ports factor error: %s", exc)

    # ── Clamp & band ──────────────────────────────────────────────────────────
    score = max(0, min(100, score))
    band = _band(score)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    for f in factors:
        sev = f.get("severity", "")
        name = f.get("factor", "")
        impact = f.get("impact", 0)

        if impact >= 0:
            continue  # positive/neutral factor — no action needed

        if sev == "critical":
            if "CVE" in name:
                recommendations.append(
                    "Patch or mitigate all critical CVEs immediately — this is the single largest insurance premium driver."
                )
            elif "Dark Web" in name:
                recommendations.append(
                    "Rotate all credentials found in dark web findings and enforce MFA across all accounts."
                )
            elif "CE" in name:
                recommendations.append(
                    "Complete a Cyber Essentials assessment — CE certification typically reduces cyber insurance premiums by 20–40%."
                )
            elif "Secret" in name or "Credential" in name:
                recommendations.append(
                    "Revoke and rotate all leaked API keys and credentials detected by the endpoint agents."
                )

        elif sev == "high":
            if "Port" in name or "Service" in name:
                recommendations.append(
                    "Restrict risky services (RDP, Telnet, FTP, VNC) to authorised IP ranges using firewall rules."
                )
            elif "CVE" in name:
                recommendations.append(
                    "Schedule patching of high-severity CVEs within the next 30 days to reduce premium loading."
                )

        elif sev == "medium":
            recommendations.append(
                f"Improve {name} to strengthen insurability and reduce potential premium loading."
            )

    if not recommendations:
        recommendations.append(
            "Excellent security posture — maintain current controls and re-assess quarterly to retain favourable insurance terms."
        )

    return {
        "readiness_score": score,
        "risk_band": band,
        "band_color": _band_color(band),
        "factors": factors,
        "recommendations": recommendations,
        "snapshot": snapshot,
    }


# ── Persistence helpers ───────────────────────────────────────────────────────

def save_assessment(db: Session, tenant_id: str, data: dict) -> dict:
    from models.insurance import InsuranceAssessment

    record = InsuranceAssessment(
        tenant_id=tenant_id,
        readiness_score=data["readiness_score"],
        risk_band=data["risk_band"],
        factors_json=data.get("factors", []),
        recommendations_json=data.get("recommendations", []),
        snapshot_json=data.get("snapshot", {}),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {
        "id": record.id,
        "created_at": record.created_at.isoformat(),
        "readiness_score": record.readiness_score,
        "risk_band": record.risk_band,
    }


def list_assessments(db: Session, tenant_id: str) -> list:
    from models.insurance import InsuranceAssessment

    rows = (
        db.query(InsuranceAssessment)
        .filter(InsuranceAssessment.tenant_id == tenant_id)
        .order_by(desc(InsuranceAssessment.id))
        .limit(20)
        .all()
    )
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "readiness_score": r.readiness_score,
            "risk_band": r.risk_band,
            "factors": r.factors_json,
            "recommendations": r.recommendations_json,
        }
        for r in rows
    ]


def log_referral(
    db: Session,
    tenant_id: str,
    partner: str = "general",
    assessment_id: int | None = None,
) -> dict:
    from models.insurance import InsuranceReferral

    ref = InsuranceReferral(
        tenant_id=tenant_id,
        partner=partner,
        assessment_id=assessment_id,
    )
    db.add(ref)
    db.commit()
    return {"logged": True, "partner": partner}
