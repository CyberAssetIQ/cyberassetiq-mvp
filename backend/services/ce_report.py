from __future__ import annotations

"""
CyberAssetIQ — CE v3.2 Evidence Package PDF Generator
======================================================
Generates a professional PDF evidence package for Cyber Essentials v3.2
certification. Matches the format expected by IASME assessors.

Controls covered: A1-A8
Output: Multi-page PDF with:
  - Cover page (org name, date, overall status)
  - Executive summary (pass/fail counts, score)
  - Per-control evidence pages
  - Asset inventory appendix
  - Remediation action plan
"""

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable


# ── Colour palette ────────────────────────────────────────────────────────
NAVY       = colors.HexColor("#0f172a")
ACCENT     = colors.HexColor("#3b82f6")
GREEN      = colors.HexColor("#22c55e")
AMBER      = colors.HexColor("#f59e0b")
RED        = colors.HexColor("#ef4444")
LIGHT_GREY = colors.HexColor("#f1f5f9")
MID_GREY   = colors.HexColor("#94a3b8")
WHITE      = colors.white
DARK_TEXT  = colors.HexColor("#1e293b")


def _status_colour(status: str) -> colors.Color:
    s = (status or "").upper()
    if s == "PASS":    return GREEN
    if s == "PARTIAL": return AMBER
    if s == "FAIL":    return RED
    return MID_GREY


def _status_label(status: str) -> str:
    s = (status or "").upper()
    if s == "PASS":         return "PASS ✓"
    if s == "PARTIAL":      return "PARTIAL ⚠"
    if s == "FAIL":         return "FAIL ✗"
    if s == "NOT_ASSESSED": return "NOT ASSESSED"
    return status


def _pct(score: float) -> str:
    return f"{round(score * 100)}%"


def generate_ce_report(
    tenant_data: dict[str, Any],
    org_name: str = "Organisation",
    assessor: str = "CyberAssetIQ",
    full_reports: list[Any] | None = None,
) -> bytes:
    """
    Generate a CE v3.2 evidence package PDF.

    Args:
        tenant_data:  Output from assess_tenant() — tenant-level summary
        org_name:     Organisation name for the cover page
        assessor:     Assessor/tool name
        full_reports: List of AssetComplianceReport objects with full control detail

    Returns:
        PDF as bytes — ready to return as a FastAPI response
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"CE v3.2 Evidence Package — {org_name}",
        author=assessor,
    )

    styles = getSampleStyleSheet()
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%d %B %Y")
    overall_score = tenant_data.get("tenant_overall_score", 0.0)
    overall_status = "PASS" if tenant_data.get("ce_ready") else (
        "PARTIAL" if overall_score >= 0.6 else "FAIL"
    )
    assets = tenant_data.get("assets", [])

    # Build full asset detail from full_reports if available
    # full_reports is a list of AssetComplianceReport dataclass instances
    full_report_map: dict[str, Any] = {}
    if full_reports:
        for r in full_reports:
            full_report_map[r.agent_id] = r

    # ── Custom styles ─────────────────────────────────────────────────────
    h1 = ParagraphStyle("H1", fontSize=22, textColor=NAVY,
                        spaceAfter=18, spaceBefore=10, fontName="Helvetica-Bold")
    h2 = ParagraphStyle("H2", fontSize=14, textColor=NAVY,
                        spaceAfter=12, spaceBefore=20, fontName="Helvetica-Bold")
    h3 = ParagraphStyle("H3", fontSize=11, textColor=ACCENT,
                        spaceAfter=10, spaceBefore=18, fontName="Helvetica-Bold")
    body = ParagraphStyle("Body", fontSize=9, textColor=DARK_TEXT,
                          spaceAfter=8, leading=18)
    small = ParagraphStyle("Small", fontSize=8, textColor=MID_GREY,
                           spaceAfter=6, leading=16)
    centre = ParagraphStyle("Centre", fontSize=9, alignment=TA_CENTER,
                            textColor=DARK_TEXT)
    finding_style = ParagraphStyle("Finding", fontSize=9, textColor=RED,
                                   leftIndent=12, spaceAfter=7, leading=17)
    remediation_style = ParagraphStyle("Remediation", fontSize=9,
                                       textColor=colors.HexColor("#065f46"),
                                       leftIndent=12, spaceAfter=7, leading=17)

    story = []

    # ══════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 3*cm))

    # Header bar
    header_data = [[Paragraph(
        f'<font color="white"><b>CYBER ESSENTIALS v3.2</b><br/>'
        f'<font size="11">Evidence Package</font></font>',
        ParagraphStyle("hdr", fontSize=18, textColor=WHITE,
                       fontName="Helvetica-Bold", alignment=TA_CENTER)
    )]]
    header_table = Table(header_data, colWidths=[17*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
        ("LEFTPADDING",   (0,0), (-1,-1), 16),
        ("RIGHTPADDING",  (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8,8,8,8]),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 1*cm))

    story.append(Paragraph(org_name, ParagraphStyle(
        "OrgName", fontSize=26, textColor=NAVY,
        fontName="Helvetica-Bold", alignment=TA_CENTER)))
    story.append(Spacer(1, 1.0*cm))
    story.append(Paragraph(f"Assessment Date: {date_str}", ParagraphStyle(
        "Date", fontSize=11, textColor=MID_GREY, alignment=TA_CENTER)))
    story.append(Spacer(1, 1.5*cm))

    # Overall status badge
    status_col = _status_colour(overall_status)
    status_data = [[
        Paragraph(f'<font color="white"><b>{_status_label(overall_status)}</b></font>',
                  ParagraphStyle("badge", fontSize=16, textColor=WHITE,
                                 fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(
            f'<b>Overall Score: {_pct(overall_score)}</b><br/>'
            f'<font size="9" color="grey">{tenant_data.get("assets_assessed",0)} assets assessed • '
            f'{tenant_data.get("assets_passing",0)} passing • '
            f'{tenant_data.get("assets_partial",0)} partial • '
            f'{tenant_data.get("assets_failing",0)} failing</font>',
            ParagraphStyle("scoreP", fontSize=12, textColor=DARK_TEXT,
                           alignment=TA_CENTER)
        ),
    ]]
    status_table = Table(status_data, colWidths=[5*cm, 12*cm])
    status_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,0), status_col),
        ("BACKGROUND",    (1,0), (1,0), LIGHT_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 12),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ROUNDEDCORNERS",(0,0), (-1,-1), [8,8,8,8]),
    ]))
    story.append(status_table)
    story.append(Spacer(1, 1.5*cm))

    story.append(Paragraph(
        f"Generated by: <b>{assessor}</b>  |  "
        f"Tenant ID: <b>{tenant_data.get('tenant_id','—')}</b>  |  "
        f"Framework: <b>Cyber Essentials v3.2 (IASME)</b>",
        ParagraphStyle("footer_cover", fontSize=8, textColor=MID_GREY,
                       alignment=TA_CENTER)
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Executive Summary", h1))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT,
                             spaceAfter=0))
    story.append(Spacer(1, 0.4*cm))

    # Summary metrics table
    metrics = [
        ["Assets Assessed",    str(tenant_data.get("assets_assessed", 0))],
        ["Assets Passing",     str(tenant_data.get("assets_passing", 0))],
        ["Assets Partial",     str(tenant_data.get("assets_partial", 0))],
        ["Assets Failing",     str(tenant_data.get("assets_failing", 0))],
        ["Overall Score",      _pct(overall_score)],
        ["CE Ready",           "YES" if tenant_data.get("ce_ready") else "NO"],
    ]
    metric_data = [[
        Paragraph(f"<b>{k}</b>", body),
        Paragraph(v, body)
    ] for k, v in metrics]

    metric_table = Table(metric_data, colWidths=[8*cm, 9*cm])
    metric_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GREY),
        ("BACKGROUND",    (0,0), (0,-1), colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("LINEBELOW",     (0,0), (-1,-2), 0.5, colors.HexColor("#cbd5e1")),
        ("ROUNDEDCORNERS",(0,0), (-1,-1), [6,6,6,6]),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(
        "This evidence package has been automatically generated by CyberAssetIQ "
        "using live asset telemetry, security posture data, and software inventory. "
        "All findings are based on data collected at assessment time and mapped to "
        "Cyber Essentials v3.2 controls as defined by IASME/NCSC.",
        body
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # CE CONTROL SUMMARY TABLE
    # ══════════════════════════════════════════════════════════════════════
    story.append(Paragraph("CE v3.2 Control Summary", h1))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT,
                             spaceAfter=0))
    story.append(Spacer(1, 0.4*cm))

    # Aggregate controls across all assets
    # Use full_reports for complete data if available, else fall back to slim summary
    control_agg: dict[str, dict] = {}
    source_assets = full_reports if full_reports else []

    if source_assets:
        for r in source_assets:
            for c in r.controls:
                cid = c.control_id
                if cid not in control_agg:
                    control_agg[cid] = {
                        "name":     c.control_name,
                        "scores":   [],
                        "statuses": [],
                        "findings": [],
                    }
                control_agg[cid]["scores"].append(c.score)
                control_agg[cid]["statuses"].append(c.status)
                control_agg[cid]["findings"].extend(c.findings)
    else:
        # Fall back to slim tenant summary
        for asset in assets:
            for cid, ctrl in asset.get("controls", {}).items():
                if cid not in control_agg:
                    control_agg[cid] = {
                        "name":     ctrl.get("name", cid),
                        "scores":   [],
                        "statuses": [],
                        "findings": [],
                    }
                control_agg[cid]["scores"].append(ctrl.get("score", 0))
                control_agg[cid]["statuses"].append(ctrl.get("status", ""))

    # Control summary table
    ctrl_header = [
        Paragraph("<b>Control</b>", centre),
        Paragraph("<b>Name</b>", body),
        Paragraph("<b>Status</b>", centre),
        Paragraph("<b>Score</b>", centre),
        Paragraph("<b>Issues</b>", centre),
    ]
    ctrl_rows = [ctrl_header]

    for cid in sorted(control_agg.keys()):
        agg = control_agg[cid]
        avg_score = sum(agg["scores"]) / len(agg["scores"]) if agg["scores"] else 0
        # Worst status wins
        status_priority = {"FAIL": 0, "PARTIAL": 1, "NOT_ASSESSED": 2, "PASS": 3}
        worst = min(agg["statuses"],
                    key=lambda s: status_priority.get(s.upper(), 2)) if agg["statuses"] else "NOT_ASSESSED"
        issue_count = len(set(agg["findings"]))
        status_col = _status_colour(worst)

        ctrl_rows.append([
            Paragraph(f"<b>{cid}</b>", centre),
            Paragraph(agg["name"], body),
            Paragraph(
                f'<font color="white"><b>{_status_label(worst)}</b></font>',
                ParagraphStyle("sc", fontSize=8, textColor=WHITE,
                               alignment=TA_CENTER, fontName="Helvetica-Bold")
            ),
            Paragraph(_pct(avg_score), centre),
            Paragraph(str(issue_count) if issue_count else "—", centre),
        ])

    if ctrl_rows[1:]:
        ctrl_table = Table(ctrl_rows, colWidths=[2*cm, 7*cm, 3.5*cm, 2*cm, 2.5*cm])
        ts = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("LINEBELOW",     (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ])
        # Colour the status cells
        for i, row in enumerate(ctrl_rows[1:], start=1):
            status_text = agg["statuses"][0] if control_agg else ""
            cid_key = sorted(control_agg.keys())[i-1] if i-1 < len(control_agg) else ""
            if cid_key:
                statuses = control_agg[cid_key]["statuses"]
                status_priority = {"FAIL": 0, "PARTIAL": 1, "NOT_ASSESSED": 2, "PASS": 3}
                worst_s = min(statuses,
                              key=lambda s: status_priority.get(s.upper(), 2)) if statuses else "NOT_ASSESSED"
                ts.add("BACKGROUND", (2,i), (2,i), _status_colour(worst_s))

        ctrl_table.setStyle(ts)
        story.append(ctrl_table)
    else:
        story.append(Paragraph("No compliance data available. Run a full agent scan first.", body))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # PER-ASSET DETAIL PAGES
    # ══════════════════════════════════════════════════════════════════════
    # Use full_reports for detailed per-asset pages if available
    report_source = full_reports if full_reports else []

    for r in report_source:
        hostname    = r.hostname or r.agent_id or "Unknown"
        asset_status = r.overall_status
        asset_score  = r.overall_score
        agent_id     = r.agent_id

        story.append(Paragraph(f"Asset: {hostname}", h1))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width="100%", thickness=2,
                                 color=_status_colour(asset_status), spaceAfter=0))
        story.append(Spacer(1, 0.4*cm))

        asset_meta = [
            [Paragraph("<b>Agent ID</b>", small),
             Paragraph(agent_id, body)],
            [Paragraph("<b>Overall Status</b>", small),
             Paragraph(_status_label(asset_status), body)],
            [Paragraph("<b>Overall Score</b>", small),
             Paragraph(_pct(asset_score), body)],
            [Paragraph("<b>Controls Pass/Fail</b>", small),
             Paragraph(
                 f"{r.summary.get('controls_pass',0)} pass · "
                 f"{r.summary.get('controls_partial',0)} partial · "
                 f"{r.summary.get('controls_fail',0)} fail",
                 body)],
        ]
        am_table = Table(asset_meta, colWidths=[4*cm, 13*cm])
        am_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GREY),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("LINEBELOW",     (0,0), (-1,-2), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(am_table)
        story.append(Spacer(1, 0.6*cm))

        for ctrl in r.controls:
            ctrl_id   = ctrl.control_id
            ctrl_name = ctrl.control_name
            ctrl_st   = ctrl.status
            ctrl_sc   = ctrl.score
            findings  = ctrl.findings
            remediation = ctrl.remediation

            block = []
            block.append(Paragraph(
                f"<b>{ctrl_id} — {ctrl_name}</b>  "
                f"<font color='grey'>Score: {_pct(ctrl_sc)}</font>",
                h3
            ))

            # Status pill row
            status_data = [[
                Paragraph(
                    f'<font color="white"><b>{_status_label(ctrl_st)}</b></font>',
                    ParagraphStyle("cp", fontSize=9, textColor=WHITE,
                                   fontName="Helvetica-Bold", alignment=TA_CENTER)
                )
            ]]
            sp_table = Table(status_data, colWidths=[3.5*cm])
            sp_table.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), _status_colour(ctrl_st)),
                ("TOPPADDING",    (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 7),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                ("ROUNDEDCORNERS",(0,0), (-1,-1), [4,4,4,4]),
            ]))
            block.append(sp_table)
            block.append(Spacer(1, 0.4*cm))

            if findings:
                block.append(Paragraph("<b>Findings:</b>", body))
                for f in findings:
                    block.append(Paragraph(f"• {f}", finding_style))
            else:
                block.append(Paragraph("• No issues found for this control.", body))

            if remediation:
                block.append(Paragraph("<b>Remediation:</b>", body))
                for r in remediation:
                    block.append(Paragraph(f"→ {r}", remediation_style))

            block.append(Spacer(1, 0.5*cm))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # ASSET INVENTORY APPENDIX
    # ══════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Appendix A — Asset Inventory", h1))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT,
                             spaceAfter=0))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "The following assets were discovered and assessed as part of this "
        "Cyber Essentials v3.2 evidence package.", body))
    story.append(Spacer(1, 0.3*cm))

    inv_header = [
        Paragraph("<b>Hostname / Agent ID</b>", body),
        Paragraph("<b>OS</b>", body),
        Paragraph("<b>Status</b>", centre),
        Paragraph("<b>Score</b>", centre),
    ]
    inv_rows = [inv_header]
    # Use full reports for inventory if available
    inv_source = full_reports if full_reports else []
    for r in inv_source:
        hostname = r.hostname or r.agent_id or "—"
        # Get OS from summary if available
        # os_family is on CanonicalAsset not AssetComplianceReport
        # Use the summary data or default to Windows for agent-managed assets
        os_info = getattr(r, "os_family", None) or "Windows (agent-managed)"
        status   = r.overall_status
        score    = r.overall_score
        inv_rows.append([
            Paragraph(hostname, body),
            Paragraph(os_info, body),
            Paragraph(_status_label(status), body),
            Paragraph(_pct(score), centre),
        ])
    # If no full reports, fall back to slim summary
    if not inv_source:
        for asset in assets:
            hostname = asset.get("hostname") or asset.get("agent_id", "—")
            os_info  = asset.get("os_family", "—")
            status   = asset.get("overall_status", "NOT_ASSESSED")
            score    = asset.get("overall_score", 0.0)
            inv_rows.append([
                Paragraph(hostname, body),
                Paragraph(os_info, body),
                Paragraph(_status_label(status), body),
                Paragraph(_pct(score), centre),
            ])

    if len(inv_rows) > 1:
        inv_table = Table(inv_rows, colWidths=[7*cm, 4*cm, 4*cm, 2*cm])
        inv_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("LINEBELOW",     (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ]))
        story.append(inv_table)
    else:
        story.append(Paragraph(
            "No assets found. Enrol agents and run a full scan to populate.", body))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # REMEDIATION ACTION PLAN
    # ══════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Appendix B — Remediation Action Plan", h1))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT,
                             spaceAfter=0))
    story.append(Spacer(1, 0.4*cm))

    # Collect all unique remediations from full reports
    all_remediations: list[dict] = []
    seen_remediations: set[str] = set()
    rem_source = full_reports if full_reports else []
    for rep in rem_source:
        for ctrl in rep.controls:
            ctrl_id   = ctrl.control_id
            ctrl_name = ctrl.control_name
            for action in ctrl.remediation:
                key = f"{ctrl_id}|{action}"
                if key not in seen_remediations:
                    seen_remediations.add(key)
                    all_remediations.append({
                        "control":  f"{ctrl_id} — {ctrl_name}",
                        "action":   action,
                        "priority": "HIGH" if ctrl.status == "FAIL" else "MEDIUM",
                    })

    if all_remediations:
        rem_header = [
            Paragraph("<b>Control</b>", body),
            Paragraph("<b>Action Required</b>", body),
            Paragraph("<b>Priority</b>", centre),
        ]
        rem_rows = [rem_header]
        for item in all_remediations:
            pri_col = RED if item["priority"] == "HIGH" else AMBER
            rem_rows.append([
                Paragraph(item["control"], small),
                Paragraph(item["action"], body),
                Paragraph(
                    f'<font color="white"><b>{item["priority"]}</b></font>',
                    ParagraphStyle("pri", fontSize=8, textColor=WHITE,
                                   fontName="Helvetica-Bold", alignment=TA_CENTER)
                ),
            ])

        rem_table = Table(rem_rows, colWidths=[5*cm, 9*cm, 3*cm])
        ts = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("LINEBELOW",     (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ])
        # Colour priority cells
        for i, item in enumerate(all_remediations, start=1):
            col = RED if item["priority"] == "HIGH" else AMBER
            ts.add("BACKGROUND", (2,i), (2,i), col)
        rem_table.setStyle(ts)
        story.append(rem_table)
    else:
        story.append(Paragraph(
            "No remediation actions required — all controls passing.", body))

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"<i>This report was automatically generated by CyberAssetIQ on {date_str}. "
        "It is intended as supporting evidence for Cyber Essentials v3.2 certification "
        "and should be reviewed by a qualified assessor before submission to IASME.</i>",
        small
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()
