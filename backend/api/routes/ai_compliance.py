from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from services.ai_compliance_intelligence_service import AIComplianceIntelligenceService

router = APIRouter(prefix="/api/ai/compliance", tags=["AI Compliance Intelligence"])
DEFAULT_TENANT = "tenant-001"

class AnalyseRequest(BaseModel):
    tenant_id: Optional[str] = DEFAULT_TENANT
    use_llm: Optional[bool] = True

class NarrativeRequest(BaseModel):
    tenant_id: Optional[str] = DEFAULT_TENANT

@router.get("/overview")
def get_compliance_overview(tenant_id: str = Query(DEFAULT_TENANT), db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    return svc.get_multi_framework_overview(tenant_id=tenant_id)

@router.post("/analyse")
def run_compliance_analysis(payload: AnalyseRequest, db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    result = svc.run_full_analysis(tenant_id=payload.tenant_id or DEFAULT_TENANT, use_llm=payload.use_llm if payload.use_llm is not None else True)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/board-summary")
def get_board_summary(payload: NarrativeRequest, db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    analysis = svc.run_full_analysis(tenant_id=payload.tenant_id or DEFAULT_TENANT, use_llm=False)
    if "error" in analysis:
        raise HTTPException(status_code=404, detail=analysis["error"])
    return {"board_summary": svc.generate_board_summary(analysis), "scores": analysis.get("scores"), "tenant_id": payload.tenant_id}

@router.post("/gap-report")
def get_gap_report(payload: NarrativeRequest, db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    analysis = svc.run_full_analysis(tenant_id=payload.tenant_id or DEFAULT_TENANT, use_llm=False)
    if "error" in analysis:
        raise HTTPException(status_code=404, detail=analysis["error"])
    return {"gap_report": svc.generate_gap_report(analysis), "gaps": analysis.get("gaps", []), "remediation_priorities": analysis.get("remediation_priorities", []), "tenant_id": payload.tenant_id}

@router.get("/frameworks")
def get_framework_reference(db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    return svc.get_framework_reference()


import re
import io as _io
from datetime import datetime as _dt
from fastapi.responses import StreamingResponse as _SR
from reportlab.lib.pagesizes import A4 as _A4
from reportlab.lib.styles import getSampleStyleSheet as _gss, ParagraphStyle as _PS
from reportlab.lib.units import mm as _mm
from reportlab.lib import colors as _colors
from reportlab.platypus import (
    SimpleDocTemplate as _SDT, Paragraph as _Para, Spacer as _Sp,
    HRFlowable as _HR, Table as _Tbl, TableStyle as _TS
)

_BRAND  = _colors.HexColor("#1a3a5c")
_ACCENT = _colors.HexColor("#2980b9")
_GREEN  = _colors.HexColor("#27ae60")
_AMBER  = _colors.HexColor("#f39c12")
_RED    = _colors.HexColor("#e74c3c")
_LGRAY  = _colors.HexColor("#f4f6f9")
_DGRAY  = _colors.HexColor("#555555")

def _sc(s):
    if s is None: return _DGRAY
    if s >= 80: return _GREEN
    if s >= 50: return _AMBER
    return _RED

def _build_pdf(board_summary, scores, tenant_id):
    buf = _io.BytesIO()
    doc = _SDT(buf, pagesize=_A4,
               leftMargin=20*_mm, rightMargin=20*_mm,
               topMargin=20*_mm, bottomMargin=20*_mm)
    st = _gss()
    T  = lambda n,**k: _PS(n, parent=st["Normal"], **k)
    title_s  = T("ct", fontSize=22, textColor=_BRAND,  spaceAfter=10, leading=28, fontName="Helvetica-Bold")
    sub_s    = T("cs", fontSize=10, textColor=_DGRAY,  spaceAfter=2,  fontName="Helvetica")
    h2_s     = T("ch", fontSize=13, textColor=_BRAND,  spaceBefore=10,spaceAfter=4, fontName="Helvetica-Bold")
    body_s   = T("cb", fontSize=10, textColor=_colors.black, leading=16, spaceAfter=6, fontName="Helvetica")
    foot_s   = T("cf", fontSize=8,  textColor=_DGRAY,  alignment=1,   fontName="Helvetica-Oblique")
    story = []
    story.append(_Para("CyberAssetIQ", title_s))
    story.append(_Para("Executive Board Security Report", sub_s))
    story.append(_Para(
        f"Tenant: {tenant_id}  |  Generated: {_dt.utcnow().strftime('%d %B %Y %H:%M')} UTC", sub_s))
    story.append(_HR(width="100%", thickness=2, color=_ACCENT, spaceAfter=10))
    if scores:
        story.append(_Para("Compliance Score Overview", h2_s))
        rows = [["Framework","Score","Status"]]
        for fw, sc in scores.items():
            if sc is None:   st2,col = "No Data",   _DGRAY
            elif sc >= 80:   st2,col = "Compliant",  _GREEN
            elif sc >= 50:   st2,col = "Partial",    _AMBER
            else:            st2,col = "Non-Compliant", _RED
            rows.append([fw.upper().replace("_"," "), f"{sc}%" if sc is not None else "N/A", st2])
        tbl = _Tbl(rows, colWidths=[90*_mm,40*_mm,50*_mm])
        tbl.setStyle(_TS([
            ("BACKGROUND",(0,0),(-1,0),_BRAND),
            ("TEXTCOLOR",(0,0),(-1,0),_colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),10),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[_colors.white,_LGRAY]),
            ("GRID",(0,0),(-1,-1),0.5,_colors.HexColor("#dddddd")),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ("ALIGN",(1,1),(2,-1),"CENTER"),
        ]))
        for i,(fw,sc) in enumerate(scores.items(),1):
            tbl.setStyle(_TS([("TEXTCOLOR",(2,i),(2,i),_sc(sc))]))
        story.append(tbl)
        story.append(_Sp(1,10))
    story.append(_Para("Board Summary", h2_s))
    story.append(_HR(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=6))
    for line in board_summary.splitlines():
        s = line.strip()
        if not s: story.append(_Sp(1,4)); continue
        if s.isupper() or (s.endswith(":") and len(s)<60):
            story.append(_Para(s, h2_s))
        else:
            safe = s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            # convert **bold** markdown to reportlab <b> tags
            safe = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', safe)
            story.append(_Para(safe, body_s))
    story.append(_Sp(1,16))
    story.append(_HR(width="100%", thickness=0.5, color=_DGRAY))
    story.append(_Sp(1,4))
    story.append(_Para(
        "CONFIDENTIAL - For Board Use Only  |  Generated by CyberAssetIQ  |  TotalIT Solutions Limited",
        foot_s))
    doc.build(story)
    buf.seek(0)
    return buf.read()


@router.get("/board-summary/pdf")
def download_board_summary_pdf(
    tenant_id: str = Query(DEFAULT_TENANT),
    db: Session = Depends(get_db),
):
    svc = AIComplianceIntelligenceService(db=db)
    analysis = svc.run_full_analysis(tenant_id=tenant_id, use_llm=False)
    if "error" in analysis:
        raise HTTPException(status_code=404, detail=analysis["error"])
    board_text = svc.generate_board_summary(analysis)
    scores     = analysis.get("scores", {})
    pdf_bytes  = _build_pdf(board_text, scores, tenant_id)
    filename   = f"CyberAssetIQ_BoardReport_{_dt.utcnow().strftime('%Y%m%d')}.pdf"
    return _SR(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



@router.get("/quick-wins")
def get_quick_wins(tenant_id: str = Query(DEFAULT_TENANT), db: Session = Depends(get_db)):
    svc = AIComplianceIntelligenceService(db=db)
    overview = svc.get_multi_framework_overview(tenant_id=tenant_id)
    return {"quick_wins": overview.get("quick_wins", []), "top_overlapping_wins": overview.get("top_overlapping_wins", [])}
