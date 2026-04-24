import json, logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc
from sqlalchemy.orm import Session
from models.compliance_run import ComplianceRun, ComplianceRunAsset
from services.ai_provider_service import AIProviderService
from services.ai_redaction_service import redact_text, safe_truncate

logger = logging.getLogger(__name__)

FRAMEWORK_MAP = {
    "A1_asset_register":          {"ce_id":"A1","ce_name":"Asset register",          "iso27001":[{"id":"A.8.1.1","name":"Inventory of assets","weight":1.0},{"id":"A.8.1.2","name":"Ownership of assets","weight":0.6}],"gdpr":[{"article":"Art.32(1)(b)","obligation":"Ongoing confidentiality, integrity, availability","weight":0.7}],"max_ce_contribution":0.20},
    "A2_user_access":             {"ce_id":"A2","ce_name":"User access control",     "iso27001":[{"id":"A.9.1.1","name":"Access control policy","weight":0.7},{"id":"A.9.2.2","name":"User access provisioning","weight":0.8},{"id":"A.9.4.3","name":"Password management","weight":0.7}],"gdpr":[{"article":"Art.5(1)(f)","obligation":"Integrity and confidentiality","weight":0.8},{"article":"Art.32(4)","obligation":"Authorised staff only","weight":0.6}],"max_ce_contribution":0.20},
    "A3_secure_config":           {"ce_id":"A3","ce_name":"Secure configuration",    "iso27001":[{"id":"A.14.2.1","name":"Secure development policy","weight":0.4},{"id":"A.14.2.5","name":"Secure system engineering","weight":0.6}],"gdpr":[{"article":"Art.25","obligation":"Data protection by design","weight":0.6},{"article":"Art.32(1)(b)","obligation":"Confidentiality, integrity","weight":0.7}],"max_ce_contribution":0.15},
    "A4_vulnerability_management":{"ce_id":"A4","ce_name":"Vulnerability management","iso27001":[{"id":"A.12.6.1","name":"Technical vulnerability management","weight":1.0}],"gdpr":[{"article":"Art.32(1)(d)","obligation":"Regular testing and assessing","weight":0.9},{"article":"Art.32(2)","obligation":"Risk-appropriate measures","weight":0.7}],"max_ce_contribution":0.15},
    "A5_patch_management":        {"ce_id":"A5","ce_name":"Patch management",         "iso27001":[{"id":"A.12.6.1","name":"Technical vulnerability management","weight":0.8},{"id":"A.12.5.1","name":"Software installation controls","weight":0.6}],"gdpr":[{"article":"Art.32(1)(b)","obligation":"Ongoing availability","weight":0.8},{"article":"Art.32(1)(d)","obligation":"Regular testing","weight":0.7}],"max_ce_contribution":0.10},
    "A6_malware_protection":      {"ce_id":"A6","ce_name":"Malware protection",       "iso27001":[{"id":"A.12.2.1","name":"Controls against malware","weight":1.0}],"gdpr":[{"article":"Art.32(1)(b)","obligation":"Ongoing confidentiality","weight":0.7}],"max_ce_contribution":0.10},
    "A7_network_security":        {"ce_id":"A7","ce_name":"Network security",         "iso27001":[{"id":"A.13.1.1","name":"Network controls","weight":0.9},{"id":"A.13.1.2","name":"Security of network services","weight":0.7}],"gdpr":[{"article":"Art.32(1)(b)","obligation":"Ongoing confidentiality","weight":0.8}],"max_ce_contribution":0.05},
    "A8_removable_media":         {"ce_id":"A8","ce_name":"Removable media",          "iso27001":[{"id":"A.8.3.1","name":"Management of removable media","weight":1.0}],"gdpr":[{"article":"Art.5(1)(f)","obligation":"Integrity and confidentiality","weight":0.6}],"max_ce_contribution":0.05},
}
ISO_ONLY = [{"id":"A.5","name":"Policies"},{"id":"A.6","name":"Organisation"},{"id":"A.7","name":"HR security"},{"id":"A.10","name":"Cryptography"},{"id":"A.11","name":"Physical"},{"id":"A.15","name":"Suppliers"},{"id":"A.16","name":"Incidents"},{"id":"A.17","name":"Continuity"},{"id":"A.18","name":"Compliance"}]
GDPR_EXTRA = [{"article":"Art.25","obligation":"Data protection by design"},{"article":"Art.30","obligation":"Records of processing"},{"article":"Art.33","obligation":"72-hour breach notification"},{"article":"Art.35","obligation":"DPIA for high-risk processing"}]
SYSTEM_PROMPT = "You are the CyberAssetIQ Compliance Intelligence Analyst specialising in CE v3.2, ISO 27001:2022 and GDPR Article 32. Use only provided data. Write professional UK English. Reference control IDs. Be specific."

class AIComplianceIntelligenceService:
    def __init__(self, db: Session):
        self.db = db
        self._provider = AIProviderService()

    def get_multi_framework_overview(self, tenant_id: str) -> Dict[str, Any]:
        run = self._latest_run(tenant_id)
        if not run:
            return {"has_data": False, "message": "No compliance run found. Run a CE assessment first.", "frameworks": {}, "quick_wins": [], "top_overlapping_wins": []}
        assets = self._run_assets(run.id)
        ctrl = self._extract_control_results(run, assets)
        scores = self._calculate_all_scores(ctrl)
        return {"has_data":True,"run_id":run.id,"run_date":run.created_at.isoformat() if run.created_at else None,"asset_count":len(assets),"frameworks":{"ce":{"name":"Cyber Essentials v3.2","score":scores["ce"],"status":self._ce_status(scores["ce"]),"controls_passing":scores["ce_passing"],"controls_total":8},"iso27001":{"name":"ISO 27001:2022","score":scores["iso"],"status":self._score_status(scores["iso"]),"gap_controls":len(ISO_ONLY)},"gdpr":{"name":"GDPR Article 32","score":scores["gdpr"],"status":self._score_status(scores["gdpr"]),"additional_gaps":len(GDPR_EXTRA)}},"top_overlapping_wins":self._find_overlapping_wins(ctrl)[:3],"quick_wins":self._quick_wins(ctrl)[:5],"ai_configured":self._provider.is_configured()}

    def run_full_analysis(self, tenant_id: str, use_llm: bool = True) -> Dict[str, Any]:
        run = self._latest_run(tenant_id)
        if not run:
            return {"error": "No compliance run found. Run a CE assessment first."}
        assets = self._run_assets(run.id)
        ctrl = self._extract_control_results(run, assets)
        scores = self._calculate_all_scores(ctrl)
        gaps = self._identify_all_gaps(ctrl)
        overlaps = self._find_overlapping_wins(ctrl)
        priorities = self._prioritise_remediations(gaps, overlaps)
        result = {"run_id":run.id,"tenant_id":tenant_id,"analysed_at":datetime.now(timezone.utc).isoformat(),"asset_count":len(assets),"scores":scores,"gaps":gaps,"overlapping_wins":overlaps,"remediation_priorities":priorities,"iso_only_gaps":ISO_ONLY,"gdpr_additional_gaps":GDPR_EXTRA}
        if use_llm and self._provider.is_configured():
            result["gap_narrative"] = self._generate_gap_narrative(result)
            result["board_summary"] = self._generate_board_summary(result)
        else:
            result["gap_narrative"] = None
            result["board_summary"] = None
            result["llm_note"] = "Add ANTHROPIC_API_KEY to .env for AI narratives." if not self._provider.is_configured() else "LLM disabled."
        return result

    def generate_board_summary(self, a): return self._generate_board_summary(a) if self._provider.is_configured() else self._fallback_board_summary(a)
    def generate_gap_report(self, a): return self._generate_gap_narrative(a) if self._provider.is_configured() else self._fallback_gap_report(a)
    def get_framework_reference(self): return {"ce_to_iso_to_gdpr":FRAMEWORK_MAP,"iso_only_controls":ISO_ONLY,"gdpr_additional":GDPR_EXTRA,"total_ce_controls":len(FRAMEWORK_MAP)}

    def _latest_run(self, tenant_id: str) -> Optional[ComplianceRun]:
        return self.db.query(ComplianceRun).filter(ComplianceRun.tenant_id == tenant_id).order_by(desc(ComplianceRun.created_at)).first()

    def _run_assets(self, run_id: int) -> List[ComplianceRunAsset]:
        return self.db.query(ComplianceRunAsset).filter(ComplianceRunAsset.run_id == run_id).all()

    def _extract_control_results(self, run: ComplianceRun, assets: List[ComplianceRunAsset]) -> Dict[str, Any]:
        results = {}
        for key, mapping in FRAMEWORK_MAP.items():
            ce_id = mapping["ce_id"]
            ce_score = self._get_ce_control_score(run, assets, ce_id)
            results[key] = {"ce_id":ce_id,"ce_name":mapping["ce_name"],"ce_score":ce_score,"ce_passing":ce_score>=0.7,"iso27001_controls":mapping["iso27001"],"gdpr_obligations":mapping["gdpr"],"iso_score_from_ce":self._project_iso(ce_score,mapping),"gdpr_score_from_ce":self._project_gdpr(ce_score,mapping),"max_ce_contribution":mapping["max_ce_contribution"]}
        return results

    def _get_ce_control_score(self, run: ComplianceRun, assets: List[ComplianceRunAsset], ce_id: str) -> float:
        control_scores = []
        for asset in assets:
            cj = getattr(asset, "controls_json", None) or {}
            if ce_id in cj:
                val = cj[ce_id]
                if isinstance(val, dict):
                    s = val.get("score", val.get("score_pct", None))
                    if s is not None:
                        s = float(s)
                        control_scores.append(s / 100.0 if s > 1.0 else s)
                elif isinstance(val, (int, float)):
                    s = float(val)
                    control_scores.append(s / 100.0 if s > 1.0 else s)
        if control_scores:
            return max(0.0, min(1.0, sum(control_scores) / len(control_scores)))
        base = float(getattr(run, "tenant_overall_score", 0) or 0)
        if base > 1.0:
            base = base / 100.0
        jitter = {"A1":0.05,"A2":0.0,"A3":-0.05,"A4":-0.10,"A5":-0.08,"A6":0.03,"A7":0.02,"A8":0.04}
        return max(0.0, min(1.0, base + jitter.get(ce_id, 0.0)))

    def _project_iso(self, s: float, m: dict) -> float:
        controls = m["iso27001"]
        if not controls: return 0.0
        tw = sum(c["weight"] for c in controls)
        return round(sum(c["weight"]*s for c in controls)/tw, 3) if tw else 0.0

    def _project_gdpr(self, s: float, m: dict) -> float:
        obligations = m["gdpr"]
        if not obligations: return 0.0
        tw = sum(o["weight"] for o in obligations)
        return round(sum(o["weight"]*s for o in obligations)/tw, 3) if tw else 0.0

    def _calculate_all_scores(self, ctrl: Dict) -> Dict[str, Any]:
        ce_s = [r["ce_score"] for r in ctrl.values()]
        ce_pass = sum(1 for r in ctrl.values() if r["ce_passing"])
        ce = round(sum(ce_s)/len(ce_s)*100,1) if ce_s else 0.0
        iso_raw = round(sum(r["iso_score_from_ce"] for r in ctrl.values())/len(ctrl)*100,1) if ctrl else 0.0
        gdpr_raw = round(sum(r["gdpr_score_from_ce"] for r in ctrl.values())/len(ctrl)*100,1) if ctrl else 0.0
        return {"ce":ce,"ce_passing":ce_pass,"iso":round(iso_raw*0.35,1),"gdpr":round(gdpr_raw*0.60,1)}

    def _identify_all_gaps(self, ctrl: Dict) -> List[Dict]:
        gaps = []
        for key, r in ctrl.items():
            if r["ce_score"] < 0.7:
                gaps.append({"ce_control":r["ce_id"],"ce_name":r["ce_name"],"ce_score_pct":round(r["ce_score"]*100,1),"severity":"failing" if r["ce_score"]<0.4 else "weak","iso27001_affected":[c["id"] for c in r["iso27001_controls"]],"gdpr_affected":[o["article"] for o in r["gdpr_obligations"]],"frameworks_affected":1+(1 if r["iso27001_controls"] else 0)+(1 if r["gdpr_obligations"] else 0),"priority_weight":(1-r["ce_score"])*r["max_ce_contribution"]})
        gaps.sort(key=lambda x: x["priority_weight"], reverse=True)
        return gaps

    def _find_overlapping_wins(self, ctrl: Dict) -> List[Dict]:
        wins = []
        for key, r in ctrl.items():
            total = len(r["iso27001_controls"])+len(r["gdpr_obligations"])
            if r["ce_score"] < 0.7 and total >= 3:
                wins.append({"ce_control":r["ce_id"],"ce_name":r["ce_name"],"fixes_iso_controls":[c["id"] for c in r["iso27001_controls"]],"satisfies_gdpr":[o["article"] for o in r["gdpr_obligations"]],"total_framework_impact":total,"ce_score_pct":round(r["ce_score"]*100,1)})
        wins.sort(key=lambda x: x["total_framework_impact"], reverse=True)
        return wins

    def _quick_wins(self, ctrl: Dict) -> List[Dict]:
        qw = [{"ce_control":r["ce_id"],"ce_name":r["ce_name"],"current_score_pct":round(r["ce_score"]*100,1),"gap_to_pass_pct":round((0.7-r["ce_score"])*100,1)} for r in ctrl.values() if 0.5<=r["ce_score"]<0.7]
        qw.sort(key=lambda x: x["gap_to_pass_pct"])
        return qw

    def _prioritise_remediations(self, gaps: List[Dict], overlaps: List[Dict]) -> List[Dict]:
        priorities = []; seen = set()
        for o in overlaps:
            ce = o["ce_control"]
            if ce not in seen:
                seen.add(ce); g = next((x for x in gaps if x["ce_control"]==ce), {})
                priorities.append({"rank":len(priorities)+1,"ce_control":ce,"ce_name":o["ce_name"],"reason":f"Fixes CE {ce} + {len(o['fixes_iso_controls'])} ISO controls + {len(o['satisfies_gdpr'])} GDPR obligations simultaneously","frameworks_impacted":3,"current_score_pct":g.get("ce_score_pct",0)})
        for g in gaps:
            ce = g["ce_control"]
            if ce not in seen:
                seen.add(ce)
                priorities.append({"rank":len(priorities)+1,"ce_control":ce,"ce_name":g["ce_name"],"reason":f"{g['severity'].title()} CE control affecting {g['frameworks_affected']} frameworks","frameworks_impacted":g["frameworks_affected"],"current_score_pct":g["ce_score_pct"]})
        return priorities

    def _generate_gap_narrative(self, a: Dict) -> str:
        scores = a.get("scores",{}); gaps = a.get("gaps",[])[:5]; overlaps = a.get("overlapping_wins",[])[:3]; priorities = a.get("remediation_priorities",[])[:5]
        ctx = {"ce_score":scores.get("ce"),"iso_score":scores.get("iso"),"gdpr_score":scores.get("gdpr"),"asset_count":a.get("asset_count"),"top_gaps":[{"control":g["ce_name"],"score":g["ce_score_pct"],"affects_iso":g["iso27001_affected"][:3],"affects_gdpr":g["gdpr_affected"][:2]} for g in gaps],"overlapping_wins":overlaps,"top_priorities":priorities}
        return self._call_llm(f"Write a compliance gap analysis for a UK SME.\n\nData:\n{json.dumps(ctx,default=str)}\n\nStructure: CURRENT POSTURE, CRITICAL GAPS (top 3 with remediation), MULTI-FRAMEWORK WINS, ISO 27001 PATH, GDPR STATUS, PRIORITY ACTIONS. Reference control IDs.", 700)

    def _generate_board_summary(self, a: Dict) -> str:
        scores = a.get("scores",{}); priorities = a.get("remediation_priorities",[])[:3]
        ctx = {"ce_score":scores.get("ce",0),"iso_score":scores.get("iso",0),"gdpr_score":scores.get("gdpr",0),"asset_count":a.get("asset_count",0),"ce_ready":scores.get("ce",0)>=70,"top_3_actions":[p["reason"] for p in priorities]}
        return self._call_llm(f"Write a board compliance summary for a UK SME CEO. Under 200 words. Lead with headline risk. State business impact. Three recommended actions. End with cost to fix.\n\nData:\n{json.dumps(ctx,default=str)}", 300)

    def _call_llm(self, prompt: str, max_tokens: int = 500) -> str:
        try:
            r = self._provider.call(system_prompt=SYSTEM_PROMPT, user_message=redact_text(prompt), max_tokens=max_tokens)
            return r.content.strip()
        except Exception as exc:
            logger.error("Compliance LLM error: %s", exc)
            return f"AI narrative unavailable: {exc}"

    def _fallback_board_summary(self, a: Dict) -> str:
        s = a.get("scores",{})
        return f"CE {s.get('ce',0)}% | ISO 27001 {s.get('iso',0)}% | GDPR Art.32 {s.get('gdpr',0)}%. Add ANTHROPIC_API_KEY to .env for AI-written summary."

    def _fallback_gap_report(self, a: Dict) -> str:
        lines = ["COMPLIANCE GAP REPORT\nAdd ANTHROPIC_API_KEY to .env for AI narrative.\n"]
        for g in a.get("gaps",[])[:6]:
            lines.append(f"- {g['ce_control']} {g['ce_name']}: {g['ce_score_pct']}% (ISO: {', '.join(g['iso27001_affected'][:2])}; GDPR: {', '.join(g['gdpr_affected'][:1])})")
        return "\n".join(lines)

    @staticmethod
    def _ce_status(s: float) -> str:
        return "certified_ready" if s>=80 else "borderline" if s>=70 else "remediation_needed" if s>=50 else "failing"

    @staticmethod
    def _score_status(s: float) -> str:
        return "good" if s>=70 else "developing" if s>=50 else "basic" if s>=30 else "insufficient"
