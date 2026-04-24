"""blast_radius_service.py

Simulates the potential spread of a compromise starting from a given asset.
Uses the attack graph edges to perform a weighted BFS and identify all
reachable assets within N hops, scoring them by criticality.

Reads from: attack_graph_nodes, attack_graph_edges, asset_criticality_profiles,
            crown_jewel_assets, canonical_assets.
Writes to:  blast_radius_results, ransomware_scenarios.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.blast_radius import BlastRadiusResult, RansomwareScenario

logger = logging.getLogger("cyberassetiq.blast_radius")

MAX_HOPS = 4          # Maximum lateral movement hops to simulate
TOP_RISKY_ASSETS = 20 # How many high-spread assets to pre-compute


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_blast_radius_summary(db: Session, tenant_id: str) -> dict:
    """Return top 5 highest-spread assets and tenant-level stats."""
    results = (
        db.query(BlastRadiusResult)
        .filter(BlastRadiusResult.tenant_id == tenant_id)
        .order_by(BlastRadiusResult.estimated_spread_score.desc())
        .limit(5)
        .all()
    )
    total_simulated = db.query(BlastRadiusResult).filter(
        BlastRadiusResult.tenant_id == tenant_id
    ).count()

    top = []
    for r in results:
        asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == r.source_asset_id).first()
        top.append({
            "asset_id": r.source_asset_id,
            "hostname": asset.hostname if asset else None,
            "impacted_count": r.impacted_asset_count,
            "critical_impacted": r.impacted_critical_count,
            "spread_score": r.estimated_spread_score,
        })

    return {
        "assets_simulated": total_simulated,
        "top_spread_assets": top,
    }


def get_asset_blast_radius(db: Session, tenant_id: str, asset_id: int) -> dict:
    """Return the latest blast radius simulation for a specific asset."""
    result = (
        db.query(BlastRadiusResult)
        .filter(
            BlastRadiusResult.tenant_id == tenant_id,
            BlastRadiusResult.source_asset_id == asset_id,
        )
        .order_by(BlastRadiusResult.computed_at.desc())
        .first()
    )
    if not result:
        return {"asset_id": asset_id, "simulated": False}

    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == asset_id).first()
    scenarios = db.query(RansomwareScenario).filter(
        RansomwareScenario.tenant_id == tenant_id,
        RansomwareScenario.source_asset_id == asset_id,
    ).all()

    return {
        "asset_id": asset_id,
        "hostname": asset.hostname if asset else None,
        "simulated": True,
        "impacted_assets": result.impacted_assets_json or [],
        "impacted_count": result.impacted_asset_count,
        "critical_impacted": result.impacted_critical_count,
        "spread_score": result.estimated_spread_score,
        "computed_at": result.computed_at.isoformat() if result.computed_at else None,
        "ransomware_scenarios": [_scenario_to_dict(s) for s in scenarios],
    }


def simulate(db: Session, tenant_id: str, asset_id: int) -> dict:
    """Run blast radius simulation for a specific asset and persist result."""
    adj = _build_adjacency(db, tenant_id)
    node_id = _get_node_id(db, tenant_id, asset_id)
    if node_id is None:
        return {"error": "asset_not_in_graph", "asset_id": asset_id}

    reachable = _bfs_reachable(node_id, adj, max_hops=MAX_HOPS)
    impacted = _score_reachable(db, tenant_id, reachable, asset_id)

    critical_count = sum(1 for a in impacted if a.get("criticality_score", 0) >= 70)
    spread_score = _spread_score(impacted, critical_count)

    # Upsert result
    existing = db.query(BlastRadiusResult).filter(
        BlastRadiusResult.tenant_id == tenant_id,
        BlastRadiusResult.source_asset_id == asset_id,
    ).first()

    if existing:
        existing.impacted_assets_json = impacted
        existing.impacted_asset_count = len(impacted)
        existing.impacted_critical_count = critical_count
        existing.estimated_spread_score = spread_score
        from sqlalchemy.sql import func
        existing.computed_at = func.now()
    else:
        db.add(BlastRadiusResult(
            tenant_id=tenant_id,
            source_asset_id=asset_id,
            impacted_assets_json=impacted,
            impacted_asset_count=len(impacted),
            impacted_critical_count=critical_count,
            estimated_spread_score=spread_score,
        ))

    # Add ransomware scenario if crown jewels are reachable
    crown_hits = [a for a in impacted if a.get("is_crown_jewel")]
    if crown_hits:
        _persist_ransomware_scenario(db, tenant_id, asset_id, impacted, crown_hits)

    db.commit()
    return {
        "asset_id": asset_id,
        "impacted_count": len(impacted),
        "critical_impacted": critical_count,
        "spread_score": spread_score,
        "crown_jewels_reachable": len(crown_hits),
    }


def simulate_all(db: Session, tenant_id: str) -> dict:
    """Run blast radius simulation for the highest-criticality assets."""
    try:
        from models.criticality import AssetCriticalityProfile
        top_assets = (
            db.query(AssetCriticalityProfile)
            .filter(AssetCriticalityProfile.tenant_id == tenant_id)
            .order_by(AssetCriticalityProfile.criticality_score.desc())
            .limit(TOP_RISKY_ASSETS)
            .all()
        )
        asset_ids = [a.asset_id for a in top_assets]
    except Exception:
        # Fallback: take all assets
        assets = db.query(CanonicalAsset).filter(
            CanonicalAsset.tenant_id == tenant_id
        ).limit(TOP_RISKY_ASSETS).all()
        asset_ids = [a.id for a in assets]

    simulated = 0
    for asset_id in asset_ids:
        try:
            simulate(db, tenant_id, asset_id)
            simulated += 1
        except Exception as exc:
            logger.warning("Blast radius simulation failed for asset %d: %s", asset_id, exc)

    return {"assets_simulated": simulated}


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _build_adjacency(db: Session, tenant_id: str) -> dict[int, list[tuple[int, float]]]:
    """Load attack graph edges into an adjacency dict {node_id: [(neighbour, weight)]}."""
    try:
        from models.attack_graph import AttackGraphEdge
        edges = db.query(AttackGraphEdge).filter(
            AttackGraphEdge.tenant_id == tenant_id
        ).all()
        adj: dict[int, list[tuple[int, float]]] = defaultdict(list)
        for e in edges:
            adj[e.source_node_id].append((e.target_node_id, e.weight))
        return adj
    except Exception as e:
        logger.warning("Could not load attack graph edges: %s", e)
        return {}


def _get_node_id(db: Session, tenant_id: str, asset_id: int) -> int | None:
    try:
        from models.attack_graph import AttackGraphNode
        node = db.query(AttackGraphNode).filter(
            AttackGraphNode.tenant_id == tenant_id,
            AttackGraphNode.asset_id == asset_id,
        ).first()
        return node.id if node else None
    except Exception:
        return None


def _bfs_reachable(
    start_node_id: int,
    adj: dict[int, list[tuple[int, float]]],
    max_hops: int = MAX_HOPS,
) -> list[tuple[int, int, float]]:
    """BFS returning [(node_id, hop_distance, cumulative_weight)]."""
    visited = {start_node_id}
    queue: deque[tuple[int, int, float]] = deque([(start_node_id, 0, 0.0)])
    reachable: list[tuple[int, int, float]] = []

    while queue:
        node_id, hops, weight = queue.popleft()
        if hops >= max_hops:
            continue
        for neighbour, edge_weight in adj.get(node_id, []):
            if neighbour not in visited:
                visited.add(neighbour)
                new_weight = weight + edge_weight
                reachable.append((neighbour, hops + 1, new_weight))
                queue.append((neighbour, hops + 1, new_weight))

    return reachable


def _score_reachable(
    db: Session,
    tenant_id: str,
    reachable: list[tuple[int, int, float]],
    source_asset_id: int,
) -> list[dict]:
    """Convert node_id hits to asset dicts with criticality info."""
    if not reachable:
        return []

    # Load node → asset mapping
    try:
        from models.attack_graph import AttackGraphNode
        node_ids = [r[0] for r in reachable]
        nodes = db.query(AttackGraphNode).filter(
            AttackGraphNode.id.in_(node_ids),
            AttackGraphNode.asset_id.isnot(None),
        ).all()
        node_asset_map = {n.id: n.asset_id for n in nodes}
    except Exception:
        return []

    # Load criticality
    crit_map: dict[int, int] = {}
    crown_ids: set[int] = set()
    try:
        from models.criticality import AssetCriticalityProfile, CrownJewelAsset
        for cp in db.query(AssetCriticalityProfile).filter(
            AssetCriticalityProfile.tenant_id == tenant_id
        ).all():
            crit_map[cp.asset_id] = cp.criticality_score
        crown_ids = {
            cj.asset_id for cj in db.query(CrownJewelAsset).filter(
                CrownJewelAsset.tenant_id == tenant_id
            ).all()
        }
    except Exception:
        pass

    result = []
    seen_assets: set[int] = {source_asset_id}

    for node_id, hop, weight in reachable:
        asset_id = node_asset_map.get(node_id)
        if not asset_id or asset_id in seen_assets:
            continue
        seen_assets.add(asset_id)

        asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == asset_id).first()
        result.append({
            "asset_id": asset_id,
            "hostname": asset.hostname if asset else None,
            "hop_distance": hop,
            "reach_weight": round(weight, 2),
            "criticality_score": crit_map.get(asset_id, 0),
            "is_crown_jewel": asset_id in crown_ids,
        })

    return sorted(result, key=lambda x: (-x["criticality_score"], x["hop_distance"]))


def _spread_score(impacted: list[dict], critical_count: int) -> float:
    """0-100 score: how dangerous this asset is as an attack starting point."""
    if not impacted:
        return 0.0
    base = min(50, len(impacted) * 2)
    crit_bonus = min(50, critical_count * 10)
    return round(base + crit_bonus, 1)


def _persist_ransomware_scenario(
    db: Session,
    tenant_id: str,
    source_asset_id: int,
    impacted: list[dict],
    crown_hits: list[dict],
) -> None:
    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == source_asset_id).first()
    name = f"Ransomware from {asset.hostname if asset else source_asset_id}"

    # Rough recovery estimate: 1 day per critical asset + 0.5 per other
    critical_count = len(crown_hits)
    recovery_days = critical_count * 1 + (len(impacted) - critical_count) * 0.5

    existing = db.query(RansomwareScenario).filter(
        RansomwareScenario.tenant_id == tenant_id,
        RansomwareScenario.source_asset_id == source_asset_id,
    ).first()
    scenario_data = {
        "total_impacted": len(impacted),
        "crown_jewels_hit": [c["hostname"] or c["asset_id"] for c in crown_hits],
        "estimated_recovery_days": round(recovery_days, 1),
        "spread_path": [a["hostname"] or a["asset_id"] for a in impacted[:10]],
    }
    if existing:
        existing.scenario_result_json = scenario_data
        existing.scenario_name = name
    else:
        db.add(RansomwareScenario(
            tenant_id=tenant_id,
            source_asset_id=source_asset_id,
            scenario_name=name,
            scenario_result_json=scenario_data,
        ))


def _scenario_to_dict(s: RansomwareScenario) -> dict:
    return {
        "id": s.id,
        "scenario_name": s.scenario_name,
        "result": s.scenario_result_json,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
