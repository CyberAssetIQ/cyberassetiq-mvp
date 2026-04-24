"""attack_graph_service.py

Builds a directed attack graph from existing asset, network, identity,
vulnerability, and dark-web data. Computes attack paths to crown jewels.

Reads from: canonical_assets, network_discovered_assets, exposure_findings,
            attack_path_findings (existing), crown_jewel_assets, darkweb_findings,
            canonical_software, security_posture_events.
Writes to:  attack_graph_nodes, attack_graph_edges, attack_paths,
            identity_relationships, credential_exposure_links  (all new).
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CredentialExposureLink,
    IdentityRelationship,
)
from models.criticality import CrownJewelAsset

logger = logging.getLogger("cyberassetiq.attack_graph")

# Ports that represent reachable attack vectors
_SMB_PORTS = {445, 139}
_RDP_PORTS = {3389}
_SSH_PORTS = {22}
_WINRM_PORTS = {5985, 5986}
_ADMIN_PORTS = _RDP_PORTS | _WINRM_PORTS | _SSH_PORTS


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_attack_graph_summary(db: Session, tenant_id: str) -> dict:
    node_count = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id
    ).count()
    edge_count = db.query(AttackGraphEdge).filter(
        AttackGraphEdge.tenant_id == tenant_id
    ).count()
    path_count = db.query(AttackPath).filter(
        AttackPath.tenant_id == tenant_id,
        AttackPath.status == "active",
    ).count()
    high_risk_paths = db.query(AttackPath).filter(
        AttackPath.tenant_id == tenant_id,
        AttackPath.status == "active",
        AttackPath.risk_score >= 7.0,
    ).count()

    return {
        "nodes": node_count,
        "edges": edge_count,
        "active_paths": path_count,
        "high_risk_paths": high_risk_paths,
    }


def get_attack_paths(
    db: Session,
    tenant_id: str,
    min_risk: float = 0.0,
    limit: int = 50,
) -> list[dict]:
    paths = (
        db.query(AttackPath)
        .filter(
            AttackPath.tenant_id == tenant_id,
            AttackPath.status == "active",
            AttackPath.risk_score >= min_risk,
        )
        .order_by(AttackPath.risk_score.desc())
        .limit(limit)
        .all()
    )
    return [_path_to_dict(p, db) for p in paths]


def get_asset_attack_routes(db: Session, tenant_id: str, asset_id: int) -> dict:
    """All paths that start from or pass through a given asset."""
    node = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id,
        AttackGraphNode.asset_id == asset_id,
    ).first()

    if not node:
        return {"asset_id": asset_id, "paths_from": [], "paths_to": [], "edges": []}

    paths_from = (
        db.query(AttackPath)
        .filter(
            AttackPath.tenant_id == tenant_id,
            AttackPath.start_node_id == node.id,
        )
        .order_by(AttackPath.risk_score.desc())
        .limit(20)
        .all()
    )
    paths_to = (
        db.query(AttackPath)
        .filter(
            AttackPath.tenant_id == tenant_id,
            AttackPath.target_node_id == node.id,
        )
        .order_by(AttackPath.risk_score.desc())
        .limit(20)
        .all()
    )
    edges_out = db.query(AttackGraphEdge).filter(
        AttackGraphEdge.tenant_id == tenant_id,
        AttackGraphEdge.source_node_id == node.id,
    ).all()
    edges_in = db.query(AttackGraphEdge).filter(
        AttackGraphEdge.tenant_id == tenant_id,
        AttackGraphEdge.target_node_id == node.id,
    ).all()

    return {
        "asset_id": asset_id,
        "node_id": node.id,
        "paths_from": [_path_to_dict(p, db) for p in paths_from],
        "paths_to": [_path_to_dict(p, db) for p in paths_to],
        "edges_out": [_edge_to_dict(e, db) for e in edges_out],
        "edges_in": [_edge_to_dict(e, db) for e in edges_in],
    }


def get_crown_jewel_paths(db: Session, tenant_id: str) -> list[dict]:
    """All active paths that terminate at a crown jewel asset."""
    crown_jewels = db.query(CrownJewelAsset).filter(
        CrownJewelAsset.tenant_id == tenant_id
    ).all()
    if not crown_jewels:
        return []

    crown_jewel_asset_ids = {cj.asset_id for cj in crown_jewels}
    crown_nodes = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id,
        AttackGraphNode.asset_id.in_(list(crown_jewel_asset_ids)),
    ).all()
    crown_node_ids = [n.id for n in crown_nodes]

    if not crown_node_ids:
        return []

    paths = (
        db.query(AttackPath)
        .filter(
            AttackPath.tenant_id == tenant_id,
            AttackPath.target_node_id.in_(crown_node_ids),
            AttackPath.status == "active",
        )
        .order_by(AttackPath.risk_score.desc())
        .limit(50)
        .all()
    )
    return [_path_to_dict(p, db) for p in paths]


def get_graph_data(db: Session, tenant_id: str) -> dict:
    """Return nodes + edges for frontend graph rendering."""
    nodes = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id
    ).limit(200).all()
    edges = db.query(AttackGraphEdge).filter(
        AttackGraphEdge.tenant_id == tenant_id
    ).limit(500).all()

    crown_asset_ids = {
        cj.asset_id for cj in db.query(CrownJewelAsset).filter(
            CrownJewelAsset.tenant_id == tenant_id
        ).all()
    }

    return {
        "nodes": [_node_to_dict(n, crown_asset_ids) for n in nodes],
        "edges": [{"id": e.id, "source": e.source_node_id, "target": e.target_node_id,
                   "type": e.edge_type, "weight": e.weight} for e in edges],
    }


def rebuild_graph(db: Session, tenant_id: str) -> dict:
    """Full graph rebuild — delete existing graph for tenant, reconstruct from scratch."""
    # Purge existing graph data for tenant
    db.query(AttackPath).filter(AttackPath.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(AttackGraphEdge).filter(AttackGraphEdge.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(AttackGraphNode).filter(AttackGraphNode.tenant_id == tenant_id).delete(synchronize_session=False)
    db.commit()

    # Rebuild
    node_map = _build_nodes(db, tenant_id)
    edge_count = _build_edges(db, tenant_id, node_map)
    path_count = _compute_paths(db, tenant_id, node_map)
    _link_credentials(db, tenant_id)

    return {
        "nodes": len(node_map),
        "edges": edge_count,
        "paths": path_count,
    }


# ---------------------------------------------------------------------------
# Internal: graph construction
# ---------------------------------------------------------------------------

def _build_nodes(db: Session, tenant_id: str) -> dict[int, int]:
    """Create AttackGraphNode rows for all assets. Returns {asset_id: node_id}."""
    assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    crown_ids = {
        cj.asset_id for cj in db.query(CrownJewelAsset).filter(
            CrownJewelAsset.tenant_id == tenant_id
        ).all()
    }

    # Internet entry-point node
    internet_node = AttackGraphNode(
        tenant_id=tenant_id,
        node_type="internet",
        label="Internet",
        node_metadata_json={},
    )
    db.add(internet_node)
    db.flush()

    asset_node_map: dict[int, int] = {}
    for asset in assets:
        node_type = "crown_jewel" if asset.id in crown_ids else "asset"
        meta = asset.raw_metadata_json or {}
        node = AttackGraphNode(
            tenant_id=tenant_id,
            node_type=node_type,
            asset_id=asset.id,
            label=asset.hostname or asset.agent_id or f"asset-{asset.id}",
            node_metadata_json={
                "os": asset.os_family,
                "ips": asset.ips,
                "is_exposed": bool(meta.get("is_internet_exposed")),
            },
        )
        db.add(node)
        db.flush()
        asset_node_map[asset.id] = node.id

    # Identity nodes from local admin data
    identities: set[str] = set()
    for asset in assets:
        sec = asset.security_posture_json or {}
        for admin in sec.get("local_admins", []):
            if admin and admin not in identities:
                identities.add(admin)
                id_node = AttackGraphNode(
                    tenant_id=tenant_id,
                    node_type="identity",
                    identity_name=admin,
                    label=admin,
                    node_metadata_json={"type": "local_admin"},
                )
                db.add(id_node)

    db.commit()
    return asset_node_map


def _build_edges(db: Session, tenant_id: str, asset_node_map: dict[int, int]) -> int:
    """Build edges between nodes based on network reachability and admin relationships."""
    assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    asset_lookup = {a.id: a for a in assets}
    edge_count = 0

    # Internet node id
    internet_node = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id,
        AttackGraphNode.node_type == "internet",
    ).first()

    for asset in assets:
        meta = asset.raw_metadata_json or {}
        open_ports = set(meta.get("open_ports", []))
        is_exposed = bool(meta.get("is_internet_exposed"))
        src_node_id = asset_node_map.get(asset.id)
        if not src_node_id:
            continue

        # Internet → exposed asset edge
        if is_exposed and internet_node:
            edge = AttackGraphEdge(
                tenant_id=tenant_id,
                source_node_id=internet_node.id,
                target_node_id=src_node_id,
                edge_type="exposed_service",
                weight=2.5,
                evidence_json={"ports": list(open_ports)[:10]},
            )
            db.add(edge)
            edge_count += 1

        # Asset → asset edges based on shared subnet / protocol reachability
        src_ips = set(asset.ips or [])
        for target_id, tgt_node_id in asset_node_map.items():
            if target_id == asset.id:
                continue
            target_asset = asset_lookup.get(target_id)
            if not target_asset:
                continue
            tgt_meta = target_asset.raw_metadata_json or {}
            tgt_ports = set(tgt_meta.get("open_ports", []))

            # Same subnet heuristic: first 3 octets match
            tgt_ips = set(target_asset.ips or [])
            same_subnet = _shares_subnet(src_ips, tgt_ips)
            if not same_subnet:
                continue

            # SMB lateral movement
            if _RDP_PORTS & tgt_ports:
                db.add(AttackGraphEdge(
                    tenant_id=tenant_id,
                    source_node_id=src_node_id,
                    target_node_id=tgt_node_id,
                    edge_type="rdp_reachable",
                    weight=1.8,
                    evidence_json={"port": 3389},
                ))
                edge_count += 1

            if _SMB_PORTS & tgt_ports:
                db.add(AttackGraphEdge(
                    tenant_id=tenant_id,
                    source_node_id=src_node_id,
                    target_node_id=tgt_node_id,
                    edge_type="smb_reachable",
                    weight=1.5,
                    evidence_json={"ports": list(_SMB_PORTS & tgt_ports)},
                ))
                edge_count += 1

        # Shared admin identity edges
        sec = asset.security_posture_json or {}
        admins = sec.get("local_admins", [])
        if admins:
            # Find any other asset sharing the same admin
            for target_id, target_asset in asset_lookup.items():
                if target_id == asset.id:
                    continue
                tgt_sec = target_asset.security_posture_json or {}
                tgt_admins = set(tgt_sec.get("local_admins", []))
                shared = set(admins) & tgt_admins
                if shared:
                    tgt_node_id = asset_node_map.get(target_id)
                    if tgt_node_id:
                        db.add(AttackGraphEdge(
                            tenant_id=tenant_id,
                            source_node_id=src_node_id,
                            target_node_id=tgt_node_id,
                            edge_type="shared_credential",
                            weight=2.0,
                            evidence_json={"shared_admins": list(shared)[:5]},
                        ))
                        edge_count += 1

    db.commit()
    return edge_count


def _compute_paths(db: Session, tenant_id: str, asset_node_map: dict[int, int]) -> int:
    """BFS from internet node to all crown jewel nodes. Stores shortest paths."""
    internet_node = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id,
        AttackGraphNode.node_type == "internet",
    ).first()
    if not internet_node:
        return 0

    crown_nodes = db.query(AttackGraphNode).filter(
        AttackGraphNode.tenant_id == tenant_id,
        AttackGraphNode.node_type.in_(["crown_jewel"]),
    ).all()
    if not crown_nodes:
        return 0

    # Build adjacency map from edges
    edges = db.query(AttackGraphEdge).filter(
        AttackGraphEdge.tenant_id == tenant_id
    ).all()

    adj: dict[int, list[tuple[int, float, str]]] = defaultdict(list)
    for e in edges:
        adj[e.source_node_id].append((e.target_node_id, e.weight, e.edge_type))

    path_count = 0
    for crown_node in crown_nodes:
        path = _bfs_shortest_path(internet_node.id, crown_node.id, adj)
        if path and len(path) > 1:
            risk = _score_path(path, adj)
        else:
            # Direct baseline path: Internet -> Crown Jewel
            # Represents the fundamental threat that any networked device
            # can be targeted from the internet regardless of known open ports
            path = [internet_node.id, crown_node.id]
            risk = 5.0
            existing_edge = db.query(AttackGraphEdge).filter(
                AttackGraphEdge.tenant_id == tenant_id,
                AttackGraphEdge.source_node_id == internet_node.id,
                AttackGraphEdge.target_node_id == crown_node.id,
            ).first()
            if not existing_edge:
                db.add(AttackGraphEdge(
                    tenant_id=tenant_id,
                    source_node_id=internet_node.id,
                    target_node_id=crown_node.id,
                    edge_type="potential_exposure",
                    weight=2.0,
                    evidence_json={"note": "Crown jewel reachable from internet — baseline threat path"},
                ))
                db.flush()
        ap = AttackPath(
            tenant_id=tenant_id,
            start_node_id=internet_node.id,
            target_node_id=crown_node.id,
            path_json=path,
            risk_score=risk,
            hop_count=len(path) - 1,
            status="active",
        )
        db.add(ap)
        path_count += 1

    # Also compute paths between high-criticality asset nodes
    try:
        from models.criticality import AssetCriticalityProfile
        high_crit = db.query(AssetCriticalityProfile).filter(
            AssetCriticalityProfile.tenant_id == tenant_id,
            AssetCriticalityProfile.criticality_score >= 70,
        ).all()
        high_crit_asset_ids = {p.asset_id for p in high_crit}

        all_asset_nodes = db.query(AttackGraphNode).filter(
            AttackGraphNode.tenant_id == tenant_id,
            AttackGraphNode.node_type.in_(["asset", "crown_jewel"]),
        ).all()

        exposed_nodes = [
            n for n in all_asset_nodes
            if n.node_metadata_json and n.node_metadata_json.get("is_exposed")
        ]

        for start_node in exposed_nodes[:10]:  # Cap to avoid combinatorial explosion
            for target_node in crown_nodes:
                if start_node.id == target_node.id:
                    continue
                path = _bfs_shortest_path(start_node.id, target_node.id, adj)
                if path and len(path) > 1:
                    risk = _score_path(path, adj)
                    ap = AttackPath(
                        tenant_id=tenant_id,
                        start_node_id=start_node.id,
                        target_node_id=target_node.id,
                        path_json=path,
                        risk_score=risk,
                        hop_count=len(path) - 1,
                        status="active",
                    )
                    db.add(ap)
                    path_count += 1
    except Exception as e:
        logger.warning("Extended path computation skipped: %s", e)

    db.commit()
    return path_count


def _link_credentials(db: Session, tenant_id: str) -> None:
    """Link dark-web credential findings to assets via CredentialExposureLink."""
    try:
        from models.darkweb import DarkWebFinding
        findings = db.query(DarkWebFinding).filter(
            DarkWebFinding.tenant_id == tenant_id,
            DarkWebFinding.finding_type.in_(["credential", "password", "email_password"]),
        ).all()

        assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
        domain_asset_map: dict[str, int] = {}
        for a in assets:
            if a.domain:
                domain_asset_map[a.domain.lower()] = a.id

        for finding in findings:
            identity = getattr(finding, "email", None) or getattr(finding, "username", None) or "unknown"
            asset_id = None
            # Try to match domain
            source_domain = getattr(finding, "source_domain", None) or ""
            for domain, aid in domain_asset_map.items():
                if domain in source_domain.lower():
                    asset_id = aid
                    break

            existing = db.query(CredentialExposureLink).filter(
                CredentialExposureLink.tenant_id == tenant_id,
                CredentialExposureLink.identity_name == str(identity),
            ).first()
            if not existing:
                db.add(CredentialExposureLink(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    identity_name=str(identity),
                    secret_type="password",
                    source="dark_web",
                    risk_level="high",
                ))
        db.commit()
    except Exception as e:
        logger.warning("Credential linking skipped: %s", e)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _bfs_shortest_path(
    start: int, end: int, adj: dict[int, list[tuple[int, float, str]]]
) -> list[int] | None:
    if start == end:
        return [start]
    visited = {start}
    queue: deque[list[int]] = deque([[start]])
    while queue:
        path = queue.popleft()
        node = path[-1]
        for neighbour, _, _ in adj.get(node, []):
            if neighbour == end:
                return path + [neighbour]
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append(path + [neighbour])
    return None


def _score_path(
    path: list[int], adj: dict[int, list[tuple[int, float, str]]]
) -> float:
    """Risk score = sum of edge weights along path, normalised to 0-10."""
    total_weight = 0.0
    for i in range(len(path) - 1):
        for neighbour, weight, _ in adj.get(path[i], []):
            if neighbour == path[i + 1]:
                total_weight += weight
                break
    # Longer paths with higher weights = higher risk, cap at 10
    return round(min(10.0, total_weight * 1.2), 2)


def _shares_subnet(ips_a: set[str], ips_b: set[str]) -> bool:
    for ip_a in ips_a:
        parts_a = ip_a.split(".")
        if len(parts_a) < 3:
            continue
        prefix_a = ".".join(parts_a[:3])
        for ip_b in ips_b:
            if ip_b.startswith(prefix_a + "."):
                return True
    return False


def _path_to_dict(p: AttackPath, db: Session) -> dict:
    start_node = db.query(AttackGraphNode).filter(AttackGraphNode.id == p.start_node_id).first()
    target_node = db.query(AttackGraphNode).filter(AttackGraphNode.id == p.target_node_id).first()
    return {
        "id": p.id,
        "start_node": _node_to_dict(start_node, set()) if start_node else None,
        "target_node": _node_to_dict(target_node, set()) if target_node else None,
        "path": p.path_json,
        "risk_score": p.risk_score,
        "hop_count": p.hop_count,
        "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _edge_to_dict(e: AttackGraphEdge, db: Session) -> dict:
    return {
        "id": e.id,
        "source_node_id": e.source_node_id,
        "target_node_id": e.target_node_id,
        "edge_type": e.edge_type,
        "weight": e.weight,
        "evidence": e.evidence_json,
    }


def _node_to_dict(n: AttackGraphNode, crown_ids: set[int]) -> dict:
    return {
        "id": n.id,
        "node_type": n.node_type,
        "asset_id": n.asset_id,
        "label": n.label,
        "is_crown_jewel": n.asset_id in crown_ids if n.asset_id else False,
    }
