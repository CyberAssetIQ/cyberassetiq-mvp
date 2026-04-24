from db.session import Base
from models.agent import Agent, AgentEnrollmentToken, AgentPolicy
from models.asset import CanonicalAsset, ManualAsset
from models.auth import TenantAPIKey
from models.commands import AgentCommand, ScanJob
from models.darkweb import DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist
from models.network import NetworkDiscoveredAsset, NetworkScanJob
from models.telemetry import (
    HeartbeatEvent,
    LocalFindingsEvent,
    SecurityPostureEvent,
    SoftwareInventoryEvent,
    AssetSnapshotEvent,
    CanonicalSoftware,
    VulnerabilityFinding,
)
from models.compliance_run import ComplianceRun, ComplianceRunAsset
from models.vuln_scan import VulnScanRun, VulnAnnotation
from models.network_extensions import ExtensionServiceJob, PassiveDiscoveryResult, ExposureFinding, AttackPathFinding
from models.ai_event import AIEvent
from models.ai_alert import AIAlert
from models.ai_correlation import AICorrelation
from models.ai_investigation import AIInvestigation
from models.ai_baseline import AIBaseline
from models.ai_model_run import AIModelRun
from models.insurance import InsuranceAssessment, InsuranceReferral
from models.training import TrainingModule, TrainingProgress, TrainingQuizAttempt
from models.patch import PatchReport, PatchApproval
from models.notification import NotificationRule, NotificationLog
from models.external_exposure import ExternalScan, ExternalFinding
from models.risk_snapshot import RiskSnapshot
from models.billing import TenantSubscription, UsageRecord
from models.user import TenantUser, UserInvitation

# ── Phase 1: Foundational Intelligence (additive — safe to revert) ──────────
from models.drift import AssetStateSnapshot, AssetDriftEvent, ApprovedChange, DriftBaseline
from models.criticality import AssetCriticalityProfile, BusinessService, AssetServiceMap, CrownJewelAsset
from models.risk_engine import RiskFactorScore, RiskSnapshotV2, RiskRecommendation, RiskScoreExplanation

# ── Phase 2: Strategic Differentiation (additive — safe to revert) ───────────
from models.attack_graph import AttackGraphNode, AttackGraphEdge, AttackPath, IdentityRelationship, CredentialExposureLink
from models.backup_resilience import BackupProfile, BackupRiskFinding, RecoveryConfidenceScore
from models.blast_radius import BlastRadiusResult, RansomwareScenario

# ── Phase 3: Actionability (additive — safe to revert) ──────────────────────
from models.remediation import RemediationAction, RemediationPlaybook, RemediationRun, RemediationApproval
from models.shadow_it import ShadowITFinding, RogueSoftwareFinding, UnknownDeviceFinding

# ── Phase 4: Modern Estate Coverage (additive — safe to revert) ─────────────
from models.cloud_posture import (
    CloudAccount, CloudAsset, CloudPostureFinding,
    IdentityPostureFinding, SaaSApp, SaaSPostureFinding, ConnectorSyncLog,
)
from models.business_context import DataClassification, AssetBusinessContext

# ── Phase 5: Scale Channel (additive — safe to revert) ──────────────────────
from models.msp import MSPAccount, MSPTenantMap, TenantHealthScore, PortfolioAlert

__all__ = [
    "Agent",
    "AgentEnrollmentToken",
    "AgentPolicy",
    "TenantAPIKey",
    "CanonicalAsset",
    "ManualAsset",
    "HeartbeatEvent",
    "LocalFindingsEvent",
    "SecurityPostureEvent",
    "SoftwareInventoryEvent",
    "AssetSnapshotEvent",
    "CanonicalSoftware",
    "VulnerabilityFinding",
    "ScanJob",
    "AgentCommand",
    "NetworkScanJob",
    "NetworkDiscoveredAsset",
    "DarkWebWatchlist",
    "DarkWebSourceItem",
    "DarkWebFinding",
    "ComplianceRun",
    "ComplianceRunAsset",
    "VulnScanRun",
    "VulnAnnotation",
    "ExtensionServiceJob",
    "PassiveDiscoveryResult",
    "ExposureFinding",
    "AttackPathFinding",
    "AIEvent",
    "AIAlert",
    "AICorrelation",
    "AIInvestigation",
    "AIBaseline",
    "AIModelRun",
    # Phase 1
    "AssetStateSnapshot",
    "AssetDriftEvent",
    "ApprovedChange",
    "DriftBaseline",
    "AssetCriticalityProfile",
    "BusinessService",
    "AssetServiceMap",
    "CrownJewelAsset",
    "RiskFactorScore",
    "RiskSnapshotV2",
    "RiskRecommendation",
    "RiskScoreExplanation",
    # Phase 2
    "AttackGraphNode",
    "AttackGraphEdge",
    "AttackPath",
    "IdentityRelationship",
    "CredentialExposureLink",
    "BackupProfile",
    "BackupRiskFinding",
    "RecoveryConfidenceScore",
    "BlastRadiusResult",
    "RansomwareScenario",
    # Phase 3
    "RemediationAction",
    "RemediationPlaybook",
    "RemediationRun",
    "RemediationApproval",
    "ShadowITFinding",
    "RogueSoftwareFinding",
    "UnknownDeviceFinding",
    # Phase 4
    "CloudAccount",
    "CloudAsset",
    "CloudPostureFinding",
    "IdentityPostureFinding",
    "SaaSApp",
    "SaaSPostureFinding",
    "ConnectorSyncLog",
    "DataClassification",
    "AssetBusinessContext",
    # Phase 5
    "MSPAccount",
    "MSPTenantMap",
    "TenantHealthScore",
    "PortfolioAlert",
    "PostureRecord",
    "PostureRecordVersion",
    "PostureDomain",
    "PostureEvidenceItem",
    "PostureConsumer",
    "PostureAccessGrant",
    "PostureShareLink",
    "PostureAccessAudit",
    "BrokerAccount",
    "BrokerUser",
    "BrokerClientLink",
    "BrokerQuoteRequest",
    "BuyerAccount",
    "SupplierRelationship",
    "AssuranceRequest",
    "SupplierAttestation",
    "AssuranceReview",
    "VerificationCredential",
    "VerificationEvent",
]


from models.posture_record import PostureRecord, PostureRecordVersion, PostureDomain, PostureEvidenceItem
from models.posture_sharing import PostureConsumer, PostureAccessGrant, PostureShareLink, PostureAccessAudit
from models.broker import BrokerAccount, BrokerUser, BrokerClientLink, BrokerQuoteRequest
from models.supply_chain import BuyerAccount, SupplierRelationship, AssuranceRequest, SupplierAttestation, AssuranceReview
from models.verification import VerificationCredential, VerificationEvent
from models.consumer_api_key import ConsumerAPIKey
from models.incident_response import Incident, IncidentTimeline, IncidentAsset, IncidentReport
from models.agentic_loop import AgentLoopRun, AgentLoopAction
from models.integration_connector import IntegrationConnector
