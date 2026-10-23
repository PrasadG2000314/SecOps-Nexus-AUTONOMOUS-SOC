"""
Remediation and AI Reasoning Schemas
Defines AI assessment outputs, Ansible playbooks, HITL decisions, and execution artifacts.
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class BlastRadiusRating(str, Enum):
    LOW = "LOW"                   # Zero downtime expected, isolated patch / minor version
    MEDIUM = "MEDIUM"             # Non-breaking service reload, slight latency risk
    HIGH = "HIGH"                 # Service restart required, potential configuration drift
    CATASTROPHIC = "CATASTROPHIC" # Database schema change, network core partition risk

class RemediationActionType(str, Enum):
    PACKAGE_UPGRADE = "PACKAGE_UPGRADE"
    FIREWALL_RULE = "FIREWALL_RULE"
    CONFIG_PATCH = "CONFIG_PATCH"
    CONTAINER_ROLLOUT = "CONTAINER_ROLLOUT"
    ISOLATION_CONTAINMENT = "ISOLATION_CONTAINMENT"
    IAM_REVOCATION = "IAM_REVOCATION"

class AIAnalysisResult(BaseModel):
    alert_id: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: str
    mitre_attack_tactics: List[str] = Field(default_factory=list)
    mitre_attack_techniques: List[str] = Field(default_factory=list)
    exploitability_assessment: str
    cisa_kev_notes: Optional[str] = None
    blast_radius: BlastRadiusRating = BlastRadiusRating.MEDIUM
    blast_radius_rationale: str
    auto_containment_eligible: bool = False
    remediation_plan_md: str
    ansible_playbook_yaml: str
    dry_run_command: str
    rollback_playbook_yaml: Optional[str] = None
    verification_check_cmd: str

class HITLDecision(BaseModel):
    alert_id: str
    decision: str                                       # "APPROVED" or "REJECTED"
    approver_name: str = "SecOps Lead"
    approver_role: str = "Senior SOC Analyst"
    approver_signature: str                             # Cryptographic HMAC/WebAuthn signature
    notes: Optional[str] = "Approved after reviewing blast radius and Ansible dry-run."
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RemediationExecutionResult(BaseModel):
    alert_id: str
    action_type: RemediationActionType = RemediationActionType.PACKAGE_UPGRADE
    success: bool
    exit_code: int = 0
    stdout: str
    stderr: str = ""
    execution_duration_ms: int = 420
    pam_session_id: str
    ephemeral_token_revoked: bool = True
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_passed: bool = True
    verification_details: str = "Target host re-scanned. Vulnerability signature absent."
