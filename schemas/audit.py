"""
WORM (Write Once Read Many) Cryptographic Audit Log Schema
Implements append-only hash-chained ledger for Zero Trust forensic compliance.
"""
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class AuditEventType(str, Enum):
    SYSTEM_BOOT = "SYSTEM_BOOT"
    ALERT_INGESTED = "ALERT_INGESTED"
    ALERT_DEDUPLICATED = "ALERT_DEDUPLICATED"
    RISK_EVALUATED = "RISK_EVALUATED"
    AI_REASONING_COMPLETED = "AI_REASONING_COMPLETED"
    AUTO_CONTAINMENT_TRIGGERED = "AUTO_CONTAINMENT_TRIGGERED"
    HITL_APPROVAL_REQUESTED = "HITL_APPROVAL_REQUESTED"
    HITL_DECISION_RECORDED = "HITL_DECISION_RECORDED"
    PAM_EPHEMERAL_TOKEN_ISSUED = "PAM_EPHEMERAL_TOKEN_ISSUED"
    PAM_TOKEN_REVOKED = "PAM_TOKEN_REVOKED"
    REMEDIATION_EXECUTED = "REMEDIATION_EXECUTED"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"
    INTEGRITY_AUDIT_PASSED = "INTEGRITY_AUDIT_PASSED"
    INTEGRITY_AUDIT_FAILED = "INTEGRITY_AUDIT_FAILED"

class AuditRecord(BaseModel):
    index: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType
    actor: str
    alert_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str
    previous_hash: str
    current_hash: str

class AuditChainVerificationResult(BaseModel):
    is_valid: bool
    total_records: int
    genesis_hash: str
    latest_hash: str
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    broken_link_index: Optional[int] = None
    message: str
