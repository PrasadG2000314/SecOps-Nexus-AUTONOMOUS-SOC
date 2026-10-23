"""
SecOps Lifecycle State Machine
Defines valid transitions from initial alert discovery to verified remediation.
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from schemas.alerts import UnifiedAlert
from schemas.remediation import AIAnalysisResult, HITLDecision, RemediationExecutionResult

class WorkflowState(str, Enum):
    INGESTED = "INGESTED"
    EVALUATING = "EVALUATING"
    ANALYZED = "ANALYZED"
    AWAITING_HITL = "AWAITING_HITL"
    AUTO_CONTAINED = "AUTO_CONTAINED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"

class StateTransition(BaseModel):
    from_state: WorkflowState
    to_state: WorkflowState
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str
    actor: str

class AlertLifecycle(BaseModel):
    alert: UnifiedAlert
    state: WorkflowState = WorkflowState.INGESTED
    occurrence_count: int = 1
    ai_analysis: Optional[AIAnalysisResult] = None
    hitl_decision: Optional[HITLDecision] = None
    execution_result: Optional[RemediationExecutionResult] = None
    transitions: List[StateTransition] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def transition_to(self, new_state: WorkflowState, actor: str, reason: str):
        """Records state transition and timestamps."""
        trans = StateTransition(
            from_state=self.state,
            to_state=new_state,
            reason=reason,
            actor=actor
        )
        self.transitions.append(trans)
        self.state = new_state
        self.updated_at = datetime.now(timezone.utc)
        self.alert.status_updated_at = self.updated_at
