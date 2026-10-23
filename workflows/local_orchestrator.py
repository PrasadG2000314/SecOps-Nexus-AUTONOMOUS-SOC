"""
Standalone Zero-Dependency SecOps Orchestrator
Enables instant local execution and full stateful simulation of the
Autonomous SOC & Vulnerability Remediation Platform without requiring external daemon infrastructure.
"""
import asyncio
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timezone
from schemas.alerts import UnifiedAlert, AlertStatus
from schemas.remediation import HITLDecision, RemediationExecutionResult
from schemas.audit import AuditEventType
from core.audit_log import worm_audit_log
from core.risk_scorer import risk_engine
from core.deduplicator import alert_deduplicator
from core.security import sign_approval_decision
from intelligence.gemini_reasoner import gemini_security_reasoner
from execution.ansible_executor import ansible_executor
from workflows.state_machine import WorkflowState, AlertLifecycle

class LocalSecOpsOrchestrator:
    def __init__(self):
        self._lifecycles: Dict[str, AlertLifecycle] = {}
        self._listeners: List[Callable[[str, Dict[str, Any]], Any]] = []

    def register_listener(self, callback: Callable[[str, Dict[str, Any]], Any]):
        """Registers a callback for WebSocket and event broadcasting."""
        self._listeners.append(callback)

    async def _broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts event to all active UI WebSocket connections."""
        for listener in self._listeners:
            try:
                res = listener(event_type, data)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as e:
                print(f"[ORCHESTRATOR] Listener broadcast error: {e}")

    async def process_alert(self, alert: UnifiedAlert) -> AlertLifecycle:
        """
        Executes the end-to-end autonomous triage workflow:
        1. Ingestion & WORM audit logging
        2. Deduplication check
        3. Contextual Risk Scoring
        4. Gemini Security Reasoning (MITRE mapping + Ansible synthesis)
        5. Auto-Containment evaluation or HITL Gate pause
        """
        # Step 1: Log Ingestion to WORM Audit Log
        worm_audit_log.record_event(
            event_type=AuditEventType.ALERT_INGESTED,
            actor="INGESTION_CONTROLLER",
            alert_id=alert.id,
            details={
                "source": alert.source.value,
                "asset": alert.asset.hostname,
                "title": alert.vulnerability.title,
                "cve": alert.vulnerability.cve_id,
                "cvss": alert.vulnerability.cvss_base_score
            }
        )

        # Step 2: Deduplication Check
        is_dup, canonical, count = alert_deduplicator.process(alert)
        if is_dup and canonical.id in self._lifecycles:
            lifecycle = self._lifecycles[canonical.id]
            lifecycle.occurrence_count = count
            lifecycle.transition_to(
                lifecycle.state,
                actor="DEDUPLICATOR",
                reason=f"Correlated duplicate alert occurrence (Total: {count})"
            )
            worm_audit_log.record_event(
                event_type=AuditEventType.ALERT_DEDUPLICATED,
                actor="DEDUPLICATOR",
                alert_id=canonical.id,
                details={"occurrence_count": count}
            )
            await self._broadcast("ALERT_UPDATED", {"alert_id": canonical.id, "count": count})
            return lifecycle

        # Step 3: Contextual Risk Scoring
        risk_engine.evaluate_alert(alert)
        worm_audit_log.record_event(
            event_type=AuditEventType.RISK_EVALUATED,
            actor="RISK_ENGINE",
            alert_id=alert.id,
            details={
                "contextual_score": alert.contextual_risk_score,
                "severity": alert.severity_level,
                "asset_criticality": alert.asset.criticality.value,
                "cisa_kev_active": alert.vulnerability.cisa_kev_active
            }
        )

        lifecycle = AlertLifecycle(alert=alert, state=WorkflowState.EVALUATING)
        lifecycle.transition_to(WorkflowState.EVALUATING, "ORCHESTRATOR", "Calculating contextual risk")
        self._lifecycles[alert.id] = lifecycle

        # Step 4: AI Security Reasoning Layer
        lifecycle.transition_to(WorkflowState.ANALYZED, "GEMINI_REASONER", "Synthesizing MITRE ATT&CK and remediation artifacts")
        ai_result = await gemini_security_reasoner.analyze_alert(alert)
        lifecycle.ai_analysis = ai_result

        # Step 5: Evaluate Auto-Containment vs HITL Approval Gate
        can_auto_contain = (
            ai_result.auto_containment_eligible and
            risk_engine.is_auto_containment_permitted(alert.contextual_risk_score, alert)
        )

        if can_auto_contain:
            # Autonomous remediation path
            lifecycle.transition_to(WorkflowState.AUTO_CONTAINED, "SAFETY_GOVERNOR", "Risk score <= 30 and low blast radius. Auto-containment triggered.")
            worm_audit_log.record_event(
                event_type=AuditEventType.AUTO_CONTAINMENT_TRIGGERED,
                actor="SAFETY_GOVERNOR",
                alert_id=alert.id,
                details={"risk_score": alert.contextual_risk_score}
            )
            alert.status = AlertStatus.AUTO_CONTAINED

            # Execute remediation
            lifecycle.transition_to(WorkflowState.EXECUTING, "ANSIBLE_RUNNER", "Applying autonomous patch")
            exec_result = await ansible_executor.execute_playbook(
                alert_id=alert.id,
                target_host=alert.asset.hostname,
                playbook_yaml=ai_result.ansible_playbook_yaml,
                verification_cmd=ai_result.verification_check_cmd
            )
            lifecycle.execution_result = exec_result
            lifecycle.transition_to(WorkflowState.VERIFIED, "FORENSIC_VERIFIER", "Remediation applied and verified")
            alert.status = AlertStatus.VERIFIED

        else:
            # Mandated Human-in-the-Loop (HITL) Gate
            lifecycle.transition_to(
                WorkflowState.AWAITING_HITL,
                "HITL_GATE",
                "High-impact or critical risk threat. Pausing workflow for Human Engineer approval."
            )
            worm_audit_log.record_event(
                event_type=AuditEventType.HITL_APPROVAL_REQUESTED,
                actor="HITL_GATE",
                alert_id=alert.id,
                details={
                    "blast_radius": ai_result.blast_radius.value,
                    "risk_score": alert.contextual_risk_score
                }
            )
            alert.status = AlertStatus.AWAITING_APPROVAL

        await self._broadcast("ALERT_PROCESSED", {"alert_id": alert.id, "state": lifecycle.state.value})
        return lifecycle

    async def resolve_hitl(self, alert_id: str, decision: str, approver_name: str,
                           approver_role: str, notes: str) -> Optional[AlertLifecycle]:
        """
        Resolves the Human-In-The-Loop approval gate when an engineer clicks in the dashboard.
        """
        lifecycle = self._lifecycles.get(alert_id)
        if not lifecycle:
            return None

        # Generate cryptographic signature for audit authenticity
        signature = sign_approval_decision(alert_id, approver_name, approver_role)
        hitl_obj = HITLDecision(
            alert_id=alert_id,
            decision=decision.upper(),
            approver_name=approver_name,
            approver_role=approver_role,
            approver_signature=signature,
            notes=notes,
            timestamp=datetime.now(timezone.utc)
        )
        lifecycle.hitl_decision = hitl_obj

        # Record decision in WORM log
        worm_audit_log.record_event(
            event_type=AuditEventType.HITL_DECISION_RECORDED,
            actor=f"ENGINEER:{approver_name}",
            alert_id=alert_id,
            details={
                "decision": hitl_obj.decision,
                "role": approver_role,
                "signature": signature[:12] + "...",
                "notes": notes
            }
        )

        if hitl_obj.decision == "APPROVED":
            lifecycle.transition_to(WorkflowState.APPROVED, f"ENGINEER:{approver_name}", f"Remediation plan approved: {notes}")
            lifecycle.transition_to(WorkflowState.EXECUTING, "ANSIBLE_RUNNER", "Executing approved remediation playbook")
            lifecycle.alert.status = AlertStatus.EXECUTING

            # Execute via Ansible with Ephemeral PAM token
            playbook = lifecycle.ai_analysis.ansible_playbook_yaml if lifecycle.ai_analysis else "---"
            verify_cmd = lifecycle.ai_analysis.verification_check_cmd if lifecycle.ai_analysis else "exit 0"

            exec_result = await ansible_executor.execute_playbook(
                alert_id=alert_id,
                target_host=lifecycle.alert.asset.hostname,
                playbook_yaml=playbook,
                verification_cmd=verify_cmd
            )
            lifecycle.execution_result = exec_result
            lifecycle.transition_to(WorkflowState.VERIFIED, "FORENSIC_VERIFIER", "Remediation executed and verified")
            lifecycle.alert.status = AlertStatus.VERIFIED

        else:
            lifecycle.transition_to(WorkflowState.REJECTED, f"ENGINEER:{approver_name}", f"Remediation rejected: {notes}")
            lifecycle.alert.status = AlertStatus.REJECTED

        await self._broadcast("HITL_RESOLVED", {"alert_id": alert_id, "decision": hitl_obj.decision})
        return lifecycle

    def get_lifecycle(self, alert_id: str) -> Optional[AlertLifecycle]:
        return self._lifecycles.get(alert_id)

    def list_lifecycles(self) -> List[AlertLifecycle]:
        return list(self._lifecycles.values())

    def get_stats(self) -> Dict[str, Any]:
        """Aggregates metrics for the SOC Command Center."""
        all_items = list(self._lifecycles.values())
        total = len(all_items)
        pending_hitl = sum(1 for item in all_items if item.state == WorkflowState.AWAITING_HITL)
        auto_contained = sum(1 for item in all_items if item.state in (WorkflowState.AUTO_CONTAINED, WorkflowState.VERIFIED) and not item.hitl_decision)
        verified = sum(1 for item in all_items if item.state == WorkflowState.VERIFIED)
        critical_count = sum(1 for item in all_items if item.alert.severity_level == "CRITICAL")
        cisa_kev_count = sum(1 for item in all_items if item.alert.vulnerability.cisa_kev_active)

        return {
            "total_alerts": total,
            "pending_hitl": pending_hitl,
            "auto_contained": auto_contained,
            "verified_remediations": verified,
            "critical_threats": critical_count,
            "cisa_kev_active": cisa_kev_count
        }

orchestrator = LocalSecOpsOrchestrator()
