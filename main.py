"""
SecOps-Nexus Main Application Server
Autonomous SOC & Automated Vulnerability Remediation Platform
"""
import os
import json
import asyncio
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Header, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.encoders import jsonable_encoder

from config import settings
from schemas.alerts import UnifiedAlert, SensorSource, AlertStatus
from schemas.remediation import HITLDecision
from core.security import verify_hmac_signature, generate_hmac_signature
from core.audit_log import worm_audit_log
from core.pam_service import pam_manager
from ingestion import parse_trivy_report, parse_sonarqube_alert, parse_nmap_scan, parse_wazuh_event
from scanner.file_scanner import file_security_scanner
from execution.file_patcher import safe_file_patcher
from workflows.local_orchestrator import orchestrator
from workflows.state_machine import WorkflowState

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        safe_msg = jsonable_encoder(message)
        for connection in list(self.active_connections):
            try:
                await connection.send_json(safe_msg)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Hook orchestrator broadcasts into WebSocket manager
def handle_orchestrator_event(event_type: str, data: Dict[str, Any]):
    asyncio.create_task(ws_manager.broadcast({"type": event_type, "data": data}))

orchestrator.register_listener(handle_orchestrator_event)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[*] Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    print(f"[*] Zero-Trust HMAC Signature Enforcement: ACTIVE")
    print(f"[*] WORM Cryptographic Ledger: ONLINE (Blocks: {len(worm_audit_log.records)})")
    print(f"[*] Standalone Async Orchestration: {settings.STANDALONE_MODE}")
    yield
    print(f"[*] Shutting down {settings.PROJECT_NAME}")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous SOC & Automated Vulnerability Remediation Engine with Zero Trust Architecture and HITL Gates.",
    lifespan=lifespan
)

# Enforce Defense-in-Depth Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

@app.get("/api/v1/health")
async def health_check():
    """System health check and safe masked configuration status."""
    return {
        "status": "HEALTHY",
        "audit_blocks": len(worm_audit_log.records),
        "configuration": settings.get_masked_overview()
    }

# Static and template directories
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ==========================================
# 1. UI DASHBOARD ROUTE
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request):
    """Renders the SecOps-Nexus Cyber Command Center."""
    stats = orchestrator.get_stats()
    audit_integrity = worm_audit_log.verify_chain_integrity()
    context = {
        "title": f"{settings.PROJECT_NAME} | Autonomous Cyber Defense",
        "stats": stats,
        "audit_integrity": audit_integrity,
        "settings": settings
    }
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=context
    )

# ==========================================
# 2. INGESTION & ZERO TRUST WEBHOOKS
# ==========================================
@app.post("/api/v1/ingest/webhook")
async def ingest_webhook(
    request: Request,
    source: SensorSource = SensorSource.TRIVY,
    x_hmac_signature: Optional[str] = Header(None, alias="X-HMAC-Signature"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256")
):
    """
    Zero-Trust Ingestion Endpoint.
    Requires valid HMAC-SHA256 signature to guarantee payload integrity against adversary forgery.
    """
    raw_body = await request.body()
    signature = x_hmac_signature or x_hub_signature_256

    # Verify cryptographic signature
    if not verify_hmac_signature(raw_body, signature):
        raise HTTPException(
            status_code=401,
            detail="Zero Trust Security Violation: Invalid or missing HMAC-SHA256 signature. Ingestion rejected."
        )

    try:
        data = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    parsed_alerts: List[UnifiedAlert] = []
    if source == SensorSource.TRIVY:
        parsed_alerts = parse_trivy_report(data)
    elif source == SensorSource.SONARQUBE:
        parsed_alerts = parse_sonarqube_alert(data)
    elif source == SensorSource.NMAP:
        parsed_alerts = parse_nmap_scan(data)
    elif source == SensorSource.WAZUH_EDR:
        parsed_alerts = parse_wazuh_event(data)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported sensor source: {source}")

    results = []
    for alert in parsed_alerts:
        lifecycle = await orchestrator.process_alert(alert)
        results.append({
            "alert_id": alert.id,
            "status": lifecycle.state.value,
            "risk_score": alert.contextual_risk_score,
            "severity": alert.severity_level
        })

    return {"status": "SUCCESS", "ingested_count": len(results), "alerts": results}

# ==========================================
# 3. INTERACTIVE SIMULATION API
# ==========================================
@app.post("/api/v1/simulator/trigger")
async def trigger_simulation(scenario: str = "xz_backdoor"):
    """
    Simulates real-world threat alerts for rapid testing & live SOC demonstration.
    """
    alert: Optional[UnifiedAlert] = None

    if scenario == "xz_backdoor":
        # Simulates CVE-2024-3094 Trivy scan finding
        trivy_data = {
            "SchemaVersion": 2,
            "ArtifactName": "k8s-prod-ingress-gateway:v2.1",
            "Results": [
                {
                    "Target": "k8s-prod-ingress-gateway (debian 12.5)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-3094",
                            "PkgName": "xz-utils",
                            "InstalledVersion": "5.6.0-0.2",
                            "FixedVersion": "5.4.5-0.1",
                            "Severity": "CRITICAL",
                            "Title": "Upstream liblzma Supply Chain Backdoor in OpenSSH daemon",
                            "Description": "Malicious backdoor inserted into xz-utils liblzma upstream tarballs that compromises sshd authentication and permits unauthorized remote code execution.",
                            "CVSS": {
                                "nvd": {
                                    "V3Score": 10.0,
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                }
                            }
                        }
                    ]
                }
            ]
        }
        alerts = parse_trivy_report(trivy_data, {
            "hostname": "k8s-worker-ingress-01.prod.corp",
            "ip_address": "198.51.100.10",
            "criticality": "TIER_0_MISSION_CRITICAL",
            "exposure": "PUBLIC_INTERNET"
        })
        if alerts:
            alert = alerts[0]

    elif scenario == "sqli_attack":
        # Simulates SonarQube SAST detection
        sq_data = {
            "project": {"name": "payment-api-gateway"},
            "issues": [
                {
                    "rule": "python:S3649",
                    "severity": "CRITICAL",
                    "component": "services/billing/checkout_controller.py",
                    "line": 142,
                    "message": "User-supplied query parameter 'account_id' passed directly into raw SQL string formatting without parameterization."
                }
            ]
        }
        alerts = parse_sonarqube_alert(sq_data, {
            "hostname": "billing-api-prod.internal",
            "ip_address": "10.0.14.88",
            "criticality": "TIER_1_PRODUCTION",
            "exposure": "PUBLIC_INTERNET"
        })
        if alerts:
            alert = alerts[0]

    elif scenario == "exposed_rdp":
        # Simulates Nmap perimeter scan
        nmap_data = {
            "ip": "203.0.113.88",
            "hostname": "bastion-mgmt-pub-01",
            "ports": [
                {"port": 3389, "service": "ms-wbt-server", "state": "open"},
                {"port": 80, "service": "http", "state": "open"}
            ]
        }
        alerts = parse_nmap_scan(nmap_data)
        if alerts:
            alert = alerts[0]

    elif scenario == "wazuh_brute_force":
        # Simulates Wazuh EDR alert
        wazuh_data = {
            "agent": {"name": "dmz-auth-proxy-01", "ip": "10.0.3.50"},
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "sshd: Excessive unauthorized authentication failures (brute force attack detected)",
                "mitre": {"tactic": ["Credential Access"], "id": ["T1110"]}
            },
            "full_log": "Apr 14 02:11:05 dmz-auth-proxy-01 sshd[28491]: Failed password for root from 198.51.100.99 port 42318 ssh2 (25 attempts in 30s)"
        }
        alerts = parse_wazuh_event(wazuh_data)
        if alerts:
            alert = alerts[0]

    elif scenario == "generate_sample":
        return await generate_sample_endpoint()

    if not alert:
        raise HTTPException(status_code=400, detail="Unknown simulation scenario.")

@app.post("/api/v1/simulator/generate-sample")
async def generate_sample_endpoint():
    """Generates a realistic vulnerable Python file on disk for immediate live testing."""
    sample_path = "vulnerable_sample.py"
    sample_content = '''"""
Vulnerable Application Sample for Industrial Security Analysis Testing
"""
import os
import pickle
import hashlib

# 1. Hardcoded Cloud Secrets (CWE-798)
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"

def execute_user_query(user_input):
    # 2. Command Injection / RCE (CWE-78)
    os.system("ping -c 1 " + user_input)

def load_user_session(serialized_data):
    # 3. Insecure Deserialization (CWE-502)
    return pickle.loads(serialized_data)

def hash_user_password(password):
    # 4. Insecure Cryptographic Hash (CWE-327)
    return hashlib.md5(password.encode()).hexdigest()
'''
    with open(sample_path, "w", encoding="utf-8") as f:
        f.write(sample_content)
    return {"status": "SUCCESS", "file_path": sample_path}

    lifecycle = await orchestrator.process_alert(alert)
    return {
        "status": "SIMULATED",
        "scenario": scenario,
        "alert_id": alert.id,
        "state": lifecycle.state.value,
        "risk_score": alert.contextual_risk_score,
        "severity": alert.severity_level,
        "cisa_kev_active": alert.vulnerability.cisa_kev_active
    }

# ==========================================
# 4. ALERTS & HITL APPROVAL GATE APIS
# ==========================================
@app.get("/api/v1/alerts")
async def list_alerts():
    """Lists all active and historical alerts."""
    lifecycles = orchestrator.list_lifecycles()
    data = []
    for lc in reversed(lifecycles):
        data.append({
            "id": lc.alert.id,
            "title": lc.alert.vulnerability.title,
            "cve": lc.alert.vulnerability.cve_id,
            "source": lc.alert.source.value,
            "hostname": lc.alert.asset.hostname,
            "ip_address": lc.alert.asset.ip_address,
            "criticality": lc.alert.asset.criticality.value,
            "exposure": lc.alert.asset.exposure.value,
            "cvss": lc.alert.vulnerability.cvss_base_score,
            "risk_score": lc.alert.contextual_risk_score,
            "severity": lc.alert.severity_level,
            "status": lc.state.value,
            "cisa_kev_active": lc.alert.vulnerability.cisa_kev_active,
            "created_at": lc.created_at.isoformat(),
            "has_ai_analysis": lc.ai_analysis is not None,
            "blast_radius": lc.ai_analysis.blast_radius.value if lc.ai_analysis else "N/A"
        })
    return {"alerts": data}

@app.get("/api/v1/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Retrieves deep triage, AI reasoning, and Ansible playbook details for an alert."""
    lc = orchestrator.get_lifecycle(alert_id)
    if not lc:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return {
        "alert": lc.alert.model_dump(),
        "state": lc.state.value,
        "occurrence_count": lc.occurrence_count,
        "ai_analysis": lc.ai_analysis.model_dump() if lc.ai_analysis else None,
        "hitl_decision": lc.hitl_decision.model_dump() if lc.hitl_decision else None,
        "execution_result": lc.execution_result.model_dump() if lc.execution_result else None,
        "transitions": [t.model_dump() for t in lc.transitions]
    }

@app.post("/api/v1/alerts/{alert_id}/hitl")
async def submit_hitl_approval(
    alert_id: str,
    decision: str = "APPROVED",
    approver_name: str = "SecOps Lead",
    approver_role: str = "Principal Security Engineer",
    notes: str = "Verified playbook safety and approved deployment."
):
    """
    Human-In-The-Loop Approval Gate.
    Authorizes or rejects high-impact vulnerability remediation.
    """
    lifecycle = await orchestrator.resolve_hitl(
        alert_id=alert_id,
        decision=decision,
        approver_name=approver_name,
        approver_role=approver_role,
        notes=notes
    )
    if not lifecycle:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return {
        "status": "PROCESSED",
        "alert_id": alert_id,
        "new_state": lifecycle.state.value,
        "decision": decision,
        "execution_success": lifecycle.execution_result.success if lifecycle.execution_result else None
    }

# ==========================================
# 5. CRYPTOGRAPHIC WORM AUDIT LOG & COMPLIANCE
# ==========================================
@app.get("/api/v1/audit/records")
async def get_audit_records(limit: int = 40):
    """Retrieves recent blocks in the WORM append-only cryptographic ledger."""
    records = worm_audit_log.get_recent_records(limit=limit)
    return {"records": [r.model_dump() for r in records]}

@app.get("/api/v1/audit/verify")
async def verify_audit_ledger():
    """Performs full SHA-256 Merkle chain verification of the audit log."""
    res = worm_audit_log.verify_chain_integrity()
    return res.model_dump()

# ==========================================
# 6. METRICS & PAM STATUS
# ==========================================
@app.get("/api/v1/stats")
async def get_system_stats():
    """Returns real-time SOC metrics."""
    stats = orchestrator.get_stats()
    audit_res = worm_audit_log.verify_chain_integrity()
    return {
        **stats,
        "audit_ledger_valid": audit_res.is_valid,
        "total_audit_blocks": audit_res.total_records
    }

# ==========================================
# 7. WEBSOCKET REAL-TIME STREAM
# ==========================================
@app.websocket("/ws/stream")
async def websocket_telemetry_stream(websocket: WebSocket):
    """Streams live alerts, AI analyses, and audit blocks to connected SOC screens."""
    await ws_manager.connect(websocket)
    try:
        # Send initial state snapshot
        init_payload = {
            "type": "INIT_SNAPSHOT",
            "data": {
                "stats": orchestrator.get_stats(),
                "audit_integrity": worm_audit_log.verify_chain_integrity().model_dump(mode="json")
            }
        }
        await websocket.send_json(jsonable_encoder(init_payload))
        while True:
            # Keepalive listener
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# ==========================================
# 8. REAL INDUSTRIAL FILE SCANNER & AUTO-PATCH
# ==========================================
@app.post("/api/v1/scan/file")
async def scan_file_endpoint(file_path: str):
    """
    Industrial File Security Scanner.
    Analyzes an exact file on disk for syntax bugs, OWASP flaws, and exposed credentials.
    """
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    try:
        result = file_security_scanner.scan_file(file_path)
        
        # Correlate critical issues into the SOC Orchestrator
        for issue in result.issues:
            if issue.severity in ("CRITICAL", "HIGH"):
                # Create a UnifiedAlert so it appears in the live SOC triage
                alert = UnifiedAlert(
                    source=SensorSource.SONARQUBE,
                    asset={
                        "hostname": os.path.basename(file_path),
                        "ip_address": "127.0.0.1",
                        "environment": "production",
                        "criticality": "TIER_1_PRODUCTION",
                        "exposure": "PUBLIC_INTERNET",
                        "owner_team": "AppSec"
                    },
                    vulnerability={
                        "cwe_id": issue.cwe_id,
                        "title": f"File Security Flaw: {issue.title}",
                        "description": f"{issue.description} Found at line {issue.line_number} of {os.path.basename(file_path)}.",
                        "cvss_base_score": issue.cvss_score,
                        "affected_resource": f"{file_path}:{issue.line_number}",
                        "evidence": {"vulnerable_code": issue.vulnerable_code, "fix": issue.recommended_fix}
                    },
                    raw_payload_hash="file-scan-" + file_path
                )
                await orchestrator.process_alert(alert)

        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan/directory")
async def scan_directory_endpoint(dir_path: str = ".", max_files: int = 300):
    """
    Industrial Codebase Scanner.
    Recursively scans projects, checking errors, security issues, and generating fixes.
    """
    if not os.path.exists(dir_path):
        raise HTTPException(status_code=404, detail=f"Directory not found: {dir_path}")

    try:
        result = file_security_scanner.scan_directory(dir_path, max_files=max_files)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/fix/apply")
async def apply_fix_endpoint(
    file_path: str,
    line_number: int,
    original_code: str,
    remediated_code: str,
    approver_name: str = "SecOps Lead",
    notes: str = "Automated file patch verified and applied."
):
    """
    Applies an automated code fix with atomic backups and pre-flight syntax checks.
    """
    result = safe_file_patcher.apply_patch(
        file_path=file_path,
        line_number=line_number,
        original_code=original_code,
        remediated_code=remediated_code,
        approver=approver_name,
        notes=notes
    )
    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    await ws_manager.broadcast({
        "type": "FILE_PATCHED",
        "data": {
            "file_path": file_path,
            "backup_path": result.backup_path,
            "line_number": line_number
        }
    })

    return result.model_dump()

@app.post("/api/v1/fix/rollback")
async def rollback_fix_endpoint(file_path: str, backup_path: str, actor: str = "SecOps Engineer"):
    """
    Reverts a previously applied code fix from its atomic backup.
    """
    success, msg = safe_file_patcher.rollback(file_path, backup_path, actor=actor)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "SUCCESS", "message": msg}
