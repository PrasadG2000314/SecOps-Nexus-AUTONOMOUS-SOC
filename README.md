# 🛡️ SecOps-Nexus: Autonomous SOC & Automated Vulnerability Remediation Platform

SecOps-Nexus is an enterprise-grade autonomous cyber defense and vulnerability remediation system built with a **Zero Trust Architecture (ZTA)**, **Gemini Security Reasoning Engine**, **Ephemeral PAM Access Controls**, and a mandatory **Human-in-the-Loop (HITL) Approval Gate**.

> 📘 **Looking for step-by-step instructions?** Read the comprehensive [HOW_TO_USE.md](file:///e:/ai%20agent/cyber%20tool/1/HOW_TO_USE.md) guide covering Web UI triage, HITL approvals, scanner integrations, and HMAC signatures.

---

## 🏗️ Architecture Overview

```
                                  [ TARGET INFRASTRUCTURE / CODEBASE ]
                                    (Servers, K8s Clusters, Apps, IAM)
                                                  │
                  ┌───────────────────────────────┴───────────────────────────────┐
                  ▼                                                               ▼
        [ Continuous Scanners ]                                      [ Security Agents / Sensors ]
   (Trivy, SonarQube, Nmap, Burp API)                          (Wazuh / EDR / PAM Audit Logs)
                  │                                                               │
                  └───────────────────────────────┬───────────────────────────────┘
                                                  ▼
                                 ┌─────────────────────────────────┐
                                 │   INGESTION & CORRELATION BUS   │
                                 │  (Zero-Trust HMAC Verification) │
                                 └────────────────┬────────────────┘
                                                  │
                                                  ▼
                         ┌──────────────────────────────────────────────────┐
                         │              CORE SEC-ENGINE (Python)            │
                         │  - CVE Aggregation & Deduplication               │
                         │  - Contextual Risk Scoring (CISA KEV + Asset)    │
                         └────────────────┬────────────────┬────────────────┘
                                          │                │
            ┌─────────────────────────────┘                └─────────────────────────────┐
            ▼                                                                            ▼
  [ INTELLIGENCE LAYER ]                                                     [ INTEGRATION LAYER ]
  - Gemini Security Reasoning Agent                                          - PAM (HashiCorp Vault / CyberArk)
  - MITRE ATT&CK Mapping & Exploit Verification                             - Ephemeral 5-minute single-use tokens
            │                                                                            │
            └─────────────────────────────┬───────────────────────────────┘
                                          ▼
                         ┌──────────────────────────────────┐
                         │   SECURE WORKFLOW ORCHESTRATOR   │
                         │      (Temporal.io / Async Core)  │
                         └────────────────┬─────────────────┘
                                          │
                        ┌─────────────────┴─────────────────┐
                        │  (Automatic Safety Checks Passed) │
                        ▼                                   ▼
             ┌─────────────────────┐             ┌─────────────────────┐
             │   AUTO-CONTAINMENT  │             │ 🛑 HITL APPROVAL    │
             │   (Low-Risk Fixes)  │             │   GATE (Web UI)     │
             └─────────────────────┘             └──────────┬──────────┘
                                                            │
                                                (Engineer Reviews & Clicks)
                                                            │
                                                            ▼
                                                 [ SECURE EXECUTION ]
                                            (Ansible / Ephemeral Creds)
```

---

## 🔒 Defense-in-Depth & Hacker-Resistant Controls

1. **HMAC-SHA256 Payload Signing**: All inbound sensor alerts (Trivy, SonarQube, Nmap, Wazuh) must carry an authentic HMAC signature (`X-HMAC-Signature`). Forged or tampered alerts are rejected at the ingress gate.
2. **WORM (Write Once, Read Many) Cryptographic Ledger**: Every scan, risk evaluation, AI reasoning plan, and engineer approval is cryptographically sealed in an append-only SHA-256 Merkle chain. Any tamper attempt is immediately detectable.
3. **Principle of Least Privilege (PoLP) via PAM**: The remediation runner does not store credentials. It requests single-use, 5-minute ephemeral tokens from HashiCorp Vault / PAM and revokes them immediately upon playbook completion.
4. **Sandboxed / Dry-Run Pre-Flight Execution**: Ansible playbooks are validated for safety and executed in check-mode (`--check --diff`) prior to granting approval.
5. **Prompt Injection & Adversarial Sanitization**: Scanner input passed into the Gemini Security Reasoning Agent is stripped of escape sequences and wrapped in untrusted boundary tokens.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+
- Dependencies installed:
  ```bash
  pip install -r requirements.txt
  ```

### 2. Launch the SecOps-Nexus Server
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Access the Cyber Command Center at: **[http://localhost:8000](http://localhost:8000)**

### 3. Run the Automated Test Suite
```bash
python -m pytest tests/ -v
```

---

## 🕹️ Interactive SOC Command Center Features

- **Live Vulnerability Triage Queue**: Sort and filter alerts by severity, status, and CISA KEV tags.
- **Deep Inspection & HITL Modal**:
  - Executive Threat Summary & Attack Vectors
  - Mapped **MITRE ATT&CK** Framework Tactics & Techniques
  - Real-World Exploitability Analysis & CISA KEV Notes
  - Generated **Ansible Remediation Playbook (YAML)** with pre-flight dry-run command
  - Ephemeral PAM credential countdown clock (5-minute TTL)
  - Dual-control **[ 🛡️ Approve & Execute Fix ]** and **[ ❌ Reject Remediation ]** buttons
- **Cryptographic WORM Audit Trail**: Real-time explorer showing block indexes, previous hashes, and event actors with a 1-click **Verify Blockchain Integrity** tool.
- **Threat Scenario Simulator**: 1-click generation of realistic detections:
  - `CVE-2024-3094` (XZ Liblzma Supply Chain Backdoor)
  - `CWE-89` (SonarQube SQL Injection in billing gateway)
  - `Port 3389` (Nmap Public RDP exposed on bastion)
  - `SSH Brute Force` (Wazuh EDR dictionary attack)

---

## ⚙️ Configuration & Environment Variables

| Variable | Description | Default / Source |
| :--- | :--- | :--- |
| `WEBHOOK_HMAC_SECRET` | Secret key for verifying sensor webhooks | Stored in `.env` (cryptographically generated if unset) |
| `GEMINI_API_KEY` | Google Gemini API key for live security reasoning | `.env` *(deterministic fallback active if unset)* |
| `GEMINI_MODEL` | Gemini model identifier | `gemini-2.0-flash` |
| `PAM_SIMULATION_MODE` | Dynamic ephemeral simulation mode | `true` |
| `VAULT_ADDR` | HashiCorp Vault server URL | `http://127.0.0.1:8200` |
| `VAULT_TOKEN` | HashiCorp Vault administrative token | Stored in `.env` or Vault AppRole |
| `STANDALONE_MODE` | Use built-in async state machine (zero external daemons) | `true` |
| `TEMPORAL_HOST` | Temporal server endpoint | `localhost:7233` |
| `AUTO_CONTAINMENT_MAX_RISK` | Maximum contextual risk score eligible for auto-containment | `30.0` |

---

## 📡 Webhook Integration Example (cURL with HMAC)

```bash
# Payload
PAYLOAD='{"SchemaVersion": 2, "ArtifactName": "api-gateway:latest", "Results": []}'

# Load HMAC Secret from environment (.env)
SECRET="${WEBHOOK_HMAC_SECRET:-$(grep WEBHOOK_HMAC_SECRET .env | cut -d '=' -f2)}"

# Generate HMAC-SHA256 signature
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

# Dispatch webhook to SecOps-Nexus
curl -X POST http://localhost:8000/api/v1/ingest/webhook?source=TRIVY \
  -H "Content-Type: application/json" \
  -H "X-HMAC-Signature: $SIG" \
  -d "$PAYLOAD"
```
# SecOps-Nexus-AUTONOMOUS-SOC
