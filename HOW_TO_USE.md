# 📖 SecOps-Nexus: Comprehensive Operator & Usage Guide

Welcome to the **SecOps-Nexus** User & Operator Guide. This document provides step-by-step instructions for operating the Autonomous SOC, performing Human-in-the-Loop (HITL) approvals, sending authenticated scanner alerts, and auditing cryptographic supply-chain ledgers.

---

## 📑 Table of Contents

1. [Prerequisites & Quick Start](#1-prerequisites--quick-start)
2. [Operating the SOC Command Center Web UI](#2-operating-the-soc-command-center-web-ui)
3. [Human-in-the-Loop (HITL) Remediation Workflow](#3-human-in-the-loop-hitl-remediation-workflow)
4. [Industrial Real File & Code Security Scanner & Auto-Fix](#4-industrial-real-file--code-security-scanner--auto-fix)
5. [Using the 1-Click Threat Simulator](#5-using-the-1-click-threat-simulator)
6. [Connecting Real Scanners via Zero-Trust HMAC Webhooks](#6-connecting-real-scanners-via-zero-trust-hmac-webhooks)
   - [A. Trivy Container / Filesystem Ingestion](#a-trivy-container--filesystem-ingestion)
   - [B. SonarQube SAST Ingestion](#b-sonarqube-sast-ingestion)
   - [C. Nmap Perimeter Scan Ingestion](#c-nmap-perimeter-scan-ingestion)
   - [D. Wazuh / EDR / SIEM Alert Ingestion](#d-wazuh--edr--siem-alert-ingestion)
7. [Generating HMAC-SHA256 Signatures](#7-generating-hmac-sha256-signatures)
   - [PowerShell (Windows)](#powershell-windows)
   - [Bash / OpenSSL (Linux / macOS)](#bash--openssl-linux--macos)
   - [Python Script](#python-script)
8. [Verifying the WORM Cryptographic Ledger](#8-verifying-the-worm-cryptographic-ledger)
9. [Configuration & Environment Setup](#9-configuration--environment-setup)
   - [Connecting Google Gemini AI](#connecting-google-gemini-ai)
   - [Connecting HashiCorp Vault (PAM)](#connecting-hashicorp-vault-pam)
10. [REST API & Swagger Documentation](#10-rest-api--swagger-documentation)
11. [Running Automated Tests](#11-running-automated-tests)

---

## 1. Prerequisites & Quick Start

### System Requirements
- **Python**: Version 3.11+
- **Network Port**: `8000` (configurable via `PORT` environment variable)

### Launching the Server

#### Option A: Direct Python Command
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

#### Option B: In Windows PowerShell
```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Once started, open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 2. Operating the SOC Command Center Web UI

The Web Dashboard ([`templates/index.html`](file:///e:/ai%20agent/cyber%20tool/1/templates/index.html)) is organized into four main functional sections:

```
┌────────────────────────────────────────────────────────────────────────┐
│  HEADER: Brand, Zero-Trust Ingress Status, PAM Vault, WORM Status       │
├────────────────────────────────────────────────────────────────────────┤
│  KPI METRICS: Total Alerts │ Pending HITL │ Auto-Contained │ CISA KEV  │
├────────────────────────────────────────────────────────────────────────┤
│  SIMULATOR BAR: [ 🚨 CVE-2024-3094 ] [ 💉 SQLi ] [ 🌐 RDP ] [ 🔨 SSH ]  │
├───────────────────────────────────────┬────────────────────────────────┤
│  TRIAGE QUEUE (Filterable Feed)       │  WORM CRYPTOGRAPHIC LEDGER     │
│  - Severity Borders & Risk Scores     │  - Real-Time Hash Chain Stream │
│  - CISA KEV & MITRE Badges            │  - [ Verify Blockchain ] Button│
└───────────────────────────────────────┴────────────────────────────────┘
```

1. **Top Status Ribbon**: Confirms that Zero-Trust HMAC ingress is active, PAM Vault connection is healthy, and the live WebSocket telemetry stream is connected.
2. **KPI Metric Cards**: Displays real-time counts for ingested alerts, pending approval gates, auto-contained actions, and active in-the-wild exploits.
3. **Triage Filter Tabs**:
   - **All Alerts**: Shows the complete queue.
   - **🛑 Pending HITL**: Filters strictly for alerts that require human approval before execution.
   - **⚠️ Critical & KEV**: Filters for CVSS >= 80 or active CISA Known Exploited Vulnerabilities.
   - **🛡️ Resolved**: Shows verified fixes and auto-contained threats.
4. **WORM Cryptographic Ledger**: Live display of append-only audit blocks showing timestamp, event type, actor, and previous/current SHA-256 block hashes.

---

## 3. Human-in-the-Loop (HITL) Remediation Workflow

When an alert is scored above the safety limit (Contextual Risk > 30, Tier 0 Mission Critical asset, or weaponized CISA KEV exploit), the engine automatically **pauses** execution at the **HITL Approval Gate**.

### Step-by-Step Approval Procedure:

1. **Select Alert**: In the Triage Queue, click on any alert displaying `🛑 PENDING APPROVAL` (such as `CVE-2024-3094`).
2. **Review Modal Tabs**:
   - **Overview & Context**: Review target hostname, asset criticality, network exposure, and the AI's executive threat summary.
   - **Gemini Intelligence & MITRE**: Inspect the mapped MITRE ATT&CK tactics (e.g., `TA0001 Initial Access`) and techniques (e.g., `T1195 Supply Chain Compromise`), exploitability rating, and blast radius rationale.
   - **Ansible Remediation Diff**: Review the exact, syntactically-checked Ansible playbook generated by the reasoner, as well as the pre-flight dry-run check command (`ansible-playbook --check --diff`).
   - **PAM Ephemeral Session**: Confirm that PAM has issued a temporary credential with a 5-minute countdown timer.
3. **Enter Approval Notes**: Type an audit note into the input field (e.g., *"Reviewed blast radius and approved for emergency patching"*).
4. **Make Decision**:
   - Click **`[ 🛡️ Approve & Execute Fix ]`**: SecOps-Nexus authenticates with the ephemeral PAM token, applies the Ansible patch, runs post-remediation verification probes, revokes the token, and records a cryptographic block in the WORM ledger. The alert updates to `🛡️ VERIFIED FIXED`.
   - Click **`[ ❌ Reject Remediation ]`**: Pauses remediation, transitions alert to `REJECTED`, and logs the rejection justification into the tamper-evident ledger.

---

## 4. Industrial Real File & Code Security Scanner & Auto-Fix

SecOps-Nexus includes a full-featured, industrial-grade **Static Analysis (SAST), AST Semantic Analyzer, and Auto-Fix Engine** built to scan real source files, detect syntax errors and vulnerabilities, and safely apply verified code patches.

### Supported Scans & Security Checks:
- **Python AST Semantic Inspection**: Detects fatal `SyntaxError` bugs, unsafe `eval()` / `exec()` calls, `subprocess` invocations with `shell=True`, insecure `pickle.loads()`, `yaml.load()` without SafeLoader, and broken cryptographic hashes (`hashlib.md5`, `hashlib.sha1`).
- **Hardcoded Secrets & Cloud Credentials**: AWS Access Keys (`AKIA...`), GitHub Personal Access Tokens (`ghp_...`), OpenAI API keys (`sk-...`), and plaintext password assignments.
- **OWASP Top 10 Injection Vectors**: Raw string formatted SQL queries (`cursor.execute(f"SELECT ... {input}")`), OS command execution (`os.system()`), and path traversal.
- **IaC & Dockerfile Hardening**: Checks for containers running as root (`USER root`) and insecure curl-to-shell pipes (`curl | bash`).

### How to Use the Scanner in the Web Dashboard:
1. Click **`🔬 Real File & Code Security Scanner & Auto-Fix`** in the top navigation bar.
2. Enter a relative or absolute file path (e.g. `src/server.py` or `.`) or click **`🧪 Generate Test Vulnerable File`** to create an immediate real test subject.
3. Click **`🔍 Analyze File`** or **`📁 Scan Entire Codebase`**.
4. Review the findings table:
   - **Vulnerable Code**: Highlighted in red with exact line numbers.
   - **Recommended Fix**: Highlighted in green with secure code replacement.
   - **Git Diff Patch**: Unified git diff preview.
5. Click **`🛡️ Apply Auto-Fix`**:
   - The engine creates an atomic, timestamped backup file (`<filepath>.bak.<timestamp>`).
   - Applies the patch in memory.
   - Performs a **pre-flight Python AST syntax check** to guarantee no syntax errors or breaking code are introduced.
   - Commits the patch to disk and records an immutable block in the WORM Cryptographic Ledger.
   - Reveals an immediate **`↩️ Rollback Patch`** button if you wish to revert.

### CLI & REST API Usage:

#### 1. Scan a Single File
```bash
curl -X POST "http://localhost:8000/api/v1/scan/file?file_path=src/app.py"
```

#### 2. Scan an Entire Directory
```bash
curl -X POST "http://localhost:8000/api/v1/scan/directory?dir_path=.&max_files=200"
```

#### 3. Apply an Auto-Fix Programmatically
```bash
curl -X POST "http://localhost:8000/api/v1/fix/apply" \
  -d "file_path=src/app.py" \
  -d "line_number=14" \
  -d "original_code=os.system('ping ' + user_input)" \
  -d "remediated_code=    subprocess.run(['ping', user_input], check=True)" \
  -d "approver_name=SOC_Lead"
```

#### 4. Rollback a Patch
```bash
curl -X POST "http://localhost:8000/api/v1/fix/rollback?file_path=src/app.py&backup_path=src/app.py.bak.20261023_075524"
```

---

## 5. Using the 1-Click Threat Simulator

To test the system immediately without external scanners, click any of the scenario buttons located in the **Interactive Simulator Bar**:

| Simulation Button | Simulated Detection | Triggered Behavior |
| :--- | :--- | :--- |
| **🚨 CVE-2024-3094** | Trivy scan discovering liblzma upstream backdoor in `k8s-prod-ingress-gateway` | High risk (100/100). Mandates **HITL Approval**. Generates xz-utils downgrade & sshd restart Ansible playbook. |
| **💉 SonarQube SQLi** | SAST detecting unescaped user input in `checkout_controller.py` | Medium risk. Generates ModSecurity/Nginx emergency WAF rule. Eligible for auto-containment or review. |
| **🌐 Nmap Port 3389** | Perimeter port scanner finding public RDP on bastion host | High exposure. Formulates iptables network perimeter closure playbook. |
| **🔨 Wazuh EDR** | Host sensor detecting 25 failed SSH logins in 30 seconds from malicious IP | Active intrusion. Generates fail2ban & iptables drop rule to isolate the attacker IP. |

You can also trigger these scenarios programmatically via HTTP:
```bash
curl -X POST "http://localhost:8000/api/v1/simulator/trigger?scenario=xz_backdoor"
curl -X POST "http://localhost:8000/api/v1/simulator/trigger?scenario=sqli_attack"
curl -X POST "http://localhost:8000/api/v1/simulator/trigger?scenario=exposed_rdp"
curl -X POST "http://localhost:8000/api/v1/simulator/trigger?scenario=wazuh_brute_force"
```

---

## 5. Connecting Real Scanners via Zero-Trust HMAC Webhooks

All external sensor webhooks must be sent to:
`POST /api/v1/ingest/webhook?source={TRIVY|SONARQUBE|NMAP|WAZUH_EDR}`

### Zero-Trust Header Requirement:
Every request must include the HMAC-SHA256 signature header:
- Header: `X-HMAC-Signature: <64-character-hex-digest>` (or `X-Hub-Signature-256: sha256=<hex>`)
- Shared Secret: Securely stored in your `.env` file as `WEBHOOK_HMAC_SECRET` (see `.env.example`).

---

### A. Trivy Container / Filesystem Ingestion

Configure your CI/CD pipeline (GitHub Actions, GitLab CI, or Jenkins) to output JSON and POST to SecOps-Nexus:

```bash
# Run Trivy Scan
trivy image --format json -o trivy_report.json my-app:latest

# Send to SecOps-Nexus using Python helper (loads WEBHOOK_HMAC_SECRET from environment/.env)
python scripts/send_webhook.py --source TRIVY --file trivy_report.json
```

**JSON Payload Schema:**
```json
{
  "SchemaVersion": 2,
  "ArtifactName": "payment-service:v3.2",
  "Results": [
    {
      "Target": "payment-service (debian 12)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-4863",
          "PkgName": "libwebp",
          "InstalledVersion": "1.2.4",
          "FixedVersion": "1.3.2",
          "Severity": "CRITICAL",
          "Title": "Heap buffer overflow in libwebp",
          "Description": "Heap buffer overflow in WebP codec permitting arbitrary code execution.",
          "CVSS": {
            "nvd": { "V3Score": 8.8 }
          }
        }
      ]
    }
  ]
}
```

---

### B. SonarQube SAST Ingestion

In your SonarQube Project:
1. Navigate to **Project Settings** > **Webhooks**.
2. Set URL to: `http://<secops-nexus-host>:8000/api/v1/ingest/webhook?source=SONARQUBE`
3. Enter Secret: `${WEBHOOK_HMAC_SECRET}` (the secret defined in your secure `.env`)

**JSON Payload Schema:**
```json
{
  "project": { "name": "auth-microservice" },
  "issues": [
    {
      "rule": "python:S3649",
      "severity": "CRITICAL",
      "component": "src/controllers/auth.py",
      "line": 88,
      "message": "Direct concatenation into raw SQL statement detected."
    }
  ]
}
```

---

### C. Nmap Perimeter Scan Ingestion

**JSON Payload Schema:**
```json
{
  "ip": "198.51.100.45",
  "hostname": "prod-bastion-external",
  "ports": [
    {
      "port": 3389,
      "service": "ms-wbt-server",
      "state": "open"
    }
  ]
}
```

---

### D. Wazuh / EDR / SIEM Alert Ingestion

In Wazuh `ossec.conf`:
```xml
<integration>
  <name>custom-secops-nexus</name>
  <hook_url>http://127.0.0.1:8000/api/v1/ingest/webhook?source=WAZUH_EDR</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

**JSON Payload Schema:**
```json
{
  "agent": {
    "name": "edge-proxy-01",
    "ip": "10.0.1.20"
  },
  "rule": {
    "id": "5710",
    "level": 10,
    "description": "sshd: Excessive unauthorized authentication failures",
    "mitre": {
      "tactic": ["Credential Access"],
      "id": ["T1110"]
    }
  },
  "full_log": "sshd[1243]: Failed password for invalid user admin from 203.0.113.55 port 55122"
}
```

---

## 6. Generating HMAC-SHA256 Signatures

### PowerShell (Windows)
```powershell
# Read from environment or local .env
$secret = $env:WEBHOOK_HMAC_SECRET
if (-not $secret -and (Test-Path ".env")) {
    $secret = (Get-Content .env | Select-String "WEBHOOK_HMAC_SECRET=").ToString().Split("=")[1].Trim()
}
$body = Get-Content -Raw -Path "report.json"

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
$hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
$signature = [BitConverter]::ToString($hash).Replace("-", "").ToLower()

# Dispatch authenticated webhook
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ingest/webhook?source=TRIVY" `
  -Method POST `
  -Headers @{ "Content-Type" = "application/json"; "X-HMAC-Signature" = $signature } `
  -Body $body
```

### Bash / OpenSSL (Linux / macOS)
```bash
# Read from environment or .env file
SECRET="${WEBHOOK_HMAC_SECRET:-$(grep WEBHOOK_HMAC_SECRET .env | cut -d '=' -f2)}"
PAYLOAD=$(cat report.json)

# Calculate HMAC-SHA256 signature
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

# Dispatch webhook
curl -X POST "http://localhost:8000/api/v1/ingest/webhook?source=TRIVY" \
  -H "Content-Type: application/json" \
  -H "X-HMAC-Signature: $SIG" \
  -d "$PAYLOAD"
```

### Python Script
```python
import os
import hmac
import hashlib
import httpx
from dotenv import load_dotenv

load_dotenv()
SECRET = os.getenv("WEBHOOK_HMAC_SECRET", "")
payload_bytes = open("report.json", "rb").read()

signature = hmac.new(SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()

response = httpx.post(
    "http://127.0.0.1:8000/api/v1/ingest/webhook?source=TRIVY",
    headers={"X-HMAC-Signature": signature, "Content-Type": "application/json"},
    content=payload_bytes
)
print("Status:", response.status_code, response.json())
```

---

## 7. Verifying the WORM Cryptographic Ledger

Every action (ingestion, risk calculation, AI reasoning, approval decision, Ansible execution, verification probe) creates an immutable block linked by SHA-256:

$$\text{Current Hash} = \text{SHA256}(\text{Index} + \text{Timestamp} + \text{Event} + \text{Actor} + \text{Payload SHA256} + \text{Previous Hash})$$

### In the Web UI:
1. Locate the **WORM Audit Ledger** in the right column of the dashboard.
2. Click **`🔍 Verify Blockchain Integrity`**.
3. A modal appears displaying total verified blocks, genesis hash, tip hash, and integrity status.

### Via API:
```bash
curl http://localhost:8000/api/v1/audit/verify
```

**Response Example:**
```json
{
  "is_valid": true,
  "total_records": 32,
  "genesis_hash": "528a245a87863a8da87f3e9bb1b87ffcaf38b1252edb32a684a6760cdfe533b4",
  "latest_hash": "a4d38c11e749a2bf1892c90df0319241852077e63b652882191db0285a7ce623",
  "broken_link_index": null,
  "message": "WORM Audit Ledger Integrity Verified: All cryptographic links intact."
}
```

---

## 8. Configuration & Environment Setup

All settings can be customized in [`config.py`](file:///e:/ai%20agent/cyber%20tool/1/config.py) or overridden using environment variables.

### Connecting Google Gemini AI
By default, the platform includes a deterministic security reasoning engine that runs offline with zero API keys required. To enable live reasoning with Google Gemini 2.0 / 1.5 Flash:

```bash
# In your terminal or .env file:
export GEMINI_API_KEY="AIzaSyYourGeminiApiKeyHere"
export GEMINI_MODEL="gemini-2.0-flash"
```
Or on Windows PowerShell:
```powershell
$env:GEMINI_API_KEY="AIzaSyYourGeminiApiKeyHere"
```

### Connecting HashiCorp Vault (PAM)
By default, `PAM_SIMULATION_MODE=true` issues realistic ephemeral credentials. To connect to a live enterprise HashiCorp Vault cluster:

```bash
export PAM_SIMULATION_MODE="false"
export VAULT_ADDR="https://vault.corp.internal:8200"
export VAULT_TOKEN="s.YourAppRoleOrAdminToken"
```

### Tuning Safety & Auto-Containment Thresholds
- `AUTO_CONTAINMENT_MAX_RISK`: Contextual risk score threshold below which low-blast actions are auto-contained without pausing for human approval (Default: `30.0`).
- `EPHEMERAL_TOKEN_TTL_SECONDS`: Validity window for PAM credentials (Default: `300` seconds / 5 minutes).

---

## 9. REST API & Swagger Documentation

SecOps-Nexus provides interactive API documentation out of the box:
- **Swagger UI**: **[http://localhost:8000/docs](http://localhost:8000/docs)**
- **ReDoc UI**: **[http://localhost:8000/redoc](http://localhost:8000/redoc)**

### Key API Endpoints:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Interactive Cyber Command Center Web Dashboard |
| `/api/v1/alerts` | `GET` | List all triaged alerts with risk scores and lifecycle states |
| `/api/v1/alerts/{id}` | `GET` | Deep detail: AI reasoning, Ansible playbook, blast radius |
| `/api/v1/alerts/{id}/hitl` | `POST` | Submit Human-in-the-Loop decision (`APPROVED` or `REJECTED`) |
| `/api/v1/ingest/webhook` | `POST` | Zero-Trust HMAC-validated webhook ingestion |
| `/api/v1/simulator/trigger` | `POST` | Trigger test scenario (`xz_backdoor`, `sqli_attack`, etc.) |
| `/api/v1/audit/records` | `GET` | Retrieve latest blocks from the WORM cryptographic ledger |
| `/api/v1/audit/verify` | `GET` | Cryptographically verify the integrity of the audit blockchain |
| `/api/v1/stats` | `GET` | Aggregated SOC counts (pending approvals, KEV count, etc.) |
| `/ws/stream` | `WebSocket` | Real-time live event broadcast stream |

---

## 10. Running Automated Tests

SecOps-Nexus comes with an automated unit and integration test suite ([`tests/test_secops_nexus.py`](file:///e:/ai%20agent/cyber%20tool/1/tests/test_secops_nexus.py)) validating HMAC checks, input sanitization, risk calculation, WORM audit verification, and HITL state transitions:

```bash
python -m pytest tests/ -v
```

**Expected Result:**
```
tests/test_secops_nexus.py::test_hmac_zero_trust_signature PASSED        [ 14%]
tests/test_secops_nexus.py::test_prompt_injection_sanitization PASSED    [ 28%]
tests/test_secops_nexus.py::test_contextual_risk_scoring PASSED          [ 42%]
tests/test_secops_nexus.py::test_worm_cryptographic_audit_ledger PASSED  [ 57%]
tests/test_secops_nexus.py::test_pam_ephemeral_token_lifecycle PASSED    [ 71%]
tests/test_secops_nexus.py::test_gemini_reasoner_ansible_synthesis PASSED [ 85%]
tests/test_secops_nexus.py::test_orchestrator_hitl_workflow PASSED       [100%]
============================== 7 passed in 1.71s ==============================
```

---

*SecOps-Nexus — Autonomous Security Engineering & Zero-Trust Governance.*
