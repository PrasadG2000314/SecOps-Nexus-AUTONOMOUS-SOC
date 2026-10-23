/**
 * SecOps-Nexus Interactive Command Center Client
 * Handles real-time WebSockets, alert triage, simulator triggers,
 * HITL approval decisions, and cryptographic WORM ledger verification.
 */

// Global State
let allAlerts = [];
let currentFilter = 'all';
let selectedAlert = null;
let ws = null;
let pamInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    fetchAlerts();
    fetchAuditLedger();
    fetchStats();
    setupEventListeners();
});

// ==========================================
// 1. WebSocket Telemetry Stream
// ==========================================
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/stream`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('[WEBSOCKET] Connected to SecOps-Nexus telemetry stream.');
        const statusEl = document.getElementById('ws-status-text');
        if (statusEl) statusEl.textContent = 'TELEMETRY LIVE';
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleIncomingTelemetry(msg);
        } catch (e) {
            console.error('[WEBSOCKET] Parse error:', e);
        }
    };

    ws.onclose = () => {
        console.warn('[WEBSOCKET] Disconnected. Reconnecting in 3s...');
        const statusEl = document.getElementById('ws-status-text');
        if (statusEl) statusEl.textContent = 'RECONNECTING';
        setTimeout(initWebSocket, 3000);
    };
}

function handleIncomingTelemetry(msg) {
    if (msg.type === 'ALERT_PROCESSED' || msg.type === 'HITL_RESOLVED' || msg.type === 'ALERT_UPDATED') {
        fetchAlerts();
        fetchAuditLedger();
        fetchStats();
    }
}

// ==========================================
// 2. Data Fetching
// ==========================================
async function fetchAlerts() {
    try {
        const res = await fetch('/api/v1/alerts');
        const data = await res.json();
        allAlerts = data.alerts || [];
        renderAlerts();
    } catch (err) {
        console.error('Failed to fetch alerts:', err);
    }
}

async function fetchAuditLedger() {
    try {
        const res = await fetch('/api/v1/audit/records?limit=30');
        const data = await res.json();
        renderAuditTrail(data.records || []);
    } catch (err) {
        console.error('Failed to fetch audit ledger:', err);
    }
}

async function fetchStats() {
    try {
        const res = await fetch('/api/v1/stats');
        const stats = await res.json();
        
        document.getElementById('stat-total-alerts').textContent = stats.total_alerts || 0;
        document.getElementById('stat-pending-hitl').textContent = stats.pending_hitl || 0;
        document.getElementById('stat-auto-contained').textContent = stats.auto_contained || 0;
        document.getElementById('stat-cisa-kev').textContent = stats.cisa_kev_active || 0;
        document.getElementById('stat-audit-blocks').textContent = stats.total_audit_blocks || 0;
    } catch (err) {
        console.error('Failed to fetch stats:', err);
    }
}

// ==========================================
// 3. Rendering Alerts & Triage
// ==========================================
function renderAlerts() {
    const container = document.getElementById('alert-list-container');
    const badgeCount = document.getElementById('alert-filter-count');

    let filtered = allAlerts;
    if (currentFilter === 'pending') {
        filtered = allAlerts.filter(a => a.status === 'AWAITING_APPROVAL' || a.status === 'AWAITING_HITL');
    } else if (currentFilter === 'critical') {
        filtered = allAlerts.filter(a => a.severity === 'CRITICAL' || a.cisa_kev_active);
    } else if (currentFilter === 'auto') {
        filtered = allAlerts.filter(a => a.status === 'AUTO_CONTAINED' || a.status === 'VERIFIED');
    }

    if (badgeCount) badgeCount.textContent = `${filtered.length} Alerts`;

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No alerts matching "${currentFilter}" filter.</p>
                <p style="font-size: 0.8rem; margin-top: 0.5rem; color: var(--neon-cyan);">
                    Click one of the simulation triggers above to generate live threats!
                </p>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(alert => {
        const sevClass = (alert.severity || 'medium').toLowerCase();
        const statusClass = (alert.status || '').toLowerCase().replace(/_/g, '-');
        
        let statusBadge = `<span class="status-pill ${statusClass}">${alert.status}</span>`;
        if (alert.status === 'AWAITING_APPROVAL' || alert.status === 'AWAITING_HITL') {
            statusBadge = `<span class="status-pill awaiting">🛑 PENDING APPROVAL</span>`;
        } else if (alert.status === 'VERIFIED') {
            statusBadge = `<span class="status-pill verified">🛡️ VERIFIED FIXED</span>`;
        } else if (alert.status === 'AUTO_CONTAINED') {
            statusBadge = `<span class="status-pill auto_contained">⚡ AUTO-CONTAINED</span>`;
        }

        return `
            <div class="alert-item ${sevClass}" onclick="openAlertDetails('${alert.id}')">
                <div class="alert-main">
                    <div class="alert-tags">
                        <span class="tag source">${alert.source}</span>
                        ${alert.cve ? `<span class="tag cve">${alert.cve}</span>` : ''}
                        ${alert.cisa_kev_active ? `<span class="tag kev">⚠️ CISA KEV ACTIVE</span>` : ''}
                        <span class="tag" style="background: rgba(255,255,255,0.06); font-family: var(--font-mono);">${alert.hostname}</span>
                    </div>
                    <div class="alert-title">${escapeHtml(alert.title)}</div>
                    <div class="alert-meta">
                        <span>CVSS: <b>${alert.cvss.toFixed(1)}</b></span>
                        <span>Blast Radius: <b>${alert.blast_radius}</b></span>
                        <span>Env: <b>${alert.criticality}</b></span>
                    </div>
                </div>
                <div class="alert-risk-score">
                    <div class="risk-number ${sevClass}">${alert.risk_score.toFixed(1)}</div>
                    <div style="font-size: 0.65rem; color: var(--text-dim); font-family: var(--font-mono); text-transform: uppercase;">Contextual Risk</div>
                    ${statusBadge}
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================
// 4. Rendering WORM Audit Ledger
// ==========================================
function renderAuditTrail(records) {
    const container = document.getElementById('audit-stream-container');
    if (!container) return;

    if (!records || records.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No audit blocks recorded yet.</p></div>`;
        return;
    }

    container.innerHTML = records.map(rec => {
        const timeStr = new Date(rec.timestamp).toLocaleTimeString();
        return `
            <div class="audit-block">
                <div class="audit-block-header">
                    <span class="audit-index">#${rec.index}</span>
                    <span class="audit-event-type">${rec.event_type}</span>
                    <span class="audit-time">${timeStr}</span>
                </div>
                <div class="audit-actor">${rec.actor} ${rec.alert_id ? `[${rec.alert_id}]` : ''}</div>
                <div class="audit-hash-chain">
                    <span><b>PREV:</b> ${rec.previous_hash.substring(0, 16)}...</span>
                    <span><b>HASH:</b> ${rec.current_hash.substring(0, 16)}...</span>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================
// 5. Deep Inspection & HITL Modal Logic
// ==========================================
async function openAlertDetails(alertId) {
    try {
        const res = await fetch(`/api/v1/alerts/${alertId}`);
        if (!res.ok) throw new Error('Alert not found');
        const data = await res.json();
        selectedAlert = data;
        populateModal(data);
        document.getElementById('hitl-modal').classList.add('open');
    } catch (err) {
        alert(`Failed to load alert details: ${err.message}`);
    }
}

function populateModal(data) {
    const { alert, state, ai_analysis, hitl_decision, execution_result } = data;

    document.getElementById('modal-alert-id').textContent = alert.id;
    document.getElementById('modal-title').textContent = alert.vulnerability.title;

    // Overview Tab
    document.getElementById('modal-cve').textContent = alert.vulnerability.cve_id || 'N/A';
    document.getElementById('modal-cvss').textContent = `${alert.vulnerability.cvss_base_score} (Context: ${alert.contextual_risk_score}/100)`;
    document.getElementById('modal-host').textContent = `${alert.asset.hostname} (${alert.asset.ip_address})`;
    document.getElementById('modal-criticality').textContent = alert.asset.criticality;
    document.getElementById('modal-exposure').textContent = alert.asset.exposure;
    document.getElementById('modal-source').textContent = alert.source;

    // AI Intelligence
    if (ai_analysis) {
        document.getElementById('modal-summary').textContent = ai_analysis.executive_summary;
        document.getElementById('modal-exploit').textContent = ai_analysis.exploitability_assessment;
        document.getElementById('modal-blast').textContent = `${ai_analysis.blast_radius} - ${ai_analysis.blast_radius_rationale}`;
        
        // MITRE Badges
        const mitreContainer = document.getElementById('modal-mitre-tags');
        const allMitre = [...(ai_analysis.mitre_attack_tactics || []), ...(ai_analysis.mitre_attack_techniques || [])];
        mitreContainer.innerHTML = allMitre.map(t => `<span class="tag cve">${t}</span>`).join(' ');

        // Ansible Playbook
        document.getElementById('modal-ansible-code').textContent = ai_analysis.ansible_playbook_yaml;
        document.getElementById('modal-dryrun-cmd').textContent = ai_analysis.dry_run_command;
    } else {
        document.getElementById('modal-summary').textContent = 'AI Reasoning pending or unavailable.';
    }

    // Execution / Verification
    const execBox = document.getElementById('modal-exec-container');
    if (execution_result) {
        execBox.style.display = 'block';
        document.getElementById('modal-exec-stdout').textContent = execution_result.stdout;
        document.getElementById('modal-verification-text').textContent = execution_result.verification_details;
    } else {
        execBox.style.display = 'none';
    }

    // PAM Countdown
    startPamCountdown();

    // HITL Buttons state
    const hitlActions = document.getElementById('hitl-action-bar');
    const isPending = (state === 'AWAITING_APPROVAL' || state === 'AWAITING_HITL');
    if (isPending) {
        hitlActions.style.display = 'flex';
    } else {
        hitlActions.style.display = 'none';
    }

    // Switch to first tab by default
    switchModalTab('overview');
}

function startPamCountdown() {
    if (pamInterval) clearInterval(pamInterval);
    let secondsLeft = 300;
    const el = document.getElementById('pam-timer-display');
    
    function tick() {
        const m = Math.floor(secondsLeft / 60);
        const s = secondsLeft % 60;
        if (el) el.textContent = `${m}:${s < 10 ? '0' : ''}${s}`;
        if (secondsLeft > 0) secondsLeft--;
        else clearInterval(pamInterval);
    }
    tick();
    pamInterval = setInterval(tick, 1000);
}

function switchModalTab(tabId) {
    document.querySelectorAll('.modal-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const tabBtn = document.querySelector(`.modal-tab[data-tab="${tabId}"]`);
    const pane = document.getElementById(`tab-pane-${tabId}`);
    if (tabBtn) tabBtn.classList.add('active');
    if (pane) pane.classList.add('active');
}

function closeModal() {
    document.getElementById('hitl-modal').classList.remove('open');
    if (pamInterval) clearInterval(pamInterval);
    selectedAlert = null;
}

// ==========================================
// 6. HITL Decisions (Approve / Reject)
// ==========================================
async function submitHitl(decision) {
    if (!selectedAlert) return;
    const alertId = selectedAlert.alert.id;
    const notesInput = document.getElementById('hitl-notes-field');
    const notes = notesInput.value.trim() || (decision === 'APPROVED' ? 'Approved after review' : 'Rejected by engineer');

    try {
        const res = await fetch(`/api/v1/alerts/${alertId}/hitl?decision=${decision}&notes=${encodeURIComponent(notes)}`, {
            method: 'POST'
        });
        const result = await res.json();
        
        // Show result feedback
        if (decision === 'APPROVED') {
            alert(`🛡️ Remediation Approved & Executed successfully for ${alertId}!`);
        } else {
            alert(`Remediation for ${alertId} was Rejected.`);
        }
        
        closeModal();
        fetchAlerts();
        fetchAuditLedger();
        fetchStats();
    } catch (err) {
        alert(`Failed to submit HITL decision: ${err.message}`);
    }
}

// ==========================================
// 7. Threat Simulation Triggers
// ==========================================
async function triggerSimulation(scenario) {
    try {
        const btn = document.querySelector(`[onclick="triggerSimulation('${scenario}')"]`);
        if (btn) btn.style.opacity = '0.5';

        const res = await fetch(`/api/v1/simulator/trigger?scenario=${scenario}`, { method: 'POST' });
        const data = await res.json();
        
        console.log('Simulated scenario triggered:', data);
        if (btn) btn.style.opacity = '1';

        fetchAlerts();
        fetchAuditLedger();
        fetchStats();
    } catch (err) {
        alert(`Simulation failed: ${err.message}`);
    }
}

// ==========================================
// 8. Cryptographic Chain Verification
// ==========================================
async function verifyAuditLedger() {
    try {
        const res = await fetch('/api/v1/audit/verify');
        const data = await res.json();

        if (data.is_valid) {
            alert(`✅ WORM CRYPTOGRAPHIC LEDGER VERIFIED!\n\nAll ${data.total_records} blocks are cryptographically intact.\nGenesis: ${data.genesis_hash.substring(0, 16)}...\nTip: ${data.latest_hash.substring(0, 16)}...\nNo tampering detected.`);
        } else {
            alert(`❌ TAMPER DETECTED!\nBroken link at block #${data.broken_link_index}\nReason: ${data.message}`);
        }
    } catch (err) {
        alert(`Verification failed: ${err.message}`);
    }
}

// ==========================================
// 9. Event Listeners & Helpers
// ==========================================
function setupEventListeners() {
    // Filter Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            renderAlerts();
        });
    });

    // Modal Tabs
    document.querySelectorAll('.modal-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            switchModalTab(btn.getAttribute('data-tab'));
        });
    });

    // Close Modal on Esc key
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ==========================================
// 10. REAL FILE & CODE SECURITY SCANNER & AUTO-FIX
// ==========================================
function switchViewMode(mode) {
    const socBtn = document.getElementById('btn-mode-soc');
    const scannerBtn = document.getElementById('btn-mode-scanner');
    const socGrid = document.getElementById('soc-main-grid');
    const socSim = document.getElementById('soc-simulator-bar');
    const scannerPanel = document.getElementById('real-file-scanner-panel');

    if (mode === 'scanner') {
        socBtn.classList.remove('active');
        scannerBtn.classList.add('active');
        socGrid.style.display = 'none';
        socSim.style.display = 'none';
        scannerPanel.style.display = 'flex';
    } else {
        scannerBtn.classList.remove('active');
        socBtn.classList.add('active');
        scannerPanel.style.display = 'none';
        socGrid.style.display = 'grid';
        socSim.style.display = 'flex';
    }
}

async function generateVulnerableSample() {
    try {
        const res = await fetch('/api/v1/simulator/generate-sample', { method: 'POST' });
        const data = await res.json();
        document.getElementById('scan-target-path').value = data.file_path;
        runFileScan();
    } catch (e) {
        // Fallback: direct path
        document.getElementById('scan-target-path').value = 'vulnerable_sample.py';
        runFileScan();
    }
}

async function runFileScan() {
    const pathInput = document.getElementById('scan-target-path');
    const filePath = pathInput.value.trim();
    if (!filePath) {
        alert('Please enter a valid file path to scan.');
        return;
    }

    const statusBadge = document.getElementById('scanner-file-status');
    const container = document.getElementById('scan-findings-container');
    const summaryBar = document.getElementById('scan-summary-bar');

    statusBadge.textContent = 'SCANNING...';
    container.innerHTML = `<div class="empty-state"><p>Analyzing file AST and matching security rules for <b>${escapeHtml(filePath)}</b>...</p></div>`;

    try {
        const res = await fetch(`/api/v1/scan/file?file_path=${encodeURIComponent(filePath)}`, { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Scan failed');
        }
        const data = await res.json();

        // Update Summary
        statusBadge.textContent = `${data.issues.length} Issues Found`;
        summaryBar.style.display = 'block';
        document.getElementById('scan-res-path').textContent = data.file_name;
        document.getElementById('scan-res-total').textContent = data.issues.length;
        document.getElementById('scan-res-critical').textContent = data.issues.filter(i => i.severity === 'CRITICAL').length;
        document.getElementById('scan-res-risk').textContent = `${data.risk_score} / 100`;

        renderScanFindings(data.issues, data.file_path);
        fetchStats();
        fetchAuditLedger();
    } catch (err) {
        statusBadge.textContent = 'ERROR';
        container.innerHTML = `<div class="empty-state" style="color: var(--color-critical);"><p>Error scanning file: ${escapeHtml(err.message)}</p></div>`;
    }
}

async function runDirectoryScan() {
    const pathInput = document.getElementById('scan-target-path');
    const dirPath = pathInput.value.trim() || '.';
    const statusBadge = document.getElementById('scanner-file-status');
    const container = document.getElementById('scan-findings-container');
    const summaryBar = document.getElementById('scan-summary-bar');

    statusBadge.textContent = 'SCANNING DIRECTORY...';
    container.innerHTML = `<div class="empty-state"><p>Recursively analyzing codebase in <b>${escapeHtml(dirPath)}</b>...</p></div>`;

    try {
        const res = await fetch(`/api/v1/scan/directory?dir_path=${encodeURIComponent(dirPath)}`, { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Directory scan failed');
        }
        const data = await res.json();

        statusBadge.textContent = `${data.total_issues} Issues in ${data.files_scanned} Files`;
        summaryBar.style.display = 'block';
        document.getElementById('scan-res-path').textContent = `${data.files_scanned} files (${data.scan_duration_ms}ms)`;
        document.getElementById('scan-res-total').textContent = data.total_issues;
        document.getElementById('scan-res-critical').textContent = data.critical_count;
        document.getElementById('scan-res-risk').textContent = `${data.critical_count > 0 ? 95 : 50} / 100`;

        // Flatten all issues from all scanned files
        let allIssues = [];
        data.file_results.forEach(fr => {
            allIssues.push(...fr.issues);
        });

        renderScanFindings(allIssues, dirPath);
        fetchStats();
        fetchAuditLedger();
    } catch (err) {
        statusBadge.textContent = 'ERROR';
        container.innerHTML = `<div class="empty-state" style="color: var(--color-critical);"><p>Error scanning directory: ${escapeHtml(err.message)}</p></div>`;
    }
}

function renderScanFindings(issues, basePath) {
    const container = document.getElementById('scan-findings-container');
    if (!issues || issues.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="color: var(--color-success);">
                <h3>🛡️ Clean Security Audit!</h3>
                <p>Zero security flaws, unhandled syntax errors, or hardcoded credentials detected.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = issues.map((iss, idx) => {
        const cardId = `finding-card-${idx}`;
        const sevClass = (iss.severity || 'medium').toLowerCase();

        return `
            <div class="finding-card ${sevClass}" id="${cardId}">
                <div class="finding-header">
                    <div>
                        <span class="status-pill ${sevClass}" style="margin-right: 0.5rem;">${iss.severity}</span>
                        <span class="tag cve">${iss.rule_id}</span>
                        ${iss.cwe_id ? `<span class="tag" style="background: rgba(255,255,255,0.06); font-family: var(--font-mono);">${iss.cwe_id}</span>` : ''}
                        <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted); margin-left: 0.5rem;">
                            📍 Line ${iss.line_number} in <b>${escapeHtml(iss.file_path.split(/[\\\\/]/).pop())}</b>
                        </span>
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 0.85rem; font-weight: 700; color: var(--color-${sevClass});">
                        CVSS: ${iss.cvss_score.toFixed(1)}
                    </div>
                </div>

                <div class="finding-title">${escapeHtml(iss.title)}</div>
                <p style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(iss.description)}</p>

                <div class="code-compare-grid">
                    <div>
                        <div style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--color-critical); margin-bottom: 0.25rem;">
                            VULNERABLE CODE:
                        </div>
                        <div class="code-box-vulnerable">${escapeHtml(iss.vulnerable_code)}</div>
                    </div>
                    <div>
                        <div style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--color-success); margin-bottom: 0.25rem;">
                            RECOMMENDED FIX:
                        </div>
                        <div class="code-box-fix">${escapeHtml(iss.recommended_fix)}</div>
                    </div>
                </div>

                ${iss.remediation_diff ? `
                    <div>
                        <div style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--neon-cyan); margin-bottom: 0.25rem;">
                            PROPOSED GIT DIFF PATCH:
                        </div>
                        <div class="diff-preview">${formatDiff(iss.remediation_diff)}</div>
                    </div>
                ` : ''}

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
                    <div id="${cardId}-status" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">
                        Backup will be created automatically before patching.
                    </div>
                    <div style="display: flex; gap: 0.5rem;" id="${cardId}-actions">
                        <button type="button" class="btn-hitl approve" onclick="applyCodeFix('${escapeHtml(iss.file_path)}', ${iss.line_number}, '${escapeJsString(iss.vulnerable_code)}', '${escapeJsString(iss.recommended_fix)}', '${cardId}')">
                            🛡️ Apply Auto-Fix
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function formatDiff(diffText) {
    return escapeHtml(diffText).split('\n').map(line => {
        if (line.startsWith('+') && !line.startsWith('+++')) {
            return `<span class="diff-add">${line}</span>`;
        } else if (line.startsWith('-') && !line.startsWith('---')) {
            return `<span class="diff-del">${line}</span>`;
        }
        return line;
    }).join('\n');
}

function escapeJsString(str) {
    if (!str) return '';
    return str.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\\n/g, '\\\\n');
}

async function applyCodeFix(filePath, lineNo, origCode, fixCode, cardId) {
    const statusEl = document.getElementById(`${cardId}-status`);
    const actionsEl = document.getElementById(`${cardId}-actions`);

    statusEl.innerHTML = `<span style="color: var(--neon-cyan);">Applying patch with pre-flight syntax check...</span>`;

    try {
        const res = await fetch(`/api/v1/fix/apply?file_path=${encodeURIComponent(filePath)}&line_number=${lineNo}&original_code=${encodeURIComponent(origCode)}&remediated_code=${encodeURIComponent(fixCode)}&approver_name=SOC_Lead`, {
            method: 'POST'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Patch failed');

        statusEl.innerHTML = `<span style="color: var(--color-success); font-weight: 600;">✅ Patched! Backup: ${escapeHtml(data.backup_path)}</span>`;
        actionsEl.innerHTML = `
            <button type="button" class="btn-hitl reject" onclick="rollbackCodeFix('${escapeHtml(filePath)}', '${escapeJsString(data.backup_path)}', '${cardId}')">
                ↩️ Rollback Patch
            </button>
        `;

        fetchAuditLedger();
        fetchStats();
    } catch (err) {
        statusEl.innerHTML = `<span style="color: var(--color-critical);">❌ ${escapeHtml(err.message)}</span>`;
    }
}

async function rollbackCodeFix(filePath, backupPath, cardId) {
    const statusEl = document.getElementById(`${cardId}-status`);
    try {
        const res = await fetch(`/api/v1/fix/rollback?file_path=${encodeURIComponent(filePath)}&backup_path=${encodeURIComponent(backupPath)}`, {
            method: 'POST'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Rollback failed');

        statusEl.innerHTML = `<span style="color: var(--color-warning);">↩️ Rolled back to original state.</span>`;
        runFileScan();
    } catch (err) {
        statusEl.innerHTML = `<span style="color: var(--color-critical);">❌ Rollback failed: ${escapeHtml(err.message)}</span>`;
    }
}
