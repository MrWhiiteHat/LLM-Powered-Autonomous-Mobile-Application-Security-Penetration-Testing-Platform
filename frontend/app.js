/**
 * MSA — Mobile Security Agent v2.0
 * Advanced Frontend Controller
 * Live Terminal + Donut Chart + Scan History
 */
const API_BASE = '';
let currentScanId = null;
let pollInterval = null;
let logPollInterval = null;
let lastLogLength = 0;

// ─── Navigation ───
function initNav() {
    const header = document.getElementById('main-header');
    const hamburger = document.getElementById('hamburger-btn');
    const mobileMenu = document.getElementById('mobile-menu');

    window.addEventListener('scroll', () => {
        header.classList.toggle('scrolled', window.scrollY > 10);
    });

    hamburger.addEventListener('click', () => {
        hamburger.classList.toggle('active');
        mobileMenu.classList.toggle('hidden');
    });

    document.querySelectorAll('.mobile-link').forEach(link => {
        link.addEventListener('click', () => {
            hamburger.classList.remove('active');
            mobileMenu.classList.add('hidden');
        });
    });

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', (e) => {
            const targetId = anchor.getAttribute('href');
            if (targetId === '#') return;
            e.preventDefault();
            const target = document.querySelector(targetId);
            if (target) {
                const offset = 80;
                const pos = target.getBoundingClientRect().top + window.scrollY - offset;
                window.scrollTo({ top: pos, behavior: 'smooth' });
            }
        });
    });
}

// ─── Scroll Reveal ───
function initScrollReveal() {
    const reveals = document.querySelectorAll('.feature-card, .integrations-card, .step-card, .section-header');
    reveals.forEach(el => el.classList.add('reveal'));

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

    reveals.forEach(el => observer.observe(el));
}

// ─── Server Health ───
async function checkHealth() {
    const el = document.getElementById('server-status');
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        if (res.ok) {
            const data = await res.json();
            el.innerHTML = `<span class="status-dot online"></span><span class="status-text">Online (v${data.version || '2.0'})</span>`;
        } else {
            el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Error</span>';
        }
    } catch {
        el.innerHTML = '<span class="status-dot offline"></span><span class="status-text">Offline</span>';
    }
}

// ─── File Upload ───
function initUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');

    if (!dropZone || !fileInput || !browseBtn) return;

    browseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    dropZone.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) handleFile(fileInput.files[0]);
    });
}

async function handleFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['apk', 'ipa', 'xapk'].includes(ext)) {
        showNotification('Invalid file. Please upload APK, IPA, or XAPK.', 'error');
        return;
    }
    await startScan(file);
}

// ─── Notification ───
function showNotification(message, type = 'info') {
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notif = document.createElement('div');
    notif.className = `notification notification-${type}`;
    notif.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;cursor:pointer;font-size:1.2rem;color:inherit;margin-left:1rem;">\u00d7</button>
    `;
    notif.style.cssText = `
        position: fixed; top: 80px; right: 20px; z-index: 9999;
        display: flex; align-items: center; gap: 0.5rem;
        padding: 0.85rem 1.25rem; border-radius: 12px;
        font-size: 0.85rem; font-weight: 500;
        background: ${type === 'error' ? '#FEF2F2' : type === 'success' ? '#F0FDF4' : '#F8FAFC'};
        color: ${type === 'error' ? '#DC2626' : type === 'success' ? '#16A34A' : '#334155'};
        border: 1px solid ${type === 'error' ? '#FECACA' : type === 'success' ? '#BBF7D0' : '#E2E8F0'};
        box-shadow: 0 8px 30px rgba(0,0,0,0.1);
        animation: slideInRight 0.4s ease-out;
    `;
    document.body.appendChild(notif);
    setTimeout(() => notif.remove(), 5000);
}

// ─── Scan ───
async function startScan(file) {
    document.getElementById('scan').classList.add('hidden');
    document.getElementById('scan-progress-section').classList.remove('hidden');
    document.getElementById('results-section').classList.add('hidden');
    document.getElementById('scan-filename').textContent = file.name;

    // Reset terminal
    const terminalOutput = document.getElementById('terminal-output');
    if (terminalOutput) {
        terminalOutput.innerHTML = '<div class="terminal-line">[INIT] Preparing analysis environment...</div>';
    }
    lastLogLength = 0;

    // Reset step indicator
    const stepEl = document.getElementById('scan-current-step');
    if (stepEl) stepEl.textContent = 'Initializing...';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(`${API_BASE}/api/scan`, { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok) {
            showNotification(data.detail || 'Scan failed', 'error');
            showUpload();
            return;
        }
        currentScanId = data.scan_id;
        pollScanStatus();
        pollScanLogs();
    } catch (err) {
        showNotification(`Connection error: ${err.message}`, 'error');
        showUpload();
    }
}

function pollScanStatus() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/scan/${currentScanId}`);
            const data = await res.json();
            updateProgress(data.progress || 0);

            // Update current step
            const stepEl = document.getElementById('scan-current-step');
            if (stepEl && data.current_step) {
                stepEl.textContent = `Phase: ${data.current_step}`;
            }

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                if (logPollInterval) clearInterval(logPollInterval);
                updateProgress(100);
                setTimeout(() => showResults(data.results), 800);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                if (logPollInterval) clearInterval(logPollInterval);
                showNotification(data.error || 'Analysis failed', 'error');
                showUpload();
            }
        } catch { }
    }, 1500);
}

function pollScanLogs() {
    if (logPollInterval) clearInterval(logPollInterval);
    logPollInterval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/scan/${currentScanId}/log`);
            const data = await res.json();
            updateTerminal(data.log || []);
        } catch { }
    }, 1000);
}

function updateTerminal(logLines) {
    const terminalBody = document.getElementById('terminal-output');
    if (!terminalBody) return;

    // Only add new lines
    if (logLines.length > lastLogLength) {
        const newLines = logLines.slice(lastLogLength);
        newLines.forEach(line => {
            const div = document.createElement('div');
            div.className = 'terminal-line';

            // Color coding
            if (line.includes('PHASE')) {
                div.classList.add('phase');
            } else if (line.includes('COMPLETE') || line.includes('PASSED')) {
                div.classList.add('success');
            } else if (line.includes('ERROR') || line.includes('FAIL')) {
                div.classList.add('error');
            } else if (line.includes('Found') || line.includes('Total')) {
                div.classList.add('highlight');
            }

            div.textContent = line;
            terminalBody.appendChild(div);
        });

        // Add blinking cursor to last line
        const oldCursors = terminalBody.querySelectorAll('.terminal-cursor');
        oldCursors.forEach(c => c.remove());
        const cursor = document.createElement('span');
        cursor.className = 'terminal-cursor';
        terminalBody.lastElementChild.appendChild(cursor);

        // Auto-scroll
        terminalBody.scrollTop = terminalBody.scrollHeight;
        lastLogLength = logLines.length;
    }
}

function updateProgress(pct) {
    document.getElementById('progress-fill').style.width = `${pct}%`;
    document.getElementById('progress-text').textContent = `${pct}%`;
    const steps = document.querySelectorAll('.astep');
    const thresholds = [10, 25, 40, 50, 60, 70, 80, 85, 90, 100];
    steps.forEach((step, i) => {
        if (pct >= thresholds[i]) {
            step.classList.remove('active');
            step.classList.add('completed');
        } else if (pct >= thresholds[i] - 10) {
            step.classList.add('active');
        }
    });
}

// ─── Results ───
function showResults(results) {
    document.getElementById('scan-progress-section').classList.add('hidden');
    document.getElementById('results-section').classList.remove('hidden');
    renderScanMeta(results);
    renderDonutChart(results.risk_assessment);
    renderRiskSummary(results.risk_assessment);
    renderFindings(results.risk_assessment.findings);
    renderAppInfo(results);
    renderReportButtons();
    renderScanHistory();
    initFilterButtons();

    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderScanMeta(results) {
    // Insert meta bar before risk summary
    const metaEl = document.getElementById('scan-meta');
    if (metaEl) metaEl.remove();

    const app = results.application || {};
    const risk = results.risk_assessment || {};
    const fileSize = app.file_size_bytes ? formatFileSize(app.file_size_bytes) : 'N/A';

    const metaHtml = `<div class="scan-meta-bar" id="scan-meta">
        <div class="scan-meta-item"><div class="meta-val">${app.platform ? app.platform.toUpperCase() : 'N/A'}</div><div class="meta-label">Platform</div></div>
        <div class="scan-meta-item"><div class="meta-val">${fileSize}</div><div class="meta-label">File Size</div></div>
        <div class="scan-meta-item"><div class="meta-val">${risk.total_findings || 0}</div><div class="meta-label">Findings</div></div>
        <div class="scan-meta-item"><div class="meta-val" style="color:${getSeverityColor(risk.overall_risk)}">${(risk.overall_risk || 'N/A').toUpperCase()}</div><div class="meta-label">Risk Level</div></div>
    </div>`;

    const riskCard = document.getElementById('risk-summary');
    riskCard.insertAdjacentHTML('beforebegin', metaHtml);
}

function renderDonutChart(risk) {
    const s = risk.risk_summary || {};
    const total = Object.values(s).reduce((a, b) => a + b, 0) || 1;
    const sevColors = {
        critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#6B7280'
    };

    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    let arcs = '';

    for (const [sev, count] of Object.entries(s)) {
        if (count === 0) continue;
        const pct = count / total;
        const dashLength = pct * circumference;
        arcs += `<circle cx="90" cy="90" r="${radius}" fill="none" stroke="${sevColors[sev] || '#999'}" 
            stroke-width="18" stroke-dasharray="${dashLength} ${circumference - dashLength}" 
            stroke-dashoffset="${-offset}" stroke-linecap="round" style="transition:all 1s ease"/>`;
        offset += dashLength;
    }

    let legendHtml = '';
    for (const [sev, count] of Object.entries(s)) {
        legendHtml += `<div class="donut-legend-item"><span class="donut-legend-dot" style="background:${sevColors[sev]}"></span>${sev}: ${count}</div>`;
    }

    // Insert donut chart above risk grid
    const existingDonut = document.querySelector('.donut-chart-container');
    if (existingDonut) existingDonut.remove();

    const riskCards = document.getElementById('risk-cards');
    riskCards.insertAdjacentHTML('beforebegin', `
        <div class="donut-chart-container">
            <div class="donut-chart">
                <svg width="180" height="180" viewBox="0 0 180 180">
                    <circle cx="90" cy="90" r="${radius}" fill="none" stroke="#F3F4F6" stroke-width="18"/>
                    ${arcs}
                </svg>
                <div class="donut-center-label">
                    <div class="donut-total">${total}</div>
                    <div class="donut-label">Findings</div>
                </div>
            </div>
            <div class="donut-legend">${legendHtml}</div>
        </div>
    `);
}

function renderRiskSummary(risk) {
    const s = risk.risk_summary;
    const colors = {
        critical: 'var(--severity-critical)',
        high: 'var(--severity-high)',
        medium: 'var(--severity-medium)',
        low: 'var(--severity-low)',
        info: 'var(--severity-info)'
    };

    let h = '';
    for (const [k, v] of Object.entries(s)) {
        h += `<div class="risk-stat">
            <div class="num" style="color:${colors[k]}">${v}</div>
            <div class="label">${k}</div>
        </div>`;
    }
    document.getElementById('risk-cards').innerHTML = h;

    const o = risk.overall_risk;
    document.getElementById('overall-risk').innerHTML = `
        <div class="overall-label">Threat Level</div>
        <div class="overall-value" style="color:${colors[o] || colors.info}">${o.toUpperCase()}</div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:0.25rem">${risk.total_findings} vulnerabilities detected</div>`;
}

function renderFindings(findings) {
    const list = document.getElementById('findings-list');
    const colors = {
        critical: 'var(--severity-critical)',
        high: 'var(--severity-high)',
        medium: 'var(--severity-medium)',
        low: 'var(--severity-low)',
        info: 'var(--severity-info)'
    };

    if (!findings.length) {
        list.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:2rem">No vulnerabilities detected. All clear!</p>';
        return;
    }

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));

    let h = '';
    findings.forEach((f, i) => {
        const sev = f.severity || 'info';
        h += `<div class="finding-item" data-severity="${sev}" onclick="this.classList.toggle('expanded')" style="border-left-color:${colors[sev]};animation:fadeInUp 0.3s ease ${i * 0.05}s both">
            <div class="finding-top">
                <span class="finding-title">${f.title}</span>
                <span class="severity-badge" style="background:${colors[sev]}">${sev.toUpperCase()} ${f.cvss_score ? `(${f.cvss_score})` : ''}</span>
            </div>
            <div class="finding-desc">${f.description || ''}</div>
            <div class="finding-meta">
                ${f.cwe ? `<span class="meta-tag">${f.cwe}</span>` : ''}
                ${f.owasp ? `<span class="meta-tag">OWASP ${f.owasp}</span>` : ''}
                ${f.capec ? `<span class="meta-tag">${f.capec.split(':')[0]}</span>` : ''}
                ${f.category ? `<span class="meta-tag">${f.category}</span>` : ''}
            </div>
            <div class="finding-details">
                ${f.evidence ? `<div class="detail-row"><span class="detail-label">Evidence:</span><span class="detail-value">${f.evidence}</span></div>` : ''}
                ${f.cwe_details ? `<div class="detail-row"><span class="detail-label">CWE:</span><span class="detail-value">${f.cwe_details.name} — <a href="${f.cwe_details.url}" target="_blank" style="color:var(--accent)">Details</a></span></div>` : ''}
                ${f.owasp_mobile ? `<div class="detail-row"><span class="detail-label">OWASP:</span><span class="detail-value">${f.owasp_mobile.id}: ${f.owasp_mobile.name}</span></div>` : ''}
                ${f.owasp_details ? `<div class="detail-row"><span class="detail-label">Fix:</span><span class="detail-value">${f.owasp_details.remediation || f.remediation || ''}</span></div>` : ''}
            </div>
        </div>`;
    });
    list.innerHTML = h;
}

function initFilterButtons() {
    document.querySelectorAll('.filter-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const f = btn.dataset.filter;
            document.querySelectorAll('.finding-item').forEach(item => {
                item.style.display = (f === 'all' || item.dataset.severity === f) ? '' : 'none';
            });
        });
    });
}

function renderAppInfo(results) {
    const app = results.application || {};
    const sa = results.static_analysis || {};
    const net = results.network_analysis || {};
    let h = '';

    h += `<div class="info-section"><h4>Application</h4>
        <div class="info-item"><strong>Name:</strong> ${app.name || 'N/A'}</div>
        <div class="info-item"><strong>Platform:</strong> ${(app.platform || 'N/A').toUpperCase()}</div>
        <div class="info-item"><strong>File:</strong> ${app.filename || 'N/A'}</div>
        <div class="info-item"><strong>Size:</strong> ${app.file_size_bytes ? formatFileSize(app.file_size_bytes) : 'N/A'}</div>
        ${app.hashes ? `<div class="info-item"><strong>SHA-256:</strong> <code style="font-size:0.65rem;word-break:break-all;color:var(--accent);font-family:var(--font-mono)">${app.hashes.sha256 || ''}</code></div>` : ''}</div>`;

    const perms = sa.permissions || [];
    if (perms.length) {
        h += `<div class="info-section"><h4>Permissions (${perms.length})</h4>
            ${perms.slice(0, 12).map(p => `<div class="info-item">${p.split('.').pop()}</div>`).join('')}
            ${perms.length > 12 ? `<div class="info-item" style="color:var(--text-muted)">...+${perms.length - 12} more</div>` : ''}</div>`;
    }

    const eps = sa.api_endpoints || [];
    if (eps.length) {
        h += `<div class="info-section"><h4>Endpoints (${eps.length})</h4>
            ${eps.slice(0, 8).map(e => `<div class="info-item" style="word-break:break-all">${e.url || e}</div>`).join('')}
            ${eps.length > 8 ? `<div class="info-item" style="color:var(--text-muted)">...+${eps.length - 8} more</div>` : ''}</div>`;
    }

    const secrets = sa.secrets || [];
    if (secrets.length) {
        h += `<div class="info-section"><h4>Secrets (${secrets.length})</h4>
            ${secrets.map(s => `<div class="info-item"><strong>${s.type}:</strong> ${s.masked_value}</div>`).join('')}</div>`;
    }

    h += `<div class="info-section"><h4>Network</h4>
        <div class="info-item"><strong>Cert Pinning:</strong> ${net.cert_pinning ? 'Yes' : 'No'}</div>
        <div class="info-item"><strong>Net Config:</strong> ${net.has_network_security_config ? 'Yes' : 'No'}</div>
        <div class="info-item"><strong>Cleartext:</strong> ${net.cleartext_allowed ? 'Allowed' : 'Blocked'}</div></div>`;

    const comps = sa.components || {};
    const tc = Object.values(comps).reduce((a, b) => a + (b ? b.length : 0), 0);
    if (tc) {
        h += `<div class="info-section"><h4>Components (${tc})</h4>
            <div class="info-item"><strong>Activities:</strong> ${(comps.activities || []).length}</div>
            <div class="info-item"><strong>Services:</strong> ${(comps.services || []).length}</div>
            <div class="info-item"><strong>Receivers:</strong> ${(comps.receivers || []).length}</div>
            <div class="info-item"><strong>Providers:</strong> ${(comps.providers || []).length}</div></div>`;
    }
    document.getElementById('info-grid').innerHTML = h;
}

function renderReportButtons() {
    document.getElementById('report-buttons').innerHTML = `
        <a class="btn btn-primary" href="${API_BASE}/api/scan/${currentScanId}/report/json" target="_blank">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            JSON Report
        </a>
        <a class="btn btn-primary" href="${API_BASE}/api/scan/${currentScanId}/report/html" target="_blank">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            HTML Report
        </a>
        <button class="btn btn-outline-dark" onclick="shareResults()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            Copy Results
        </button>`;
}

async function renderScanHistory() {
    try {
        const res = await fetch(`${API_BASE}/api/scans`);
        const scans = await res.json();
        if (!scans.length) return;

        // Remove existing history card
        const existing = document.querySelector('.scan-history-card');
        if (existing) existing.remove();

        const sevColors = {
            critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#6B7280', pending: '#9CA3AF', unknown: '#9CA3AF'
        };

        let rows = '';
        scans.forEach(s => {
            const riskColor = sevColors[s.overall_risk] || '#9CA3AF';
            rows += `<tr>
                <td style="font-family:var(--font-mono);font-size:0.7rem;">${s.filename || 'N/A'}</td>
                <td>${(s.platform || 'N/A').toUpperCase()}</td>
                <td><span class="risk-badge" style="background:${riskColor}">${(s.overall_risk || 'pending').toUpperCase()}</span></td>
                <td>${s.total_findings || 0}</td>
                <td>${s.duration_seconds ? s.duration_seconds + 's' : '-'}</td>
                <td>${s.status === 'completed' ? 'Done' : s.status === 'running' ? 'Running...' : s.status}</td>
            </tr>`;
        });

        const historyHtml = `<div class="scan-history-card">
            <h3>Scan History</h3>
            <table class="scan-history-table">
                <thead><tr><th>File</th><th>Platform</th><th>Risk</th><th>Findings</th><th>Duration</th><th>Status</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;

        const reportsCard = document.getElementById('reports-card');
        reportsCard.insertAdjacentHTML('afterend', historyHtml);
    } catch { }
}

async function shareResults() {
    try {
        const res = await fetch(`${API_BASE}/api/scan/${currentScanId}`);
        const data = await res.json();
        const json = JSON.stringify({
            application_name: data.results.application.name,
            platform: data.results.application.platform,
            analysis_type: "full_scan",
            vulnerabilities: data.results.risk_assessment.findings.map(f => ({
                title: f.title,
                severity: f.severity,
                owasp_category: f.owasp || '',
                description: f.description || '',
                impact: f.description || '',
                fix: f.remediation || '',
            }))
        }, null, 2);
        await navigator.clipboard.writeText(json);
        showNotification('Results copied to clipboard!', 'success');
    } catch {
        showNotification('Failed to copy results.', 'error');
    }
}

function showUpload() {
    document.getElementById('scan').classList.remove('hidden');
    document.getElementById('scan-progress-section').classList.add('hidden');
    document.getElementById('results-section').classList.add('hidden');

    // Reset
    document.querySelectorAll('.astep').forEach(s => s.classList.remove('active', 'completed'));
    const fill = document.getElementById('progress-fill');
    if (fill) fill.style.width = '0%';
    const text = document.getElementById('progress-text');
    if (text) text.textContent = '0%';

    if (logPollInterval) clearInterval(logPollInterval);
}

// ─── Utilities ───
function formatFileSize(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
}

function getSeverityColor(severity) {
    const colors = {
        critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#6B7280'
    };
    return colors[severity] || '#6B7280';
}

// ─── CSS Animation for Notification ───
function injectNotificationStyles() {
    if (document.getElementById('notif-styles')) return;
    const style = document.createElement('style');
    style.id = 'notif-styles';
    style.textContent = `
        @keyframes slideInRight {
            from { opacity: 0; transform: translateX(40px); }
            to { opacity: 1; transform: translateX(0); }
        }
    `;
    document.head.appendChild(style);
}

// ─── Init ───
document.addEventListener('DOMContentLoaded', () => {
    injectNotificationStyles();
    initNav();
    initUpload();
    initScrollReveal();
    checkHealth();
    setInterval(checkHealth, 30000);

    const newScanBtn = document.getElementById('new-scan-btn');
    if (newScanBtn) newScanBtn.addEventListener('click', showUpload);
});
