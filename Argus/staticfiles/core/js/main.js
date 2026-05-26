/**
 * Argus — Frontend
 *
 * Handles:
 * - Scan lifecycle via HTTP API
 * - Live updates via WebSocket (strict event schema)
 * - Domain confirmation via POST /scan/{id}/continue/ (no WS polling)
 */

let ws = null;
let currentSessionId = null;

const counts = { ports: 0, dirs: 0, vhosts: 0, dns: 0 };

// ── Helpers ──────────────────────────────────────────────────────

function getCookie(name) {
    const val = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return val ? val.pop() : '';
}

function $(id) {
    return document.getElementById(id);
}

function appendLog(text, cssClass = 'log-line') {
    const terminal = $('terminal');
    const line = document.createElement('div');
    line.className = cssClass;
    line.textContent = text;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// ── Scan Control ──────────────────────────────────────────────────

async function startScan() {
    const target = $('target').value.trim();
    if (!target) {
        alert('Enter a target!');
        return;
    }

    const btn = $('startBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Scanning...';

    resetUI();

    const formData = new FormData();
    formData.append('target', target);
    formData.append('nmap_flags', $('nmap_flags').value);
    formData.append('dir_wordlist', $('dir_wordlist').value);
    formData.append('vhost_wordlist', $('vhost_wordlist').value);
    formData.append('dns_wordlist', $('dns_wordlist').value);

    const res = await fetch('/scan/start/', {
        method: 'POST',
        headers: { 'X-CSRFToken': getCookie('csrftoken') },
        body: formData,
    });

    const data = await res.json();
    currentSessionId = data.session_id;
    connectWebSocket(currentSessionId);
}

async function stopScan() {
    if (!currentSessionId) return;

    await fetch(`/scan/${currentSessionId}/stop/`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCookie('csrftoken') },
    });
}

// ── WebSocket ───────────────────────────────────────────────────

function connectWebSocket(sessionId) {
    ws = new WebSocket(`ws://${location.host}/ws/scan/${sessionId}/`);

    ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        handleEvent(msg);
    };

    ws.onclose = () => {
        $('startBtn').disabled = false;
        $('startBtn').textContent = '▶ Start scan';
    };
}

// ── Event Handler (strict schema) ───────────────────────────────

const EVENT_HANDLERS = {
    // Connection
    connected:          (msg) => appendLog(msg.message),

    // Lifecycle
    scan_started:       (msg) => appendLog(msg.message, 'log-done'),
    scan_completed:     (msg) => { appendLog(msg.message, 'log-done'); endScan(); },
    scan_failed:        (msg) => { appendLog(`ERROR: ${msg.message}`, 'log-error'); endScan(); },
    scan_stopped:       (msg) => { appendLog(msg.message, 'log-skip'); endScan(); },

    // Module lifecycle
    module_started:     (msg) => { updateStage(msg.module, 'active'); appendLog(msg.message); },
    module_completed:   (msg) => { updateStage(msg.module, 'done'); appendLog(msg.message, 'log-done'); },
    module_failed:      (msg) => { updateStage(msg.module, 'error'); appendLog(`FAIL [${msg.module}]: ${msg.message}`, 'log-error'); },
    module_skipped:     (msg) => { updateStage(msg.module, 'done'); appendLog(msg.message, 'log-skip'); },

    // Results
    port_found:         (msg) => addPortRow(msg.data),
    directory_found:    (msg) => addDirRow(msg.data),
    vhost_found:        (msg) => addVhostRow(msg.data),
    dns_record_found:   (msg) => addDnsRow(msg.data),

    // Domain confirmation
    domains_awaiting:   (msg) => { updateStage('domains', 'active'); showDomainModal(msg.data?.domains || []); },
    domains_confirmed:  (msg) => { updateStage('domains', 'done'); appendLog(msg.message, 'log-done'); },

    // Log
    log:                (msg) => appendLog(msg.message),
};

function handleEvent(msg) {
    const handler = EVENT_HANDLERS[msg.type];
    if (handler) {
        handler(msg);
    } else {
        console.warn('Unknown event type:', msg.type, msg);
    }
}

function endScan() {
    $('startBtn').disabled = false;
    $('startBtn').textContent = '▶ Start scan';
    if (ws) ws.close();
}

// ── Stage UI ────────────────────────────────────────────────────

function updateStage(module, state) {
    const el = $(`stage-${module}`);
    if (!el) return;

    el.className = 'stage';
    if (state === 'active')  el.classList.add('active');
    if (state === 'done')    el.classList.add('done');
    if (state === 'error')   el.classList.add('error');
}

// ── Result Rows ─────────────────────────────────────────────────

function addPortRow(d) {
    const tbody = $('ports-body');
    if (counts.ports === 0) tbody.innerHTML = '';

    const httpBadge = d.is_http ? '<span class="http-badge">HTTP</span>' : '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><span class="port-num">${d.port}</span>/${d.protocol} ${httpBadge}</td>
        <td>${d.protocol}</td>
        <td class="service-name">${d.service || '—'}</td>
        <td>${[d.product, d.version].filter(Boolean).join(' ') || '—'}</td>
    `;
    tbody.appendChild(tr);
    $('cnt-ports').textContent = ++counts.ports;
}

function addDirRow(d) {
    const tbody = $('dirs-body');
    if (counts.dirs === 0) tbody.innerHTML = '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td><a href="${d.url}" target="_blank" style="color:var(--accent2)">${d.url}</a></td>
        <td class="status-${d.status_code}">${d.status_code}</td>
        <td>${d.size} B</td>
    `;
    tbody.appendChild(tr);
    $('cnt-dirs').textContent = ++counts.dirs;
}

function addVhostRow(d) {
    const tbody = $('vhosts-body');
    if (counts.vhosts === 0) tbody.innerHTML = '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td style="color:var(--accent2)">${d.hostname}</td>
        <td>${d.port}</td>
        <td>${d.status_code}</td>
        <td>${d.content_length}</td>
        <td>${d.words}</td>
        <td>${d.lines}</td>
    `;
    tbody.appendChild(tr);
    $('cnt-vhosts').textContent = ++counts.vhosts;
}

function addDnsRow(d) {
    const tbody = $('dns-body');
    if (counts.dns === 0) tbody.innerHTML = '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td style="color:var(--accent2)">${d.subdomain}</td>
        <td style="color:#c084fc">${d.record_type}</td>
        <td>${d.value}</td>
    `;
    tbody.appendChild(tr);
    $('cnt-dns').textContent = ++counts.dns;
}

// ── Tabs ────────────────────────────────────────────────────────

function showTab(name, btn) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $(`tab-${name}`).classList.add('active');
}

// ── Domain Modal ────────────────────────────────────────────────

function showDomainModal(domains) {
    const checklist = $('domainChecklist');
    checklist.innerHTML = '';

    if (domains.length === 0) {
        checklist.innerHTML = `
            <div style="color:var(--muted);font-size:0.82rem;padding:0.25rem 0.5rem">
                No domains detected automatically — add one below.
            </div>`;
    }

    domains.forEach(domain => {
        const label = document.createElement('label');
        label.className = 'domain-check-item';
        label.innerHTML = `
            <input type="checkbox" value="${domain}" checked>
            <span>${domain}</span>
        `;
        checklist.appendChild(label);
    });

    $('customDomainInput').value = '';
    $('domainModal').style.display = 'flex';
}

function addCustomDomain() {
    const input = $('customDomainInput');
    const val = input.value.trim();
    if (!val) return;

    const checklist = $('domainChecklist');
    const existing = checklist.querySelectorAll('input[type=checkbox]');
    for (const cb of existing) {
        if (cb.value === val) { input.value = ''; return; }
    }

    const label = document.createElement('label');
    label.className = 'domain-check-item';
    label.innerHTML = `
        <input type="checkbox" value="${val}" checked>
        <span>${val}</span>
    `;
    checklist.appendChild(label);
    input.value = '';
}

async function confirmDomains(skip = false) {
    $('domainModal').style.display = 'none';

    let domains = [];
    if (!skip) {
        const checkboxes = document.querySelectorAll('#domainChecklist input[type=checkbox]:checked');
        domains = Array.from(checkboxes).map(cb => cb.value);
    }

    // POST to /scan/{id}/continue/ — no WebSocket, no polling
    const res = await fetch(`/scan/${currentSessionId}/continue/`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken'),
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domains }),
    });

    const data = await res.json();

    updateStage('domains', domains.length > 0 ? 'done' : 'done');
    appendLog(
        domains.length > 0
            ? `Confirmed domains: ${domains.join(', ')}`
            : 'Domain scan skipped.',
        'log-done',
    );

    if (data.status === 'completed') {
        appendLog('Scan completed.', 'log-done');
        endScan();
    }
}

// ── Reset / Clear ───────────────────────────────────────────────

function resetUI() {
    $('terminal').innerHTML = '';
    $('ports-body').innerHTML = '<tr><td colspan="4" class="empty-state">Please wait...</td></tr>';
    $('dirs-body').innerHTML = '<tr><td colspan="3" class="empty-state">Please wait...</td></tr>';
    $('vhosts-body').innerHTML = '<tr><td colspan="6" class="empty-state">Please wait...</td></tr>';
    $('dns-body').innerHTML = '<tr><td colspan="3" class="empty-state">Please wait...</td></tr>';

    counts.ports = 0; counts.dirs = 0; counts.vhosts = 0; counts.dns = 0;
    $('cnt-ports').textContent = '0';
    $('cnt-dirs').textContent = '0';
    $('cnt-vhosts').textContent = '0';
    $('cnt-dns').textContent = '0';

    ['nmap', 'gobuster', 'domains', 'vhost', 'dns'].forEach(s => {
        const el = $(`stage-${s}`);
        if (el) el.className = 'stage';
    });
}

async function clearDB() {
    if (!confirm('Delete all scans?')) return;

    await fetch('/db/clear/', {
        method: 'POST',
        headers: { 'X-CSRFToken': getCookie('csrftoken') },
    });

    $('sessionList').innerHTML = '<div class="empty-state">No scans</div>';
}
