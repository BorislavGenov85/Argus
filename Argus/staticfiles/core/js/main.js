let ws = null;
let currentSessionId = null;

const portCount = {
    ports: 0,
    dirs: 0,
    dns: 0
};

function getCookie(name) {
    const val = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return val ? val.pop() : '';
}

async function startScan() {

    const target = document.getElementById('target').value.trim();

    if (!target) {
        alert('Въведи таргет!');
        return;
    }

    const btn = document.getElementById('startBtn');

    btn.disabled = true;
    btn.textContent = '⏳ Сканиране...';

    resetUI();

    const formData = new FormData();

    formData.append('target', target);
    formData.append('nmap_flags', document.getElementById('nmap_flags').value);
    formData.append('dir_wordlist', document.getElementById('dir_wordlist').value);
    formData.append('dns_wordlist', document.getElementById('dns_wordlist').value);
    formData.append('csrfmiddlewaretoken', getCookie('csrftoken'));

    const res = await fetch('/scan/start/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: formData
    });

    const data = await res.json();

    currentSessionId = data.session_id;

    connectWebSocket(currentSessionId);
}

function connectWebSocket(sessionId) {

    ws = new WebSocket(`ws://${location.host}/ws/scan/${sessionId}/`);

    ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        handleMessage(msg);
    };

    ws.onclose = () => {
        document.getElementById('startBtn').disabled = false;
        document.getElementById('startBtn').textContent = '▶ Start scan';
    };
}

function handleMessage(msg) {

    const terminal = document.getElementById('terminal');

    // CONNECTED
    if (msg.type === 'connected') {

        const line = document.createElement('div');

        line.className = 'log-line';
        line.textContent = msg.message;

        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;

        return;
    }

    // RAW LOG
    if (msg.type === 'log') {

        const line = document.createElement('div');

        line.className = 'log-line';
        line.textContent = msg.message;

        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;

        return;
    }

    const {stage, status} = msg;

    // TERMINAL STATES
    if (
        status === 'completed' ||
        status === 'stopped' ||
        status === 'failed' ||
        status === 'error'
    ) {

        document.getElementById('startBtn').disabled = false;
        document.getElementById('startBtn').textContent = '▶ Start scan';

        if (ws) {
            ws.close();
        }
    }

    // TERMINAL LOG
    const line = document.createElement('div');

    let cssClass = 'log-' + stage;

    if (status === 'error' || status === 'failed') {
        cssClass = 'log-error';
    }

    if (status === 'stopped') {
        cssClass = 'log-skip';
    }

    if (status === 'done' || status === 'completed') {
        cssClass = 'log-done';
    }

    if (status === 'skipped') {
        cssClass = 'log-skip';
    }

    line.className = cssClass;

    if (msg.message) {

        line.textContent = msg.message;

        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    // UPDATE STAGE UI
    updateStage(stage, status);

    // STOPPED STAGE COLOR
    if (status === 'stopped') {

        const el2 = document.getElementById(`stage-${stage}`);

        if (el2) {
            el2.classList.add('error');
        }
    }

    // RESULTS

    if (stage === 'nmap' && status === 'result') {

        addPortRow(msg);

    } else if (stage === 'gobuster' && status === 'result') {

        addDirRow(msg);

    } else if (stage === 'dns' && status === 'result') {

        addDnsRow(msg);
    }
}

function updateStage(stage, status) {

    const el = document.getElementById(`stage-${stage}`);

    if (!el) return;

    el.className = 'stage';

    if (status === 'started' || status === 'result') {
        el.classList.add('active');
    }

    if (status === 'done' || status === 'completed') {
        el.classList.add('done');
    }

    if (status === 'error' || status === 'failed' || status === 'stopped') {
        el.classList.add('error');
    }

    if (status === 'skipped') {
        el.classList.add('done');
    }
}

function addPortRow(msg) {

    const tbody = document.getElementById('ports-body');

    if (portCount.ports === 0) {
        tbody.innerHTML = '';
    }

    const httpBadge = msg.is_http
        ? '<span class="http-badge">HTTP</span>'
        : '';

    const tr = document.createElement('tr');

    tr.innerHTML = `
        <td>
            <span class="port-num">${msg.port}</span>/${msg.protocol}
            ${httpBadge}
        </td>

        <td>${msg.protocol}</td>

        <td class="service-name">
            ${msg.service || '—'}
        </td>

        <td>
            ${[msg.product, msg.version].filter(Boolean).join(' ') || '—'}
        </td>
    `;

    tbody.appendChild(tr);

    portCount.ports++;

    document.getElementById('cnt-ports').textContent = portCount.ports;
}

function addDirRow(msg) {

    const tbody = document.getElementById('dirs-body');

    if (portCount.dirs === 0) {
        tbody.innerHTML = '';
    }

    const statusClass = `status-${msg.status_code}`;

    const tr = document.createElement('tr');

    tr.innerHTML = `
        <td>
            <a href="${msg.url}" target="_blank" style="color:var(--accent2)">
                ${msg.url}
            </a>
        </td>

        <td class="${statusClass}">
            ${msg.status_code}
        </td>

        <td>
            ${msg.size} B
        </td>
    `;

    tbody.appendChild(tr);

    portCount.dirs++;

    document.getElementById('cnt-dirs').textContent = portCount.dirs;
}

function addDnsRow(msg) {

    const tbody = document.getElementById('dns-body');

    if (portCount.dns === 0) {
        tbody.innerHTML = '';
    }

    const tr = document.createElement('tr');

    tr.innerHTML = `
        <td style="color:var(--accent2)">
            ${msg.subdomain}
        </td>

        <td style="color:#c084fc">
            ${msg.record_type}
        </td>

        <td>
            ${msg.value}
        </td>
    `;

    tbody.appendChild(tr);

    portCount.dns++;

    document.getElementById('cnt-dns').textContent = portCount.dns;
}

function showTab(name, btn) {

    document.querySelectorAll('.tab').forEach(t => {
        t.classList.remove('active');
    });

    document.querySelectorAll('.tab-panel').forEach(p => {
        p.classList.remove('active');
    });

    btn.classList.add('active');

    document.getElementById(`tab-${name}`).classList.add('active');
}

function resetUI() {

    document.getElementById('terminal').innerHTML = '';

    document.getElementById('ports-body').innerHTML =
        '<tr><td colspan="4" class="empty-state">Please wait...</td></tr>';

    document.getElementById('dirs-body').innerHTML =
        '<tr><td colspan="3" class="empty-state">Please wait...</td></tr>';

    document.getElementById('dns-body').innerHTML =
        '<tr><td colspan="3" class="empty-state">Please wait...</td></tr>';

    portCount.ports = 0;
    portCount.dirs = 0;
    portCount.dns = 0;

    document.getElementById('cnt-ports').textContent = '0';
    document.getElementById('cnt-dirs').textContent = '0';
    document.getElementById('cnt-dns').textContent = '0';

    ['nmap', 'gobuster', 'dns'].forEach(s => {
        document.getElementById(`stage-${s}`).className = 'stage';
    });
}

async function clearDB() {

    if (!confirm('Delete all scans?')) return;

    await fetch('/db/clear/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken')
        }
    });

    document.getElementById('sessionList').innerHTML =
        '<div class="empty-state">No scans</div>';
}

async function stopScan() {

    if (!currentSessionId) return;

    await fetch(`/scan/${currentSessionId}/stop/`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken')
        }
    });
}