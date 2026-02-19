/**
 * ============================================================
 *  AI Phishing Detector — app.js
 *  UI orchestration, tab switching, gauge, history
 * ============================================================
 */

// ─── STATE ──────────────────────────────────────────────────
let activeTab = 'url';
let scanHistory = JSON.parse(localStorage.getItem('phish_history') || '[]');

// ─── INIT ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    renderHistory();
    setupTabListeners();
    setupFormListeners();
    setupPasteButtons();
});

// ─── TABS ────────────────────────────────────────────────────
function setupTabListeners() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tab}`));
    hideResults();
}

// ─── FORM SUBMISSION ─────────────────────────────────────────
function setupFormListeners() {
    document.querySelectorAll('.analyze-form').forEach(form => {
        form.addEventListener('submit', e => {
            e.preventDefault();
            handleAnalyze(form.dataset.type);
        });
    });
}

function handleAnalyze(type) {
    let result, inputPreview;

    if (type === 'url') {
        const url = document.getElementById('url-input').value.trim();
        if (!url) return showInputError('url-input', 'Please enter a URL to analyze.');
        result = analyzeURL(url);
        inputPreview = url.length > 60 ? url.substring(0, 60) + '…' : url;

    } else if (type === 'email') {
        const sender = document.getElementById('email-sender').value.trim();
        const subject = document.getElementById('email-subject').value.trim();
        const body = document.getElementById('email-body').value.trim();
        if (!sender && !subject && !body) return showInputError('email-body', 'Please enter at least one email field.');
        result = analyzeEmail({ sender, subject, body });
        inputPreview = subject || sender || 'Email body';

    } else if (type === 'message') {
        const msg = document.getElementById('message-input').value.trim();
        if (!msg) return showInputError('message-input', 'Please enter a message to analyze.');
        result = analyzeMessage(msg);
        inputPreview = msg.length > 60 ? msg.substring(0, 60) + '…' : msg;
    }

    showLoadingState(type);

    setTimeout(() => {
        hideLoadingState(type);
        renderResults(result, type, inputPreview);
        saveHistory({ type, inputPreview, score: result.score, level: result.level });
    }, 700);
}

// ─── LOADING STATE ────────────────────────────────────────────
function showLoadingState(type) {
    const btn = document.querySelector(`#panel-${type} .btn-analyze`);
    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Analyzing…';
    btn.querySelector('.spinner').style.display = 'block';
    btn.querySelector('.btn-icon').style.display = 'none';
    hideResults();
}

function hideLoadingState(type) {
    const btn = document.querySelector(`#panel-${type} .btn-analyze`);
    btn.disabled = false;
    const labels = { url: 'Analyze URL', email: 'Analyze Email', message: 'Analyze Message' };
    btn.querySelector('.btn-text').textContent = labels[type];
    btn.querySelector('.spinner').style.display = 'none';
    btn.querySelector('.btn-icon').style.display = 'inline';
}

// ─── RESULTS RENDERER ─────────────────────────────────────────
function renderResults(result, type, inputPreview) {
    const { score, level, signals } = result;
    const meta = getRiskMeta(level);

    // Gauge
    renderGauge(score, meta.color);

    // Score number
    document.getElementById('gauge-score').textContent = score;
    document.getElementById('gauge-score').style.color = meta.color;

    // Badge
    const badge = document.getElementById('risk-badge');
    badge.style.color = meta.color;
    badge.style.borderColor = meta.color;
    badge.style.backgroundColor = meta.glow;
    badge.style.boxShadow = `0 0 20px ${meta.glow}`;
    document.getElementById('risk-icon').textContent = meta.icon;
    document.getElementById('risk-label').textContent = meta.label;
    document.getElementById('risk-desc').textContent = meta.desc;

    // Signals
    const list = document.getElementById('signal-list');
    list.innerHTML = '';
    signals.forEach((sig, i) => {
        const item = document.createElement('div');
        item.className = `signal-item ${sig.type}`;
        item.style.animationDelay = `${i * 60}ms`;
        item.innerHTML = `<span class="signal-dot"></span><span>${sig.text}</span>`;
        list.appendChild(item);
    });

    // Signals count header
    document.getElementById('signals-count').textContent =
        `${signals.length} signal${signals.length !== 1 ? 's' : ''} detected`;

    // Input preview
    document.getElementById('result-input-preview').textContent = inputPreview;
    document.getElementById('result-type-label').textContent = type.toUpperCase();

    // Show section
    const section = document.getElementById('results-section');
    section.classList.add('visible');
    setTimeout(() => section.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
}

// ─── SVG GAUGE ────────────────────────────────────────────────
function renderGauge(score, color) {
    const svg = document.getElementById('gauge-svg');
    svg.innerHTML = '';

    const cx = 100, cy = 100, r = 80;
    const startAngle = -210;
    const endAngle = 30;
    const totalDeg = endAngle - startAngle; // 240°

    function polarToCart(angle) {
        const rad = (angle * Math.PI) / 180;
        return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
    }

    function describeArc(start, end) {
        const s = polarToCart(start);
        const e = polarToCart(end);
        const large = end - start > 180 ? 1 : 0;
        return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
    }

    const circumference = 2 * Math.PI * r;
    const arcFraction = totalDeg / 360;
    const arcLen = circumference * arcFraction;

    // Track (background arc)
    const trackPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    trackPath.setAttribute('d', describeArc(startAngle, endAngle));
    trackPath.setAttribute('fill', 'none');
    trackPath.setAttribute('stroke', 'rgba(255,255,255,0.06)');
    trackPath.setAttribute('stroke-width', '12');
    trackPath.setAttribute('stroke-linecap', 'round');
    svg.appendChild(trackPath);

    // Gradient segments (safe → suspicious → likely → phishing)
    const segments = [
        { from: 0, to: 25, color: '#22c55e' },
        { from: 25, to: 55, color: '#eab308' },
        { from: 55, to: 79, color: '#f97316' },
        { from: 79, to: 100, color: '#ef4444' }
    ];

    segments.forEach(seg => {
        if (score <= seg.from) return;
        const segEnd = Math.min(score, seg.to);
        const startDeg = startAngle + (seg.from / 100) * totalDeg;
        const endDeg = startAngle + (segEnd / 100) * totalDeg;
        const segPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        segPath.setAttribute('d', describeArc(startDeg, endDeg));
        segPath.setAttribute('fill', 'none');
        segPath.setAttribute('stroke', seg.color);
        segPath.setAttribute('stroke-width', '12');
        segPath.setAttribute('stroke-linecap', 'round');
        // Animate via stroke-dasharray trick
        const totalLen = segPath.getTotalLength ? segPath.getTotalLength() : arcLen * ((seg.to - seg.from) / 100);
        svg.appendChild(segPath);
    });

    // Needle dot at score position
    const needleAngle = startAngle + (score / 100) * totalDeg;
    const needlePos = polarToCart(needleAngle);
    const outerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    outerCircle.setAttribute('cx', needlePos.x);
    outerCircle.setAttribute('cy', needlePos.y);
    outerCircle.setAttribute('r', '9');
    outerCircle.setAttribute('fill', color);
    outerCircle.setAttribute('filter', `drop-shadow(0 0 6px ${color})`);
    svg.appendChild(outerCircle);

    const innerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    innerCircle.setAttribute('cx', needlePos.x);
    innerCircle.setAttribute('cy', needlePos.y);
    innerCircle.setAttribute('r', '4');
    innerCircle.setAttribute('fill', '#050b18');
    svg.appendChild(innerCircle);

    // Tick marks
    [0, 25, 50, 75, 100].forEach(pct => {
        const angle = startAngle + (pct / 100) * totalDeg;
        const outer = polarToCart(angle);
        const innerR = r - 16;
        const inner = { x: cx + innerR * Math.cos(angle * Math.PI / 180), y: cy + innerR * Math.sin(angle * Math.PI / 180) };
        const tick = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        tick.setAttribute('x1', inner.x); tick.setAttribute('y1', inner.y);
        tick.setAttribute('x2', outer.x); tick.setAttribute('y2', outer.y);
        tick.setAttribute('stroke', 'rgba(255,255,255,0.12)');
        tick.setAttribute('stroke-width', '1.5');
        svg.appendChild(tick);
    });
}

// ─── ERROR HIGHLIGHTING ───────────────────────────────────────
function showInputError(id, msg) {
    const el = document.getElementById(id);
    el.style.borderColor = 'rgba(239,68,68,0.7)';
    el.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.15)';
    el.placeholder = msg;
    el.focus();
    setTimeout(() => {
        el.style.borderColor = '';
        el.style.boxShadow = '';
    }, 2500);
}

function hideResults() {
    document.getElementById('results-section').classList.remove('visible');
}

// ─── PASTE BUTTONS ────────────────────────────────────────────
function setupPasteButtons() {
    document.querySelectorAll('[data-paste-target]').forEach(btn => {
        btn.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                const target = document.getElementById(btn.dataset.pasteTarget);
                if (target) { target.value = text; target.focus(); }
            } catch {
                btn.textContent = '⚠ Allow clipboard access';
                setTimeout(() => btn.textContent = '📋 Paste', 2000);
            }
        });
    });
}

// ─── HISTORY ─────────────────────────────────────────────────
function saveHistory(entry) {
    scanHistory.unshift({ ...entry, ts: Date.now() });
    if (scanHistory.length > 5) scanHistory = scanHistory.slice(0, 5);
    localStorage.setItem('phish_history', JSON.stringify(scanHistory));
    renderHistory();
}

function renderHistory() {
    const section = document.getElementById('history-section');
    const list = document.getElementById('history-list');
    if (!scanHistory.length) { section.style.display = 'none'; return; }

    section.style.display = 'block';
    list.innerHTML = '';

    scanHistory.forEach(entry => {
        const meta = getRiskMeta(entry.level);
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
      <span class="history-dot" style="background:${meta.color}; box-shadow: 0 0 5px ${meta.color}60"></span>
      <span class="history-type">${entry.type.toUpperCase()}</span>
      <span class="history-input">${entry.inputPreview}</span>
      <span class="history-score" style="color:${meta.color}">${entry.score}</span>
    `;
        list.appendChild(item);
    });
}

function clearHistory() {
    scanHistory = [];
    localStorage.removeItem('phish_history');
    renderHistory();
}
