// ══════════════════════════════════════════════════════════════
//  PQC CBOM SCANNER — app.js
//  All state management, API calls, rendering, and mascot logic
// ══════════════════════════════════════════════════════════════

const API = 'https://pqc-scanner-zle8.onrender.com';

// ── State ────────────────────────────────────────────────────
let state = {
  token:      localStorage.getItem('pqc_token'),
  user:       JSON.parse(localStorage.getItem('pqc_user') || 'null'),
  page:       'scan',
  scans:      [],
  activeScan: null,
  viewScanId: null,
  reports:    [],
  jobs:       [],
  analytics:  null,
  toasts:     [],
  authTab:    'login',
  scanFilter: 'all',
  darkMode:   localStorage.getItem('pqc_theme') === 'dark',
};

// ── Theme bootstrap (applied before first render) ─────────────
(function() {
  if (localStorage.getItem('pqc_theme') === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();

// ── Dark mode toggle ──────────────────────────────────────────
function toggleDarkMode() {
  const next = !state.darkMode;
  state.darkMode = next;
  document.documentElement.setAttribute('data-theme', next ? 'dark' : '');
  localStorage.setItem('pqc_theme', next ? 'dark' : 'light');
  // Re-render charts with updated grid line colours if on analytics page
  if (state.page === 'analytics') setTimeout(renderCharts, 50);
  render();
}

function setState(patch) {
  Object.assign(state, patch);
  render();
}

// ── API helpers ───────────────────────────────────────────────
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
  const r = await fetch(API + path, { ...opts, headers });
  if (r.status === 401) { logout(); return null; }
  return r;
}

// ── Auth ──────────────────────────────────────────────────────
async function login(username, password) {
  const r = await fetch(API + '/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
 let d = {};
try {
  d = await r.json();
} catch (e) {
  console.error("Invalid JSON response", e);
  return "Server error (invalid response)";
}

if (!r.ok) {
  return d.detail || "Login failed";
}
  const usr = { id: d.user_id, username: d.username, email: d.email, is_admin: d.is_admin };
  localStorage.setItem('pqc_token', d.access_token);
  localStorage.setItem('pqc_user', JSON.stringify(usr));
  setState({ token: d.access_token, user: usr, page: 'scan' });
  loadScans();
  return null;
}

async function register(username, email, password, full_name) {
  const r = await fetch(API + '/auth/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, full_name })
  });
  let d = {};
try {
  d = await r.json();
} catch (e) {
  console.error("Invalid JSON response", e);
  return "Server error (invalid response)";
}

if (!r.ok) {
  return d.detail || "Login failed";
}
  const usr = { id: d.user_id, username: d.username, email: d.email, is_admin: d.is_admin };
  localStorage.setItem('pqc_token', d.access_token);
  localStorage.setItem('pqc_user', JSON.stringify(usr));
  setState({ token: d.access_token, user: usr, page: 'scan' });
  loadScans();
  return null;
}

function logout() {
  localStorage.removeItem('pqc_token');
  localStorage.removeItem('pqc_user');
  setState({ token: null, user: null, page: 'scan', scans: [], activeScan: null });
}

// ── Data loaders ───────────────────────────────────────────────
async function loadScans() {
  const r = await api('/scans');
  if (r && r.ok) { const d = await r.json(); setState({ scans: d }); }
}

async function loadReports() {
  const r = await api('/reports');
  if (r && r.ok) { const d = await r.json(); setState({ reports: d }); }
}

async function loadJobs() {
  const r = await api('/jobs');
  if (r && r.ok) { const d = await r.json(); setState({ jobs: d }); }
}

async function loadAnalytics() {
  const r = await api('/analytics/overview');
  if (r && r.ok) { const d = await r.json(); setState({ analytics: d }); setTimeout(renderCharts, 100); }
}

async function selectScan(id) {
  const r = await api('/scan/' + id);
  if (r && r.ok) {
    const d = await r.json();
    setState({ activeScan: d, viewScanId: id, page: 'results' });
  }
}

// ── Scan ──────────────────────────────────────────────────────
async function startScan(domain, ports) {
  if (!domain.trim()) return;
  const r = await api('/scan', { method: 'POST', body: JSON.stringify({ domain, ports, threads: 100, include_subdomains: true }) });
  if (!r || !r.ok) { toast('Failed to start scan', 'err'); return; }
  const d = await r.json();
  const scanId = d.scan_id;
  const initScan = { id: scanId, domain, status: 'running', progress: 0, events: [], results: [], summary: {} };
  setState({ activeScan: initScan, viewScanId: scanId, page: 'results' });

  const es = new EventSource(`${API}/scan/${scanId}/stream?token=${encodeURIComponent(state.token)}`);
  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    const current = state.activeScan;
    if (!current || current.id !== scanId) { es.close(); return; }
    const events = [...(current.events || []), ev];
    const update = { ...current, events, message: ev.message || current.message, progress: ev.progress ?? current.progress };
    if (ev.type === 'done' || ev.type === 'complete') {
      update.status = ev.status || 'complete';
      es.close();
      api('/scan/' + scanId).then(r => r && r.ok ? r.json() : null).then(full => {
        if (full) { setState({ activeScan: full }); loadScans(); }
      });
    }
    setState({ activeScan: update });
  };
  es.onerror = () => es.close();
}

// ── Reports ───────────────────────────────────────────────────
async function submitOnDemand(scanId, format, emailTo, sendEmail, notes) {
  const r = await api('/report/on-demand', { method: 'POST', body: JSON.stringify({
    scan_id: scanId, format, email_to: emailTo ? emailTo.split(',').map(e => e.trim()) : [],
    send_email: sendEmail, notes
  })});
  if (r && r.ok) { toast('Report generating…', 'ok'); setTimeout(loadReports, 3000); }
  else toast('Error generating report', 'err');
}

async function submitScheduled(form) {
  const r = await api('/report/scheduled', { method: 'POST', body: JSON.stringify({
    domain: form.domain, run_at: new Date(form.run_at).toISOString(),
    format: form.format, label: form.label,
    email_to: form.email_to ? form.email_to.split(',').map(e => e.trim()) : [],
    send_email: form.send_email, ports: 'top'
  })});
  if (r && r.ok) { toast('Report scheduled ✓', 'ok'); loadJobs(); }
  else toast('Error scheduling report', 'err');
}

async function submitFrequency(form) {
  const r = await api('/report/frequency', { method: 'POST', body: JSON.stringify({
    domain: form.domain, interval_value: parseInt(form.interval_value),
    interval_unit: form.interval_unit, format: form.format, label: form.label,
    max_runs: form.max_runs ? parseInt(form.max_runs) : null,
    email_to: form.email_to ? form.email_to.split(',').map(e => e.trim()) : [],
    send_email: form.send_email, ports: 'top'
  })});
  if (r && r.ok) { toast('Frequency monitoring active ✓', 'ok'); loadJobs(); }
  else toast('Error activating monitoring', 'err');
}

async function cancelJob(id) {
  const r = await api('/jobs/' + id, { method: 'DELETE' });
  if (r && r.ok) { toast('Job cancelled', 'ok'); loadJobs(); }
}

// ── Toast ─────────────────────────────────────────────────────
function toast(msg, type = 'ok') {
  const id = Date.now();
  state.toasts = [...state.toasts, { id, msg, type }];
  render();
  setTimeout(() => { state.toasts = state.toasts.filter(t => t.id !== id); render(); }, 3500);
}

// ── Helpers ───────────────────────────────────────────────────
function fmt(d) { if (!d) return '—'; return new Date(d).toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'short' }); }
function elapsed(s) { if (!s) return ''; return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`; }
function riskColor(n) { return n <= 20 ? 'var(--safe)' : n <= 60 ? 'var(--warn)' : 'var(--danger)'; }
function lcClass(lc) { return { safe: 'safe', 'pqc-ready': 'pqcr', warn: 'warn', danger: 'danger' }[lc] || 'neutral'; }
function userInitial(u) { return u ? u.username[0].toUpperCase() : '?'; }

// ── Chart helpers ─────────────────────────────────────────────
const chartInstances = {};
function destroyChart(id) { if (chartInstances[id]) { chartInstances[id].destroy(); delete chartInstances[id]; } }

function renderCharts() {
  const a = state.analytics;
  if (!a || state.page !== 'analytics') return;

  // Resolve grid/tick colours from current theme
  const isDark    = state.darkMode;
  const gridColor = isDark ? '#2e2e2b' : '#e8e8e4';
  const tickColor = isDark ? '#72726a' : '#9f9f96';
  const fontOpts  = (size) => ({ family: 'DM Mono', size, color: tickColor });

  if (a.trends && a.trends.length > 0) {
    destroyChart('risk-trend');
    const ctx = document.getElementById('chart-risk-trend');
    if (ctx) {
      chartInstances['risk-trend'] = new Chart(ctx, {
        type: 'line',
        data: {
          labels: a.trends.map(t => new Date(t.date).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })),
          datasets: [{
            label: 'Quantum Risk Score',
            data: a.trends.map(t => t.risk_score),
            borderColor: '#991b1b', backgroundColor: 'rgba(153,27,27,.06)',
            borderWidth: 2, pointRadius: 4, pointBackgroundColor: '#991b1b',
            fill: true, tension: 0.3
          }, {
            label: 'Fully Safe',
            data: a.trends.map(t => t.fully_safe),
            borderColor: '#166534', backgroundColor: 'transparent',
            borderWidth: 2, pointRadius: 3, pointBackgroundColor: '#166534',
            tension: 0.3
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: true, labels: { font: { family: 'DM Mono', size: 11 }, color: tickColor, boxWidth: 12 } } },
          scales: {
            y: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: fontOpts(10) } },
            x: { grid: { display: false }, ticks: { font: fontOpts(10) } }
          }
        }
      });
    }
  }

  const sm = a.latest_summary || {};
  if (sm.tls_endpoints > 0) {
    destroyChart('pqc-donut');
    const ctx2 = document.getElementById('chart-pqc-donut');
    if (ctx2) {
      chartInstances['pqc-donut'] = new Chart(ctx2, {
        type: 'doughnut',
        data: {
          labels: ['Fully Safe', 'PQC Ready', 'Not Ready', 'Not Safe'],
          datasets: [{
            data: [sm.fully_quantum_safe || 0, sm.pqc_ready || 0, sm.pqc_not_ready || 0, sm.not_quantum_safe || 0],
            backgroundColor: isDark
              ? ['#4ade80', '#38bdf8', '#fbbf24', '#f87171']
              : ['#166534', '#0c4a6e', '#854d0e', '#991b1b'],
            borderWidth: 0, hoverOffset: 4
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: '65%',
          plugins: { legend: { position: 'right', labels: { font: { family: 'DM Mono', size: 11 }, color: tickColor, boxWidth: 12, padding: 12 } } }
        }
      });
    }
  }

  const ciphers = Object.entries(a.cipher_totals || {}).slice(0, 10);
  if (ciphers.length > 0) {
    destroyChart('cipher-bar');
    const ctx3 = document.getElementById('chart-cipher-bar');
    if (ctx3) {
      chartInstances['cipher-bar'] = new Chart(ctx3, {
        type: 'bar',
        data: {
          labels: ciphers.map(([k]) => k.length > 28 ? k.slice(0, 28) + '…' : k),
          datasets: [{
            label: 'Occurrences', data: ciphers.map(([, v]) => v),
            backgroundColor: ciphers.map(([k]) =>
              k.includes('TLS_AES') || k.includes('CHACHA') ? (isDark ? '#4ade80' : '#166534') :
              k.includes('ECDHE') || k.includes('DHE') ? (isDark ? '#f87171' : '#991b1b') : (isDark ? '#fbbf24' : '#854d0e')),
            borderRadius: 3, borderSkipped: false
          }]
        },
        options: {
          indexAxis: 'y', responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: fontOpts(10) } },
            y: { grid: { display: false }, ticks: { font: fontOpts(9) } }
          }
        }
      });
    }
  }

  const tlsVersions = Object.entries(a.tls_totals || {});
  if (tlsVersions.length > 0) {
    destroyChart('tls-bar');
    const ctx4 = document.getElementById('chart-tls-bar');
    if (ctx4) {
      const colorsLight = { 'TLSv1.3': '#166534', 'TLSv1.2': '#854d0e', 'TLSv1.1': '#991b1b', 'TLSv1.0': '#991b1b', 'SSLv3': '#991b1b' };
      const colorsDark  = { 'TLSv1.3': '#4ade80', 'TLSv1.2': '#fbbf24', 'TLSv1.1': '#f87171', 'TLSv1.0': '#f87171', 'SSLv3': '#f87171' };
      const colors = isDark ? colorsDark : colorsLight;
      chartInstances['tls-bar'] = new Chart(ctx4, {
        type: 'bar',
        data: {
          labels: tlsVersions.map(([k]) => k),
          datasets: [{
            data: tlsVersions.map(([, v]) => v),
            backgroundColor: tlsVersions.map(([k]) => colors[k] || tickColor),
            borderRadius: 4, borderSkipped: false
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: fontOpts(10) } },
            x: { grid: { display: false }, ticks: { font: fontOpts(11) } }
          }
        }
      });
    }
  }

  const ports = Object.entries(a.port_totals || {}).slice(0, 10);
  if (ports.length > 0) {
    destroyChart('port-heat');
    const ctx5 = document.getElementById('chart-port-heat');
    if (ctx5) {
      chartInstances['port-heat'] = new Chart(ctx5, {
        type: 'bar',
        data: {
          labels: ports.map(([k]) => ':' + k),
          datasets: [{
            label: 'Open across hosts', data: ports.map(([, v]) => v),
            backgroundColor: isDark ? '#efefec' : '#1a1a18', borderRadius: 3, borderSkipped: false
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: fontOpts(10) } },
            x: { grid: { display: false }, ticks: { font: fontOpts(11) } }
          }
        }
      });
    }
  }
}

// ══════════════════════════════════════════════════════════════
//  MASCOT SVG GENERATORS
// ══════════════════════════════════════════════════════════════

/**
 * Returns the letter-shaped body path, clip path, face positions,
 * and hand positions for a given letter.
 * All coordinates are within a 96×96 viewBox.
 *
 * faceCenter: {ex, ey}   — centre of the "face zone" (for eye layout)
 * eyes: [{cx,cy}, {cx,cy}] — eye-white centres  [left, right]
 * pupils: [{cx,cy}, {cx,cy}] — pupil base positions
 * shines: [{cx,cy}, {cx,cy}] — eye-shine dots
 * cheeks: [{cx,cy,rx,ry}, ...]
 * mouth: "M … Q … path string"
 * highlight: "M … ellipse-approx path" or null
 * hands: { lx, ly, rx, ry }  — hand-ellipse centres
 */
function _mascotLetterData(letter) {
  switch (letter) {
    case 'C':
      // Big open arc letter. Face lives in the curved body of the C.
      return {
        // Thick C: outer arc minus inner arc, with rounded end caps
        bodyPath: `
          M 70 18
          A 38 38 0 1 0 70 78
          L 62 78
          A 30 30 0 1 1 62 18 Z`,
        clipId: 'letter-c',
        eyes:    [{ cx: 42, cy: 44 }, { cx: 62, cy: 44 }],
        pupils:  [{ cx: 42, cy: 45 }, { cx: 62, cy: 45 }],
        shines:  [{ cx: 44, cy: 41 }, { cx: 64, cy: 41 }],
        cheeks:  [{ cx: 30, cy: 58, rx: 7, ry: 5 }, { cx: 66, cy: 58, rx: 6, ry: 4 }],
        mouth:   'M 36 62 Q 45 70 56 62',
        highlightEllipse: { cx: 44, cy: 26, rx: 14, ry: 7 },
        hands: { lx: 36, ly: 44, rx: 64, ry: 44 },
      };

    case 'B':
      // Wide, chunky B: vertical left bar + two bumps on the right
      return {
        bodyPath: `
          M 18 10
          L 18 86
          L 52 86
          Q 76 86 76 72
          Q 76 60 58 57
          Q 76 54 76 40
          Q 76 10 52 10 Z
          M 32 24
          L 50 24
          Q 60 24 60 38
          Q 60 52 50 52
          L 32 52 Z
          M 32 56
          L 52 56
          Q 64 56 64 72
          Q 64 82 52 82
          L 32 82 Z`,
        clipId: 'letter-b',
        // Top bump face
        eyes:    [{ cx: 38, cy: 36 }, { cx: 54, cy: 36 }],
        pupils:  [{ cx: 38, cy: 37 }, { cx: 54, cy: 37 }],
        shines:  [{ cx: 40, cy: 33 }, { cx: 56, cy: 33 }],
        cheeks:  [{ cx: 26, cy: 50, rx: 6, ry: 4 }, { cx: 66, cy: 50, rx: 6, ry: 4 }],
        mouth:   'M 34 66 Q 44 74 56 66',
        highlightEllipse: { cx: 40, cy: 22, rx: 12, ry: 6 },
        hands: { lx: 32, ly: 36, rx: 58, ry: 36 },
      };

    case 'O':
      // Thick O ring — face is centered in the ring body
      return {
        bodyPath: `
          M 48 6
          A 42 42 0 1 1 47.99 6 Z
          M 48 20
          A 28 28 0 1 0 48.01 20 Z`,
        clipId: 'letter-o',
        eyes:    [{ cx: 34, cy: 45 }, { cx: 62, cy: 45 }],
        pupils:  [{ cx: 34, cy: 46 }, { cx: 62, cy: 46 }],
        shines:  [{ cx: 36, cy: 42 }, { cx: 64, cy: 42 }],
        cheeks:  [{ cx: 22, cy: 56, rx: 7, ry: 5 }, { cx: 74, cy: 56, rx: 7, ry: 5 }],
        mouth:   'M 36 62 Q 48 72 60 62',
        highlightEllipse: { cx: 40, cy: 24, rx: 14, ry: 7 },
        hands: { lx: 30, ly: 45, rx: 66, ry: 45 },
      };

    case 'M':
    default:
      // Wide M with two peaks — face lives in the flat lower body
      return {
        bodyPath: `
          M 8 82
          L 8 14
          L 26 14
          L 48 50
          L 70 14
          L 88 14
          L 88 82
          L 74 82
          L 74 38
          L 55 72
          L 41 72
          L 22 38
          L 22 82 Z`,
        clipId: 'letter-m',
        eyes:    [{ cx: 30, cy: 60 }, { cx: 66, cy: 60 }],
        pupils:  [{ cx: 30, cy: 61 }, { cx: 66, cy: 61 }],
        shines:  [{ cx: 32, cy: 57 }, { cx: 68, cy: 57 }],
        cheeks:  [{ cx: 18, cy: 72, rx: 6, ry: 4 }, { cx: 78, cy: 72, rx: 6, ry: 4 }],
        mouth:   'M 36 74 Q 48 83 60 74',
        highlightEllipse: { cx: 48, cy: 32, rx: 18, ry: 7 },
        hands: { lx: 26, ly: 60, rx: 70, ry: 60 },
      };
  }
}

/**
 * Builds one clay-style SVG mascot with the body shaped as the letter itself.
 * @param {string} letter   - 'C' | 'B' | 'O' | 'M'
 * @param {string} bodyFill - main color
 * @param {string} shade    - darker shade for bottom
 * @param {string} cheek    - cheek highlight color
 * @param {string} textFill - letter color (unused for body, kept for API compat)
 * @param {number} idx      - 0-3 for unique IDs
 */
function buildMascotSVG(letter, bodyFill, shade, cheek, textFill, idx) {
  const d = _mascotLetterData(letter);
  const { bodyPath, eyes, pupils, shines, cheeks, mouth, highlightEllipse, hands } = d;

  return `
<svg class="mascot-svg mascot-letter-${letter.toLowerCase()}" viewBox="0 0 96 96"
     xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Mascot ${letter}">
  <defs>
    <!-- Radial gradient for clay body shine -->
    <radialGradient id="mg${idx}" cx="35%" cy="30%" r="65%">
      <stop offset="0%"   stop-color="${bodyFill}" stop-opacity="1"/>
      <stop offset="70%"  stop-color="${bodyFill}" stop-opacity="1"/>
      <stop offset="100%" stop-color="${shade}"    stop-opacity="1"/>
    </radialGradient>

    <!-- Inner-shadow / bottom darkness -->
    <radialGradient id="mgb${idx}" cx="50%" cy="90%" r="55%">
      <stop offset="0%"   stop-color="${shade}" stop-opacity="0.6"/>
      <stop offset="100%" stop-color="${shade}" stop-opacity="0"/>
    </radialGradient>

    <!-- Drop shadow filter -->
    <filter id="mf${idx}" x="-20%" y="-20%" width="140%" height="150%">
      <feDropShadow dx="0" dy="5" stdDeviation="5" flood-color="rgba(0,0,0,0.28)"/>
    </filter>

    <!-- Clip to letter shape -->
    <clipPath id="mc${idx}">
      <path d="${bodyPath}"/>
    </clipPath>
  </defs>

  <!-- ── Letter Body ── -->
  <path d="${bodyPath}" fill="url(#mg${idx})" filter="url(#mf${idx})"/>

  <!-- Bottom shade overlay clipped to letter -->
  <path d="${bodyPath}" fill="url(#mgb${idx})" clip-path="url(#mc${idx})"/>

  <!-- Top specular highlight (clipped) -->
  <ellipse cx="${highlightEllipse.cx}" cy="${highlightEllipse.cy}"
           rx="${highlightEllipse.rx}" ry="${highlightEllipse.ry}"
           fill="white" opacity="0.22" clip-path="url(#mc${idx})"/>

  <!-- ── Cheeks ── -->
  ${cheeks.map(c => `<ellipse cx="${c.cx}" cy="${c.cy}" rx="${c.rx}" ry="${c.ry}"
    fill="${cheek}" opacity="0.55" clip-path="url(#mc${idx})"/>`).join('\n  ')}

  <!-- ── Eyes (mouse-tracked) ── -->
  <g class="mascot-eyes" id="mascot-eyes-${idx}">
    <!-- Eye whites -->
    <ellipse cx="${eyes[0].cx}" cy="${eyes[0].cy}" rx="8" ry="9" fill="white"/>
    <ellipse cx="${eyes[1].cx}" cy="${eyes[1].cy}" rx="8" ry="9" fill="white"/>
    <!-- Pupils -->
    <circle class="mascot-pupil-l" id="pupil-l-${idx}"
            cx="${pupils[0].cx}" cy="${pupils[0].cy}" r="4.5" fill="#1a1a18"/>
    <circle class="mascot-pupil-r" id="pupil-r-${idx}"
            cx="${pupils[1].cx}" cy="${pupils[1].cy}" r="4.5" fill="#1a1a18"/>
    <!-- Shines -->
    <circle cx="${shines[0].cx}" cy="${shines[0].cy}" r="1.5" fill="white" opacity="0.9"/>
    <circle cx="${shines[1].cx}" cy="${shines[1].cy}" r="1.5" fill="white" opacity="0.9"/>
  </g>

  <!-- ── Peek-a-boo hands (shown on password focus) ── -->
  <g class="mascot-hands" id="mascot-hands-${idx}">
    <!-- Left hand -->
    <ellipse cx="${hands.lx}" cy="${hands.ly}" rx="14" ry="11"
             fill="${bodyFill}" stroke="${shade}" stroke-width="1.5"/>
    <ellipse cx="${hands.lx}" cy="${hands.ly - 2}" rx="12" ry="7" fill="${bodyFill}"/>
    <line x1="${hands.lx - 8}" y1="${hands.ly - 6}" x2="${hands.lx - 8}" y2="${hands.ly + 6}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.lx - 3}" y1="${hands.ly - 8}" x2="${hands.lx - 3}" y2="${hands.ly + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.lx + 2}" y1="${hands.ly - 8}" x2="${hands.lx + 2}" y2="${hands.ly + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.lx + 7}" y1="${hands.ly - 6}" x2="${hands.lx + 7}" y2="${hands.ly + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <!-- Right hand -->
    <ellipse cx="${hands.rx}" cy="${hands.ry}" rx="14" ry="11"
             fill="${bodyFill}" stroke="${shade}" stroke-width="1.5"/>
    <ellipse cx="${hands.rx}" cy="${hands.ry - 2}" rx="12" ry="7" fill="${bodyFill}"/>
    <line x1="${hands.rx - 8}" y1="${hands.ry - 6}" x2="${hands.rx - 8}" y2="${hands.ry + 6}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.rx - 3}" y1="${hands.ry - 8}" x2="${hands.rx - 3}" y2="${hands.ry + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.rx + 2}" y1="${hands.ry - 8}" x2="${hands.rx + 2}" y2="${hands.ry + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="${hands.rx + 7}" y1="${hands.ry - 6}" x2="${hands.rx + 7}" y2="${hands.ry + 7}"
          stroke="${shade}" stroke-width="1.2" stroke-linecap="round"/>
  </g>

  <!-- ── Mouth ── -->
  <path d="${mouth}" stroke="${shade}" stroke-width="2.2" fill="none" stroke-linecap="round"
        clip-path="url(#mc${idx})"/>
</svg>`;
}

// Mascot config: [letter, bodyFill, shade, cheek, textFill]
const MASCOT_CONFIG = [
  ['C', '#e8c547', '#c9a92e', '#f0a862', '#1a1a18'],
  ['B', '#4ecdc4', '#3aafa6', '#7fecea', '#1a1a18'],
  ['O', '#ff6b6b', '#e05555', '#ffaaaa', '#ffffff'],
  ['M', '#a29bfe', '#7c75db', '#c8c4ff', '#ffffff'],
];

function renderMascots() {
  return MASCOT_CONFIG.map(([letter, bodyFill, shade, cheek, textFill], idx) => `
    <div class="mascot-wrap">
      ${buildMascotSVG(letter, bodyFill, shade, cheek, textFill, idx)}
      <span class="mascot-label">${letter}</span>
    </div>
  `).join('');
}

// ── Eye tracking ──────────────────────────────────────────────
function initMascotBehavior() {
  const authPage = document.querySelector('.auth-page');
  if (!authPage) return;

  // Mascot SVG bounding rects for relative eye movement
  function updateEyes(mouseX, mouseY) {
    MASCOT_CONFIG.forEach((_, idx) => {
      const lPupil = document.getElementById(`pupil-l-${idx}`);
      const rPupil = document.getElementById(`pupil-r-${idx}`);
      const svgEl  = lPupil && lPupil.closest('svg');
      if (!lPupil || !rPupil || !svgEl) return;

      const rect = svgEl.getBoundingClientRect();
      // Centres of eye whites in SVG coords → scale to screen
      const scale = rect.width / 96;
      const ld = _mascotLetterData(MASCOT_CONFIG[idx][0]);
      const eyePositions = [
        { px: rect.left + ld.eyes[0].cx * scale, py: rect.top + ld.eyes[0].cy * scale,
          el: lPupil, baseX: ld.pupils[0].cx, baseY: ld.pupils[0].cy },
        { px: rect.left + ld.eyes[1].cx * scale, py: rect.top + ld.eyes[1].cy * scale,
          el: rPupil, baseX: ld.pupils[1].cx, baseY: ld.pupils[1].cy },
      ];

      eyePositions.forEach(({ px, py, el, baseX, baseY }) => {
        const dx = mouseX - px;
        const dy = mouseY - py;
        const angle = Math.atan2(dy, dx);
        const dist = Math.min(Math.hypot(dx, dy) / 60, 1); // normalize 0–1
        const MAX = 2.8; // max pixel offset in SVG coords
        const ox = Math.cos(angle) * dist * MAX;
        const oy = Math.sin(angle) * dist * MAX;
        el.setAttribute('cx', baseX + ox);
        el.setAttribute('cy', baseY + oy);
      });
    });
  }

  // Mouse move on the whole auth page
  document.addEventListener('mousemove', (e) => {
    if (!document.querySelector('.auth-page')) return;
    updateEyes(e.clientX, e.clientY);
  });

  // Password focus: cover eyes
  function bindPasswordEyes() {
    const passInput = document.getElementById('a-pass');
    if (!passInput) return;
    passInput.addEventListener('focus', () => {
      document.querySelector('.auth-page')?.classList.add('password-focused');
    });
    passInput.addEventListener('blur', () => {
      document.querySelector('.auth-page')?.classList.remove('password-focused');
    });
  }
  bindPasswordEyes();

  // Re-bind after tab switch (DOM is re-rendered)
  // Uses MutationObserver to watch for #a-pass appearing
  const observer = new MutationObserver(() => {
    const pass = document.getElementById('a-pass');
    if (pass && !pass._eyeBound) {
      pass._eyeBound = true;
      pass.addEventListener('focus', () => {
        document.querySelector('.auth-page')?.classList.add('password-focused');
      });
      pass.addEventListener('blur', () => {
        document.querySelector('.auth-page')?.classList.remove('password-focused');
      });
    }
  });
  const root = document.getElementById('root');
  if (root) observer.observe(root, { childList: true, subtree: true });
}

// ══════════════════════════════════════════════════════════════
//  RENDER
// ══════════════════════════════════════════════════════════════
function render() {
  const root = document.getElementById('root');
  if (!state.token) {
    root.innerHTML = renderAuth();
    bindAuth();
    initMascotBehavior();
    return;
  }
  root.innerHTML = renderApp();
  bindApp();
  if (state.page === 'analytics') setTimeout(renderCharts, 50);
}

// ── Auth page ─────────────────────────────────────────────────
function renderAuth() {
  const isLogin = state.authTab === 'login';
  return `
  <div class="auth-page">
    <div class="auth-card">

      <!-- LEFT: Mascot Panel -->
      <div class="auth-mascot-panel">
        <div class="mascot-brand">
          <div class="mascot-dot"></div>
          <span class="mascot-brand-text">CBOM Scanner</span>
        </div>

        <div class="cbom-mascots">
          ${renderMascots()}
        </div>

        <p class="mascot-tagline">
          <strong>C</strong>rypto <strong>B</strong>ill <strong>O</strong>f <strong>M</strong>aterials<br/>
          Quantum Readiness Platform
        </p>
      </div>

      <!-- RIGHT: Form Panel -->
      <div class="auth-form-panel">
        <div class="auth-top">
          <div style="display:flex;align-items:flex-start;justify-content:space-between">
            <div>
              <div class="auth-logo">
                <div class="auth-dot"></div>
                <span style="font-family:var(--mono);font-size:13px;color:#fff">PQC CBOM Scanner</span>
              </div>
              <div class="auth-sub">Quantum Readiness Assessment Platform</div>
            </div>
            <button
              onclick="toggleDarkMode()"
              title="${state.darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}"
              style="background:none;border:1px solid rgba(255,255,255,.15);border-radius:6px;padding:5px 9px;cursor:pointer;display:flex;align-items:center;gap:6px;color:rgba(255,255,255,.6);font-size:12px;font-family:var(--font-body);transition:border-color 150ms,color 150ms;flex-shrink:0;margin-top:2px;"
              onmouseover="this.style.borderColor='rgba(255,255,255,.4)';this.style.color='rgba(255,255,255,.9)'"
              onmouseout="this.style.borderColor='rgba(255,255,255,.15)';this.style.color='rgba(255,255,255,.6)'"
            >
              <div class="theme-toggle-track" style="width:26px;height:15px;"><div class="theme-toggle-thumb" style="width:11px;height:11px;top:2px;left:2px;"></div></div>
              <span>${state.darkMode ? '☾' : '☀'}</span>
            </button>
          </div>
        </div>

        <div class="auth-body">
          <div class="auth-tabs">
            <button class="auth-tab ${isLogin ? 'active' : ''}" onclick="setState({authTab:'login'})">Sign In</button>
            <button class="auth-tab ${!isLogin ? 'active' : ''}" onclick="setState({authTab:'register'})">Register</button>
          </div>

          <div id="auth-error"></div>

          ${isLogin ? `
            <div class="form-group">
              <label class="form-label">Username</label>
              <input class="form-input" id="a-user" placeholder="username" autocomplete="username"/>
            </div>
            <div class="form-group">
              <label class="form-label">Password</label>
              <input class="form-input" id="a-pass" type="password" placeholder="••••••••" autocomplete="current-password"/>
            </div>
            <button class="auth-btn" id="a-submit">Sign In</button>
          ` : `
            <div class="form-group">
              <label class="form-label">Full Name</label>
              <input class="form-input" id="a-name" placeholder="Your name"/>
            </div>
            <div class="form-group">
              <label class="form-label">Username</label>
              <input class="form-input" id="a-user" placeholder="username"/>
            </div>
            <div class="form-group">
              <label class="form-label">Email</label>
              <input class="form-input" id="a-email" type="email" placeholder="you@example.com"/>
            </div>
            <div class="form-group">
              <label class="form-label">Password</label>
              <input class="form-input" id="a-pass" type="password" placeholder="min 8 characters"/>
            </div>
            <button class="auth-btn" id="a-submit">Create Account</button>
          `}
        </div>
      </div>

    </div>
  </div>`;
}

function bindAuth() {
  const showErr = (msg) => {
    const el = document.getElementById('auth-error');
    if (el) el.innerHTML = msg ? `<div class="auth-error">${msg}</div>` : '';
  };
  const btn = document.getElementById('a-submit');
  if (!btn) return;

  btn.onclick = async () => {
    btn.disabled = true; showErr('');
    const user = document.getElementById('a-user')?.value || '';
    const pass = document.getElementById('a-pass')?.value || '';
    let err;
    if (state.authTab === 'login') {
      err = await login(user, pass);
    } else {
      const name  = document.getElementById('a-name')?.value  || '';
      const email = document.getElementById('a-email')?.value || '';
      err = await register(user, email, pass, name);
    }
    if (err) { showErr(err); btn.disabled = false; }
  };

  ['a-user', 'a-pass'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
  });
}

// ── App shell ─────────────────────────────────────────────────
function renderApp() {
  const p = state.page;
  const pages = [
    ['scan',      '⚡', 'New Scan'],
    ['results',   '◎', 'Results'],
    ['analytics', '▦', 'Analytics'],
    ['reports',   '⬇', 'Reports'],
    ['jobs',      '⏱', 'Scheduled Jobs'],
    ['about',     '?',  'About'],
  ];
  const u = state.user || {};
  const completedScans = state.scans.filter(s => s.status === 'complete');

  return `
  <div class="app">
    <aside class="sidebar">
      <div class="sidebar-logo"><div class="s-dot"></div><span class="s-brand">PQC Scanner</span></div>
      <nav class="sidebar-nav">
        ${pages.map(([id, icon, label]) => `
          <button class="nav-item${p === id ? ' active' : ''}" onclick="navigate('${id}')">
            <span class="icon">${icon}</span><span>${label}</span>
            ${id === 'results' && state.scans.length > 0 ? `<span class="nav-badge">${state.scans.length}</span>` : ''}
          </button>`).join('')}
      </nav>
      <div class="sidebar-footer">
        <div class="user-pill">
          <div class="user-avatar">${userInitial(u)}</div>
          <div class="user-info">
            <div class="user-name">${u.username || ''}</div>
            <div class="user-email">${u.email || ''}</div>
          </div>
          <button class="logout-btn" onclick="logout()">Out</button>
        </div>
        <button class="theme-toggle" onclick="toggleDarkMode()" title="${state.darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}">
          <div class="theme-toggle-track"><div class="theme-toggle-thumb"></div></div>
          <span class="theme-toggle-icon">${state.darkMode ? '☾' : '☀'}</span>
          <span class="theme-toggle-label">${state.darkMode ? 'Dark Mode' : 'Light Mode'}</span>
        </button>
      </div>
    </aside>
    <main class="main-content">
      ${p === 'scan'      ? renderScanPage()                  : ''}
      ${p === 'results'   ? renderResultsPage()               : ''}
      ${p === 'analytics' ? renderAnalyticsPage()             : ''}
      ${p === 'reports'   ? renderReportsPage(completedScans) : ''}
      ${p === 'jobs'      ? renderJobsPage()                  : ''}
      ${p === 'about'     ? renderAboutPage()                 : ''}
    </main>
  </div>
  <div class="toast-wrap">
    ${state.toasts.map(t => `<div class="toast ${t.type}">${t.type === 'ok' ? '✓' : '✕'} ${t.msg}</div>`).join('')}
  </div>`;
}

function navigate(page) {
  setState({ page });
  if (page === 'analytics' && !state.analytics) loadAnalytics();
  if (page === 'reports') loadReports();
  if (page === 'jobs') loadJobs();
}

// ── Scan page ─────────────────────────────────────────────────
function renderScanPage() {
  const scans = state.scans;
  return `
  <div class="page-header">
    <div>
      <div class="page-title">New Scan</div>
      <div class="page-sub">Discover subdomains and assess quantum readiness across all endpoints</div>
    </div>
  </div>
  <div class="scan-hero">
    <div class="scan-headline">Scan a domain for PQC readiness</div>
    <div class="scan-sub">Runs 9 discovery sources · TLS enumeration · PQC key exchange detection · CycloneDX CBOM export</div>
    <div class="scan-row">
      <input class="scan-input" id="scan-domain" placeholder="pnb.co.in" onkeydown="if(event.key==='Enter')doScan()"/>
      <button class="scan-btn" onclick="doScan()">Scan Domain →</button>
    </div>
    <div class="scan-opts">
      <div style="display:flex;align-items:center;gap:6px">
        <span class="opt-lbl">Port scope</span>
        <select class="opt-sel" id="scan-ports">
          <option value="top">Top 20 ports</option>
          <option value="web">Web only</option>
        </select>
      </div>
      <div style="display:flex;align-items:center;gap:6px">
        <span class="opt-lbl">Discovery sources</span>
        <span class="mono" style="font-size:11px;color:var(--muted)">crt.sh · HackerTarget · AlienVault · RapidDNS · Shodan · SecurityTrails · VirusTotal · DNS Brute-force</span>
      </div>
    </div>
  </div>
  ${scans.length === 0 ? '' : `
  <div class="page-header" style="margin-bottom:16px"><div class="page-title" style="font-size:15px">Scan History</div></div>
  <div class="tbl">
    <div class="tbl-head" style="grid-template-columns:1fr 80px 110px 120px 90px 70px">
      <span>Domain</span><span>Status</span><span>Risk Score</span><span>Hosts</span><span>Started</span><span>Duration</span>
    </div>
    ${scans.map(s => {
      const sm = s.summary || {};
      const risk = sm.quantum_risk_score ?? '—';
      const rcolor = typeof risk === 'number' ? riskColor(risk) : 'var(--muted)';
      return `<div class="tbl-row" onclick="selectScan('${s.id}')">
        <div class="tbl-cell" style="grid-template-columns:1fr 80px 110px 120px 90px 70px">
          <div><div class="host-name">${s.domain}</div><div class="host-ip">${s.id.slice(0, 8)}</div></div>
          <span class="badge ${s.status === 'complete' ? 'safe' : s.status === 'running' ? 'pqcr' : 'neutral'}">${s.status}</span>
          <span style="font-family:var(--mono);font-size:14px;font-weight:500;color:${rcolor}">${risk}${typeof risk === 'number' ? '<span style="font-size:10px;color:var(--muted)">/100</span>' : ''}</span>
          <span style="font-size:12px;color:var(--muted)">${sm.total_hosts || '—'} hosts</span>
          <span style="font-size:11px;color:var(--muted);font-family:var(--mono)">${fmt(s.started_at)}</span>
          <span style="font-size:11px;color:var(--muted);font-family:var(--mono)">${elapsed(s.elapsed)}</span>
        </div>
      </div>`;
    }).join('')}
  </div>`}`;
}

function doScan() {
  const domain = document.getElementById('scan-domain')?.value || '';
  const ports  = document.getElementById('scan-ports')?.value  || 'top';
  startScan(domain, ports);
}

// ── Results page ──────────────────────────────────────────────
function renderResultsPage() {
  const scan = state.activeScan;
  if (!scan) return `<div class="empty"><div class="empty-icon">◎</div>No scan selected. Start a scan from New Scan.</div>`;
  if (scan.status === 'running') return renderProgress(scan) + renderLiveHosts(scan);
  if (scan.status === 'error')   return `<div class="empty" style="color:var(--danger)"><div class="empty-icon">✕</div>${scan.message || 'Scan failed'}</div>`;
  if (!scan.results || scan.results.length === 0) return `<div class="empty"><div class="empty-icon">◎</div>Scan complete — no responsive hosts found.</div>`;
  return renderScanResults(scan);
}

function renderProgress(scan) {
  const pct = scan.progress || 0;
  const events = scan.events || [];
  const rows = events.slice(-18).map(e => {
    const cls = e.type === 'complete' ? 'log-safe' : e.type === 'error' ? 'log-warn' : '';
    return `<div class="log-line"><span class="log-time">${e.ts ? new Date(e.ts).toLocaleTimeString('en', { hour12: false }) : '—'}</span><span class="${cls}">${e.message || ''}</span></div>`;
  }).join('');
  return `
  <div class="progress-card">
    <div class="progress-head">
      <div class="progress-title"><div class="spinner"></div>Scanning ${scan.domain}…</div>
      <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">${pct}%</span>
    </div>
    <div class="progress-bar-wrap"><div class="progress-bar" style="width:${pct}%"></div></div>
    <div class="progress-log">${rows || '<div class="log-line"><span style="color:var(--dim)">Initialising…</span></div>'}</div>
  </div>`;
}

function renderLiveHosts(scan) {
  const hosts = (scan.results || []).slice(0, 20);
  if (hosts.length === 0) return '';
  return `<div style="margin-top:4px;font-size:12px;color:var(--muted);font-weight:500;margin-bottom:10px">${hosts.length} hosts discovered so far</div>
  <div class="tbl">
    <div class="tbl-head" style="grid-template-columns:1fr 1fr 1fr 120px">
      <span>Hostname</span><span>IP</span><span>Ports</span><span>Status</span>
    </div>
    ${hosts.map(h => {
      const worst = getWorstPqc(h);
      return `<div class="tbl-row"><div class="tbl-cell" style="grid-template-columns:1fr 1fr 1fr 120px">
        <span class="host-name">${h.hostname}</span>
        <span class="host-ip">${h.ip || '—'}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">${h.ports.map(p => ':' + p.port).join(' ')}</span>
        ${worst ? `<span class="badge ${lcClass(worst.label_class)}">${worst.label}</span>` : `<span class="badge neutral">No TLS</span>`}
      </div></div>`;
    }).join('')}
  </div>`;
}

function getWorstPqc(host) {
  const order = { danger: 0, warn: 1, 'pqc-ready': 2, safe: 3 };
  let worst = null;
  for (const p of host.ports) {
    if (!p.pqc) continue;
    if (worst === null || order[p.pqc.label_class] < order[worst.label_class]) worst = p.pqc;
  }
  return worst;
}

function renderScanResults(scan) {
  const sm = scan.summary || {};
  const risk = sm.quantum_risk_score ?? 0;
  const rLabel = risk <= 20 ? 'Low Risk' : risk <= 60 ? 'Medium Risk' : 'High Risk';
  const filter = state.scanFilter || 'all';
  const circ = 2 * Math.PI * 24;
  const fill = circ - (risk / 100) * circ;

  const filtered = filter === 'all' ? scan.results
    : scan.results.filter(h => h.ports.some(p => p.pqc?.label_class === filter));

  return `
  <div class="page-header">
    <div>
      <div class="page-title">${scan.domain}</div>
      <div class="page-sub">${scan.results.length} hosts · ${elapsed(scan.elapsed)} · ${fmt(scan.started_at)}</div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="scan-btn" style="background:var(--white);color:var(--text);border:1px solid var(--border);height:36px;padding:0 14px;font-size:12px" onclick="navigate('reports')">Generate Report</button>
    </div>
  </div>
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-val">${sm.total_hosts || 0}</div><div class="stat-label">Hosts Scanned</div></div>
    <div class="stat-card"><div class="stat-val">${sm.tls_endpoints || 0}</div><div class="stat-label">TLS Endpoints</div></div>
    <div class="stat-card"><div class="stat-val safe">${sm.fully_quantum_safe || 0}</div><div class="stat-label">Fully Quantum Safe</div></div>
    <div class="stat-card"><div class="stat-val pqc">${sm.pqc_ready || 0}</div><div class="stat-label">PQC Ready</div></div>
    <div class="stat-card"><div class="stat-val warn">${sm.pqc_not_ready || 0}</div><div class="stat-label">PQC Not Ready</div></div>
    <div class="stat-card"><div class="stat-val danger">${sm.not_quantum_safe || 0}</div><div class="stat-label">Not Quantum Safe</div></div>
    <div class="stat-card"><div class="stat-val">${sm.labels_awarded || 0}</div><div class="stat-label">Labels Awarded</div></div>
    <div class="stat-card">
      <div class="risk-wrap">
        <div class="gauge">
          <svg viewBox="0 0 56 56">
            <circle cx="28" cy="28" r="24" fill="none" stroke="var(--border)" stroke-width="5"/>
            <circle cx="28" cy="28" r="24" fill="none" stroke="${riskColor(risk)}" stroke-width="5"
              stroke-dasharray="${circ}" stroke-dashoffset="${fill}" stroke-linecap="round"/>
          </svg>
          <div class="gauge-num" style="color:${riskColor(risk)}">${risk}</div>
        </div>
        <div>
          <div style="font-size:12px;font-weight:500;color:${riskColor(risk)}">${rLabel}</div>
          <div style="font-size:11px;color:var(--muted)">Quantum Risk Score</div>
        </div>
      </div>
    </div>
  </div>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
    <div style="font-size:14px;font-weight:500">${filtered.length} hosts</div>
    <div class="filter-bar">
      ${[['all', 'All'], ['danger', 'Not Safe'], ['warn', 'Not Ready'], ['pqc-ready', 'PQC Ready'], ['safe', 'Fully Safe']].map(([f, l]) =>
        `<button class="fbtn${filter === f ? ' active' : ''}" onclick="setState({scanFilter:'${f}'})">${l}</button>`).join('')}
    </div>
  </div>
  <div class="tbl">
    <div class="tbl-head" style="grid-template-columns:1fr 110px 80px 150px 100px 24px">
      <span>Hostname / IP</span><span>Open Ports</span><span>TLS</span><span>PQC Status</span><span>TLS Version</span><span></span>
    </div>
    ${filtered.map((h, i) => renderHostRow(h, i)).join('')}
  </div>`;
}

function renderHostRow(h, i) {
  const worst = getWorstPqc(h);
  const lc = worst ? lcClass(worst.label_class) : 'neutral';
  const openPorts = h.ports.map(p => ':' + p.port).join(' ');
  const tlsPorts = h.ports.filter(p => p.has_tls);
  const topTls = tlsPorts[0]?.tls?.version || '—';
  const isOpen = state['hostOpen_' + i];

  return `
  <div class="tbl-row">
    <div class="tbl-cell" style="grid-template-columns:1fr 110px 80px 150px 100px 24px" onclick="toggleHost(${i})">
      <div><div class="host-name">${h.hostname}</div><div class="host-ip">${h.ip || '—'}</div></div>
      <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">${openPorts}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">${tlsPorts.length} TLS</span>
      ${worst ? `<span class="badge ${lc}">${worst.label}</span>` : `<span class="badge neutral">No TLS</span>`}
      <span style="font-family:var(--mono);font-size:11px">${topTls}</span>
      <span style="color:var(--muted);font-size:12px">${isOpen ? '▲' : '▼'}</span>
    </div>
    ${isOpen ? `<div class="host-detail"><div class="port-cards">${h.ports.map(p => renderPortCard(p)).join('')}</div></div>` : ''}
  </div>`;
}

function toggleHost(i) {
  state['hostOpen_' + i] = !state['hostOpen_' + i];
  render();
}

function renderPortCard(port) {
  if (!port.has_tls) return `
    <div class="port-card"><div class="port-head">
      <span class="port-num">:${port.port}</span>
      <span class="port-svc">${port.service_type || ''}</span>
      <span class="badge neutral">No TLS</span>
    </div></div>`;

  const tls  = port.tls  || {};
  const cert = port.certificate || {};
  const pqc  = port.pqc  || {};
  const lc   = lcClass(pqc.label_class);
  const kexCls  = tls.key_exchange_pqc ? 'safe' : 'danger';
  const certCls = cert.sig_is_pqc       ? 'safe' : 'danger';
  const isDanger = pqc.label_class === 'danger';

  const cipherPills = (tls.all_ciphers || []).map(c => {
    const cls = (tls.pqc_ciphers || []).includes(c) ? 'safe' : (tls.vulnerable_ciphers || []).includes(c) ? 'danger' : 'neutral';
    return `<span class="cp ${cls}">${c}</span>`;
  }).join('');

  const recs = (pqc.recommendations || []).map(r => `<div class="rec ${isDanger ? 'd' : ''}">${r}</div>`).join('');
  const san  = (cert.san_domains || []).slice(0, 5).join(', ') + (cert.san_domains?.length > 5 ? ` +${cert.san_domains.length - 5} more` : '');

  return `
  <div class="port-card">
    <div class="port-head">
      <span class="port-num">:${port.port}</span>
      <span class="port-svc">${port.service_type || ''}</span>
      <span class="badge neutral" style="margin-right:4px">${tls.version || '—'}</span>
      <span class="badge ${lc}">${pqc.label || '—'}</span>
    </div>
    <div class="port-body">
      <div class="di"><div class="dk">Preferred Cipher</div><div class="dv">${tls.preferred_cipher || '—'}</div></div>
      <div class="di"><div class="dk">Key Exchange</div><div class="dv ${kexCls}">${tls.key_exchange || '—'}</div></div>
      <div class="di"><div class="dk">Detection</div><div class="dv">${tls.detection_method || '—'}</div></div>
      <div class="di"><div class="dk">Cert Subject</div><div class="dv">${cert.subject || '—'}</div></div>
      <div class="di"><div class="dk">Cert Issuer</div><div class="dv">${cert.issuer || '—'}</div></div>
      <div class="di"><div class="dk">Expiry</div><div class="dv">${cert.expiry || '—'}</div></div>
      <div class="di"><div class="dk">Signature Algo</div><div class="dv ${certCls}">${cert.sig_algorithm || '—'}</div></div>
      <div class="di"><div class="dk">Public Key</div><div class="dv">${cert.key_type || ''} ${cert.key_bits || ''}‑bit</div></div>
      <div class="di"><div class="dk">PQC Certificate</div><div class="dv ${cert.sig_is_pqc ? 'safe' : 'danger'}">${cert.sig_is_pqc ? 'Yes' : 'No'}</div></div>
      ${san ? `<div class="di full"><div class="dk">SAN Domains</div><div class="dv">${san}</div></div>` : ''}
      ${tls.all_ciphers?.length ? `<div class="di full"><div class="dk">All Ciphers (${tls.all_ciphers.length})</div><div class="cipher-pills">${cipherPills}</div></div>` : ''}
      ${recs ? `<div class="di full"><div class="dk">Recommendations</div><div class="rec-list">${recs}</div></div>` : ''}
    </div>
  </div>`;
}

// ── Analytics page ────────────────────────────────────────────
function renderAnalyticsPage() {
  const a = state.analytics;
  if (!a) return `<div class="empty"><div class="empty-icon">▦</div>Loading analytics…</div>`;
  const sm = a.latest_summary || {};
  const risk = sm.quantum_risk_score ?? 0;

  return `
  <div class="page-header">
    <div>
      <div class="page-title">Analytics</div>
      <div class="page-sub">${a.total_scans} scans analysed · All domains</div>
    </div>
    <button class="scan-btn" style="background:var(--white);color:var(--text);border:1px solid var(--border);height:36px;padding:0 14px;font-size:12px" onclick="loadAnalytics()">↻ Refresh</button>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-val">${a.total_scans}</div><div class="stat-label">Total Scans</div></div>
    <div class="stat-card"><div class="stat-val safe">${sm.fully_quantum_safe || 0}</div><div class="stat-label">Fully Safe (latest)</div></div>
    <div class="stat-card"><div class="stat-val danger">${sm.not_quantum_safe || 0}</div><div class="stat-label">Not Safe (latest)</div></div>
    <div class="stat-card"><div class="stat-val" style="color:${riskColor(risk)}">${risk}</div><div class="stat-label">Latest Risk Score</div></div>
  </div>

  <div class="chart-grid">
    <div class="card"><div class="card-header"><span class="card-title">Quantum Risk Score — Over Time</span></div><div class="chart-wrap"><canvas id="chart-risk-trend"></canvas></div></div>
    <div class="card"><div class="card-header"><span class="card-title">PQC Status Distribution (latest scan)</span></div><div class="chart-wrap"><canvas id="chart-pqc-donut"></canvas></div></div>
  </div>

  <div class="chart-grid">
    <div class="card"><div class="card-header"><span class="card-title">TLS Version Breakdown</span></div><div class="chart-wrap"><canvas id="chart-tls-bar"></canvas></div></div>
    <div class="card"><div class="card-header"><span class="card-title">Open Port Frequency (Heatmap)</span></div><div class="chart-wrap"><canvas id="chart-port-heat"></canvas></div></div>
  </div>

  <div class="card" style="margin-bottom:24px">
    <div class="card-header"><span class="card-title">Top Cipher Suites (all scans)</span></div>
    <div class="chart-wrap tall"><canvas id="chart-cipher-bar"></canvas></div>
  </div>

  <div class="page-header" style="margin-bottom:14px"><div class="page-title" style="font-size:15px">Scan Timeline</div></div>
  <div class="tbl">
    <div class="tbl-head" style="grid-template-columns:1fr 80px 90px 90px 80px">
      <span>Domain</span><span>Risk</span><span>Hosts</span><span>Date</span><span>Action</span>
    </div>
    ${(a.scans || []).slice().reverse().map(s => `
      <div class="tbl-row"><div class="tbl-cell" style="grid-template-columns:1fr 80px 90px 90px 80px">
        <span class="host-name">${s.domain}</span>
        <span style="font-family:var(--mono);font-size:14px;font-weight:500;color:${riskColor(s.risk)}">${s.risk}</span>
        <span style="font-size:12px;color:var(--muted)">${s.summary?.total_hosts ?? '—'} hosts</span>
        <span style="font-size:11px;color:var(--muted);font-family:var(--mono)">${fmt(s.date)}</span>
        <button class="scan-btn" style="height:28px;padding:0 10px;font-size:11px" onclick="selectScan('${s.id}')">View</button>
      </div></div>`).join('')}
  </div>`;
}

// ── Reports page ──────────────────────────────────────────────
function renderReportsPage(completedScans) {
  const reports = state.reports;
  return `
  <div class="page-header">
    <div>
      <div class="page-title">Reports</div>
      <div class="page-sub">Generate, schedule, and deliver scan reports via email</div>
    </div>
  </div>
  <div class="smtp-note">
    📧 Email reports are sent from the server's configured SMTP address. Just enter recipient email(s) below — no SMTP credentials needed here.
  </div>
  <div class="rep-grid">
    <div class="rep-card">
      <div class="rep-icon">⚡</div>
      <div class="rep-title">On-Demand Report</div>
      <div class="rep-desc">Generate immediately from a completed scan. Download or email.</div>
      <div class="rf">
        <div><label class="fl">Scan</label>
          <select class="fs" id="od-scan">
            <option value="">— select scan —</option>
            ${completedScans.map(s => `<option value="${s.id}">${s.domain} · ${fmt(s.started_at)}</option>`).join('')}
          </select>
        </div>
        <div><label class="fl">Format</label>
          <select class="fs" id="od-fmt">
            <option value="html">HTML</option>
            <option value="json">JSON</option>
            <option value="cbom">CycloneDX CBOM</option>
          </select>
        </div>
        <div><label class="fl">Email recipients (optional, comma separated)</label>
          <input class="fi" id="od-email" placeholder="ciso@bank.com, security@bank.com"/>
        </div>
        <div><label class="fl">Notes (optional)</label><input class="fi" id="od-notes" placeholder="Q1 audit review"/></div>
        <button class="sbtn" onclick="doOnDemand()">Generate Report</button>
      </div>
    </div>

    <div class="rep-card">
      <div class="rep-icon">🗓</div>
      <div class="rep-title">Scheduled Report</div>
      <div class="rep-desc">Trigger a fresh scan + report at a specific future time.</div>
      <div class="rf">
        <div><label class="fl">Domain</label><input class="fi" id="sc-domain" placeholder="pnb.co.in"/></div>
        <div><label class="fl">Run at</label><input class="fi" id="sc-runat" type="datetime-local"/></div>
        <div><label class="fl">Label</label><input class="fi" id="sc-label" placeholder="Monthly audit"/></div>
        <div><label class="fl">Format</label>
          <select class="fs" id="sc-fmt">
            <option value="html">HTML</option>
            <option value="json">JSON</option>
            <option value="cbom">CBOM</option>
          </select>
        </div>
        <div><label class="fl">Email recipients (optional)</label><input class="fi" id="sc-email" placeholder="team@bank.com"/></div>
        <button class="sbtn" onclick="doScheduled()">Schedule Report</button>
      </div>
    </div>

    <div class="rep-card">
      <div class="rep-icon">🔁</div>
      <div class="rep-title">Frequency Report</div>
      <div class="rep-desc">Automatically scan every N hours/days/weeks. Continuous monitoring.</div>
      <div class="rf">
        <div><label class="fl">Domain</label><input class="fi" id="fr-domain" placeholder="pnb.co.in"/></div>
        <div class="fr2">
          <div><label class="fl">Every</label><input class="fi" id="fr-val" type="number" min="1" value="7"/></div>
          <div><label class="fl">Unit</label>
            <select class="fs" id="fr-unit">
              <option value="hours">Hours</option>
              <option value="days" selected>Days</option>
              <option value="weeks">Weeks</option>
            </select>
          </div>
        </div>
        <div><label class="fl">Label</label><input class="fi" id="fr-label" placeholder="Weekly PNB monitoring"/></div>
        <div><label class="fl">Max runs (blank = forever)</label><input class="fi" id="fr-max" type="number" min="1" placeholder="52"/></div>
        <div><label class="fl">Email recipients (optional)</label><input class="fi" id="fr-email" placeholder="soc@bank.com"/></div>
        <button class="sbtn" onclick="doFrequency()">Activate Monitoring</button>
      </div>
    </div>
  </div>

  ${reports.length === 0 ? '' : `
  <div class="page-header" style="margin-bottom:14px"><div class="page-title" style="font-size:15px">Generated Reports</div></div>
  <div class="tbl">
    <div class="tbl-head" style="grid-template-columns:1fr 90px 80px 140px 80px 80px">
      <span>Domain</span><span>Type</span><span>Format</span><span>Generated</span><span>Email</span><span>Download</span>
    </div>
    ${reports.map(r => `
      <div class="tbl-row"><div class="tbl-cell" style="grid-template-columns:1fr 90px 80px 140px 80px 80px;cursor:default">
        <div><div class="host-name">${r.domain || '—'}</div><div class="host-ip">${r.id.slice(0, 8)}</div></div>
        <span class="badge neutral">${r.report_type}</span>
        <span style="font-family:var(--mono);font-size:10px;color:var(--muted);text-transform:uppercase">${r.format}</span>
        <span style="font-size:11px;color:var(--muted);font-family:var(--mono)">${fmt(r.created_at)}</span>
        <span style="font-size:11px;color:${r.email_status === 'sent' ? 'var(--safe)' : 'var(--muted)'}">${r.email_status || '—'}</span>
        ${r.status === 'ready'
          ? `<a href="${API}/report/${r.id}/download?token=${encodeURIComponent(state.token || '')}" target="_blank" style="font-size:11px;color:var(--pqc);font-weight:500;text-decoration:none">Download ↗</a>`
          : `<span style="font-size:11px;color:var(--dim)">${r.status}</span>`}
      </div></div>`).join('')}
  </div>`}`;
}

function doOnDemand() {
  const scanId  = document.getElementById('od-scan')?.value;
  const fmtVal  = document.getElementById('od-fmt')?.value || 'html';
  const emailTo = document.getElementById('od-email')?.value || '';
  const notes   = document.getElementById('od-notes')?.value || '';
  if (!scanId) { toast('Select a scan first', 'err'); return; }
  submitOnDemand(scanId, fmtVal, emailTo, !!emailTo, notes);
}

function doScheduled() {
  submitScheduled({
    domain:     document.getElementById('sc-domain')?.value || '',
    run_at:     document.getElementById('sc-runat')?.value || '',
    format:     document.getElementById('sc-fmt')?.value || 'html',
    label:      document.getElementById('sc-label')?.value || '',
    email_to:   document.getElementById('sc-email')?.value || '',
    send_email: !!(document.getElementById('sc-email')?.value),
  });
}

function doFrequency() {
  submitFrequency({
    domain:         document.getElementById('fr-domain')?.value || '',
    interval_value: document.getElementById('fr-val')?.value || '7',
    interval_unit:  document.getElementById('fr-unit')?.value || 'days',
    label:          document.getElementById('fr-label')?.value || '',
    max_runs:       document.getElementById('fr-max')?.value || '',
    email_to:       document.getElementById('fr-email')?.value || '',
    send_email:     !!(document.getElementById('fr-email')?.value),
  });
}

// ── Jobs page ─────────────────────────────────────────────────
function renderJobsPage() {
  const jobs = state.jobs;
  return `
  <div class="page-header">
    <div>
      <div class="page-title">Scheduled Jobs</div>
      <div class="page-sub">${jobs.filter(j => j.status === 'active').length} active jobs</div>
    </div>
    <button class="scan-btn" style="background:var(--white);color:var(--text);border:1px solid var(--border);height:36px;padding:0 14px;font-size:12px" onclick="loadJobs()">↻ Refresh</button>
  </div>
  ${jobs.length === 0
    ? `<div class="empty"><div class="empty-icon">⏱</div>No jobs yet. Create one in Reports.</div>`
    : `<div class="tbl">
      <div class="jobs-head"><span>Job</span><span>Type</span><span>Status</span><span>Next Run</span><span>Action</span></div>
      ${jobs.map(j => `
        <div class="job-row">
          <div>
            <div style="font-size:13px;font-weight:500">${j.label || j.domain}</div>
            <div style="font-size:11px;color:var(--muted);font-family:var(--mono)">${j.domain} · ${j.interval_value ? j.interval_value + ' ' + j.interval_unit : fmt(j.next_run_at)}</div>
          </div>
          <span class="badge neutral">${j.job_type}</span>
          <span class="badge ${j.status === 'active' ? 'safe' : j.status === 'completed' ? 'neutral' : 'danger'}">${j.status}</span>
          <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">${fmt(j.next_run_at)}</span>
          ${j.status === 'active'
            ? `<button class="cancel-btn" onclick="cancelJob('${j.id}')">Cancel</button>`
            : `<span style="font-size:11px;color:var(--dim)">—</span>`}
        </div>`).join('')}
    </div>`}`;
}

// ── About page ────────────────────────────────────────────────
function renderAboutPage() {
  return `
  <div class="page-header">
    <div>
      <div class="page-title">About</div>
      <div class="page-sub">NIST FIPS 203/204/205 · CycloneDX 1.6 · CBOM</div>
    </div>
  </div>
  <div class="info-grid">
    ${[
      ['NIST FIPS 203', 'ML-KEM (Kyber)',    'Post-quantum key encapsulation standard. Replaces ECDH/X25519 in TLS key exchange.'],
      ['NIST FIPS 204', 'ML-DSA (Dilithium)','Post-quantum digital signature standard. Replaces RSA and ECDSA in X.509 certificates.'],
      ['NIST FIPS 205', 'SLH-DSA (SPHINCS+)','Hash-based PQC signature scheme. Security based purely on hash functions.'],
      ['HNDL Threat',   'Harvest Now, Decrypt Later','Adversaries record encrypted traffic today to decrypt when quantum computers exist. Banking data is highest priority.'],
      ['CycloneDX 1.6 CBOM','Cryptographic Bill of Materials','Industry standard for inventorying cryptographic assets — enables compliance, risk tracking, migration planning.'],
      ['Hybrid PQC',    'Transition Strategy','Deploy X25519 + ML-KEM-768 together. Protects against HNDL now while maintaining backward compatibility.'],
    ].map(([tag, title, desc]) => `
      <div class="info-card">
        <div class="info-tag">${tag}</div>
        <h4>${title}</h4>
        <p>${desc}</p>
      </div>`).join('')}
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">PQC Readiness Labels</span></div>
    <div style="display:flex;flex-direction:column;gap:10px">
      ${[
        ['safe',  'FULLY QUANTUM SAFE','TLS 1.3 + PQC key exchange (ML-KEM) + PQC certificate signature (ML-DSA/SLH-DSA). Fully NIST compliant.'],
        ['pqcr',  'PQC READY',         'TLS 1.3 + PQC KEX, classical certificate. Protected against HNDL. Certificate migration recommended.'],
        ['warn',  'PQC NOT READY',     'TLS 1.3 but classical key exchange. Vulnerable to harvest-now-decrypt-later.'],
        ['danger','NOT QUANTUM SAFE',  'TLS 1.2 or below. Immediate upgrade required.'],
      ].map(([lc, label, desc]) => `
        <div style="display:flex;align-items:flex-start;gap:12px">
          <span class="badge ${lc}" style="margin-top:1px;white-space:nowrap">${label}</span>
          <span style="font-size:12px;color:var(--muted);line-height:1.6">${desc}</span>
        </div>`).join('')}
    </div>
  </div>`;
}

function bindApp() {}

// ── Init ──────────────────────────────────────────────────────
if (state.token) { loadScans(); }
render();