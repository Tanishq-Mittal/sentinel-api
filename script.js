// Lucide Icons Render Init
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initNavigation();
  initFileUpload();
  initCopilot();
  loadDashboardData();
  loadDatabaseData();
});

// Single Page View Navigation Manager
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  
  navButtons.forEach(button => {
    button.addEventListener('click', () => {
      const targetViewId = button.getAttribute('data-target');
      navigateTo(targetViewId);
    });
  });
}

function navigateTo(viewId) {
  // Hide all active views
  document.querySelectorAll('.page-view').forEach(view => {
    view.classList.remove('active');
  });

  // Deactivate all sidebar nav buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.remove('active');
    
    // Remove Aurora edge indicator
    const edge = btn.querySelector('.aurora-edge');
    if (edge) edge.remove();
  });

  // Activate target view
  const targetView = document.getElementById(viewId);
  if (targetView) {
    targetView.classList.add('active');
  }

  // Highlight corresponding sidebar button
  const activeBtn = document.querySelector(`.nav-item[data-target="${viewId}"]`);
  if (activeBtn) {
    activeBtn.classList.add('active');
    
    // Inject Aurora Edge
    const auroraEdge = document.createElement('span');
    auroraEdge.className = 'aurora-edge';
    activeBtn.prepend(auroraEdge);
  }
}

// Drag & Drop File Upload Handler
function initFileUpload() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');

  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--ice)';
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--border-color)';
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleUploadedFile(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleUploadedFile(e.target.files[0]);
    }
  });
}

function handleUploadedFile(file) {
  const specSummary = document.getElementById('specSummary');
  const fileName = document.getElementById('fileName');
  const fileMeta = document.getElementById('fileMeta');

  fileName.textContent = file.name;
  fileMeta.textContent = `Ready to parse • ${(file.size / 1024).toFixed(1)} KB`;
  specSummary.style.display = 'flex';
  specSummary.dataset.filename = file.name;
}

async function startScanProcess() {
  const summary = document.getElementById('specSummary');
  if (!summary || summary.style.display === 'none') {
    navigateTo('new-scan');
    document.getElementById('dropzone')?.classList.add('dropzone-attention');
    return;
  }

  const fileInput = document.getElementById('fileInput');
  const file = fileInput?.files?.[0];
  if (!file) return;
  const scanButton = document.querySelector('#new-scan .btn-lg');
  if (scanButton) {
    scanButton.disabled = true;
    scanButton.innerHTML = '<i data-lucide="loader-circle"></i> Scanning specification...';
    lucide.createIcons();
  }

  try {
    const formData = new FormData();
    formData.append('spec', file);
    const response = await fetch('/api/scans', { method: 'POST', body: formData });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Scan could not be saved.');
    window.latestScan = result;
    updateDashboard(result);
    refreshHistory(result);
    if (scanButton) {
      scanButton.disabled = false;
      scanButton.innerHTML = '<i data-lucide="check-circle"></i> Saved to SQLite';
      lucide.createIcons();
    }
    navigateTo('vulnerabilities');
  } catch (error) {
    if (scanButton) {
      scanButton.disabled = false;
      scanButton.innerHTML = '<i data-lucide="play"></i> Start Security Scan';
      lucide.createIcons();
    }
    alert(error.message);
  }
}

async function loadDashboardData() {
  try {
    const response = await fetch('/api/dashboard');
    if (!response.ok) return;
    const data = await response.json();
    const latestSummary = data.scans?.[0];
    const latestDetail = latestSummary ? await fetch(`/api/scans/${latestSummary.id}`).then(item => item.ok ? item.json() : latestSummary) : data.latest;
    updateDashboard({ ...data.latest, ...latestDetail }, data);
    renderHistory(data.scans);
  } catch (error) {
    console.warn('SQLite API unavailable:', error.message);
  }
}

function updateDashboard(scan, data = {}) {
  const latest = scan || {};
  const totals = data.totals || {};
  document.getElementById('securityScore').firstChild.textContent = latest.score || 0;
  document.getElementById('criticalFindings').textContent = latest.finding_count || 0;
  document.getElementById('endpointCount').textContent = latest.endpoint_count || 0;
  document.getElementById('scanCount').textContent = totals.scans ?? 0;
  document.getElementById('inventoryScanCount').textContent = totals.scans ?? 0;
  document.getElementById('inventoryEndpointCount').textContent = totals.endpoints ?? 0;
  const badge = document.querySelector('[data-target="vulnerabilities"] .nav-badge');
  if (badge) badge.textContent = `${latest.finding_count || 0} Findings`;
  if (latest.findings?.length) {
    const finding = latest.findings[0];
    document.getElementById('vulnerabilityPath').textContent = `${finding.path || 'API route'} · ${finding.severity}`;
    document.getElementById('vulnerabilityTitle').textContent = finding.title;
    document.getElementById('vulnerabilityDescription').textContent = finding.description;
  }
}

function renderHistory(scans = []) {
  const list = document.getElementById('historyList');
  if (!list) return;
  list.innerHTML = scans.length ? scans.map(scan => {
    const date = new Date(scan.created_at);
    return `<div class="data-row"><span class="history-date">${date.toLocaleDateString(undefined, { day: '2-digit', month: 'short' }).toUpperCase()}<br><small>${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</small></span><div><strong>${escapeHtml(scan.filename)}</strong><small>${scan.endpoint_count} endpoints · ${scan.finding_count} findings</small></div><span class="score-pill ${scan.score >= 70 ? 'score-good' : 'score-warning'}">${scan.score} / 100</span></div>`;
  }).join('') : '<div class="empty-state">No scans saved yet. Upload an OpenAPI file to begin.</div>';
}

function refreshHistory(scan) {
  renderHistory([scan]);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
}

/* Keep the old transition behavior only for non-API callers. */
function finishScanButton(scanButton) {
    if (scanButton) {
      scanButton.disabled = false;
      scanButton.innerHTML = '<i data-lucide="check-circle"></i> Saved to SQLite';
      lucide.createIcons();
    }
}

function downloadReport(name) {
  const report = `SENTINEL API SECURITY REPORT\n${name}\nGenerated: ${new Date().toLocaleDateString()}\n\nSecurity score: 78/100\nCritical findings: 3\nEndpoints analyzed: 142`;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([report], { type: 'text/plain' }));
  link.download = `${name}.txt`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function saveSettings() {
  const button = document.querySelector('#settings .btn-primary');
  if (!button) return;
  button.innerHTML = '<i data-lucide="check"></i> Saved';
  lucide.createIcons();
  setTimeout(() => {
    button.innerHTML = '<i data-lucide="save"></i> Save changes';
    lucide.createIcons();
  }, 1600);
}

async function loadDatabaseData() {
  try {
    const response = await fetch('/api/database');
    if (!response.ok) return;
    const data = await response.json();
    const container = document.getElementById('databaseTables');
    if (!container) return;
    container.innerHTML = data.tables.map(table => `<div class="database-table"><i data-lucide="table-2"></i><span><strong>${escapeHtml(table.name)}</strong><small>${table.rows} saved rows</small></span><span class="table-state">LIVE</span></div>`).join('');
    lucide.createIcons();
  } catch (error) {
    console.warn('Database metadata unavailable:', error.message);
  }
}

function initCopilot() {
  const form = document.getElementById('chatForm');
  const input = document.getElementById('chatInput');
  if (!form || !input) return;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    appendChatMessage('user', message);
    input.value = '';
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      const response = await fetch('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Copilot is unavailable.');
      appendChatMessage('assistant', result.answer);
    } catch (error) {
      appendChatMessage('assistant', `I could not reach the local analysis service: ${error.message}`);
    } finally {
      button.disabled = false;
      input.focus();
    }
  });
}

function appendChatMessage(role, message) {
  const container = document.getElementById('chatMessages');
  if (!container) return;
  const bubble = document.createElement('div');
  bubble.className = `chat-message ${role}`;
  bubble.innerHTML = `<strong>${role === 'user' ? 'You' : 'Copilot'}</strong><p>${escapeHtml(message)}</p>`;
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
}

async function downloadDatabaseSnapshot() {
  const response = await fetch('/api/database');
  const snapshot = await response.json();
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
  link.download = 'sentinel-database-snapshot.json';
  link.click();
  URL.revokeObjectURL(link.href);
}