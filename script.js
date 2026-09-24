'use strict';

/* ==========================================================================
   SENTINEL // API SECURITY SCANNER
   Vanilla ES6 application layer. Backend contracts remain unchanged.
   ========================================================================== */

const state = {
  dashboard: {
    latest: {},
    totals: { scans: 0, endpoints: 0, findings: 0 },
    scans: []
  },
  latestScan: null,
  database: null,
  uploadedFile: null,
  selectedFindingKey: null,
  selectedFindingIndex: null,
  selectedRequest: '',
  detailUnavailable: false,
  inventoryFilter: 'all',
  inventorySearch: '',
  vulnerabilityFilter: 'all',
  chatBusy: false,
  scanInProgress: false,
  scanCompleted: false,
  progressIndex: 0,
  progressTimer: null,
  activeView: 'dashboard',
  settings: {
    scanNotifications: true,
    includePoc: true,
    defaultEnvironment: 'lab',
    safeScanning: true,
    compactDensity: false,
    allowMotion: true
  }
};

const PAGE_META = {
  dashboard: {
    section: 'OVERVIEW',
    title: 'DASHBOARD',
    description: 'Monitor your API security and investigate vulnerabilities'
  },
  'new-scan': {
    section: 'SCANNING',
    title: 'NEW SCAN',
    description: 'Upload an API specification and start a security review'
  },
  vulnerabilities: {
    section: 'SECURITY',
    title: 'VULNERABILITIES',
    description: 'Review and fix security issues found in your APIs'
  },
  inventory: {
    section: 'SECURITY',
    title: 'API INVENTORY',
    description: 'Review the endpoints discovered in your scans'
  },
  history: {
    section: 'SCANNING',
    title: 'SCAN HISTORY',
    description: 'Review previous API security scans'
  },
  insights: {
    section: 'REPORTING',
    title: 'SENTINEL AI',
    description: 'Understand your scan results in plain language'
  },
  reports: {
    section: 'REPORTING',
    title: 'REPORTS',
    description: 'Download clear security reports for your team'
  },
  settings: {
    section: 'SYSTEM',
    title: 'SETTINGS',
    description: 'Manage scan defaults and workspace preferences'
  }
};

const SEVERITIES = [
  { key: 'critical', label: 'CRITICAL' },
  { key: 'high', label: 'HIGH' },
  { key: 'medium', label: 'MEDIUM' },
  { key: 'low', label: 'LOW' }
];

const SCAN_STAGES = [
  'initializing',
  'parsing',
  'discovering',
  'generating',
  'authorization',
  'analyzing',
  'severity',
  'complete'
];

const SCAN_STAGE_LABELS = {
  initializing: 'INITIALIZING SCANNER',
  parsing: 'PARSING API SPECIFICATION',
  discovering: 'DISCOVERING ENDPOINTS',
  generating: 'PREPARING SECURITY CONTROL CONTEXT',
  authorization: 'RUNNING AUTHORIZATION CHECKS',
  analyzing: 'ANALYZING SPECIFICATION SIGNALS',
  severity: 'CALCULATING SEVERITY',
  complete: 'SCAN COMPLETE'
};

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.json', '.yaml', '.yml'];

class ApiError extends Error {
  constructor(message, kind = 'unknown', status = 0, payload = null, cause = null) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
    this.payload = payload;
    this.cause = cause;
  }
}

function $(id) {
  return document.getElementById(id);
}

function queryAll(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[character]));
}

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function formatBytes(bytes) {
  const size = safeNumber(bytes);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(value, options = {}) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    ...options
  }).format(date).toUpperCase();
}

function formatDateTime(value) {
  return formatDate(value, { hour: '2-digit', minute: '2-digit' });
}

function formatRelative(value) {
  if (!value) return 'NO SCAN DATA';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'UNKNOWN TIME';
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return 'JUST NOW';
  if (seconds < 60) return 'JUST NOW';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}M AGO`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}H AGO`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}D AGO`;
  return formatDate(value);
}

function normalizeSeverity(value) {
  const severity = String(value || 'unknown').toLowerCase();
  if (severity.includes('critical')) return 'critical';
  if (severity.includes('high')) return 'high';
  if (severity.includes('medium') || severity.includes('moderate')) return 'medium';
  if (severity.includes('low') || severity.includes('info')) return 'low';
  return 'unknown';
}

function severityLabel(value) {
  const key = normalizeSeverity(value);
  return key === 'unknown' ? 'UNKNOWN' : key.toUpperCase();
}

function methodLabel(value) {
  return String(value || 'UNKNOWN').toUpperCase();
}

function methodClass(value) {
  const method = methodLabel(value).toLowerCase();
  const allowed = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']);
  return allowed.has(method) ? `method-${method}` : 'method-unknown';
}

function pathLabel(value) {
  return String(value || 'API route').trim() || 'API route';
}

function humanAuthLabel(value) {
  const auth = String(value || 'UNKNOWN').toLowerCase();
  if (auth.includes('public') || auth === 'none' || auth.includes('not required')) return 'Public';
  if (auth.includes('auth') || auth.includes('required')) return 'Required';
  return 'Unknown';
}

function humanStatusLabel(value) {
  const status = String(value || 'UNASSESSED').toLowerCase();
  if (status.includes('review')) return 'Needs review';
  if (status.includes('unassess') || status.includes('untested')) return 'Not tested';
  if (status.includes('complete')) return 'Complete';
  return status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown';
}

function getScanId(scan) {
  return scan && scan.id !== undefined && scan.id !== null ? `SC-${scan.id}` : 'NO SCAN';
}

function hasScanData(scan) {
  if (!isRecord(scan)) return false;
  return Boolean(
    scan.id !== undefined && scan.id !== null ||
    scan.filename ||
    scan.title ||
    safeNumber(scan.endpoint_count) > 0 ||
    safeNumber(scan.finding_count) > 0 ||
    safeNumber(scan.score) > 0
  );
}

function normalizeFinding(finding, index = 0) {
  const source = isRecord(finding) ? finding : {};
  return {
    id: source.id ?? `finding-${index}`,
    severity: severityLabel(source.severity),
    title: String(source.title || source.name || source.vulnerability || 'Untitled finding'),
    path: source.path ? String(source.path) : '',
    method: source.method ? methodLabel(source.method) : 'UNKNOWN',
    description: String(source.description || source.details || 'No description was returned by the scan service.'),
    remediation: source.remediation || source.recommendation || '',
    confidence: source.confidence || '',
    status: source.status || 'OPEN',
    detected: source.detected_at || source.created_at || '',
    request: source.request || source.proof_of_concept?.request || '',
    response: source.response || source.proof_of_concept?.response || '',
    responseStatus: source.response_status || source.status_code || source.proof_of_concept?.status || '',
    raw: source
  };
}

function normalizeEndpoint(endpoint, index = 0) {
  const source = isRecord(endpoint) ? endpoint : {};
  return {
    id: source.id ?? `endpoint-${index}`,
    path: String(source.path || source.route || ''),
    method: methodLabel(source.method || 'UNKNOWN'),
    operationId: source.operation_id || source.operationId || '',
    auth: String(source.auth || source.authentication || 'UNKNOWN'),
    risk: String(source.risk || source.risk_level || 'UNASSESSED'),
    lastTested: source.last_tested || source.lastTested || '',
    status: String(source.status || 'UNASSESSED'),
    raw: source
  };
}

function normalizeScan(scan) {
  const source = isRecord(scan) ? scan : {};
  const findings = Array.isArray(source.findings)
    ? source.findings.map(normalizeFinding)
    : [];
  const endpoints = Array.isArray(source.endpoints)
    ? source.endpoints.map(normalizeEndpoint)
    : [];
  const hasIdentity = Boolean(
    source.id !== undefined && source.id !== null ||
    source.filename ||
    source.name ||
    source.title ||
    source.created_at ||
    source.createdAt
  );
  const endpointCount = source.endpoint_count ?? source.endpointCount;
  const findingCount = source.finding_count ?? source.findingCount;
  return {
    id: source.id ?? null,
    filename: String(source.filename || source.name || (hasIdentity ? 'Unnamed specification' : '')),
    title: String(source.title || source.filename || source.name || (hasIdentity ? 'Unnamed API' : '')),
    version: source.version || '',
    format: source.format || '',
    endpoint_count: Number.isFinite(Number(endpointCount)) ? safeNumber(endpointCount) : endpoints.length,
    score: safeNumber(source.score),
    finding_count: Number.isFinite(Number(findingCount)) ? safeNumber(findingCount) : findings.length,
    critical_count: source.critical_count !== undefined && source.critical_count !== null && Number.isFinite(Number(source.critical_count))
      ? safeNumber(source.critical_count)
      : null,
    created_at: source.created_at || source.createdAt || '',
    findings,
    endpoints,
    raw: source
  };
}

function normalizeDashboard(payload) {
  if (!isRecord(payload) || !Array.isArray(payload.scans)) {
    throw new ApiError('The dashboard response was malformed.', 'malformed');
  }
  const totals = isRecord(payload.totals) ? payload.totals : {};
  const scans = payload.scans.map(scan => normalizeScan(scan));
  const hasTotal = value => value !== undefined && value !== null && Number.isFinite(Number(value));
  return {
    latest: normalizeScan(isRecord(payload.latest) ? payload.latest : {}),
    totals: {
      scans: hasTotal(totals.scans) ? safeNumber(totals.scans) : scans.length,
      endpoints: hasTotal(totals.endpoints) ? safeNumber(totals.endpoints) : scans.reduce((sum, scan) => sum + scan.endpoint_count, 0),
      findings: hasTotal(totals.findings) ? safeNumber(totals.findings) : scans.reduce((sum, scan) => sum + scan.finding_count, 0)
    },
    scans
  };
}

function getLatestFindings() {
  return state.latestScan && Array.isArray(state.latestScan.findings) ? state.latestScan.findings : [];
}

function getSeverityCounts() {
  const findings = getLatestFindings();
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  findings.forEach(finding => {
    counts[normalizeSeverity(finding.severity)] += 1;
  });
  return counts;
}

function getCriticalCount() {
  if (!state.latestScan) return 0;
  if (state.latestScan.critical_count !== null) return state.latestScan.critical_count;
  return getSeverityCounts().critical;
}

function getPreviousScan() {
  return state.dashboard.scans.length > 1 ? state.dashboard.scans[1] : null;
}

function getKnownEndpointRecords() {
  if (!state.latestScan) return [];
  const explicitEndpoints = state.latestScan.endpoints
    .filter(endpoint => endpoint.path)
    .map(endpoint => ({ ...endpoint, source: 'endpoint' }));
  if (explicitEndpoints.length) return explicitEndpoints;

  const seen = new Set();
  return getLatestFindings()
    .filter(finding => finding.path)
    .map((finding, index) => {
      const key = `${finding.path}::${finding.method}`;
      if (seen.has(key)) return null;
      seen.add(key);
      return normalizeEndpoint({
        path: finding.path,
        method: finding.method,
        risk: finding.severity,
        status: 'REVIEW',
        last_tested: state.latestScan.created_at
      }, index);
    })
    .filter(Boolean)
    .map(endpoint => ({ ...endpoint, source: 'finding' }));
}

function getInventoryRecords() {
  return getKnownEndpointRecords().map(record => ({
    ...record,
    auth: record.auth || 'UNKNOWN',
    risk: record.risk || 'UNASSESSED',
    lastTested: record.lastTested || state.latestScan?.created_at || '',
    status: record.status || 'UNASSESSED'
  }));
}

function findingKey(finding, index) {
  return `${index}:${finding.title}:${finding.path}:${finding.method}`;
}

function getSelectedFinding() {
  const findings = getLatestFindings();
  if (!findings.length) return null;
  if (state.selectedFindingIndex !== null && findings[state.selectedFindingIndex]) {
    return { finding: findings[state.selectedFindingIndex], index: state.selectedFindingIndex };
  }
  const selected = findings.find((finding, index) => findingKey(finding, index) === state.selectedFindingKey);
  if (selected) {
    const index = findings.indexOf(selected);
    state.selectedFindingIndex = index;
    return { finding: selected, index };
  }
  return { finding: findings[0], index: 0 };
}

function setText(id, value) {
  const element = $(id);
  if (element) element.textContent = value ?? '—';
}

function renderIcons() {
  if (!window.lucide || typeof window.lucide.createIcons !== 'function') return;
  try {
    window.lucide.createIcons({ attrs: { 'aria-hidden': 'true' } });
  } catch (error) {
    // Icon rendering is decorative; do not interrupt the security workspace.
  }
}

function setStatusDot(id, status) {
  const dot = $(id);
  if (!dot) return;
  dot.classList.remove('status-dot-operational', 'status-dot-warning', 'status-dot-critical', 'status-dot-neutral');
  dot.classList.add(`status-dot-${status}`);
}

function setSystemState(status, label) {
  const normalized = ['operational', 'warning', 'critical', 'neutral'].includes(status) ? status : 'neutral';
  setText('systemStatus', label);
  setText('railStatusText', label);
  setStatusDot('headerStatusDot', normalized);
  setStatusDot('railStatusDot', normalized);
}

function setConnectionError(error) {
  const banner = $('connectionBanner');
  if (!banner) return;
  if (error && error.kind === 'network') {
    setText('connectionTitle', 'CONNECTION ERROR');
    setText('connectionMessage', 'Unable to reach SentinelAPI backend.');
    banner.hidden = false;
    setSystemState('critical', 'DEGRADED');
  } else if (error && error.kind === 'malformed') {
    setText('connectionTitle', 'RESPONSE ERROR');
    setText('connectionMessage', 'The backend returned an unreadable response.');
    banner.hidden = false;
    setSystemState('warning', 'DEGRADED');
  } else if (error && error.kind === 'http') {
    setText('connectionTitle', 'REQUEST ERROR');
    setText('connectionMessage', friendlyError(error, 'The SentinelAPI backend rejected the request.'));
    banner.hidden = false;
    setSystemState('warning', 'DEGRADED');
  } else {
    banner.hidden = true;
  }
}

function clearConnectionError() {
  const banner = $('connectionBanner');
  if (banner) banner.hidden = true;
  setSystemState('operational', 'OPERATIONAL');
}

function friendlyError(error, fallback = 'The SentinelAPI backend could not complete this request.') {
  if (error instanceof ApiError) {
    if (error.kind === 'network') return 'Unable to reach SentinelAPI backend.';
    if (error.kind === 'malformed') return 'The backend returned an unreadable response.';
    if (error.payload && typeof error.payload.error === 'string') return error.payload.error;
  }
  return fallback;
}

function handleApiError(error, context = 'request') {
  if (error && ['network', 'malformed', 'http'].includes(error.kind)) {
    setConnectionError(error);
  } else {
    setSystemState('warning', 'DEGRADED');
    showToast(friendlyError(error, `The ${context} request could not be completed.`), 'error');
  }
  console.error(`SentinelAPI ${context} failed:`, error);
}

async function apiFetch(endpoint, options = {}) {
  let response;
  try {
    response = await fetch(endpoint, options);
  } catch (error) {
    throw new ApiError('Unable to reach SentinelAPI backend.', 'network', 0, null, error);
  }

  const contentType = response.headers.get('content-type') || '';
  let payload = null;
  try {
    const body = await response.text();
    if (!body) {
      payload = null;
    } else if (contentType.includes('json')) {
      payload = JSON.parse(body);
    } else {
      try {
        payload = JSON.parse(body);
      } catch (parseError) {
        throw new ApiError('The backend returned an unreadable response.', 'malformed', response.status, null, parseError);
      }
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('The backend returned an unreadable response.', 'malformed', response.status, null, error);
  }

  if (!response.ok) {
    throw new ApiError(
      isRecord(payload) && typeof payload.error === 'string' ? payload.error : `Request failed with HTTP ${response.status}.`,
      'http',
      response.status,
      payload
    );
  }

  return payload;
}

/* Navigation --------------------------------------------------------------- */

function initNavigation() {
  queryAll('.nav-item[data-target]').forEach(button => {
    button.addEventListener('click', () => navigateTo(button.dataset.target));
  });

  const mobileToggle = $('mobileMenuToggle');
  const rail = $('navRail');
  if (mobileToggle && rail) {
    mobileToggle.addEventListener('click', () => {
      const open = rail.classList.toggle('is-open');
      mobileToggle.setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('click', event => {
      if (rail.classList.contains('is-open') && !rail.contains(event.target) && !mobileToggle.contains(event.target)) {
        rail.classList.remove('is-open');
        mobileToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  const retry = $('retryConnectionButton');
  if (retry) {
    retry.addEventListener('click', () => {
      clearConnectionError();
      loadDashboardData();
      loadDatabaseData();
    });
  }
}

function navigateTo(viewId) {
  const target = document.getElementById(viewId);
  if (!target || !target.classList.contains('page-view')) return;

  queryAll('.page-view').forEach(page => page.classList.remove('active'));
  target.classList.add('active');

  queryAll('.nav-item[data-target]').forEach(button => {
    const active = button.dataset.target === viewId;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });

  const meta = PAGE_META[viewId] || PAGE_META.dashboard;
  setText('topbarSection', meta.section);
  setText('topbarTitle', meta.title);
  setText('topbarDescription', meta.description);
  state.activeView = viewId;

  const rail = $('navRail');
  const mobileToggle = $('mobileMenuToggle');
  if (rail) rail.classList.remove('is-open');
  if (mobileToggle) mobileToggle.setAttribute('aria-expanded', 'false');

  if (viewId === 'vulnerabilities') renderVulnerabilities();
  if (viewId === 'inventory') renderInventory();
  if (viewId === 'reports') renderReports();
  if (viewId === 'insights') renderInsights();
  if (viewId === 'history') renderHistory();

  try {
    window.history.replaceState(null, '', `#${viewId}`);
  } catch (error) {
    // History state is optional for file-based previews.
  }
}

/* Shared rendering --------------------------------------------------------- */

function renderAll() {
  renderDashboard();
  renderHistory();
  renderVulnerabilities();
  renderInventory();
  renderReports();
  renderInsights();
  updateGlobalMetadata();
  renderIcons();
}

function updateGlobalMetadata() {
  const latest = state.latestScan || state.dashboard.latest;
  setText('lastScanTime', latest?.created_at ? formatRelative(latest.created_at) : 'NO SCAN DATA');
  setText('scanCount', state.dashboard.totals.scans);
  setText('inventoryScanCount', state.dashboard.totals.scans);
  setText('inventoryEndpointCount', state.dashboard.totals.endpoints || latest?.endpoint_count || 0);
  setText('navFindingCount', state.dashboard.totals.findings || latest?.finding_count || 0);
  setText('databaseName', state.database?.database || 'SQLITE');
  setText('databaseStatus', state.database ? 'LOCAL PERSISTENT WORKSPACE' : 'LOCAL SQLITE STORE');
}

function setScoreColor(score) {
  const ring = $('scoreRingProgress');
  if (!ring) return;
  const color = score >= 75 ? 'var(--cyan)' : score >= 50 ? 'var(--amber)' : 'var(--red)';
  ring.style.stroke = color;
}

function renderScore(score) {
  const numericScore = Math.max(0, Math.min(100, safeNumber(score)));
  setText('securityScore', numericScore);
  const ring = $('scoreRingProgress');
  if (ring) {
    const circumference = 314.16;
    ring.style.strokeDashoffset = String(circumference - (circumference * numericScore / 100));
  }
  setScoreColor(numericScore);

  let status = 'NO SCAN DATA';
  let description = 'Upload an OpenAPI specification to establish a baseline.';
  if (hasScanData(state.latestScan || state.dashboard.latest)) {
    if (numericScore >= 90) status = 'STRONG';
    else if (numericScore >= 75) status = 'GOOD';
    else if (numericScore >= 50) status = 'NEEDS REVIEW';
    else status = 'HIGH RISK';
    description = numericScore >= 75
      ? 'Your latest API scan is in a good range. Review the findings below for remaining improvements.'
      : 'Your latest API scan found security issues that need engineering review.';
  }
  setText('scoreStatus', status);
  setText('scoreDescription', description);

  const previous = getPreviousScan();
  const latest = state.latestScan || state.dashboard.latest;
  const trend = $('scoreTrend');
  if (trend) {
    if (previous) {
      const delta = safeNumber(latest?.score) - safeNumber(previous.score);
      const direction = delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat';
      const icon = direction === 'up' ? 'arrow-up-right' : direction === 'down' ? 'arrow-down-right' : 'minus';
      trend.classList.toggle('is-negative', delta < 0);
      trend.classList.toggle('is-neutral', delta === 0);
      trend.innerHTML = `<i data-lucide="${icon}" aria-hidden="true"></i><span>${delta > 0 ? '↑' : delta < 0 ? '↓' : '—'} ${Math.abs(delta)} pts from previous scan</span>`;
    } else {
      trend.classList.remove('is-negative');
      trend.classList.add('is-neutral');
      trend.innerHTML = '<i data-lucide="minus" aria-hidden="true"></i><span>No previous scan to compare</span>';
    }
  }
  setText('scoreUpdatedAt', latest?.created_at ? formatDateTime(latest.created_at) : '—');
}

function renderSeverityChart() {
  const chart = $('severityChart');
  const legend = $('severityLegend');
  if (!chart || !legend) return;
  const counts = getSeverityCounts();
  const max = Math.max(...SEVERITIES.map(item => counts[item.key]), 1);
  const total = SEVERITIES.reduce((sum, item) => sum + counts[item.key], 0);
  const unclassified = Math.max(0, (state.latestScan?.finding_count || 0) - total);

  chart.innerHTML = SEVERITIES.map(item => {
    const count = counts[item.key];
    const width = total ? Math.max(count ? 4 : 0, (count / max) * 100) : 0;
    return `<div class="severity-row"><span>${item.label}</span><div class="severity-track"><svg class="severity-bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect class="severity-fill severity-${item.key}" x="0" y="0" width="${width}" height="8"></rect></svg></div><span>${String(count).padStart(2, '0')}</span></div>`;
  }).join('') + (total === 0 ? '<div class="chart-note">No findings were returned for the latest scan.</div>' : unclassified > 0 ? '<div class="chart-note">Additional finding records were reported by the summary, but severity details are unavailable.</div>' : '');

  legend.innerHTML = SEVERITIES.map(item => `<span class="legend-item"><span class="legend-swatch ${item.key}"></span>${item.label} ${counts[item.key]}</span>`).join('');
}

function renderTrendChart(container, scans, emptyTitle = 'NO SCAN HISTORY', emptyMessage = 'Run a scan to establish a security score trend.') {
  if (!container) return;
  if (!scans.length) {
    container.innerHTML = `<div class="empty-state"><strong>${escapeHtml(emptyTitle)}</strong><p>${escapeHtml(emptyMessage)}</p></div>`;
    return;
  }

  const ordered = scans.slice(0, 10).reverse();
  const width = 640;
  const height = 150;
  const padX = 15;
  const padTop = 13;
  const padBottom = 22;
  const usableHeight = height - padTop - padBottom;
  const points = ordered.map((scan, index) => {
    const x = ordered.length === 1 ? width / 2 : padX + (index * (width - padX * 2) / (ordered.length - 1));
    const y = padTop + (1 - (safeNumber(scan.score) / 100)) * usableHeight;
    return { x, y, scan };
  });
  const linePath = points.map((point, index) => `${index ? 'L' : 'M'} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${height - padBottom} L ${points[0].x.toFixed(1)} ${height - padBottom} Z`;
  const grid = [0, 25, 50, 75, 100].map(value => {
    const y = padTop + (1 - value / 100) * usableHeight;
    return `<line class="trend-grid-line" x1="${padX}" x2="${width - padX}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}"></line>`;
  }).join('');

  container.innerHTML = `<svg class="trend-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Security score trend"><g>${grid}</g><path class="trend-area" d="${areaPath}"></path><path class="trend-line" d="${linePath}"></path>${points.map(point => `<circle class="trend-point" cx="${point.x.toFixed(1)}" cy="${point.y.toFixed(1)}" r="3.5"></circle>`).join('')}</svg><div class="trend-labels"><span>${escapeHtml(formatDate(ordered[0].created_at))}</span><span>${escapeHtml(formatDate(ordered[ordered.length - 1].created_at))}</span></div>`;
}

function renderEndpointRow(endpoint) {
  const method = methodLabel(endpoint.method);
  const risk = severityLabel(endpoint.risk);
  const auth = String(endpoint.auth || 'UNKNOWN').toUpperCase();
  const status = String(endpoint.status || 'UNASSESSED').toUpperCase();
  const authClass = auth.includes('PUBLIC') ? 'auth-public' : auth.includes('AUTH') ? 'auth-required' : 'auth-unknown';
  const statusClass = status.includes('REVIEW') ? 'status-medium' : status.includes('UNASSESS') ? 'status-unknown' : 'status-low';
  return `<tr><td><span class="method-badge ${methodClass(method)}">${escapeHtml(method)}</span></td><td><span class="endpoint-cell" title="${escapeHtml(pathLabel(endpoint.path))}">${escapeHtml(pathLabel(endpoint.path))}</span></td><td><span class="auth-badge ${authClass}">${escapeHtml(auth)}</span></td><td><span class="risk-badge risk-${risk.toLowerCase()}">${escapeHtml(risk)}</span></td><td><span class="status-badge ${statusClass}">${escapeHtml(status)}</span></td></tr>`;
}

function renderInventoryRow(endpoint) {
  const method = methodLabel(endpoint.method);
  const risk = severityLabel(endpoint.risk);
  const auth = humanAuthLabel(endpoint.auth);
  const status = humanStatusLabel(endpoint.status);
  const lastTested = endpoint.lastTested ? formatRelative(endpoint.lastTested) : 'Not tested';
  const authClass = auth === 'Public' ? 'auth-public' : auth === 'Required' ? 'auth-required' : 'auth-unknown';
  const statusClass = status === 'Needs review' ? 'status-medium' : status === 'Not tested' ? 'status-unknown' : 'status-low';
  return `<tr><td><span class="method-badge ${methodClass(method)}">${escapeHtml(method)}</span></td><td><span class="endpoint-cell" title="${escapeHtml(pathLabel(endpoint.path))}">${escapeHtml(pathLabel(endpoint.path))}</span></td><td><span class="auth-badge ${authClass}">${escapeHtml(auth)}</span></td><td><span class="risk-badge risk-${risk.toLowerCase()}">${escapeHtml(risk)}</span></td><td>${escapeHtml(lastTested)}</td><td><span class="status-badge ${statusClass}">${escapeHtml(status)}</span></td></tr>`;
}

function renderAttackSurface() {
  const body = $('attackSurfaceBody');
  const empty = $('attackSurfaceEmpty');
  const summary = $('attackSurfaceSummary');
  const source = $('attackSurfaceSource');
  if (!body || !empty) return;
  const records = getKnownEndpointRecords();
  const hasScan = hasScanData(state.latestScan || state.dashboard.latest);
  body.innerHTML = records.map(renderEndpointRow).join('');
  empty.hidden = records.length > 0;
  if (!records.length) {
    empty.innerHTML = hasScan
      ? '<div class="empty-state"><div class="empty-icon"><i data-lucide="route-off" aria-hidden="true"></i></div><strong>ENDPOINT DETAILS UNAVAILABLE</strong><p>The latest scan contains an endpoint count, but this backend response does not include the full route inventory.</p></div>'
      : '<div class="empty-state"><div class="empty-icon"><i data-lucide="scan-search" aria-hidden="true"></i></div><strong>NO SCAN DATA</strong><p>Run a security scan to discover API routes.</p></div>';
  }
  const summaryText = records.length
    ? `${records.length} route record${records.length === 1 ? '' : 's'} linked to the latest scan evidence.`
    : hasScan ? `${safeNumber(state.latestScan?.endpoint_count)} endpoints counted; detailed route records unavailable.` : 'No endpoint records available.';
  if (summary) summary.textContent = summaryText;
  const sourceText = records.some(item => item.source === 'endpoint') ? 'SCAN DETAILS' : hasScan ? 'FINDING-LINKED ROUTES' : 'WAITING FOR SCAN';
  const hasAuthMetadata = records.some(item => !['UNKNOWN', 'UNASSESSED', ''].includes(String(item.auth || '').toUpperCase()));
  const authenticated = records.filter(item => /AUTH|REQUIRED/i.test(String(item.auth || ''))).length;
  const publicRoutes = records.filter(item => /PUBLIC|NONE|NOT REQUIRED/i.test(String(item.auth || ''))).length;
  const reviewQueue = records.filter(item => /REVIEW|HIGH|CRITICAL/i.test(`${item.status || ''} ${item.risk || ''}`)).length;
  setText('surfaceTotal', hasScan ? safeNumber(state.latestScan?.endpoint_count) : '—');
  setText('surfaceAuthenticated', hasAuthMetadata ? authenticated : '—');
  setText('surfacePublic', hasAuthMetadata ? publicRoutes : '—');
  setText('surfaceReview', records.length ? reviewQueue : '—');
  if (source) {
    source.textContent = sourceText;
    const sourceDot = source.parentElement?.querySelector('.status-dot');
    sourceDot?.classList.remove('status-dot-operational', 'status-dot-neutral');
    sourceDot?.classList.add(records.length ? 'status-dot-operational' : 'status-dot-neutral');
  }
}

function renderRecentFindings() {
  const body = $('recentFindingsBody');
  const empty = $('recentFindingsEmpty');
  if (!body || !empty) return;
  const findings = getLatestFindings();
  body.innerHTML = findings.slice(0, 5).map((finding, index) => `<tr data-finding-index="${index}"><td><span class="severity-badge severity-${normalizeSeverity(finding.severity)}">${escapeHtml(severityLabel(finding.severity))}</span></td><td><strong class="finding-title-cell">${escapeHtml(finding.title)}</strong></td><td><span class="endpoint-cell" title="${escapeHtml(pathLabel(finding.path))}">${escapeHtml(pathLabel(finding.path))}</span></td><td><span class="method-badge ${methodClass(finding.method)}">${escapeHtml(methodLabel(finding.method))}</span></td><td><span class="finding-status ${finding.status === 'CLOSED' ? 'status-closed' : ''}">${escapeHtml(humanStatusLabel(finding.status || 'OPEN'))}</span></td><td class="mono">${escapeHtml(finding.detected || state.latestScan?.created_at ? formatDate(finding.detected || state.latestScan?.created_at) : '—')}</td><td><button class="row-action" type="button" data-finding-index="${index}" aria-label="View ${escapeHtml(finding.title)}"><i data-lucide="chevron-right" aria-hidden="true"></i></button></td></tr>`).join('');
  empty.hidden = findings.length > 0;
  if (!findings.length) {
    const hasSummary = safeNumber(state.latestScan?.finding_count) > 0;
    empty.innerHTML = `<div class="empty-state"><div class="empty-icon"><i data-lucide="shield-check" aria-hidden="true"></i></div><strong>${hasSummary ? 'FINDING DETAILS UNAVAILABLE' : 'NO VULNERABILITIES'}</strong><p>${hasSummary ? 'The scan summary contains findings, but detailed records are not available in this response.' : 'No findings are available for this scan.'}</p></div>`;
  }
}

function renderActivity() {
  const body = $('scanActivityBody');
  const empty = $('scanActivityEmpty');
  if (!body || !empty) return;
  const scans = state.dashboard.scans;
  body.innerHTML = scans.slice(0, 5).map(scan => `<tr data-scan-id="${escapeHtml(String(scan.id))}"><td><span class="scan-id-badge">${escapeHtml(getScanId(scan))}</span></td><td><strong>${escapeHtml(scan.title || scan.filename)}</strong><small class="table-subtext">${escapeHtml(scan.filename)}</small></td><td class="mono">${safeNumber(scan.endpoint_count)}</td><td class="mono">${safeNumber(scan.finding_count)}</td><td><span class="score-cell ${safeNumber(scan.score) < 70 ? 'score-low' : ''}">${safeNumber(scan.score)} / 100</span></td><td><span class="status-badge status-low">Complete</span></td><td class="mono">${escapeHtml(formatDateTime(scan.created_at))}</td></tr>`).join('');
  empty.hidden = scans.length > 0;
  if (!scans.length) empty.innerHTML = '<div class="empty-state"><div class="empty-icon"><i data-lucide="history" aria-hidden="true"></i></div><strong>NO SCAN HISTORY</strong><p>Run your first API security scan to see results here.</p></div>';
}

function renderDashboard() {
  const latest = state.latestScan || state.dashboard.latest;
  const hasScan = hasScanData(latest);
  const dashboardState = $('dashboardState');
  if (dashboardState) dashboardState.hidden = hasScan;
  document.getElementById('dashboard')?.classList.toggle('is-onboarding', !hasScan);
  setText('postureMeta', hasScan ? `LATEST SCAN / ${formatRelative(latest.created_at)}` : 'NO ACTIVE SCAN');
  renderScore(latest?.score || 0);

  const critical = getCriticalCount();
  const criticalUnavailable = Boolean(state.detailUnavailable && latest?.finding_count > 0 && latest?.critical_count === null);
  setText('criticalFindings', criticalUnavailable ? '—' : critical);
  setText('criticalDelta', criticalUnavailable ? 'Severity details unavailable' : critical === 0 ? 'No critical findings recorded' : `${critical} critical finding${critical === 1 ? '' : 's'} require priority review`);
  setText('endpointCount', latest?.endpoint_count || 0);
  setText('endpointMeta', hasScan ? `Stored in ${getScanId(latest)}` : 'Waiting for your first scan');
  setText('scanCount', state.dashboard.totals.scans);
  setText('scanMeta', state.dashboard.totals.scans ? `${state.dashboard.totals.scans} completed run${state.dashboard.totals.scans === 1 ? '' : 's'}` : 'No completed runs');
  setText('navFindingCount', state.dashboard.totals.findings || latest?.finding_count || 0);
  const notificationIndicator = $('notificationIndicator');
  if (notificationIndicator) notificationIndicator.hidden = getCriticalCount() === 0;

  renderSeverityChart();
  renderTrendChart($('scoreTrendChart'), state.dashboard.scans, 'NO SCORE HISTORY', 'Complete a scan to establish a baseline score.');
  const historyScans = state.dashboard.scans;
  const historyDelta = historyScans.length > 1 ? safeNumber(historyScans[0].score) - safeNumber(historyScans[1].score) : null;
  setText('trendRange', historyScans.length ? `${historyScans.length} COMPLETED SCAN${historyScans.length === 1 ? '' : 'S'}` : 'NO SCAN HISTORY');
  setText('trendDelta', historyDelta === null ? '—' : `${historyDelta > 0 ? '+' : ''}${historyDelta} PTS VS PREVIOUS`);
  renderAttackSurface();
  renderRecentFindings();
  renderActivity();
}

/* Scan intake -------------------------------------------------------------- */

function validateSpecificationFile(file) {
  if (!file) return 'Choose an OpenAPI or Swagger specification.';
  const name = String(file.name || '').toLowerCase();
  if (!ALLOWED_EXTENSIONS.some(extension => name.endsWith(extension))) {
    return 'Unsupported file type. Use .json, .yaml, or .yml.';
  }
  if (safeNumber(file.size) <= 0) return 'The selected file is empty.';
  if (safeNumber(file.size) > MAX_FILE_SIZE) return 'The selected file exceeds the 10 MB upload limit.';
  return '';
}

function initFileUpload() {
  const dropzone = $('dropzone');
  const fileInput = $('fileInput');
  const removeButton = $('removeFileButton');
  if (!dropzone || !fileInput) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      dropzone.classList.add('is-dragging');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      dropzone.classList.remove('is-dragging');
    });
  });

  dropzone.addEventListener('drop', event => {
    const files = event.dataTransfer?.files;
    if (files && files.length) handleUploadedFile(files[0]);
  });

  dropzone.addEventListener('click', event => {
    if (event.target === fileInput || event.target.closest('button')) return;
    fileInput.click();
  });

  dropzone.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', event => {
    if (event.target.files?.length) handleUploadedFile(event.target.files[0]);
  });

  if (removeButton) {
    removeButton.addEventListener('click', resetUpload);
  }
}

function handleUploadedFile(file) {
  const error = validateSpecificationFile(file);
  const errorElement = $('fileError');
  if (error) {
    if (errorElement) {
      errorElement.textContent = error;
      errorElement.hidden = false;
    }
    showToast(error, 'error');
    return;
  }

  state.uploadedFile = file;
  state.scanCompleted = false;
  const summary = $('specSummary');
  const badge = $('fileValidationBadge');
  if (summary) summary.hidden = false;
  setText('fileName', file.name);
  setText('fileMeta', `${formatBytes(file.size)} / Ready to scan`);
  if (badge) {
    badge.textContent = 'FILE UPLOADED';
    badge.classList.remove('validation-error');
  }
  if (errorElement) errorElement.hidden = true;
  setText('importStepState', 'FILE READY');
  updateScanActionState();
  renderIcons();
}

function resetUpload() {
  state.uploadedFile = null;
  state.scanCompleted = false;
  const fileInput = $('fileInput');
  if (fileInput) fileInput.value = '';
  const summary = $('specSummary');
  if (summary) summary.hidden = true;
  const error = $('fileError');
  if (error) error.hidden = true;
  setText('importStepState', 'REQUIRED');
  updateScanActionState();
}

function initScanModules() {
  $('chooseFileButton')?.addEventListener('click', () => $('fileInput')?.click());
  $('selectAllModules')?.addEventListener('click', () => {
    queryAll('input[name="securityModule"]').forEach(input => { input.checked = true; input.closest('.module-card')?.classList.add('is-selected'); });
    updateScanActionState();
  });
  $('clearAllModules')?.addEventListener('click', () => {
    queryAll('input[name="securityModule"]').forEach(input => { input.checked = false; input.closest('.module-card')?.classList.remove('is-selected'); });
    updateScanActionState();
  });
  queryAll('input[name="securityModule"]').forEach(input => {
    input.addEventListener('change', () => {
      input.closest('.module-card')?.classList.toggle('is-selected', input.checked);
      updateScanActionState();
    });
  });
  updateScanActionState();
}

function getSelectedModules() {
  return queryAll('input[name="securityModule"]:checked').map(input => input.value);
}

function updateScanActionState() {
  const hasFile = Boolean(state.uploadedFile);
  const hasModule = getSelectedModules().length > 0;
  const button = $('startScanButton');
  if (button && !state.scanInProgress) button.disabled = !hasFile || !hasModule;
  const status = $('scanActionStatus');
  const hint = $('scanActionHint');
  const dot = $('scanActionDot');
  if (state.scanInProgress) {
    setText('scanActionStatus', 'Scanning your API');
    setText('scanActionHint', 'Your security checks are running now.');
    if (dot) dot.className = 'status-dot status-dot-warning';
  } else if (state.scanCompleted) {
    setText('scanActionStatus', 'Scan complete');
    setText('scanActionHint', 'Review your findings or run another scan.');
    if (dot) dot.className = 'status-dot status-dot-operational';
  } else if (!hasFile) {
    setText('scanActionStatus', 'Waiting for a file');
    setText('scanActionHint', 'Choose an OpenAPI file to continue.');
    if (dot) dot.className = 'status-dot status-dot-neutral';
  } else if (!hasModule) {
    setText('scanActionStatus', 'Choose a security check');
    setText('scanActionHint', 'Select at least one check to continue.');
    if (dot) dot.className = 'status-dot status-dot-warning';
  } else {
    setText('scanActionStatus', 'Ready to scan');
    setText('scanActionHint', `${getSelectedModules().length} checks selected / ${formatBytes(state.uploadedFile.size)} file ready`);
    if (dot) dot.className = 'status-dot status-dot-operational';
  }
  setText('modulesStepState', `${getSelectedModules().length} CHECK${getSelectedModules().length === 1 ? '' : 'S'}`);
  setText('summaryFileName', state.uploadedFile?.name || 'No file selected');
  setText('summaryChecks', `${getSelectedModules().length} selected`);
  setText('summaryEnvironment', String($('scanEnvironment')?.value || 'lab').toUpperCase());
}

function resetScanProgress() {
  const panel = $('scanProgress');
  const bar = $('scanProgressBar');
  const percent = $('scanProgressPercent');
  if (panel) panel.hidden = false;
  if (bar) bar.style.width = '0%';
  if (percent) percent.textContent = '0%';
  queryAll('[data-progress-step]').forEach(item => item.classList.remove('is-active', 'is-complete'));
  const actions = $('progressCompleteActions');
  if (actions) actions.hidden = true;
  state.progressIndex = 0;
  setText('scanProgressSummary', 'Preparing your scan…');
  setText('technicalLogOutput', 'No technical logs yet.');
  setProgressStep(0);
}

function setProgressStep(index) {
  state.progressIndex = Math.max(0, Math.min(SCAN_STAGES.length - 1, index));
  const percent = Math.round((state.progressIndex / (SCAN_STAGES.length - 1)) * 100);
  const bar = $('scanProgressBar');
  const percentElement = $('scanProgressPercent');
  if (bar) bar.style.width = `${percent}%`;
  if (percentElement) percentElement.textContent = `${percent}%`;
  queryAll('[data-progress-step]').forEach(item => {
    const itemIndex = SCAN_STAGES.indexOf(item.dataset.progressStep);
    item.classList.toggle('is-complete', itemIndex < state.progressIndex);
    item.classList.toggle('is-active', itemIndex === state.progressIndex);
  });
  const stageLabel = SCAN_STAGE_LABELS[SCAN_STAGES[state.progressIndex]];
  setText('scanProgressSummary', state.progressIndex === 0 ? 'Preparing your scan…' : 'Analyzing your API…');
  setText('technicalLogOutput', `${String(percent).padStart(3, ' ')}%  ${stageLabel}`);
}

function completeScanProgress() {
  if (state.progressTimer) {
    clearInterval(state.progressTimer);
    state.progressTimer = null;
  }
  state.progressIndex = SCAN_STAGES.length - 1;
  queryAll('[data-progress-step]').forEach(item => {
    item.classList.remove('is-active');
    item.classList.add('is-complete');
  });
  const bar = $('scanProgressBar');
  if (bar) bar.style.width = '100%';
  setText('scanProgressPercent', '100%');
  setText('scanProgressSummary', 'Scan complete. Your results are ready to review.');
  setText('technicalLogOutput', '100%  SCAN COMPLETE\nResults persisted to the local data store.');
  const actions = $('progressCompleteActions');
  if (actions) actions.hidden = false;
  renderIcons();
}

async function startScanProcess() {
  if (state.scanInProgress) return;
  if (!state.uploadedFile) {
    showToast('Select a valid OpenAPI specification before starting the scan.', 'error');
    $('dropzone')?.focus();
    return;
  }
  if (!getSelectedModules().length) {
    showToast('Select at least one security module before starting the scan.', 'error');
    return;
  }

  const button = $('startScanButton');
  const feedback = $('scanFeedback');
  state.scanInProgress = true;
  state.scanCompleted = false;
  if (button) {
    button.disabled = true;
    button.innerHTML = '<i data-lucide="loader-circle" aria-hidden="true"></i> SCANNING…';
  }
  if (feedback) {
    feedback.hidden = false;
    feedback.classList.remove('is-success');
    feedback.textContent = 'Submitting the specification to the local scan service…';
  }
  updateScanActionState();
  resetScanProgress();
  state.progressTimer = window.setInterval(() => {
    if (state.progressIndex < SCAN_STAGES.length - 2) setProgressStep(state.progressIndex + 1);
  }, 700);

  try {
    const formData = new FormData();
    formData.append('spec', state.uploadedFile);
    const result = await apiFetch('/api/scans', { method: 'POST', body: formData });
    if (!isRecord(result) || result.error || result.id === undefined || result.id === null) {
      throw new ApiError('The scan service returned an unreadable response.', 'malformed', 201, result);
    }

    const scan = normalizeScan(result);
    window.latestScan = result;
    const wasAlreadyStored = state.dashboard.scans.some(item => String(item.id) === String(scan.id));
    state.latestScan = scan;
    state.dashboard.latest = scan;
    state.detailUnavailable = false;
    state.selectedFindingKey = null;
    state.selectedFindingIndex = null;
    refreshHistory(scan);
    if (!wasAlreadyStored) {
      state.dashboard.totals.scans += 1;
      state.dashboard.totals.endpoints += scan.endpoint_count;
      state.dashboard.totals.findings += scan.finding_count;
    }
    state.scanCompleted = true;
    renderAll();
    completeScanProgress();
    clearConnectionError();
    setText('scanActionStatus', 'SCAN COMPLETE');
    setText('scanActionHint', `${getScanId(scan)} is ready for investigation.`);
    if (feedback) {
      feedback.classList.add('is-success');
      feedback.textContent = `${getScanId(scan)} completed successfully. ${scan.endpoint_count} endpoints analyzed and ${scan.finding_count} findings recorded.`;
    }
    if (button) {
      button.disabled = false;
      button.innerHTML = '<i data-lucide="scan-search" aria-hidden="true"></i> RUN ANOTHER SCAN';
    }
    showToast(`${getScanId(scan)} completed and is ready for review.`, 'success');
    loadDatabaseData();
  } catch (error) {
    if (state.progressTimer) {
      clearInterval(state.progressTimer);
      state.progressTimer = null;
    }
    const message = friendlyError(error, 'The scan could not be completed. Check the specification and try again.');
    if (feedback) {
      feedback.hidden = false;
      feedback.classList.remove('is-success');
      feedback.textContent = `Scan could not be completed. ${message}`;
    }
    handleApiError(error, 'scan');
    if (button) {
      button.disabled = false;
      button.innerHTML = '<i data-lucide="play" aria-hidden="true"></i> START SECURITY SCAN';
    }
  } finally {
    state.scanInProgress = false;
    updateScanActionState();
    renderIcons();
  }
}

/* Vulnerability workspace --------------------------------------------------- */

function initVulnerabilityFilters() {
  const search = $('findingSearch');
  const severity = $('findingSeverityFilter');
  search?.addEventListener('input', renderVulnerabilities);
  severity?.addEventListener('change', event => {
    state.vulnerabilityFilter = event.target.value;
    queryAll('[data-vulnerability-filter]').forEach(button => button.classList.toggle('is-active', button.dataset.vulnerabilityFilter === state.vulnerabilityFilter));
    renderVulnerabilities();
  });
  queryAll('[data-vulnerability-filter]').forEach(button => {
    button.addEventListener('click', () => {
      state.vulnerabilityFilter = button.dataset.vulnerabilityFilter;
      if (severity) severity.value = state.vulnerabilityFilter;
      queryAll('[data-vulnerability-filter]').forEach(item => item.classList.toggle('is-active', item === button));
      renderVulnerabilities();
    });
  });
  $('copyRequestButton')?.addEventListener('click', copyRequestEvidence);
}

function findingListItem(finding, index, selected) {
  const key = normalizeSeverity(finding.severity);
  return `<button class="finding-list-item ${selected ? 'is-selected' : ''}" type="button" data-finding-index="${index}"><div class="finding-list-top"><span class="severity-badge severity-${key}">${escapeHtml(severityLabel(finding.severity))}</span><span class="finding-status ${finding.status === 'CLOSED' ? 'status-closed' : ''}">${escapeHtml(humanStatusLabel(finding.status || 'OPEN'))}</span></div><strong class="finding-list-title">${escapeHtml(finding.title)}</strong><span class="finding-list-path">${escapeHtml(methodLabel(finding.method))} ${escapeHtml(pathLabel(finding.path))}</span><div class="finding-list-bottom"><span class="method-mini">${escapeHtml(methodLabel(finding.method))}</span><span class="finding-view-label">View details <i data-lucide="arrow-up-right" aria-hidden="true"></i></span></div></button>`;
}

function renderVulnerabilities() {
  const list = $('vulnerabilityList');
  const empty = $('vulnerabilityEmpty');
  const content = $('vulnerabilityContent');
  if (!list || !empty || !content) return;
  const findings = getLatestFindings();
  const counts = getSeverityCounts();
  setText('vulnCriticalCount', counts.critical);
  setText('vulnHighCount', counts.high);
  setText('vulnMediumCount', counts.medium);
  setText('vulnLowCount', counts.low);
  const searchTerm = String($('findingSearch')?.value || '').trim().toLowerCase();
  const filter = state.vulnerabilityFilter || $('findingSeverityFilter')?.value || 'all';
  const filtered = findings.filter(finding => {
    const matchesSeverity = filter === 'all' || normalizeSeverity(finding.severity) === filter;
    const haystack = `${finding.title} ${finding.path} ${finding.method} ${finding.description}`.toLowerCase();
    return matchesSeverity && (!searchTerm || haystack.includes(searchTerm));
  });

  setText('findingCountBadge', findings.length);
  if (!findings.length) {
    const summaryOnly = state.detailUnavailable && hasScanData(state.latestScan || state.dashboard.latest);
    list.innerHTML = `<div class="empty-state"><div class="empty-icon"><i data-lucide="${summaryOnly ? 'file-warning' : 'shield-check'}" aria-hidden="true"></i></div><strong>${summaryOnly ? 'SCAN DETAIL UNAVAILABLE' : 'NO VULNERABILITIES'}</strong><p>${summaryOnly ? 'The scan summary is available, but detailed finding records could not be loaded.' : 'No findings are available for this scan.'}</p></div>`;
    empty.hidden = false;
    content.hidden = true;
    setText('vulnerabilityPath', summaryOnly ? 'Detailed evidence is unavailable for this scan.' : 'No scan detail available.');
    setText('investigationMeta', summaryOnly ? 'SUMMARY ONLY' : 'NO SCAN DETAIL');
    setText('investigationDot', '');
    $('investigationDot')?.classList.add('status-dot-neutral');
    renderIcons();
    return;
  }

  if (!filtered.length) {
    list.innerHTML = '<div class="empty-state"><strong>NO MATCHING FINDINGS</strong><p>Adjust the severity or search filter.</p></div>';
  } else {
    let selected = getSelectedFinding();
    if (selected && !filtered.includes(selected.finding)) {
      const firstIndex = findings.indexOf(filtered[0]);
      state.selectedFindingIndex = firstIndex;
      state.selectedFindingKey = findingKey(filtered[0], firstIndex);
      selected = { finding: filtered[0], index: firstIndex };
    }
    list.innerHTML = filtered.map(finding => {
      const originalIndex = findings.indexOf(finding);
      return findingListItem(finding, originalIndex, selected && selected.index === originalIndex);
    }).join('');
  }

  const selected = getSelectedFinding();
  if (selected) {
    empty.hidden = true;
    content.hidden = false;
    renderVulnerabilityDetail(selected.finding, selected.index);
  }
  renderIcons();
}

function impactForFinding(finding) {
  const title = finding.title.toLowerCase();
  if (title.includes('authorization') || title.includes('bola') || title.includes('idor') || title.includes('ownership')) {
    return 'A user could view or change another user’s resource. This can lead to unauthorized data access and account impact.';
  }
  if (title.includes('exposure') || title.includes('sensitive') || title.includes('data')) {
    return 'Sensitive information could be returned to clients that should not receive it.';
  }
  if (title.includes('auth')) {
    return 'A route may be reachable without the authentication policy your API expects.';
  }
  return 'This issue could weaken the protection boundary around your API.';
}

function remediationForFinding(finding) {
  if (finding.remediation) return finding.remediation;
  const title = finding.title.toLowerCase();
  if (title.includes('authorization') || title.includes('bola') || title.includes('idor') || title.includes('ownership')) {
    return "Verify that the authenticated user's identity is authorized to access the requested object before returning the resource.";
  }
  if (title.includes('exposure') || title.includes('sensitive') || title.includes('data')) {
    return 'Review the response schema and remove internal identifiers, credentials, or sensitive fields that the client does not need.';
  }
  if (title.includes('auth')) {
    return 'Require a valid authentication mechanism on the route and validate token expiry, signature, and authorization policy at the boundary.';
  }
  return 'Review the endpoint boundary, apply least privilege, and document the expected control before release.';
}

function formatCodeValue(value) {
  if (isRecord(value) || Array.isArray(value)) return JSON.stringify(value, null, 2);
  return String(value ?? '');
}

function highlightCode(value) {
  const safe = escapeHtml(value);
  return safe
    .replace(/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g, '<span class="code-method">$1</span>')
    .replace(/(Authorization|Content-Type|Host|HTTP\/1\.1)\b:?/g, '<span class="code-key">$1</span>:')
    .replace(/(&quot;[^&]+?&quot;)(\s*:)/g, '<span class="code-key">$1</span>$2');
}

function requestTemplateForFinding(finding) {
  const method = methodLabel(finding.method);
  const path = pathLabel(finding.path);
  return `${method} ${path} HTTP/1.1\nHost: sandbox API endpoint not provided\nAuthorization: Bearer ********\nX-Sentinel-Scan: authorized-review-template`;
}

function renderVulnerabilityDetail(finding, index) {
  if (!finding) return;
  const severity = severityLabel(finding.severity);
  setText('vulnerabilityTitle', finding.title);
  setText('vulnerabilityPath', `${methodLabel(finding.method)} ${pathLabel(finding.path)} · ${severity}`);
  setText('vulnerabilityDescription', finding.description);
  setText('detailImpact', impactForFinding(finding));
  const technicalDetails = $('technicalDetails');
  if (technicalDetails) technicalDetails.open = false;
  setText('detailSeverity', severity);
  setText('detailSeverityValue', severity);
  setText('detailMethod', methodLabel(finding.method));
  setText('detailPath', pathLabel(finding.path));
  setText('detailEndpoint', `${methodLabel(finding.method)} ${pathLabel(finding.path)}`);
  setText('detailDetected', formatDate(finding.detected || state.latestScan?.created_at));
  setText('detailConfidence', finding.confidence ? `CONFIDENCE: ${String(finding.confidence).toUpperCase()}` : 'CONFIDENCE NOT REPORTED');
  setText('detailStatus', String(finding.status || 'OPEN').toUpperCase());
  setText('detailRemediation', remediationForFinding(finding));
  setText('evidenceMethod', methodLabel(finding.method));
  setText('responseStatus', finding.responseStatus ? String(finding.responseStatus).toUpperCase() : 'NOT REPORTED');
  setText('evidenceSource', finding.request || finding.response ? 'BACKEND EVIDENCE' : 'RECONSTRUCTED / NO POC');

  const severityBadge = $('detailSeverity');
  if (severityBadge) severityBadge.className = `severity-badge severity-${normalizeSeverity(finding.severity)}`;
  const status = $('detailStatus');
  if (status) status.className = `finding-status ${String(finding.status).toUpperCase() === 'CLOSED' ? 'status-closed' : ''}`;

  const request = finding.request ? formatCodeValue(finding.request) : requestTemplateForFinding(finding);
  const response = finding.response ? formatCodeValue(finding.response) : 'No response evidence was returned by the scan service.';
  state.selectedRequest = request;
  const requestElement = $('requestEvidence');
  const responseElement = $('responseEvidence');
  if (requestElement) requestElement.innerHTML = finding.request ? highlightCode(request) : `${escapeHtml(request)}\n\n<span class="evidence-empty">Reconstructed request template. The backend did not return proof-of-concept evidence.</span>`;
  if (responseElement) responseElement.innerHTML = finding.response ? highlightCode(response) : `<span class="evidence-empty">${escapeHtml(response)}</span>`;

  const findingKeyElement = $('vulnerabilityList')?.querySelector(`[data-finding-index="${index}"]`);
  findingKeyElement?.classList.add('is-selected');
  setText('investigationMeta', `${getScanId(state.latestScan || state.dashboard.latest)} / FINDING ${index + 1}`);
  const investigationDot = $('investigationDot');
  if (investigationDot) investigationDot.className = `status-dot status-dot-${normalizeSeverity(finding.severity) === 'critical' ? 'critical' : 'warning'}`;
}

async function copyRequestEvidence() {
  const request = state.selectedRequest;
  if (!request) {
    showToast('No request evidence is available for this finding.', 'error');
    return;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(request);
    } else {
      const area = document.createElement('textarea');
      area.value = request;
      area.setAttribute('readonly', '');
      area.className = 'sr-only';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    showToast('Request evidence copied to clipboard.', 'success');
  } catch (error) {
    showToast('Clipboard access is unavailable in this browser.', 'error');
  }
}

/* Inventory and database --------------------------------------------------- */

function initInventoryFilters() {
  const search = $('inventorySearch');
  search?.addEventListener('input', event => {
    state.inventorySearch = event.target.value.trim().toLowerCase();
    renderInventory();
  });
  queryAll('[data-inventory-filter]').forEach(button => {
    button.addEventListener('click', () => {
      state.inventoryFilter = button.dataset.inventoryFilter;
      queryAll('[data-inventory-filter]').forEach(item => item.classList.toggle('is-active', item === button));
      renderInventory();
    });
  });
}

function inventoryMatches(record) {
  const auth = String(record.auth || '').toLowerCase();
  const risk = String(record.risk || '').toLowerCase();
  const status = String(record.status || '').toLowerCase();
  const filter = state.inventoryFilter;
  if (state.inventorySearch && !`${record.method || ''} ${record.path || ''} ${auth} ${risk}`.toLowerCase().includes(state.inventorySearch)) return false;
  if (filter === 'all') return true;
  if (filter === 'public') return auth.includes('public') || auth === 'none' || auth === 'not required';
  if (filter === 'authenticated') return auth.includes('auth') || auth.includes('required');
  if (filter === 'high') return risk.includes('critical') || risk.includes('high');
  if (filter === 'untested') return !record.lastTested || status.includes('untested') || status.includes('unassessed');
  return true;
}

function renderInventory() {
  const body = $('inventoryBody');
  const empty = $('inventoryEmpty');
  if (!body || !empty) return;
  const allRecords = getInventoryRecords();
  const records = allRecords.filter(inventoryMatches);
  body.innerHTML = records.map(renderInventoryRow).join('');
  empty.style.display = records.length ? 'none' : 'flex';
  if (!records.length) {
    const hasScan = hasScanData(state.latestScan || state.dashboard.latest);
    empty.innerHTML = hasScan && state.inventoryFilter !== 'all'
      ? '<div class="empty-state"><div class="empty-icon"><i data-lucide="filter-x" aria-hidden="true"></i></div><strong>NO ROUTES MATCH FILTER</strong><p>Change the inventory filter to review other route records.</p></div>'
      : hasScan
        ? '<div class="empty-state"><div class="empty-icon"><i data-lucide="route-off" aria-hidden="true"></i></div><strong>ROUTE INVENTORY UNAVAILABLE</strong><p>The backend returned an endpoint count but no route records. Run a scan with detail support or use the finding-linked routes.</p></div>'
        : '<div class="empty-state"><div class="empty-icon"><i data-lucide="scan-search" aria-hidden="true"></i></div><strong>NO API INVENTORY</strong><p>Upload an OpenAPI specification to discover endpoints.</p></div>';
  }
  setText('inventoryEndpointCount', state.dashboard.totals.endpoints || state.latestScan?.endpoint_count || 0);
  setText('inventoryScanCount', state.dashboard.totals.scans);
}

function renderDatabase() {
  const container = $('databaseTables');
  if (!container) return;
  if (!state.database) {
    container.innerHTML = '<div class="database-loading">Database metadata has not been loaded.</div>';
    return;
  }
  if (!Array.isArray(state.database.tables) || !state.database.tables.length) {
    container.innerHTML = '<div class="database-loading">The backend returned no database tables.</div>';
    return;
  }
  container.innerHTML = state.database.tables.map(table => {
    const name = String(table.name || 'table');
    const rows = safeNumber(table.rows);
    return `<div class="database-table"><i data-lucide="table-2" aria-hidden="true"></i><span><strong>${escapeHtml(name)}</strong><small>${rows} saved row${rows === 1 ? '' : 's'}</small></span><span class="table-state">LIVE</span></div>`;
  }).join('');
  renderIcons();
}

async function loadDatabaseData() {
  const container = $('databaseTables');
  if (container) container.innerHTML = '<div class="database-loading">Loading database metadata…</div>';
  try {
    const data = await apiFetch('/api/database');
    if (!isRecord(data) || !Array.isArray(data.tables)) {
      throw new ApiError('The database response was malformed.', 'malformed');
    }
    state.database = data;
    renderDatabase();
    updateGlobalMetadata();
  } catch (error) {
    state.database = null;
    setText('databaseStatus', 'DATABASE METADATA UNAVAILABLE');
    if (container) {
      container.innerHTML = `<div class="database-loading">Unable to load database metadata. <button class="text-button" type="button" data-action="retry-database">RETRY</button></div>`;
    }
    handleApiError(error, 'database metadata');
  }
  renderIcons();
}

/* History ------------------------------------------------------------------ */

function renderHistory(scanInput = state.dashboard.scans) {
  const body = $('historyList');
  const empty = $('historyEmpty');
  if (!body || !empty) return;
  const historyScans = Array.isArray(scanInput) ? scanInput : [];
  const scans = historyScans;
  body.innerHTML = scans.map(scan => `<tr data-scan-id="${escapeHtml(String(scan.id))}"><td><span class="scan-id-badge">${escapeHtml(getScanId(scan))}</span></td><td><strong>${escapeHtml(scan.title || scan.filename)}</strong><small class="table-subtext">${escapeHtml(scan.filename)}</small></td><td>${safeNumber(scan.endpoint_count)}</td><td>${safeNumber(scan.finding_count)}</td><td><span class="score-cell ${safeNumber(scan.score) < 70 ? 'score-low' : ''}">${safeNumber(scan.score)} / 100</span></td><td><span class="status-badge status-low">Complete</span></td><td>${escapeHtml(formatDateTime(scan.created_at))}</td><td><button class="button button-secondary button-small" type="button" data-scan-id="${escapeHtml(String(scan.id))}" aria-label="View scan ${escapeHtml(getScanId(scan))}">View scan</button></td></tr>`).join('');
  empty.hidden = scans.length > 0;
  if (!scans.length) empty.innerHTML = '<div class="empty-state"><div class="empty-icon"><i data-lucide="history" aria-hidden="true"></i></div><strong>NO SCANS YET</strong><p>Your API security journey starts here. Upload an OpenAPI specification and run your first scan.</p><button class="button button-primary" type="button" data-nav-target="new-scan">START NEW SCAN</button></div>';
  renderTrendChart($('historyTrend'), scans, 'NO SCORE HISTORY', 'Complete a scan to establish a baseline score.');
  setText('historySource', scans.length ? 'LOCAL STORAGE' : 'WAITING FOR SCAN');
}

function refreshHistory(scan) {
  const normalized = normalizeScan(scan);
  if (normalized.id === null || normalized.id === undefined) return;
  state.dashboard.scans = [normalized, ...state.dashboard.scans.filter(item => item.id !== normalized.id)];
  renderHistory();
}

async function loadScanDetails(scanId, options = {}) {
  const id = encodeURIComponent(String(scanId));
  setSystemState('neutral', 'LOADING');
  try {
    const data = await apiFetch(`/api/scans/${id}`);
    if (!isRecord(data) || data.error || data.id === undefined || data.id === null) {
      throw new ApiError('The scan detail response was malformed.', 'malformed');
    }
    state.latestScan = normalizeScan(data);
    state.detailUnavailable = false;
    state.selectedFindingIndex = null;
    state.selectedFindingKey = null;
    renderAll();
    clearConnectionError();
    if (options.navigate) navigateTo('vulnerabilities');
    if (options.notify) showToast(`${getScanId(state.latestScan)} loaded for investigation.`, 'success');
    return state.latestScan;
  } catch (error) {
    const summary = state.dashboard.scans.find(scan => String(scan.id) === String(scanId));
    if (summary) {
      state.latestScan = summary;
      state.detailUnavailable = true;
      setSystemState('warning', 'DEGRADED');
      state.selectedFindingIndex = null;
      state.selectedFindingKey = null;
      renderAll();
      if (options.navigate) navigateTo('vulnerabilities');
      showToast('Scan summary is available, but detailed evidence could not be loaded.', 'error');
    } else {
      handleApiError(error, 'scan detail');
    }
    return null;
  }
}

/* Reports ------------------------------------------------------------------ */

function renderReports() {
  const scan = state.latestScan || state.dashboard.latest;
  const hasScan = hasScanData(scan);
  setText('reportSource', hasScan ? `${getScanId(scan)} / LOCAL STORE` : 'NO SCAN SELECTED');
  setText('reportScanLabel', hasScan ? `${getScanId(scan)} / ${scan.title || scan.filename}` : 'NO SCAN DATA');
  setText('reportScanMeta', hasScan ? `${scan.filename} / ${scan.endpoint_count} endpoints analyzed` : 'Complete a scan to generate a grounded report.');
  setText('reportScore', hasScan ? `${safeNumber(scan.score)} / 100` : '—');
  setText('reportFindingCount', hasScan ? safeNumber(scan.finding_count) : '—');
  setText('reportGenerated', hasScan ? formatDate(new Date()) : '—');
  setText('executiveReportMeta', hasScan ? `${getScanId(scan)} / ${scan.finding_count} findings` : 'No completed scan');
  setText('technicalReportMeta', hasScan ? `${getScanId(scan)} / ${scan.endpoint_count} endpoints` : 'No completed scan');
}

function buildReportContent(type) {
  const scan = state.latestScan || state.dashboard.latest;
  const hasScan = hasScanData(scan);
  const generated = new Date().toISOString();
  const lines = [
    'SENTINEL // API SECURITY',
    type === 'executive' ? 'EXECUTIVE SECURITY REPORT' : 'TECHNICAL SECURITY REPORT',
    `Generated: ${generated}`,
    `Scan: ${hasScan ? getScanId(scan) : 'NO SCAN DATA'}`,
    ''
  ];
  if (!hasScan) {
    lines.push('No completed scan is available.', 'Run an authorized OpenAPI security scan to generate a grounded report.');
    return lines.join('\n');
  }

  lines.push('SUMMARY', `API: ${scan.title || scan.filename}`, `Specification: ${scan.filename}`, `Endpoints analyzed: ${scan.endpoint_count}`, `Findings: ${scan.finding_count}`, `Security score: ${scan.score}/100`, `Scan timestamp: ${scan.created_at || 'not reported'}`, '');
  if (type === 'executive') {
    lines.push('PRIORITY SUMMARY', `Critical findings: ${getCriticalCount()}`, '');
    getLatestFindings().filter(finding => normalizeSeverity(finding.severity) === 'critical').forEach((finding, index) => {
      lines.push(`${index + 1}. ${finding.title} — ${methodLabel(finding.method)} ${pathLabel(finding.path)}`, `   ${finding.description}`);
    });
    lines.push('', 'RECOMMENDATION', 'Review and remediate recorded findings in descending severity order. Validate fixes with a new authorized scan.');
  } else {
    lines.push('FINDING REGISTER');
    const findings = getLatestFindings();
    if (!findings.length) lines.push('No detailed finding records were returned by the backend.');
    findings.forEach((finding, index) => {
      lines.push('', `${index + 1}. [${severityLabel(finding.severity)}] ${finding.title}`, `Method: ${methodLabel(finding.method)}`, `Endpoint: ${pathLabel(finding.path)}`, `Description: ${finding.description}`, `Recommended action: ${remediationForFinding(finding)}`);
    });
    lines.push('', 'EVIDENCE NOTE', 'Proof-of-concept evidence is included only when returned by the scan service.');
  }
  return lines.join('\n');
}

function downloadReport(name) {
  const type = String(name).toLowerCase().includes('technical') || String(name).toLowerCase().includes('technical-findings') ? 'technical' : 'executive';
  const content = buildReportContent(type);
  const link = document.createElement('a');
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }));
  link.href = url;
  link.download = `sentinel-${type}-security-report.txt`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast(`${type === 'executive' ? 'Executive' : 'Technical'} report downloaded.`, 'success');
}

/* Insights and Copilot ----------------------------------------------------- */

function renderInsights() {
  const scan = state.latestScan || state.dashboard.latest;
  const findings = getLatestFindings();
  setText('insightContextTitle', hasScanData(scan) ? `${getScanId(scan)} / ${scan.title || scan.filename}` : 'NO SCAN DATA');
  setText('insightScanId', hasScanData(scan) ? getScanId(scan) : '—');
  setText('insightEndpointCount', scan?.endpoint_count || 0);
  setText('insightFindingCount', scan?.finding_count || 0);
  setText('insightQueueMeta', findings.length ? `${findings.length} RECORDED FINDING${findings.length === 1 ? '' : 'S'}` : 'NO FINDINGS');

  const queue = $('insightQueue');
  if (!queue) return;
  if (!findings.length) {
    queue.innerHTML = '<div class="empty-state"><div class="empty-icon"><i data-lucide="sparkles" aria-hidden="true"></i></div><strong>NO PRIORITY FINDINGS</strong><p>Run a security scan to generate grounded remediation priorities.</p><button class="button button-secondary" type="button" data-nav-target="new-scan">START A SCAN</button></div>';
    return;
  }
  queue.innerHTML = findings.slice(0, 4).map((finding, index) => `<article class="insight-item"><span class="insight-item-index">0${index + 1}</span><div class="insight-item-copy"><span class="severity-badge severity-${normalizeSeverity(finding.severity)}">${escapeHtml(severityLabel(finding.severity))}</span><strong>${escapeHtml(finding.title)}</strong><p>${escapeHtml(finding.description)}</p></div><i data-lucide="arrow-up-right" aria-hidden="true"></i></article>`).join('');
  renderIcons();
}

function initCopilot() {
  const form = $('chatForm');
  const input = $('chatInput');
  if (!form || !input) return;
  form.addEventListener('submit', event => {
    event.preventDefault();
    const message = input.value.trim();
    if (message) sendChatMessage(message);
  });
  queryAll('[data-prompt]').forEach(button => {
    button.addEventListener('click', () => sendChatMessage(button.dataset.prompt || ''));
  });
  $('clearChatButton')?.addEventListener('click', clearChat);
}

function appendChatMessage(role, message, options = {}) {
  const container = $('chatMessages');
  if (!container) return null;
  const bubble = document.createElement('article');
  bubble.className = `chat-message ${role === 'user' ? 'user' : 'assistant'}${options.error ? ' is-error' : ''}`;
  const meta = document.createElement('div');
  meta.className = 'chat-message-meta';
  const author = document.createElement('strong');
  author.textContent = role === 'user' ? 'YOU' : 'SENTINEL AI';
  const timestamp = document.createElement('time');
  timestamp.dateTime = new Date().toISOString();
  timestamp.textContent = options.timestamp || new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date());
  meta.append(author, timestamp);
  const text = document.createElement('p');
  text.textContent = String(message ?? '');
  bubble.append(meta, text);
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function showChatTyping() {
  const container = $('chatMessages');
  if (!container) return null;
  const typing = document.createElement('article');
  typing.className = 'chat-message assistant';
  typing.id = 'chatTyping';
  typing.innerHTML = '<div class="chat-message-meta"><strong>SENTINEL AI</strong><time>ANALYZING</time></div><p class="chat-message-typing">Reading local scan context…</p>';
  container.appendChild(typing);
  container.scrollTop = container.scrollHeight;
  return typing;
}

async function sendChatMessage(message) {
  const input = $('chatInput');
  const form = $('chatForm');
  const button = form?.querySelector('button[type="submit"]');
  const text = String(message || '').trim();
  if (!text || state.chatBusy) return;
  state.chatBusy = true;
  if (input) {
    input.value = '';
    input.disabled = true;
  }
  if (button) button.disabled = true;
  $('chatError')?.setAttribute('hidden', 'true');
  appendChatMessage('user', text);
  const typing = showChatTyping();

  try {
    const result = await apiFetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text })
    });
    if (!isRecord(result) || typeof result.answer !== 'string') {
      throw new ApiError('The copilot response was malformed.', 'malformed', 200, result);
    }
    appendChatMessage('assistant', result.answer, { timestamp: result.timestamp ? formatDateTime(result.timestamp) : undefined });
    clearConnectionError();
  } catch (error) {
    const messageText = friendlyError(error, 'The copilot is temporarily unavailable. Try again when the local API is online.');
    appendChatMessage('assistant', messageText, { error: true });
    const chatError = $('chatError');
    if (chatError) {
      chatError.textContent = messageText;
      chatError.hidden = false;
    }
    handleApiError(error, 'copilot');
  } finally {
    typing?.remove();
    state.chatBusy = false;
    if (input) {
      input.disabled = false;
      input.focus();
    }
    if (button) button.disabled = false;
  }
}

function clearChat() {
  const container = $('chatMessages');
  if (!container) return;
  container.innerHTML = '';
  appendChatMessage('assistant', 'Ask about the current security score, findings, endpoint exposure, or remediation priorities.');
  const error = $('chatError');
  if (error) error.hidden = true;
  showToast('Copilot conversation cleared.', 'success');
}

/* Settings ----------------------------------------------------------------- */

function initSettings() {
  const form = $('settingsForm');
  if (!form) return;
  try {
    const stored = JSON.parse(window.localStorage.getItem('sentinel-settings') || 'null');
    if (isRecord(stored)) state.settings = { ...state.settings, ...stored };
  } catch (error) {
    // Ignore invalid local preferences and use safe defaults.
  }

  Object.entries(state.settings).forEach(([key, value]) => {
    const field = form.elements.namedItem(key);
    if (!field) return;
    if (field.type === 'checkbox') field.checked = Boolean(value);
    else field.value = value;
  });
  applyInterfaceSettings();
  $('saveSettingsButton')?.addEventListener('click', saveSettings);
  form.addEventListener('submit', event => {
    event.preventDefault();
    saveSettings();
  });
  $('environmentSelect')?.addEventListener('change', event => {
    const scanEnvironment = $('scanEnvironment');
    const defaultEnvironment = $('settingsForm')?.elements.namedItem('defaultEnvironment');
    if (scanEnvironment) scanEnvironment.value = event.target.value;
    if (defaultEnvironment) defaultEnvironment.value = event.target.value;
    updateScanActionState();
  });
  $('scanEnvironment')?.addEventListener('change', event => {
    const environment = $('environmentSelect');
    if (environment) environment.value = event.target.value;
    updateScanActionState();
  });
}

function applyInterfaceSettings() {
  document.body.classList.toggle('compact-density', Boolean(state.settings.compactDensity));
  document.body.classList.toggle('no-motion', !state.settings.allowMotion);
  setText('settingsEnvironment', String(state.settings.defaultEnvironment || 'lab').toUpperCase());
  const topEnvironment = $('environmentSelect');
  if (topEnvironment && ['lab', 'staging'].includes(state.settings.defaultEnvironment)) topEnvironment.value = state.settings.defaultEnvironment;
  const scanEnvironment = $('scanEnvironment');
  if (scanEnvironment && ['lab', 'staging'].includes(state.settings.defaultEnvironment)) scanEnvironment.value = state.settings.defaultEnvironment;
  updateScanActionState();
}

function saveSettings() {
  const form = $('settingsForm');
  if (form) {
    const data = new FormData(form);
    state.settings = {
      scanNotifications: data.get('scanNotifications') === 'on',
      includePoc: data.get('includePoc') === 'on',
      defaultEnvironment: data.get('defaultEnvironment') || 'lab',
      safeScanning: data.get('safeScanning') === 'on',
      compactDensity: data.get('compactDensity') === 'on',
      allowMotion: data.get('allowMotion') === 'on'
    };
    try {
      window.localStorage.setItem('sentinel-settings', JSON.stringify(state.settings));
    } catch (error) {
      // Settings still apply for the current session if storage is unavailable.
    }
  }
  applyInterfaceSettings();
  const button = $('saveSettingsButton');
  const feedback = $('settingsSaveFeedback');
  if (button) {
    button.innerHTML = '<i data-lucide="check" aria-hidden="true"></i> SAVED';
    window.setTimeout(() => {
      button.innerHTML = '<i data-lucide="save" aria-hidden="true"></i> SAVE CHANGES';
      renderIcons();
    }, 1600);
  }
  if (feedback) {
    feedback.hidden = false;
    feedback.textContent = 'Workspace preferences saved locally.';
    window.setTimeout(() => { feedback.hidden = true; }, 2600);
  }
  showToast('Settings saved for this workspace.', 'success');
  renderIcons();
}

/* Feedback and top controls ------------------------------------------------ */

function showToast(message, type = 'info') {
  const region = $('toastRegion');
  if (!region) return;
  const toast = document.createElement('div');
  toast.className = `toast${type === 'error' ? ' is-error' : type === 'success' ? ' is-success' : ''}`;
  const icon = document.createElement('i');
  icon.dataset.lucide = type === 'error' ? 'triangle-alert' : type === 'success' ? 'check-circle-2' : 'info';
  const text = document.createElement('span');
  text.textContent = message;
  toast.append(icon, text);
  region.appendChild(toast);
  renderIcons();
  window.setTimeout(() => {
    toast.classList.add('is-leaving');
    window.setTimeout(() => toast.remove(), 180);
  }, 3600);
}

function initTopControls() {
  $('notificationButton')?.addEventListener('click', () => {
    const findings = getCriticalCount();
    showToast(findings ? `${findings} critical finding${findings === 1 ? '' : 's'} require review.` : 'No critical notifications are active.', findings ? 'error' : 'info');
  });
  $('profileButton')?.addEventListener('click', () => {
    showToast('Local operator session: Security Admin.', 'info');
  });
  $('exportDatabaseButton')?.addEventListener('click', downloadDatabaseSnapshot);
  $('startScanButton')?.addEventListener('click', startScanProcess);
  queryAll('[data-download-report]').forEach(button => {
    button.addEventListener('click', () => downloadReport(button.dataset.downloadReport));
  });
  $('mainContent')?.addEventListener('click', event => {
    const navigationTarget = event.target.closest('[data-nav-target]');
    if (navigationTarget) {
      navigateTo(navigationTarget.dataset.navTarget);
      return;
    }

    const findingTarget = event.target.closest('[data-finding-index]');
    if (findingTarget) {
      const index = Number(findingTarget.dataset.findingIndex);
      const findings = getLatestFindings();
      if (Number.isInteger(index) && findings[index]) {
        state.selectedFindingIndex = index;
        state.selectedFindingKey = findingKey(findings[index], index);
        renderVulnerabilities();
        navigateTo('vulnerabilities');
      }
      return;
    }

    const scanTarget = event.target.closest('[data-scan-id]');
    if (scanTarget) {
      const scanId = scanTarget.dataset.scanId;
      if (scanId) loadScanDetails(scanId, { navigate: true, notify: true });
      return;
    }

    const retryDatabase = event.target.closest('[data-action="retry-database"]');
    if (retryDatabase) loadDatabaseData();
  });
}

async function downloadDatabaseSnapshot() {
  try {
    const snapshot = await apiFetch('/api/database');
    if (!isRecord(snapshot)) throw new ApiError('The database snapshot was malformed.', 'malformed');
    const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sentinel-database-snapshot.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Database snapshot downloaded.', 'success');
    clearConnectionError();
  } catch (error) {
    handleApiError(error, 'database snapshot');
    showToast(friendlyError(error, 'The database snapshot could not be downloaded.'), 'error');
  }
}

/* Dashboard data flow ------------------------------------------------------ */

async function loadDashboardData() {
  setSystemState('neutral', 'SYNCING');
  try {
    const payload = await apiFetch('/api/dashboard');
    const dashboard = normalizeDashboard(payload);
    state.dashboard = dashboard;
    state.latestScan = dashboard.latest.id !== null ? dashboard.latest : null;
    state.detailUnavailable = false;

    const latestSummary = dashboard.scans[0];
    if (latestSummary && latestSummary.id !== null) {
      state.latestScan = latestSummary;
      try {
        const detailPayload = await apiFetch(`/api/scans/${encodeURIComponent(String(latestSummary.id))}`);
        if (isRecord(detailPayload) && !detailPayload.error && detailPayload.id !== undefined) {
          state.latestScan = normalizeScan(detailPayload);
          state.detailUnavailable = false;
        }
      } catch (error) {
        // A dashboard summary remains useful when the detail route is unavailable.
        state.detailUnavailable = true;
        if (error.kind === 'http') {
          showToast('Latest scan summary loaded; detailed evidence is unavailable.', 'error');
        }
      }
    }

    clearConnectionError();
    renderAll();
  } catch (error) {
    handleApiError(error, 'dashboard');
    state.dashboard = { latest: {}, totals: { scans: 0, endpoints: 0, findings: 0 }, scans: [] };
    state.latestScan = null;
    state.detailUnavailable = false;
    renderAll();
  }
}

function updateDashboard(scan, data = {}) {
  if (isRecord(data) && (data.latest || data.totals || data.scans)) {
    try {
      state.dashboard = normalizeDashboard(data);
    } catch (error) {
      // Preserve the current dashboard if a legacy caller supplies partial data.
    }
  }
  if (scan) {
    const normalized = normalizeScan(scan);
    state.latestScan = normalized;
    if (normalized.id !== null) {
      state.detailUnavailable = false;
      refreshHistory(normalized);
    }
  }
  renderAll();
}

/* Application startup ------------------------------------------------------ */

function initApp() {
  renderIcons();
  initNavigation();
  initFileUpload();
  initScanModules();
  initVulnerabilityFilters();
  initInventoryFilters();
  initCopilot();
  initSettings();
  initTopControls();
  renderAll();
  loadDashboardData();
  loadDatabaseData();

  const hashView = window.location.hash.replace('#', '');
  if (hashView && document.getElementById(hashView)) navigateTo(hashView);
  window.addEventListener('hashchange', () => {
    const nextView = window.location.hash.replace('#', '');
    if (nextView && document.getElementById(nextView)) navigateTo(nextView);
  });
}

// Keep the established public function names available to inline integrations.
window.navigateTo = navigateTo;
window.startScanProcess = startScanProcess;
window.handleUploadedFile = handleUploadedFile;
window.downloadReport = downloadReport;
window.downloadDatabaseSnapshot = downloadDatabaseSnapshot;
window.saveSettings = saveSettings;
window.renderScanProgress = setProgressStep;
window.sendChatMessage = sendChatMessage;
window.appendChatMessage = appendChatMessage;
window.loadDashboard = loadDashboardData;
window.loadDashboardData = loadDashboardData;
window.loadDatabase = loadDatabaseData;
window.loadDatabaseData = loadDatabaseData;
window.loadScanDetails = loadScanDetails;
window.handleApiError = handleApiError;

document.addEventListener('DOMContentLoaded', initApp);
