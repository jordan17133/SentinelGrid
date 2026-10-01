const STORAGE_KEY = "sentinelgrid-state-v1";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_WEIGHT = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEVERITY_COLOR = {
  critical: "#ff5d5d",
  high: "#f59b4c",
  medium: "#f6d166",
  low: "#42d392",
  info: "#6ca7ff"
};

const tactics = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control"
];

const ruleSeed = [
  {
    id: "SG-R-100",
    name: "Impossible travel or anomalous SSO",
    severity: "high",
    tactic: "Initial Access",
    technique: "T1078 Valid Accounts",
    source: "Okta SSO",
    enabled: true,
    description: "Flags sign-ins from impossible travel, risky geography, or unusual device fingerprints.",
    runbook: ["Confirm user location", "Invalidate active sessions", "Require password reset", "Review new OAuth grants"]
  },
  {
    id: "SG-R-120",
    name: "MFA fatigue and brute force chain",
    severity: "critical",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    source: "Okta SSO",
    enabled: true,
    description: "Correlates repeated failed logins followed by repeated MFA push attempts.",
    runbook: ["Disable affected account", "Block source IP", "Collect IdP logs", "Notify identity owner"]
  },
  {
    id: "SG-R-210",
    name: "Endpoint process injection",
    severity: "critical",
    tactic: "Defense Evasion",
    technique: "T1055 Process Injection",
    source: "CrowdStrike EDR",
    enabled: true,
    description: "Detects suspicious process injection, unsigned memory loads, and credential tool staging.",
    runbook: ["Isolate host", "Capture process tree", "Collect memory artifacts", "Search for related hashes"]
  },
  {
    id: "SG-R-330",
    name: "Cloud key reconnaissance",
    severity: "high",
    tactic: "Discovery",
    technique: "T1526 Cloud Service Discovery",
    source: "AWS CloudTrail",
    enabled: true,
    description: "Detects abnormal IAM enumeration and access key discovery activity.",
    runbook: ["Rotate exposed keys", "Review IAM changes", "Check AssumeRole chain", "Inspect cloud egress"]
  },
  {
    id: "SG-R-410",
    name: "Outbound beaconing pattern",
    severity: "medium",
    tactic: "Command and Control",
    technique: "T1071 Application Layer Protocol",
    source: "Zeek Sensor",
    enabled: true,
    description: "Finds periodic outbound connections to rare domains or known risky networks.",
    runbook: ["Block destination", "Review DNS history", "Inspect endpoint process", "Collect packet sample"]
  },
  {
    id: "SG-R-520",
    name: "Domain admin enumeration",
    severity: "medium",
    tactic: "Discovery",
    technique: "T1069 Permission Groups Discovery",
    source: "Windows DC01",
    enabled: true,
    description: "Catches group enumeration, directory scraping, and abnormal LDAP query volume.",
    runbook: ["Review account purpose", "Check interactive logon", "Inspect parent process", "Search lateral movement"]
  }
];

const sourceSeed = [
  { name: "Okta SSO", type: "identity", health: 98, eps: 42, status: "healthy" },
  { name: "CrowdStrike EDR", type: "endpoint", health: 94, eps: 78, status: "healthy" },
  { name: "FortiGate Edge", type: "firewall", health: 91, eps: 115, status: "healthy" },
  { name: "AWS CloudTrail", type: "cloud", health: 86, eps: 31, status: "delayed" },
  { name: "Windows DC01", type: "identity", health: 82, eps: 68, status: "delayed" },
  { name: "Zeek Sensor", type: "network", health: 97, eps: 89, status: "healthy" },
  { name: "Microsoft Defender", type: "endpoint", health: 76, eps: 44, status: "degraded" }
];

const assetSeed = [
  { id: "dc01", name: "dc01.corp.local", type: "Domain controller", owner: "Identity", criticality: 5, risk: 91, lastSeenMins: 4, vulnerabilities: 2 },
  { id: "vpn-gateway-02", name: "vpn-gateway-02", type: "Remote access", owner: "Network", criticality: 5, risk: 84, lastSeenMins: 7, vulnerabilities: 1 },
  { id: "aws-prod-iam", name: "aws-prod-iam", type: "Cloud control plane", owner: "Cloud", criticality: 5, risk: 79, lastSeenMins: 3, vulnerabilities: 0 },
  { id: "fin-app-07", name: "fin-app-07", type: "Finance app", owner: "Business apps", criticality: 4, risk: 68, lastSeenMins: 11, vulnerabilities: 4 },
  { id: "hr-laptop-144", name: "hr-laptop-144", type: "Workstation", owner: "HR", criticality: 3, risk: 57, lastSeenMins: 16, vulnerabilities: 3 },
  { id: "sql-ledger-01", name: "sql-ledger-01", type: "Database", owner: "Data", criticality: 5, risk: 73, lastSeenMins: 9, vulnerabilities: 1 }
];

const users = ["jbell", "acarven", "svc-backup", "mchen", "rpatel", "nlee", "svc-cloudsync"];
const eventTypes = ["auth", "endpoint", "network", "cloud_audit", "windows_event", "dns"];
const destinations = ["185.199.110.153", "44.214.88.10", "10.42.8.22", "172.16.4.9", "203.0.113.77", "198.51.100.24"];

let state = loadState();
let filters = {
  query: "",
  severity: "all",
  source: "all",
  time: "6h",
  incident: "open"
};
let selectedIncidentId = state.incidents[0]?.id || null;
let selectedEventId = state.events[0]?.id || null;
let liveTimer = null;
let toastTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  bindControls();
  populateFilterOptions();
  renderAll();
  startLiveIngest();
});

function bindControls() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view));
  });

  document.getElementById("liveToggle").addEventListener("click", toggleLiveIngest);
  document.getElementById("runCorrelation").addEventListener("click", () => {
    const count = runCorrelation();
    showToast(`${count} incidents updated from enabled rules.`);
  });
  document.getElementById("exportReport").addEventListener("click", exportCaseData);
  document.getElementById("resetData").addEventListener("click", resetData);
  document.getElementById("clearFilters").addEventListener("click", clearFilters);
  document.getElementById("globalSearch").addEventListener("input", (event) => {
    filters.query = event.target.value.trim();
    renderEventsAndCharts();
  });
  document.getElementById("severityFilter").addEventListener("change", (event) => {
    filters.severity = event.target.value;
    renderEventsAndCharts();
  });
  document.getElementById("sourceFilter").addEventListener("change", (event) => {
    filters.source = event.target.value;
    renderEventsAndCharts();
  });
  document.getElementById("timeFilter").addEventListener("change", (event) => {
    filters.time = event.target.value;
    renderEventsAndCharts();
  });
  document.getElementById("incidentFilter").addEventListener("change", (event) => {
    filters.incident = event.target.value;
    renderIncidents();
  });
  document.getElementById("chooseFile").addEventListener("click", () => document.getElementById("importFile").click());
  document.getElementById("importFile").addEventListener("change", handleFileImport);
  document.getElementById("importEvents").addEventListener("click", importEventsFromText);
  document.getElementById("loadSample").addEventListener("click", loadSamplePayload);
  document.getElementById("enableAllRules").addEventListener("click", () => {
    state.rules = state.rules.map((rule) => ({ ...rule, enabled: true }));
    saveState();
    renderRules();
    showToast("All detection rules enabled.");
  });
}

function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((section) => section.classList.remove("active"));
  document.getElementById(`${view}View`).classList.add("active");
}

function loadState() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (saved?.events?.length && saved?.incidents && saved?.rules) {
      return saved;
    }
  } catch {
    localStorage.removeItem(STORAGE_KEY);
  }
  return seedState();
}

function seedState() {
  const events = buildSeedEvents();
  const incidents = [
    buildIncident("INC-1001", "Endpoint process injection on hr-laptop-144", "critical", "New", "Unassigned", "hr-laptop-144", "SG-R-210", events),
    buildIncident("INC-1002", "MFA fatigue targeting jbell", "critical", "In Progress", "A. Carven", "vpn-gateway-02", "SG-R-120", events),
    buildIncident("INC-1003", "Cloud key reconnaissance in production IAM", "high", "New", "Cloud on-call", "aws-prod-iam", "SG-R-330", events),
    buildIncident("INC-1004", "Periodic outbound beaconing from fin-app-07", "medium", "Contained", "N. Lee", "fin-app-07", "SG-R-410", events)
  ].filter(Boolean);

  return {
    createdAt: new Date().toISOString(),
    events,
    incidents,
    rules: ruleSeed,
    sources: sourceSeed,
    assets: assetSeed,
    live: true
  };
}

function buildSeedEvents() {
  const specific = [
    sampleEvent({ minutesAgo: 14, severity: "critical", source: "CrowdStrike EDR", type: "endpoint", asset: "hr-laptop-144", user: "mchen", tactic: "Defense Evasion", technique: "T1055 Process Injection", ruleId: "SG-R-210", message: "Suspicious process injection from unsigned PowerShell child process" }),
    sampleEvent({ minutesAgo: 18, severity: "high", source: "CrowdStrike EDR", type: "endpoint", asset: "hr-laptop-144", user: "mchen", tactic: "Credential Access", technique: "T1003 OS Credential Dumping", ruleId: "SG-R-210", message: "Credential access tool staged in user temp directory" }),
    sampleEvent({ minutesAgo: 23, severity: "critical", source: "Okta SSO", type: "auth", asset: "vpn-gateway-02", user: "jbell", tactic: "Credential Access", technique: "T1110 Brute Force", ruleId: "SG-R-120", message: "Repeated failed login followed by MFA push burst" }),
    sampleEvent({ minutesAgo: 29, severity: "high", source: "Okta SSO", type: "auth", asset: "vpn-gateway-02", user: "jbell", tactic: "Initial Access", technique: "T1078 Valid Accounts", ruleId: "SG-R-100", message: "Impossible travel sign-in from unfamiliar ASN" }),
    sampleEvent({ minutesAgo: 37, severity: "high", source: "AWS CloudTrail", type: "cloud_audit", asset: "aws-prod-iam", user: "svc-cloudsync", tactic: "Discovery", technique: "T1526 Cloud Service Discovery", ruleId: "SG-R-330", message: "Burst of IAM ListAccessKeys and GetCallerIdentity calls" }),
    sampleEvent({ minutesAgo: 42, severity: "medium", source: "Zeek Sensor", type: "network", asset: "fin-app-07", user: "svc-backup", tactic: "Command and Control", technique: "T1071 Application Layer Protocol", ruleId: "SG-R-410", message: "Regular outbound HTTPS beacon to rare external destination" }),
    sampleEvent({ minutesAgo: 51, severity: "medium", source: "Windows DC01", type: "windows_event", asset: "dc01.corp.local", user: "rpatel", tactic: "Discovery", technique: "T1069 Permission Groups Discovery", ruleId: "SG-R-520", message: "Domain admin group enumeration from non-admin workstation" })
  ];

  const generated = Array.from({ length: 92 }, (_, index) => randomEvent(60 + index * 5));
  return [...specific, ...generated].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function buildIncident(id, title, severity, status, owner, asset, ruleId, events) {
  const matching = events.filter((event) => event.ruleId === ruleId || event.asset === asset).slice(0, 6);
  const rule = ruleSeed.find((item) => item.id === ruleId);
  if (!rule) return null;
  return {
    id,
    title,
    severity,
    status,
    owner,
    asset,
    entity: matching[0]?.user || asset,
    ruleId,
    tactic: rule.tactic,
    technique: rule.technique,
    summary: rule.description,
    createdAt: matching.at(-1)?.timestamp || new Date().toISOString(),
    updatedAt: matching[0]?.timestamp || new Date().toISOString(),
    evidenceIds: matching.map((event) => event.id),
    notes: [
      {
        at: new Date(Date.now() - 8 * 60000).toISOString(),
        by: "SOC",
        text: "Initial correlation completed. Evidence attached for analyst validation."
      }
    ]
  };
}

function sampleEvent(overrides) {
  return makeEvent({
    timestamp: new Date(Date.now() - overrides.minutesAgo * 60000).toISOString(),
    source: overrides.source,
    type: overrides.type,
    severity: overrides.severity,
    asset: overrides.asset,
    user: overrides.user,
    srcIp: randomIp(),
    destIp: pick(destinations),
    tactic: overrides.tactic,
    technique: overrides.technique,
    ruleId: overrides.ruleId,
    message: overrides.message
  });
}

function randomEvent(minutesAgo = Math.floor(Math.random() * 360)) {
  const source = pick(sourceSeed).name;
  const asset = pick(assetSeed).name;
  const severity = weightedSeverity();
  const type = typeForSource(source);
  const rule = Math.random() < 0.24 ? pick(ruleSeed.filter((item) => item.source === source || source.includes(item.source.split(" ")[0]))) : null;
  const tactic = rule?.tactic || pick(tactics);
  const technique = rule?.technique || techniqueForTactic(tactic);
  return makeEvent({
    timestamp: new Date(Date.now() - minutesAgo * 60000).toISOString(),
    source,
    type,
    severity,
    asset,
    user: pick(users),
    srcIp: randomIp(),
    destIp: pick(destinations),
    tactic,
    technique,
    ruleId: rule?.id || null,
    message: messageForEvent(source, type, severity, technique, rule)
  });
}

function makeEvent(input) {
  const id = input.id || `evt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
  return {
    id,
    timestamp: input.timestamp || new Date().toISOString(),
    source: input.source || "Unknown source",
    type: input.type || "generic",
    severity: normalizeSeverity(input.severity),
    asset: input.asset || "unknown-asset",
    user: input.user || "unknown",
    srcIp: input.srcIp || input.src_ip || randomIp(),
    destIp: input.destIp || input.dest_ip || pick(destinations),
    tactic: input.tactic || "Discovery",
    technique: input.technique || "Unmapped",
    ruleId: input.ruleId || input.rule_id || null,
    message: input.message || input.event || input.description || "Normalized security event",
    raw: input.raw || input
  };
}

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  if (SEVERITIES.includes(normalized)) return normalized;
  if (["severe", "fatal"].includes(normalized)) return "critical";
  if (["warn", "warning"].includes(normalized)) return "medium";
  return "info";
}

function typeForSource(source) {
  if (source.includes("Okta")) return "auth";
  if (source.includes("EDR") || source.includes("Defender")) return "endpoint";
  if (source.includes("CloudTrail")) return "cloud_audit";
  if (source.includes("DC")) return "windows_event";
  if (source.includes("Zeek") || source.includes("FortiGate")) return "network";
  return pick(eventTypes);
}

function techniqueForTactic(tactic) {
  const mapping = {
    "Initial Access": "T1078 Valid Accounts",
    Execution: "T1059 Command and Scripting Interpreter",
    Persistence: "T1136 Create Account",
    "Privilege Escalation": "T1068 Exploitation for Privilege Escalation",
    "Defense Evasion": "T1027 Obfuscated Files or Information",
    "Credential Access": "T1110 Brute Force",
    Discovery: "T1087 Account Discovery",
    "Lateral Movement": "T1021 Remote Services",
    Collection: "T1119 Automated Collection"
  };
  return mapping[tactic] || "T1071 Application Layer Protocol";
}

function messageForEvent(source, type, severity, technique, rule) {
  if (rule) return `${rule.name} matched: ${technique}`;
  if (type === "auth") return severity === "high" ? "Risky authentication sequence observed" : "User authentication event normalized";
  if (type === "endpoint") return severity === "critical" ? "High-risk endpoint behavior detected" : "Endpoint process telemetry received";
  if (type === "cloud_audit") return "Cloud control plane API call recorded";
  if (type === "network") return "Network flow enriched with reputation and DNS context";
  if (type === "windows_event") return "Windows security log event normalized";
  return "Security telemetry event normalized";
}

function weightedSeverity() {
  const roll = Math.random();
  if (roll > 0.97) return "critical";
  if (roll > 0.86) return "high";
  if (roll > 0.58) return "medium";
  if (roll > 0.28) return "low";
  return "info";
}

function populateFilterOptions() {
  const sourceSelect = document.getElementById("sourceFilter");
  const sources = ["all", ...new Set(state.events.map((event) => event.source).sort())];
  sourceSelect.innerHTML = sources.map((source) => `<option value="${escapeAttr(source)}">${source === "all" ? "All" : escapeHtml(source)}</option>`).join("");
  sourceSelect.value = sources.includes(filters.source) ? filters.source : "all";
}

function renderAll() {
  populateFilterOptions();
  renderMetrics();
  renderHealthRail();
  renderEventsAndCharts();
  renderIncidents();
  renderRules();
  renderMitreGrid();
  renderAssets();
  renderSources();
  renderHunts();
  renderRawRecord();
}

function renderEventsAndCharts() {
  const events = getFilteredEvents();
  renderMetrics();
  renderEventTable(events);
  renderChart(events);
  renderSeverityLegend(events);
  renderRawRecord();
  document.getElementById("lastUpdated").textContent = `Updated ${formatTime(new Date().toISOString())}`;
}

function renderMetrics() {
  const lastHour = Date.now() - 60 * 60000;
  const lastSixHours = Date.now() - 6 * 60 * 60000;
  const recentEvents = state.events.filter((event) => new Date(event.timestamp).getTime() >= lastSixHours);
  const critical = recentEvents.filter((event) => event.severity === "critical").length;
  const openIncidents = state.incidents.filter((incident) => incident.status !== "Closed").length;
  const hourlyEvents = state.events.filter((event) => new Date(event.timestamp).getTime() >= lastHour).length;
  const activeSources = state.sources.filter((source) => source.health >= 80).length;
  const risk = Math.round(state.assets.reduce((sum, asset) => sum + asset.risk, 0) / state.assets.length);
  const highRiskAssets = state.assets.filter((asset) => asset.risk >= 75).length;

  setText("metricCritical", critical);
  setText("metricCriticalTrend", `${recentEvents.length} events in the active window`);
  setText("metricOpenIncidents", openIncidents);
  setText("metricMtta", `${calculateMtta()} min mean acknowledge`);
  setText("metricEventsHour", hourlyEvents);
  setText("metricSources", `${activeSources} sources healthy`);
  setText("metricRisk", risk);
  setText("metricRiskCopy", `${highRiskAssets} high-risk assets`);

  const sla = Math.max(42, Math.min(98, 100 - openIncidents * 7 + state.incidents.filter((item) => item.status === "Contained").length * 5));
  document.documentElement.style.setProperty("--sla-angle", `${Math.round(sla * 3.6)}deg`);
  setText("slaValue", `${sla}%`);
  setText("slaCopy", `${openIncidents} open cases, ${calculateMtta()} min MTTA.`);
}

function calculateMtta() {
  const acknowledged = state.incidents.filter((incident) => incident.status !== "New");
  if (!acknowledged.length) return 0;
  const avg = acknowledged.reduce((sum, incident) => {
    return sum + Math.max(1, Math.round((new Date(incident.updatedAt) - new Date(incident.createdAt)) / 60000));
  }, 0) / acknowledged.length;
  return Math.round(avg);
}

function renderHealthRail() {
  document.getElementById("railHealth").innerHTML = state.sources.slice(0, 5).map((source) => `
    <div class="health-item">
      <div class="health-top">
        <strong>${escapeHtml(source.name)}</strong>
        <span class="tag">${source.eps} EPS</span>
      </div>
      <div class="bar-meter" aria-label="${escapeAttr(source.name)} health ${source.health} percent">
        <span style="width:${source.health}%; background:${healthColor(source.health)}"></span>
      </div>
      <small>${source.status} pipeline, ${source.health}% parser success</small>
    </div>
  `).join("");
}

function renderEventTable(events) {
  const rows = events.slice(0, 160).map((event) => `
    <tr>
      <td><button class="event-row-button" type="button" data-event-id="${escapeAttr(event.id)}">${formatTime(event.timestamp)}</button></td>
      <td><span class="severity-pill ${event.severity}">${event.severity}</span></td>
      <td>${escapeHtml(event.source)}</td>
      <td>${escapeHtml(event.user)}<br><small>${escapeHtml(event.asset)}</small></td>
      <td>${escapeHtml(event.technique)}</td>
      <td>${escapeHtml(event.message)}<br><small>${escapeHtml(event.srcIp)} to ${escapeHtml(event.destIp)}</small></td>
    </tr>
  `).join("");
  document.getElementById("eventTable").innerHTML = rows || `<tr><td colspan="6">No events match the active query.</td></tr>`;
  document.querySelectorAll("[data-event-id]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedEventId = button.dataset.eventId;
      renderRawRecord();
      switchView("hunt");
    });
  });
}

function renderChart(events) {
  const canvas = document.getElementById("eventsChart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(600, Math.floor(rect.width * dpr));
  canvas.height = Math.floor(260 * dpr);
  ctx.scale(dpr, dpr);
  const width = canvas.width / dpr;
  const height = canvas.height / dpr;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#0b100d";
  ctx.fillRect(0, 0, width, height);

  const buckets = buildBuckets(events, 12);
  const max = Math.max(4, ...buckets.map((bucket) => bucket.total));
  const pad = { top: 24, right: 18, bottom: 32, left: 38 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  ctx.strokeStyle = "#26342b";
  ctx.lineWidth = 1;
  ctx.font = "12px Inter, sans-serif";
  ctx.fillStyle = "#6f8276";
  for (let index = 0; index <= 4; index += 1) {
    const y = pad.top + plotH - (plotH * index) / 4;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillText(String(Math.round((max * index) / 4)), 8, y + 4);
  }

  const barWidth = Math.max(10, plotW / buckets.length - 8);
  buckets.forEach((bucket, bucketIndex) => {
    let yCursor = pad.top + plotH;
    SEVERITIES.forEach((severity) => {
      const count = bucket[severity] || 0;
      if (!count) return;
      const segmentH = Math.max(2, (count / max) * plotH);
      ctx.fillStyle = SEVERITY_COLOR[severity];
      ctx.fillRect(pad.left + bucketIndex * (plotW / buckets.length) + 4, yCursor - segmentH, barWidth, segmentH);
      yCursor -= segmentH;
    });
    if (bucketIndex % 3 === 0) {
      ctx.fillStyle = "#6f8276";
      ctx.fillText(bucket.label, pad.left + bucketIndex * (plotW / buckets.length), height - 10);
    }
  });
}

function buildBuckets(events, count) {
  const now = Date.now();
  const windowMs = 6 * 60 * 60000;
  const bucketMs = windowMs / count;
  const buckets = Array.from({ length: count }, (_, index) => {
    const start = now - windowMs + index * bucketMs;
    return { start, total: 0, label: formatShortTime(start), critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  });
  events.forEach((event) => {
    const ts = new Date(event.timestamp).getTime();
    const index = Math.floor((ts - (now - windowMs)) / bucketMs);
    if (index >= 0 && index < buckets.length) {
      buckets[index].total += 1;
      buckets[index][event.severity] += 1;
    }
  });
  return buckets;
}

function renderSeverityLegend(events) {
  const counts = SEVERITIES.reduce((acc, severity) => {
    acc[severity] = events.filter((event) => event.severity === severity).length;
    return acc;
  }, {});
  document.getElementById("severityLegend").innerHTML = SEVERITIES.map((severity) => `
    <span class="legend-item"><span class="legend-swatch" style="background:${SEVERITY_COLOR[severity]}"></span>${severity}: ${counts[severity]}</span>
  `).join("");
}

function renderIncidents() {
  let incidents = [...state.incidents];
  if (filters.incident === "open") incidents = incidents.filter((incident) => incident.status !== "Closed");
  if (filters.incident === "critical") incidents = incidents.filter((incident) => incident.severity === "critical");
  if (filters.incident === "unassigned") incidents = incidents.filter((incident) => incident.owner === "Unassigned");
  incidents.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || new Date(b.updatedAt) - new Date(a.updatedAt));

  document.getElementById("incidentList").innerHTML = incidents.map((incident) => `
    <article class="incident-row ${incident.id === selectedIncidentId ? "active" : ""}">
      <button type="button" data-incident-id="${escapeAttr(incident.id)}">
        <div class="incident-top">
          <strong>${escapeHtml(incident.title)}</strong>
          <span class="severity-pill ${incident.severity}">${incident.severity}</span>
        </div>
        <small>${escapeHtml(incident.id)} updated ${relativeTime(incident.updatedAt)}</small>
        <div class="incident-meta">
          <span class="status-pill ${statusClass(incident.status)}">${escapeHtml(incident.status)}</span>
          <span class="tag">${escapeHtml(incident.owner)}</span>
          <span class="tag">${incident.evidenceIds.length} events</span>
        </div>
      </button>
    </article>
  `).join("") || `<p class="detail-empty">No incidents match that filter.</p>`;

  document.querySelectorAll("[data-incident-id]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedIncidentId = button.dataset.incidentId;
      renderIncidents();
      renderIncidentDetail();
    });
  });
  renderIncidentDetail();
}

function renderIncidentDetail() {
  const incident = state.incidents.find((item) => item.id === selectedIncidentId) || state.incidents[0];
  if (!incident) {
    document.getElementById("incidentDetail").innerHTML = `<p class="detail-empty">No incident selected.</p>`;
    return;
  }
  selectedIncidentId = incident.id;
  const rule = state.rules.find((item) => item.id === incident.ruleId);
  const evidence = incident.evidenceIds.map((id) => state.events.find((event) => event.id === id)).filter(Boolean);
  document.getElementById("incidentDetail").innerHTML = `
    <div class="detail-summary">
      <div class="incident-top">
        <h3>${escapeHtml(incident.title)}</h3>
        <span class="severity-pill ${incident.severity}">${incident.severity}</span>
      </div>
      <p>${escapeHtml(incident.summary)}</p>
      <div class="detail-meta">
        <span class="status-pill ${statusClass(incident.status)}">${escapeHtml(incident.status)}</span>
        <span class="tag">${escapeHtml(incident.owner)}</span>
        <span class="tag">${escapeHtml(incident.technique)}</span>
      </div>
    </div>
    <div>
      <h3>Response actions</h3>
      <div class="action-grid">
        ${["New", "In Progress", "Contained", "Closed"].map((status) => `<button class="control-button compact" type="button" data-status="${status}">${status}</button>`).join("")}
      </div>
    </div>
    <div>
      <h3>Runbook</h3>
      <div class="timeline">
        ${(rule?.runbook || []).map((step, index) => `<div class="timeline-item"><strong>Step ${index + 1}</strong><span>${escapeHtml(step)}</span></div>`).join("")}
      </div>
    </div>
    <div>
      <h3>Evidence timeline</h3>
      <div class="timeline">
        ${evidence.map((event) => `<button class="event-row-button timeline-item" type="button" data-detail-event="${escapeAttr(event.id)}"><strong>${formatTime(event.timestamp)} ${event.source}</strong><span>${escapeHtml(event.message)}</span></button>`).join("")}
      </div>
    </div>
  `;

  document.querySelectorAll("[data-status]").forEach((button) => {
    button.addEventListener("click", () => updateIncidentStatus(incident.id, button.dataset.status));
  });
  document.querySelectorAll("[data-detail-event]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedEventId = button.dataset.detailEvent;
      renderRawRecord();
      switchView("hunt");
    });
  });
}

function updateIncidentStatus(id, status) {
  state.incidents = state.incidents.map((incident) => {
    if (incident.id !== id) return incident;
    return {
      ...incident,
      status,
      owner: incident.owner === "Unassigned" && status !== "New" ? "SOC analyst" : incident.owner,
      updatedAt: new Date().toISOString(),
      notes: [
        { at: new Date().toISOString(), by: "SOC", text: `Status changed to ${status}.` },
        ...incident.notes
      ]
    };
  });
  saveState();
  renderMetrics();
  renderIncidents();
  showToast(`Incident ${id} moved to ${status}.`);
}

function renderRules() {
  document.getElementById("rulesList").innerHTML = state.rules.map((rule) => {
    const count = state.events.filter((event) => eventMatchesRule(rule, event)).length;
    return `
      <article class="rule-row ${rule.enabled ? "" : "disabled"}">
        <div class="rule-top">
          <strong>${escapeHtml(rule.name)}</strong>
          <div class="rule-actions">
            <span class="severity-pill ${rule.severity}">${rule.severity}</span>
            <button class="switch-button ${rule.enabled ? "on" : ""}" type="button" data-rule-id="${escapeAttr(rule.id)}">${rule.enabled ? "On" : "Off"}</button>
          </div>
        </div>
        <p class="muted-copy">${escapeHtml(rule.description)}</p>
        <div class="rule-meta">
          <span class="tag">${escapeHtml(rule.id)}</span>
          <span class="tag">${escapeHtml(rule.tactic)}</span>
          <span class="tag">${escapeHtml(rule.technique)}</span>
          <span class="tag">${count} matches</span>
        </div>
      </article>
    `;
  }).join("");

  document.querySelectorAll("[data-rule-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.rules = state.rules.map((rule) => rule.id === button.dataset.ruleId ? { ...rule, enabled: !rule.enabled } : rule);
      saveState();
      renderRules();
    });
  });
}

function renderMitreGrid() {
  const max = Math.max(1, ...tactics.map((tactic) => state.events.filter((event) => event.tactic === tactic).length));
  document.getElementById("mitreGrid").innerHTML = tactics.map((tactic) => {
    const events = state.events.filter((event) => event.tactic === tactic);
    const techniques = [...new Set(events.map((event) => event.technique))].slice(0, 3);
    const width = Math.max(5, Math.round((events.length / max) * 100));
    return `
      <article class="mitre-cell">
        <strong>${escapeHtml(tactic)}</strong>
        <small>${events.length} events</small>
        <div class="heat-bar"><span style="width:${width}%"></span></div>
        <p class="muted-copy">${techniques.map(escapeHtml).join(", ") || "No recent coverage"}</p>
      </article>
    `;
  }).join("");
}

function renderAssets() {
  const incidentsByAsset = state.incidents.reduce((acc, incident) => {
    acc[incident.asset] = (acc[incident.asset] || 0) + (incident.status === "Closed" ? 0 : 1);
    return acc;
  }, {});
  document.getElementById("assetRegister").innerHTML = [...state.assets].sort((a, b) => b.risk - a.risk).map((asset) => {
    const riskClass = asset.risk >= 85 ? "risk-critical" : asset.risk >= 70 ? "risk-high" : asset.risk >= 50 ? "risk-medium" : "risk-low";
    return `
      <article class="asset-row">
        <div class="asset-top">
          <strong>${escapeHtml(asset.name)}</strong>
          <span class="${riskClass}">${asset.risk} risk</span>
        </div>
        <small>${escapeHtml(asset.type)} owned by ${escapeHtml(asset.owner)}</small>
        <div class="asset-meta">
          <span class="tag">criticality ${asset.criticality}</span>
          <span class="tag">${incidentsByAsset[asset.name] || incidentsByAsset[asset.id] || 0} open cases</span>
          <span class="tag">${asset.vulnerabilities} vulns</span>
          <span class="tag">seen ${asset.lastSeenMins}m ago</span>
        </div>
      </article>
    `;
  }).join("");
}

function renderSources() {
  document.getElementById("sourceStatus").innerHTML = state.sources.map((source) => `
    <article class="source-item">
      <div class="source-top">
        <strong>${escapeHtml(source.name)}</strong>
        <span class="status-pill ${source.status === "healthy" ? "closed" : source.status === "delayed" ? "new" : "contained"}">${escapeHtml(source.status)}</span>
      </div>
      <small>${escapeHtml(source.type)} source, ${source.eps} events/sec, ${source.health}% parser success</small>
      <div class="bar-meter"><span style="width:${source.health}%; background:${healthColor(source.health)}"></span></div>
    </article>
  `).join("");
}

function renderHunts() {
  const hunts = [
    { name: "Authentication surge by user", query: "type:auth severity:high", copy: "Start with high-risk sign-in events and pivot by user, source IP, and ASN." },
    { name: "Endpoint defense evasion", query: "tactic:\"Defense Evasion\" source:EDR", copy: "Review process injection, obfuscation, and unsigned execution from EDR telemetry." },
    { name: "Cloud discovery spike", query: "source:CloudTrail tactic:Discovery", copy: "Find IAM and cloud asset enumeration from service accounts or unusual identities." },
    { name: "External beaconing", query: "technique:T1071", copy: "Filter periodic application-layer traffic and correlate with endpoint context." }
  ];
  document.getElementById("huntLibrary").innerHTML = hunts.map((hunt) => `
    <article class="hunt-card">
      <strong>${escapeHtml(hunt.name)}</strong>
      <p class="muted-copy">${escapeHtml(hunt.copy)}</p>
      <button class="control-button compact" type="button" data-hunt-query="${escapeAttr(hunt.query)}">Run hunt</button>
    </article>
  `).join("");

  document.querySelectorAll("[data-hunt-query]").forEach((button) => {
    button.addEventListener("click", () => {
      filters.query = button.dataset.huntQuery;
      document.getElementById("globalSearch").value = filters.query;
      switchView("dashboard");
      renderEventsAndCharts();
    });
  });
}

function renderRawRecord() {
  const event = state.events.find((item) => item.id === selectedEventId) || state.events[0];
  if (!event) return;
  selectedEventId = event.id;
  document.getElementById("rawRecord").textContent = JSON.stringify(event, null, 2);
}

function getFilteredEvents() {
  const cutoff = cutoffForFilter(filters.time);
  return state.events.filter((event) => {
    if (cutoff && new Date(event.timestamp).getTime() < cutoff) return false;
    if (filters.severity !== "all" && event.severity !== filters.severity) return false;
    if (filters.source !== "all" && event.source !== filters.source) return false;
    if (filters.query && !matchesQuery(event, filters.query)) return false;
    return true;
  }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function cutoffForFilter(value) {
  if (value === "all") return null;
  if (value === "1h") return Date.now() - 60 * 60000;
  if (value === "6h") return Date.now() - 6 * 60 * 60000;
  if (value === "24h") return Date.now() - 24 * 60 * 60000;
  return null;
}

function matchesQuery(event, query) {
  const terms = tokenize(query);
  const haystack = Object.values(event).join(" ").toLowerCase();
  return terms.every((term) => {
    const [field, ...rest] = term.split(":");
    if (rest.length) {
      const expected = rest.join(":").replace(/^"|"$/g, "").toLowerCase();
      const fieldMap = {
        ip: `${event.srcIp} ${event.destIp}`,
        severity: event.severity,
        source: event.source,
        asset: event.asset,
        user: event.user,
        type: event.type,
        tactic: event.tactic,
        technique: event.technique,
        rule: event.ruleId || ""
      };
      return String(fieldMap[field.toLowerCase()] || "").toLowerCase().includes(expected);
    }
    return haystack.includes(term.toLowerCase().replace(/^"|"$/g, ""));
  });
}

function tokenize(query) {
  return query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
}

function startLiveIngest() {
  stopLiveIngest();
  state.live = true;
  document.getElementById("liveToggle").textContent = "Live ingest on";
  document.getElementById("liveToggle").setAttribute("aria-pressed", "true");
  liveTimer = setInterval(() => {
    const event = randomEvent(Math.floor(Math.random() * 5));
    event.timestamp = new Date().toISOString();
    state.events = [event, ...state.events].slice(0, 1000);
    if (Math.random() < 0.28) runCorrelation(false);
    saveState();
    renderAll();
  }, 6500);
}

function stopLiveIngest() {
  if (liveTimer) window.clearInterval(liveTimer);
  liveTimer = null;
}

function toggleLiveIngest() {
  if (liveTimer) {
    stopLiveIngest();
    state.live = false;
    saveState();
    document.getElementById("liveToggle").textContent = "Live ingest paused";
    document.getElementById("liveToggle").setAttribute("aria-pressed", "false");
    showToast("Live ingest paused.");
  } else {
    startLiveIngest();
    showToast("Live ingest resumed.");
  }
}

function runCorrelation(showRender = true) {
  const activeRules = state.rules.filter((rule) => rule.enabled);
  const recentEvents = state.events.filter((event) => new Date(event.timestamp).getTime() >= Date.now() - 6 * 60 * 60000);
  let updated = 0;

  activeRules.forEach((rule) => {
    const matches = recentEvents.filter((event) => eventMatchesRule(rule, event)).slice(0, 8);
    if (!matches.length) return;
    const primary = matches[0];
    const title = `${rule.name} on ${primary.asset}`;
    const existing = state.incidents.find((incident) => incident.ruleId === rule.id && incident.asset === primary.asset && incident.status !== "Closed");
    if (existing) {
      existing.updatedAt = new Date().toISOString();
      existing.evidenceIds = [...new Set([...matches.map((event) => event.id), ...existing.evidenceIds])].slice(0, 12);
      existing.severity = higherSeverity(existing.severity, rule.severity);
      updated += 1;
    } else {
      state.incidents.unshift({
        id: nextIncidentId(),
        title,
        severity: rule.severity,
        status: "New",
        owner: "Unassigned",
        asset: primary.asset,
        entity: primary.user,
        ruleId: rule.id,
        tactic: rule.tactic,
        technique: rule.technique,
        summary: rule.description,
        createdAt: primary.timestamp,
        updatedAt: new Date().toISOString(),
        evidenceIds: matches.map((event) => event.id),
        notes: [{ at: new Date().toISOString(), by: "Correlation engine", text: `${matches.length} matching events grouped into a new incident.` }]
      });
      updated += 1;
    }
  });

  saveState();
  if (showRender) renderAll();
  return updated;
}

function eventMatchesRule(rule, event) {
  const message = event.message.toLowerCase();
  if (event.ruleId === rule.id) return true;
  if (rule.id === "SG-R-100") return event.source.includes("Okta") && (message.includes("impossible") || event.severity === "high");
  if (rule.id === "SG-R-120") return event.type === "auth" && (message.includes("mfa") || message.includes("failed") || event.severity === "critical");
  if (rule.id === "SG-R-210") return event.source.includes("EDR") && (message.includes("injection") || event.technique.includes("T1055") || event.severity === "critical");
  if (rule.id === "SG-R-330") return event.source.includes("CloudTrail") && (message.includes("iam") || message.includes("key") || event.tactic === "Discovery");
  if (rule.id === "SG-R-410") return ["network", "dns"].includes(event.type) && (message.includes("beacon") || event.technique.includes("T1071"));
  if (rule.id === "SG-R-520") return event.source.includes("Windows") && (message.includes("group") || event.technique.includes("T1069"));
  return false;
}

function higherSeverity(a, b) {
  return SEVERITY_WEIGHT[a] >= SEVERITY_WEIGHT[b] ? a : b;
}

function nextIncidentId() {
  const max = state.incidents.reduce((highest, incident) => {
    const num = Number(String(incident.id).replace(/\D/g, ""));
    return Math.max(highest, num);
  }, 1000);
  return `INC-${max + 1}`;
}

async function handleFileImport(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  document.getElementById("importText").value = text;
  importEventsFromText();
  event.target.value = "";
}

function importEventsFromText() {
  const text = document.getElementById("importText").value.trim();
  if (!text) {
    showToast("Paste or choose a log payload first.");
    return;
  }
  try {
    const records = parseImportPayload(text);
    const events = records.map((record) => makeEvent({ ...record, raw: record }));
    state.events = [...events, ...state.events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 1200);
    saveState();
    populateFilterOptions();
    renderAll();
    showToast(`${events.length} events normalized and ingested.`);
  } catch (error) {
    showToast(`Import failed: ${error.message}`);
  }
}

function parseImportPayload(text) {
  if (text.startsWith("[") || text.startsWith("{")) {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (Array.isArray(parsed.events)) return parsed.events;
    return [parsed];
  }
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.every((line) => line.startsWith("{"))) {
    return lines.map((line) => JSON.parse(line));
  }
  if (lines[0]?.includes(",")) {
    return parseCsv(lines);
  }
  return lines.map((line) => ({
    timestamp: new Date().toISOString(),
    source: line.includes("firewall") ? "FortiGate Edge" : "Imported logs",
    severity: line.match(/critical|high|medium|low|info/i)?.[0] || "info",
    asset: line.match(/asset=([^\s]+)/)?.[1] || "unknown-asset",
    user: line.match(/user=([^\s]+)/)?.[1] || "unknown",
    srcIp: line.match(/src=([^\s]+)/)?.[1] || randomIp(),
    destIp: line.match(/dst=([^\s]+)/)?.[1] || pick(destinations),
    message: line
  }));
}

function parseCsv(lines) {
  const headers = splitCsvLine(lines[0]).map((header) => header.trim());
  return lines.slice(1).map((line) => {
    const values = splitCsvLine(line);
    return headers.reduce((acc, header, index) => {
      acc[header] = values[index] || "";
      return acc;
    }, {});
  });
}

function splitCsvLine(line) {
  const values = [];
  let current = "";
  let quoted = false;
  for (const char of line) {
    if (char === "\"") {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values;
}

function loadSamplePayload() {
  document.getElementById("importText").value = JSON.stringify([
    {
      timestamp: new Date().toISOString(),
      source: "Okta SSO",
      severity: "critical",
      type: "auth",
      asset: "vpn-gateway-02",
      user: "jbell",
      srcIp: "203.0.113.50",
      destIp: "10.42.0.12",
      tactic: "Credential Access",
      technique: "T1110 Brute Force",
      message: "MFA fatigue pattern after 19 failed login attempts"
    },
    {
      timestamp: new Date(Date.now() - 120000).toISOString(),
      source: "AWS CloudTrail",
      severity: "high",
      type: "cloud_audit",
      asset: "aws-prod-iam",
      user: "svc-cloudsync",
      tactic: "Discovery",
      technique: "T1526 Cloud Service Discovery",
      message: "Access key enumeration from unusual role session"
    }
  ], null, 2);
}

function exportCaseData() {
  const payload = {
    exportedAt: new Date().toISOString(),
    metrics: {
      events: state.events.length,
      incidents: state.incidents.length,
      openIncidents: state.incidents.filter((incident) => incident.status !== "Closed").length
    },
    incidents: state.incidents,
    rules: state.rules,
    assets: state.assets,
    recentEvents: state.events.slice(0, 250)
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinelgrid-export-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("Case data export prepared.");
}

function resetData() {
  stopLiveIngest();
  localStorage.removeItem(STORAGE_KEY);
  state = seedState();
  selectedIncidentId = state.incidents[0]?.id || null;
  selectedEventId = state.events[0]?.id || null;
  saveState();
  renderAll();
  startLiveIngest();
  showToast("Dashboard reset to the seeded SOC dataset.");
}

function clearFilters() {
  filters = { query: "", severity: "all", source: "all", time: "6h", incident: filters.incident };
  document.getElementById("globalSearch").value = "";
  document.getElementById("severityFilter").value = "all";
  document.getElementById("sourceFilter").value = "all";
  document.getElementById("timeFilter").value = "6h";
  renderEventsAndCharts();
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("show"), 3200);
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function pick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

function randomIp() {
  return `${pick([10, 172, 192, 198, 203])}.${Math.floor(Math.random() * 220) + 10}.${Math.floor(Math.random() * 220) + 10}.${Math.floor(Math.random() * 220) + 10}`;
}

function healthColor(value) {
  if (value >= 90) return "var(--green)";
  if (value >= 80) return "var(--yellow)";
  return "var(--orange)";
}

function statusClass(status) {
  return status.toLowerCase().replace(/\s+/g, "-");
}

function formatTime(value) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function formatShortTime(value) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function relativeTime(value) {
  const mins = Math.max(1, Math.round((Date.now() - new Date(value).getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  return `${Math.round(mins / 60)}h ago`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#096;");
}
