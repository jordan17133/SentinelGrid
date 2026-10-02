// SentinelGrid console: renders data/snapshot.json, a scrubbed export of the
// SentinelGrid SQL warehouse. Read-only by design; nothing here talks to the SIEM.

const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SEV_COLOR = { critical: "#ff5d5d", high: "#f59b4c", medium: "#e8c24a", low: "#6e7681" };
const TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
  "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const TZ = "America/New_York";

const fmtTime = new Intl.DateTimeFormat("en-US", { timeZone: TZ, month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
const fmtHour = new Intl.DateTimeFormat("en-US", { timeZone: TZ, month: "short", day: "numeric", hour: "numeric" });
const fmtNum = new Intl.NumberFormat("en-US");

let data = null;
let techniqueNames = {};
let selectedAlert = null;
let selectedCase = null;

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sevOf = (level) => (level >= 15 ? "critical" : level >= 12 ? "high" : level >= 7 ? "medium" : "low");
const sevTag = (level) => `<span class="sev ${sevOf(level)}">${SEV_LABEL[sevOf(level)]} ${level}</span>`;
const time = (iso) => (iso ? fmtTime.format(new Date(iso)) : "-");

function verdictPill(verdict) {
  if (!verdict) return '<span class="pill">Not triaged</span>';
  const cls = verdict.startsWith("True positive") ? "tp" : verdict.startsWith("Benign") ? "benign" : "";
  return `<span class="pill ${cls}">${esc(verdict.split(":")[0])}</span>`;
}

fetch("data/snapshot.json", { cache: "no-cache" })
  .then((r) => r.json())
  .then((json) => {
    data = json;
    data.attack.forEach((t) => { techniqueNames[t.id] = t.name; });
    $("snapshotTime").textContent = `exported ${time(data.generated_utc)} US Eastern`;
    renderOverview();
    renderAlerts();
    renderCases();
    renderAttack();
    renderPipeline();
    bindControls();
    route();
  })
  .catch(() => {
    $("notice").textContent = "The data snapshot could not be loaded.";
  });

window.addEventListener("hashchange", route);

function route() {
  const view = (location.hash || "#overview").slice(1).split("/")[0];
  const known = ["overview", "alerts", "cases", "attack", "pipeline"].includes(view) ? view : "overview";
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${known}`));
  document.querySelectorAll(".tabs a").forEach((a) => a.classList.toggle("active", a.dataset.view === known));
}

function kpi(label, value, sub, accent) {
  return `<div class="kpi"><div class="label">${esc(label)}</div><div class="value${accent ? " accent" : ""}">${value}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;
}

/* ---------- Overview ---------- */

function renderOverview() {
  const k = data.kpi;
  $("kpis").innerHTML = [
    kpi("Alerts collected", fmtNum.format(k.alerts_total), "loaded into SQL every 15 minutes"),
    kpi("ATT&CK techniques fired", k.techniques_fired, "every one triaged to a verdict", true),
    kpi("Cases", k.cases_open + k.cases_closed, `${k.cases_closed} closed, ${k.cases_open} open`),
    kpi("Median time to verdict", `${k.median_hours_to_verdict.toFixed(1)} h`, "first alert to closed case"),
    kpi("Vulnerability findings", `${k.vulns_all} → ${k.vulns_open}`, `${k.vulns_critical_open} Critical open`, true),
    kpi("CIS benchmark", `${k.cis_first.toFixed(1)}% → ${k.cis_now.toFixed(1)}%`, "Windows 11 Enterprise v3.0.0"),
  ].join("");

  $("hourLegend").innerHTML = SEV_ORDER.map((s) => `<span><i style="background:${SEV_COLOR[s]}"></i>${SEV_LABEL[s]}</span>`).join("");
  renderHourChart();

  const maxRule = Math.max(...data.rules.map((r) => r.total));
  $("topRules").innerHTML = data.rules.slice(0, 8).map((r) => `
    <div class="bar-row">
      <div>
        <div>${sevTag(r.level)} <span class="muted">${r.rule_id}</span> ${esc(r.rule)}</div>
        <div class="verdict">${r.verdict ? esc(r.verdict) : "Not triaged"}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(100 * r.total / maxRule).toFixed(1)}%"></div></div>
      </div>
      <div class="num">${fmtNum.format(r.total)}</div>
    </div>`).join("");

  const high = data.alerts.filter((a) => a.level >= 12).slice(0, 8);
  $("recentHigh").innerHTML = high.length ? `<table class="table"><tbody>${high.map((a) => `
    <tr data-alert="${esc(a.id)}"><td class="nowrap">${time(a.ts)}</td><td>${sevTag(a.level)}</td><td>${esc(a.rule)}<div class="verdict">${a.verdict ? esc(a.verdict) : ""}</div></td></tr>`).join("")}</tbody></table>`
    : '<p class="muted">No Critical or High alerts in the snapshot.</p>';
  $("recentHigh").querySelectorAll("tr").forEach((tr) => tr.addEventListener("click", () => {
    location.hash = "#alerts";
    selectAlert(tr.dataset.alert);
  }));
}

function renderHourChart() {
  const rows = data.hourly;
  const W = 1000, H = 220, padL = 40, padB = 26, padT = 8;
  const totals = rows.map((r) => SEV_ORDER.reduce((s, k) => s + r[k], 0));
  const max = Math.max(...totals, 1);
  const step = (W - padL) / rows.length;
  const bw = Math.max(2, step - 2);
  const y = (v) => padT + (H - padT - padB) * (1 - v / max);
  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Alerts per hour by severity">`;
  [0, 0.5, 1].forEach((f) => {
    const v = Math.round(max * f);
    svg += `<line x1="${padL}" x2="${W}" y1="${y(v)}" y2="${y(v)}" stroke="#2a3340" stroke-width="1"/>`;
    svg += `<text x="${padL - 6}" y="${y(v) + 4}" fill="#7d8590" font-size="11" text-anchor="end">${fmtNum.format(v)}</text>`;
  });
  rows.forEach((r, i) => {
    const x = padL + i * step + 1;
    let base = 0;
    ["low", "medium", "high", "critical"].forEach((s) => {
      if (!r[s]) return;
      const top = y(base + r[s]);
      svg += `<rect x="${x}" y="${top}" width="${bw}" height="${Math.max(1, y(base) - top)}" fill="${SEV_COLOR[s]}" rx="1"/>`;
      base += r[s];
    });
    svg += `<rect class="hit" data-i="${i}" x="${padL + i * step}" y="${padT}" width="${step}" height="${H - padT - padB}" fill="transparent"/>`;
    if (i % 6 === 0) svg += `<text x="${x}" y="${H - 8}" fill="#7d8590" font-size="11">${esc(fmtHour.format(new Date(r.hour)))}</text>`;
  });
  svg += "</svg>";
  $("hourChart").innerHTML = svg;
  const tip = $("tooltip");
  $("hourChart").querySelectorAll(".hit").forEach((el) => {
    el.addEventListener("mousemove", (e) => {
      const r = rows[+el.dataset.i];
      tip.innerHTML = `<b>${esc(fmtHour.format(new Date(r.hour)))}</b>` +
        SEV_ORDER.map((s) => `<div><span style="color:${SEV_COLOR[s]}">●</span> ${SEV_LABEL[s]}: ${fmtNum.format(r[s])}</div>`).join("");
      tip.hidden = false;
      tip.style.left = `${Math.min(e.clientX + 14, window.innerWidth - 170)}px`;
      tip.style.top = `${e.clientY + 14}px`;
    });
    el.addEventListener("mouseleave", () => { tip.hidden = true; });
  });
}

/* ---------- Alerts ---------- */

function bindControls() {
  $("alertSearch").addEventListener("input", renderAlerts);
  $("alertSeverity").addEventListener("change", renderAlerts);
}

function renderAlerts() {
  const q = $("alertSearch").value.trim().toLowerCase();
  const sev = $("alertSeverity").value;
  const rows = data.alerts.filter((a) => {
    if (sev !== "all" && sevOf(a.level) !== sev) return false;
    if (!q) return true;
    const hay = [a.rule, a.rule_id, a.process, a.agent, a.channel, ...a.techniques, ...a.techniques.map((t) => techniqueNames[t])].join(" ").toLowerCase();
    return hay.includes(q);
  });
  $("alertCount").textContent = `${fmtNum.format(rows.length)} of ${fmtNum.format(data.alerts.length)} alerts in this snapshot`;
  $("alertTable").innerHTML = `<thead><tr><th>Time (ET)</th><th>Severity</th><th>Rule</th><th>Endpoint</th><th>ATT&amp;CK</th></tr></thead><tbody>${
    rows.slice(0, 400).map((a) => `<tr data-alert="${esc(a.id)}" class="${a.id === selectedAlert ? "selected" : ""}">
      <td class="nowrap">${time(a.ts)}</td><td>${sevTag(a.level)}</td>
      <td><span class="muted">${a.rule_id}</span> ${esc(a.rule)}</td>
      <td>${esc(a.agent)}</td><td class="nowrap">${esc(a.techniques.join(", "))}</td></tr>`).join("")}</tbody>`;
  $("alertTable").querySelectorAll("tbody tr").forEach((tr) => tr.addEventListener("click", () => selectAlert(tr.dataset.alert)));
}

function selectAlert(id) {
  selectedAlert = id;
  const a = data.alerts.find((x) => x.id === id);
  if (!a) return;
  document.querySelectorAll("#alertTable tbody tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.alert === id));
  const techs = a.techniques.length ? a.techniques.map((t) => `${esc(t)} ${esc(techniqueNames[t] || "")}`).join("<br>") : "Not mapped";
  $("alertDetail").innerHTML = `
    <h3>${esc(a.rule)}</h3>
    ${sevTag(a.level)} ${verdictPill(a.verdict)}
    <dl>
      <dt>Time</dt><dd>${time(a.ts)} ET</dd>
      <dt>Wazuh rule</dt><dd>${a.rule_id} (level ${a.level})</dd>
      <dt>Endpoint</dt><dd>${esc(a.agent)}</dd>
      <dt>Log source</dt><dd>${esc(a.channel || "Wazuh / syslog")}</dd>
      <dt>Process</dt><dd>${esc(a.process || "-")}</dd>
      <dt>ATT&amp;CK</dt><dd>${techs}</dd>
      <dt>Triage</dt><dd>${a.verdict ? esc(a.verdict) : "This rule has not been triaged."}</dd>
      <dt>Document ID</dt><dd><code>${esc(a.id)}</code></dd>
    </dl>
    <p class="muted">Every alert keeps its Wazuh document ID, so it can be traced back to the original event in the SIEM.</p>`;
}

/* ---------- Cases ---------- */

function renderCases() {
  if (!selectedCase) selectedCase = (data.cases.find((c) => c.status !== "Closed") || data.cases[0])?.number;
  $("caseList").innerHTML = data.cases.map((c) => `
    <div class="case-item ${c.number === selectedCase ? "selected" : ""}" data-case="${esc(c.number)}">
      <div class="row"><span class="case-num">${esc(c.number)}</span>${sevTag({ Critical: 15, High: 12, Medium: 7, Low: 3 }[c.severity]).replace(/ \d+</, "<")}
        <span class="pill ${c.status === "Closed" ? "" : "open"}">${esc(c.status)}</span>${c.status === "Closed" ? verdictPill(c.verdict) : ""}</div>
      <div class="title">${esc(c.title)}</div>
      <div class="muted">${c.hours_to_verdict != null ? `${c.hours_to_verdict.toFixed(1)} h to verdict` : `open ${c.open_age_hours.toFixed(1)} h`} · ${fmtNum.format(c.alerts)} alerts · rules ${esc(c.rules)}</div>
    </div>`).join("");
  $("caseList").querySelectorAll(".case-item").forEach((el) => el.addEventListener("click", () => {
    selectedCase = el.dataset.case;
    renderCases();
  }));
  const c = data.cases.find((x) => x.number === selectedCase);
  if (!c) return;
  $("caseDetail").innerHTML = `
    <div class="case-num">${esc(c.number)}</div>
    <h3>${esc(c.title)}</h3>
    <span class="pill ${c.status === "Closed" ? "" : "open"}">${esc(c.status)}</span> ${c.status === "Closed" ? verdictPill(c.verdict) : '<span class="pill">Pending</span>'}
    <dl>
      <dt>Severity</dt><dd>${esc(c.severity)}</dd>
      <dt>Owner</dt><dd>${esc(c.owner || "Unassigned")}</dd>
      <dt>First alert</dt><dd>${time(c.first_alert)} ET</dd>
      <dt>Time to verdict</dt><dd>${c.hours_to_verdict != null ? `${c.hours_to_verdict.toFixed(1)} hours` : `still open (${c.open_age_hours.toFixed(1)} hours)`}</dd>
      <dt>Rules</dt><dd>${esc(c.rules)}</dd>
      <dt>Alerts in case</dt><dd>${fmtNum.format(c.alerts)}</dd>
      <dt>Summary</dt><dd>${esc(c.summary)}</dd>
    </dl>
    ${c.report ? `<p><a href="${esc(c.report)}" target="_blank" rel="noopener">Read the full investigation report</a></p>` : ""}
    <h2>Case history</h2>
    <ul class="timeline">${c.history.map((h) => `<li><div class="when">${time(h.ts)} · ${esc(h.actor)}</div><strong>${esc(h.action)}</strong> ${esc(h.detail || "")}</li>`).join("")}</ul>`;
}

/* ---------- ATT&CK ---------- */

function renderAttack() {
  const k = data.kpi;
  $("attackLead").innerHTML = `${k.techniques_fired} techniques fired on this lab, grouped by tactic. ${k.techniques_ready} of ${k.techniques_catalog} Windows and Linux techniques have a deployed rule whose data source is collected here. ` +
    `A technique firing is not the same as an attack: each card shows the verdict for the rule behind most of its alerts. <span style="color:var(--critical)">Red</span> marks a true positive from a controlled test; <span style="color:var(--good)">green</span> is benign with a named source.`;
  $("matrix").innerHTML = TACTICS.map((tactic) => {
    const techs = data.attack.filter((t) => (t.tactics || "").split(", ").includes(tactic));
    if (!techs.length) return "";
    return `<div class="tactic"><h2><span>${esc(tactic)}</span><span class="muted">${techs.length}</span></h2>${techs.map((t) => {
      const cls = (t.verdict || "").startsWith("True positive") ? "tp" : (t.verdict || "").startsWith("Benign") ? "benign" : "";
      return `<div class="tech ${cls}" title="${esc(t.verdict)}"><div class="id">${esc(t.id)}</div><div class="name">${esc(t.name)}</div>
        <div class="meta">${fmtNum.format(t.alerts)} alerts · top rule ${t.top_rule_id}</div></div>`;
    }).join("")}</div>`;
  }).join("");
}

/* ---------- Pipeline ---------- */

function renderPipeline() {
  const p = data.pipeline;
  $("pipeKpis").innerHTML = [
    kpi("Loader success, 7 days", `${p.success_rate_7d_pct.toFixed(1)}%`, `${p.runs_24h} runs in the last 24 hours`, true),
    kpi("Alert to SQL, median", `${p.latency_p50_minutes.toFixed(1)} min`, "scheduled every 15 minutes"),
    kpi("Alert to SQL, 95th percentile", `${p.latency_p95_minutes.toFixed(1)} min`),
    kpi("Alerts loaded, 24 hours", fmtNum.format(p.alerts_loaded_24h)),
    kpi("Warehouse size", `${fmtNum.format(Math.round(p.data_used_mb))} MB`, "capped at 100 GB"),
  ].join("");
  $("endpoints").innerHTML = `<table class="table"><thead><tr><th>Endpoint</th><th class="num">Minutes since last alert</th><th class="num">Alerts, 24 hours</th></tr></thead><tbody>${
    data.endpoints.map((e) => `<tr><td>${esc(e.name)}</td><td class="num">${fmtNum.format(e.minutes_since_last_alert)}</td><td class="num">${fmtNum.format(e.alerts_24h)}</td></tr>`).join("")}</tbody></table>
    <p class="muted">Figures are as of the snapshot time, not live.</p>`;
}
