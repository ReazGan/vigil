"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

let token = sessionStorage.getItem("vigil_token") || "";
let timer = null;
let view = "dashboard";
let rangeSeconds = 300;
let latest = { stats: null, events: [], buckets: [] };
let rules = null;
let config = null;

const CAT_COLORS = [
  "#e9655f", "#ec8f4b", "#e0ab54", "#cf8140",
  "#9aa86a", "#72b487", "#c07a5c", "#8b94a6",
];
const SEV_COLORS = { Critical: "#e9655f", High: "#ec8f4b", Medium: "#e0ab54", Low: "#72b487" };
const SEV_ORDER = ["Critical", "High", "Medium", "Low"];
const TITLES = {
  dashboard: "Dashboard", alerts: "Alerts", traffic: "Traffic Monitor", analysis: "Analysis",
  reports: "Reports", rules: "Rules", system: "System", settings: "Settings",
};

// ---- helpers --------------------------------------------------------
function humanBytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n || 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
}
function humanDur(s) {
  s = Math.floor(s || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function fmtTime(ts) {
  try { return new Date(ts * 1000).toLocaleTimeString(); } catch (e) { return "-"; }
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function countBy(items, key) {
  const m = {};
  for (const it of items) { const k = it[key]; m[k] = (m[k] || 0) + 1; }
  return m;
}

// ---- auth -----------------------------------------------------------
async function login(username, password) {
  const res = await fetch("api/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("bad credentials");
  token = (await res.json()).token;
  sessionStorage.setItem("vigil_token", token);
}
async function api(path) {
  const res = await fetch(path, { headers: { Authorization: "Bearer " + token } });
  if (res.status === 401) { logout(); throw new Error("unauthorized"); }
  return res.json();
}
function logout() {
  token = "";
  sessionStorage.removeItem("vigil_token");
  if (timer) { clearInterval(timer); timer = null; }
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
}

// ---- range filtering ------------------------------------------------
function eventsInRange() {
  if (!rangeSeconds) return latest.events;
  const now = Date.now() / 1000;
  return latest.events.filter(e => e.seen && (now - e.seen) <= rangeSeconds);
}
function bucketsInRange() {
  const b = latest.buckets || [];
  if (!rangeSeconds) return b;
  const now = Date.now() / 1000;
  return b.filter(x => (now - x.t) <= rangeSeconds);
}

// ---- chart builders -------------------------------------------------
function buildLine(buckets, height) {
  const W = 600, H = height, pad = 8;
  if (!buckets || buckets.length < 2) return '<div class="empty">waiting for traffic...</div>';
  const plotW = W - pad * 2, plotH = H - pad * 2;
  let max = 1;
  for (const b of buckets) max = Math.max(max, b.packets, b.detections);
  const x = i => pad + (i / (buckets.length - 1)) * plotW;
  const y = v => pad + plotH - (v / max) * plotH;
  const poly = key => buckets.map((b, i) => `${x(i).toFixed(1)},${y(b[key]).toFixed(1)}`).join(" ");
  const area = buckets.map((b, i) => `${x(i).toFixed(1)},${y(b.packets).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="traffic">
    <line x1="${pad}" y1="${pad + plotH / 2}" x2="${W - pad}" y2="${pad + plotH / 2}" stroke="#32343e" stroke-width="1"/>
    <polyline points="${x(0).toFixed(1)},${(H - pad).toFixed(1)} ${area} ${x(buckets.length - 1).toFixed(1)},${(H - pad).toFixed(1)}" fill="rgba(224,171,84,0.12)" stroke="none"/>
    <polyline points="${poly("packets")}" fill="none" stroke="#e0ab54" stroke-width="2" stroke-linejoin="round"/>
    <polyline points="${poly("detections")}" fill="none" stroke="#e9655f" stroke-width="2" stroke-linejoin="round"/>
  </svg>`;
}

function buildDonut(byCategory) {
  const entries = Object.entries(byCategory || {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, e) => s + e[1], 0);
  if (!total) return '<div class="empty">no attacks detected in range</div>';
  const r = 52, cx = 66, cy = 66, sw = 20, C = 2 * Math.PI * r;
  let offset = 0;
  const arcs = entries.map(([n, count], i) => {
    const len = (count / total) * C, color = CAT_COLORS[i % CAT_COLORS.length];
    const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="${sw}" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
    offset += len;
    return seg;
  }).join("");
  const legend = entries.map(([n, count], i) => {
    const pct = Math.round((count / total) * 100);
    return `<li><span class="swatch" style="background:${CAT_COLORS[i % CAT_COLORS.length]}"></span><span class="name">${esc(n)}</span><span class="num">${pct}% (${count})</span></li>`;
  }).join("");
  return `<svg width="132" height="132" viewBox="0 0 132 132">${arcs}
    <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="#e7e9ee" font-size="22" font-family="ui-monospace,monospace">${total}</text>
    <text x="${cx}" y="${cy + 15}" text-anchor="middle" fill="#949cad" font-size="10">events</text></svg>
    <ul class="donut-legend">${legend}</ul>`;
}

function buildBars(items, colorFn) {
  if (!items.length) return '<div class="empty">no data in range</div>';
  const max = Math.max(...items.map(i => i.value), 1);
  return items.map((it, i) => {
    const w = (it.value / max) * 100;
    const color = colorFn ? colorFn(i, it) : "var(--accent)";
    return `<div class="bar"><span class="blabel" title="${esc(it.label)}">${esc(it.label)}</span>
      <span class="btrack"><span class="bfill" style="width:${w.toFixed(1)}%;background:${color}"></span></span>
      <span class="bval">${it.value}</span></div>`;
  }).join("");
}

function evRows(events, withSummary) {
  if (!events.length) return `<tr><td colspan="${withSummary ? 6 : 5}" class="empty">no alerts in range</td></tr>`;
  return events.map(e => {
    const head = `<td class="mono">${fmtTime(e.seen || e.ts)}</td>`;
    const sev = `<td><span class="badge ${e.severity}">${e.severity}</span></td>`;
    if (withSummary) {
      return `<tr>${head}<td>${esc(e.category)}</td>${sev}<td class="mono">${esc(e.src_ip)}</td><td class="mono">${esc(e.dst_ip)}</td><td>${esc(e.summary)}</td></tr>`;
    }
    return `<tr>${head}<td>${esc(e.category)}</td><td class="mono">${esc(e.src_ip)}</td><td class="mono">${esc(e.dst_ip)}</td>${sev}</tr>`;
  }).join("");
}

function engineList(s) {
  const total = SEV_ORDER.reduce((n, k) => n + (s.by_severity[k] || 0), 0) || 1;
  const bar = SEV_ORDER.map(k => {
    const v = s.by_severity[k] || 0;
    return v ? `<span style="width:${(v / total) * 100}%;background:${SEV_COLORS[k]}" title="${k}: ${v}"></span>` : "";
  }).join("");
  const rows = [
    ["Throughput", `${s.pps} pkt/s`], ["Events", s.events_total],
    ["Persisted", (s.events_stored || 0).toLocaleString()],
    ["Raw detections", (s.raw_detections || 0).toLocaleString()],
    ["Flows", (s.flows || 0).toLocaleString()], ["Detectors", s.detectors],
    ["Uptime", humanDur(s.uptime_s)],
  ];
  return rows.map(([k, v]) => `<div class="erow"><span class="k">${k}</span><span class="v">${v}</span></div>`).join("") +
    `<div><div class="erow"><span class="k">Severity mix</span></div><div class="sevbar">${bar}</div></div>`;
}

function cardHtml(c) {
  return `<div class="card${c.flag ? " flag" : ""}"><div class="label">${c.label}</div><div class="value">${c.value}</div><div class="sub">${c.sub}</div></div>`;
}

// ---- view renderers -------------------------------------------------
function renderDashboard() {
  const s = latest.stats; if (!s) return;
  const ev = eventsInRange();
  $("#d-cards").innerHTML = [
    { label: "Events", value: s.events_total, sub: `${s.raw_detections} raw detections` },
    { label: "High / Critical", value: s.high_critical, sub: "need attention", flag: s.high_critical > 0 },
    { label: "Packets", value: (s.packets || 0).toLocaleString(), sub: `${s.pps}/s now` },
    { label: "Traffic", value: humanBytes(s.bytes), sub: `${s.flows} flows` },
    { label: "Active flows", value: s.active_flows, sub: `${s.detectors} detectors` },
  ].map(cardHtml).join("");
  $("#d-traffic").innerHTML = buildLine(bucketsInRange(), 180);
  $("#d-donut").innerHTML = buildDonut(countBy(ev, "category"));
  $("#d-events").innerHTML = evRows(ev.slice(0, 8), false);
  $("#d-engine").innerHTML = engineList(s);
}

function ensureCategoryOptions() {
  const sel = $("#a-cat");
  if (sel.dataset.filled || !rules) return;
  const cats = new Set();
  rules.detectors.forEach(d => { if (d.name !== "signature") cats.add(d.category); });
  rules.signatures.forEach(r => cats.add(r.category));
  [...cats].sort().forEach(c => {
    const o = document.createElement("option"); o.value = c; o.textContent = c; sel.appendChild(o);
  });
  sel.dataset.filled = "1";
}

function renderAlerts() {
  ensureCategoryOptions();
  const sev = $("#a-sev").value, cat = $("#a-cat").value;
  let ev = eventsInRange();
  if (sev) ev = ev.filter(e => e.severity === sev);
  if (cat) ev = ev.filter(e => e.category === cat);
  $("#a-table").innerHTML = evRows(ev.slice(0, 200), true);
  $("#a-count").textContent = `${ev.length} alert${ev.length === 1 ? "" : "s"}`;
}

function renderTraffic() {
  const s = latest.stats; if (!s) return;
  $("#t-cards").innerHTML = [
    { label: "Packets", value: (s.packets || 0).toLocaleString(), sub: `${s.pps}/s now` },
    { label: "Traffic", value: humanBytes(s.bytes), sub: "analyzed" },
    { label: "Flows", value: (s.flows || 0).toLocaleString(), sub: "total" },
    { label: "Active flows", value: s.active_flows, sub: "recent" },
    { label: "Throughput", value: `${s.pps}`, sub: "packets/s" },
  ].map(cardHtml).join("");
  $("#t-chart").innerHTML = buildLine(bucketsInRange(), 260);
  const proto = Object.entries(s.by_protocol || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v }));
  $("#t-proto").innerHTML = buildBars(proto);
}

function renderAnalysis() {
  const ev = eventsInRange();
  const toItems = m => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => ({ label: k, value: v }));
  $("#an-sources").innerHTML = buildBars(toItems(countBy(ev, "src_ip")), () => "var(--high)");
  $("#an-targets").innerHTML = buildBars(toItems(countBy(ev, "dst_ip")), () => "var(--accent)");
  $("#an-cats").innerHTML = buildBars(toItems(countBy(ev, "category")), i => CAT_COLORS[i % CAT_COLORS.length]);
}

function renderReports() {
  const s = latest.stats; if (!s) return;
  const ev = eventsInRange();
  const rangeLabel = $("#range").selectedOptions[0].textContent;
  $("#r-span").textContent = `${rangeLabel} - ${ev.length} events`;
  const byCat = countBy(ev, "category"), bySev = countBy(ev, "severity");
  const times = ev.map(e => e.seen).filter(Boolean);
  const span = times.length ? `${fmtTime(Math.min(...times))} - ${fmtTime(Math.max(...times))}` : "-";
  const kv = (k, v) => `<div class="kv"><span>${k}</span><span class="v">${v}</span></div>`;
  const list = m => Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, v]) => kv(k, v)).join("") || '<div class="muted-note">none</div>';
  $("#r-summary").innerHTML =
    `<h3>Overview</h3>${kv("Source", esc(s.source || "-"))}${kv("Uptime", humanDur(s.uptime_s))}${kv("Packets analyzed", (s.packets || 0).toLocaleString())}${kv("Traffic", humanBytes(s.bytes))}${kv("Events in range", ev.length)}${kv("Time span", span)}
     <h3>By category</h3>${list(byCat)}
     <h3>By severity</h3>${list(bySev)}`;
}

function renderRules() {
  if (!rules) return;
  $("#ru-detectors").innerHTML = rules.detectors.map(d =>
    `<tr><td>${esc(d.name)}</td><td>${esc(d.category)}</td><td class="mono">${esc(d.type)}</td></tr>`).join("");
  $("#ru-signatures").innerHTML = rules.signatures.map(r =>
    `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.category)}</td><td><span class="badge ${r.severity}">${r.severity}</span></td></tr>`).join("");
}

function renderSystem() {
  const s = latest.stats; if (!s) return;
  const cells = [
    ["Uptime", humanDur(s.uptime_s)], ["Throughput", `${s.pps} pkt/s`],
    ["Packets", (s.packets || 0).toLocaleString()], ["Traffic", humanBytes(s.bytes)],
    ["Flows", (s.flows || 0).toLocaleString()], ["Active flows", s.active_flows],
    ["Detectors", s.detectors], ["Events", s.events_total],
    ["Persisted", (s.events_stored || 0).toLocaleString()], ["Source", esc(s.source || "-")],
  ];
  $("#sy-grid").innerHTML = cells.map(([k, v]) => `<div class="cell"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("");
  const total = SEV_ORDER.reduce((n, k) => n + (s.by_severity[k] || 0), 0) || 1;
  $("#sy-sevbar").innerHTML = SEV_ORDER.map(k => {
    const v = s.by_severity[k] || 0;
    return v ? `<span style="width:${(v / total) * 100}%;background:${SEV_COLORS[k]}" title="${k}: ${v}"></span>` : "";
  }).join("");
}

function renderSettings() {
  if (!config) return;
  const cells = Object.entries(config).map(([k, v]) => {
    const val = Array.isArray(v) ? v.join(", ") : v;
    return `<div class="cell"><div class="k">${esc(k)}</div><div class="v">${esc(val)}</div></div>`;
  });
  $("#se-config").innerHTML = cells.join("");
}

const RENDERERS = {
  dashboard: renderDashboard, alerts: renderAlerts, traffic: renderTraffic, analysis: renderAnalysis,
  reports: renderReports, rules: renderRules, system: renderSystem, settings: renderSettings,
};

function render() {
  const fn = RENDERERS[view];
  if (fn) { try { fn(); } catch (e) { /* ignore transient */ } }
}

// ---- export ---------------------------------------------------------
function download(name, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function exportJson() {
  download("vigil-events.json", JSON.stringify(eventsInRange(), null, 2), "application/json");
}
function exportCsv() {
  const rows = [["time", "category", "severity", "src_ip", "dst_ip", "summary"]];
  for (const e of eventsInRange()) {
    rows.push([fmtTime(e.seen || e.ts), e.category, e.severity, e.src_ip, e.dst_ip, (e.summary || "").replace(/"/g, "'")]);
  }
  download("vigil-events.csv", rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n"), "text/csv");
}

// ---- poll -----------------------------------------------------------
async function tick() {
  try {
    const [stats, events, ts] = await Promise.all([
      api("api/stats"), api("api/events?limit=200"), api("api/timeseries"),
    ]);
    latest = { stats, events, buckets: ts.buckets || [] };
    $("#source").textContent = stats.source || "live";
    $("#uptime").textContent = humanDur(stats.uptime_s);
    render();
  } catch (e) { /* 401 handled; ignore transient */ }
}

// ---- view switching -------------------------------------------------
function setView(name) {
  view = name;
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach(v => v.classList.toggle("active", v.dataset.view === name));
  $("#view-title").textContent = TITLES[name] || name;
  render();
}

async function startApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  try { rules = await api("api/rules"); } catch (e) {}
  try { config = await api("api/config"); } catch (e) {}
  await tick();
  if (timer) clearInterval(timer);
  timer = setInterval(tick, 1500);
}

// ---- wire up --------------------------------------------------------
$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#login-error").textContent = "";
  try { await login($("#username").value.trim(), $("#password").value); startApp(); }
  catch (e) { $("#login-error").textContent = "Invalid username or password."; }
});
$("#logout").addEventListener("click", logout);
$$(".nav-item").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
$("#range").addEventListener("change", (e) => { rangeSeconds = parseInt(e.target.value, 10); render(); });
$("#a-sev").addEventListener("change", render);
$("#a-cat").addEventListener("change", render);
$("#r-json").addEventListener("click", exportJson);
$("#r-csv").addEventListener("click", exportCsv);

if (token) startApp();
