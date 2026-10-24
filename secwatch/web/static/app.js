/* secwatch web UI - vanilla JS, no build step. All text via i18n (t('key')). */
"use strict";

const S = { session: null, dict: {}, lang: "en", host: "", cfg: null, detect: null };
const SEVS = ["critical", "high", "medium", "low"];
const PHASE2 = ["lynis", "exposure", "secrets", "auth", "updates", "sbom"];

/* ------------------------------------------------------------------ helpers */
function t(key, vars) {
  let s = S.dict[key];
  if (s === undefined) s = key;
  if (vars) for (const k of Object.keys(vars)) s = s.split("{" + k + "}").join(String(vars[k]));
  return s;
}
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else if (k === "disabled") el.disabled = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const kid of kids) el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function fmtTime(s) {
  if (!s) return "–";
  const d = new Date(s);
  if (isNaN(d)) return s;
  return d.toLocaleString(S.lang, { dateStyle: "medium", timeStyle: "short" });
}
function ago(s) {
  if (!s) return "–";
  const sec = (Date.now() - new Date(s).getTime()) / 1000;
  if (isNaN(sec)) return s;
  if (sec < 3600) return t("time.minutes", { n: Math.max(1, Math.round(sec / 60)) });
  if (sec < 86400 * 2) return t("time.hours", { n: Math.round(sec / 3600) });
  return t("time.days", { n: Math.round(sec / 86400) });
}
function sevBadge(s) { return h("span", { class: "sev " + (s || "unknown") }, t("severity." + (s || "unknown"))); }
function toast(msg, err) {
  const el = h("div", { class: "toast" + (err ? " err" : "") }, msg);
  document.body.appendChild(el);
  setTimeout(() => el.remove(), err ? 7000 : 3500);
}
function getPath(obj, path) { return path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj); }
function setPath(obj, path, val) {
  const parts = path.split("."); let o = obj;
  for (const p of parts.slice(0, -1)) { if (typeof o[p] !== "object" || o[p] === null) o[p] = {}; o = o[p]; }
  o[parts[parts.length - 1]] = val;
}
function isLocked(path) {
  const L = (S.cfg && S.cfg.locked) || [];
  return L.some(l => l === path || path.startsWith(l + ".") || l.startsWith(path + "."));
}

async function api(method, path, body) {
  const opt = { method, headers: { "Accept": "application/json" }, credentials: "same-origin" };
  if (method !== "GET") {
    opt.headers["Content-Type"] = "application/json";
    opt.headers["X-Secwatch-CSRF"] = (S.session && S.session.csrf) || "-";
    opt.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (r.status === 401 && path !== "/api/login") { await boot(); throw new Error(t("err.unauthorized")); }
  if (!r.ok) {
    const msg = data && (data.detail || data.error || (data.errors && data.errors.join("; ")));
    const e = new Error(msg || ("HTTP " + r.status)); e.data = data; throw e;
  }
  return data;
}

async function loadLang(lang) {
  try { S.dict = await api("GET", "/api/i18n/" + encodeURIComponent(lang)); S.lang = lang; }
  catch (e) { if (lang !== "en") return loadLang("en"); }
  document.documentElement.lang = S.lang;
  try { localStorage.setItem("secwatch.lang", S.lang); } catch (e) { /* ignore */ }
}

/* ------------------------------------------------------------------ boot / layout */
async function boot() {
  S.session = await (await fetch("/api/session", { credentials: "same-origin" })).json();
  let lang = S.session.language || "en";
  try { lang = localStorage.getItem("secwatch.lang") || lang; } catch (e) { /* ignore */ }
  if (!(S.session.languages || []).includes(lang)) lang = S.session.language || "en";
  await loadLang(lang);
  if (!S.session.authenticated) return renderLogin();
  try { S.cfg = await api("GET", "/api/config"); } catch (e) { S.cfg = null; }
  renderShell();
  // Changing the hash fires "hashchange" → route(); calling route() as well would render twice.
  if (!S.session.setup_complete && !location.hash.startsWith("#/wizard")) location.hash = "#/wizard";
  else route();
}

/* password input with show/hide toggle (eye icon), used for every password field */
const EYE = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.9 17.9A10.9 10.9 0 0 1 12 19C5 19 1 12 1 12a20 20 0 0 1 5.1-5.9M9.9 5.2A10 10 0 0 1 12 5c7 0 11 7 11 7a20 20 0 0 1-2.2 3.2M14.1 14.1a3 3 0 1 1-4.2-4.2"/><path d="M1 1l22 22"/></svg>';
function pwInput(attrs) {
  const inp = h("input", Object.assign({}, attrs, { type: "password" }));
  const btn = h("button", { type: "button", class: "pwtoggle", title: t("pw.show"), "aria-label": t("pw.show"), onclick: () => {
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    btn.innerHTML = show ? EYE_OFF : EYE;
    btn.title = t(show ? "pw.hide" : "pw.show"); btn.setAttribute("aria-label", btn.title);
  } });
  btn.innerHTML = EYE;
  if (attrs.disabled) btn.disabled = true;
  const wrap = h("span", { class: "pwwrap" }, inp, btn);
  wrap.input = inp;
  return wrap;
}

function renderLogin() {
  const root = clear(document.getElementById("root"));
  const needCode = S.session.needs_setup_code;
  const pw = pwInput({ id: "pw", autocomplete: "current-password", placeholder: t(needCode ? "login.setup_code" : "login.password_or_token") });
  const inp = pw.input;
  const err = h("div", { class: "err-text small" });
  const submit = async (ev) => {
    ev.preventDefault();
    const v = inp.value.trim();
    if (!v) return;
    const body = needCode ? { setup_code: v } : { password: v, token: v };
    try { await api("POST", "/api/login", body); await boot(); }
    catch (e) { err.textContent = t("login.failed"); }
  };
  root.appendChild(h("div", { class: "login" },
    h("div", { class: "brand" }, "sec", h("span", null, "watch")),
    h("form", { class: "card", onsubmit: submit },
      h("h3", null, t(needCode ? "login.setup_title" : "login.title")),
      needCode ? h("p", { class: "mute small" }, t("login.setup_hint", { path: "<state>/setup-code" })) : null,
      pw, err, h("button", { class: "btn primary", type: "submit" }, t("login.submit"))),
    langSwitcher()));
  inp.focus();
}

function langSwitcher() {
  const sel = h("select", { "aria-label": t("header.language"), onchange: async (e) => { await loadLang(e.target.value); if (S.session.authenticated) { renderShell(); route(); } else renderLogin(); } },
    (S.session.languages || ["en"]).map(l => h("option", { value: l, selected: l === S.lang ? true : null }, l.toUpperCase())));
  return sel;
}

const NAV = [
  ["overview", "nav.overview"], ["findings", "nav.findings"], ["reports", "nav.reports"], "-",
  ["hardening", "nav.hardening", "lynis"], ["exposure", "nav.exposure", "exposure"], ["secrets", "nav.secrets", "secrets"],
  ["auth", "nav.auth", "auth"], ["updates", "nav.updates", "updates"], "-",
  ["settings", "nav.settings"], ["wizard", "nav.wizard"],
];

function renderShell() {
  const root = clear(document.getElementById("root"));
  const rail = h("nav", { class: "rail", "aria-label": "main" },
    h("div", { class: "brand" }, "sec", h("span", null, "watch")),
    NAV.map(n => n === "-" ? h("div", { class: "sep" }) :
      h("a", { href: "#/" + n[0], "data-page": n[0] }, t(n[1]), n[2] ? h("span", { class: "soon" }, t("nav.phase2")) : null)),
    h("div", { class: "sep" }),
    h("a", { href: "#", onclick: async (e) => { e.preventDefault(); try { await api("POST", "/api/logout"); } catch (x) { /* */ } boot(); } }, t("nav.logout")));
  const hostSel = h("select", { id: "hostsel", "aria-label": t("header.host"), onchange: (e) => { S.host = e.target.value; route(); } },
    h("option", { value: "" }, t("header.all_hosts")));
  const scanBtn = h("button", { class: "btn primary", id: "scanbtn", onclick: scanNow }, t("header.scan_now"));
  const header = h("header", { class: "top" }, h("h1", { id: "title" }, ""), h("span", { class: "meta", id: "lastscan" }, ""),
    hostSel, langSwitcher(), scanBtn);
  const main = h("div", { class: "main" }, header, h("div", { class: "content", id: "page" }));
  root.appendChild(h("div", { class: "app" }, rail, main));
  root.appendChild(h("aside", { class: "drawer", id: "drawer", "aria-hidden": "true" }));
  refreshHeader();
}

async function refreshHeader() {
  try {
    const ov = await api("GET", "/api/overview");
    const sel = document.getElementById("hostsel");
    if (sel) {
      const cur = S.host;
      clear(sel).appendChild(h("option", { value: "" }, t("header.all_hosts")));
      for (const hh of ov.hosts) sel.appendChild(h("option", { value: hh.host, selected: hh.host === cur ? true : null }, hh.host));
    }
    const ls = document.getElementById("lastscan");
    if (ls) ls.textContent = ov.last_scan ? t("header.last_scan", { when: ago(ov.last_scan.started_at), status: t("scan.status." + ov.last_scan.status) }) : t("header.never_scanned");
    const b = document.getElementById("scanbtn");
    if (b) { b.disabled = !!ov.trigger_pending; b.textContent = ov.trigger_pending ? t("header.scan_queued") : t("header.scan_now"); }
  } catch (e) { /* header is best effort */ }
}

async function scanNow() {
  try { await api("POST", "/api/scan"); toast(t("scan.queued")); refreshHeader(); }
  catch (e) { toast(e.message, true); }
}

function setTitle(key) { const el = document.getElementById("title"); if (el) el.textContent = t(key); document.title = "secwatch · " + t(key); }

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [page, qs] = raw.split("?");
  return { page: page || "overview", params: new URLSearchParams(qs || "") };
}

async function route() {
  if (!S.session || !S.session.authenticated) return;
  const { page, params } = parseHash();
  if (params.get("host") !== null && params.get("host") !== S.host) S.host = params.get("host");
  document.querySelectorAll(".rail a[data-page]").forEach(a => a.classList.toggle("active", a.dataset.page === page));
  closeDrawer();
  const seq = ++routeSeq;
  const host = clear(document.getElementById("page") || document.body);
  const el = h("div");  // offscreen; attached only if no newer navigation started meanwhile
  const pages = { overview: pageOverview, findings: pageFindings, reports: pageReports, settings: pageSettings, wizard: pageWizard,
    hardening: () => pagePhase2("hardening", "lynis"), exposure: () => pagePhase2("exposure", "exposure"),
    secrets: () => pagePhase2("secrets", "secrets"), auth: () => pagePhase2("auth", "auth"), updates: () => pagePhase2("updates", "updates") };
  const fn = pages[page] || pageOverview;
  try { await fn(el, params); }
  catch (e) { el.appendChild(h("div", { class: "card err-text" }, t("err.load"), " ", e.message)); }
  if (seq === routeSeq) host.appendChild(el);
}
let routeSeq = 0;
window.addEventListener("hashchange", route);

/* ------------------------------------------------------------------ overview */
async function pageOverview(el) {
  setTitle("nav.overview");
  const q = S.host ? "?host=" + encodeURIComponent(S.host) : "";
  const ov = await api("GET", "/api/overview" + q);
  const c = ov.counts;
  el.appendChild(h("div", { class: "cards" },
    SEVS.map(s => h("a", { class: "card stat " + s, href: "#/findings?severity=" + s + (S.host ? "&host=" + encodeURIComponent(S.host) : "") }, h("b", null, c[s] || 0), h("span", null, t("severity." + s)))),
    h("a", { class: "card stat kev", href: "#/findings?kev=1" }, h("b", null, c.kev || 0), h("span", null, t("ov.kev"))),
    h("div", { class: "card stat" }, h("b", null, ov.accepted || 0), h("span", null, t("ov.accepted")))));
  const chart = h("div", { class: "card chart" }, h("h3", null, t("ov.trend")), trendChart(ov.trend));
  const next = h("div", { class: "card" }, h("h3", null, t("ov.next")),
    h("div", { class: "kv" }, Object.entries(ov.next || {}).map(([k, v]) => [h("div", null, t("ov.next." + k)), h("div", null, fmtTime(v))])));
  el.appendChild(h("div", { class: "two" }, chart, next));
  const hosts = h("div", { class: "card tablecard" }, h("table", null,
    h("thead", null, h("tr", null, h("th", null, t("col.host")), h("th", null, t("col.role")), h("th", null, t("col.status")),
      SEVS.map(s => h("th", null, t("severity." + s))), h("th", null, "KEV"), h("th", null, t("col.last_scan")))),
    h("tbody", null, ov.hosts.length ? ov.hosts.map(x => h("tr", { class: "click", onclick: () => { S.host = x.host; location.hash = "#/findings?host=" + encodeURIComponent(x.host); } },
      h("td", null, x.host), h("td", null, t("role." + x.role)), h("td", null, statusBadge(x.status)),
      SEVS.map(s => h("td", null, x.counts[s] || 0)), h("td", null, x.counts.kev || 0), h("td", null, ago(x.last_scan || x.last_contact))))
      : h("tr", null, h("td", { colspan: 9, class: "empty" }, t("ov.no_hosts"))))));
  el.appendChild(h("h3", { class: "mute" }, t("ov.hosts")));
  el.appendChild(hosts);
  const ls = ov.last_scan;
  const coll = h("div", { class: "card tablecard" }, h("table", null,
    h("thead", null, h("tr", null, h("th", null, t("ov.check")), h("th", null, t("col.status")), h("th", null, t("ov.count")), h("th", null, t("ov.duration")), h("th", null, t("ov.message")))),
    h("tbody", null, ls ? Object.entries(ls.collectors).filter(([k, v]) => !k.startsWith("_") && v.enabled).map(([k, v]) =>
      h("tr", null, h("td", null, t("collector." + k + ".title")), h("td", null, v.ok ? (v.implemented === false ? h("span", { class: "badge warn" }, t("ov.phase2")) : h("span", { class: "badge ok" }, "OK")) : h("span", { class: "badge err" }, t("ov.failed"))),
        h("td", null, v.count || 0), h("td", null, (v.duration_s || 0) + " s"), h("td", { class: "small mute" }, v.error || (v.messages || []).join("; ")))) :
      h("tr", null, h("td", { colspan: 5, class: "empty" }, t("ov.no_scan"))))));
  const tools = h("div", { class: "card tablecard" }, h("table", null,
    h("thead", null, h("tr", null, h("th", null, t("col.host")), h("th", null, t("ov.tool")), h("th", null, t("ov.version")), h("th", null, t("ov.db_age")))),
    h("tbody", null, ov.tools.length ? ov.tools.map(x => h("tr", null, h("td", null, x.host), h("td", null, x.name), h("td", { class: "mono" }, x.version || "–"), h("td", null, x.db_age ? ago(x.db_age) : "–")))
      : h("tr", null, h("td", { colspan: 4, class: "empty" }, "–")))));
  el.appendChild(h("div", { class: "two" }, h("div", null, h("h3", { class: "mute" }, t("ov.last_scan")), coll), h("div", null, h("h3", { class: "mute" }, t("ov.tools")), tools)));
}

function statusBadge(s) {
  const cls = s === "ok" ? "ok" : (s === "partial" ? "warn" : (s === "unknown" ? "" : "err"));
  return h("span", { class: "badge " + cls }, t("hoststatus." + s));
}

function trendChart(data) {
  if (!data || data.length < 1) return h("div", { class: "empty" }, t("ov.no_trend"));
  const W = 700, H = 200, P = 28;
  const max = Math.max(1, ...data.map(d => d.total));
  const x = i => P + (data.length === 1 ? (W - 2 * P) / 2 : i * (W - 2 * P) / (data.length - 1));
  const y = v => H - P - (v / max) * (H - 2 * P);
  const line = (key, color) => svg("polyline", { points: data.map((d, i) => x(i) + "," + y(key(d))).join(" "), fill: "none", stroke: color, "stroke-width": 2 });
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": t("ov.trend") },
    svg("line", { x1: P, y1: H - P, x2: W - P, y2: H - P, class: "axis" }),
    svg("line", { x1: P, y1: P, x2: P, y2: H - P, class: "axis" }),
    svg("text", { x: 2, y: P + 4 }, String(max)), svg("text", { x: 2, y: H - P }, "0"),
    svg("text", { x: P, y: H - 8 }, data[0].day), svg("text", { x: W - P - 60, y: H - 8 }, data[data.length - 1].day),
    line(d => d.total, "#6aa8ff"), line(d => d.critical + d.high, "#ff8c42"), line(d => d.kev, "#ff4d6d"));
  if (data.length <= 31) for (const [key, color] of [[d => d.total, "#6aa8ff"], [d => d.critical + d.high, "#ff8c42"], [d => d.kev, "#ff4d6d"]])
    data.forEach((d, i) => s.appendChild(svg("circle", { cx: x(i), cy: y(key(d)), r: 3, fill: color })));
  return h("div", null, s, h("div", { class: "legend" },
    h("span", null, h("i", { class: "lg-total" }), t("ov.total")), h("span", null, h("i", { class: "lg-ch" }), t("ov.crit_high")), h("span", null, h("i", { class: "lg-kev" }), "KEV")));
}

/* ------------------------------------------------------------------ findings */
async function pageFindings(el, params) {
  setTitle("nav.findings");
  const f = {
    host: params.get("host") || S.host || "", kind: params.get("kind") || "", severity: params.get("severity") || "",
    state: params.get("state") || "open", kev: params.get("kev") || "", q: params.get("q") || "", sort: params.get("sort") || "priority",
    offset: parseInt(params.get("offset") || "0", 10) || 0,
  };
  const data = await api("GET", "/api/findings?" + new URLSearchParams({ ...f, limit: 100 }).toString());
  const go = (patch) => {
    const nf = { ...f, ...patch };
    if (!("offset" in patch)) nf.offset = 0;
    const qs = new URLSearchParams(Object.entries(nf).filter(([k, v]) => v !== "" && !(k === "offset" && !v)));
    location.hash = "#/findings?" + qs.toString();
  };
  const sel = (name, opts, labeller) => h("select", { "aria-label": t("filter." + name), onchange: e => go({ [name]: e.target.value }) },
    opts.map(o => h("option", { value: o, selected: o === f[name] ? true : null }, labeller(o))));
  const search = h("input", { type: "search", placeholder: t("filter.search"), value: f.q, onkeydown: e => { if (e.key === "Enter") go({ q: e.target.value }); } });
  el.appendChild(h("div", { class: "filters" },
    sel("host", ["", ...data.facets.hosts], o => o || t("header.all_hosts")),
    sel("kind", ["", ...data.facets.kinds], o => o ? t("kind." + o) : t("filter.all_kinds")),
    sel("severity", ["", "critical", "high", "medium", "low", "unknown"], o => o ? t("severity." + o) : t("filter.all_severities")),
    sel("state", ["open", "accepted", "false_positive", "fixed", "all"], o => t("state." + o)),
    h("label", { class: "check" }, h("input", { type: "checkbox", checked: f.kev === "1", onchange: e => go({ kev: e.target.checked ? "1" : "" }) }), t("filter.kev_only")),
    search,
    sel("sort", ["priority", "severity", "age", "newest", "host", "package"], o => t("sort." + o)),
    h("span", { class: "mute small" }, t("findings.count", { n: data.total }))));
  const rows = data.items.map(x => h("tr", { class: "click", onclick: () => openFinding(x.key) },
    h("td", null, sevBadge(x.severity), x.kev ? h("span", { class: "badge kev" }, "KEV") : null),
    h("td", null, h("div", { class: "mono" }, x.id), h("div", { class: "small mute" }, (x.title || "").slice(0, 90))),
    h("td", null, x.package || "–", h("div", { class: "small mute mono" }, x.installed || "")),
    h("td", { class: "mono small" }, x.fixed || "–"),
    h("td", null, x.host, x.component ? h("div", { class: "small mute" }, x.component) : null),
    h("td", null, x.epss !== null && x.epss !== undefined ? (x.epss * 100).toFixed(1) + "%" : "–"),
    h("td", null, x.cvss !== null && x.cvss !== undefined ? x.cvss.toFixed(1) : "–"),
    h("td", { class: "nowrap" }, ago(x.first_seen)),
    h("td", null, h("span", { class: "badge" }, t("state." + x.state)))));
  el.appendChild(h("div", { class: "card tablecard" }, h("table", null,
    h("thead", null, h("tr", null, ["col.severity", "col.id", "col.package", "col.fixed", "col.host", "EPSS", "CVSS", "col.age", "col.state"].map(k => h("th", null, k.startsWith("col.") ? t(k) : k)))),
    h("tbody", null, rows.length ? rows : h("tr", null, h("td", { colspan: 9, class: "empty" }, t("findings.none"))))),
    h("div", { class: "pager" },
      h("button", { class: "btn", disabled: f.offset <= 0, onclick: () => go({ offset: Math.max(0, f.offset - 100) }) }, "‹"),
      h("span", { class: "small mute" }, `${data.total ? f.offset + 1 : 0}–${Math.min(f.offset + 100, data.total)} / ${data.total}`),
      h("button", { class: "btn", disabled: f.offset + 100 >= data.total, onclick: () => go({ offset: f.offset + 100 }) }, "›"))));
  if (/^[0-9a-f]{24}$/.test(params.get("open") || "")) openFinding(params.get("open"));
}

function closeDrawer() { const d = document.getElementById("drawer"); if (d) { d.classList.remove("open"); d.setAttribute("aria-hidden", "true"); } }

async function openFinding(key) {
  const d = document.getElementById("drawer");
  clear(d).appendChild(h("div", { class: "empty" }, "…"));
  d.classList.add("open"); d.setAttribute("aria-hidden", "false");
  let x;
  try { x = await api("GET", "/api/findings/" + encodeURIComponent(key)); }
  catch (e) { clear(d).appendChild(h("div", { class: "err-text" }, e.message)); return; }
  const ex = x.extra || {};
  const reason = h("input", { type: "text", placeholder: t("action.reason"), maxlength: 500 });
  const until = h("input", { type: "date", "aria-label": t("action.until") });
  const act = async (action) => {
    try {
      await api("POST", "/api/findings/" + encodeURIComponent(key) + "/action", { action, reason: reason.value, until: until.value || null });
      toast(t("action.done")); openFinding(key); route();
    } catch (e) { toast(e.message, true); }
  };
  const actions = x.state === "open" ? h("div", null,
      h("h3", { class: "mute" }, t("action.title")), h("div", { class: "row" }, reason, until),
      h("div", { class: "row" }, h("button", { class: "btn", onclick: () => act("accept") }, t("action.accept")),
        h("button", { class: "btn", onclick: () => act("false_positive") }, t("action.false_positive"))),
      h("p", { class: "small mute" }, t("action.help")))
    : (x.state === "accepted" || x.state === "false_positive") ? h("div", { class: "row" },
      h("span", { class: "mute" }, t("state." + x.state) + (x.reason ? ": " + x.reason : "") + (x.until ? " · " + t("action.until") + " " + fmtTime(x.until) : "")),
      h("button", { class: "btn", onclick: () => act("reopen") }, t("action.reopen"))) : null;
  clear(d).append(
    h("button", { class: "btn close", onclick: closeDrawer, "aria-label": t("action.close") }, "×"),
    h("h2", { class: "mono" }, x.id), h("div", null, sevBadge(x.severity), x.kev ? h("span", { class: "badge kev" }, "KEV") : null, h("span", { class: "badge" }, t("state." + x.state)), h("span", { class: "badge" }, t("kind." + x.kind))),
    h("p", null, ex.description || x.title || ""),
    h("div", { class: "kv" },
      h("div", null, t("col.host")), h("div", null, x.host),
      h("div", null, t("col.component")), h("div", null, x.component || "–"),
      h("div", null, t("col.package")), h("div", { class: "mono" }, x.package || "–"),
      h("div", null, t("col.installed")), h("div", { class: "mono" }, x.installed || "–"),
      h("div", null, t("col.fixed")), h("div", { class: "mono" }, x.fixed || t("detail.no_fix")),
      h("div", null, t("col.source")), h("div", null, x.source + (ex.target ? " · " + ex.target : "")),
      h("div", null, "CVSS"), h("div", null, x.cvss !== null && x.cvss !== undefined ? String(x.cvss) : "–"),
      h("div", null, "EPSS"), h("div", null, x.epss !== null && x.epss !== undefined ? `${(x.epss * 100).toFixed(2)}% (${t("detail.percentile")} ${((x.epss_pct || 0) * 100).toFixed(0)})` : "–"),
      x.kev ? [h("div", null, "KEV"), h("div", null, t("detail.kev_added", { date: ex.kev_date_added || "?", due: ex.kev_due_date || "?" }) + (ex.kev_ransomware === "Known" ? " · " + t("detail.ransomware") : ""))] : null,
      ex.image ? [h("div", null, t("detail.image")), h("div", { class: "mono" }, ex.image)] : null,
      ex.derivation ? [h("div", null, t("detail.derivation")), h("div", { class: "mono small" }, ex.derivation)] : null,
      h("div", null, t("detail.first_seen")), h("div", null, fmtTime(x.first_seen)),
      h("div", null, t("detail.last_seen")), h("div", null, fmtTime(x.last_seen)),
      x.fixed_at ? [h("div", null, t("detail.fixed_at")), h("div", null, fmtTime(x.fixed_at))] : null),
    h("h3", { class: "mute" }, t("detail.links")),
    h("div", null, (x.links || []).map(l => h("div", null, h("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.label)))),
    actions,
    h("h3", { class: "mute" }, t("detail.history")),
    h("div", { class: "small" }, (x.events || []).map(e => h("div", null, fmtTime(e.ts), " · ", t("event." + e.type), e.detail ? " – " + e.detail : ""))));
}

/* ------------------------------------------------------------------ reports */
async function pageReports(el) {
  setTitle("nav.reports");
  const data = await api("GET", "/api/reports");
  const monthly = data.items.filter(r => r.kind === "monthly");
  const selA = h("select", { "aria-label": "A" }, monthly.map((r, i) => h("option", { value: r.id, selected: i === 1 ? true : null }, r.period)));
  const selB = h("select", { "aria-label": "B" }, monthly.map((r, i) => h("option", { value: r.id, selected: i === 0 ? true : null }, r.period)));
  const out = h("div");
  const cmp = async () => {
    try {
      const c = await api("GET", `/api/reports/compare/${selA.value}/${selB.value}`);
      clear(out).appendChild(compareTable(c));
    } catch (e) { toast(e.message, true); }
  };
  el.appendChild(h("div", { class: "card" }, h("h3", null, t("reports.compare")),
    monthly.length >= 2 ? h("div", { class: "row" }, selA, h("span", null, "→"), selB, h("button", { class: "btn", onclick: cmp }, t("reports.compare_btn"))) : h("div", { class: "mute" }, t("reports.compare_need_two")),
    out));
  for (const kind of ["daily", "weekly", "monthly"]) {
    const items = data.items.filter(r => r.kind === kind);
    el.appendChild(h("h3", { class: "mute" }, t("report.kind." + kind)));
    el.appendChild(h("div", { class: "card tablecard" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, t("report.period")), h("th", null, t("report.generated")), h("th", null, t("report.open")), h("th", null, t("report.new")), h("th", null, t("report.fixed")), h("th", null, ""))),
      h("tbody", null, items.length ? items.map(r => h("tr", null,
        h("td", null, r.period), h("td", null, fmtTime(r.created_at)), h("td", null, r.summary.open_count ?? (r.summary.totals ? r.summary.totals.total : "–")),
        h("td", null, r.summary.new_count ?? "–"), h("td", null, r.summary.fixed_count ?? "–"),
        h("td", null, h("button", { class: "btn", onclick: () => openReport(r) }, t("reports.open")), " ",
          h("a", { class: "btn", href: `/api/reports/${r.id}/html`, target: "_blank", rel: "noopener" }, "↗"), " ",
          h("a", { class: "btn", href: `/api/reports/${r.id}/json`, target: "_blank", rel: "noopener" }, "JSON"))))
        : h("tr", null, h("td", { colspan: 6, class: "empty" }, t("reports.none")))))));
  }
}

function openReport(r) {
  const bg = h("div", { class: "modal-bg", onclick: e => { if (e.target === bg) bg.remove(); } },
    h("div", { class: "modal" }, h("div", { class: "row" }, h("b", null, t("report.kind." + r.kind) + " " + r.period), h("span", { class: "mute" }, ""), h("button", { class: "btn", onclick: () => bg.remove() }, "×")),
      h("iframe", { src: `/api/reports/${r.id}/html`, sandbox: "allow-popups allow-popups-to-escape-sandbox", title: r.period })));
  document.body.appendChild(bg);
}

function compareTable(c) {
  const sign = v => (v > 0 ? "+" : "") + v;
  const cls = v => v > 0 ? "err-text" : (v < 0 ? "ok-text" : "");
  const row = (label, a, b, d) => h("tr", null, h("td", null, label), h("td", null, a ?? "–"), h("td", null, b ?? "–"), h("td", { class: cls(d || 0) }, d === null || d === undefined ? "–" : sign(d)));
  const ta = c.a.totals || {}, tb = c.b.totals || {};
  return h("table", null, h("thead", null, h("tr", null, h("th", null, ""), h("th", null, c.a.period), h("th", null, c.b.period), h("th", null, "Δ"))),
    h("tbody", null,
      row(t("report.open"), ta.total, tb.total, c.delta.total),
      ["critical", "high", "medium", "low", "unknown"].map(s => row(t("severity." + s), (ta.by_severity || {})[s], (tb.by_severity || {})[s], c.delta.by_severity[s])),
      row("KEV", ta.kev, tb.kev, c.delta.kev),
      row(t("report.new"), c.a.new_count, c.b.new_count, c.delta.new),
      row(t("report.fixed"), c.a.fixed_count, c.b.fixed_count, c.delta.fixed),
      row(t("report.mttf"), c.a.mttf_days, c.b.mttf_days, c.delta.mttf_days),
      Object.keys(c.delta.by_host || {}).sort().map(hh => row(hh, ((ta.by_host || {})[hh] || {}).total, ((tb.by_host || {})[hh] || {}).total, c.delta.by_host[hh]))));
}

/* ------------------------------------------------------------------ phase-2 placeholder pages */
async function pagePhase2(page, collector) {
  setTitle("nav." + page);
  const el = document.getElementById("page");
  if (!S.cfg) S.cfg = await api("GET", "/api/config");
  const path = "collectors." + collector + ".enabled";
  const val = getPath(S.cfg.config, path);
  const locked = isLocked(path);
  const toggle = h("input", { type: "checkbox", checked: val === true, disabled: locked,
    onchange: async e => {
      try { await saveChanges({ collectors: { [collector]: { enabled: e.target.checked } } }); toast(t("settings.saved")); }
      catch (x) { toast(x.message, true); e.target.checked = !e.target.checked; }
    } });
  el.appendChild(h("div", { class: "card placeholder" },
    h("h3", null, t("phase2.title")),
    h("p", { class: "big" }, t("collector." + collector + ".desc")),
    h("p", { class: "mute" }, t("phase2.body." + page)),
    h("div", { class: "privacy" }, t("collector." + collector + ".privacy")),
    h("p", null, h("label", { class: "check" }, toggle, t("phase2.enable"))),
    locked ? h("div", { class: "lock" }, t("settings.locked")) : null,
    h("p", { class: "small mute" }, t("phase2.note"))));
}

/* ------------------------------------------------------------------ settings & wizard forms */
const COLLECTOR_FIELDS = ["nix", "os", "containers", "lynis", "exposure", "secrets", "auth", "updates", "sbom"];
const TRISTATE = ["nix", "os", "containers"];

function sections() {
  const roles = ["standalone", "agent", "hub"];
  const days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
  return [
    { id: "welcome", fields: [
      { path: "language", type: "select", options: (S.cfg.languages || ["en"]) },
      { path: "role", type: "select", options: roles, label: o => t("role." + o) },
      { path: "host_name", type: "text" },
      { special: "admin_password" },
      { path: "web.auth_mode", type: "select", options: ["password", "token", "trusted_proxy"], label: o => t("authmode." + o) },
      { secret: "web.token" },
      { path: "web.base_url", type: "text" },
      { path: "web.secure_cookie", type: "bool" },
      { path: "registry_file", type: "text" },
    ] },
    { id: "environment", special: "detect" },
    { id: "checks", fields: [
      ...COLLECTOR_FIELDS.map(c => ({ path: `collectors.${c}.enabled`, type: TRISTATE.includes(c) ? "tristate" : "bool", collector: c })),
      { path: "collectors.nix.whitelist", type: "list" },
      { path: "collectors.containers.runtime", type: "select", options: ["auto", "docker", "podman"] },
      { path: "collectors.containers.exclude", type: "list" },
      { path: "collectors.lynis.frequency", type: "select", options: ["daily", "weekly", "monthly"], label: o => t("freq." + o) },
      { path: "enrichers.kev.enabled", type: "bool", enricher: "kev" },
      { path: "enrichers.epss.enabled", type: "bool", enricher: "epss" },
      { path: "enrichers.epss.mode", type: "select", options: ["csv", "api"], label: o => t("epss.mode." + o) },
      { path: "enrichers.cvss.enabled", type: "bool", enricher: "cvss" },
      { path: "trivy.db_repository", type: "list" },
    ] },
    { id: "schedule", fields: [
      { group: "scan" },
      { path: "schedule.scan.frequency", type: "select", options: ["daily", "weekly", "monthly"], label: o => t("freq." + o) },
      { path: "schedule.scan.time", type: "time" },
      { path: "schedule.scan.weekday", type: "select", options: days, label: o => t("day." + o) },
      { path: "schedule.scan.monthday", type: "number", min: 1, max: 28 },
      { group: "daily", groupHelp: true },
      { path: "schedule.reports.daily.enabled", type: "bool" },
      { path: "schedule.reports.daily.time", type: "time" },
      { group: "weekly", groupHelp: true },
      { path: "schedule.reports.weekly.enabled", type: "bool" },
      { path: "schedule.reports.weekly.weekday", type: "select", options: days, label: o => t("day." + o) },
      { path: "schedule.reports.weekly.time", type: "time" },
      { path: "schedule.reports.weekly.notify_only_if_open", type: "bool" },
      { group: "monthly", groupHelp: true },
      { path: "schedule.reports.monthly.enabled", type: "bool" },
      { path: "schedule.reports.monthly.monthday", type: "number", min: 1, max: 28 },
      { path: "schedule.reports.monthly.time", type: "time" },
      { group: "retention" },
      { path: "schedule.reports.retention_days", type: "number", min: 0, max: 36500 },
    ] },
    { id: "matrix", special: "matrix", fields: [
      { group: "limits" },
      { path: "notify.dedup_hours", type: "number", min: 0, max: 8760 },
      { path: "notify.max_per_hour", type: "number", min: 0, max: 1000 },
      { path: "notify.update_security_only", type: "bool" },
    ] },
    { id: "channels", special: "channels", fields: [
      { path: "notify.ntfy.enabled", type: "bool" },
      { path: "notify.ntfy.url", type: "text" },
      { path: "notify.ntfy.topic", type: "text" },
      { secret: "notify.ntfy.token", file: "notify.ntfy.token_file" },
      { path: "notify.ntfy.tags", type: "bool" },
      { path: "notify.mail.enabled", type: "bool" },
      { path: "notify.mail.host", type: "text" },
      { path: "notify.mail.port", type: "number", min: 1, max: 65535 },
      { path: "notify.mail.tls", type: "select", options: ["starttls", "ssl", "none"] },
      { path: "notify.mail.user", type: "text" },
      { secret: "notify.mail.password", file: "notify.mail.password_file" },
      { path: "notify.mail.from", type: "text" },
      { path: "notify.mail.to", type: "list" },
    ] },
    { id: "exposure", phase2: "exposure", fields: [
      { path: "collectors.exposure.enabled", type: "bool" },
      { path: "collectors.exposure.public_names", type: "list", suggest: "public_hostnames" },
      { path: "collectors.exposure.public_ip", type: "text" },
      { path: "collectors.exposure.expected_ports", type: "list", suggest: "ports" },
      { path: "collectors.exposure.check_tls", type: "bool" },
      { path: "collectors.exposure.check_headers", type: "bool" },
    ] },
    { id: "secrets", phase2: "secrets", fields: [
      { path: "collectors.secrets.enabled", type: "bool" },
      { path: "collectors.secrets.repos", type: "list" },
      { path: "collectors.secrets.git_urls", type: "list" },
    ] },
    { id: "auth", phase2: "auth", fields: [
      { path: "collectors.auth.enabled", type: "bool" },
      { path: "collectors.auth.sources", type: "list", suggest: "auth_sources" },
      { path: "collectors.auth.threshold_per_day", type: "number", min: 1, max: 1000000 },
      { path: "collectors.auth.baseline_factor", type: "number", min: 1, max: 100 },
    ] },
    { id: "agents", special: "agents", fields: [
      { secret: "agent.token", file: "agent.token_file" },
      { path: "agent.ui", type: "bool" },
      { path: "hub.timeout", type: "number", min: 1, max: 600 },
      { path: "hub.verify_tls", type: "bool" },
    ] },
    { id: "summary", special: "summary" },
  ];
}

function fieldLabel(f) { return t("f." + (f.path || f.secret || f.special)); }

function renderField(f, pending) {
  if (f.group) return h("div", { class: "fgroup" }, h("span", null, t("group." + f.group)),
    f.groupHelp ? h("span", { class: "help" }, t("group." + f.group + ".help")) : null);
  if (f.special === "admin_password") {
    const locked = isLocked("web.admin_password_hash");
    const inp = pwInput({ autocomplete: "new-password", placeholder: S.cfg.admin_password === "set" ? t("secret.keep") : t("secret.enter"), disabled: locked,
      oninput: e => { pending.admin_password = e.target.value; } });
    return [h("label", { class: "l" }, t("f.admin_password")), h("div", null, inp,
      h("div", { class: "help" }, t("h.admin_password") + " · " + t("secret.status." + S.cfg.admin_password)), locked ? h("div", { class: "lock" }, t("settings.locked")) : null)];
  }
  if (f.secret) {
    const filePath = f.file || (f.secret + "_file");
    const locked = isLocked(filePath);
    const st = (S.cfg.secrets || {})[f.secret] || "unset";
    const inp = h("input", { type: "password", autocomplete: "off", placeholder: st === "set" ? t("secret.keep") : t("secret.enter"), disabled: locked,
      oninput: e => { pending.secrets = pending.secrets || {}; pending.secrets[f.secret] = e.target.value; } });
    return [h("label", { class: "l" }, fieldLabel(f)), h("div", null, inp,
      h("div", { class: "help" }, t("secret.status." + st) + (getPath(S.cfg.config, filePath) ? " · " + getPath(S.cfg.config, filePath) : "")), locked ? h("div", { class: "lock" }, t("settings.locked")) : null)];
  }
  const val = getPath(pending.changes, f.path) !== undefined ? getPath(pending.changes, f.path) : getPath(S.cfg.config, f.path);
  const locked = isLocked(f.path);
  const set = v => setPath(pending.changes, f.path, v);
  let input;
  if (f.type === "bool") input = h("input", { type: "checkbox", checked: val === true, disabled: locked, onchange: e => set(e.target.checked) });
  else if (f.type === "tristate") input = h("select", { disabled: locked, onchange: e => set(e.target.value === "auto" ? "auto" : e.target.value === "true") },
    ["auto", "true", "false"].map(o => h("option", { value: o, selected: String(val) === o ? true : null }, t("tristate." + o))));
  else if (f.type === "select") input = h("select", { disabled: locked, onchange: e => set(e.target.value) },
    f.options.map(o => h("option", { value: o, selected: val === o ? true : null }, f.label ? f.label(o) : o)));
  else if (f.type === "number") input = h("input", { type: "number", value: val ?? "", min: f.min, max: f.max, disabled: locked, onchange: e => set(parseInt(e.target.value, 10) || 0) });
  else if (f.type === "time") input = h("input", { type: "time", value: val || "", disabled: locked, onchange: e => set(e.target.value) });
  else if (f.type === "list") {
    const ta = h("textarea", { disabled: locked, onchange: e => set(e.target.value.split("\n").map(s => s.trim()).filter(Boolean)) });
    ta.value = (val || []).map(x => typeof x === "object" ? JSON.stringify(x) : x).join("\n");
    input = h("div", null, ta, f.suggest && !locked ? suggestButton(f, ta, set) : null);
  } else input = h("input", { type: "text", value: val ?? "", disabled: locked, onchange: e => set(e.target.value) });
  const help = S.dict["h." + f.path] ? h("div", { class: "help" }, t("h." + f.path)) : null;
  const priv = f.collector ? h("div", null, h("div", { class: "help" }, t("collector." + f.collector + ".desc") + (PHASE2.includes(f.collector) ? " · " + t("nav.phase2") : "")), h("div", { class: "privacy" }, t("collector." + f.collector + ".privacy")))
    : f.enricher ? h("div", { class: "privacy" }, t("enricher." + f.enricher + ".privacy")) : null;
  return [h("label", { class: "l" }, f.collector ? t("collector." + f.collector + ".title") : f.enricher ? t("enricher." + f.enricher + ".title") : fieldLabel(f)),
    h("div", null, input, help, priv, locked ? h("div", { class: "lock" }, t("settings.locked")) : null)];
}

function suggestButton(f, ta, set) {
  return h("button", { class: "btn small", type: "button", onclick: async () => {
    const d = S.detect || (S.detect = await api("GET", "/api/detect"));
    let vals = [];
    if (f.suggest === "ports") vals = (d.ports || []).filter(p => p.public).map(p => `${p.proto}/${p.port}`);
    else vals = d[f.suggest] || [];
    vals = [...new Set([...(ta.value.split("\n").map(s => s.trim()).filter(Boolean)), ...vals])];
    ta.value = vals.join("\n"); set(vals);
  } }, t("wizard.prefill"));
}

async function saveChanges(changes, extra) {
  const r = await api("PUT", "/api/config", { changes, ...(extra || {}) });
  S.cfg = await api("GET", "/api/config");
  if (r.relogin) { toast(t("settings.relogin")); setTimeout(boot, 800); }
  return r;
}

function renderMatrix(pending) {
  const locked = isLocked("notify.matrix");
  const cur = () => getPath(pending.changes, "notify.matrix") || JSON.parse(JSON.stringify(S.cfg.config.notify.matrix));
  const wrap = h("div");
  const draw = () => {
    const m = cur();
    clear(wrap).appendChild(h("div", null,
      h("div", { class: "row presets" }, h("span", { class: "mute" }, t("matrix.presets")),
        ["quiet", "normal", "strict"].map(p => h("button", { class: "btn", type: "button", disabled: locked, onclick: () => {
          setPath(pending.changes, "notify.matrix", JSON.parse(JSON.stringify(S.cfg.presets[p]))); setPath(pending.changes, "notify.preset", p); draw();
        } }, t("matrix.preset." + p)))),
      h("div", { class: "card tablecard" }, h("table", { class: "matrix" },
        h("thead", null, h("tr", null, h("th", null, t("matrix.event")), S.cfg.severities.map(s => h("th", null, sevBadge(s))))),
        h("tbody", null, S.cfg.events.map(ev => h("tr", null, h("td", null, t("event." + ev), h("div", { class: "small mute" }, t("matrix.help." + ev))),
          S.cfg.severities.map(s => h("td", null, ["push", "mail"].map(ch => h("label", null,
            h("input", { type: "checkbox", disabled: locked, checked: !!(((m[ev] || {})[s] || {})[ch]), onchange: e => {
              const mm = cur(); mm[ev] = mm[ev] || {}; mm[ev][s] = mm[ev][s] || { push: false, mail: false }; mm[ev][s][ch] = e.target.checked;
              setPath(pending.changes, "notify.matrix", mm); setPath(pending.changes, "notify.preset", "custom");
            } }), t("matrix." + ch)))))))))),
      locked ? h("div", { class: "lock" }, t("settings.locked")) : null));
  };
  draw();
  return wrap;
}

async function renderDetect() {
  const d = S.detect = await api("GET", "/api/detect");
  const yes = v => v ? t("common.yes") : t("common.no");
  return h("div", { class: "grid" },
    h("div", { class: "card" }, h("div", { class: "kv" },
      h("div", null, t("detect.os")), h("div", null, d.os || "–"),
      h("div", null, "NixOS"), h("div", null, yes(d.is_nixos)),
      h("div", null, t("detect.runtime")), h("div", null, d.container_runtime || t("common.none"), d.container_socket ? h("span", { class: "mono small" }, " " + d.container_socket) : null),
      h("div", null, t("detect.containers")), h("div", null, (d.containers || []).length ? (d.containers || []).map(c => h("div", { class: "small" }, c.name, " ", h("span", { class: "mute mono" }, c.image))) : (d.containers_error ? h("span", { class: "mute small" }, t("detect.containers_hidden")) : "–")),
      h("div", null, "journald"), h("div", null, yes(d.journald)),
      h("div", null, t("detect.auth_sources")), h("div", null, (d.auth_sources || []).join(", ") || "–"),
      h("div", null, t("detect.hostnames")), h("div", null, (d.hostnames || []).join(", ") || t("detect.no_registry")),
      h("div", null, t("detect.tools")), h("div", null, Object.entries(d.tools || {}).map(([k, v]) => h("span", { class: "badge " + (v ? "ok" : "") }, k))),
      h("div", null, t("detect.source")), h("div", { class: "small mute" }, d.from_scan ? t("detect.from_scan") : t("detect.live_only")))),
    h("div", { class: "card" }, h("h3", null, t("detect.ports")),
      h("div", { class: "list-ports mono" }, (d.ports || []).map(p => h("div", { class: p.public ? "" : "mute" }, `${p.proto}/${p.port} ${p.address}${p.process ? " (" + p.process + ")" : ""}`)))));
}

function renderAgents(pending) {
  const role = getPath(pending.changes, "role") || S.cfg.config.role;
  const locked = isLocked("hub.agents");
  const agents = JSON.parse(JSON.stringify(getPath(pending.changes, "hub.agents") || S.cfg.agents || []));
  pending.agent_tokens = pending.agent_tokens || {};
  const wrap = h("div");
  const sync = () => setPath(pending.changes, "hub.agents", agents.map(a => ({ name: a.name, url: a.url, token_file: a.token_file || "" })));
  const draw = () => {
    clear(wrap);
    if (role !== "hub") { wrap.appendChild(h("p", { class: "mute" }, t("agents.only_hub"))); return; }
    agents.forEach((a, i) => {
      const tok = h("input", { type: "password", placeholder: a.token_status === "set" ? t("secret.keep") : t("agents.token"), disabled: locked, oninput: e => { pending.agent_tokens[a.name] = e.target.value; } });
      const res = h("span", { class: "small" });
      wrap.appendChild(h("div", { class: "card row" },
        h("input", { type: "text", value: a.name, placeholder: t("agents.name"), disabled: locked, onchange: e => { const old = a.name; a.name = e.target.value.trim(); if (pending.agent_tokens[old]) { pending.agent_tokens[a.name] = pending.agent_tokens[old]; delete pending.agent_tokens[old]; } sync(); } }),
        h("input", { type: "text", value: a.url, placeholder: "https://agent:8478", disabled: locked, onchange: e => { a.url = e.target.value.trim(); sync(); } }),
        tok,
        h("button", { class: "btn", type: "button", onclick: async () => {
          res.textContent = "…";
          try { const r = await api("POST", "/api/agents/test", { url: a.url, token: tok.value, token_file: a.token_file });
            res.textContent = r.ok ? t("agents.ok", { host: r.host, n: r.findings }) : t("agents.fail", { error: r.error }); res.className = r.ok ? "ok-text small" : "err-text small"; }
          catch (e) { res.textContent = e.message; res.className = "err-text small"; }
        } }, t("agents.test")),
        h("button", { class: "btn danger", type: "button", disabled: locked, onclick: () => { agents.splice(i, 1); sync(); draw(); } }, "×"), res));
    });
    wrap.appendChild(h("button", { class: "btn", type: "button", disabled: locked, onclick: () => { agents.push({ name: "", url: "", token_file: "" }); draw(); } }, t("agents.add")));
    if (locked) wrap.appendChild(h("div", { class: "lock" }, t("settings.locked")));
  };
  draw();
  return wrap;
}

function renderChannelsTest() {
  const out = h("span", { class: "small" });
  const test = async ch => {
    try { await api("POST", "/api/notify/test", { channel: ch }); out.textContent = t("channels.test_queued"); pollActions(out); }
    catch (e) { out.textContent = e.message; }
  };
  return h("div", { class: "row" }, h("button", { class: "btn", type: "button", onclick: () => test("push") }, t("channels.test_push")),
    h("button", { class: "btn", type: "button", onclick: () => test("mail") }, t("channels.test_mail")), out,
    h("div", { class: "help" }, t("channels.test_help")));
}

async function pollActions(out, tries) {
  tries = tries || 0;
  if (tries > 40) return;
  setTimeout(async () => {
    try {
      const a = await api("GET", "/api/actions");
      if (a.trigger_pending) return pollActions(out, tries + 1);
      const last = (a.items || []).find(x => x.action === "notify-test");
      if (last) out.textContent = Object.entries(last.results || {}).map(([k, v]) => `${k}: ${v.ok ? "OK" : v.error}`).join(" · ");
    } catch (e) { /* ignore */ }
  }, 3000);
}

function renderSection(sec, pending, el) {
  el.appendChild(h("p", { class: "section-intro" }, t("wiz." + sec.id + ".intro")));
  if (sec.phase2) el.appendChild(h("div", { class: "privacy" }, t("wizard.phase2_note")));
  if (sec.special === "matrix") el.appendChild(renderMatrix(pending));
  if (sec.special === "agents") el.appendChild(renderAgents(pending));
  if (sec.fields) el.appendChild(h("div", { class: "form" }, sec.fields.map(f => renderField(f, pending))));
  if (sec.special === "channels") el.appendChild(renderChannelsTest());
}

function newPending() { return { changes: {}, secrets: {}, admin_password: "", agent_tokens: {} }; }

async function flush(pending) {
  const hasChanges = Object.keys(pending.changes).length || Object.values(pending.secrets || {}).some(Boolean) || pending.admin_password || Object.values(pending.agent_tokens || {}).some(Boolean);
  if (!hasChanges) return;
  const extra = { secrets: pending.secrets, agent_tokens: pending.agent_tokens };
  if (pending.admin_password) extra.admin_password = pending.admin_password;
  await saveChanges(pending.changes, extra);
  if (getPath(pending.changes, "language")) await loadLang(getPath(pending.changes, "language"));
  Object.assign(pending, newPending());
}

async function pageSettings(el, params) {
  setTitle("nav.settings");
  S.cfg = await api("GET", "/api/config");
  const secs = sections().filter(s => s.id !== "summary");
  const cur = params.get("tab") || "welcome";
  el.appendChild(h("div", { class: "tabs" }, secs.map(s => h("a", { href: "#/settings?tab=" + s.id, class: s.id === cur ? "active" : "" }, t("wiz." + s.id + ".title")))));
  if ((S.cfg.locked || []).length) el.appendChild(h("p", { class: "small mute" }, t("settings.locked_info", { n: S.cfg.locked.length })));
  (S.cfg.warnings || []).forEach(w => el.appendChild(h("div", { class: "card err-text small" }, w)));
  const sec = secs.find(s => s.id === cur) || secs[0];
  const pending = newPending();
  const body = h("div", { class: "card" });
  el.appendChild(body);
  if (sec.special === "detect") { body.appendChild(h("p", { class: "section-intro" }, t("wiz.environment.intro"))); body.appendChild(await renderDetect()); return; }
  renderSection(sec, pending, body);
  body.appendChild(h("div", { class: "row" }, h("button", { class: "btn primary", onclick: async () => {
    try { await flush(pending); toast(t("settings.saved")); route(); } catch (e) { toast(e.message, true); }
  } }, t("settings.save"))));
}

async function pageWizard(el, params) {
  setTitle("nav.wizard");
  S.cfg = await api("GET", "/api/config");
  const secs = sections();
  let idx = Math.max(0, Math.min(secs.length - 1, parseInt(params.get("step") || "0", 10) || 0));
  const sec = secs[idx];
  el.appendChild(h("div", { class: "steps" }, secs.map((s, i) => h("span", { class: i === idx ? "cur" : (i < idx ? "done" : "") }, `${i + 1}. ${t("wiz." + s.id + ".title")}`))));
  const pending = newPending();
  const body = h("div", { class: "card" }, h("h3", null, `${idx + 1}/${secs.length} · ${t("wiz." + sec.id + ".title")}`));
  el.appendChild(body);
  if (sec.special === "detect") {
    body.appendChild(h("p", { class: "section-intro" }, t("wiz.environment.intro")));
    body.appendChild(await renderDetect());
    body.appendChild(h("p", null, h("button", { class: "btn", onclick: async () => {
      const d = S.detect; const ch = {};
      setPath(ch, "collectors.nix.enabled", "auto"); setPath(ch, "collectors.os.enabled", "auto"); setPath(ch, "collectors.containers.enabled", "auto");
      if ((d.auth_sources || []).length && !isLocked("collectors.auth.sources")) setPath(ch, "collectors.auth.sources", d.auth_sources);
      if (!isLocked("collectors.exposure.expected_ports")) setPath(ch, "collectors.exposure.expected_ports", (d.ports || []).filter(p => p.public).map(p => `${p.proto}/${p.port}`));
      if ((d.public_hostnames || []).length && !isLocked("collectors.exposure.public_names")) setPath(ch, "collectors.exposure.public_names", d.public_hostnames);
      for (const k of ["collectors.nix.enabled", "collectors.os.enabled", "collectors.containers.enabled"]) if (isLocked(k)) { const parts = k.split("."); delete ch.collectors[parts[1]]; }
      try { await saveChanges(ch); toast(t("wizard.applied")); } catch (e) { toast(e.message, true); }
    } }, t("wizard.apply_detect"))));
  } else if (sec.special === "summary") {
    body.appendChild(h("p", { class: "section-intro" }, t("wiz.summary.intro")));
    const c = S.cfg.config;
    const enabled = Object.entries(c.collectors).filter(([k, v]) => v.enabled !== false).map(([k, v]) => t("collector." + k + ".title") + (v.enabled === "auto" ? " (auto)" : ""));
    body.appendChild(h("div", { class: "kv" },
      h("div", null, t("f.role")), h("div", null, t("role." + c.role)),
      h("div", null, t("f.admin_password")), h("div", null, t("secret.status." + S.cfg.admin_password)),
      h("div", null, t("wiz.checks.title")), h("div", null, enabled.join(", ")),
      h("div", null, t("wiz.schedule.title")), h("div", null, `${t("freq." + c.schedule.scan.frequency)} ${c.schedule.scan.time}`),
      h("div", null, "ntfy"), h("div", null, c.notify.ntfy.enabled ? c.notify.ntfy.url + " / " + c.notify.ntfy.topic : t("common.off")),
      h("div", null, t("wiz.channels.mail")), h("div", null, c.notify.mail.enabled ? (c.notify.mail.to || []).join(", ") : t("common.off")),
      h("div", null, t("wiz.agents.title")), h("div", null, (S.cfg.agents || []).map(a => a.name).join(", ") || "–")));
  } else {
    renderSection(sec, pending, body);
  }
  const nav = h("div", { class: "row wiznav" },
    idx > 0 ? h("button", { class: "btn", onclick: async () => { try { await flush(pending); location.hash = "#/wizard?step=" + (idx - 1); } catch (e) { toast(e.message, true); } } }, t("wizard.back")) : null,
    idx < secs.length - 1 ? h("button", { class: "btn primary", onclick: async () => {
      try { await flush(pending); location.hash = "#/wizard?step=" + (idx + 1); } catch (e) { toast(e.message, true); }
    } }, t("wizard.next")) : h("button", { class: "btn primary", onclick: async () => {
      try { await api("POST", "/api/wizard/complete"); S.session.setup_complete = true; toast(t("wizard.done")); location.hash = "#/overview"; await boot(); }
      catch (e) { toast(e.message, true); }
    } }, t("wizard.finish")));
  body.appendChild(nav);
}

boot().catch(e => { clear(document.getElementById("root")).appendChild(h("div", { class: "empty err-text" }, String(e))); });
