// WebAuthn glue and small UI behaviour. No inline scripts (CSP: script-src 'self').
"use strict";

const b64uToBuf = (s) => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const csrf = () => document.querySelector('meta[name="csrf"]')?.content || "";

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf(), Accept: "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) throw new Error(data.detail || data.error || `Request failed (${res.status})`);
  return data;
}

function requestOptions(json) {
  const o = { ...json, challenge: b64uToBuf(json.challenge) };
  if (json.allowCredentials) o.allowCredentials = json.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  return o;
}

function creationOptions(json) {
  return {
    ...json,
    challenge: b64uToBuf(json.challenge),
    user: { ...json.user, id: b64uToBuf(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}

function assertionJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      authenticatorData: bufToB64u(r.authenticatorData),
      signature: bufToB64u(r.signature),
      userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

function attestationJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      attestationObject: bufToB64u(r.attestationObject),
      transports: r.getTransports ? r.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

function showError(id, err) {
  const el = document.getElementById(id);
  if (!el) return alert(err.message || err);
  el.textContent = err.name === "NotAllowedError" ? "Cancelled or timed out." : (err.message || String(err));
  el.classList.remove("hidden");
}

async function getAssertion(beginUrl) {
  const opts = await postJSON(beginUrl);
  const cred = await navigator.credentials.get({ publicKey: requestOptions(opts) });
  return assertionJSON(cred);
}

function bind(id, handler) {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener("click", async (ev) => {
    ev.preventDefault();
    el.disabled = true;
    try { await handler(el); } finally { el.disabled = false; }
  });
}

// Reconcile server fragments in place. Unchanged subtrees retain DOM identity, focus and SVG state.
function patchNode(current, next, allowOwned = false) {
  if (!allowOwned && current.nodeType === 1 && next.nodeType === 1 && current.hasAttribute("data-client-owned") && next.hasAttribute("data-client-owned")) return current;
  if (current.isEqualNode(next)) return current;
  if (current.nodeType !== next.nodeType || current.nodeName !== next.nodeName) {
    const replacement = next.cloneNode(true); current.replaceWith(replacement); return replacement;
  }
  if (current.nodeType !== 1) { current.nodeValue = next.nodeValue; return current; }
  for (const attr of [...current.attributes]) if (!next.hasAttribute(attr.name)) current.removeAttribute(attr.name);
  for (const attr of [...next.attributes]) if (current.getAttribute(attr.name) !== attr.value) current.setAttribute(attr.name, attr.value);
  patchChildren(current, next);
  return current;
}
function patchChildren(current, next) {
  const key = (node) => node.nodeType === 1 ? node.getAttribute("data-refresh-section") || node.id : null;
  const keyed = new Map([...current.childNodes].filter(key).map((node) => [key(node), node]));
  let cursor = current.firstChild;
  for (const incoming of [...next.childNodes]) {
    const id = key(incoming);
    let match = id ? keyed.get(id) : cursor && !key(cursor) ? cursor : null;
    if (match) {
      if (match !== cursor) current.insertBefore(match, cursor);
      cursor = patchNode(match, incoming).nextSibling;
    } else {
      current.insertBefore(incoming.cloneNode(true), cursor);
    }
  }
  while (cursor) { const following = cursor.nextSibling; cursor.remove(); cursor = following; }
}
function patchFragment(main, html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  patchChildren(main, template.content);
}
function liveRate(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "—";
  let n = Number(value);
  for (const unit of ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"]) {
    if (n < 1000) return `${n.toFixed(unit === "bit/s" ? 0 : 1)} ${unit}`;
    n /= 1000;
  }
  return `${n.toFixed(1)} Tbit/s`;
}
function matchingLiveClient(client, dataset) {
  return client && client.mac === dataset.liveClient && client.ip === dataset.clientIp && client.segment === dataset.clientSegment ? client : null;
}
function flowLevel(rate, stale) {
  return stale || typeof rate !== "number" || !Number.isFinite(rate) || rate < 2000 ? 0 : rate < 1e6 ? 1 : rate < 25e6 ? 2 : 3;
}
// Real observations only: a bounded browser-session window; long gaps break the lines.
function liveSeries(points, end) {
  const start = end - 180;
  const visible = points.filter((p) => p.ts >= start && p.ts <= end);
  const values = visible.flatMap((p) => [p.rx, p.tx]).filter((v) => Number.isFinite(v) && v >= 0);
  const high = Math.max(1000, ...values);
  const step = 10 ** Math.floor(Math.log10(high));
  const ceiling = Math.ceil(high / step) * step;
  const path = (field) => {
    let previous = null, d = "";
    for (const p of visible) {
      if (!Number.isFinite(p[field]) || p[field] < 0) { previous = null; continue; }
      const x = 80 + (p.ts - start) / 180 * 880, y = 146 - p[field] / ceiling * 120;
      const join = previous !== null && p.ts - previous <= 10;
      d += `${join ? " L" : " M"}${x.toFixed(1)} ${y.toFixed(1)}`;
      // Round line caps make an isolated sample visible, without bridging missing reports.
      if (!join) d += " l0.01 0";
      previous = p.ts;
    }
    return d.trim();
  };
  return { rx: path("rx"), tx: path("tx"), ceiling, count: visible.length, start, end };
}
function paintLiveGraph(points) {
  const graph = document.getElementById("live-wan-chart");
  if (!graph) return;
  const data = liveSeries(points, Math.max(Date.now() / 1000, points.length ? points[points.length - 1].ts : 0));
  const set = (selector, value, attr) => {
    const node = graph.querySelector(selector);
    if (attr) { if (node.getAttribute(attr) !== value) node.setAttribute(attr, value); }
    else if (node.textContent !== value) node.textContent = value;
  };
  set(".traffic-line.down", data.rx, "d"); set(".traffic-line.up", data.tx, "d");
  set("[data-live-ceiling]", liveRate(data.ceiling)); set("[data-live-half]", liveRate(data.ceiling / 2));
  const time = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  set("[data-live-start]", time(data.start)); set("[data-live-end]", time(data.end));
  set("[data-live-empty]", data.count < 2 ? "Collecting live samples…" : "");
  set("title", `Live WAN rates. ${data.count} observed reports in the last three minutes; scale 0 to ${liveRate(data.ceiling)}.`);
}
// Polling never counts as user activity for the idle timeout.
function startLive() {
  const main = document.getElementById("main");
  const every = parseInt(main?.dataset.refresh || "0", 10);
  if (!main || !every) return;
  const fast = !!main.querySelector("[data-live-rate], [data-live-client-rate]");
  const chip = document.getElementById("live"), text = document.getElementById("live-text");
  let paused = false, busy = false, liveBusy = false, last = Date.now(), failed = false, liveFailed = false, snapshot = null;
  const livePoints = [];
  let flowController = null;
  let stream = null, streamConnected = false, streamOpenedAt = 0, lastStreamAt = 0, streamRetryAt = 0;
  try { paused = localStorage.getItem("portal-live-paused") === "1"; } catch (_) {}
  const userBusy = () => {
    const a = document.activeElement;
    return (a && main.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName))
      || main.querySelector("details[open]") || String(window.getSelection() || "").length > 0;
  };
  const setText = (el, value) => { if (el.textContent !== value) el.textContent = value; };
  const paintSnapshot = () => {
    if (!snapshot) {
      if (liveFailed) main.querySelectorAll("[data-live-status]").forEach((el) => setText(el, "Rate update failed; showing the page snapshot."));
      return;
    }
    main.querySelectorAll("[data-live-rate]").forEach((el) => {
      const iface = el.dataset.liveInterface;
      const data = iface === undefined ? snapshot.wan : snapshot.interfaces?.find((i) => i.name === iface);
      setText(el, (el.dataset.livePrefix || "") + liveRate(data?.[el.dataset.liveRate]));
    });
    const clients = new Map((snapshot.clients || []).map(client => [client.mac, client]));
    const deviceAge = snapshot.clients_reported_at ? Date.now() / 1000 - snapshot.clients_reported_at : Infinity;
    const staleDevices = snapshot.clients_stale || deviceAge >= 5 || liveFailed;
    main.classList.toggle("device-rates-stale", staleDevices);
    main.querySelectorAll("[data-live-client-rate]").forEach(el => {
      const client = matchingLiveClient(clients.get(el.dataset.liveClient), el.dataset);
      setText(el, liveRate(client?.[el.dataset.liveClientRate]));
    });
    main.querySelectorAll("[data-flow-client-rate]").forEach(el => {
      const client = matchingLiveClient(clients.get(el.dataset.liveClient), el.dataset);
      const level = flowLevel(client?.[el.dataset.flowClientRate], staleDevices);
      for (let n = 0; n <= 3; n++) el.classList.toggle(`lvl-${n}`, n === level);
    });
    main.querySelectorAll("[data-live-device-status]").forEach(el => setText(el,
      snapshot.clients_reported_at ? `Device rates reported ${Math.max(0, Math.floor(deviceAge))} s ago${staleDevices ? " · stale" : ""}. Firewall-observed traffic; names and policy states refresh every 30 s.`
      : "Live device counters unavailable. Names and policy states refresh every 30 s."));
    const ceiling = Math.max(1, ...(snapshot.interfaces || []).flatMap(i => [i.rx_bps, i.tx_bps]).filter(v => typeof v === "number" && Number.isFinite(v)));
    main.querySelectorAll("[data-live-bars]").forEach(svg => {
      const iface = snapshot.interfaces?.find(i => i.name === svg.dataset.liveBars);
      const wan = svg.dataset.barsWan === "true";
      for (const [lane, field] of [["down", wan ? "rx_bps" : "tx_bps"], ["up", wan ? "tx_bps" : "rx_bps"]]) {
        const bar = svg.querySelector(`rect.${lane}`), value = iface?.[field];
        const width = typeof value === "number" && Number.isFinite(value) ? Math.min(200, Math.max(0, value) / ceiling * 200).toFixed(1) : "0";
        if (bar && bar.getAttribute("width") !== width) bar.setAttribute("width", width);
      }
    });
    const rateAge = snapshot.reported_at ? Date.now() / 1000 - snapshot.reported_at : Infinity;
    const staleRates = snapshot.stale || rateAge >= (snapshot.source === "live" ? 5 : 120);
    main.querySelectorAll(".flow-wrap").forEach(el => el.classList.toggle("stale-flow", staleRates || liveFailed));
    main.querySelectorAll("[data-flow-rate]").forEach(el => {
      const iface = snapshot.interfaces?.find(i => i.name === el.dataset.flowInterface);
      const rate = iface?.[el.dataset.flowRate];
      const level = flowLevel(rate, staleRates || liveFailed);
      for (let n = 0; n <= 3; n++) el.classList.toggle(`lvl-${n}`, n === level);
    });
    const gatewayAge = snapshot.telemetry_reported_at ? Date.now() / 1000 - snapshot.telemetry_reported_at : Infinity;
    const state = snapshot.gateway_stale || gatewayAge >= 120 ? "stale" : snapshot.gateway?.online === true ? "online" : snapshot.gateway?.online === false ? "offline" : "unknown";
    main.querySelectorAll("[data-gateway-status]").forEach(el => setText(el, state));
    main.querySelectorAll("[data-flow-gateway]").forEach(el => {
      el.classList.toggle("ok", state === "online"); el.classList.toggle("bad", state === "offline");
      el.classList.toggle("unknown", state !== "online" && state !== "offline");
    });
    const age = snapshot.reported_at ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.reported_at)) : null;
    main.querySelectorAll("[data-live-status]").forEach((el) => setText(el,
      liveFailed ? "Rate update failed; showing last known values."
      : `Rates reported ${age === null ? "at an unknown time" : age + " s ago"}${snapshot.stale || age >= (snapshot.source === "telemetry" ? 120 : 5) ? " · stale" : ""}${snapshot.source === "telemetry" ? " · full-report fallback (30 s)" : ""}.`));
  };
  const label = () => {
    main.classList.toggle("live-paused", paused);
    if (chip) {
      chip.classList.toggle("paused", paused); chip.classList.toggle("error", (failed || liveFailed) && !paused);
      if (text) setText(text, paused ? "Paused" : failed || liveFailed ? "Retrying" : "Live");
      chip.setAttribute("aria-pressed", String(!paused));
      chip.title = `Click to ${paused ? "resume" : "pause"} updates.`;
    }
    const status = document.getElementById("refresh-status");
    if (status) setText(status, paused ? "Automatic updates paused. Use Refresh for a manual update."
      : failed ? "History refresh failed; displayed history may be stale."
      : `${fast ? streamConnected && Date.now() - lastStreamAt < 4000 ? "Live stream · 1 s · " : "Live JSON fallback · 1 s · " : ""}History/details refresh every ${every} s · last refreshed ${new Date(last).toLocaleTimeString()}. Times shown in ${status.dataset.tz || "your time zone"}.`);
    paintSnapshot();
    if (fast && !paused && !document.hidden && !userBusy()) paintLiveGraph(livePoints);
  };
  async function request(url, json, controller = new AbortController()) {
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const res = await fetch(url, { signal: controller.signal, credentials: "same-origin", cache: "no-store",
        headers: { "X-Auto-Refresh": "1", Accept: json ? "application/json" : "text/html", ...(json && snapshot?.revision ? { "X-Live-Revision": snapshot.revision } : {}) } });
      if (res.status === 401 || (res.redirected && new URL(res.url).pathname === "/login")) { window.location.reload(); return null; }
      if (res.status === 204) return snapshot;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await (json ? res.json() : res.text());
    } finally { clearTimeout(timeout); }
  }
  async function tick(force = false) {
    if (busy || (!force && paused) || document.hidden || userBusy()) return;
    busy = true;
    const expanded = flowOpen();
    try {
      const html = await request(window.location.href, false);
      if (html === null || userBusy() || document.hidden || (!force && paused) || expanded !== flowOpen()) return;
      patchFragment(main, html); placeFlowControls(); watchFlow();
      last = Date.now(); failed = false; paintSnapshot();
    } catch (_) { failed = true; }
    finally { busy = false; label(); }
  }
  async function tickRates(force = false) {
    if (!fast || liveBusy || (!force && paused) || document.hidden) return;
    liveBusy = true;
    try {
      const data = await request("/api/live", true);
      if (!data || document.hidden || (!force && paused)) return;
      acceptSnapshot(data);
    } catch (_) { liveFailed = true; }
    finally { liveBusy = false; label(); }
  }
  function acceptSnapshot(data) {
    if (!data || !Array.isArray(data.interfaces) || !data.revision) throw new Error("Invalid live snapshot");
    if (snapshot?.reported_at > data.reported_at) return;
    snapshot = data; liveFailed = false;
    const ts = Number(data.reported_at);
    if (ts > 0 && (!livePoints.length || ts > livePoints[livePoints.length - 1].ts)) {
      const numeric = v => typeof v === "number" && Number.isFinite(v) ? v : null;
      livePoints.push({ts, rx:numeric(data.wan?.rx_bps), tx:numeric(data.wan?.tx_bps)});
      while (livePoints.length > 180 || (livePoints.length && livePoints[0].ts < ts - 180)) livePoints.shift();
    }
    label();
  }
  function closeStream() {
    const previous = stream; stream = null; streamConnected = false;
    previous?.close();
  }
  function openStream() {
    if (!fast || stream || paused || document.hidden || Date.now() < streamRetryAt || typeof EventSource !== "function") return;
    const source = new EventSource("/api/live/stream"); stream = source; streamOpenedAt = Date.now();
    source.onopen = () => { if (source === stream) streamConnected = true; };
    source.addEventListener("telemetry", event => {
      if (source !== stream) return;
      if (paused || document.hidden) { closeStream(); return; }
      try { acceptSnapshot(JSON.parse(event.data)); lastStreamAt = Date.now(); }
      catch (_) { liveFailed = true; closeStream(); streamRetryAt = Date.now() + 3000; }
    });
    source.addEventListener("auth", () => { closeStream(); window.location.reload(); });
    source.addEventListener("reconnect", () => { closeStream(); streamRetryAt = 0; openStream(); });
    source.onerror = () => {
      if (source !== stream) return;
      closeStream(); streamRetryAt = Date.now() + 3000; liveFailed = true; tickRates();
    };
  }
  async function tickFlow(force = false) {
    const panel = document.getElementById("flow-panel");
    if (!panel || (!force && paused) || document.hidden || userBusy()) return;
    flowController?.abort();
    const controller = new AbortController(); flowController = controller;
    const expanded = flowOpen(); panel.setAttribute("aria-busy", "true");
    try {
      const html = await request("/api/flow", false, controller);
      if (html === null || controller !== flowController || expanded !== flowOpen() || document.hidden || (!force && paused) || userBusy()) return;
      const template = document.createElement("template"); template.innerHTML = html;
      const fresh = template.content.querySelector("#flow-panel");
      if (!fresh) throw new Error("Missing network map");
      patchNode(panel, fresh, true); placeFlowControls(); watchFlow(); paintSnapshot();
    } catch (error) {
      if (controller === flowController) {
        const status = panel.querySelector("[data-flow-load-status]");
        if (status) setText(status, "Network view update failed. Use Refresh to retry.");
      }
    } finally { if (controller === flowController) panel.removeAttribute("aria-busy"); }
  }
  const refresh = () => { tick(true); tickRates(true); tickFlow(true); openStream(); };
  chip?.addEventListener("click", () => {
    paused = !paused;
    try { localStorage.setItem("portal-live-paused", paused ? "1" : "0"); } catch (_) {}
    if (paused) closeStream();
    label(); if (!paused) refresh();
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) closeStream(); else if (!paused) refresh(); });
  window.addEventListener("pagehide", closeStream);
  document.getElementById("refresh-now")?.addEventListener("click", refresh);
  document.addEventListener("portal:refresh", () => tick(true));
  document.addEventListener("portal:flow", () => tickFlow(true));
  setInterval(() => tick(), every * 1000);
  if (fast) {
    setInterval(() => {
      if (paused || document.hidden) { closeStream(); return; }
      if (stream && !streamConnected && Date.now() - streamOpenedAt > 10000) { closeStream(); streamRetryAt = Date.now() + 3000; }
      openStream();
      if (!streamConnected || Date.now() - lastStreamAt > 3000) tickRates();
    }, 1000);
    openStream(); tickRates();
  }
  if (document.getElementById("flow-panel")) setInterval(() => tickFlow(), 30000);
  setInterval(label, fast ? 1000 : 5000); label();
}

// Tell the server the browser's time zone (a plain "tz" cookie) so pages show local times.
// Reload once when it changes; the sessionStorage flag stops a loop if cookies are blocked.
function syncTimeZone() {
  let tz = "";
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) { return; }
  if (!/^[A-Za-z0-9_+\-\/]{1,64}$/.test(tz)) return;
  const current = (document.cookie.match(/(?:^|; )tz=([^;]*)/) || [])[1];
  if (current && decodeURIComponent(current) === tz) return;
  document.cookie = `tz=${encodeURIComponent(tz)}; path=/; max-age=31536000; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
  try {
    if (sessionStorage.getItem("portal-tz") === tz) return;
    sessionStorage.setItem("portal-tz", tz);
  } catch (_) { return; }
  window.location.reload();
}

function bindThemeToggle() {
  const button = document.getElementById("theme-toggle");
  if (!button) return;
  const names = { "": "Theme: follows your system", light: "Theme: light", dark: "Theme: dark" };
  const show = () => { button.title = names[document.documentElement.dataset.theme || ""] + ". Click to change."; };
  button.addEventListener("click", () => {
    const next = { "": "light", light: "dark", dark: "" }[document.documentElement.dataset.theme || ""];
    if (next) document.documentElement.dataset.theme = next;
    else delete document.documentElement.dataset.theme;
    try { next ? localStorage.setItem("portal-theme", next) : localStorage.removeItem("portal-theme"); } catch (_) { /* storage blocked */ }
    show();
  });
  show();
}

// Row menus (Clients > Manage) live inside a scrolling table, which would clip them, so the open
// panel is placed against the window instead. Delegated, because live refresh replaces the table.
// Each device card on the flow map gets an invisible hit area that opens its Manage menu.
// data-top/data-h are % of the SVG's height; set through the CSSOM because the CSP forbids inline styles.
function placeFlowControls() {
  document.querySelectorAll(".flow-ctrl[data-top]").forEach((el) => {
    el.style.top = `${el.dataset.top}%`;
    el.style.height = `${el.dataset.h}%`;
  });
}

function bindMenus() {
  const closeAll = (except) => document.querySelectorAll("details.menu[open]").forEach((d) => { if (d !== except) d.open = false; });
  document.addEventListener("toggle", (ev) => {
    const menu = ev.target;
    if (!(menu instanceof HTMLDetailsElement) || !menu.classList.contains("menu") || !menu.open) return;
    closeAll(menu);
    const panel = menu.querySelector(".menu-panel");
    const box = menu.querySelector("summary").getBoundingClientRect();
    panel.style.position = "fixed";
    panel.style.left = `${Math.max(8, Math.min(box.right, window.innerWidth - 8) - panel.offsetWidth)}px`;
    // Below the button if it fits, else above, else pinned inside the window (the panel scrolls itself).
    const below = box.bottom + 6, above = box.top - panel.offsetHeight - 6;
    const top = below + panel.offsetHeight <= window.innerHeight - 8 ? below
      : above >= 8 ? above : Math.max(8, window.innerHeight - 8 - panel.offsetHeight);
    panel.style.top = `${top}px`;
    panel.querySelector("button, input, select")?.focus({ preventScroll: true });
  }, true);
  document.addEventListener("click", (ev) => { if (!ev.target.closest("details.menu")) closeAll(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeAll(); });
  window.addEventListener("resize", () => closeAll());
  document.addEventListener("scroll", (ev) => { if (!ev.target.closest?.(".menu-panel")) closeAll(); }, true);
}

document.addEventListener("DOMContentLoaded", () => {
  bindMenus();
  placeFlowControls();
  bindThemeToggle();
  syncTimeZone();
  startLive();
  if (!window.PublicKeyCredential) {
    document.querySelectorAll("#passkey-login, #stepup-passkey, #register-key, #approve-action")
      .forEach((b) => { b.disabled = true; b.title = "This browser does not support security keys"; });
  }

  bind("passkey-login", async (el) => {
    try {
      const credential = await getAssertion("/auth/passkey/begin");
      const res = await postJSON("/auth/passkey/finish", { credential, next: el.dataset.next || "/" });
      window.location.assign(res.redirect || "/");
    } catch (e) { showError("passkey-error", e); }
  });

  bind("stepup-passkey", async () => {
    try {
      const credential = await getAssertion("/security/stepup/passkey/begin");
      await postJSON("/security/stepup/passkey/finish", { credential });
      window.location.reload();
    } catch (e) { showError("wa-error", e); }
  });

  bind("register-key", async () => {
    try {
      const opts = await postJSON("/security/passkey/register/begin");
      const cred = await navigator.credentials.create({ publicKey: creationOptions(opts) });
      const name = document.getElementById("key-name")?.value || "Security key";
      await postJSON("/security/passkey/register/finish", { credential: attestationJSON(cred), name });
      window.location.assign("/security?ok=Key+added");
    } catch (e) { showError("wa-error", e); }
  });

  bind("approve-action", async (el) => {
    const id = el.dataset.action;
    try {
      const credential = await getAssertion(`/actions/${id}/begin`);
      await postJSON(`/actions/${id}/approve`, { credential });
      window.location.reload();
    } catch (e) { showError("wa-error", e); }
  });

  // Show only the fields that belong to the selected action.
  const typeSel = document.getElementById("action-type");
  if (typeSel) {
    const sync = () => {
      document.querySelectorAll("#action-form [data-for]").forEach((label) => {
        const on = label.dataset.for.split(" ").includes(typeSel.value);
        label.classList.toggle("hidden", !on);
        label.querySelectorAll("input, select").forEach((i) => { i.disabled = !on; });
      });
    };
    typeSel.addEventListener("change", sync);
    sync();
  }
});

// Chart hover: svg[data-tips] holds [x, (y,) label] per point in viewBox units. One guide line, one dot and
// one tooltip follow the pointer, instead of a dot and <title> per point.
const tipCache = new WeakMap();
let tipEl = null;
function chartTip(e) {
  const svg = e.target.closest && e.target.closest("svg[data-tips]");
  document.querySelectorAll("svg.hovering").forEach((s) => { if (s !== svg) s.classList.remove("hovering"); });
  if (!svg) { if (tipEl) tipEl.hidden = true; return; }
  const rawTips = svg.dataset.tips || "[]";
  let cached = tipCache.get(svg);
  if (!cached || cached.raw !== rawTips) {
    let tips;
    try { tips = JSON.parse(rawTips); } catch (_) { tips = []; }
    cached = { raw: rawTips, tips }; tipCache.set(svg, cached);
  }
  const tips = cached.tips;
  if (!tips.length) return;
  const box = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
  const x = (e.clientX - box.left) / box.width * vb.width;
  let lo = 0, hi = tips.length - 1;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (tips[mid][0] < x) lo = mid + 1; else hi = mid; }
  if (lo > 0 && x - tips[lo - 1][0] < tips[lo][0] - x) lo -= 1;
  const tip = tips[lo];
  const guide = svg.querySelector(".hover-guide"), dot = svg.querySelector(".hover-dot");
  guide?.setAttribute("x1", tip[0]); guide?.setAttribute("x2", tip[0]);
  if (dot && tip.length > 2) { dot.setAttribute("cx", tip[0]); dot.setAttribute("cy", tip[1]); }
  svg.classList.add("hovering");
  if (!tipEl) { tipEl = document.createElement("div"); tipEl.className = "chart-tip"; tipEl.setAttribute("role", "status"); document.body.appendChild(tipEl); }
  tipEl.textContent = tip[tip.length - 1];
  tipEl.hidden = false;
  const left = box.left + tip[0] / vb.width * box.width;
  const w = tipEl.offsetWidth;
  tipEl.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, left - w / 2)) + "px";
  tipEl.style.top = Math.max(8, box.top - tipEl.offsetHeight - 6) + "px";
}
// Coalesce fast pointer events into one chart/layout update per browser frame.
let hoverFrame = 0, hoverPointer = null;
document.addEventListener("pointermove", (event) => {
  hoverPointer = { target: event.target, clientX: event.clientX };
  if (!hoverFrame) hoverFrame = requestAnimationFrame(() => {
    hoverFrame = 0;
    chartTip(hoverPointer);
  });
}, { passive: true });
document.addEventListener("scroll", () => { if (tipEl) tipEl.hidden = true; }, { passive: true, capture: true });

// Stop the flow animations while the map is scrolled out of view.
let flowObserver = null;
function watchFlow() {
  if (!("IntersectionObserver" in window)) return;
  flowObserver?.disconnect();
  flowObserver = new IntersectionObserver((entries) => {
    entries.forEach((en) => en.target.classList.toggle("offscreen", !en.isIntersecting));
  });
  document.querySelectorAll(".flow-wrap").forEach((el) => flowObserver.observe(el));
}
watchFlow();
document.addEventListener("visibilitychange", () => document.documentElement.classList.toggle("page-hidden", document.hidden));
document.documentElement.classList.toggle("page-hidden", document.hidden);

// Flow map: networks start collapsed; clicking one shows (or hides) its devices. The choice lives in the
// flow_open cookie so live refreshes keep it, and only the clicked part of the map is rebuilt server-side.
function flowOpen() {
  const m = document.cookie.match(/(?:^|; )flow_open=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : "";
}
function setFlowOpen(value) {
  document.cookie = `flow_open=${encodeURIComponent(value)}; path=/; max-age=31536000; SameSite=Lax`;
  if (document.getElementById("main")?.dataset.refresh) document.dispatchEvent(new Event("portal:flow"));
  else window.location.reload();
}
document.addEventListener("click", (e) => {
  const all = e.target.closest && e.target.closest("[data-flow-all]");
  if (all) { setFlowOpen(all.dataset.flowAll); return; }
  const seg = e.target.closest && e.target.closest(".seg-toggle[data-segment]");
  if (!seg) return;
  e.preventDefault();
  const name = seg.dataset.segment;
  const names = document.querySelectorAll(".seg-toggle[data-segment]");
  let open = flowOpen() === "*" ? [...names].map((n) => n.dataset.segment) : flowOpen().split(",").filter(Boolean);
  open = open.includes(name) ? open.filter((n) => n !== name) : [...open, name];
  setFlowOpen(open.join(","));
});
document.addEventListener("keydown", (e) => {
  const seg = e.target.closest && e.target.closest(".seg-toggle[data-segment]");
  if (seg && e.key === " ") { e.preventDefault(); seg.dispatchEvent(new MouseEvent("click", { bubbles: true })); }
});
