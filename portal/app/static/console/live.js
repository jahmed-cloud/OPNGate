// OPNGate live workspace.
"use strict";
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
  set("title", `Live WAN rates. ${data.count} observed ${data.count === 1 ? "report" : "reports"} in the last three minutes; scale 0 to ${liveRate(data.ceiling)}.`);
}
// Polling never counts as user activity for the idle timeout.
function startLive() {
  const main = document.getElementById("main");
  const every = parseInt(main?.dataset.refresh || "0", 10);
  if (!main || !every) return;
  const fast = !!main.querySelector("[data-live-rate], [data-live-client-rate]");
  const chip = document.getElementById("live"), text = document.getElementById("live-text");
  let paused = false, busy = false, liveBusy = false, last = Date.now(), failed = false, liveFailed = false, snapshot = null;
  let paintScheduled = false, manualPaint = false;
  const nodeCache = new Map();
  const nodes = (selector) => {
    if (!nodeCache.has(selector)) nodeCache.set(selector, [...main.querySelectorAll(selector)]);
    return nodeCache.get(selector);
  };
  const livePoints = [];
  let flowController = null;
  let stream = null, streamConnected = false, streamOpenedAt = 0, lastStreamAt = 0, streamRetryAt = 0;
  try { paused = localStorage.getItem("portal-live-paused") === "1"; } catch (_) {}
  const userBusy = () => {
    const a = document.activeElement;
    return (a && main.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName))
      || [...main.querySelectorAll("details[open]")].some(el => !el.closest("details:not([open])"))
      || String(window.getSelection() || "").length > 0;
  };
  const setText = (el, value) => { if (el.textContent !== value) el.textContent = value; };
  const paintSnapshot = () => {
    if (!snapshot) {
      if (liveFailed) nodes("[data-live-status]").forEach((el) => setText(el, "Rate update failed; showing the page snapshot."));
      return;
    }
    nodes("[data-live-rate]").forEach((el) => {
      const iface = el.dataset.liveInterface;
      const data = iface === undefined ? snapshot.wan : snapshot.interfaces?.find((i) => i.name === iface);
      setText(el, (el.dataset.livePrefix || "") + liveRate(data?.[el.dataset.liveRate]));
    });
    const clients = new Map((snapshot.clients || []).map(client => [client.mac, client]));
    const deviceAge = snapshot.clients_reported_at ? Date.now() / 1000 - snapshot.clients_reported_at : Infinity;
    const staleDevices = snapshot.clients_stale || deviceAge >= 5 || liveFailed;
    main.classList.toggle("device-rates-stale", staleDevices);
    nodes("[data-live-client-rate]").forEach(el => {
      const client = matchingLiveClient(clients.get(el.dataset.liveClient), el.dataset);
      setText(el, liveRate(client?.[el.dataset.liveClientRate]));
    });
    nodes("[data-flow-client-rate]").forEach(el => {
      const client = matchingLiveClient(clients.get(el.dataset.liveClient), el.dataset);
      const level = flowLevel(client?.[el.dataset.flowClientRate], staleDevices);
      for (let n = 0; n <= 3; n++) el.classList.toggle(`lvl-${n}`, n === level);
    });
    nodes("[data-live-device-status]").forEach(el => setText(el,
      snapshot.clients_reported_at ? `Devices · ${Math.max(0, Math.floor(deviceAge))} s ago${staleDevices ? " · stale" : ""} · details every 30 s`
      : "Device rates unavailable · details every 30 s"));
    const ceiling = Math.max(1, ...(snapshot.interfaces || []).flatMap(i => [i.rx_bps, i.tx_bps]).filter(v => typeof v === "number" && Number.isFinite(v)));
    nodes("[data-live-bars]").forEach(svg => {
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
    nodes(".flow-wrap").forEach(el => el.classList.toggle("stale-flow", staleRates || liveFailed));
    nodes("[data-flow-rate]").forEach(el => {
      const iface = snapshot.interfaces?.find(i => i.name === el.dataset.flowInterface);
      const rate = iface?.[el.dataset.flowRate];
      const level = flowLevel(rate, staleRates || liveFailed);
      for (let n = 0; n <= 3; n++) el.classList.toggle(`lvl-${n}`, n === level);
    });
    const gatewayAge = snapshot.telemetry_reported_at ? Date.now() / 1000 - snapshot.telemetry_reported_at : Infinity;
    const state = snapshot.gateway_stale || gatewayAge >= 120 ? "stale" : snapshot.gateway?.online === true ? "online" : snapshot.gateway?.online === false ? "offline" : "unknown";
    nodes("[data-gateway-status]").forEach(el => setText(el, state));
    nodes("[data-flow-gateway]").forEach(el => {
      el.classList.toggle("ok", state === "online"); el.classList.toggle("bad", state === "offline");
      el.classList.toggle("unknown", state !== "online" && state !== "offline");
    });
    const age = snapshot.reported_at ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.reported_at)) : null;
    nodes("[data-live-status]").forEach((el) => setText(el,
      liveFailed ? "Rate update failed; showing last known values."
      : `Rates · ${age === null ? "time unknown" : age + " s ago"}${snapshot.stale || age >= (snapshot.source === "telemetry" ? 120 : 5) ? " · stale" : ""}${snapshot.source === "telemetry" ? " · full-report fallback (30 s)" : ""}`));
  };
  // Coalesce SSE + timer/fragment work into one paint. Cache mounted nodes until a fragment changes.
  const queuePaint = () => {
    if (paintScheduled) return;
    paintScheduled = true;
    requestAnimationFrame(() => {
      paintScheduled = false;
      if (document.hidden) return;
      paintSnapshot();
      if (fast && (!paused || manualPaint) && !userBusy()) paintLiveGraph(livePoints);
      manualPaint = false;
    });
  };
  const label = () => {
    main.classList.toggle("live-paused", paused);
    if (chip) {
      chip.classList.toggle("paused", paused); chip.classList.toggle("error", (failed || liveFailed) && !paused);
      if (text) setText(text, paused ? "Paused" : failed || liveFailed ? "Retrying" : "Live");
      chip.setAttribute("aria-pressed", String(!paused));
      chip.setAttribute("aria-label", `${paused ? "Resume" : "Pause"} automatic updates`);
      chip.title = `Click to ${paused ? "resume" : "pause"} updates.`;
    }
    const status = document.getElementById("refresh-status");
    if (status) setText(status.querySelector("[data-refresh-message]") || status, paused ? "Updates paused · use Refresh for a manual update"
      : failed ? "History refresh failed; displayed history may be stale."
      : `${fast ? streamConnected && Date.now() - lastStreamAt < 4000 ? "Live stream · 1 s" : stream ? "Connecting to live stream" : "Live JSON fallback · 1 s" : "Auto-update"} · details ${every} s · updated ${new Date(last).toLocaleTimeString()}`);
    queuePaint();
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
      patchFragment(main, html); nodeCache.clear(); placeFlowControls(); watchFlow();
      last = Date.now(); failed = false; queuePaint();
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
      patchNode(panel, fresh, true); nodeCache.clear(); placeFlowControls(); watchFlow(); queuePaint();
    } catch (error) {
      if (controller === flowController) {
        const status = panel.querySelector("[data-flow-load-status]");
        if (status) setText(status, "Network view update failed. Use Refresh to retry.");
      }
    } finally { if (controller === flowController) panel.removeAttribute("aria-busy"); }
  }
  const refresh = () => { openStream(); return Promise.allSettled([tick(true), tickRates(true), tickFlow(true)]); };
  chip?.addEventListener("click", () => {
    paused = !paused;
    try { localStorage.setItem("portal-live-paused", paused ? "1" : "0"); } catch (_) {}
    if (paused) closeStream();
    label(); if (!paused) refresh();
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) closeStream(); else if (!paused) refresh(); });
  window.addEventListener("pagehide", closeStream);
  const refreshButton = document.getElementById("refresh-now");
  refreshButton?.addEventListener("click", async () => {
    if (refreshButton.disabled) return;
    refreshButton.disabled = true; refreshButton.setAttribute("aria-busy", "true");
    try { await refresh(); manualPaint = true; queuePaint(); }
    finally { refreshButton.disabled = false; refreshButton.removeAttribute("aria-busy"); }
  });
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
