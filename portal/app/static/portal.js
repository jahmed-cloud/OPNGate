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

// Live pages: re-fetch the page and swap <main>, unless the user is in the middle of something on it.
// The X-Auto-Refresh header keeps these fetches from counting as activity for the idle timeout.
function startLive() {
  const main = document.getElementById("main");
  const every = parseInt(main?.dataset.refresh || "0", 10);
  if (!main || !every) return;
  const chip = document.getElementById("live");
  const text = document.getElementById("live-text");
  let paused = false, busy = false, last = Date.now(), failed = false, lastHtml = "";
  try { paused = localStorage.getItem("portal-live-paused") === "1"; } catch (_) { /* storage blocked */ }

  const label = () => {
    if (!chip) return;
    chip.classList.toggle("paused", paused);
    chip.classList.toggle("error", failed && !paused);
    text.textContent = paused ? "Paused" : failed ? "Offline" : "Live";
    chip.setAttribute("aria-pressed", String(!paused));
    const status = document.getElementById("refresh-status");
    if (status) status.textContent = failed ? "Refresh failed. Displayed figures may be stale; use Refresh to retry."
      : paused ? "Automatic updates paused. Use Refresh for a manual update."
      : `Last updated ${new Date(last).toLocaleTimeString()}. Times shown in ${status.dataset.tz || "your time zone"}.`;
    const age = Math.round((Date.now() - last) / 1000);
    chip.title = paused ? "Live updates paused. Click to resume."
      : `Updated ${age < 5 ? "just now" : age + " s ago"}; refreshes every ${every} s. Click to pause.`;
  };
  const userBusy = () => {
    const a = document.activeElement;
    return (a && main.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName))
      || main.querySelector("details[open]") || String(window.getSelection() || "").length > 0;
  };
  async function tick(force) {
    if (busy || (!force && paused) || document.hidden || userBusy()) return;
    busy = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const res = await fetch(window.location.href, { signal: controller.signal, credentials: "same-origin", headers: { "X-Auto-Refresh": "1" } });
      if (res.redirected && new URL(res.url).pathname === "/login") { window.location.reload(); return; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const html = await res.text();
      if (userBusy()) return;
      if (html !== lastHtml) {  // nothing new since the last report: leave the DOM alone
        lastHtml = html;
        main.innerHTML = html;
        placeFlowControls();
        watchFlow();
      }
      last = Date.now(); failed = false;
    } catch (_) {
      failed = true;
    } finally {
      clearTimeout(timeout);
      busy = false;
      label();
    }
  }

  chip?.addEventListener("click", () => {
    paused = !paused;
    try { localStorage.setItem("portal-live-paused", paused ? "1" : "0"); } catch (_) { /* storage blocked */ }
    label();
    if (!paused) tick(true);
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(true); });
  document.getElementById("refresh-now")?.addEventListener("click", () => tick(true));
  setInterval(() => tick(false), every * 1000);
  setInterval(label, 5000);
  label();
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
  let tips = tipCache.get(svg);
  if (!tips) { try { tips = JSON.parse(svg.dataset.tips || "[]"); } catch (_) { tips = []; } tipCache.set(svg, tips); }
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
document.addEventListener("pointermove", chartTip, { passive: true });
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
