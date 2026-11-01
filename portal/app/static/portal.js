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
  let paused = false, busy = false, last = Date.now(), failed = false;
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
      : `Last updated ${new Date(last).toISOString().replace("T", " ").slice(0, 19)} UTC. All graph times are UTC.`;
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
      main.innerHTML = html;
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

document.addEventListener("DOMContentLoaded", () => {
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
