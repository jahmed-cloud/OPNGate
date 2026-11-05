// OPNGate credentials workspace.
"use strict";
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
