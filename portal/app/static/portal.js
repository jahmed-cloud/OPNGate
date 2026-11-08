// OPNGate application bootstrap. Workspace scripts are deferred in dependency order.
"use strict";
document.addEventListener("DOMContentLoaded", () => {
  bindMenus();
  bindNavigation();
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
