// OPNGate ui workspace.
"use strict";
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
