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

function bindNavigation() {
  const toggle = document.getElementById("nav-toggle"), sidebar = document.getElementById("sidebar");
  const open = document.getElementById("nav-open"), close = document.getElementById("nav-close");
  const content = document.querySelector(".content");
  if (!toggle || !sidebar || !open || !close || !content) return;
  const narrow = window.matchMedia("(max-width: 960px)");
  const apply = (focus = false) => {
    const expanded = narrow.matches && toggle.checked;
    open.setAttribute("aria-expanded", String(expanded));
    sidebar.inert = narrow.matches && !expanded;
    content.inert = expanded;
    document.body.classList.toggle("nav-open", expanded);
    if (focus) (expanded ? close : open).focus({ preventScroll: true });
  };
  const setOpen = (value) => { toggle.checked = value; apply(true); };
  open.addEventListener("click", () => setOpen(!toggle.checked));
  close.addEventListener("click", () => setOpen(false));
  toggle.addEventListener("change", () => apply(true));
  narrow.addEventListener("change", () => { toggle.checked = false; apply(); });
  document.addEventListener("keydown", (event) => {
    if (!narrow.matches || !toggle.checked) return;
    if (event.key === "Escape") { event.preventDefault(); setOpen(false); }
    if (event.key !== "Tab") return;
    const items = [...sidebar.querySelectorAll("a[href], button:not([disabled])")].filter(el => el.getClientRects().length);
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  apply();
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
  const closeAll = (except, restoreFocus = false) => document.querySelectorAll("details.menu[open]").forEach((d) => {
    if (d === except) return;
    const returnFocus = restoreFocus && d.contains(document.activeElement);
    d.open = false;
    if (returnFocus) d.querySelector("summary")?.focus({ preventScroll: true });
  });
  const position = (menu) => {
    const panel = menu.querySelector(".menu-panel");
    const box = menu.querySelector("summary").getBoundingClientRect();
    panel.style.position = "fixed";
    panel.style.left = `${Math.max(8, Math.min(box.right, window.innerWidth - 8) - panel.offsetWidth)}px`;
    // Below the button if it fits, else above, else pinned inside the window (the panel scrolls itself).
    const below = box.bottom + 6, above = box.top - panel.offsetHeight - 6;
    const top = below + panel.offsetHeight <= window.innerHeight - 8 ? below
      : above >= 8 ? above : Math.max(8, window.innerHeight - 8 - panel.offsetHeight);
    panel.style.top = `${top}px`;
  };
  document.addEventListener("toggle", (ev) => {
    const target = ev.target;
    if (!(target instanceof HTMLDetailsElement)) return;
    const menu = target.closest("details.menu[open]");
    if (!menu) return;
    if (target === menu) closeAll(menu);
    position(menu);
  }, true);
  document.addEventListener("click", (ev) => { if (!ev.target.closest("details.menu")) closeAll(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeAll(null, true); });
  window.addEventListener("resize", () => closeAll());
  document.addEventListener("scroll", (ev) => { if (!ev.target.closest?.(".menu-panel")) closeAll(); }, true);
}
