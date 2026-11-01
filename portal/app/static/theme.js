// Applies the saved light/dark choice before the page paints (loaded without defer).
// No choice saved = follow the system setting. The toggle in the app bar cycles auto -> light -> dark.
"use strict";
(function () {
  let saved = "";
  try { saved = localStorage.getItem("portal-theme") || ""; } catch (_) { /* storage blocked */ }
  if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
})();
