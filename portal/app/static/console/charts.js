// OPNGate charts workspace.
"use strict";
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
