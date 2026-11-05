// OPNGate flow workspace.
"use strict";
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
  // "*" means every network open, each showing its busiest devices; full lists ("<network>~all") only when asked for.
  let open = flowOpen() === "*" ? [...names].map((n) => n.dataset.segment).filter((n) => !n.endsWith("~all")) : flowOpen().split(",").filter(Boolean);
  open = open.includes(name) ? open.filter((n) => n !== name) : [...open, name];
  setFlowOpen(open.join(","));
});
document.addEventListener("keydown", (e) => {
  const seg = e.target.closest && e.target.closest(".seg-toggle[data-segment]");
  if (seg && e.key === " ") { e.preventDefault(); seg.dispatchEvent(new MouseEvent("click", { bubbles: true })); }
});
