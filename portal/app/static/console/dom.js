// OPNGate dom workspace.
"use strict";
// Reconcile server fragments in place. Unchanged subtrees retain DOM identity, focus and SVG state.
function patchNode(current, next, allowOwned = false) {
  if (!allowOwned && current.nodeType === 1 && next.nodeType === 1 && current.hasAttribute("data-client-owned") && next.hasAttribute("data-client-owned")) return current;
  if (current.isEqualNode(next)) return current;
  if (current.nodeType !== next.nodeType || current.nodeName !== next.nodeName) {
    const replacement = next.cloneNode(true); current.replaceWith(replacement); return replacement;
  }
  if (current.nodeType !== 1) { current.nodeValue = next.nodeValue; return current; }
  for (const attr of [...current.attributes]) if (!next.hasAttribute(attr.name)) current.removeAttribute(attr.name);
  for (const attr of [...next.attributes]) if (current.getAttribute(attr.name) !== attr.value) current.setAttribute(attr.name, attr.value);
  patchChildren(current, next);
  return current;
}
function patchChildren(current, next) {
  const key = (node) => node.nodeType === 1 ? node.getAttribute("data-refresh-section") || node.id : null;
  const keyed = new Map([...current.childNodes].filter(key).map((node) => [key(node), node]));
  let cursor = current.firstChild;
  for (const incoming of [...next.childNodes]) {
    const id = key(incoming);
    let match = id ? keyed.get(id) : cursor && !key(cursor) ? cursor : null;
    if (match) {
      if (match !== cursor) current.insertBefore(match, cursor);
      cursor = patchNode(match, incoming).nextSibling;
    } else {
      current.insertBefore(incoming.cloneNode(true), cursor);
    }
  }
  while (cursor) { const following = cursor.nextSibling; cursor.remove(); cursor = following; }
}
function patchFragment(main, html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  patchChildren(main, template.content);
}
