/* TripWire web: shared helpers. Every value from the server is inserted as text, never as HTML. */
"use strict";
const TW = (() => {
  const $ = (id) => document.getElementById(id);

  // h("div", {class: "x", onclick: fn}, child, "text", [more]) -> Element
  function h(tag, attrs, ...kids) {
    const el = document.createElementNS(tag === "svg" || (attrs && attrs.svg) ? "http://www.w3.org/2000/svg" : "http://www.w3.org/1999/xhtml", tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false || k === "svg") continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "class") el.setAttribute("class", v);
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    add(el, kids);
    return el;
  }
  function add(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k === null || k === undefined || k === false) continue;
      el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
    }
  }
  function fill(target, ...kids) {
    const el = typeof target === "string" ? $(target) : target;
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
    add(el, kids);
  }

  let toastTimer = 0;
  function toast(msg, err) {
    let t = $("toast");
    if (!t) { t = h("div", {id: "toast", class: "toast", role: "status"}); document.body.appendChild(t); }
    t.textContent = msg;
    t.className = "toast show" + (err ? " err" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = "toast" + (err ? " err" : ""); }, err ? 4200 : 2600);
  }

  async function api(path, body) {
    const opt = body === undefined ? {} : {method: "POST", body: JSON.stringify(body),
      headers: {"Content-Type": "application/json", "X-TripWire-Client": "dashboard"}};
    const r = await fetch(path, opt);
    let data = {};
    try { data = await r.json(); } catch (e) { throw new Error("server returned " + r.status); }
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    if (data.state) setFirewall(data.state.firewall.mode);
    return data;
  }

  let busy = false;
  async function act(path, body, okMsg) {
    if (busy) return null;
    busy = true; document.body.style.cursor = "progress";
    try {
      const d = await api(path, body || {});
      if (okMsg) toast(typeof okMsg === "function" ? okMsg(d) : okMsg);
      return d;
    } catch (e) { toast(e.message, true); return null; }
    finally { busy = false; document.body.style.cursor = ""; }
  }

  function setFirewall(mode) {
    const p = $("fwPill");
    if (!p) return;
    p.className = "fw " + mode;
    fill(p.querySelector("span"), mode === "OFFLINE" ? "SERVER OFFLINE" : "FIREWALL " + mode);
  }

  // shared top navigation
  function nav(active) {
    const links = [["/", "Home", "home"], ["/demo", "Live demo", "demo"], ["/arena", "Attack arena", "arena"],
                   ["/evidence", "Evidence", "evidence"]];
    const menu = h("nav", {class: "navlinks", id: "navlinks"},
      links.map(([href, label, key]) => h("a", {href, class: key === active ? "on" : null}, label)));
    const bar = h("header", {class: "nav"}, h("div", {class: "wrap"},
      h("a", {class: "brand", href: "/", "aria-label": "TripWire home"}, h("span", {class: "mark"}), "TRIPWIRE"),
      menu,
      h("div", {class: "navright"},
        h("a", {class: "fw", id: "fwPill", href: "/arena", title: "Live firewall state"}, h("i"), h("span", null, "FIREWALL ...")),
        active === "demo" ? null : h("a", {class: "btn primary navcta", href: "/demo"}, "Run demo ↗"),
        h("button", {class: "menu", "aria-label": "Menu", onclick: () => menu.classList.toggle("open")}, "Menu"))));
    document.body.prepend(bar);
    document.body.appendChild(h("footer", {class: "footer"}, h("div", {class: "wrap"},
      h("div", null, h("b", null, "TRIPWIRE"), "  ·  Constrain → Enforce → Prove  ·  Team HELLCODE  ·  HackInverse 1.0"),
      h("div", null, "Local · offline · synthetic data · no email or upload ever leaves this machine"))));
  }

  async function health() {
    try { const r = await fetch("/api/health"); const d = await r.json(); setFirewall(d.firewall); return d; }
    catch (e) { setFirewall("OFFLINE"); return null; }
  }

  // tiny line icons (own drawings), stroke = currentColor
  const ICONS = {
    shield: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z",
    db: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zm0 0v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
    spark: "M12 3v5M12 16v5M3 12h5M16 12h5M6 6l3 3M15 15l3 3M18 6l-3 3M9 15l-3 3",
    bolt: "M13 2L4 14h7l-1 8 9-12h-7z",
    lock: "M6 11h12v10H6zM8 11V7a4 4 0 018 0v4",
    eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zm10 3a3 3 0 100-6 3 3 0 000 6z",
    doc: "M6 2h9l5 5v15H6zM14 2v6h6M9 13h8M9 17h6",
    mail: "M3 5h18v14H3zM3 6l9 7 9-7",
    chain: "M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1",
    arrow: "M5 12h14M13 6l6 6-6 6",
  };
  function icon(name, size) {
    const s = size || 16;
    return h("svg", {viewBox: "0 0 24 24", width: s, height: s, fill: "none", stroke: "currentColor",
      "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true"},
      h("path", {svg: true, d: ICONS[name] || ICONS.shield}));
  }

  const fmtINR =(n) => "₹" + Number(n || 0).toLocaleString("en-IN");
  const time = (t) => t ? new Date(t * 1000).toLocaleTimeString([], {hour12: false}) : "";
  const pretty = (s) => String(s || "").replace(/_/g, " ");

  return {$, h, fill, toast, api, act, nav, health, setFirewall, icon, fmtINR, time, pretty, get busy() { return busy; }};
})();
