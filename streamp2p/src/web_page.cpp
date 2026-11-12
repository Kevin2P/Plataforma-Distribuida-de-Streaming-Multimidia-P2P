#include "http.hpp"

namespace sp {

const char* dashboard_html() {
    return R"HTML(<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StreamP2P - painel do tracker</title>
<style>
:root { --bg:#fff; --card:#F1F3F6; --bar:#E3EEF7; --line:#A8BECE; --text:#282830; --muted:#6C7480; --head:#1F4E79; --none:#F9DCE0; --one:#C9DDF0; --many:#6F9FCC; }
* { box-sizing: border-box; }
body { margin:0; font-family: "Times New Roman", Georgia, serif; background:var(--bg); color:var(--text); }
header { background:var(--head); color:#fff; padding:18px 28px; display:flex; align-items:center; justify-content:space-between; }
header h1 { margin:0; font-size:26px; }
#status { font-size:15px; }
.dot { display:inline-block; width:11px; height:11px; border-radius:50%; margin-right:8px; background:#8fd19e; }
.dot.off { background:#e08a8a; }
main { padding:22px 28px; max-width:1200px; margin:0 auto; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(136px,1fr)); gap:14px; margin-bottom:22px; }
.tile { background:var(--bar); border:1px solid var(--line); border-radius:8px; padding:14px 16px; }
.tile .v { font-size:28px; font-weight:bold; }
.tile .k { color:var(--muted); font-size:14px; }
section { margin-bottom:26px; }
h2 { font-size:20px; margin:0 0 10px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:15px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-weight:normal; }
.empty { color:var(--muted); font-style:italic; }
.content { margin-bottom:14px; }
.content .meta { color:var(--muted); font-size:14px; margin-bottom:6px; }
.avail { display:flex; height:22px; border:1px solid var(--line); border-radius:4px; overflow:hidden; background:#fff; }
.avail div { flex:1; min-width:1px; }
.legend { font-size:13px; color:var(--muted); margin-top:6px; }
.legend span { display:inline-block; width:12px; height:12px; margin:0 4px 0 12px; vertical-align:middle; border:1px solid var(--line); }
#events { list-style:none; margin:0; padding:0; font-size:15px; max-height:260px; overflow-y:auto; }
#events li { padding:4px 0; border-bottom:1px solid var(--line); }
#events time { color:var(--muted); margin-right:10px; }
</style>
</head>
<body>
<header><h1>StreamP2P &middot; painel do tracker</h1><div id="status"><span class="dot off" id="dot"></span><span id="statustext">conectando...</span></div></header>
<main>
<div class="tiles" id="tiles"></div>
<section><h2>Peers conectados</h2><div class="card" id="peers"></div></section>
<section><h2>Conteúdos e disponibilidade por chunk</h2><div class="card" id="contents"></div></section>
<section><h2>Eventos recentes</h2><div class="card"><ul id="events"></ul></div></section>
</main>
<script>
"use strict";
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function fmtBytes(n) { const u = ["B","KiB","MiB","GiB"]; let i = 0, v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return (i ? v.toFixed(1).replace(".", ",") : v) + " " + u[i]; }
function fmtDur(ms) { const s = Math.floor(ms / 1000); if (s < 60) return s + " s"; const m = Math.floor(s / 60); return m + " min " + (s % 60) + " s"; }
function tile(k, v) { const t = el("div", undefined, "tile"); t.appendChild(el("div", String(v), "v")); t.appendChild(el("div", k, "k")); return t; }
function setDot(on, text) { document.getElementById("dot").className = "dot" + (on ? "" : " off"); document.getElementById("statustext").textContent = text; }
function render(s) {
  const tiles = document.getElementById("tiles"); tiles.replaceChildren();
  let up = 0, down = 0; for (const p of s.peers) { up += p.uploaded; down += p.downloaded; }
  tiles.append(tile("peers online", s.peers.length), tile("conteúdos", s.contents.length), tile("enviado pelos peers", fmtBytes(up)),
    tile("recebido pelos peers", fmtBytes(down)), tile("peers expirados", s.stats.expired), tile("autenticações recusadas", s.stats.auth_failures), tile("tempo no ar", fmtDur(s.uptime_ms)));
  const peers = document.getElementById("peers"); peers.replaceChildren();
  if (!s.peers.length) peers.appendChild(el("div", "nenhum peer registrado", "empty"));
  else {
    const t = el("table"); const h = el("tr");
    for (const c of ["id","endereço","TCP","UDP","último sinal","enviado","recebido","conteúdos (chunks)"]) h.appendChild(el("th", c));
    t.appendChild(h);
    for (const p of s.peers) {
      const r = el("tr");
      const held = p.contents.map(c => c.have + "/" + c.total).join(", ") || "-";
      for (const v of [p.id, p.host, p.tcp_port, p.udp_port, fmtDur(p.age_ms) + " atrás", fmtBytes(p.uploaded), fmtBytes(p.downloaded), held]) r.appendChild(el("td", String(v)));
      t.appendChild(r);
    }
    peers.appendChild(t);
  }
  const contents = document.getElementById("contents"); contents.replaceChildren();
  if (!s.contents.length) contents.appendChild(el("div", "nenhum conteúdo publicado", "empty"));
  for (const c of s.contents) {
    const box = el("div", undefined, "content");
    box.appendChild(el("strong", c.name));
    box.appendChild(el("div", fmtBytes(c.size) + " · " + c.chunks + " chunks de " + fmtBytes(c.chunk_size) + " · " + c.bitrate_kbps + " kbit/s · " + c.seeders + " seeders, " + c.holders + " com algum chunk · id " + c.id.slice(0, 12), "meta"));
    const bar = el("div", undefined, "avail");
    for (const n of c.availability) { const d = el("div"); d.style.background = n === 0 ? "var(--none)" : n === 1 ? "var(--one)" : "var(--many)"; d.title = n + " peer(s)"; bar.appendChild(d); }
    box.appendChild(bar);
    const lg = el("div", "cada faixa é um chunk (ou um grupo de chunks):", "legend");
    for (const [txt, col] of [["sem cópia","var(--none)"],["1 peer","var(--one)"],["2 ou mais","var(--many)"]]) { const sw = el("span"); sw.style.background = col; lg.append(sw, txt); }
    box.appendChild(lg); contents.appendChild(box);
  }
  const ev = document.getElementById("events"); ev.replaceChildren();
  for (const e of s.events.slice().reverse()) { const li = el("li"); li.appendChild(el("time", new Date(e.t).toLocaleTimeString())); li.appendChild(document.createTextNode(e.msg)); ev.appendChild(li); }
}
async function tick() {
  try { const r = await fetch("/api/status", { cache: "no-store" }); if (!r.ok) throw new Error(r.status); const s = await r.json(); render(s); setDot(true, "ao vivo"); }
  catch (e) { setDot(false, "sem resposta do tracker"); }
}
tick(); setInterval(tick, 1000);
</script>
</body>
</html>
)HTML";
}

}
