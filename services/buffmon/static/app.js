// buffmon live dashboard. Data arrives over one WebSocket (/v1/live):
//   hello    -> thresholds, retention
//   backfill -> every session summary + all retained 1 s points
//   snapshot -> every session summary + points stored since the last message
// All text is set with textContent; nothing from the server is parsed as HTML.
(function () {
  "use strict";

  var STATUS_ORDER = ["bad", "degraded", "insufficient-samples", "good", "no-data"];
  var STATUS_LABEL = {
    bad: "Bad", degraded: "Degraded", "insufficient-samples": "Low samples", good: "Good", "no-data": "No data",
  };
  var STATUS_HELP = {
    "insufficient-samples": "Loss looks fine but too few packets have been sent to prove it is under target",
  };
  var KIND_LABEL = { stamp: "STAMP", tcp: "TCP", icmp: "Reachability" };
  var DSCP = { 0: "BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2", 18: "AF21", 20: "AF22", 22: "AF23",
    24: "CS3", 26: "AF31", 28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42", 38: "AF43", 40: "CS5",
    44: "VA", 46: "EF", 48: "CS6", 56: "CS7" };
  var SPARK_MS = 5 * 60 * 1000;
  var LIVE_MS = 15 * 60 * 1000;

  var S = {
    sessions: {}, list: [], series: {}, thresholds: null, retentionMs: 900000, paths: {}, pathsUnavailable: null, tunnels: [], routes: {}, speed: null, speedMsg: "",
    filterStatus: null, search: "", cls: "", kind: "", lastMsgAt: 0, retry: 0,
    open: null, histRange: "1h", histTimer: null, cards: {}, siteEls: {}, ever: false,
  };

  // ---------------------------------------------------------------- helpers
  var PATH_LABEL = {
    forward_dscp_mismatch: "DSCP re-marked → (probe may be on the wrong overlay)",
    return_dscp_mismatch: "DSCP re-marked on the return path"
  };
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function fmtMs(v) { return v == null ? "–" : BMChart.fmtMs(v); }
  function fmtPct(v) {
    if (v == null) return "–";
    if (v === 0) return "0";
    return v < 0.1 ? v.toFixed(3) : v < 10 ? v.toFixed(2) : v.toFixed(1);
  }
  function dscpName(d) { return (DSCP[d] || "DSCP") + "\u00a0" + d; }
  function target(s) { return s.kind === "icmp" ? s.dst.replace(/:0$/, "") : s.dst; }
  function ago(sec) {
    if (sec < 90) return Math.round(sec) + " s ago";
    if (sec < 5400) return Math.round(sec / 60) + " min ago";
    return Math.round(sec / 3600) + " h ago";
  }
  function classTh(s) {
    // The server resolves class + per-target override; prefer that.
    if (s.thresholds) return s.thresholds;
    var t = S.thresholds;
    if (!t) return null;
    return t.classes[s.effective_class] || t.classes[t.default_class] || null;
  }
  function grade(limit, v) {
    if (!limit || v == null) return "";
    return v > limit.bad ? "crit" : v > limit.good ? "warn" : "";
  }
  function store(key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* unavailable */ } }

  // ---------------------------------------------------------------- data
  function mergePoints(key, pts) {
    var arr = S.series[key] || (S.series[key] = []);
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      var n = arr.length;
      if (!n || p[0] > arr[n - 1][0]) { arr.push(p); continue; }
      var lo = 0, hi = n;
      while (lo < hi) { var mid = (lo + hi) >> 1; if (arr[mid][0] < p[0]) lo = mid + 1; else hi = mid; }
      if (lo < n && arr[lo][0] === p[0]) arr[lo] = p; else arr.splice(lo, 0, p);
    }
    var cut = arr.length ? arr[arr.length - 1][0] - S.retentionMs : 0;
    var drop = 0;
    while (drop < arr.length && arr[drop][0] < cut) drop++;
    if (drop) arr.splice(0, drop);
  }

  function setSessions(list) {
    S.list = list;
    var next = {};
    list.forEach(function (s) { next[s.key] = s; });
    Object.keys(S.series).forEach(function (k) { if (!next[k]) delete S.series[k]; });
    S.sessions = next;
    if (list.length) S.ever = true;
  }

  function onMessage(ev) {
    var msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    S.lastMsgAt = Date.now();
    if (msg.type === "hello") {
      S.thresholds = msg.thresholds;
      S.retentionMs = (msg.retention_s || 900) * 1000;
      fillClassFilter();
      return;
    }
    if (msg.type === "backfill") {
      S.series = {};
      setSessions(msg.sessions || []);
      Object.keys(msg.points || {}).forEach(function (k) { mergePoints(k, msg.points[k]); });
    } else if (msg.type === "snapshot") {
      setSessions(msg.sessions || []);
      Object.keys(msg.points || {}).forEach(function (k) { mergePoints(k, msg.points[k]); });
    } else {
      return;
    }
    render();
  }

  // ---------------------------------------------------------------- connection
  function setConn(kind, text) {
    var c = $("conn");
    c.className = "conn " + kind;
    $("conn-text").textContent = text;
  }

  function connect() {
    var url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/v1/live";
    var ws;
    try { ws = new WebSocket(url); } catch (e) { scheduleReconnect(); return; }
    ws.onopen = function () { S.retry = 0; setConn("live", "Live"); };
    ws.onmessage = onMessage;
    ws.onclose = function (ev) {
      if (ev.code === 4401) { location.href = "/login"; return; }
      scheduleReconnect();
    };
  }
  function scheduleReconnect() {
    S.retry = Math.min(S.retry + 1, 6);
    var delay = Math.min(10000, 500 * Math.pow(2, S.retry));
    setConn("down", "Reconnecting…");
    setTimeout(connect, delay);
  }
  setInterval(function () {
    if (!S.lastMsgAt) return;
    var age = (Date.now() - S.lastMsgAt) / 1000;
    if (age > 5 && $("conn").classList.contains("live")) $("conn-text").textContent = "Stalled " + Math.round(age) + " s";
    else if ($("conn").classList.contains("live")) $("conn-text").textContent = "Live";
  }, 1000);

  // ---------------------------------------------------------------- filters
  function fillClassFilter() {
    var sel = $("class-filter");
    var have = {};
    Array.prototype.forEach.call(sel.options, function (o) { have[o.value] = true; });
    Object.keys((S.thresholds && S.thresholds.classes) || {}).forEach(function (c) {
      if (!have[c]) { var o = el("option", null, c); o.value = c; sel.appendChild(o); }
    });
  }
  function visible(s) {
    if (S.filterStatus && s.status !== S.filterStatus) return false;
    if (S.cls && s.app_class !== S.cls) return false;
    if (S.kind && s.kind !== S.kind) return false;
    if (S.search) {
      var hay = (s.site + " " + s.session + " " + s.dst + " " + s.probe_id + " " + s.app_class).toLowerCase();
      if (hay.indexOf(S.search) < 0) return false;
    }
    return true;
  }

  function renderChips() {
    var counts = {};
    STATUS_ORDER.forEach(function (k) { counts[k] = 0; });
    S.list.forEach(function (s) { counts[s.status] = (counts[s.status] || 0) + 1; });
    var box = $("chips");
    if (!box.childElementCount) {
      STATUS_ORDER.forEach(function (k) {
        var b = el("button", "chip s-" + k);
        b.type = "button";
        b.dataset.status = k;
        b.setAttribute("aria-pressed", "false");
        if (STATUS_HELP[k]) b.title = STATUS_HELP[k];
        b.appendChild(el("span", "dot"));
        b.appendChild(el("b", "num", "0"));
        b.appendChild(el("span", null, STATUS_LABEL[k]));
        b.addEventListener("click", function () {
          S.filterStatus = S.filterStatus === k ? null : k;
          Array.prototype.forEach.call(box.children, function (c) {
            c.setAttribute("aria-pressed", String(c.dataset.status === S.filterStatus));
          });
          render();
        });
        box.appendChild(b);
      });
    }
    Array.prototype.forEach.call(box.children, function (c) {
      c.querySelector("b").textContent = counts[c.dataset.status] || 0;
    });
  }

  // ---------------------------------------------------------------- cards
  function metricsFor(s) {
    var w10 = s.w10 || {}, w30 = s.w30 || {}, th = classTh(s) || {};
    if (s.kind === "tcp") {
      var errs = Object.keys(w30.errors || {}).map(function (k) { return k + " " + w30.errors[k]; }).join(", ");
      return [
        { label: "Connect", value: fmtMs(w30.rtt_p50_ms), unit: "ms", sub: "p95 " + fmtMs(w30.rtt_p95_ms) + " ms",
          title: "TCP handshake time over the last 30 s",
          cls: grade(th.rtt_p95_ms, w30.rtt_p95_ms) },
        { label: "Failed · 30 s", value: (w30.lost || 0) + " / " + (w30.sent || 0), unit: "", sub: errs || "connects",
          cls: w30.sent && w30.lost === w30.sent ? "crit" : w30.lost ? "warn" : "" },
        { label: "Jitter", value: fmtMs(w30.rtt_jitter_ms), unit: "ms", sub: "Δ handshake", cls: "" },
      ];
    }
    if (s.kind === "icmp") {
      var reach = w10.sent ? (w10.received > 0) : null;
      return [
        { label: "RTT p50 · 10 s", value: fmtMs(w10.rtt_p50_ms), unit: "ms", sub: "p95 " + fmtMs(w10.rtt_p95_ms) + " ms", cls: "" },
        { label: "Loss · 30 s", value: fmtPct(w30.loss_pct), unit: "%", sub: (w30.sent || 0) + " echoes",
          cls: grade(th.loss_pct, w30.loss_pct) },
        { label: "Reachable", value: reach == null ? "–" : reach ? "Yes" : "No", unit: "", sub: "ICMP only",
          cls: reach === false ? "crit" : "" },
      ];
    }
    var dirJit = (w10.ipdv_fwd_ms != null || w10.ipdv_back_ms != null)
      ? "→" + fmtMs(w10.ipdv_fwd_ms) + " ←" + fmtMs(w10.ipdv_back_ms) : "ΔRTT";
    var lossSub = w30.loss_hi_pct != null ? "95% ≤ " + fmtPct(w30.loss_hi_pct) + "%" : "";
    var lossTitle = w30.loss_hi_pct != null
      ? "95% upper bound " + fmtPct(w30.loss_hi_pct) + "% from " + (w30.sent || 0) + " packets in 30 s" : "";
    return [
      { label: "RTT p50 · 10 s", value: fmtMs(w10.rtt_p50_ms), unit: "ms", sub: "p95 " + fmtMs(w10.rtt_p95_ms) + " ms",
        cls: grade(th.rtt_p95_ms, w10.rtt_p95_ms) },
      { label: "Loss · 30 s", value: fmtPct(w30.loss_pct), unit: "%", sub: lossSub, title: lossTitle,
        cls: grade(th.loss_pct, w30.loss_pct) },
      { label: "Jitter · 10 s", value: fmtMs(w10.jitter_ms), unit: "ms", sub: dirJit,
        title: "Mean |IPDV| forward → and return ←, worst direction shown large", cls: grade(th.jitter_ms, w10.jitter_ms) },
    ];
  }

  function footFor(s) {
    var w30 = s.w30 || {};
    var parts = [];
    if (s.kind === "stamp" && w30.fwd_loss_pct != null) {
      parts.push("Loss split → " + fmtPct(w30.fwd_loss_pct) + "%  ← " + fmtPct(w30.back_loss_pct) + "%");
    }
    if (s.kind === "stamp" && (s.hops_fwd != null || s.hops_back != null)) {
      parts.push("Hops → " + (s.hops_fwd == null ? "–" : s.hops_fwd) + "  ← " + (s.hops_back == null ? "–" : s.hops_back));
    } else if (s.hops_back != null) {
      parts.push("Hops " + s.hops_back);
    }
    if (s.age_s > 6) parts.push("data " + ago(s.age_s));
    return parts;
  }

  function buildCard(s) {
    var c = el("div", "card");
    c.tabIndex = 0;
    c.setAttribute("role", "button");
    var head = el("div", "card-head");
    var titles = el("div");
    var t = el("div", "card-title");
    var meta = el("div", "card-meta");
    titles.appendChild(t); titles.appendChild(meta);
    var badge = el("span", "badge");
    var pill = el("span", "pill");
    head.appendChild(titles); head.appendChild(badge); head.appendChild(pill);
    var metrics = el("div", "metrics");
    var mEls = [];
    for (var i = 0; i < 3; i++) {
      var m = el("div", "metric");
      var lab = el("div", "label"), val = el("div", "value"), sub = el("div", "sub");
      m.appendChild(lab); m.appendChild(val); m.appendChild(sub);
      metrics.appendChild(m);
      mEls.push({ box: m, label: lab, value: val, sub: sub });
    }
    var canvas = el("canvas", "spark");
    canvas.setAttribute("aria-hidden", "true");
    var foot = el("div", "card-foot");
    var footText = el("span");
    var pathchg = el("span", "pathchg");
    var pathinfo = el("span", "pathinfo");
    var reason = el("span", "reason");
    foot.appendChild(footText); foot.appendChild(pathchg); foot.appendChild(pathinfo); foot.appendChild(reason);
    c.appendChild(head); c.appendChild(metrics); c.appendChild(canvas); c.appendChild(foot);
    c.addEventListener("click", function () { openDrawer(c.dataset.key); });
    c.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(c.dataset.key); } });
    return { root: c, title: t, meta: meta, badge: badge, pill: pill, metrics: mEls, canvas: canvas,
      footText: footText, pathchg: pathchg, pathinfo: pathinfo, reason: reason };
  }

  function updateCard(card, s, xMax) {
    card.root.dataset.key = s.key;
    card.root.className = "card s-" + s.status;
    card.root.setAttribute("aria-label", s.session + " at " + s.site + ": " + STATUS_LABEL[s.status]);
    card.title.textContent = s.session;
    card.meta.textContent = s.app_class + " · " + dscpName(s.dscp) + "\u00a0· ";
    card.meta.appendChild(el("span", "target", "→ " + target(s)));
    card.badge.textContent = KIND_LABEL[s.kind] || s.kind;
    card.pill.className = "pill s-" + s.status;
    card.pill.textContent = STATUS_LABEL[s.status] || s.status;
    if (STATUS_HELP[s.status]) card.pill.title = STATUS_HELP[s.status]; else card.pill.removeAttribute("title");
    var ms = metricsFor(s);
    ms.forEach(function (m, i) {
      var e = card.metrics[i];
      e.box.className = "metric " + (m.cls || "");
      e.label.textContent = m.label;
      e.value.textContent = m.value;
      if (m.unit && m.value !== "–") e.value.appendChild(el("small", null, m.unit));
      e.sub.textContent = m.sub;
      e.box.title = m.title || "";
    });
    card.footText.textContent = footFor(s).join("   ·   ");
    var rc = recentRouteChange(s, xMax);
    if (rc && (!s.path_change || rc.ts_ms >= s.path_change.ts_ms)) {
      card.pathchg.textContent = "Route changed" + (rc.change_ttl ? " at hop " + rc.change_ttl : "") + ", " +
        ago((xMax - rc.ts_ms) / 1000);
      card.pathchg.title = rc.prev_signature + "\n→ " + rc.signature;
    } else if (s.path_change) {
      var pc = s.path_change;
      card.pathchg.textContent = "Path change " + (pc.direction === "fwd" ? "→" : "←") + " " +
        pc.hops_from + "→" + pc.hops_to + " hops, " + ago((xMax - pc.ts_ms) / 1000);
      card.pathchg.removeAttribute("title");
    } else {
      card.pathchg.textContent = "";
      card.pathchg.removeAttribute("title");
    }
    var path = s.kind === "stamp" ? S.paths[s.key] : null;
    if (path) {
      card.pathinfo.className = "pathinfo" + (path.status === "warn" ? " warn" : "");
      var warnF = path.findings.filter(function (f) { return f.severity === "warn"; })[0];
      card.pathinfo.textContent = warnF ? (PATH_LABEL[warnF.code] || "Path warning")
        : path.summary ? "via " + path.summary : "not in flow export";
      card.pathinfo.title = path.findings.map(function (f) { return f.text; }).join("\n");
    } else {
      card.pathinfo.textContent = "";
      card.pathinfo.removeAttribute("title");
    }
    card.reason.textContent = s.reasons && s.reasons.length ? s.reasons[0] : "";
    card.reason.title = s.reasons ? s.reasons.join("\n") : "";
    BMChart.draw(card.canvas, { points: S.series[s.key] || [], xMin: xMax - SPARK_MS, xMax: xMax, compact: true });
  }

  function latestTs() {
    var mx = 0;
    S.list.forEach(function (s) { if (s.last_ts_ms && s.last_ts_ms > mx) mx = s.last_ts_ms; });
    return mx ? mx + 1000 : Date.now();
  }

  function render() {
    renderChips();
    var root = $("sites");
    $("empty").hidden = S.list.length > 0;
    var xMax = latestTs();
    var bySite = {};
    S.list.forEach(function (s) { if (visible(s)) (bySite[s.site] = bySite[s.site] || []).push(s); });
    var sites = Object.keys(bySite).sort();
    var keep = {};
    sites.forEach(function (site, idx) {
      var sec = S.siteEls[site];
      if (!sec) {
        sec = { root: el("section", "site"), head: el("div", "site-head"), dot: el("span", "dot"),
          name: el("h2"), probe: el("span", "probe"), counts: el("span", "counts"), grid: el("div", "grid") };
        sec.head.appendChild(sec.dot); sec.head.appendChild(sec.name); sec.head.appendChild(sec.probe);
        sec.head.appendChild(sec.counts);
        sec.root.appendChild(sec.head); sec.root.appendChild(sec.grid);
        S.siteEls[site] = sec;
      }
      if (root.children[idx] !== sec.root) root.insertBefore(sec.root, root.children[idx] || null);
      var list = bySite[site].sort(function (a, b) { return a.session < b.session ? -1 : a.session > b.session ? 1 : 0; });
      var worst = "no-data";
      list.forEach(function (s) { if (STATUS_ORDER.indexOf(s.status) < STATUS_ORDER.indexOf(worst)) worst = s.status; });
      sec.dot.className = "dot s-" + worst;
      sec.name.textContent = site;
      var probes = {};
      list.forEach(function (s) { probes[s.probe_id] = true; });
      sec.probe.textContent = Object.keys(probes).join(", ");
      var bad = list.filter(function (s) { return s.status === "bad" || s.status === "degraded"; }).length;
      sec.counts.textContent = list.length + " sessions" + (bad ? " · " + bad + " need attention" : "");
      list.forEach(function (s, i) {
        var card = S.cards[s.key];
        if (!card) { card = buildCard(s); S.cards[s.key] = card; }
        if (sec.grid.children[i] !== card.root) sec.grid.insertBefore(card.root, sec.grid.children[i] || null);
        updateCard(card, s, xMax);
        keep[s.key] = true;
      });
      while (sec.grid.children.length > list.length) sec.grid.removeChild(sec.grid.lastChild);
    });
    Object.keys(S.siteEls).forEach(function (site) {
      if (!bySite[site]) {
        var e = S.siteEls[site].root;
        if (e.parentNode) e.parentNode.removeChild(e);
      }
    });
    Object.keys(S.cards).forEach(function (k) { if (!S.sessions[k]) delete S.cards[k]; });
    if (S.open) refreshDrawer(false);
  }

  // ---------------------------------------------------------------- drawer
  function openDrawer(key) {
    if (!S.sessions[key]) return;
    S.open = key;
    S.lastFocus = document.activeElement;
    $("drawer").hidden = false;
    $("scrim").hidden = false;
    refreshDrawer(true);
    loadHistory();
    $("d-close").focus();
  }
  function closeDrawer() {
    S.open = null;
    $("drawer").hidden = true;
    $("scrim").hidden = true;
    if (S.lastFocus && S.lastFocus.focus) S.lastFocus.focus();
  }

  function row(tbl, label, vals) {
    var tr = el("tr");
    tr.appendChild(el("td", null, label));
    vals.forEach(function (v) { tr.appendChild(el("td", null, v)); });
    tbl.appendChild(tr);
  }

  function hopText(h, dir) {
    var out = h.out_if_name || ("ifIndex " + h.out_if), inn = h.in_if_name || ("ifIndex " + h.in_if);
    return h.appliance + ": in " + inn + (h.in_transport ? " (" + h.in_transport + ")" : "") +
      " → out " + out + (h.out_transport ? " (" + h.out_transport + ")" : "") +
      " · " + dscpName(h.dscp) + " · " + h.packets + " pkts · last " +
      ago(Math.max(0, (Date.now() - h.last_ms) / 1000));
  }
  function renderPath(s) {
    var box = $("d-path");
    box.textContent = "";
    if (s.kind !== "stamp") { box.appendChild(el("p", "muted", "Path validation applies to STAMP sessions.")); return; }
    if (S.pathsUnavailable) { box.appendChild(el("p", "muted", S.pathsUnavailable)); return; }
    var p = S.paths[s.key];
    if (!p) { box.appendChild(el("p", "muted", "Waiting for flow data…")); return; }
    [["Forward (probe → reflector)", p.forward], ["Return (reflector → probe)", p["return"]]].forEach(function (d) {
      box.appendChild(el("div", "path-dir", d[0]));
      var ul = el("ul", "path-hops");
      if (!d[1].length) ul.appendChild(el("li", "muted", "not seen in the flow export"));
      d[1].forEach(function (h) { ul.appendChild(el("li", h.dscp !== s.dscp ? "warn" : null, hopText(h))); });
      box.appendChild(ul);
    });
    if (p.findings.length) {
      var fl = el("ul", "reasons");
      p.findings.forEach(function (f) { fl.appendChild(el("li", f.severity === "warn" ? "warn" : null, f.text)); });
      box.appendChild(fl);
    }
  }

  // -- forward route (traceroute on the session's own flow) and capacity ------
  var ROUTE_CHANGE_RECENT_MS = 60 * 60 * 1000;
  function recentRouteChange(s, now) {
    var r = s.kind === "stamp" ? S.routes[s.key] : null;
    var c = r && r.changes && r.changes[0];
    return c && now - c.ts_ms <= ROUTE_CHANGE_RECENT_MS ? c : null;
  }
  function fmtBps(v) {
    if (v == null) return "–";
    return v >= 1e9 ? (v / 1e9).toFixed(2) + " Gbit/s" : (v / 1e6).toFixed(v >= 1e8 ? 0 : 1) + " Mbit/s";
  }
  var TRIGGER = { start: "at start", schedule: "scheduled", ttl_change: "after a TTL change" };
  function renderRoute(s) {
    var box = $("d-route");
    box.textContent = "";
    if (s.kind !== "stamp") { box.appendChild(el("p", "muted", "Route tracing applies to STAMP sessions.")); return; }
    var e = S.routes[s.key];
    var now = Date.now();
    if (!e || !e.route) {
      box.appendChild(el("p", "muted", "No trace yet. The probe traces at start and every few minutes " +
        "(it needs CAP_NET_RAW to read the routers' replies)."));
    } else {
      var r = e.route;
      var n = r.hop_count_fwd == null ? "unknown number of" : r.hop_count_fwd;
      box.appendChild(el("div", "path-dir", "Forward, " + n + " router(s) · traced " + ago((now - r.ts_ms) / 1000) +
        " (" + (TRIGGER[r.trigger] || r.trigger) + ")" + (r.complete ? "" : " · some routers did not answer")));
      var ol = el("ul", "path-hops");
      r.hops.forEach(function (h) {
        var text = h.ttl + ". " + (h.addrs.length ? h.addrs.join(", ") : "* no reply") +
          (h.rtt_us != null ? " · " + (h.rtt_us < 1000 ? (h.rtt_us / 1000).toFixed(2) : fmtMs(h.rtt_us / 1000)) + " ms" : "") +
          (h.unreachable != null ? " · unreachable (code " + h.unreachable + ")" : "");
        var changedHop = e.changes[0] && e.changes[0].ts_ms === r.ts_ms && e.changes[0].change_ttl === h.ttl;
        ol.appendChild(el("li", changedHop || h.unreachable != null ? "warn" : null, text));
      });
      ol.appendChild(el("li", "muted", (r.hop_count_fwd == null ? "?" : r.hop_count_fwd + 1) + ". " + target(s) + " (reflector)"));
      box.appendChild(ol);
      if (r.multipath) box.appendChild(el("p", "muted", "Several routers answered for one hop: per-packet load balancing, or the route moved during the trace."));
      if (e.changes.length) {
        var cl = el("ul", "reasons");
        e.changes.slice(0, 3).forEach(function (c) {
          cl.appendChild(el("li", now - c.ts_ms <= ROUTE_CHANGE_RECENT_MS ? "warn" : null,
            "Route changed " + ago((now - c.ts_ms) / 1000) + (c.change_ttl ? " at hop " + c.change_ttl : " (hop count)") +
            ": " + c.prev_signature + " → " + c.signature));
        });
        box.appendChild(cl);
      }
    }
    var c = e && e.capacity;
    if (c) {
      box.appendChild(el("div", "path-dir", "Capacity · packet trains (" + c.valid_trains + "/" + c.trains + " trains of " +
        c.packets + " × " + c.size + " B, " + dscpName(c.dscp) + ") · " + ago((now - c.ts_ms) / 1000)));
      var cu = el("ul", "path-hops");
      cu.appendChild(el("li", null, "→ " + fmtBps(c.fwd_bps) +
        (c.fwd_bps_min != null ? " (trains " + fmtBps(c.fwd_bps_min) + " – " + fmtBps(c.fwd_bps_max) + ")" : "")));
      if (c.burst_bytes != null) {
        cu.appendChild(el("li", null, "Shaper burst: ~" + Math.round(c.burst_bytes / 1024) + " KB passes ahead of the sustained rate (" +
          c.burst_trains + "/" + c.valid_trains + " trains)"));
      }
      if (c.back_method === "reflected_train") {
        cu.appendChild(el("li", null, "← " + fmtBps(c.back_bps) + " (return trains, " + c.back_valid_trains + "/" +
          c.back_trains + (c.back_bps_min != null ? ": " + fmtBps(c.back_bps_min) + " – " + fmtBps(c.back_bps_max) : "") + ")"));
        if (c.back_burst_bytes != null) {
          cu.appendChild(el("li", null, "Return shaper burst: ~" + Math.round(c.back_burst_bytes / 1024) + " KB"));
        }
      } else {
        cu.appendChild(el("li", null, "← " + (c.back_bps == null ? "–" : (c.back_is_lower_bound ? "at least " : "") + fmtBps(c.back_bps)) +
          (c.back_is_lower_bound ? " (a floor: enable return trains to measure it)" : "")));
      }
      box.appendChild(cu);
    }
  }

  // -- RFC 9946 speed tests (on demand, guarded by the collector and the probe) --
  var ST_ACTIVE = { queued: true, dispatched: true };
  function renderSpeed(s) {
    var box = $("d-speed");
    box.textContent = "";
    var sp = S.speed;
    if (!sp) { box.appendChild(el("p", "muted", "Loading…")); return; }
    if (!sp.enabled) {
      box.appendChild(el("p", "muted", "Speed tests are disabled on this collector (no BUFFMON_SPEEDTEST_POLICY)."));
      return;
    }
    var caps = sp.probes[s.probe_id];
    var jobs = sp.jobs.filter(function (j) { return j.probe_id === s.probe_id; });
    if (!caps) {
      box.appendChild(el("p", "muted", "Probe " + s.probe_id + " has no speed-test targets enabled (or has not checked in)."));
    } else {
      var siteBusy = sp.jobs.filter(function (j) { return j.site === caps.site && ST_ACTIVE[j.state]; })[0];
      var note = !caps.allowed ? "This probe is not in the speed-test policy."
        : !sp.window_open ? "Outside the speed-test windows set in the policy."
        : siteBusy ? "A test is running at " + caps.site + " (" + siteBusy.job_id + "): one per site at a time." : "";
      box.appendChild(el("p", "muted", "Fills the path for the test's duration. Through an EdgeConnect overlay it " +
        "measures what the appliance gives this traffic class, with users present, not the circuit."));
      caps.targets.forEach(function (t) {
        var row = el("div", "path-dir", t.name + " → " + t.server + " · up to " + t.max_mbps + " Mbit/s, " +
          t.max_duration_s + " s, " + dscpName(t.dscp) + "  ");
        t.directions.forEach(function (d) {
          var b = el("button", "btn", d === "down" ? "Test ↓ download" : "Test ↑ upload");
          b.type = "button";
          b.disabled = !!note;
          b.addEventListener("click", function () { requestSpeed(s.probe_id, t, d); });
          row.appendChild(b);
        });
        box.appendChild(row);
      });
      if (note) box.appendChild(el("p", "muted", note));
    }
    if (S.speedMsg) box.appendChild(el("p", "warn", S.speedMsg));
    if (jobs.length) {
      var ul = el("ul", "path-hops");
      jobs.slice(0, 6).forEach(function (j) {
        var r = j.result || {};
        var when = ago((Date.now() - (j.finished_ms || j.created_ms)) / 1000);
        var text = (j.direction === "down" ? "↓ " : "↑ ") + j.target + " · " + j.state;
        if (r.max_ip_capacity_mbps != null) {
          text += " · max " + r.max_ip_capacity_mbps.toFixed(1) + " Mbit/s" +
            (r.loss_ratio_at_max != null ? ", loss at max " + (r.loss_ratio_at_max * 100).toFixed(2) + "%" : "") +
            (r.rtt_range_ms_at_max != null ? ", RTT range " + r.rtt_range_ms_at_max.toFixed(1) + " ms" : "");
        }
        if (r.error || j.note) text += " · " + (r.error || j.note);
        ul.appendChild(el("li", j.state === "failed" || j.state === "lost" || j.state === "refused" ? "warn" : null,
          text + " · " + when));
      });
      box.appendChild(ul);
    }
  }
  function requestSpeed(probeId, t, direction) {
    var what = (direction === "down" ? "download" : "upload") + " speed test from " + probeId + " to " + t.server +
      " at up to " + t.max_mbps + " Mbit/s for " + t.max_duration_s + " s";
    if (!window.confirm("Run a " + what + "?\n\nIt fills the path for its duration and competes with users' traffic.")) return;
    S.speedMsg = "";
    fetch("/v1/speedtests", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ probe_id: probeId, target: t.name, direction: direction })
    }).then(function (r) {
      return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
    }).then(function () { loadSpeed(); })
      .catch(function (e) { S.speedMsg = "Not started: " + e.message; if (S.open) refreshDrawer(false); });
  }
  function loadSpeed() {
    fetch("/v1/speedtests", { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
        return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
      })
      .then(function (b) { S.speed = b; if (S.open) refreshDrawer(false); })
      .catch(function () { /* keep the last snapshot */ });
  }
  // Poll fast only while a test is in flight.
  setInterval(function () {
    var active = S.speed && S.speed.jobs.some(function (j) { return ST_ACTIVE[j.state]; });
    if (active || (S.open && !S.speed)) loadSpeed();
  }, 3000);
  setInterval(loadSpeed, 30000);
  setTimeout(loadSpeed, 3000);

  function renderPathTunnels(s) {
    var box = $("d-tunnels");
    box.textContent = "";
    var p = s.kind === "stamp" ? S.paths[s.key] : null;
    var apps = {};
    if (p) p.forward.concat(p["return"]).forEach(function (h) { apps[h.appliance] = true; });
    var rows = (S.tunnels || []).filter(function (t) { return apps[t.appliance]; });
    if (!rows.length) {
      box.appendChild(el("p", "muted", p && Object.keys(apps).length
        ? "No Orchestrator tunnel data for " + Object.keys(apps).join(", ") + " (is buffmon-orch-poll running?)."
        : "Shown once the probe's path through an EdgeConnect is known from the flow export."));
      return;
    }
    box.appendChild(el("p", "muted", "Tunnel loss before FEC is what the underlay did; after FEC is what the " +
      "overlay delivered. Compare with this probe's own loss above."));
    box.appendChild(tunnelTable(rows));
  }

  function refreshDrawer(first) {
    var s = S.sessions[S.open];
    if (!s) return;
    renderRoute(s);
    renderSpeed(s);
    renderPath(s);
    renderPathTunnels(s);
    $("d-title").textContent = s.session;
    $("d-sub").textContent = s.site + " · " + (KIND_LABEL[s.kind] || s.kind) + " · " + s.app_class + " · " + dscpName(s.dscp);
    var pill = $("d-pill");
    pill.className = "pill s-" + s.status;
    pill.textContent = STATUS_LABEL[s.status] || s.status;
    var ul = $("d-reasons");
    ul.textContent = "";
    (s.reasons.length ? s.reasons : ["All evaluated metrics are within target for " + s.effective_class + "."])
      .forEach(function (r) { ul.appendChild(el("li", null, r)); });
    // A probe on the wrong path measures a path nobody uses: say so next to the verdict.
    var pth = s.kind === "stamp" ? S.paths[s.key] : null;
    if (pth && pth.status === "warn") {
      ul.appendChild(el("li", "warn", "These results may not represent " + s.app_class +
        " traffic: see Path below."));
    }

    var xMax = latestTs();
    var th = classTh(s);
    var live = $("d-live");
    BMChart.attachHover(live);
    BMChart.draw(live, { points: S.series[s.key] || [], xMin: xMax - LIVE_MS, xMax: xMax,
      threshold: th ? th.rtt_p95_ms.good : null, hoverTs: live._bmOpts ? live._bmOpts.hoverTs : null });

    var tbl = $("d-windows");
    tbl.textContent = "";
    var thead = el("thead"), hr = el("tr");
    ["", "10 s", "30 s", "60 s"].forEach(function (h) { hr.appendChild(el("th", null, h)); });
    thead.appendChild(hr); tbl.appendChild(thead);
    var ws = [s.w10 || {}, s.w30 || {}, s.w60 || {}];
    function col(f) { return ws.map(f); }
    row(tbl, "Sent / received", col(function (w) { return (w.sent || 0) + " / " + (w.received || 0); }));
    row(tbl, "Loss", col(function (w) { return fmtPct(w.loss_pct) + "%"; }));
    row(tbl, "Loss, 95% upper bound", col(function (w) { return w.loss_hi_pct == null ? "–" : fmtPct(w.loss_hi_pct) + "%"; }));
    if (s.kind === "stamp") {
      row(tbl, "Loss → / ←", col(function (w) {
        return w.fwd_loss_pct == null ? "–" : fmtPct(w.fwd_loss_pct) + "% / " + fmtPct(w.back_loss_pct) + "%";
      }));
    }
    row(tbl, "RTT p50 / p95", col(function (w) { return fmtMs(w.rtt_p50_ms) + " / " + fmtMs(w.rtt_p95_ms) + " ms"; }));
    row(tbl, "RTT max", col(function (w) { return fmtMs(w.rtt_max_ms) + " ms"; }));
    if (s.kind === "stamp") {
      row(tbl, "Jitter → / ← (IPDV)", col(function (w) { return fmtMs(w.ipdv_fwd_ms) + " / " + fmtMs(w.ipdv_back_ms) + " ms"; }));
    }
    row(tbl, "Jitter (ΔRTT)", col(function (w) { return fmtMs(w.rtt_jitter_ms) + " ms"; }));
    if (s.clock_synced) {
      row(tbl, "One-way → / ←", col(function (w) { return fmtMs(w.owd_fwd_ms) + " / " + fmtMs(w.owd_back_ms) + " ms"; }));
    }
    row(tbl, "Late / dup / reordered", col(function (w) { return (w.late || 0) + " / " + (w.dup || 0) + " / " + (w.reordered || 0); }));

    var dl = $("d-meta");
    dl.textContent = "";
    var meta = [
      ["Probe", s.probe_id], ["Source", s.src], ["Target", target(s)],
      ["DSCP", dscpName(s.dscp)], ["Thresholds", s.effective_class + (s.effective_class !== s.app_class ? " (default)" : "") +
        (s.threshold_override ? " · override " + s.threshold_override : "")],
      ["TTL → / ←", (s.ttl_fwd == null ? "–" : s.ttl_fwd) + " / " + (s.ttl_back == null ? "–" : s.ttl_back)],
      ["Receive timestamps", s.rx_ts === "kernel" ? "kernel" : "user space (less precise)"],
      ["Clock sync", s.clock_synced ? "synchronised" + (s.clock_err_us != null ? " (±" + s.clock_err_us + " µs)" : "")
        : "not synchronised: one-way delay not reported"],
      ["Last record", s.last_ts_ms ? new Date(s.last_ts_ms).toLocaleTimeString() + " (" + ago(s.age_s) + " received)" : "–"],
    ];
    meta.forEach(function (kv) { dl.appendChild(el("dt", null, kv[0])); dl.appendChild(el("dd", null, kv[1])); });
    if (first) setTabs();
  }

  function setTabs() {
    Array.prototype.forEach.call($("d-tabs").children, function (b) {
      b.setAttribute("aria-selected", String(b.dataset.range === S.histRange));
    });
  }

  // EdgeConnect tunnel health from Orchestrator (buffmon-orch-poll), polled.
  function fmtNum(v, digits) { return v == null ? "–" : (Math.round(v * Math.pow(10, digits)) / Math.pow(10, digits)).toString(); }
  function lossCell(pkts, pctMax) {
    if (pkts == null) return "–";
    return pkts + " pkts" + (pkts && pctMax != null ? " (max " + fmtNum(pctMax, 2) + "%/min)" : "");
  }
  function tunnelTable(rows) {
    var tbl = el("table", "win ec-table");
    var head = el("tr");
    ["Tunnel", "Type", "Latency avg / max", "Jitter", "Loss before FEC", "Loss after FEC", "MOS min"].forEach(function (h) {
      head.appendChild(el("th", null, h));
    });
    var thead = el("thead"); thead.appendChild(head); tbl.appendChild(thead);
    rows.forEach(function (t) {
      var tr = el("tr", (t.loss_post_pkts || 0) > 0 ? "warn" : null);
      tr.title = t.tunnel_name + " (" + t.tunnel_id + ")";
      tr.appendChild(el("td", null, "→ " + (t.peer || t.tunnel_id)));
      tr.appendChild(el("td", null, t.tunnel_kind === "overlay" ? "overlay " + (t.overlay || "") :
        t.tunnel_kind === "underlay" ? "underlay " + (t.transport || "") : (t.tunnel_kind || "")));
      tr.appendChild(el("td", null, fmtNum(t.latency_ms, 1) + " / " + fmtNum(t.latency_max_ms, 0) + " ms"));
      tr.appendChild(el("td", null, fmtNum(t.jitter_ms, 1) + " ms"));
      tr.appendChild(el("td", null, lossCell(t.loss_pre_pkts, t.loss_pre_pct_max)));
      tr.appendChild(el("td", null, lossCell(t.loss_post_pkts, t.loss_post_pct_max)));
      tr.appendChild(el("td", null, fmtNum(t.mos_min, 2)));
      tbl.appendChild(tr);
    });
    return tbl;
  }
  function renderTunnels() {
    var box = $("ec-body");
    var rows = S.tunnels || [];
    $("ec").hidden = rows.length === 0;
    if (!rows.length) return;
    box.textContent = "";
    var byApp = {};
    rows.forEach(function (t) { (byApp[t.appliance] = byApp[t.appliance] || []).push(t); });
    var apps = Object.keys(byApp).sort();
    var pre = 0, post = 0;
    rows.forEach(function (t) { pre += t.loss_pre_pkts || 0; post += t.loss_post_pkts || 0; });
    $("ec-counts").textContent = apps.length + " appliances · " + rows.length + " tunnels · loss " + pre +
      " pkts before FEC, " + post + " after";
    apps.forEach(function (a) {
      var list = byApp[a];
      var head = el("div", "ec-app");
      head.appendChild(el("b", null, a));
      head.appendChild(el("span", "muted", " · " + (list[0].site || "no site") + " · " + list.length + " tunnels"));
      var rec = list.reduce(function (n, t) { return n + (t.fec_recovered_pkts || 0); }, 0);
      if (rec) head.appendChild(el("span", "ec-fec", " · FEC recovered " + rec + " pkts"));
      box.appendChild(head);
      box.appendChild(tunnelTable(list));
    });
  }
  function loadTunnels() {
    fetch("/v1/tunnels?minutes=15", { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
        return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
      })
      .then(function (b) { S.tunnels = b.tunnels || []; renderTunnels(); if (S.open) refreshDrawer(false); })
      .catch(function () { S.tunnels = []; renderTunnels(); });
  }
  setInterval(loadTunnels, 60000);
  setTimeout(loadTunnels, 1500);

  // Probe paths from the EdgeConnect flow export: near-real-time, so poll, not push.
  function loadPaths() {
    fetch("/v1/paths?minutes=5", { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
        return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
      })
      .then(function (b) { S.paths = b.paths || {}; S.pathsUnavailable = null; render(); if (S.open) refreshDrawer(false); })
      .catch(function (e) { S.pathsUnavailable = "Path data unavailable: " + e.message; });
  }
  setInterval(loadPaths, 30000);
  setTimeout(loadPaths, 2000);

  // Route traces and capacity: minutes apart, so poll.
  function loadRoutes() {
    fetch("/v1/routes", { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
        return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
      })
      .then(function (b) { S.routes = b.sessions || {}; render(); if (S.open) refreshDrawer(false); })
      .catch(function () { /* keep the last known routes */ });
  }
  setInterval(loadRoutes, 30000);
  setTimeout(loadRoutes, 2500);

  function loadHistory() {
    var s = S.sessions[S.open];
    if (!s) return;
    var key = s.key, range = S.histRange;
    var canvas = $("d-hist");
    BMChart.attachHover(canvas);
    $("d-hist-note").textContent = "Loading…";
    var url = "/v1/sessions/" + encodeURIComponent(s.probe_id) + "/" + encodeURIComponent(s.session) +
      "/history?range=" + encodeURIComponent(range);
    fetch(url, { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
        return r.json().then(function (b) { if (!r.ok) throw new Error(b.error || ("HTTP " + r.status)); return b; });
      })
      .then(function (h) {
        if (S.open !== key || S.histRange !== range) return;
        var pts = h.points.map(function (p) {
          var jit = p.ipdv_fwd_ms != null || p.ipdv_back_ms != null
            ? Math.max(p.ipdv_fwd_ms || 0, p.ipdv_back_ms || 0) : p.rtt_jitter_ms;
          return [p.ts_ms, p.rtt_p50_ms, p.rtt_p95_ms, p.loss_pct, jit];
        });
        var th = classTh(s);
        BMChart.draw(canvas, { points: pts, xMin: h.from_ms, xMax: h.to_ms, bucketMs: h.bucket_s * 1000,
          threshold: th ? th.rtt_p95_ms.good : null });
        $("d-hist-note").textContent = "Source " + h.source + " · " + h.bucket_s + " s buckets · " + pts.length + " points";
      })
      .catch(function (err) {
        if (S.open !== key) return;
        BMChart.draw(canvas, { points: [], xMin: Date.now() - 3600000, xMax: Date.now(), emptyText: "History unavailable" });
        $("d-hist-note").textContent = String(err.message || err);
      });
  }

  // ---------------------------------------------------------------- wiring
  $("d-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && S.open) closeDrawer(); });
  Array.prototype.forEach.call($("d-tabs").children, function (b) {
    b.addEventListener("click", function () { S.histRange = b.dataset.range; setTabs(); loadHistory(); });
  });
  $("search").addEventListener("input", function (e) { S.search = e.target.value.trim().toLowerCase(); render(); });
  $("class-filter").addEventListener("change", function (e) { S.cls = e.target.value; render(); });
  $("kind-filter").addEventListener("change", function (e) { S.kind = e.target.value; render(); });
  $("theme").addEventListener("click", function () {
    var rootEl = document.documentElement;
    var cur = rootEl.getAttribute("data-theme");
    if (!cur) cur = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    var next = cur === "dark" ? "light" : "dark";
    rootEl.setAttribute("data-theme", next);
    store("buffmon.theme", next);
    render();
  });
  window.addEventListener("resize", function () { render(); });

  connect();
})();
