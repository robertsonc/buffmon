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
    sessions: {}, list: [], series: {}, thresholds: null, retentionMs: 900000,
    filterStatus: null, search: "", cls: "", kind: "", lastMsgAt: 0, retry: 0,
    open: null, histRange: "1h", histTimer: null, cards: {}, siteEls: {}, ever: false,
  };

  // ---------------------------------------------------------------- helpers
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
    var reason = el("span", "reason");
    foot.appendChild(footText); foot.appendChild(pathchg); foot.appendChild(reason);
    c.appendChild(head); c.appendChild(metrics); c.appendChild(canvas); c.appendChild(foot);
    c.addEventListener("click", function () { openDrawer(c.dataset.key); });
    c.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(c.dataset.key); } });
    return { root: c, title: t, meta: meta, badge: badge, pill: pill, metrics: mEls, canvas: canvas,
      footText: footText, pathchg: pathchg, reason: reason };
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
    if (s.path_change) {
      var pc = s.path_change;
      card.pathchg.textContent = "Path change " + (pc.direction === "fwd" ? "→" : "←") + " " +
        pc.hops_from + "→" + pc.hops_to + " hops, " + ago((xMax - pc.ts_ms) / 1000);
    } else {
      card.pathchg.textContent = "";
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

  function refreshDrawer(first) {
    var s = S.sessions[S.open];
    if (!s) return;
    $("d-title").textContent = s.session;
    $("d-sub").textContent = s.site + " · " + (KIND_LABEL[s.kind] || s.kind) + " · " + s.app_class + " · " + dscpName(s.dscp);
    var pill = $("d-pill");
    pill.className = "pill s-" + s.status;
    pill.textContent = STATUS_LABEL[s.status] || s.status;
    var ul = $("d-reasons");
    ul.textContent = "";
    (s.reasons.length ? s.reasons : ["All evaluated metrics are within target for " + s.effective_class + "."])
      .forEach(function (r) { ul.appendChild(el("li", null, r)); });

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
      ["DSCP", dscpName(s.dscp)], ["Thresholds", s.effective_class + (s.effective_class !== s.app_class ? " (default)" : "")],
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
