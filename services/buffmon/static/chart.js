// Dependency-free canvas charts for buffmon: RTT p50 line, p50–p95 band and
// loss bars. Points are [ts_ms, rtt_p50_ms, rtt_p95_ms, loss_pct, jitter_ms];
// null values and time gaps break the line instead of being interpolated.
(function () {
  "use strict";

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function niceCeil(v) {
    if (!(v > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var m = v / p;
    var steps = [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10];
    for (var i = 0; i < steps.length; i++) if (m <= steps[i] + 1e-9) return steps[i] * p;
    return 10 * p;
  }

  function fmtMs(v) {
    if (v >= 100) return v.toFixed(0);
    if (v >= 10) return v.toFixed(1).replace(/\.0$/, "");
    return v.toFixed(2).replace(/0$/, "").replace(/\.0$/, "");
  }

  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  function fmtTime(ts, span) {
    var d = new Date(ts);
    if (span > 2 * 86400000) return (d.getMonth() + 1) + "/" + d.getDate() + " " + pad(d.getHours()) + ":00";
    if (span <= 20 * 60000) return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  function setup(canvas) {
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    var w = Math.max(10, Math.round(rect.width));
    var h = Math.max(10, Math.round(rect.height));
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
    }
    var ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx: ctx, w: w, h: h };
  }

  function bucketOf(points, fallback) {
    var best = Infinity;
    for (var i = 1; i < points.length; i++) {
      var d = points[i][0] - points[i - 1][0];
      if (d > 0 && d < best) best = d;
    }
    return isFinite(best) ? best : (fallback || 1000);
  }

  function draw(canvas, opts) {
    canvas._bmOpts = opts;
    var s = setup(canvas);
    var ctx = s.ctx, W = s.w, H = s.h;
    var compact = !!opts.compact;
    var pts = opts.points || [];
    var m = compact ? { l: 1, r: 1, t: 4, b: 2 } : { l: 46, r: 42, t: 12, b: 24 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var xMin = opts.xMin, xMax = opts.xMax;
    if (xMax <= xMin) xMax = xMin + 1;
    var span = xMax - xMin;
    var bucket = opts.bucketMs || bucketOf(pts, 1000);

    var maxMs = 0, maxLoss = 0;
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      if (p[0] < xMin || p[0] > xMax) continue;
      var hi = p[2] != null ? p[2] : p[1];
      if (hi != null && hi > maxMs) maxMs = hi;
      if (p[3] != null && p[3] > maxLoss) maxLoss = p[3];
    }
    var thr = opts.threshold;
    var yTop = maxMs * 1.15;
    if (!compact && thr && thr < maxMs * 3) yTop = Math.max(yTop, thr * 1.1);
    yTop = niceCeil(Math.max(yTop, compact ? 1 : 2));
    var lossTop = Math.max(2, niceCeil(maxLoss * 1.1));

    function X(ts) { return m.l + ((ts - xMin) / span) * pw; }
    function Y(v) { return m.t + ph - (v / yTop) * ph; }

    var cGrid = css("--chart-grid"), cP50 = css("--chart-p50"), cP95 = css("--chart-p95");
    var cLoss = css("--chart-loss"), cText = css("--faint"), cThr = css("--chart-threshold");

    // grid + axes
    if (!compact) {
      ctx.font = "11px " + css("--font");
      ctx.fillStyle = cText;
      ctx.strokeStyle = cGrid;
      ctx.lineWidth = 1;
      ctx.textBaseline = "middle";
      for (var g = 0; g <= 4; g++) {
        var v = (yTop / 4) * g;
        var y = Math.round(Y(v)) + 0.5;
        ctx.beginPath(); ctx.moveTo(m.l, y); ctx.lineTo(W - m.r, y); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText(fmtMs(v) + " ms", m.l - 6, y);
        ctx.textAlign = "left"; ctx.fillText(((lossTop / 4) * g).toFixed(lossTop < 4 ? 1 : 0) + "%", W - m.r + 6, y);
      }
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      for (var t = 0; t <= 4; t++) {
        var ts = xMin + (span / 4) * t;
        var tx = X(ts);
        ctx.textAlign = t === 0 ? "left" : t === 4 ? "right" : "center";
        ctx.fillText(fmtTime(ts, span), tx, H - m.b + 6);
      }
    }

    // loss bars (bottom 45% of the plot in sparklines, full height in charts)
    var barScale = compact ? 0.45 : 1;
    var bw = Math.max(1, (bucket / span) * pw - (compact ? 0.5 : 1));
    ctx.fillStyle = cLoss;
    for (var b = 0; b < pts.length; b++) {
      var lp = pts[b][3];
      if (lp == null || lp <= 0 || pts[b][0] < xMin) continue;
      var bh = Math.max(1.5, (Math.min(lp, lossTop) / lossTop) * ph * barScale);
      ctx.globalAlpha = compact ? 0.85 : 0.55;
      ctx.fillRect(X(pts[b][0]), m.t + ph - bh, bw, bh);
    }
    ctx.globalAlpha = 1;

    // segments split on nulls and gaps
    var segs = [], cur = [];
    for (var k = 0; k < pts.length; k++) {
      var q = pts[k];
      if (q[0] < xMin || q[0] > xMax) continue;
      var gap = cur.length && q[0] - cur[cur.length - 1][0] > bucket * 2.5;
      if (q[1] == null || gap) { if (cur.length) segs.push(cur); cur = []; }
      if (q[1] != null) cur.push(q);
    }
    if (cur.length) segs.push(cur);

    // p50–p95 band
    ctx.fillStyle = cP95;
    segs.forEach(function (sg) {
      if (sg.length < 2) return;
      ctx.beginPath();
      sg.forEach(function (q, j) { var yy = Y(q[2] != null ? q[2] : q[1]); if (j) ctx.lineTo(X(q[0]), yy); else ctx.moveTo(X(q[0]), yy); });
      for (var j = sg.length - 1; j >= 0; j--) ctx.lineTo(X(sg[j][0]), Y(sg[j][1]));
      ctx.closePath(); ctx.fill();
    });

    // p50 line
    ctx.strokeStyle = cP50;
    ctx.lineWidth = compact ? 1.5 : 1.8;
    ctx.lineJoin = "round";
    segs.forEach(function (sg) {
      ctx.beginPath();
      sg.forEach(function (q, j) { if (j) ctx.lineTo(X(q[0]), Y(q[1])); else ctx.moveTo(X(q[0]), Y(q[1])); });
      if (sg.length === 1) { ctx.arc(X(sg[0][0]), Y(sg[0][1]), 1.5, 0, 6.3); }
      ctx.stroke();
    });

    // target line
    if (!compact && thr && thr <= yTop) {
      var ty = Math.round(Y(thr)) + 0.5;
      ctx.save();
      ctx.setLineDash([5, 4]); ctx.strokeStyle = cThr; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(m.l, ty); ctx.lineTo(W - m.r, ty); ctx.stroke();
      ctx.restore();
      ctx.fillStyle = cThr; ctx.textAlign = "left"; ctx.textBaseline = "bottom";
      ctx.fillText("RTT target " + fmtMs(thr) + " ms", m.l + 4, ty - 2);
    }

    // hover readout
    if (!compact && opts.hoverTs != null && pts.length) {
      var near = null, nd = Infinity;
      for (var n = 0; n < pts.length; n++) {
        var dd = Math.abs(pts[n][0] - opts.hoverTs);
        if (dd < nd) { nd = dd; near = pts[n]; }
      }
      if (near && nd <= bucket * 2) {
        var hx = Math.round(X(near[0])) + 0.5;
        ctx.strokeStyle = css("--line-strong"); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(hx, m.t); ctx.lineTo(hx, m.t + ph); ctx.stroke();
        var lines = [
          fmtTime(near[0], 0),
          "p50 " + (near[1] == null ? "–" : fmtMs(near[1]) + " ms") + "   p95 " + (near[2] == null ? "–" : fmtMs(near[2]) + " ms"),
          "loss " + (near[3] == null ? "–" : near[3].toFixed(2) + "%") + (near[4] == null ? "" : "   jitter " + fmtMs(near[4]) + " ms"),
        ];
        ctx.font = "12px " + css("--font");
        var tw = Math.max.apply(null, lines.map(function (l) { return ctx.measureText(l).width; })) + 16;
        var bx = hx + 10 + tw > W - m.r ? hx - 10 - tw : hx + 10;
        ctx.fillStyle = css("--panel"); ctx.strokeStyle = css("--line-strong");
        ctx.fillRect(bx, m.t + 4, tw, 58); ctx.strokeRect(bx + 0.5, m.t + 4.5, tw - 1, 57);
        ctx.fillStyle = css("--text"); ctx.textAlign = "left"; ctx.textBaseline = "top";
        lines.forEach(function (l, i2) { ctx.fillText(l, bx + 8, m.t + 10 + i2 * 17); });
      }
    }

    if (!compact && !pts.length) {
      ctx.fillStyle = cText; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.font = "13px " + css("--font");
      ctx.fillText(opts.emptyText || "No data in this range", m.l + pw / 2, m.t + ph / 2);
    }
  }

  function attachHover(canvas) {
    if (canvas._bmHover) return;
    canvas._bmHover = true;
    canvas.addEventListener("mousemove", function (ev) {
      var o = canvas._bmOpts; if (!o) return;
      var rect = canvas.getBoundingClientRect();
      var l = 46, r = 42, pw = rect.width - l - r;
      var frac = (ev.clientX - rect.left - l) / pw;
      o.hoverTs = frac < 0 || frac > 1 ? null : o.xMin + frac * (o.xMax - o.xMin);
      draw(canvas, o);
    });
    canvas.addEventListener("mouseleave", function () {
      var o = canvas._bmOpts; if (!o) return;
      o.hoverTs = null; draw(canvas, o);
    });
  }

  window.BMChart = { draw: draw, attachHover: attachHover, fmtMs: fmtMs };
})();
