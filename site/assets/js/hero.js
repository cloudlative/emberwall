// Hero animation: packets fly at an ember wall. Accepted ones pass through, dropped ones burst.
// Pauses off-screen and in background tabs; draws one still frame for reduced motion.
(function () {
  'use strict';
  var canvas = document.querySelector('.hero-canvas');
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext('2d');
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var DPR = Math.min(window.devicePixelRatio || 1, 2);
  var W = 0, H = 0, wallX = 0, bandTop = 0, bandBot = 0;
  var stars = [], packets = [], sparks = [], rings = [], cells = [];
  var pointer = { x: 0.5, y: 0.5, active: false };
  var running = false, visible = true, last = 0, spawnAcc = 0, frameNo = 0;
  var light = false;

  var TRAFFIC = [
    ['tcp/443', 1], ['tcp/80', 1], ['udp/443', 1], ['icmp echo', 1], ['tcp/22 · admin', 1],
    ['tcp/23', 0], ['tcp/3389', 0], ['udp/161', 0], ['tcp/5432', 0], ['tcp/445', 0], ['tcp/22 · scan', 0], ['tcp/6379', 0], ['udp/1900', 0],
  ];

  function readTheme() {
    var t = document.documentElement.dataset.theme;
    light = t ? t === 'light' : window.matchMedia('(prefers-color-scheme: light)').matches;
  }
  readTheme();
  new MutationObserver(readTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', readTheme);

  // The wall bulges towards the viewer: x shifts with distance from the middle.
  function wallAt(y) {
    var mid = (bandTop + bandBot) / 2;
    var half = (bandBot - bandTop) / 2 || 1;
    var d = (y - mid) / half;
    return wallX + d * d * 46;
  }

  function resize() {
    var r = canvas.getBoundingClientRect();
    W = Math.max(1, r.width);
    H = Math.max(1, r.height);
    canvas.width = Math.round(W * DPR);
    canvas.height = Math.round(H * DPR);
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    var narrow = W < 700;
    wallX = W * (narrow ? 0.86 : W > 1300 ? 0.76 : 0.72);
    bandTop = H * 0.08;
    bandBot = H * 0.92;
    // Hex cells along the wall.
    cells = [];
    var size = narrow ? 15 : 19;
    var hexH = size * Math.sqrt(3);
    var cols = narrow ? 2 : 3;
    for (var c = 0; c < cols; c += 1) {
      for (var y = bandTop + (c % 2 ? hexH / 2 : 0); y < bandBot; y += hexH) {
        cells.push({ c: c, y: y, size: size, heat: 0, cool: 0 });
      }
    }
    // Stars, denser on wide screens.
    var n = Math.round(Math.min(260, (W * H) / 5200));
    stars = [];
    for (var i = 0; i < n; i += 1) stars.push({ x: Math.random() * W, y: Math.random() * H, z: Math.random(), tw: Math.random() * Math.PI * 2 });
  }

  function cellPos(cell) {
    return { x: wallAt(cell.y) + cell.c * cell.size * 1.5, y: cell.y };
  }

  function hexPath(x, y, s) {
    ctx.beginPath();
    for (var k = 0; k < 6; k += 1) {
      var a = Math.PI / 3 * k;
      var px = x + s * 0.92 * Math.cos(a), py = y + s * 0.92 * Math.sin(a);
      if (k) ctx.lineTo(px, py); else ctx.moveTo(px, py);
    }
    ctx.closePath();
  }

  function heatNear(y, amount, cyan) {
    for (var i = 0; i < cells.length; i += 1) {
      var d = Math.abs(cells[i].y - y);
      if (d < 70) {
        var k = amount * (1 - d / 70);
        if (cyan) cells[i].cool = Math.min(1, cells[i].cool + k);
        else cells[i].heat = Math.min(1, cells[i].heat + k);
      }
    }
  }

  function spawn() {
    var t = TRAFFIC[(Math.random() * TRAFFIC.length) | 0];
    var y = bandTop + 30 + Math.random() * (bandBot - bandTop - 60);
    packets.push({ x: -40, y: y, vy: (Math.random() - 0.5) * 0.25, v: 3.2 + Math.random() * 3.4, ok: !!t[1], label: Math.random() < 0.42 ? t[0] : null, through: false, alpha: 1, hit: false });
  }

  function burst(x, y) {
    var n = 18 + ((Math.random() * 10) | 0);
    for (var i = 0; i < n; i += 1) {
      var a = Math.PI * (0.55 + Math.random() * 0.9) * (Math.random() < 0.5 ? 1 : -1) + Math.PI;
      var sp = 1.2 + Math.random() * 4.2;
      sparks.push({ x: x, y: y, vx: Math.cos(a) * sp - 1.4, vy: Math.sin(a) * sp, life: 1, decay: 0.012 + Math.random() * 0.02, r: 0.8 + Math.random() * 1.8, hue: 14 + Math.random() * 30 });
    }
    rings.push({ x: x, y: y, r: 2, life: 1, ok: false });
  }

  function step(dt) {
    frameNo += 1;
    var k = dt / 16.67;
    // stars drift slowly left, with pointer parallax
    for (var i = 0; i < stars.length; i += 1) {
      var s = stars[i];
      s.x -= (0.05 + s.z * 0.25) * k;
      if (s.x < -2) { s.x = W + 2; s.y = Math.random() * H; }
      s.tw += 0.03 * k;
    }
    spawnAcc += dt;
    var every = W < 700 ? 420 : 260;
    while (spawnAcc > every) { spawnAcc -= every; if (packets.length < 40) spawn(); }
    for (i = packets.length - 1; i >= 0; i -= 1) {
      var p = packets[i];
      p.x += p.v * k;
      p.y += p.vy * k;
      var wx = wallAt(p.y);
      if (!p.hit && p.x >= wx) {
        p.hit = true;
        if (p.ok) { p.through = true; p.v *= 0.8; heatNear(p.y, 0.55, true); rings.push({ x: wx, y: p.y, r: 2, life: 1, ok: true }); }
        else { burst(wx, p.y); heatNear(p.y, 0.9, false); packets.splice(i, 1); continue; }
      }
      if (p.through) p.alpha -= 0.012 * k;
      if (p.x > W + 60 || p.alpha <= 0) packets.splice(i, 1);
    }
    for (i = sparks.length - 1; i >= 0; i -= 1) {
      var sp = sparks[i];
      sp.x += sp.vx * k; sp.y += sp.vy * k;
      sp.vx *= Math.pow(0.965, k); sp.vy = sp.vy * Math.pow(0.965, k) + 0.045 * k;
      sp.life -= sp.decay * k;
      if (sp.life <= 0) sparks.splice(i, 1);
    }
    for (i = rings.length - 1; i >= 0; i -= 1) {
      rings[i].r += 1.6 * k; rings[i].life -= 0.035 * k;
      if (rings[i].life <= 0) rings.splice(i, 1);
    }
    for (i = 0; i < cells.length; i += 1) {
      cells[i].heat *= Math.pow(0.955, k);
      cells[i].cool *= Math.pow(0.94, k);
    }
    if (pointer.active) heatNear(pointer.y * H, 0.02 * k, false);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    var ember = light ? '216, 74, 20' : '255, 120, 60';
    var cyan = light ? '2, 132, 199' : '92, 200, 255';
    var px = (pointer.x - 0.5) * 14, py = (pointer.y - 0.5) * 10;

    // stars
    for (var i = 0; i < stars.length; i += 1) {
      var s = stars[i];
      var a = (0.25 + s.z * 0.6) * (0.65 + 0.35 * Math.sin(s.tw));
      ctx.fillStyle = light ? 'rgba(60, 50, 80,' + a * 0.35 + ')' : 'rgba(220, 228, 255,' + a + ')';
      var r = 0.4 + s.z * 1.1;
      ctx.fillRect(s.x + px * s.z, s.y + py * s.z, r, r);
    }

    // wall: soft glow band
    var g = ctx.createLinearGradient(wallX - 120, 0, wallX + 160, 0);
    g.addColorStop(0, 'rgba(' + ember + ',0)');
    g.addColorStop(0.45, 'rgba(' + ember + ',' + (light ? 0.07 : 0.1) + ')');
    g.addColorStop(1, 'rgba(' + ember + ',0)');
    ctx.fillStyle = g;
    ctx.fillRect(wallX - 120, bandTop - 40, 300, bandBot - bandTop + 80);

    // wall: hex cells
    ctx.lineWidth = 1;
    for (i = 0; i < cells.length; i += 1) {
      var c = cells[i], pos = cellPos(c);
      var edge = 1 - Math.pow(Math.abs((c.y - (bandTop + bandBot) / 2) / ((bandBot - bandTop) / 2)), 3);
      hexPath(pos.x, pos.y, c.size);
      if (c.heat > 0.02) { ctx.fillStyle = 'rgba(' + ember + ',' + c.heat * 0.45 + ')'; ctx.fill(); }
      if (c.cool > 0.02) { ctx.fillStyle = 'rgba(' + cyan + ',' + c.cool * 0.35 + ')'; ctx.fill(); }
      ctx.strokeStyle = 'rgba(' + ember + ',' + (0.1 + edge * 0.16 + c.heat * 0.7) + ')';
      ctx.stroke();
    }

    // wall: bright leading edge
    ctx.save();
    ctx.beginPath();
    for (var y = bandTop; y <= bandBot; y += 6) { var x = wallAt(y) - 14; if (y === bandTop) ctx.moveTo(x, y); else ctx.lineTo(x, y); }
    var eg = ctx.createLinearGradient(0, bandTop, 0, bandBot);
    eg.addColorStop(0, 'rgba(' + ember + ',0)');
    eg.addColorStop(0.5, 'rgba(' + (light ? '236, 90, 31' : '255, 190, 140') + ',0.9)');
    eg.addColorStop(1, 'rgba(' + ember + ',0)');
    ctx.strokeStyle = eg;
    ctx.lineWidth = 2;
    ctx.shadowColor = 'rgba(' + ember + ',0.9)';
    ctx.shadowBlur = 18;
    ctx.stroke();
    ctx.restore();

    // rings
    for (i = 0; i < rings.length; i += 1) {
      var rg = rings[i];
      ctx.beginPath();
      ctx.arc(rg.x, rg.y, rg.r, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(' + (rg.ok ? cyan : ember) + ',' + rg.life * 0.6 + ')';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // packets with trails
    ctx.font = '500 11px "JetBrains Mono", ui-monospace, monospace';
    for (i = 0; i < packets.length; i += 1) {
      var p = packets[i];
      var col = p.ok ? cyan : ember;
      var len = 40 + p.v * 14;
      var tg = ctx.createLinearGradient(p.x - len, p.y, p.x, p.y);
      tg.addColorStop(0, 'rgba(' + col + ',0)');
      tg.addColorStop(1, 'rgba(' + col + ',' + 0.8 * p.alpha + ')');
      ctx.strokeStyle = tg;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(p.x - len, p.y - p.vy * len / p.v);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.6, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(' + (light ? col : '255, 255, 255') + ',' + p.alpha + ')';
      ctx.shadowColor = 'rgba(' + col + ',1)';
      ctx.shadowBlur = 14;
      ctx.fill();
      ctx.shadowBlur = 0;
      if (p.label && !p.through && W >= 700) {
        ctx.fillStyle = 'rgba(' + col + ',' + 0.75 * p.alpha + ')';
        ctx.fillText(p.label, p.x - len * 0.6, p.y - 9);
      }
    }

    // sparks
    for (i = 0; i < sparks.length; i += 1) {
      var sp = sparks[i];
      ctx.beginPath();
      ctx.arc(sp.x, sp.y, sp.r * sp.life + 0.3, 0, Math.PI * 2);
      ctx.fillStyle = 'hsla(' + sp.hue + ', 100%, ' + (light ? 45 : 62 + sp.life * 20) + '%,' + sp.life + ')';
      ctx.fill();
    }
  }

  function loop(t) {
    if (!running) return;
    var dt = Math.min(48, t - (last || t));
    last = t;
    step(dt);
    draw();
    requestAnimationFrame(loop);
  }

  function start() {
    if (running || reduced || !visible || document.hidden) return;
    running = true;
    last = 0;
    requestAnimationFrame(loop);
  }
  function stop() { running = false; }

  resize();
  if (reduced) {
    // One still frame: a few packets in flight and one burst.
    for (var i = 0; i < 9; i += 1) { spawn(); packets[i].x = W * (0.1 + Math.random() * 0.5); }
    burst(wallAt(H * 0.45), H * 0.45);
    for (var j = 0; j < 12; j += 1) step(16);
    draw();
  } else {
    // Warm up so the first frame is already busy.
    for (var w = 0; w < 160; w += 1) step(16);
    start();
  }

  var resizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () { resize(); if (reduced) draw(); }, 120);
  });
  var hero = canvas.parentElement;
  hero.addEventListener('pointermove', function (e) {
    var r = canvas.getBoundingClientRect();
    pointer.x = (e.clientX - r.left) / r.width;
    pointer.y = (e.clientY - r.top) / r.height;
    pointer.active = Math.abs(e.clientX - r.left - wallX) < 160;
  });
  hero.addEventListener('pointerleave', function () { pointer.active = false; });
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (es) { visible = es[0].isIntersecting; if (visible) start(); else stop(); }).observe(canvas);
  }
  document.addEventListener('visibilitychange', function () { if (document.hidden) stop(); else start(); });
})();
