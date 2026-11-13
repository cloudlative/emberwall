// Emberwall website behaviour. No dependencies; everything degrades to readable static content.
(function () {
  'use strict';
  var doc = document.documentElement;
  doc.classList.add('js');
  var root = doc.getAttribute('data-root') || './';
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var $ = function (s, el) { return (el || document).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || document).querySelectorAll(s)); };
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
  };
  var escHtml = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); };

  // ---------- theme ----------
  var themeBtn = $('.theme-toggle');
  if (themeBtn) themeBtn.addEventListener('click', function () {
    var current = doc.dataset.theme || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    var next = current === 'light' ? 'dark' : 'light';
    doc.dataset.theme = next;
    store.set('ew-site-theme', next);
  });

  // ---------- header + menus ----------
  var header = $('.site-header');
  var onScroll = function () { if (header) header.classList.toggle('scrolled', window.scrollY > 10); };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  var menuBtn = $('.menu-toggle');
  if (menuBtn) menuBtn.addEventListener('click', function () {
    var open = document.body.classList.toggle('menu-open');
    menuBtn.setAttribute('aria-expanded', String(open));
  });
  $$('.main-nav a').forEach(function (a) { a.addEventListener('click', function () { document.body.classList.remove('menu-open'); }); });
  var navToggle = $('.docs-nav-toggle');
  if (navToggle) navToggle.addEventListener('click', function () {
    var nav = navToggle.parentElement;
    var open = nav.classList.toggle('open');
    navToggle.setAttribute('aria-expanded', String(open));
  });

  // ---------- reveal on scroll ----------
  var reveals = $$('.reveal');
  if ('IntersectionObserver' in window && !reduced) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var siblings = $$('.reveal', e.target.parentElement).filter(function (x) { return x.parentElement === e.target.parentElement; });
        e.target.style.setProperty('--d', Math.min(siblings.indexOf(e.target), 8) * 0.06 + 's');
        e.target.classList.add('in');
        io.unobserve(e.target);
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    reveals.forEach(function (el) { io.observe(el); });
  } else reveals.forEach(function (el) { el.classList.add('in'); });

  // When a section scrolls into view, run its animation once.
  function whenVisible(el, fn, threshold) {
    if (!el) return;
    if (!('IntersectionObserver' in window)) return fn();
    var o = new IntersectionObserver(function (es) { if (es[0].isIntersecting) { o.disconnect(); fn(); } }, { threshold: threshold || 0.3 });
    o.observe(el);
  }

  // ---------- counters ----------
  $$('[data-count]').forEach(function (el) {
    var target = Number(el.getAttribute('data-count'));
    if (reduced || !target) return;
    el.textContent = '0';
    whenVisible(el, function () {
      var t0 = performance.now();
      var step = function (t) {
        var k = Math.min(1, (t - t0) / 1400);
        el.textContent = String(Math.round(target * (1 - Math.pow(1 - k, 3))));
        if (k < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  });

  // ---------- stage tilt: flattens as it scrolls into view ----------
  var frame = $('.stage-frame');
  if (frame && !reduced) {
    var tick = false;
    var tilt = function () {
      tick = false;
      var r = frame.getBoundingClientRect();
      var k = Math.min(1, Math.max(0, (window.innerHeight - r.top) / (window.innerHeight * 0.75)));
      frame.style.setProperty('--tilt', (14 * (1 - k)).toFixed(2) + 'deg');
      frame.style.setProperty('--scale', (0.94 + 0.06 * k).toFixed(3));
    };
    window.addEventListener('scroll', function () { if (!tick) { tick = true; requestAnimationFrame(tilt); } }, { passive: true });
    tilt();
  }

  // ---------- spotlight on tiles ----------
  $$('.tile').forEach(function (t) {
    t.addEventListener('pointermove', function (e) {
      var r = t.getBoundingClientRect();
      t.style.setProperty('--mx', e.clientX - r.left + 'px');
      t.style.setProperty('--my', e.clientY - r.top + 'px');
    });
  });

  // ---------- code tabs ----------
  $$('[data-tabs]').forEach(function (box) {
    var tabs = $$('[role="tab"]', box);
    tabs.forEach(function (tab, i) {
      tab.addEventListener('click', function () { select(i); });
      tab.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
          e.preventDefault();
          var n = (i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
          select(n);
          tabs[n].focus();
        }
      });
    });
    function select(i) {
      tabs.forEach(function (t, j) {
        t.setAttribute('aria-selected', String(i === j));
        t.tabIndex = i === j ? 0 : -1;
        var pane = document.getElementById(t.getAttribute('aria-controls'));
        if (pane) pane.hidden = i !== j;
      });
    }
    select(0);
  });

  // ---------- version journey ----------
  var journey = $('[data-journey]');
  if (journey) {
    var J = JSON.parse(journey.getAttribute('data-journey'));
    var range = $('.journey-range', journey);
    var ticks = $$('.journey-ticks span', journey);
    var render = function () {
      var i = Number(range.value);
      var v = J.versions[i];
      $('.j-version', journey).textContent = v.version;
      $('.j-distros', journey).textContent = v.distros.length ? 'Shipped by ' + v.distros.join(', ') : 'Available as a custom target';
      $('.j-on', journey).textContent = v.on.length;
      $('.j-notes', journey).textContent = v.notes.length;
      $('.j-lines', journey).textContent = v.lines;
      $$('.cap-list li', journey).forEach(function (li) { li.classList.toggle('on', v.on.indexOf(li.getAttribute('data-cap')) >= 0); });
      ticks.forEach(function (t, j) { t.classList.toggle('on', j === i); });
      range.style.setProperty('--fill', (i / (J.versions.length - 1)) * 100 + '%');
      var list = $('.j-note-list', journey);
      list.innerHTML = v.notes.length
        ? v.notes.map(function (n) { return '<li>' + escHtml(n) + '</li>'; }).join('')
        : '<li class="none">Full feature set. Nothing to fall back on for this version.</li>';
    };
    range.addEventListener('input', render);
    render();
    // A one-time sweep from the oldest version to the newest when it first appears.
    if (!reduced) whenVisible(journey, function () {
      var i = 0;
      var last = J.versions.length - 1;
      range.value = '0';
      render();
      var timer = setInterval(function () {
        i += 1;
        range.value = String(i);
        render();
        if (i >= last) clearInterval(timer);
      }, 420);
      range.addEventListener('pointerdown', function () { clearInterval(timer); }, { once: true });
    }, 0.4);
  }

  // ---------- simulator ----------
  var sim = $('[data-sims]');
  if (sim) {
    var S = JSON.parse(sim.getAttribute('data-sims'));
    var simTabs = $$('.sim-tabs button', sim);
    var simTimers = [];
    var ICON_OK = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
    var ICON_NO = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/></svg>';
    var showSim = function (i) {
      simTimers.forEach(clearTimeout);
      simTimers = [];
      simTabs.forEach(function (t, j) { t.setAttribute('aria-selected', String(i === j)); });
      var s = S[i];
      var p = s.packet;
      $('.sim-packet', sim).innerHTML = '<span><b>' + p.proto.toUpperCase() + '</b> ' + escHtml(p.src) + ' → ' + escHtml(p.dst) + ':' + p.port + '</span><span>in <b>' + escHtml(p.inIface || 'any') + '</b></span><span>state <b>' + p.state + '</b></span>';
      var ol = $('.sim-steps', sim);
      ol.innerHTML = s.steps.map(function (st) {
        var hit = st.matched;
        return '<li class="' + (hit ? 'hit ' + (st.verdict || '') : '') + '"><div><b>' + escHtml(st.label) + '</b><span>' + escHtml(st.detail) + '</span></div>' + (hit && st.verdict ? '<span class="verdict-tag ' + st.verdict + '">' + st.verdict + '</span>' : '') + '</li>';
      }).join('');
      var v = $('.sim-verdict', sim);
      v.className = 'sim-verdict ' + s.verdict;
      var accepted = s.verdict === 'accept';
      v.innerHTML = (accepted ? ICON_OK : ICON_NO) + '<div><b>Packet is ' + (accepted ? 'accepted' : s.verdict === 'reject' ? 'rejected' : 'dropped') + '</b><span>Decided by the ' + escHtml(s.decidedBy) + '.</span></div>';
      var items = $$('li', ol);
      items.forEach(function (li, k) { simTimers.push(setTimeout(function () { li.classList.add('shown'); }, reduced ? 0 : 140 + k * 230)); });
      simTimers.push(setTimeout(function () { v.classList.add('shown'); }, reduced ? 0 : 200 + items.length * 230));
    };
    simTabs.forEach(function (t, i) { t.addEventListener('click', function () { showSim(i); }); });
    whenVisible(sim, function () { showSim(0); });
  }

  // ---------- audit: one-click fixes ----------
  var audit = $('[data-audit]');
  if (audit) {
    var A = JSON.parse(audit.getAttribute('data-audit'));
    var W = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
    var ring = $('.ring', audit);
    var live = A.findings.map(function () { return true; });
    var setScore = function () {
      var s = 100;
      A.findings.forEach(function (f, i) { if (live[i]) s -= W[f.severity] || 0; });
      s = Math.max(0, s);
      var g = s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 60 ? 'C' : s >= 40 ? 'D' : 'F';
      ring.style.setProperty('--p', s);
      ring.style.setProperty('--c', s >= 75 ? 'var(--ok)' : s >= 50 ? 'var(--warn)' : 'var(--bad)');
      $('.audit-score', audit).textContent = s;
      $('.audit-grade', audit).textContent = 'grade ' + g;
    };
    var fix = function (i) {
      live[i] = false;
      var li = $('li[data-i="' + i + '"]', audit);
      if (li) li.classList.add('fixed');
      setScore();
    };
    $$('.f-fix', audit).forEach(function (b) { b.addEventListener('click', function () { fix(Number(b.closest('li').getAttribute('data-i'))); }); });
    var all = $('.audit-fix-all', audit);
    if (all) all.addEventListener('click', function () {
      A.findings.forEach(function (f, i) { if (f.fix && live[i]) setTimeout(function () { fix(i); }, reduced ? 0 : 160 * i); });
    });
    setScore();
  }

  // ---------- safe apply pipeline + countdown ----------
  var pipeline = $('.pipeline');
  var countdown = $('.countdown');
  if (pipeline && countdown) {
    var steps = $$('li', pipeline);
    var num = $('.cd-num', countdown);
    var run = function () {
      var i = 0;
      steps.forEach(function (s) { s.classList.remove('active', 'done'); });
      var next = function () {
        if (i > 0) { steps[i - 1].classList.remove('active'); steps[i - 1].classList.add('done'); }
        if (i < steps.length) { steps[i].classList.add('active'); i += 1; setTimeout(next, 1100); }
        else {
          var n = 60;
          var t = setInterval(function () {
            n -= 4;
            num.textContent = Math.max(0, n);
            countdown.style.setProperty('--p', Math.max(0, n) / 60 * 100);
            countdown.style.setProperty('--c', n > 20 ? 'var(--e3)' : 'var(--bad)');
            if (n <= 24) {
              clearInterval(t);
              num.textContent = '✓';
              countdown.style.setProperty('--c', 'var(--ok)');
              setTimeout(function () { num.textContent = '60'; countdown.style.setProperty('--p', 100); countdown.style.setProperty('--c', 'var(--e3)'); run(); }, 2600);
            }
          }, 260);
        }
      };
      next();
    };
    if (reduced) steps.forEach(function (s) { s.classList.add('done'); });
    else whenVisible(pipeline, run);
  }

  // ---------- terminal ----------
  var term = $('[data-term-sessions]');
  if (term) {
    var T = JSON.parse(term.getAttribute('data-term-sessions'));
    var body = $('.term-body code', term);
    var termTabs = $$('.term-tabs button', term);
    var typing = null;
    var colour = function (line) {
      var l = escHtml(line);
      if (/^PASS\b/.test(line)) return '<span class="pass">' + l + '</span>';
      if (/^FAIL\b/.test(line)) return '<span class="fail">' + l + '</span>';
      if (/^(CRITICAL|HIGH)\b/.test(line)) return '<span class="fail">' + l + '</span>';
      if (/^(MEDIUM|LOW|INFO)\b/.test(line)) return '<span class="hl">' + l + '</span>';
      if (/^(score|\d+\/\d+ passed|.*: \d+%)/.test(line)) return '<b>' + l + '</b>';
      if (/^\(/.test(line)) return '<span class="dim">' + l + '</span>';
      return l;
    };
    var play = function (i) {
      clearInterval(typing);
      termTabs.forEach(function (t, j) { t.setAttribute('aria-selected', String(i === j)); });
      var s = T[i];
      var out = s.out.split('\n').map(colour).join('\n');
      if (reduced) { body.innerHTML = '<span class="cmdline">' + escHtml(s.cmd) + '</span>\n' + out; return; }
      var k = 0;
      typing = setInterval(function () {
        k += 1;
        body.innerHTML = '<span class="cmdline">' + escHtml(s.cmd.slice(0, k)) + '</span><span class="caret"></span>';
        if (k >= s.cmd.length) {
          clearInterval(typing);
          setTimeout(function () { body.innerHTML = '<span class="cmdline">' + escHtml(s.cmd) + '</span>\n' + out + '\n<span class="cmdline"></span><span class="caret"></span>'; }, 260);
        }
      }, 38);
    };
    termTabs.forEach(function (t, i) { t.addEventListener('click', function () { play(i); }); });
    whenVisible(term, function () { play(0); });
  }

  // ---------- copy buttons ----------
  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.copy');
    if (!btn) return;
    var text = btn.getAttribute('data-copy');
    if (text === null) {
      var code = btn.parentElement.querySelector('pre');
      text = code ? code.innerText : '';
    }
    var done = function () { btn.classList.add('copied'); setTimeout(function () { btn.classList.remove('copied'); }, 1400); };
    if (navigator.clipboard) navigator.clipboard.writeText(text.replace(/\n$/, '')).then(done, function () {});
  });

  // ---------- lightbox ----------
  var box = $('.lightbox');
  if (box) {
    var img = $('img', box);
    var cap = $('.lightbox-caption', box);
    var last = null;
    document.addEventListener('click', function (e) {
      var z = e.target.closest && e.target.closest('.zoom');
      if (!z) return;
      last = z;
      img.src = z.getAttribute('data-full');
      img.alt = z.querySelector('img') ? z.querySelector('img').alt : '';
      cap.textContent = img.alt;
      box.hidden = false;
      $('.lightbox-close', box).focus();
    });
    var close = function () { box.hidden = true; img.removeAttribute('src'); if (last) last.focus(); };
    box.addEventListener('click', close);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !box.hidden) close(); });
  }

  // ---------- search ----------
  var modal = $('.search-modal');
  var index = null;
  var input = modal && $('input', modal);
  var results = modal && $('.search-results', modal);
  var empty = modal && $('.search-empty', modal);
  var sel = 0;
  var openSearch = function () {
    if (!modal) return;
    modal.hidden = false;
    input.value = '';
    renderResults('');
    setTimeout(function () { input.focus(); }, 10);
    if (!index) fetch(root + 'search.json').then(function (r) { return r.json(); }).then(function (j) { index = j; renderResults(input.value); }).catch(function () {});
  };
  var closeSearch = function () { if (modal) modal.hidden = true; };
  var mark = function (text, terms) {
    var t = escHtml(text);
    terms.forEach(function (w) { if (w.length > 1) t = t.replace(new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig'), '<mark>$1</mark>'); });
    return t;
  };
  var renderResults = function (q) {
    if (!results) return;
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    var list = [];
    if (index && terms.length) {
      index.forEach(function (d) {
        var hay = (d.t + ' ' + d.d).toLowerCase();
        var body = d.x.toLowerCase();
        var score = 0;
        var ok = terms.every(function (w) {
          var s = 0;
          if (d.t.toLowerCase().indexOf(w) >= 0) s += 10;
          if (hay.indexOf(w) >= 0) s += 4;
          d.h.forEach(function (h) { if (h[0].toLowerCase().indexOf(w) >= 0) s += 3; });
          if (body.indexOf(w) >= 0) s += 1;
          score += s;
          return s > 0;
        });
        if (!ok) return;
        var head = d.h.find(function (h) { return terms.some(function (w) { return h[0].toLowerCase().indexOf(w) >= 0; }); });
        var pos = body.indexOf(terms[0]);
        var snip = pos >= 0 ? (pos > 60 ? '…' : '') + d.x.slice(Math.max(0, pos - 60), pos + 120) + '…' : d.d;
        list.push({ score: score, url: root + d.u + (head ? '#' + head[1] : ''), title: d.t + (head ? ' › ' + head[0] : ''), section: d.s, snip: snip });
      });
      list.sort(function (a, b) { return b.score - a.score; });
    } else if (index) {
      list = index.slice(0, 7).map(function (d) { return { url: root + d.u, title: d.t, section: d.s, snip: d.d }; });
    }
    list = list.slice(0, 12);
    sel = 0;
    results.innerHTML = list.map(function (r, i) { return '<li role="option" aria-selected="' + (i === 0) + '"><a href="' + r.url + '"><small>' + escHtml(r.section) + '</small><b>' + mark(r.title, terms) + '</b><span>' + mark(r.snip, terms) + '</span></a></li>'; }).join('');
    empty.hidden = !(index && terms.length && list.length === 0);
  };
  $$('.search-open').forEach(function (b) { b.addEventListener('click', openSearch); });
  if (modal) {
    modal.addEventListener('click', function (e) { if (e.target === modal) closeSearch(); });
    input.addEventListener('input', function () { renderResults(input.value); });
    input.addEventListener('keydown', function (e) {
      var items = $$('li', results);
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!items.length) return;
        items[sel].setAttribute('aria-selected', 'false');
        sel = (sel + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
        items[sel].setAttribute('aria-selected', 'true');
        items[sel].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Enter' && items[sel]) {
        e.preventDefault();
        location.href = $('a', items[sel]).href;
        closeSearch();
      }
    });
  }
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (modal && modal.hidden) openSearch(); else closeSearch(); }
    else if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName) && modal && modal.hidden) { e.preventDefault(); openSearch(); }
    else if (e.key === 'Escape') closeSearch();
  });

  // ---------- docs: on-page TOC highlight ----------
  var tocLinks = $$('.toc a');
  if (tocLinks.length && 'IntersectionObserver' in window) {
    var heads = tocLinks.map(function (a) { return document.getElementById(decodeURIComponent(a.hash.slice(1))); }).filter(Boolean);
    var spy = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (!e.isIntersecting) return;
        tocLinks.forEach(function (a) { a.classList.toggle('active', a.hash === '#' + e.target.id); });
      });
    }, { rootMargin: '-15% 0px -75% 0px' });
    heads.forEach(function (h) { spy.observe(h); });
  }
  var current = $('.docs-nav a[aria-current]');
  if (current && current.scrollIntoView && window.innerWidth > 980) current.scrollIntoView({ block: 'center' });

  // ---------- download: highlight this device ----------
  var platforms = $$('.platform');
  if (platforms.length) {
    var ua = navigator.userAgent;
    var os = /Windows/.test(ua) ? 'windows' : /Mac OS X|Macintosh/.test(ua) ? 'macos' : /Linux|X11/.test(ua) && !/Android/.test(ua) ? 'linux' : null;
    var pick = function (arch) {
      platforms.forEach(function (p) { p.classList.toggle('match', p.getAttribute('data-os') === os && p.getAttribute('data-arch') === arch); });
    };
    if (os) {
      var guess = /arm64|aarch64/i.test(ua) ? 'arm64' : 'x64';
      pick(os === 'macos' ? 'arm64' : guess);
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        navigator.userAgentData.getHighEntropyValues(['architecture']).then(function (v) { if (v.architecture) pick(/arm/i.test(v.architecture) ? 'arm64' : 'x64'); }).catch(function () {});
      }
    }
  }
})();
