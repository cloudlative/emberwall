// Layout check: no two cards may overlap, and no page may scroll sideways.
// Usage: node scripts/check-layout.cjs [baseUrl]   (needs `npm run preview` or the server running;
// for a server-mode instance set EW_USER and EW_PASS)
const { chromium } = require('playwright');

const SIZES = [[1440, 900], [1100, 800], [820, 1000]];

(async () => {
  const base = process.argv[2] || 'http://localhost:4173/';
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => { try { localStorage.setItem('emberwall-welcome-seen', '1'); } catch {} });
  const page = await ctx.newPage();
  const problems = [];
  await page.goto(base);
  // Server mode: sign in with EW_USER / EW_PASS when the login screen is shown.
  await page.waitForSelector('nav, form');
  if (!(await page.locator('nav').count())) {
    await page.fill('input[autocomplete="username"]', process.env.EW_USER || '');
    await page.fill('input[type="password"]', process.env.EW_PASS || '');
    await page.click('button:has-text("Sign in")');
  }
  await page.waitForSelector('nav');
  // A project with enough content to fill every panel.
  await page.click('nav button[title="Templates"]');
  await page.click('main >> text=NAT router');
  const titles = await page.$$eval('nav button', (els) => els.map((e) => e.title));
  for (const [w, h] of SIZES) {
    await page.setViewportSize({ width: w, height: h });
    for (const title of titles) {
      await page.click(`nav button[title="${title}"]`);
      await page.waitForTimeout(350); // let the page-enter animation settle
      const found = await page.evaluate(() => {
        const out = [];
        if (document.documentElement.scrollWidth > window.innerWidth) out.push('page scrolls sideways');
        const cards = [...document.querySelectorAll('main .glass, main .tile')].filter((el) => el.offsetParent !== null);
        const label = (el) => (el.querySelector('h1,h2,.font-semibold')?.textContent || el.textContent || '').trim().slice(0, 40);
        for (let i = 0; i < cards.length; i += 1) {
          for (let j = i + 1; j < cards.length; j += 1) {
            const a = cards[i];
            const b = cards[j];
            if (a.contains(b) || b.contains(a)) continue;
            const ra = a.getBoundingClientRect();
            const rb = b.getBoundingClientRect();
            const x = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
            const y = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
            if (x > 2 && y > 2) out.push(`"${label(a)}" overlaps "${label(b)}" by ${Math.round(x)}x${Math.round(y)}px`);
          }
        }
        // Content spilling out of its own card is the same bug seen from the inside.
        for (const c of cards) {
          if (c.scrollHeight > c.clientHeight + 2 && getComputedStyle(c).overflowY === 'visible') out.push(`"${label(c)}" content is taller than its card by ${c.scrollHeight - c.clientHeight}px`);
        }
        return out;
      });
      for (const f of found.slice(0, 4)) problems.push(`${w}x${h} ${title}: ${f}`);
    }
  }
  await browser.close();
  if (problems.length) {
    console.log(problems.join('\n'));
    console.log(`\n${problems.length} layout problem(s)`);
    process.exit(1);
  }
  console.log(`layout ok: ${titles.length} pages x ${SIZES.length} sizes`);
})();
