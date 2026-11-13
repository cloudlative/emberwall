// Layout check: no two cards may overlap, and no page may scroll sideways.
// Usage: node scripts/check-layout.cjs [baseUrl]
// With no baseUrl it serves the built app (dist/) itself for the length of the check, so run
// `npm run build` first; `npm run check:layout` does both. Pass a baseUrl to check something
// already running, such as a server-mode instance (set EW_USER and EW_PASS to sign in).
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const SIZES = [[1440, 900], [1100, 800], [820, 1000]];

(async () => {
  let base = process.argv[2];
  let preview = null;
  if (!base) {
    if (!fs.existsSync(path.join(process.cwd(), 'dist', 'index.html'))) {
      console.error('Nothing to check: dist/ is missing. Run `npm run build` first, or pass the URL of a running instance.');
      process.exit(1);
    }
    const vite = await import('vite'); // ESM-only, so it cannot be require()d here
    preview = await vite.preview({ logLevel: 'silent', preview: { host: '127.0.0.1', port: 4173 } });
    base = preview.resolvedUrls.local[0];
  }
  let browser;
  try {
    browser = await chromium.launch();
  } catch (err) {
    if (preview) await preview.close();
    console.error(`Could not start the browser. Run \`npx playwright install chromium\` once.\n${err.message.split('\n')[0]}`);
    process.exit(1);
  }
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => { try { localStorage.setItem('emberwall-welcome-seen', '1'); } catch {} });
  const page = await ctx.newPage();
  const problems = [];
  try {
    await page.goto(base);
  } catch (err) {
    await browser.close();
    console.error(`Could not open ${base}. Is it running?\n${err.message.split('\n')[0]}`);
    process.exit(1);
  }
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
  if (preview) await preview.close();
  if (problems.length) {
    console.log(problems.join('\n'));
    console.log(`\n${problems.length} layout problem(s)`);
    process.exit(1);
  }
  console.log(`layout ok: ${titles.length} pages x ${SIZES.length} sizes`);
})();
