// Captures the website's screenshots from the real app, at 2x, as WebP.
// Usage: npm run site:capture   (builds the app, serves dist/ for the length of the run)
// Output: site/assets/shots/<name>.webp. The images are committed, so the site build and CI do
// not need a browser. Re-run after UI changes.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const LZString = require('lz-string');

/** A five-host fleet: one policy, each machine on its own distribution and firewall. */
const FLEET = {
  schema: 1,
  name: 'Production fleet',
  description: 'Web, database and edge hosts sharing one policy.',
  policies: { in: 'drop', out: 'accept', forward: 'drop' },
  options: { logDropped: true },
  addressGroups: [
    { id: 'admins', name: 'Admin networks', members: ['203.0.113.0/24', '2001:db8:10::/48'] },
    { id: 'apps', name: 'App servers', members: ['10.20.0.0/24'] },
  ],
  portGroups: [{ id: 'db', name: 'Database ports', ports: ['5432'] }],
  rules: [
    { id: 'ssh', name: 'SSH from admins', proto: 'tcp', ports: ['22'], src: ['@admins'] },
    { id: 'web', name: 'HTTP + HTTPS', proto: 'tcp', ports: ['80', '443'], hosts: ['h1', 'h2', 'h4'] },
    { id: 'quic', name: 'HTTP/3 (QUIC)', proto: 'udp', ports: ['443'], hosts: ['h1', 'h2'] },
    { id: 'pg', name: 'Postgres from apps', proto: 'tcp', ports: ['@db'], src: ['@apps'], hosts: ['h3'] },
    { id: 'wg', name: 'WireGuard', proto: 'udp', ports: ['51820'], hosts: ['h5'] },
  ],
  hosts: [
    { id: 'h1', name: 'web-1', address: '192.0.2.11', target: { distro: 'ubuntu-26.04', tool: 'nftables', version: '1.1.6' } },
    { id: 'h2', name: 'web-2', address: '192.0.2.12', target: { distro: 'debian-12', tool: 'nftables', version: '1.0.6' } },
    { id: 'h3', name: 'db-1', address: '10.20.0.5', target: { distro: 'rhel-9', tool: 'firewalld', version: '1.3.4' } },
    { id: 'h4', name: 'legacy-web', address: '192.0.2.40', target: { distro: 'ubuntu-20.04', tool: 'iptables', version: '1.8.4' }, overrides: { options: { ipv6: false } } },
    { id: 'h5', name: 'edge-vpn', address: '198.51.100.7', target: { distro: 'ubuntu-24.04', tool: 'ufw', version: '0.36.2' } },
  ],
};
const share = (project) => `#s=${LZString.compressToEncodedURIComponent(JSON.stringify({ project }))}`;

const OUT = path.join(__dirname, 'assets', 'shots');
const W = 1440;
const H = 900;

/** name, template to load first, page title in the sidebar, optional extra steps. */
const SHOTS = [
  { name: 'dashboard', template: 'Web server', page: 'Dashboard' },
  { name: 'dashboard-light', template: 'Web server', page: 'Dashboard', light: true },
  { name: 'rules', template: 'NAT router', page: 'Rules' },
  { name: 'nat', template: 'NAT router', page: 'NAT' },
  { name: 'objects', template: 'Database server', page: 'Objects' },
  { name: 'zones', template: 'NAT router', page: 'Zones' },
  { name: 'blocklists', template: 'Web server', page: 'Blocklists' },
  { name: 'hardening', template: 'Web server', page: 'Kernel hardening' },
  { name: 'build', template: 'Web server', page: 'Build' },
  { name: 'compare', template: 'NAT router', page: 'Compare' },
  { name: 'targets', template: 'Web server', page: 'More targets' },
  { name: 'versions', template: 'Web server', page: 'Version matrix' },
  { name: 'simulator', template: 'Web server', page: 'Simulator' },
  { name: 'reach', template: 'NAT router', page: 'Reachability' },
  { name: 'tests', template: 'Database server', page: 'Policy tests' },
  { name: 'audit', template: 'Docker host', page: 'Audit' },
  { name: 'compliance', template: 'Web server', page: 'Compliance' },
  { name: 'flow', template: 'NAT router', page: 'Packet flow' },
  { name: 'topology', template: 'NAT router', page: 'Topology' },
  { name: 'fleet', project: FLEET, page: 'Fleet' },
  { name: 'logs', template: 'Web server', page: 'Log analyzer', steps: (p) => p.click('main button:has-text("Paste sample")') },
  { name: 'assistant', template: 'Web server', page: 'Assistant' },
  { name: 'templates', template: 'Web server', page: 'Templates' },
  { name: 'snapshots', template: 'Web server', page: 'Snapshots' },
  { name: 'transfer', template: 'Web server', page: 'Import / export' },
];

async function toWebp(browser, png, quality = 0.86) {
  const p = await browser.newPage();
  const data = await p.evaluate(async ({ b64, q }) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement('canvas');
    c.width = img.naturalWidth;
    c.height = img.naturalHeight;
    c.getContext('2d').drawImage(img, 0, 0);
    return c.toDataURL('image/webp', q).split(',')[1];
  }, { b64: png.toString('base64'), q: quality });
  await p.close();
  return Buffer.from(data, 'base64');
}

(async () => {
  const only = process.argv.slice(2);
  if (!fs.existsSync(path.join(process.cwd(), 'dist', 'index.html'))) throw new Error('Run `npm run build` first.');
  const vite = await import('vite');
  const preview = await vite.preview({ logLevel: 'silent', preview: { host: '127.0.0.1', port: 4174 } });
  const base = preview.resolvedUrls.local[0];
  const browser = await chromium.launch();
  fs.mkdirSync(OUT, { recursive: true });
  try {
    for (const shot of SHOTS.filter((s) => only.length === 0 || only.includes(s.name))) {
      const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 2, reducedMotion: 'reduce', colorScheme: shot.light ? 'light' : 'dark' });
      await ctx.addInitScript(() => { try { localStorage.setItem('emberwall-welcome-seen', '1'); } catch {} });
      const page = await ctx.newPage();
      await page.goto(shot.project ? base + share(shot.project) : base);
      await page.waitForSelector('nav');
      await page.addStyleTag({ content: '[aria-live="polite"]{display:none!important}' }); // toasts
      if (shot.template) {
        await page.click('nav button[title="Templates"]');
        await page.click(`main >> text=${shot.template}`);
        await page.waitForTimeout(200);
      }
      if (shot.light) {
        const isDark = await page.evaluate(() => document.documentElement.dataset.theme !== 'light');
        if (isDark) await page.click('button[aria-label="Toggle theme"]');
      }
      await page.click(`nav button[title="${shot.page}"]`);
      await page.waitForTimeout(700);
      if (shot.steps) {
        await shot.steps(page);
        await page.waitForTimeout(500);
      }
      const png = await page.screenshot({ type: 'png' });
      const webp = await toWebp(browser, png);
      fs.writeFileSync(path.join(OUT, `${shot.name}.webp`), webp);
      console.log(`${shot.name.padEnd(16)} ${(webp.length / 1024).toFixed(0)} KB`);
      await ctx.close();
    }
    // Server-mode screens need a live SSH target, so they come from the README's captures.
    for (const name of ['live-audit', 'live-push']) {
      if (only.length && !only.includes(name)) continue;
      const webp = await toWebp(browser, fs.readFileSync(path.join(process.cwd(), 'docs', `${name}.png`)));
      fs.writeFileSync(path.join(OUT, `${name}.webp`), webp);
      console.log(`${name.padEnd(16)} ${(webp.length / 1024).toFixed(0)} KB (from docs/${name}.png)`);
    }
    // Social preview image, rendered from site/og.html.
    if (!only.length || only.includes('og')) {
      const og = await browser.newPage({ viewport: { width: 1200, height: 630 } });
      await og.goto('file://' + path.join(__dirname, 'og.html'));
      await og.waitForTimeout(400);
      await og.screenshot({ path: path.join(__dirname, 'assets', 'og.png') });
      await og.close();
      console.log('og.png           1200x630');
    }
  } finally {
    await browser.close();
    await preview.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
