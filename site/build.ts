// Builds the website into dist-site/.  Run: npm run site:build
// The app itself (npm run build -> dist/) is copied into dist-site/app/ when it exists.
// Set EMBERWALL_SITE_URL for a custom domain (default https://cloudlative.github.io/emberwall/).

// The CLI module runs itself when its process looks like a CLI run; vite-node does. Imports below
// are dynamic so this is set first.
process.env.VITEST = '1';

const { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } = await import('node:fs');
const { dirname, join } = await import('node:path');
const { fileURLToPath } = await import('node:url');
const data = await import('./lib/data');
const { docPage, docsIndex, loadDocs, searchIndex } = await import('./lib/docs');
const { page, SITE_URL } = await import('./lib/layout');
const { home } = await import('./pages/home');
const { download, notFound } = await import('./pages/download');

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const out = join(root, 'dist-site');
const started = Date.now();

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
const write = (rel: string, text: string) => {
  const file = join(out, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
};

// ---------- assets ----------
cpSync(join(here, 'assets'), join(out, 'assets'), { recursive: true, filter: (src) => !src.endsWith('install.sh') });
const fonts: [string, string][] = [
  ['@fontsource-variable/inter/files/inter-latin-wght-normal.woff2', 'inter.woff2'],
  ['@fontsource-variable/inter/files/inter-latin-wght-italic.woff2', 'inter-italic.woff2'],
  ['@fontsource/instrument-serif/files/instrument-serif-latin-400-italic.woff2', 'instrument-serif-italic.woff2'],
  ['@fontsource/instrument-serif/files/instrument-serif-latin-400-normal.woff2', 'instrument-serif.woff2'],
  ['@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2', 'jetbrains-mono.woff2'],
];
mkdirSync(join(out, 'assets', 'fonts'), { recursive: true });
for (const [from, to] of fonts) cpSync(join(root, 'node_modules', from), join(out, 'assets', 'fonts', to));
cpSync(join(root, 'public', 'favicon.svg'), join(out, 'favicon.svg'));
write('install.sh', readFileSync(join(here, 'assets', 'install.sh'), 'utf8').replaceAll('https://cloudlative.github.io/emberwall/', SITE_URL));

// ---------- pages ----------
const homeData = {
  samples: data.codeSamples(),
  journey: data.versionJourney(),
  sims: data.simulations(),
  audit: data.auditDemo(),
  cli: data.cliSessions(),
  apply: data.safeApplyExcerpt(),
  facts: data.facts,
};
write('index.html', page({ out: 'index.html', nav: 'home', bodyClass: 'home', title: 'Emberwall · Design a firewall once, ship it everywhere', description: 'Emberwall compiles one visual firewall policy into nftables, iptables, ufw and firewalld rules for the exact version you run. Simulate, audit and apply with automatic rollback. Runs in your browser.', scripts: ['hero.js'] }, home(homeData)));

const docs = loadDocs(join(here, 'docs'));
write('docs/index.html', page({ out: 'docs/index.html', nav: 'docs', bodyClass: 'docs-home', title: 'Documentation', description: 'Emberwall documentation: designing rules, version-aware builds, simulation, audit, fleets, server mode, live servers and the CLI.' }, docsIndex(docs)));
docs.forEach((d, i) => write(`docs/${d.slug}/index.html`, page({ out: `docs/${d.slug}/index.html`, nav: 'docs', bodyClass: 'doc-page', title: d.title, description: d.description }, docPage(docs, i))));
write('search.json', JSON.stringify(searchIndex(docs)));

write('download/index.html', page({ out: 'download/index.html', nav: 'download', bodyClass: 'download-page', title: 'Download', description: 'Download Emberwall as a single self-contained binary for Linux, macOS and Windows: the CLI, server mode and the web app in one file.' }, download(data.pkg.version)));
write('404.html', page({ out: '404.html', title: 'Not found', description: 'This page does not exist.', absoluteBase: true, bodyClass: 'nf-page' }, notFound()));

// ---------- SEO ----------
const urls = ['', 'docs/', 'download/', ...docs.map((d) => `docs/${d.slug}/`)];
write('sitemap.xml', `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${SITE_URL}${u}</loc></url>`).join('\n')}\n</urlset>\n`);
write('robots.txt', `User-agent: *\nAllow: /\nSitemap: ${SITE_URL}sitemap.xml\n`);
write('.nojekyll', '');

// ---------- the app ----------
const app = join(root, 'dist');
if (existsSync(join(app, 'index.html'))) cpSync(app, join(out, 'app'), { recursive: true });
else console.warn('note: dist/ not found, so the site has no app/ (run "npm run build" first)');

console.log(`site: ${docs.length} docs pages, ${urls.length} URLs, app ${existsSync(join(out, 'app')) ? 'included' : 'missing'} -> dist-site/ (${Date.now() - started} ms)`);
