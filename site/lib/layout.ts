// Page shell shared by every page of the website: head, header, footer, icons.
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Lucide from 'lucide-react';
import { esc } from './highlight';

export const REPO = 'cloudlative/emberwall';
export const REPO_URL = `https://github.com/${REPO}`;
/** Absolute URL of the site root, used only where a link must be absolute (canonical, sitemap, OG, install). */
export const SITE_URL = (process.env.EMBERWALL_SITE_URL ?? 'https://emberwall.cloudlative.com/').replace(/\/?$/, '/');

/** An inline Lucide icon (the same icon set the app uses). */
export function icon(name: keyof typeof Lucide | string, size = 18, stroke = 1.75): string {
  const C = (Lucide as unknown as Record<string, Lucide.LucideIcon | undefined>)[name];
  if (!C) throw new Error(`unknown icon ${name}`);
  return renderToStaticMarkup(createElement(C, { size, strokeWidth: stroke, 'aria-hidden': true }));
}

export const LOGO = `<svg class="logo-mark" viewBox="0 0 32 32" aria-hidden="true"><defs><linearGradient id="lg-ember" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffd2a8"/><stop offset=".45" stop-color="#ff8f5c"/><stop offset="1" stop-color="#ec4f17"/></linearGradient></defs><path d="M16 3.5l10 3.9v7.8c0 6.1-4.2 10.700-10 12.800-5.800-2.100-10-6.700-10-12.800V7.4z" fill="url(#lg-ember)"/><path d="M16 10.600c2.200 2.700 3.900 4.200 3.900 6.600a3.900 3.900 0 01-7.800 0c0-1.300.6-2.200 1.400-3.100.2 1.100.9 1.700 1.600 1.700.3-1.900.2-3.500.9-5.200z" fill="#0b0d14"/></svg>`;

export interface PageMeta {
  /** Output path relative to the site root, e.g. "index.html" or "docs/rules/index.html". */
  out: string;
  title: string;
  description: string;
  /** Which top-level nav item is active. */
  nav?: 'home' | 'docs' | 'download';
  bodyClass?: string;
  /** Extra script files (relative to assets/js). */
  scripts?: string[];
  /** For 404: links resolve against the site root rather than the page's own folder. */
  absoluteBase?: boolean;
}

/** Prefix that leads from a page back to the site root. */
export const rootOf = (out: string) => '../'.repeat(out.split('/').length - 1) || './';

export function page(meta: PageMeta, body: string): string {
  const root = meta.absoluteBase ? new URL(SITE_URL).pathname : rootOf(meta.out);
  const r = (p: string) => root + p;
  const canonical = SITE_URL + meta.out.replace(/index\.html$/, '');
  const fullTitle = meta.nav === 'home' ? meta.title : `${meta.title} · Emberwall`;
  const navLink = (id: string, href: string, label: string) => `<a href="${r(href)}"${meta.nav === id ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<!doctype html>
<html lang="en" data-root="${root}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(fullTitle)}</title>
<meta name="description" content="${esc(meta.description)}">
<link rel="canonical" href="${canonical}">
<meta name="theme-color" content="#05060b" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f2ec" media="(prefers-color-scheme: light)">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Emberwall">
<meta property="og:title" content="${esc(fullTitle)}">
<meta property="og:description" content="${esc(meta.description)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${SITE_URL}assets/og.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="${r('favicon.svg')}" type="image/svg+xml">
<link rel="preload" href="${r('assets/fonts/inter.woff2')}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${r('assets/css/site.css')}">
<script>try{var t=localStorage.getItem('ew-site-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
</head>
<body class="${meta.bodyClass ?? ''}">
<a class="skip" href="#main">Skip to content</a>
<div class="noise" aria-hidden="true"></div>
<header class="site-header" id="top">
  <div class="header-inner">
    <a class="brand" href="${r('')}" aria-label="Emberwall home">${LOGO}<span>Emberwall</span></a>
    <nav class="main-nav" aria-label="Main">
      <a href="${r('')}#features">Features</a>
      ${navLink('docs', 'docs/', 'Docs')}
      ${navLink('download', 'download/', 'Download')}
      <a href="${REPO_URL}" rel="noopener">GitHub</a>
    </nav>
    <div class="header-actions">
      <button class="icon-btn search-open" type="button" aria-label="Search the docs" title="Search (Ctrl K)">${icon('Search', 17)}<kbd>Ctrl K</kbd></button>
      <button class="icon-btn theme-toggle" type="button" aria-label="Switch between dark and light theme" title="Theme">${icon('Moon', 17)}${icon('Sun', 17)}</button>
      <a class="btn btn-ember btn-sm" href="${r('app/')}">Open the app ${icon('ArrowUpRight', 15)}</a>
      <button class="icon-btn menu-toggle" type="button" aria-label="Menu" aria-expanded="false">${icon('Menu', 20)}</button>
    </div>
  </div>
</header>
<main id="main">
${body}
</main>
${footer(r)}
<div class="search-modal" role="dialog" aria-modal="true" aria-label="Search the docs" hidden>
  <div class="search-panel">
    <div class="search-field">${icon('Search', 18)}<input type="search" placeholder="Search the docs…" aria-label="Search" autocomplete="off" spellcheck="false"><kbd>Esc</kbd></div>
    <ul class="search-results" role="listbox"></ul>
    <p class="search-empty" hidden>No matches. Try fewer or different words.</p>
  </div>
</div>
<div class="lightbox" hidden><button class="icon-btn lightbox-close" type="button" aria-label="Close">${icon('X', 20)}</button><img alt=""><p class="lightbox-caption"></p></div>
<script src="${r('assets/js/site.js')}" defer></script>
${(meta.scripts ?? []).map((s) => `<script src="${r(`assets/js/${s}`)}" defer></script>`).join('\n')}
</body>
</html>
`;
}

function footer(r: (p: string) => string): string {
  const col = (title: string, links: [string, string][]) => `<div class="footer-col"><h4>${title}</h4><ul>${links.map(([label, href]) => `<li><a href="${href}">${label}</a></li>`).join('')}</ul></div>`;
  return `<footer class="site-footer">
  <div class="footer-glow" aria-hidden="true"></div>
  <div class="footer-inner">
    <div class="footer-brand">
      <a class="brand" href="${r('')}">${LOGO}<span>Emberwall</span></a>
      <p>Design a Linux firewall once. Compile it for the exact tool and version you run. Prove it, then ship it safely.</p>
      <p class="footer-privacy">${icon('ShieldCheck', 15)} The app runs in your browser. Rulesets are never uploaded.</p>
    </div>
    ${col('Product', [['Features', `${r('')}#features`], ['Open the app', r('app/')], ['Download', r('download/')], ['Changelog', r('docs/changelog/')]])}
    ${col('Learn', [['Quick start', r('docs/quick-start/')], ['Targets and versions', r('docs/targets-and-versions/')], ['Server mode', r('docs/server-mode/')], ['Command line', r('docs/cli/')]])}
    ${col('Project', [['GitHub', REPO_URL], ['Releases', `${REPO_URL}/releases`], ['Report an issue', `${REPO_URL}/issues`], ['License (MIT)', `${REPO_URL}/blob/main/LICENSE`]])}
  </div>
  <div class="footer-base"><span>Emberwall · MIT licensed</span><a href="#top">Back to top ${icon('ArrowUp', 14)}</a></div>
</footer>`;
}
