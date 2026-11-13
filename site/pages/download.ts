// The download page: one card per platform, the install script, and how to verify.
import { esc, highlight } from '../lib/highlight';
import { icon, REPO_URL, SITE_URL } from '../lib/layout';

const latest = `${REPO_URL}/releases/latest/download`;

const PLATFORMS = [
  { os: 'linux', arch: 'x64', label: 'Linux', sub: 'x86-64', ic: 'Terminal', file: 'emberwall-linux-x64' },
  { os: 'linux', arch: 'arm64', label: 'Linux', sub: 'ARM64', ic: 'Terminal', file: 'emberwall-linux-arm64' },
  { os: 'macos', arch: 'arm64', label: 'macOS', sub: 'Apple silicon', ic: 'Laptop', file: 'emberwall-macos-arm64' },
  { os: 'macos', arch: 'x64', label: 'macOS', sub: 'Intel', ic: 'Laptop', file: 'emberwall-macos-x64' },
  { os: 'windows', arch: 'x64', label: 'Windows', sub: 'x86-64', ic: 'Monitor', file: 'emberwall-windows-x64.exe' },
];

const block = (text: string, lang: string) => `<div class="code-block"><button class="copy" type="button" aria-label="Copy code">${icon('Copy', 15)}</button><pre class="code"><code>${highlight(text, lang)}</code></pre></div>`;

export function download(version: string): string {
  const install = `curl -fsSL ${SITE_URL}install.sh | sh`;
  return `
<section class="docs-hero download-hero">
  <div class="hero-aurora small" aria-hidden="true"><i></i><i></i><i></i></div>
  <div class="container">
    <p class="eyebrow">${icon('Download', 15)} Download · v${esc(version)}</p>
    <h1 class="display-sm">One file. <em>Everything</em> inside.</h1>
    <p class="lead">The CLI, server mode and the whole web app in a single executable. No Node.js, no dependencies, no install step beyond copying it somewhere on your <code>PATH</code>.</p>
    <div class="cmd glass install-cmd"><span class="prompt">$</span><code>${esc(install)}</code><button class="copy" type="button" data-copy="${esc(install)}" aria-label="Copy install command">${icon('Copy', 15)}</button></div>
    <p class="cta-small">Linux and macOS. Detects your platform, verifies the SHA-256 checksum, installs to <code>/usr/local/bin</code> or <code>~/.local/bin</code>.</p>
  </div>
</section>
<section class="container platforms" aria-label="Downloads by platform">
  ${PLATFORMS.map((p) => `
  <a class="platform glass reveal" href="${latest}/${p.file}" data-os="${p.os}" data-arch="${p.arch}" download>
    <span class="recommended">${icon('Sparkles', 13)} For this device</span>
    <span class="tile-icon">${icon(p.ic, 22)}</span>
    <b>${p.label}</b><small>${p.sub}</small>
    <code>${p.file}</code>
    <span class="dl">${icon('Download', 16)} Download</span>
  </a>`).join('')}
</section>
<section class="container download-more">
  <div class="dl-col glass reveal">
    <h2>${icon('ShieldCheck', 18)} Verify the download</h2>
    <p>Every release publishes a <code>SHA256SUMS</code> file. The install script checks it for you; to check by hand:</p>
    ${block(`curl -fsSLO ${latest}/SHA256SUMS\nsha256sum --ignore-missing -c SHA256SUMS      # Linux\nshasum -a 256 --ignore-missing -c SHA256SUMS  # macOS`, 'sh')}
    <p class="muted">Third-party license notices ship as <code>THIRD_PARTY_NOTICES.txt</code> and are printed by <code>emberwall licenses</code>.</p>
  </div>
  <div class="dl-col glass reveal">
    <h2>${icon('Rocket', 18)} First run</h2>
    ${block(`chmod +x emberwall-linux-x64 && sudo mv emberwall-linux-x64 /usr/local/bin/emberwall\nemberwall --version\nemberwall targets\nemberwall build web.json --target debian-12:nftables --out build/\nEMBERWALL_SECRET="$(head -c 48 /dev/urandom | base64)" emberwall serve`, 'sh')}
    <p class="muted"><code>serve</code> listens on <code>http://127.0.0.1:8787</code> and keeps its database in <code>./data/emberwall.db</code>. See <a href="../docs/server-mode/">server mode</a>.</p>
  </div>
  <div class="dl-col glass reveal">
    <h2>${icon('Laptop', 18)} macOS and Windows notes</h2>
    <p><b>macOS:</b> the binaries are signed ad hoc but not notarized, so a browser download is quarantined. Allow it once:</p>
    ${block('xattr -d com.apple.quarantine emberwall-macos-*', 'sh')}
    <p><b>Windows:</b> the executable is unsigned; SmartScreen may ask you to confirm. Run it from PowerShell:</p>
    ${block('.\\emberwall-windows-x64.exe --version', 'powershell')}
  </div>
  <div class="dl-col glass reveal">
    <h2>${icon('Globe', 18)} No install at all</h2>
    <p>The whole designer runs in your browser and keeps working offline after the first visit. Install it as an app from the address bar if you like.</p>
    <a class="btn btn-ember" href="../app/">${icon('Flame', 16)} Open the app</a>
    <h2 class="mt">${icon('GitBranch', 18)} From source</h2>
    ${block(`git clone ${REPO_URL}.git\ncd emberwall && npm install\nnpm run dev          # http://localhost:5173\nnpm run build:bin    # your own single-file binary`, 'sh')}
  </div>
</section>
<section class="container all-releases reveal"><a class="text-link" href="${REPO_URL}/releases">${icon('History', 15)} All releases and release notes ${icon('ArrowRight', 15)}</a></section>`;
}

export function notFound(): string {
  return `
<section class="not-found">
  <div class="hero-aurora small" aria-hidden="true"><i></i><i></i><i></i></div>
  <div class="container">
    <p class="nf-code">404</p>
    <h1 class="display-sm">This packet was <em>dropped</em>.</h1>
    <p class="lead">No rule matched that address. The default policy sent you here instead.</p>
    <div class="cta-row"><a class="btn btn-ember" href="./">${icon('House', 16)} Home</a><a class="btn btn-glass" href="docs/">${icon('BookOpen', 16)} Docs</a><button class="btn btn-glass search-open" type="button">${icon('Search', 16)} Search</button></div>
  </div>
</section>`;
}
