// Documentation: Markdown files in site/docs/NN-slug.md rendered into pages with a sidebar,
// an on-page table of contents, previous/next links and a search index.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Marked, type Tokens } from 'marked';
import { auditChecks, facts, runCli } from './data';
import { esc, highlight } from './highlight';
import { icon, REPO_URL, SITE_URL } from './layout';

export const SECTIONS = ['Getting started', 'Design', 'Ship', 'Verify', 'Operate', 'Server mode', 'Reference'] as const;
const SECTION_ICON: Record<string, string> = { 'Getting started': 'Rocket', Design: 'PenTool', Ship: 'Package', Verify: 'FlaskConical', Operate: 'Gauge', 'Server mode': 'ServerCog', Reference: 'BookMarked' };

export interface Doc {
  slug: string;
  file: string;
  title: string;
  description: string;
  section: string;
  order: number;
  html: string;
  headings: { depth: number; text: string; id: string }[];
  text: string;
}

export const slugify = (s: string) => s.toLowerCase().replace(/<[^>]+>/g, '').replace(/&[a-z]+;/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function frontMatter(src: string, file: string): { meta: Record<string, string>; body: string } {
  const m = /^---\n([\s\S]*?)\n---\n?/.exec(src);
  if (!m) throw new Error(`${file}: missing front matter`);
  const meta: Record<string, string> = {};
  for (const line of m[1].split('\n')) {
    const i = line.indexOf(':');
    if (i > 0) meta[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^["']|["']$/g, '');
  }
  for (const k of ['title', 'description', 'section']) if (!meta[k]) throw new Error(`${file}: front matter needs "${k}"`);
  if (!(SECTIONS as readonly string[]).includes(meta.section)) throw new Error(`${file}: unknown section "${meta.section}"`);
  return { meta, body: src.slice(m[0].length) };
}

// ---------- generated tables ----------
const table = (head: string[], rows: string[][]) =>
  `<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const codeBlock = (text: string, lang = 'text') => `<div class="code-block"><button class="copy" type="button" aria-label="Copy code">${icon('Copy', 15)}</button><pre class="code"><code class="lang-${lang}">${highlight(text, lang)}</code></pre></div>`;

export function placeholders(): Record<string, string> {
  const t = facts.toolLabel;
  return {
    distros: table(['Distribution', ...facts.tools.map((x) => t[x]), 'Notes'], facts.distros.map((d) => [
      `<b>${esc(d.name)}</b><br><code>${d.id}</code>`,
      ...facts.tools.map((x) => (d.tools[x] ? `${d.tools[x]}${d.defaultTool === x ? ' <span class="badge">default</span>' : ''}` : '<span class="muted">not packaged</span>')),
      esc([d.note, d.disable?.length ? `Kernel too old for: ${d.disable.map((k) => facts.capabilities.find((c) => c.key === k)?.label ?? k).join(', ')}` : ''].filter(Boolean).join(' ')),
    ])),
    capabilities: table(['Tool', 'Feature', 'Since', 'Kernel', 'Without it'], facts.capabilities.map((c) => [t[c.tool], esc(c.label), `<code>${c.since}</code>`, c.kernel ? `<code>${c.kernel}</code>` : '', esc(c.fallback)])),
    versions: table(['Tool', 'Versions Emberwall writes for'], facts.tools.map((x) => [t[x], facts.versions[x].map((v) => `<code>${v}</code>`).join(' ')])),
    templates: table(['Template', 'What it is for', 'Rules'], facts.templates.map((x) => [`<b>${esc(x.name)}</b>`, esc(x.summary), String(x.rules)])),
    'audit-checks': table(['Severity', 'Finding (example wording)'], auditChecks().map((c) => [`<span class="sev sev-${c.severity}">${c.severity}</span>`, esc(c.title)])),
    'compliance-profiles': facts.profiles.map((p) => `<div class="profile"><h4>${esc(p.name)} <code>--profile ${p.id}</code></h4><p>${esc(p.about)}</p>${table(['Control', 'Intent'], p.controls.map((c) => [esc(c.title), esc(c.intent)]))}</div>`).join(''),
    'extra-targets': table(['Target', 'Notes'], facts.extraTargets.map((x) => [`<b>${esc(x.label)}</b>`, esc(x.description)])),
    'cli-help': codeBlock(runCli(['--help']), 'text'),
    'cli-targets': codeBlock(runCli(['targets']), 'text'),
    'probe-commands': table(['Purpose', 'Command'], Object.entries(facts.probeCommands).map(([k, v]) => [`<code>${k}</code>`, `<code>${esc(v)}</code>`])),
    sysctl: table(['Setting', 'Recommended', 'Why', 'Keys'], facts.hardening.map((h) => [`<b>${esc(h.label)}</b>`, h.recommended ? 'yes' : 'no', esc(h.why) + (h.caution ? `<br><span class="muted">Caution: ${esc(h.caution)}</span>` : ''), h.lines.map(([k, v]) => `<code>${esc(k)} = ${esc(v)}</code>`).join('<br>')])),
    install: codeBlock(`curl -fsSL ${SITE_URL}install.sh | sh`, 'sh'),
  };
}

// ---------- rendering ----------
const CALLOUT: Record<string, [string, string]> = { NOTE: ['Info', 'Note'], TIP: ['Lightbulb', 'Tip'], WARNING: ['TriangleAlert', 'Warning'], IMPORTANT: ['CircleAlert', 'Important'], CAUTION: ['OctagonAlert', 'Caution'] };

export function loadDocs(dir: string): Doc[] {
  const files = readdirSync(dir).filter((f) => /^\d+-[a-z0-9-]+\.md$/.test(f)).sort();
  const slugs = new Set(files.map((f) => f.replace(/^\d+-|\.md$/g, '')));
  const generated = placeholders();
  const shots = new Set(readdirSync(join(dir, '..', 'assets', 'shots')).map((f) => f.replace(/\.webp$/, '')));
  const anchors: { file: string; target: string; hash: string }[] = [];
  const docs = files.map((file, idx) => {
    const { meta, body } = frontMatter(readFileSync(join(dir, file), 'utf8'), file);
    const slug = file.replace(/^\d+-|\.md$/g, '');
    const headings: Doc['headings'] = [];
    const used = new Map<string, number>();
    const problems: string[] = [];
    const md = new Marked({ gfm: true });
    md.use({
      renderer: {
        heading({ tokens, depth }: Tokens.Heading) {
          const inner = this.parser.parseInline(tokens);
          let id = slugify(inner) || 'section';
          const n = used.get(id) ?? 0;
          used.set(id, n + 1);
          if (n) id = `${id}-${n}`;
          if (depth <= 3) headings.push({ depth, text: inner.replace(/<[^>]+>/g, ''), id });
          return `<h${depth} id="${id}"><a class="anchor" href="#${id}" aria-hidden="true" tabindex="-1">#</a>${inner}</h${depth}>\n`;
        },
        code({ text, lang }: Tokens.Code) {
          return codeBlock(text, (lang ?? 'text').split(/\s/)[0]);
        },
        link({ href, title, tokens }: Tokens.Link) {
          const inner = this.parser.parseInline(tokens);
          let url = href;
          let ext = false;
          if (href.startsWith('doc:')) {
            const [target, hash] = href.slice(4).split('#');
            if (!slugs.has(target)) problems.push(`link to unknown doc "${target}"`);
            else if (hash) anchors.push({ file, target, hash });
            url = `../${target}/${hash ? `#${hash}` : ''}`;
          } else if (href.startsWith('app:')) url = `../../app/${href.slice(4)}`;
          else if (/^https?:/.test(href)) ext = true;
          return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ''}${ext ? ' rel="noopener"' : ''}>${inner}${ext ? `<span class="ext">${icon('ArrowUpRight', 12)}</span>` : ''}</a>`;
        },
        image({ href, text }: Tokens.Image) {
          if (href.startsWith('shot:')) {
            const name = href.slice(5);
            if (!shots.has(name)) problems.push(`unknown screenshot "${name}"`);
            const src = `../../assets/shots/${name}.webp`;
            return `<figure class="doc-shot"><button type="button" class="zoom" data-full="${src}" aria-label="Enlarge: ${esc(text)}"><img src="${src}" alt="${esc(text)}" loading="lazy" decoding="async" width="2880" height="1800"></button><figcaption>${esc(text)}</figcaption></figure>`;
          }
          return `<img src="${esc(href)}" alt="${esc(text)}" loading="lazy">`;
        },
        blockquote({ tokens }: Tokens.Blockquote) {
          const inner = this.parser.parse(tokens);
          const m = /^<p>\[!(NOTE|TIP|WARNING|IMPORTANT|CAUTION)\]\s*/.exec(inner);
          if (!m) return `<blockquote>${inner}</blockquote>`;
          const [ic, label] = CALLOUT[m[1]];
          return `<div class="callout callout-${m[1].toLowerCase()}"><div class="callout-title">${icon(ic, 16)} ${label}</div>${inner.replace(m[0], '<p>').replace(/^<p>\s*<\/p>/, '')}</div>`;
        },
        table(token: Tokens.Table) {
          const cell = (c: Tokens.TableCell) => this.parser.parseInline(c.tokens);
          const head = `<tr>${token.header.map((h) => `<th${h.align ? ` style="text-align:${h.align}"` : ''}>${cell(h)}</th>`).join('')}</tr>`;
          const rows = token.rows.map((r) => `<tr>${r.map((c) => `<td${c.align ? ` style="text-align:${c.align}"` : ''}>${cell(c)}</td>`).join('')}</tr>`).join('');
          return `<div class="table-wrap"><table><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
        },
      },
    });
    // Placeholders sit alone on a line; replace them with the generated HTML before Markdown runs.
    const src = body.replace(/^\{\{([a-z-]+)\}\}\s*$/gm, (_, name: string) => {
      if (!generated[name]) {
        problems.push(`unknown placeholder {{${name}}}`);
        return '';
      }
      return `\n<div class="generated" data-source="${name}">${generated[name]}</div>\n`;
    }).replace(/\{\{install\}\}/g, () => `\`curl -fsSL ${SITE_URL}install.sh | sh\``);
    const html = md.parse(src) as string;
    if (problems.length) {
      // EMBERWALL_SITE_DRAFT=1 reports problems without failing (for work in progress).
      if (process.env.EMBERWALL_SITE_DRAFT) console.warn(`warning: ${file}: ${problems.join('; ')}`);
      else throw new Error(`${file}: ${problems.join('; ')}`);
    }
    const text = html.replace(/<a class="anchor"[^>]*>#<\/a>/g, '').replace(/<pre[\s\S]*?<\/pre>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/g, ' ').replace(/\s+/g, ' ').trim();
    return { slug, file, title: meta.title, description: meta.description, section: meta.section, order: idx, html, headings, text };
  });
  const bad = anchors.filter((a) => !docs.find((d) => d.slug === a.target)!.html.includes(`id="${a.hash}"`));
  if (bad.length) {
    const msg = bad.map((a) => `${a.file}: no heading #${a.hash} in "${a.target}"`).join('\n');
    if (process.env.EMBERWALL_SITE_DRAFT) console.warn(msg);
    else throw new Error(msg);
  }
  return docs;
}

function sidebar(docs: Doc[], current: string | null, prefix: string): string {
  return SECTIONS.filter((s) => docs.some((d) => d.section === s)).map((s) => `
      <div class="nav-group"><h4>${icon(SECTION_ICON[s], 15)} ${s}</h4><ul>${docs.filter((d) => d.section === s).map((d) => `<li><a href="${prefix}${d.slug}/"${d.slug === current ? ' aria-current="page"' : ''}>${esc(d.title)}</a></li>`).join('')}</ul></div>`).join('');
}

export function docPage(docs: Doc[], i: number): string {
  const d = docs[i];
  const prev = docs[i - 1];
  const next = docs[i + 1];
  const toc = d.headings.filter((h) => h.depth === 2 || h.depth === 3);
  return `
<div class="docs-layout">
  <aside class="docs-nav" aria-label="Documentation">
    <button class="docs-nav-toggle" type="button" aria-expanded="false">${icon('PanelLeft', 16)} ${esc(d.section)} · ${esc(d.title)} ${icon('ChevronDown', 16)}</button>
    <div class="docs-nav-inner">${sidebar(docs, d.slug, '../')}</div>
  </aside>
  <article class="doc">
    <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="../">Docs</a>${icon('ChevronRight', 14)}<span>${esc(d.section)}</span></nav>
    <h1>${esc(d.title)}</h1>
    <p class="doc-lede">${esc(d.description)}</p>
    <div class="prose">${d.html}</div>
    <footer class="doc-footer">
      <div class="pager">
        ${prev ? `<a class="pager-link prev" href="../${prev.slug}/"><small>${icon('ArrowLeft', 14)} Previous</small><b>${esc(prev.title)}</b></a>` : '<span></span>'}
        ${next ? `<a class="pager-link next" href="../${next.slug}/"><small>Next ${icon('ArrowRight', 14)}</small><b>${esc(next.title)}</b></a>` : '<span></span>'}
      </div>
      <p class="edit"><a href="${REPO_URL}/blob/main/site/docs/${d.file}" rel="noopener">${icon('Pencil', 14)} Edit this page on GitHub</a> · <a href="${REPO_URL}/issues/new?title=${encodeURIComponent(`Docs: ${d.title}`)}" rel="noopener">${icon('MessageCircle', 14)} Report a problem</a></p>
    </footer>
  </article>
  <aside class="toc" aria-label="On this page">${toc.length ? `<h4>On this page</h4><ul>${toc.map((h) => `<li class="d${h.depth}"><a href="#${h.id}">${h.text}</a></li>`).join('')}</ul>` : ''}</aside>
</div>`;
}

export function docsIndex(docs: Doc[]): string {
  return `
<section class="docs-hero">
  <div class="hero-aurora small" aria-hidden="true"><i></i><i></i><i></i></div>
  <div class="container">
    <p class="eyebrow">${icon('BookOpen', 15)} Documentation</p>
    <h1 class="display-sm">Everything Emberwall <em>can</em> do,<br>and exactly how.</h1>
    <p class="lead">From your first rule to guarded pushes across a fleet. Tables of versions, checks and commands on these pages are generated from the engine itself.</p>
    <button class="search-hero search-open" type="button">${icon('Search', 18)}<span>Search the docs</span><kbd>Ctrl K</kbd></button>
  </div>
</section>
<section class="container docs-cards">
  ${SECTIONS.filter((s) => docs.some((d) => d.section === s)).map((s) => `
  <div class="docs-card glass reveal">
    <h2>${icon(SECTION_ICON[s], 18)} ${s}</h2>
    <ul>${docs.filter((d) => d.section === s).map((d) => `<li><a href="${d.slug}/"><b>${esc(d.title)}</b><span>${esc(d.description)}</span></a></li>`).join('')}</ul>
  </div>`).join('')}
</section>`;
}

export function searchIndex(docs: Doc[]) {
  return docs.map((d) => ({ t: d.title, s: d.section, u: `docs/${d.slug}/`, d: d.description, h: d.headings.map((h) => [h.text, h.id]), x: d.text.slice(0, 6000) }));
}
