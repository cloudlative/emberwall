// The landing page. Every code sample, trace, score and table below comes from the real engine
// (see lib/data.ts), computed when the site is built.
import type { auditDemo, cliSessions, codeSamples, facts as Facts, simulations, versionJourney } from '../lib/data';
import { esc, highlight } from '../lib/highlight';
import { icon, REPO_URL, SITE_URL } from '../lib/layout';

interface HomeData {
  samples: ReturnType<typeof codeSamples>;
  journey: ReturnType<typeof versionJourney>;
  sims: ReturnType<typeof simulations>;
  audit: ReturnType<typeof auditDemo>;
  cli: ReturnType<typeof cliSessions>;
  apply: string;
  facts: typeof Facts;
}

const shot = (name: string, alt: string, cls = '') => `<img class="${cls}" src="assets/shots/${name}.webp" alt="${esc(alt)}" width="2880" height="1800" loading="lazy" decoding="async">`;
/** JSON for a single-quoted HTML attribute. */
const json = (x: unknown) => JSON.stringify(x).replace(/&/g, '&amp;').replace(/'/g, '&#39;').replace(/</g, '&lt;');

function codeLines(text: string, lang: string): string {
  return highlight(text, lang).split('\n').map((l) => `<span class="ln">${l || ' '}</span>`).join('');
}

export function home(d: HomeData): string {
  const { samples, journey, sims, audit, cli, facts } = d;
  const distroCount = facts.distros.length;
  const extra = facts.extraTargets;
  const install = `curl -fsSL ${SITE_URL}install.sh | sh`;

  const marquee = [
    ...facts.tools.map((t) => facts.toolLabel[t]),
    ...extra.map((t) => t.label),
    'Ansible', 'Terraform', 'cloud-init',
  ];

  // ---------- hero ----------
  const hero = `
<section class="hero" aria-labelledby="hero-title">
  <canvas class="hero-canvas" aria-hidden="true"></canvas>
  <div class="hero-aurora" aria-hidden="true"><i></i><i></i><i></i></div>
  <div class="container hero-inner">
    <a class="pill reveal" href="download/"><span class="pill-dot"></span>New: one binary for Linux, macOS and Windows ${icon('ArrowRight', 14)}</a>
    <h1 id="hero-title" class="display reveal">Design a firewall <em>once</em>.<br><span class="grad-text">Ship it everywhere.</span></h1>
    <p class="lead reveal">Emberwall turns one visual policy into ready-to-apply rules for <b>nftables</b>, <b>iptables</b>, <b>ufw</b> and <b>firewalld</b>, written for the exact version on each machine. Simulate every packet, audit every rule, then apply with an automatic rollback.</p>
    <div class="cta-row reveal">
      <a class="btn btn-ember btn-lg" href="app/">${icon('Flame', 18)} Open the app</a>
      <a class="btn btn-glass btn-lg" href="download/">${icon('Download', 18)} Download</a>
    </div>
    <ul class="hero-points reveal">
      <li>${icon('Lock', 15)} Runs in your browser, nothing uploaded</li>
      <li>${icon('WifiOff', 15)} Works offline</li>
      <li>${icon('Scale', 15)} MIT licensed</li>
    </ul>
  </div>
  <div class="hero-legend" aria-hidden="true"><span class="lg-accept">accepted</span><span class="lg-drop">dropped</span><span class="lg-wall">your policy</span></div>
  <a class="scroll-cue" href="#stage" aria-label="Scroll to the product">${icon('ChevronDown', 22)}</a>
</section>`;

  // ---------- product stage ----------
  const stage = `
<section class="stage" id="stage" aria-label="The Emberwall app">
  <div class="container">
    <div class="stage-frame tilt">
      <div class="window-bar"><span class="dots"><i></i><i></i><i></i></span><span class="window-title">${icon('Lock', 12)} emberwall · Web server</span><span></span></div>
      ${shot('dashboard', 'The Emberwall dashboard: posture score 97, inbound exposure, traffic policy and build target.', 'stage-img').replace('loading="lazy"', 'loading="eager" fetchpriority="high"')}
      <div class="float-chip c1">${icon('ShieldCheck', 16)}<span><b>Score 97</b> · grade A</span></div>
      <div class="float-chip c2">${icon('GitBranch', 16)}<span><b>nftables 1.1.6</b> · 0 fallbacks</span></div>
      <div class="float-chip c3">${icon('KeyRound', 16)}<span><b>SSH</b> · 2 admin ranges only</span></div>
      <div class="float-chip c4">${icon('TimerReset', 16)}<span><b>Rollback armed</b> · 60 s</span></div>
    </div>
  </div>
  <div class="marquee" aria-label="Output targets">
    <div class="marquee-track">${[...marquee, ...marquee].map((m, i) => `<span${i >= marquee.length ? ' aria-hidden="true"' : ''}>${esc(m)}</span>`).join('')}</div>
  </div>
</section>`;

  // ---------- stats ----------
  const stats = `
<section class="stats container" aria-label="Emberwall in numbers">
  <div class="stat reveal"><b data-count="${distroCount}">${distroCount}</b><span>distributions with their real package versions</span></div>
  <div class="stat reveal"><b data-count="${facts.versionCount}">${facts.versionCount}</b><span>tool versions the compiler writes for</span></div>
  <div class="stat reveal"><b data-count="${4 + extra.length}">${4 + extra.length}</b><span>output targets, from nftables to Kubernetes</span></div>
  <div class="stat reveal"><b>0</b><span>bytes of your ruleset sent anywhere</span></div>
</section>`;

  // ---------- compile ----------
  const tabs = samples.outputs.map((o, i) => `<button role="tab" type="button" aria-selected="${i === 0}" aria-controls="out-${o.tool}" id="tab-${o.tool}">${esc(o.label)}<small>${esc(o.version)}</small></button>`).join('');
  const panes = samples.outputs.map((o, i) => `
      <div class="code-pane" role="tabpanel" id="out-${o.tool}" aria-labelledby="tab-${o.tool}"${i === 0 ? '' : ' hidden'}>
        <div class="code-meta"><span>${icon('FileCode2', 14)} ${esc(o.file)}</span><span>${esc(o.path)}</span><span>${o.lines} lines · ${o.fallbacks} fallbacks</span></div>
        <pre class="code scroll"><code>${codeLines(o.text, o.lang)}</code></pre>
        <div class="code-files">Also generated: ${o.files.filter((f) => f !== o.file).map((f) => `<code>${esc(f)}</code>`).join(' ')}</div>
      </div>`).join('');
  const ruleRows = samples.rules.map((r) => `<li><span class="r-action">${icon('Check', 14)}</span><span class="r-name">${esc(r.name)}</span><span class="r-meta">${esc(r.proto.toUpperCase())} ${esc(r.ports.join(', '))}</span><span class="r-src">${r.src.length ? esc(r.src.join(', ')) : 'anywhere'}</span></li>`).join('');
  const compileSection = `
<section class="section" id="compile">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('Workflow', 15)} One model</p>
      <h2>One policy. Four dialects. <em>Zero</em> rewrites.</h2>
      <p>You describe what should be allowed. Emberwall writes it the way each tool expects it: an <code>nft -f</code> ruleset, <code>iptables-restore</code> files for IPv4 and IPv6, ufw commands, or a firewalld script with zone XML. Below is the real output for the same policy on Ubuntu 26.04.</p>
    </header>
    <div class="compile-grid">
      <div class="policy-card glass reveal">
        <div class="card-title">${icon('ListChecks', 16)} Policy · Web server</div>
        <ul class="rule-list">${ruleRows}</ul>
        <div class="policy-defaults">
          <span>Inbound <b class="v-drop">${samples.policies.in}</b></span>
          <span>Outbound <b class="v-accept">${samples.policies.out}</b></span>
          <span>Forward <b class="v-drop">${samples.policies.forward}</b></span>
        </div>
        <div class="compile-arrow" aria-hidden="true">${icon('Sparkles', 18)}<span>compile</span></div>
      </div>
      <div class="code-window glass reveal" data-tabs>
        <div class="code-tabs" role="tablist" aria-label="Output format">${tabs}</div>
        ${panes}
      </div>
    </div>
  </div>
</section>`;

  // ---------- version journey ----------
  const latest = journey.versions.length - 1;
  const versionSection = `
<section class="section versions-section" id="versions">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('GitCompareArrows', 15)} Version-aware</p>
      <h2>Knows what <em>your</em> version can do.</h2>
      <p>Firewall syntax changes between releases. Emberwall keeps a capability table, with the upstream commit for each feature, and writes new syntax where your version has it and a working fallback where it does not. Then it tells you exactly what changed. Drag through every nftables release it knows:</p>
    </header>
    <div class="journey glass reveal" data-journey='${json(journey)}'>
      <div class="journey-top">
        <div class="journey-version"><small>nftables</small><b class="j-version">${journey.versions[latest].version}</b><span class="j-distros"></span></div>
        <div class="journey-meter"><div><b class="j-on">0</b><small>of ${journey.caps.length} capabilities</small></div><div><b class="j-notes">0</b><small>compiler notes</small></div><div><b class="j-lines">0</b><small>lines of output</small></div></div>
      </div>
      <input class="journey-range" type="range" min="0" max="${latest}" step="1" value="${latest}" aria-label="nftables version" list="journey-ticks">
      <div class="journey-ticks" aria-hidden="true">${journey.versions.map((v) => `<span>${v.version}</span>`).join('')}</div>
      <div class="journey-body">
        <ul class="cap-list">${journey.caps.map((c) => `<li data-cap="${c.key}"><span class="cap-dot"></span><span class="cap-label">${esc(c.label)}</span><span class="cap-since">since ${c.since}${c.kernel ? ` · kernel ${c.kernel}` : ''}</span></li>`).join('')}</ul>
        <div class="journey-notes"><h3>${icon('MessageSquareText', 16)} What the compiler tells you</h3><ul class="j-note-list"></ul></div>
      </div>
    </div>
  </div>
</section>`;

  // ---------- features bento ----------
  const big = (cls: string, ic: string, title: string, text: string, img: string, alt: string, href: string) => `
      <a class="tile tile-big ${cls} reveal" href="${href}"><div class="tile-copy"><span class="tile-icon">${icon(ic, 20)}</span><h3>${title}</h3><p>${text}</p></div><div class="tile-shot">${shot(img, alt)}</div></a>`;
  const small = (ic: string, title: string, text: string, href: string) => `<a class="tile tile-small reveal" href="${href}"><span class="tile-icon">${icon(ic, 18)}</span><h3>${title}</h3><p>${text}</p></a>`;
  const features = `
<section class="section" id="features">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('LayoutGrid', 15)} Everything in one place</p>
      <h2>From an idea to a running firewall, <em>without</em> the guesswork.</h2>
      <p>Thirty-odd tools around a single model. Every one of them works offline, in your browser.</p>
    </header>
    <div class="bento">
      ${big('t-rules', 'ListChecks', 'A rule builder that shows its work', 'Click a rule to highlight the lines it produced; click a line to jump to its rule. Zones, address and port groups, NAT, rate limits, schedules and more.', 'rules', 'The rule builder with live output', 'docs/rules/')}
      ${big('t-reach', 'Grid3x3', 'Who can reach what', 'A reachability matrix across the internet, zones, groups and services, computed by the simulator.', 'reach', 'The reachability matrix', 'docs/reachability-and-topology/')}
      ${big('t-fleet', 'Server', 'One policy, a whole fleet', 'Shared rules plus host-scoped rules and per-host overrides. Each host compiled for its own tool and version, with an Ansible inventory and playbook.', 'fleet', 'Five hosts on four different firewalls', 'docs/fleet/')}
      ${big('t-compare', 'Columns2', 'Plan the upgrade', 'The same ruleset for two targets, as a diff or side by side. Ideal for moving from iptables to nftables.', 'compare', 'Comparing two targets', 'docs/build-output/')}
      ${small('FlaskConical', 'Packet simulator', 'See the verdict and every check a packet went through.', 'docs/simulator/')}
      ${small('ClipboardCheck', 'Policy tests', 'Save packets as assertions. They run on every change.', 'docs/policy-tests/')}
      ${small('ShieldAlert', 'Audit and score', 'Exposed services, shadowed rules, lock-out risk, with fixes.', 'docs/audit-and-compliance/')}
      ${small('BadgeCheck', 'Compliance profiles', 'CIS-style, PCI DSS-style and internet baseline, with evidence.', 'docs/audit-and-compliance/')}
      ${small('FolderInput', 'Import anything', 'Paste iptables-save, nft, ufw or firewalld and migrate it.', 'docs/import/')}
      ${small('Ban', 'Blocklists and geo', 'Address sets dropped first, refreshed by a systemd timer.', 'docs/protection/')}
      ${small('Zap', 'Attack protection', 'Per-client limits, SYN-flood guard, port-scan filter, auto-ban.', 'docs/protection/')}
      ${small('Cpu', 'Kernel hardening', 'A sysctl drop-in ships with every build.', 'docs/protection/')}
      ${small('Cloud', 'Beyond Linux', `pf, Windows Firewall, AWS, Azure, Google Cloud and Kubernetes.`, 'docs/more-targets/')}
      ${small('Share2', 'Topology', 'Sources, the firewall and the networks behind it, with live flows.', 'docs/reachability-and-topology/')}
      ${small('FileSearch', 'Log analyzer', 'Paste kernel logs: top sources, ports, one-click block.', 'docs/log-analyzer/')}
      ${small('FileCode2', 'Automation export', 'Ansible, Terraform and cloud-init for every build.', 'docs/build-output/')}
      ${small('Camera', 'Snapshots and diff', 'Which access opened or closed, not just which lines.', 'docs/workspace/')}
      ${small('Link', 'Share links', 'The whole project in the URL fragment. No server involved.', 'docs/workspace/')}
      ${small('Sparkles', 'Assistant, opt-in', 'Describe a policy in plain English with your own API key.', 'docs/assistant/')}
      ${small('Terminal', 'CLI for CI', 'Build, test, audit and compliance with exit codes.', 'docs/cli/')}
    </div>
  </div>
</section>`;

  // ---------- verify ----------
  const simTabs = sims.map((s, i) => `<button type="button" role="tab" aria-selected="${i === 0}" data-sim="${i}"><span class="sim-dot ${s.verdict === 'accept' ? 'ok' : 'bad'}"></span>${esc(s.title)}</button>`).join('');
  const verify = `
<section class="section verify-section" id="verify">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('FlaskConical', 15)} Verify</p>
      <h2>Prove it <em>before</em> it touches a server.</h2>
      <p>Describe a packet and watch it walk through your policy, check by check, the way the generated ruleset will treat it. These traces are produced by Emberwall's own simulator.</p>
    </header>
    <div class="verify-grid">
      <div class="sim glass reveal" data-sims='${json(sims)}'>
        <div class="sim-tabs" role="tablist" aria-label="Example packets">${simTabs}</div>
        <div class="sim-packet"></div>
        <ol class="sim-steps"></ol>
        <div class="sim-verdict"></div>
      </div>
      <div class="audit glass reveal" data-audit='${json(audit)}'>
        <div class="audit-head">
          <div class="ring" style="--p:${audit.score}"><svg viewBox="0 0 120 120" aria-hidden="true"><circle cx="60" cy="60" r="52"/><circle class="ring-val" cx="60" cy="60" r="52"/></svg><div><b class="audit-score">${audit.score}</b><small class="audit-grade">grade ${audit.grade}</small></div></div>
          <div><h3>Audit a first draft</h3><p>${audit.findings.length} findings, ${audit.fixes} with a one-click fix. Try them.</p><button class="btn btn-glass btn-sm audit-fix-all" type="button">${icon('Wand2', 15)} Apply all fixes</button></div>
        </div>
        <ul class="findings">${audit.findings.map((f, i) => `<li data-i="${i}" class="sev-${f.severity}"><span class="sev">${f.severity}</span><span class="f-title">${esc(f.title)}</span>${f.fix ? `<button type="button" class="f-fix">${esc(f.fix)}</button>` : `<span class="f-manual" title="No automatic fix: decide whether this service should be public at all">your call</span>`}</li>`).join('')}</ul>
      </div>
    </div>
  </div>
</section>`;

  // ---------- safe apply ----------
  const steps = [
    ['Archive', 'Back up', 'The running ruleset is saved before anything changes.'],
    ['ScanSearch', 'Check', 'A dry run (nft -c, iptables-restore --test) must pass, or nothing happens.'],
    ['TimerReset', 'Arm', 'A detached watchdog starts, immune to a dropped SSH session.'],
    ['Play', 'Apply', 'The new rules go live.'],
    ['UserCheck', 'Confirm', 'You open a new session. Type yes, or the old rules come back.'],
  ];
  const apply = `
<section class="section apply-section" id="apply">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('LifeBuoy', 15)} Safe apply</p>
      <h2>Lock yourself out? <em>Not</em> for long.</h2>
      <p>Every build ships with <code>emberwall-apply.sh</code>. It backs up, checks, applies, and rolls back automatically unless you confirm from a fresh connection. In server mode the timer lives on the target itself, and only a successful reconnection can cancel it.</p>
    </header>
    <div class="apply-grid">
      <ol class="pipeline reveal">${steps.map(([ic, t, p], i) => `<li style="--i:${i}"><span class="p-icon">${icon(ic, 20)}</span><div><h3>${t}</h3><p>${p}</p></div></li>`).join('')}</ol>
      <div class="apply-visual glass reveal">
        <div class="countdown" aria-hidden="true"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52"/><circle class="cd-val" cx="60" cy="60" r="52"/></svg><div><b class="cd-num">60</b><small>seconds to confirm</small></div></div>
        <div class="outcomes"><div class="outcome ok">${icon('CircleCheck', 18)}<span><b>You confirm</b>The new rules stay. The backup is kept.</span></div><div class="outcome bad">${icon('Undo2', 18)}<span><b>The connection is lost</b>The target restores the previous rules on its own.</span></div></div>
        <details class="apply-code"><summary>${icon('FileCode2', 15)} Read the generated script</summary><pre class="code scroll"><code>${codeLines(d.apply, 'sh')}</code></pre></details>
      </div>
    </div>
  </div>
</section>`;

  // ---------- server mode ----------
  const server = `
<section class="section server-section" id="server">
  <div class="container server-grid">
    <div class="server-copy reveal">
      <p class="eyebrow">${icon('Users', 15)} Server mode</p>
      <h2>Bring your team. Bring your <em>servers</em>.</h2>
      <p>Run <code>emberwall serve</code> and the same app gains sign-in with roles, a shared server inventory, team projects and an activity log, stored in a single SQLite file.</p>
      <ul class="check-list">
        <li>${icon('Radio', 17)}<span><b>Read live firewalls over SSH.</b> A fixed set of read-only commands shows the running rules, their audit and compliance, and the drift from your project.</span></li>
        <li>${icon('Rocket', 17)}<span><b>Guarded push.</b> Backup, dry-run check, rollback timer on the target, apply, then a fresh reconnection must succeed to keep it.</span></li>
        <li>${icon('KeyRound', 17)}<span><b>Credentials stay sealed.</b> AES-256-GCM with your master key, host keys pinned on first use.</span></li>
        <li>${icon('UserCog', 17)}<span><b>Roles enforced by the server.</b> Admin, operator and viewer, checked on every request.</span></li>
      </ul>
      <div class="cmd glass"><code><span class="tk-v">EMBERWALL_SECRET</span>=<span class="tk-s">"$(head -c 48 /dev/urandom | base64)"</span> <span class="tk-w">emberwall</span> serve</code><button class="copy" type="button" data-copy="EMBERWALL_SECRET=&quot;$(head -c 48 /dev/urandom | base64)&quot; emberwall serve" aria-label="Copy command">${icon('Copy', 15)}</button></div>
      <a class="text-link" href="docs/server-mode/">Set up server mode ${icon('ArrowRight', 15)}</a>
    </div>
    <div class="server-shots reveal">
      <figure class="shot-card back">${shot('live-push', 'A guarded push waiting for confirmation')}</figure>
      <figure class="shot-card front">${shot('live-audit', 'The live view of a running server: rules, audit and drift')}</figure>
    </div>
  </div>
</section>`;

  // ---------- CLI ----------
  const cliTabs = cli.map((c, i) => `<button type="button" role="tab" aria-selected="${i === 0}" data-term="${i}" title="${esc(c.cmd.split(' ').slice(0, 2).join(' '))}">${esc(c.cmd.split(' ')[1] ?? c.cmd)}</button>`).join('');
  const ci = `name: firewall
on: [push, pull_request]
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL ${SITE_URL}install.sh | sh
      - run: emberwall test firewall.json
      - run: emberwall audit firewall.json --min-score 85
      - run: emberwall build firewall.json --target debian-12:nftables --strict --out build/`;
  const cliSection = `
<section class="section" id="cli">
  <div class="container cli-grid">
    <div class="cli-copy reveal">
      <p class="eyebrow">${icon('Terminal', 15)} Command line</p>
      <h2>Policy as code, <em>checked</em> in CI.</h2>
      <p>The same engine runs in the terminal. Fail the pipeline when a policy test breaks, the audit score drops, or a build would need a version fallback.</p>
      <pre class="code ci-code glass scroll"><code>${codeLines(ci, 'yaml')}</code></pre>
    </div>
    <div class="terminal reveal" data-term-sessions='${json(cli)}'>
      <div class="window-bar"><span class="dots"><i></i><i></i><i></i></span><div class="term-tabs" role="tablist" aria-label="Example commands">${cliTabs}</div></div>
      <pre class="term-body scroll" aria-live="polite"><code></code></pre>
    </div>
  </div>
</section>`;

  // ---------- gallery ----------
  // [shot, title, what it shows, docs page]
  type Stop = [string, string, string, string];
  const chapters: { id: string; icon: string; name: string; lead: string; stops: Stop[] }[] = [
    { id: 'design', icon: 'PenTool', name: 'Design', lead: 'Describe what the host should allow.', stops: [
      ['dashboard', 'Dashboard', 'The posture score, exposed services and what needs attention, on one screen.', 'workspace'],
      ['rules', 'Rules', 'Ordered rules with sources, ports, rate limits, schedules and logging. Drag to reorder.', 'rules'],
      ['zones', 'Zones', 'Name the sides of the firewall (WAN, LAN, DMZ, VPN) and write rules between them.', 'objects-and-zones'],
      ['nat', 'NAT and port forwarding', 'Masquerade, source NAT and port forwards, including IPv6.', 'nat'],
      ['blocklists', 'Blocklists and geo-blocking', 'Block lists of addresses and whole countries, with a scheduled updater.', 'protection'],
    ] },
    { id: 'verify', icon: 'FlaskConical', name: 'Verify', lead: 'Prove it does what you meant, before it runs.', stops: [
      ['simulator', 'Packet simulator', 'Send a test packet and read every check it passes through, down to the rule that decides.', 'simulator'],
      ['reach', 'Reachability', 'A matrix of who can reach what, worked out from the ruleset.', 'reachability-and-topology'],
      ['tests', 'Policy tests', 'Assertions such as "the database is never public", checked on every change and in CI.', 'policy-tests'],
      ['audit', 'Audit', 'Risky, broken and redundant rules, a 0-100 score, and one-click fixes.', 'audit-and-compliance'],
      ['compliance', 'Compliance', 'CIS-style, PCI DSS-style and internet-server profiles, with evidence for each check.', 'audit-and-compliance'],
    ] },
    { id: 'ship', icon: 'Rocket', name: 'Ship', lead: 'Output for the exact tool and version you run.', stops: [
      ['build', 'Build', 'Every generated file, with notes for the chosen distribution and tool version.', 'build-output'],
      ['versions', 'Version matrix', 'Which features each release of nftables, iptables, ufw and firewalld supports, and the fallbacks used.', 'targets-and-versions'],
      ['compare', 'Compare backends', 'The same policy in nftables, iptables, ufw and firewalld, side by side.', 'targets-and-versions'],
      ['targets', 'More targets', 'pf, Windows Firewall, AWS, Azure and Google Cloud security groups, and Kubernetes NetworkPolicy.', 'more-targets'],
    ] },
    { id: 'operate', icon: 'ServerCog', name: 'Operate', lead: 'Keep real servers in line with the policy.', stops: [
      ['fleet', 'Fleet', 'One policy for many hosts, with per-host overrides and a build for each.', 'fleet'],
      ['live-audit', 'Live servers', 'Read the firewall running on a server over SSH, audit it, and see drift from the project.', 'live-servers'],
      ['live-push', 'Guarded push', 'Push a build with a rollback timer that only a fresh reconnection can cancel.', 'live-servers'],
      ['logs', 'Log analyzer', 'Paste kernel firewall logs to see top sources and ports, then block or allow in one click.', 'log-analyzer'],
      ['transfer', 'Import and export', 'Bring in an existing iptables, nftables, ufw or firewalld config, or move a project as JSON.', 'import'],
    ] },
  ];
  const stops = chapters.flatMap((c) => c.stops.map((s) => ({ chapter: c.id, shot: s[0], title: s[1], text: s[2], doc: s[3] })));
  const gallerySection = `
<section class="section gallery-section" id="gallery" aria-labelledby="gallery-title">
  <div class="container">
    <header class="section-head reveal"><p class="eyebrow">${icon('Images', 15)} Tour</p><h2 id="gallery-title">Take the <em>grand</em> tour.</h2><p>${stops.length} screens from the real app, captured from this release. Pick a chapter, or let it play.</p></header>
    <div class="tour reveal" data-tour>
      <div class="tour-chapters" role="tablist" aria-label="Tour chapters">${chapters.map((c, i) => `<button type="button" role="tab" aria-selected="${i === 0}" data-chapter="${c.id}">${icon(c.icon, 16)}<span>${c.name}</span><small>${c.stops.length}</small></button>`).join('')}</div>
      <div class="tour-body">
        <ol class="tour-stops">${stops.map((s, i) => `<li data-chapter="${s.chapter}"${chapters[0].id === s.chapter ? '' : ' hidden'}><button type="button" class="tour-stop" data-stop="${i}" aria-current="${i === 0}"><span class="tour-num">${String(i + 1).padStart(2, '0')}</span><span class="tour-text"><b>${esc(s.title)}</b><span>${esc(s.text)}</span></span><i class="tour-bar" aria-hidden="true"></i></button></li>`).join('')}</ol>
        <div class="tour-stage">
          <div class="tour-window">
            <div class="window-bar"><span class="dots"><i></i><i></i><i></i></span><span class="tour-url">${icon('Lock', 12)} <span>emberwall · <b class="tour-url-page">${esc(stops[0].title)}</b></span></span><span class="tour-count"><b class="tour-pos">01</b> / ${String(stops.length).padStart(2, '0')}</span></div>
            <div class="tour-screens">${stops.map((s, i) => `<button type="button" class="zoom tour-screen${i === 0 ? ' on' : ''}" data-full="assets/shots/${s.shot}.webp" data-stop="${i}" aria-label="Enlarge: ${esc(s.title)}"${i === 0 ? '' : ' tabindex="-1" aria-hidden="true"'}>${i < 2 ? shot(s.shot, `${s.title}: ${s.text}`).replace(' loading="lazy"', '') : shot(s.shot, `${s.title}: ${s.text}`)}</button>`).join('')}</div>
          </div>
          <div class="tour-controls">
            <button type="button" class="icon-btn tour-prev" aria-label="Previous screen">${icon('ChevronLeft', 18)}</button>
            <button type="button" class="icon-btn tour-play" aria-label="Pause the tour" aria-pressed="true">${icon('Pause', 16)}${icon('Play', 16)}</button>
            <button type="button" class="icon-btn tour-next" aria-label="Next screen">${icon('ChevronRight', 18)}</button>
            <p class="tour-caption" aria-live="polite"><b>${esc(stops[0].title)}</b> <a class="tour-doc" href="docs/${stops[0].doc}/">Read the docs ${icon('ArrowRight', 13)}</a></p>
            <a class="btn btn-glass btn-sm tour-open" href="app/">${icon('ExternalLink', 14)} Try it in the app</a>
          </div>
        </div>
      </div>
      <script type="application/json" class="tour-data">${JSON.stringify(stops.map((s) => ({ c: s.chapter, t: s.title, d: s.doc }))).replace(/</g, '\\u003c')}</script>
    </div>
  </div>
</section>`;

  // ---------- privacy ----------
  const privacy = `
<section class="section privacy-section" id="privacy">
  <div class="container privacy-grid">
    <div class="orbit reveal" aria-hidden="true"><div class="orbit-core">${icon('ShieldCheck', 44, 1.4)}</div><span class="o1"></span><span class="o2"></span><span class="o3"></span><i class="sat s1"></i><i class="sat s2"></i><i class="sat s3"></i></div>
    <div class="reveal">
      <p class="eyebrow">${icon('Lock', 15)} Private by design</p>
      <h2>Your rules never <em>leave</em> your browser.</h2>
      <p>Your network layout is sensitive. The app is a static page: compiling, simulating, auditing and diffing all happen on your machine. There is no account and no telemetry, and after the first visit it works with the network off.</p>
      <p>The one exception is opt-in: the assistant sends your request to the Anthropic API with your own key, and shows you exactly what will be sent first.</p>
    </div>
  </div>
</section>`;

  // ---------- proof ----------
  const proofs: [string, string, string][] = [
    ['TerminalSquare', 'Fed to the real tools', 'Every template and an edge-case project, for every version, through iptables-restore --test and nft -c. Zero errors allowed.'],
    ['Flame', 'firewalld, offline', 'Generated scripts run against firewall-offline-cmd for firewalld 2.1.1, 0.9.3 and 0.8.2 in a private config directory.'],
    ['Network', 'Loaded for real', 'Blocklists and ufw fragments loaded in a private network namespace: listed addresses dropped, then let through once removed.'],
    ['ServerCog', 'Pushed over real SSH', 'Guarded push for all four tools: a ruleset that shuts SSH out cannot be confirmed, and the target rolls itself back.'],
    ['Skull', 'Hostile input', 'Shell metacharacters in every name and field. Nothing but firewall commands runs.'],
    ['FileCheck2', 'IaC that validates', 'Terraform passes validate and fmt for AWS, Azure and Google; Ansible passes --syntax-check; PowerShell parses.'],
  ];
  const proof = `
<section class="section" id="proof">
  <div class="container">
    <header class="section-head reveal">
      <p class="eyebrow">${icon('Microscope', 15)} Checked, not claimed</p>
      <h2>Tested against the <em>real</em> tools.</h2>
      <p>Generated output is only useful if the tool on the server accepts it. Here is how it is checked, and where the checks stop.</p>
    </header>
    <div class="proof-grid">${proofs.map(([ic, t, p]) => `<div class="proof glass reveal"><span class="tile-icon">${icon(ic, 18)}</span><h3>${t}</h3><p>${p}</p></div>`).join('')}</div>
    <p class="honest reveal">${icon('Info', 15)}<span>pf output has not been run through <code>pfctl</code>, nothing was applied to a real cloud account, Windows host or cluster, and the test suite never touches a production server. <a href="docs/verification/">Read how output is verified</a>.</span></p>
  </div>
</section>`;

  // ---------- final CTA ----------
  const cta = `
<section class="final-cta" id="get-started">
  <div class="cta-glow" aria-hidden="true"></div>
  <div class="container cta-inner reveal">
    <h2 class="display">Light the <span class="grad-text">wall</span>.</h2>
    <p class="lead">Open it in your browser now, or install the single binary for the CLI and server mode.</p>
    <div class="cta-row"><a class="btn btn-ember btn-lg" href="app/">${icon('Flame', 18)} Open the app</a><a class="btn btn-glass btn-lg" href="docs/quick-start/">${icon('BookOpen', 18)} Read the quick start</a></div>
    <div class="cmd glass install-cmd"><span class="prompt">$</span><code>${esc(install)}</code><button class="copy" type="button" data-copy="${esc(install)}" aria-label="Copy install command">${icon('Copy', 15)}</button></div>
    <p class="cta-small">Linux and macOS. Windows and manual downloads on the <a href="download/">download page</a>. Source on <a href="${REPO_URL}">GitHub</a>.</p>
  </div>
</section>`;

  return hero + stage + stats + compileSection + versionSection + features + verify + apply + server + cliSection + gallerySection + privacy + proof + cta;
}
