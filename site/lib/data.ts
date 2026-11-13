// Everything the website shows about the product's behaviour is computed here from the real engine,
// so code samples, version tables, simulator traces and audit results cannot drift from the app.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main as cli } from '../../cli/emberwall';
import { compile, fileText } from '../../src/core/compile';
import { EXTRA_TARGETS } from '../../src/core/compile/extra';
import { PROFILES } from '../../src/core/compliance';
import { grade, lint, score } from '../../src/core/lint';
import { PROBE_COMMANDS } from '../../src/core/live';
import { emptyProject, newNat, newRule, type Project } from '../../src/core/model';
import { simulate, type Packet } from '../../src/core/simulate';
import { HARDENING } from '../../src/core/sysctl';
import { CAPABILITIES, DISTROS, DOCS_CHECKED, resolveTarget, TOOL_LABEL, TOOLS, VERSIONS, type Tool } from '../../src/core/targets';
import { TEMPLATES } from '../../src/core/templates';

const tpl = (id: string): Project => {
  const t = TEMPLATES.find((x) => x.id === id);
  if (!t) throw new Error(`no template ${id}`);
  return t.build();
};

export const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')) as { version: string; description: string };

/** Runs the real CLI and returns what it printed. */
export function runCli(args: string[]): string {
  const lines: string[] = [];
  cli(args, (s) => lines.push(s), (s) => lines.push(s));
  return lines.join('\n');
}

function withProjectFile<T>(p: Project, fn: (file: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'ew-site-'));
  try {
    const file = join(dir, 'project.json');
    writeFileSync(file, JSON.stringify(p));
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The same "Web server" policy compiled for the four Linux tools on Ubuntu 26.04. */
export function codeSamples() {
  const p = tpl('web');
  const pick: Record<Tool, string> = { nftables: 'emberwall.nft', iptables: 'rules.v4', ufw: 'emberwall-ufw.sh', firewalld: 'emberwall-firewalld.sh' };
  return {
    rules: p.rules.map((r) => ({ name: r.name, proto: r.proto, ports: r.ports, src: r.src.map((s) => (s.startsWith('@') ? p.addressGroups.find((g) => `@${g.id}` === s)?.name ?? s : s)) })),
    policies: p.policies,
    outputs: TOOLS.map((tool) => {
      const res = compile(p, resolveTarget({ distro: 'ubuntu-26.04', tool, version: '' }));
      const file = res.files.find((f) => f.name === pick[tool]) ?? res.files[0];
      return {
        tool,
        label: TOOL_LABEL[tool],
        version: res.target.version,
        file: file.name,
        path: file.path,
        lang: file.lang,
        text: fileText(file).trimEnd(),
        lines: file.lines.length,
        files: res.files.map((f) => f.name),
        fallbacks: res.diagnostics.filter((d) => d.kind === 'fallback').length,
      };
    }),
  };
}

/** One richer policy compiled for every nftables version Emberwall knows. */
export function versionJourney() {
  const p = tpl('router');
  // Features whose syntax depends on the version, so the journey has something to show.
  p.rules = p.rules.map((r, i) => (i === 0 ? { ...r, connLimit: 20 } : r));
  p.rules.push({ ...p.rules[0], id: 'sched', name: 'Office hours admin', ports: ['8443'], schedule: { days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], from: '08:00', to: '18:00' }, connLimit: undefined });
  p.protections = { synFlood: { rate: 50, burst: 100 }, portScan: true, autoBan: { ports: ['23', '3389'], seconds: 3600 } };
  const caps = CAPABILITIES.filter((c) => c.tool === 'nftables');
  return {
    caps: caps.map((c) => ({ key: c.key, label: c.label, since: c.since, kernel: c.kernel ?? null, fallback: c.fallback })),
    versions: VERSIONS.nftables.map((version) => {
      const res = compile(p, resolveTarget({ distro: 'custom', tool: 'nftables', version }));
      return {
        version,
        on: caps.filter((c) => res.target.caps[c.key]).map((c) => c.key),
        lines: res.files[0].lines.length,
        notes: res.diagnostics.filter((d) => d.kind === 'fallback' || d.kind === 'unsupported').map((d) => d.message),
        distros: DISTROS.filter((d) => d.tools.nftables === version).map((d) => d.name),
      };
    }),
  };
}

/** Three packets walked through the "Web server" policy by the real simulator. */
export function simulations() {
  const p = tpl('web');
  const packets: { title: string; packet: Packet }[] = [
    { title: 'HTTPS from the internet', packet: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 443, state: 'new', inIface: 'eth0' } },
    { title: 'SSH from a stranger', packet: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 22, state: 'new', inIface: 'eth0' } },
    { title: 'SSH from the admin network', packet: { direction: 'in', src: '203.0.113.7', dst: '192.0.2.10', proto: 'tcp', port: 22, state: 'new', inIface: 'eth0' } },
  ];
  return packets.map(({ title, packet }) => {
    const r = simulate(p, packet);
    return { title, packet, verdict: r.verdict, decidedBy: r.decidedBy, steps: r.steps.map((s) => ({ label: s.label, detail: s.detail, matched: s.matched, verdict: s.verdict ?? null })) };
  });
}

/** A careless first draft of a web server policy: what the audit finds, and the score after its one-click fixes. */
export function auditDemo() {
  const p = sloppy();
  const findings = lint(p);
  const s = score(findings);
  let fixed = p;
  for (const f of findings) if (f.fix) fixed = f.fix(fixed);
  const after = score(lint(fixed));
  return {
    score: s,
    grade: grade(s),
    after,
    afterGrade: grade(after),
    fixes: findings.filter((f) => f.fix).length,
    findings: findings.map((f) => ({ severity: f.severity, title: f.title, fix: f.fixLabel ?? null })),
  };
}

function sloppy(): Project {
  const p = tpl('web');
  p.name = 'First draft';
  p.options = { ...p.options, dropInvalid: false, logDropped: false };
  p.rules = [
    newRule({ name: 'SSH', proto: 'tcp', ports: ['22'] }),
    newRule({ name: 'Web', proto: 'tcp', ports: ['80', '443'] }),
    newRule({ name: 'Telnet', proto: 'tcp', ports: ['23'] }),
    newRule({ name: 'HTTPS again', proto: 'tcp', ports: ['443'] }),
    newRule({ name: 'Postgres', proto: 'tcp', ports: ['5432'] }),
  ];
  return p;
}

/** Real terminal sessions for the CLI section. */
export function cliSessions() {
  const web = tpl('web');
  web.tests = [
    { id: 't1', name: 'HTTPS is public', packet: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 443, state: 'new' }, expect: 'accept' },
    { id: 't2', name: 'SSH is never public', packet: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 22, state: 'new' }, expect: 'block' },
    { id: 't3', name: 'Admins can reach SSH', packet: { direction: 'in', src: '203.0.113.7', dst: '192.0.2.10', proto: 'tcp', port: 22, state: 'new' }, expect: 'accept' },
  ];
  return withProjectFile(web, (file) => [
    { cmd: 'emberwall test web.json', out: runCli(['test', file]) },
    { cmd: 'emberwall audit web.json --min-score 80', out: runCli(['audit', file, '--min-score', '80']) },
    { cmd: 'emberwall compliance web.json --profile cis', out: runCli(['compliance', file, '--profile', 'cis']) },
    { cmd: 'emberwall targets', out: runCli(['targets']) },
  ]);
}

export function safeApplyExcerpt() {
  const res = compile(tpl('web'), resolveTarget({ distro: 'debian-12', tool: 'nftables', version: '' }));
  const f = res.files.find((x) => x.name === 'emberwall-apply.sh')!;
  return fileText(f).trimEnd();
}

/**
 * Every audit check with its severity, collected by running the real linter over deliberately
 * flawed projects (findings are built inline in lint.ts, so there is no list to import).
 */
export function auditChecks(): { id: string; severity: string; title: string }[] {
  const e = emptyProject;
  const bad = e('Everything wrong');
  bad.policies = { in: 'accept', out: 'drop', forward: 'accept' };
  bad.options = { ...bad.options, allowEstablished: false, allowLoopback: false, dropInvalid: false, ipv6: false, logDropped: false, forwarding: false };
  bad.protections = { autoBan: { ports: ['2222'], seconds: 600 } };
  bad.rules = [
    newRule({ name: 'Allow all', proto: 'any' }),
    newRule({ name: 'Telnet', proto: 'tcp', ports: ['23'] }),
    newRule({ name: 'Web', proto: 'tcp', ports: ['443'] }),
    newRule({ name: 'Web copy', proto: 'tcp', ports: ['443'] }),
    newRule({ name: 'Trap port', proto: 'tcp', ports: ['2222'] }),
    newRule({ name: 'Old rule', proto: 'tcp', ports: ['8080'], enabled: false }),
    newRule({ name: 'Bad interface', proto: 'tcp', ports: ['81'], inIface: 'not a valid name!' }),
  ];
  bad.nat = [newNat({ name: 'App forward', kind: 'dnat', proto: 'tcp', port: '8443', toAddr: '10.0.0.5', toPort: '443', iface: 'eth0' })];
  bad.tests = [{ id: 't', name: 'HTTPS is public', packet: { direction: 'in', src: '198.51.100.1', dst: '192.0.2.1', proto: 'tcp', port: 9999, state: 'new' }, expect: 'accept' }];
  const sshOpen = e('SSH wide open');
  sshOpen.rules = [newRule({ name: 'SSH', proto: 'tcp', ports: ['22'] })];
  const projects = [bad, sshOpen, sloppy(), e('Empty'), e('No SSH'), tpl('web')];
  projects[4].rules = [newRule({ name: 'Web', proto: 'tcp', ports: ['443'] })];
  const out = new Map<string, { id: string; severity: string; title: string }>();
  for (const p of projects) for (const f of lint(p)) {
    const id = f.id.split(':')[0];
    if (!out.has(id)) out.set(id, { id, severity: f.severity, title: f.title });
  }
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  return [...out.values()].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

export const facts = {
  distros: DISTROS,
  capabilities: CAPABILITIES,
  versions: VERSIONS,
  tools: TOOLS,
  toolLabel: TOOL_LABEL,
  templates: TEMPLATES.map((t) => ({ id: t.id, name: t.name, summary: t.summary, rules: t.build().rules.length })),
  profiles: PROFILES.map((p) => ({ id: p.id, name: p.name, about: p.about, controls: p.controls.map((c) => ({ title: c.title, intent: c.intent })) })),
  extraTargets: EXTRA_TARGETS.map((t) => ({ id: t.id, label: t.label, description: t.description })),
  probeCommands: PROBE_COMMANDS,
  hardening: HARDENING,
  docsChecked: DOCS_CHECKED,
  versionCount: Object.values(VERSIONS).reduce((n, v) => n + v.length, 0),
};
