import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { assess, PROFILES } from '../src/core/compliance';
import { emptyProject, newRule, uid, type Project } from '../src/core/model';
import { simulate } from '../src/core/simulate';
import { HARDENING, RECOMMENDED_HARDENING, sysctlFile } from '../src/core/sysctl';
import { resolveTarget, TOOLS, type Tool } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

const target = (tool: Tool, version: string) => resolveTarget({ distro: 'custom', tool, version });
const latest: Record<Tool, string> = { nftables: '1.0.9', iptables: '1.8.10', ufw: '0.36.2', firewalld: '2.3.1' };
const dir = mkdtempSync(join(tmpdir(), 'emberwall-b2-'));

function withLists(): Project {
  const p = TEMPLATES[0].build();
  p.blocklists = [
    { id: uid('bl'), name: 'Known scanners', enabled: true, entries: ['198.51.100.0/24', '203.0.113.99', '2001:db8:bad::/48', 'garbage'] },
    { id: uid('bl'), name: 'Country XX', enabled: true, entries: [], url: 'https://lists.example.org/xx.zone', outbound: true },
    { id: uid('bl'), name: 'Off', enabled: false, entries: ['192.0.2.0/24'] },
  ];
  p.hardening = [...RECOMMENDED_HARDENING];
  return p;
}

describe('blocklists', () => {
  it('nftables: interval sets, early drops, updater and timer', () => {
    const res = compile(withLists(), target('nftables', '1.0.9'));
    const t = fileText(res.files[0]);
    expect(t).toContain('set ew_bl_known_scanners_v4 {\n        type ipv4_addr; flags interval; auto-merge;\n        elements = { 198.51.100.0/24, 203.0.113.99 }');
    expect(t).toContain('ip saddr @ew_bl_known_scanners_v4 counter drop comment "blocklist: Known scanners"');
    expect(t).toContain('ip6 daddr @ew_bl_country_xx_v6 counter drop');
    expect(t).not.toContain('192.0.2.0/24');
    const lines = t.split('\n');
    expect(lines.findIndex((l) => l.includes('@ew_bl_known_scanners_v4'))).toBeLessThan(lines.findIndex((l) => l.includes('ct state established')));
    expect(res.files.map((f) => f.name)).toEqual(expect.arrayContaining(['emberwall-blocklists.sh', 'emberwall-blocklists.service', 'emberwall-blocklists.timer', '99-emberwall.conf']));
    const up = fileText(res.files.find((f) => f.name === 'emberwall-blocklists.sh')!);
    expect(up).toContain(`fetch 'https://lists.example.org/xx.zone'`);
    expect(up).toContain('flush set inet emberwall ew_bl_country_xx_v4');
    expect(res.diagnostics.some((d) => d.level === 'error' && d.message.includes('garbage'))).toBe(true);
  });
  it('real nft accepts a ruleset with blocklists', () => {
    const probe = spawnSync('nft', ['-c', 'list', 'ruleset']);
    if (probe.status !== 0) return;
    const f = join(dir, 'bl.nft');
    writeFileSync(f, fileText(compile(withLists(), target('nftables', '1.0.9')).files[0]));
    const r = spawnSync('nft', ['-c', '-f', f], { encoding: 'utf8' });
    expect(r.stderr).toBe('');
  });
  it('iptables and ufw use ipset; firewalld uses its own ipsets', () => {
    const ipt = compile(withLists(), target('iptables', '1.8.10'));
    expect(fileText(ipt.files[0])).toContain('-A INPUT -m set --match-set ew_bl_known_scanners_v4 src');
    expect(fileText(ipt.files[0])).toContain('-A OUTPUT -m set --match-set ew_bl_country_xx_v4 dst');
    expect(fileText(ipt.files[2])).toContain('ipset create ew_bl_known_scanners_v4 hash:net family inet -exist');
    const ufw = compile(withLists(), target('ufw', '0.36.2'));
    expect(fileText(ufw.files.find((f) => f.name === 'before.rules.fragment')!)).toContain('-I ufw-before-input -m set --match-set ew_bl_known_scanners_v4 src');
    const fwd = fileText(compile(withLists(), target('firewalld', '2.3.1')).files[0]);
    expect(fwd).toContain('--new-ipset=ew_bl_known_scanners_v6 --type=hash:net --option=family=inet6');
    expect(fwd).toContain(`rule priority="-32500" family="ipv4" source ipset="ew_bl_known_scanners_v4" drop`);
  });
  it('refuses URLs that could break out of the shell script', () => {
    const p = withLists();
    p.blocklists[1].url = "https://x.example/$(touch_pwned)";
    const res = compile(p, target('nftables', '1.0.9'));
    expect(res.diagnostics.some((d) => d.level === 'error' && d.message.includes('URL'))).toBe(true);
    expect(res.files.some((f) => fileText(f).includes("touch_pwned"))).toBe(false);
  });
  it('simulator drops listed sources first', () => {
    const r = simulate(withLists(), { direction: 'in', src: '198.51.100.7', dst: '192.0.2.1', proto: 'tcp', port: 443, state: 'established' });
    expect(r.verdict).toBe('drop');
    expect(r.decidedBy).toContain('Known scanners');
  });
});

describe('generated shell scripts', () => {
  it('pass sh -n for every template and tool', () => {
    for (const t of [...TEMPLATES.map((x) => x.build()), withLists()]) {
      for (const tool of TOOLS) {
        for (const f of compile(t, target(tool, latest[tool])).files.filter((x) => x.lang === 'shell')) {
          const r = spawnSync('sh', ['-n'], { input: fileText(f), encoding: 'utf8' });
          expect(r.stderr, `${t.name} ${tool} ${f.name}`).toBe('');
        }
      }
    }
  });
});

describe('kernel hardening', () => {
  it('writes a sysctl drop-in only when settings are enabled', () => {
    expect(sysctlFile(emptyProject())).toBeNull();
    const p = emptyProject();
    p.hardening = ['rp_filter', 'no_redirects'];
    p.options.forwarding = true;
    const t = fileText(sysctlFile(p)!);
    expect(t).toContain('net.ipv4.conf.all.rp_filter = 1');
    expect(t).toContain('-net.ipv6.conf.all.accept_redirects = 0');
    expect(t).toContain('net.ipv4.ip_forward = 1');
    expect(t).not.toContain('tcp_syncookies');
  });
  it('has unique ids and well-formed keys', () => {
    expect(new Set(HARDENING.map((h) => h.id)).size).toBe(HARDENING.length);
    for (const h of HARDENING) for (const [k, v] of h.lines) expect(`${k}=${v}`).toMatch(/^-?net\.[a-z0-9_.]+=[01]$/);
  });
});

describe('compliance profiles', () => {
  it('scores a weak and a strong project differently', () => {
    const weak = emptyProject();
    weak.policies = { in: 'accept', out: 'accept', forward: 'accept' };
    weak.rules = [newRule({ name: 'New rule', proto: 'tcp', ports: ['23', '5432', '22'] })];
    const strong = TEMPLATES.find((t) => t.id === 'bastion')!.build();
    strong.hardening = [...RECOMMENDED_HARDENING];
    strong.tests = [{ id: 't', name: 'telnet', packet: { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 23, state: 'new' }, expect: 'block' }];
    for (const prof of PROFILES) {
      const w = assess(weak, prof.id);
      const s = assess(strong, prof.id);
      expect(w.percent, prof.id).toBeLessThan(50);
      expect(s.percent, prof.id).toBeGreaterThan(w.percent + 30);
      for (const r of [...w.results, ...s.results]) expect(r.evidence.length).toBeGreaterThan(5);
    }
    const pci = assess(weak, 'pci');
    expect(pci.results.find((r) => r.id === 'data-stores')!.status).toBe('fail');
    expect(pci.results.find((r) => r.id === 'insecure-services')!.evidence).toContain('New rule');
  });
});
