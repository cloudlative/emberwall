import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { iacFiles } from '../src/core/compile/iac';
import { importFirewalldXml } from '../src/core/import/firewalldXml';
import { importNft } from '../src/core/import/nft';
import { importUfw } from '../src/core/import/ufw';
import { lint } from '../src/core/lint';
import { coerceProject, emptyProject, newRule, uid } from '../src/core/model';
import { representative } from '../src/core/net';
import { buildAxes, reachability, runTests, semanticDiff } from '../src/core/reach';
import { simulate } from '../src/core/simulate';
import { resolveTarget, type Tool } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

const target = (tool: Tool, version: string) => resolveTarget({ distro: 'custom', tool, version });
const out = (p = TEMPLATES[0].build(), tool: Tool = 'nftables', version = '1.0.9', file = 0) => fileText(compile(p, target(tool, version)).files[file]);
const tpl = (id: string) => TEMPLATES.find((t) => t.id === id)!.build();

describe('advanced matches', () => {
  const p = emptyProject();
  p.rules = [
    newRule({ name: 'ssh', proto: 'tcp', ports: ['22'], rateLimit: { rate: 6, per: 'minute', burst: 10, perSource: true }, connLimit: 3 }),
    newRule({ name: 'hours', proto: 'tcp', ports: ['8443'], schedule: { days: ['Mon', 'Fri'], from: '08:00', to: '18:00' } }),
    newRule({ name: 'tftp', proto: 'udp', ports: ['69'], srcPorts: ['1024:65535'], srcMac: 'aa:bb:cc:00:11:22', mark: '0x10' }),
  ];
  it('iptables uses hashlimit, connlimit, time, mac and mark', () => {
    const t = out(p, 'iptables', '1.8.10');
    expect(t).toMatch(/--dport 22 -m hashlimit --hashlimit-above 6\/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name ew_\w+ .* -j DROP/);
    expect(t).toMatch(/--dport 22 -m connlimit --connlimit-above 3 .* -j REJECT --reject-with tcp-reset/);
    expect(t).toContain('-m time --timestart 08:00 --timestop 18:00 --weekdays Mon,Fri');
    expect(t).toContain('--sport 1024:65535 -m mac --mac-source aa:bb:cc:00:11:22 -m mark --mark 0x10');
  });
  it('nftables uses dynamic sets, or meters before 0.9.7', () => {
    const modern = out(p, 'nftables', '1.0.9');
    expect(modern).toMatch(/set ew_rl_\w+_v4 \{\n\s+type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m;/);
    expect(modern).toMatch(/add @ew_rl_\w+_v4 \{ ip saddr limit rate over 6\/minute burst 10 packets \} counter drop/);
    expect(modern).toMatch(/add @ew_cl_\w+_v6 \{ ip6 saddr ct count over 3 \} counter reject with tcp reset/);
    expect(modern).toContain('meta hour "08:00"-"18:00" meta day { "Monday", "Friday" }');
    expect(modern).toContain('ether saddr aa:bb:cc:00:11:22 udp sport 1024-65535 udp dport 69 meta mark 0x10');
    const old = compile(p, target('nftables', '0.9.0'));
    const text = fileText(old.files[0]);
    expect(text).toMatch(/meter ew_rl_\w+_v4 \{ ip saddr limit rate over/);
    expect(text).not.toContain('ct count');
    expect(text).not.toContain('meta hour');
    expect(old.diagnostics.filter((d) => d.kind === 'unsupported').length).toBeGreaterThanOrEqual(2);
  });
  it('ufw maps per-client limits to "limit" and sends the rest to the fragment', () => {
    const res = compile(p, target('ufw', '0.36.2'));
    const frag = fileText(res.files.find((f) => f.name === 'before.rules.fragment')!);
    expect(frag).toContain('-m time --timestart 08:00');
    expect(frag).toContain('--connlimit-above 3');
    const q = emptyProject();
    q.rules = [newRule({ name: 'ssh', proto: 'tcp', ports: ['22'], rateLimit: { rate: 6, per: 'minute', burst: 10, perSource: true } })];
    expect(out(q, 'ufw', '0.36.2')).toContain('ufw limit in proto tcp from any to any port 22');
  });
  it('firewalld reports what it cannot express', () => {
    const res = compile(p, target('firewalld', '2.3.1'));
    expect(res.diagnostics.filter((d) => d.kind === 'unsupported').map((d) => d.message).join(' ')).toMatch(/connection limit.*time-based.*packet mark/s);
  });
  it('protections appear in order: ban check first, traps before user rules', () => {
    const q = tpl('web');
    q.protections = { synFlood: { rate: 20, burst: 40 }, portScan: true, autoBan: { ports: ['23', '3389'], seconds: 600 } };
    const ipt = out(q, 'iptables', '1.8.10').split('\n');
    const idx = (s: string) => ipt.findIndex((l) => l.includes(s));
    expect(idx('--rcheck --seconds 600')).toBeLessThan(idx('RELATED,ESTABLISHED'));
    expect(idx('--tcp-flags ALL NONE')).toBeLessThan(idx('"SSH from admins"'));
    expect(idx('ew_ban --set')).toBeLessThan(idx('"SSH from admins"'));
    expect(idx('ew_syn')).toBeGreaterThan(0);
    const nft = out(q);
    expect(nft).toContain('ip saddr @ew_banned_v4 counter drop');
    expect(nft).toContain('tcp dport { 23, 3389 } add @ew_banned_v4 { ip saddr } counter drop');
    expect(nft).toContain('timeout 600s;');
    expect(simulate(q, { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 23, state: 'new' }).decidedBy).toBe('auto-ban trap');
  });
});

describe('zones', () => {
  const p = emptyProject();
  p.zones = [
    { id: 'lan', name: 'LAN', interfaces: ['eth1', 'eth2'], networks: ['192.168.0.0/16'], trust: 'trusted' },
    { id: 'wan', name: 'WAN', interfaces: ['eth0'], networks: [], trust: 'untrusted' },
  ];
  p.options.forwarding = true;
  p.rules = [
    newRule({ name: 'lan admin', proto: 'tcp', ports: ['22'], srcZone: 'lan' }),
    newRule({ name: 'lan out', direction: 'forward', proto: 'any', srcZone: 'lan', dstZone: 'wan' }),
  ];
  it('expand to interfaces and networks in every compiler', () => {
    const ipt = out(p, 'iptables', '1.8.10');
    expect(ipt).toContain('-A INPUT -i eth1 -s 192.168.0.0/16 -p tcp --dport 22');
    expect(ipt).toContain('-A INPUT -i eth2 -s 192.168.0.0/16 -p tcp --dport 22');
    expect(ipt).toContain('-A FORWARD -i eth2 -o eth0 -s 192.168.0.0/16');
    expect(out(p)).toContain('iifname "eth1" oifname "eth0" ip saddr 192.168.0.0/16');
  });
  it('drive the reachability matrix', () => {
    const axes = buildAxes(p);
    expect(axes.sources.map((s) => s.label)).toEqual(expect.arrayContaining(['Internet', 'LAN']));
    const rows = reachability(p, axes);
    const cell = (src: string, tgt: string) => rows.find((r) => r.source.label === src && r.target.label === tgt)!.cells[axes.services.findIndex((s) => s.id === 'tcp/22')];
    expect(cell('LAN', 'This host').verdict).toBe('accept');
    expect(cell('Internet', 'This host').verdict).toBe('drop');
    expect(cell('LAN', 'WAN').verdict).toBe('accept');
    expect(cell('Internet', 'LAN').verdict).toBe('drop');
  });
  it('flag unknown zones', () => {
    const q = { ...p, rules: [newRule({ name: 'x', srcZone: 'nope' })] };
    expect(lint(q).some((f) => f.detail.includes('unknown zone'))).toBe(true);
  });
});

describe('policy tests and semantic diff', () => {
  it('runs saved assertions', () => {
    const p = tpl('web');
    p.tests = [
      { id: uid('t'), name: 'web open', packet: { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 443, state: 'new' }, expect: 'accept' },
      { id: uid('t'), name: 'ssh closed', packet: { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 22, state: 'new' }, expect: 'block' },
      { id: uid('t'), name: 'wrong on purpose', packet: { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 80, state: 'new' }, expect: 'block' },
    ];
    expect(runTests(p).map((r) => r.pass)).toEqual([true, true, false]);
  });
  it('reports what a change opens and closes', () => {
    const before = tpl('web');
    const after = { ...before, rules: [...before.rules.filter((r) => r.name !== 'HTTP/3 (QUIC)'), newRule({ name: 'pg', proto: 'tcp', ports: ['5432'] })] };
    const changes = semanticDiff(before, after);
    expect(changes.some((c) => c.kind === 'opened' && c.service.id === 'tcp/5432' && c.source.id === 'internet')).toBe(true);
    expect(changes.some((c) => c.kind === 'closed' && c.service.id === 'udp/443')).toBe(true);
    expect(semanticDiff(before, before)).toEqual([]);
  });
  it('picks representative addresses', () => {
    expect(representative('10.20.0.0/24')).toBe('10.20.0.1');
    expect(representative('203.0.113.9')).toBe('203.0.113.9');
    expect(representative('2001:db8:10::/48')).toBe('2001:db8:10::1');
  });
});

describe('importers', () => {
  it('nft: importing our own output changes no access, for every template', () => {
    for (const t of TEMPLATES) {
      const p = t.build();
      const r = importNft(out(p));
      expect(r.skipped, t.id).toEqual([]);
      expect(r.project.policies, t.id).toEqual(p.policies);
      expect(r.project.nat.length, t.id).toBe(p.nat.length);
      expect(semanticDiff(p, r.project), t.id).toEqual([]);
      expect(r.project.options.allowEstablished && r.project.options.allowLoopback && r.project.options.allowIcmp).toBe(true);
    }
  });
  it('nft: reads hand-written rulesets and reports what it skips', () => {
    const r = importNft(`table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport { 22, 80, 443 } accept
    ip saddr 10.0.0.0/8 udp dport 53 counter packets 12 bytes 900 accept
    tcp dport 8080 jump web
  }
}`);
    expect(r.project.policies.in).toBe('drop');
    expect(r.project.options.allowLoopback && r.project.options.allowEstablished).toBe(true);
    expect(r.project.rules.map((x) => x.ports)).toEqual([['22', '80', '443'], ['53']]);
    expect(r.project.rules[1].src).toEqual(['10.0.0.0/8']);
    expect(r.skipped.length).toBe(1);
  });
  it('ufw: commands round-trip without changing access', () => {
    for (const id of ['web', 'bastion', 'database', 'k8s', 'workstation']) {
      const p = tpl(id);
      const r = importUfw(out(p, 'ufw', '0.36.2'));
      expect(r.skipped, id).toEqual([]);
      expect(r.project.policies, id).toEqual(p.policies);
      expect(semanticDiff(p, r.project), id).toEqual([]);
    }
  });
  it('ufw: reads a status table', () => {
    const r = importUfw(`Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
5432/tcp                   ALLOW IN    10.20.0.0/24
22/tcp (v6)                LIMIT IN    Anywhere (v6)
80,443/tcp (v6)            ALLOW IN    Anywhere (v6)
`);
    expect(r.project.rules.length).toBe(3);
    expect(r.project.rules[0].family).toBe('both');
    expect(r.project.rules[0].rateLimit?.perSource).toBe(true);
    expect(r.project.rules[2].src).toEqual(['10.20.0.0/24']);
  });
  it('firewalld: zone XML round-trips the inbound side', () => {
    for (const id of ['web', 'database', 'k8s']) {
      const p = tpl(id);
      const xml = fileText(compile(p, target('firewalld', '2.3.1')).files[1]);
      const r = importFirewalldXml(xml);
      expect(r.skipped, id).toEqual([]);
      const inbound = { ...p, rules: p.rules.filter((x) => x.direction === 'in'), nat: [] };
      expect(semanticDiff(inbound, { ...r.project, nat: [] }), id).toEqual([]);
    }
  });
  it('firewalld: maps services and reports unknown ones', () => {
    const r = importFirewalldXml('<zone><short>Public</short><service name="ssh"/><service name="https"/><service name="frobnicate"/><port port="8000-8100" protocol="tcp"/></zone>');
    expect(r.project.rules.map((x) => x.ports)).toEqual([['22'], ['443'], ['8000:8100']]);
    expect(r.skipped.length).toBe(1);
  });
});

describe('automation export and compatibility', () => {
  it('wraps a build for Ansible, Terraform and cloud-init', () => {
    const files = iacFiles(compile(tpl('web'), target('nftables', '1.0.9')));
    expect(files.map((f) => f.name)).toEqual(['emberwall-playbook.yml', 'emberwall.tf', 'emberwall-cloud-init.yaml']);
    expect(fileText(files[0])).toContain('nft -c -f /etc/emberwall/emberwall.nft');
    expect(fileText(files[1])).toContain('resource "terraform_data" "emberwall"');
    expect(fileText(files[2]).startsWith('#cloud-config')).toBe(true);
  });
  it('loads projects saved before zones and protections existed', () => {
    const p = coerceProject({ name: 'old', rules: [{ name: 'r', ports: ['22'] }] });
    expect(p.zones).toEqual([]);
    expect(p.protections).toEqual({});
    expect(p.tests).toEqual([]);
  });
});
