// Feeds generated rulesets to the real binaries when they are installed and usable.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { resolveTarget } from '../src/core/targets';
import { emptyProject, newNat, newRule } from '../src/core/model';
import { TEMPLATES as STOCK, type Template } from '../src/core/templates';

// A project that exercises the less common rule shapes.
const edge = emptyProject('Edge cases');
edge.policies.out = 'drop';
edge.options.logDropped = true;
edge.rules = [
  newRule({ name: 'block bad', action: 'drop', proto: 'any', src: ['198.51.100.7', '2001:db8::bad'], log: true }),
  newRule({ name: 'limited', proto: 'tcp', ports: ['22', '8000:8100'], rateLimit: { rate: 10, per: 'minute', burst: 20 }, log: true }),
  newRule({ name: 'v4 only', proto: 'udp', ports: ['53'], family: 'ipv4', inIface: 'eth0' }),
  newRule({ name: 'ping type', proto: 'icmp', icmpType: 'echo-request', src: ['10.0.0.0/8'] }),
  newRule({ name: 'any icmp', proto: 'icmp' }),
  newRule({ name: 'stateful', proto: 'tcp', ports: ['443'], states: ['new'] }),
  newRule({ name: "it's rejected", direction: 'out', action: 'reject', proto: 'tcpudp', ports: ['25', '587'], dst: ['192.0.2.0/24'] }),
  newRule({ name: 'many ports', proto: 'tcp', ports: Array.from({ length: 20 }, (_, i) => String(1000 + i * 3)) }),
  newRule({ name: 'fwd', direction: 'forward', proto: 'tcp', ports: ['443'], inIface: 'eth1', outIface: 'eth0', dst: ['10.1.0.0/16'] }),
];
edge.zones = [
  { id: 'lan', name: 'LAN', interfaces: ['eth1', 'eth2'], networks: ['192.168.0.0/16'], trust: 'trusted' },
  { id: 'wan', name: 'WAN', interfaces: ['eth0'], networks: [], trust: 'untrusted' },
];
edge.protections = { synFlood: { rate: 25, burst: 50 }, portScan: true, autoBan: { ports: ['23', '3389', '5900:5910'], seconds: 3600 } };
edge.rules.push(
  newRule({ name: 'per client ssh', proto: 'tcp', ports: ['2222'], rateLimit: { rate: 6, per: 'minute', burst: 10, perSource: true }, connLimit: 4, log: true }),
  newRule({ name: 'per client v4 dns', proto: 'tcpudp', ports: ['5353'], src: ['10.0.0.0/8'], rateLimit: { rate: 50, per: 'second', burst: 100, perSource: true } }),
  newRule({ name: 'office hours', proto: 'tcp', ports: ['8443'], schedule: { days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], from: '08:00', to: '18:00' } }),
  newRule({ name: 'mac and mark', proto: 'udp', ports: ['69'], srcPorts: ['1024:65535'], srcMac: 'AA:bb:cc:00:11:22', mark: '0x10' }),
  newRule({ name: 'sports', proto: 'tcpudp', srcPorts: ['53', '123'], ports: ['1024:65535'], connLimit: 10 }),
  newRule({ name: 'zone fwd', direction: 'forward', proto: 'tcp', ports: ['443'], srcZone: 'lan', dstZone: 'wan' }),
  newRule({ name: 'zone in', proto: 'any', srcZone: 'lan' }),
);
edge.nat = [
  newNat({ name: 'snat', kind: 'snat', iface: 'eth0', src: '10.0.0.0/24', toAddr: '203.0.113.5', randomFully: true }),
  newNat({ name: 'masq', kind: 'masquerade', iface: 'eth0', randomFully: true }),
  newNat({ name: 'fwd range', kind: 'dnat', iface: 'eth0', proto: 'udp', port: '5000:5010', toAddr: '10.0.0.9' }),
  newNat({ name: 'v6 fwd', kind: 'dnat', proto: 'tcp', port: '443', toAddr: '2001:db8::10', toPort: '8443' }),
];
const TEMPLATES: Template[] = [...STOCK, { id: 'edge-cases', name: 'Edge cases', icon: '', summary: '', build: () => edge }];

function usable(cmd: string, args: string[], input?: string): boolean {
  const r = spawnSync(cmd, args, { input, encoding: 'utf8' });
  return r.status === 0;
}

const dir = mkdtempSync(join(tmpdir(), 'emberwall-'));
const probe = '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n';
const hasIptables = usable('iptables-restore', ['--test'], probe);
const hasIp6tables = usable('ip6tables-restore', ['--test'], probe);
const hasNft = usable('nft', ['-c', 'list', 'ruleset']);

function check(cmd: string, args: string[], input?: string) {
  const r = spawnSync(cmd, args, { input, encoding: 'utf8' });
  expect(r.stderr + r.stdout, `${cmd} ${args.join(' ')}`).toBe('');
  expect(r.status).toBe(0);
}

describe.skipIf(!hasIptables)('real iptables-restore --test', () => {
  for (const t of TEMPLATES) {
    it(`accepts ${t.id}`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'iptables', version: '1.8.10' }));
      check('iptables-restore', ['--test'], fileText(res.files[0]));
      if (hasIp6tables) check('ip6tables-restore', ['--test'], fileText(res.files[1]));
    });
  }
});

describe.skipIf(!hasNft)('real nft --check', () => {
  const installed = execFileSync('nft', ['--version'], { encoding: 'utf8' }).match(/v(\d+\.\d+\.\d+)/)?.[1] ?? '1.0.0';
  for (const t of TEMPLATES) {
    it(`accepts ${t.id} (nft ${installed})`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'nftables', version: installed }));
      const f = join(dir, `${t.id}.nft`);
      writeFileSync(f, fileText(res.files[0]));
      check('nft', ['-c', '-f', f]);
    });
    it(`accepts ${t.id} with every fallback active`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'nftables', version: '0.9.0' }));
      const f = join(dir, `${t.id}-old.nft`);
      writeFileSync(f, fileText(res.files[0]));
      check('nft', ['-c', '-f', f]);
    });
  }
});

describe('real tools availability', () => {
  it('reports what could be checked', () => {
    console.log(`real-tool checks: iptables=${hasIptables} ip6tables=${hasIp6tables} nft=${hasNft}`);
    expect(true).toBe(true);
  });
});
