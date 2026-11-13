// Feeds generated rulesets to the real binaries when they are installed and usable.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { activeLists, ipsetCreate } from '../src/core/compile/blocklists';
import { terraformModule } from '../src/core/compile/iac';
import { resolveTarget, TOOLS } from '../src/core/targets';
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
  newRule({ name: 'any wireguard', proto: 'udp', ports: ['51820'], inIface: 'wg+' }),
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

// firewalld's own offline tool applies the generated script to a private config directory.
// Debian/Ubuntu ship it for the system python; try that interpreter explicitly as well.
const fwOffline = [['firewall-offline-cmd'], ['python3.12', '/usr/bin/firewall-offline-cmd']].find((c) => usable(c[0], [...c.slice(1), '--version'])) ?? null;

function runFirewalld(script: string, name: string) {
  const conf = mkdtempSync(join(tmpdir(), `ew-fwd-${name}-`));
  // A fresh config of our own, so whatever this machine's firewalld is set to does not matter.
  writeFileSync(join(conf, 'firewalld.conf'), 'DefaultZone=public\n');
  const bin = mkdtempSync(join(tmpdir(), 'ew-fwbin-'));
  const shim = join(bin, 'firewall-cmd');
  writeFileSync(
    shim,
    [
      '#!/bin/bash',
      'args=()',
      'for a in "$@"; do [ "$a" = --permanent ] || args+=("$a"); done',
      'case "${args[0]:-}" in --reload|--state) exit 0 ;; esac',
      `exec ${fwOffline!.join(' ')} --system-config "${conf}" "\${args[@]}"`,
    ].join('\n'),
    { mode: 0o755 },
  );
  const f = join(conf, 'script.sh');
  writeFileSync(f, script);
  const r = spawnSync('sh', [f], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
  return { status: r.status, out: r.stdout + r.stderr, conf };
}

describe.skipIf(!fwOffline)('real firewall-offline-cmd', () => {
  for (const version of ['2.1.1', '0.9.3', '0.8.2']) {
    for (const t of TEMPLATES) {
      it(`runs ${t.id} for firewalld ${version}`, () => {
        const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'firewalld', version }));
        const r = runFirewalld(fileText(res.files[0]), `${t.id}-${version}`);
        expect(r.out).not.toMatch(/Error|Traceback|INVALID/i);
        expect(r.status, r.out).toBe(0);
      });
    }
  }

  it('binds zone interfaces and builds zone-to-zone policies', () => {
    const res = compile(edge, resolveTarget({ distro: 'custom', tool: 'firewalld', version: '2.1.1' }));
    const r = runFirewalld(fileText(res.files[0]), 'zones');
    expect(r.status, r.out).toBe(0);
    const read = (p: string) => execFileSync('cat', [join(r.conf, p)], { encoding: 'utf8' });
    const lan = read('zones/ew-lan.xml');
    expect(lan).toContain('<interface name="eth1"/>');
    expect(lan).toContain('<interface name="eth2"/>');
    expect(read('zones/ew-wan.xml')).toContain('<interface name="eth0"/>');
    // "zone in" accepts everything from the LAN zone and nowhere else.
    expect(lan).toMatch(/<accept\/>/);
    const pols = execFileSync('sh', ['-c', `cat ${join(r.conf, 'policies')}/ew-fwd-*.xml`], { encoding: 'utf8' });
    expect(pols).toContain('<ingress-zone name="ew-lan"/>');
    expect(pols).toContain('<egress-zone name="ew-wan"/>');
    // Masquerading follows the WAN interface into its zone.
    expect(read('zones/ew-wan.xml')).toContain('<masquerade/>');
  });
});

// ---- ipset blocklists, loaded for real in a private network namespace and tested with ping ----

const isRoot = process.getuid?.() === 0;
const canIpsetNs = isRoot && hasIptables && usable('ipset', ['--version']) && usable('ip', ['-V']) && usable('unshare', ['-n', 'true']);

function blocklistProject() {
  const p = emptyProject('Blocklist check');
  p.rules = [newRule({ name: 'web', proto: 'tcp', ports: ['443'] })];
  p.blocklists = [{ id: 'bl1', name: 'Bad hosts', enabled: true, entries: ['10.78.0.1', '2001:db8:dead::/48'], url: 'https://lists.example/bad.txt' }];
  return p;
}

describe.skipIf(!canIpsetNs)('real ipset blocklists in a namespace', () => {
  let holder: ReturnType<typeof spawn> | null = null;
  const ns = (cmd: string) => spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'sh', '-c', cmd], { encoding: 'utf8' });
  const ping = () => spawnSync('ping', ['-c1', '-W1', '10.78.0.2']).status === 0;

  beforeAll(async () => {
    holder = spawn('unshare', ['-n', 'sleep', '600'], { stdio: 'ignore' });
    await new Promise((r) => setTimeout(r, 200));
    spawnSync('ip', ['link', 'del', 'ewbl0h']);
    for (const c of [`ip link add ewbl0h type veth peer name ewbl0t`, `ip link set ewbl0t netns ${holder.pid}`, 'ip addr add 10.78.0.1/30 dev ewbl0h', 'ip link set ewbl0h up']) {
      expect(spawnSync('sh', ['-c', c]).status, c).toBe(0);
    }
    expect(ns('ip link set lo up && ip addr add 10.78.0.2/30 dev ewbl0t && ip link set ewbl0t up').status).toBe(0);
  });
  afterAll(() => {
    holder?.kill();
    spawnSync('ip', ['link', 'del', 'ewbl0h']);
  });

  it('iptables: the sets load, and a listed address is really dropped', () => {
    const p = blocklistProject();
    const res = compile(p, resolveTarget({ distro: 'custom', tool: 'iptables', version: '1.8.10' }));
    expect(ns('iptables -F; iptables -P INPUT ACCEPT; ipset destroy 2>/dev/null; true').status).toBe(0);
    expect(ping()).toBe(true);
    for (const c of ipsetCreate(activeLists(p), true)) expect(ns(c).status, c).toBe(0);
    const v4 = join(dir, 'bl.v4');
    const v6 = join(dir, 'bl.v6');
    writeFileSync(v4, fileText(res.files[0]));
    writeFileSync(v6, fileText(res.files[1]));
    const load = ns(`iptables-restore < ${v4} && ip6tables-restore < ${v6}`);
    expect(load.status, load.stderr).toBe(0);
    expect(ns('iptables-save').stdout).toContain('--match-set ew_bl_bad_hosts_v4 src');
    expect(ping(), 'ping from a blocklisted address').toBe(false);
    expect(ns('ipset del ew_bl_bad_hosts_v4 10.78.0.1').status).toBe(0);
    expect(ping(), 'ping once the address is off the list').toBe(true);

    // The updater refreshes the set from the downloaded list and keeps the project's own entries.
    const list = join(dir, 'downloaded.txt');
    writeFileSync(list, '# a comment\n198.51.100.0/24\n203.0.113.9\nnot an address\n');
    const updater = res.files.find((f) => f.name === 'emberwall-blocklists.sh')!;
    const script = join(dir, 'updater.sh');
    writeFileSync(script, fileText(updater).replace("'https://lists.example/bad.txt'", `'file://${list}'`));
    const up = ns(`sh ${script}`);
    expect(up.status, up.stderr).toBe(0);
    const members = ns('ipset list ew_bl_bad_hosts_v4').stdout;
    expect(members).toContain('198.51.100.0/24');
    expect(members).toContain('203.0.113.9');
    expect(members).toContain('10.78.0.1');
    expect(members).not.toContain('not an address');
    expect(ping(), 'blocked again after the refresh').toBe(false);
  });

  it.skipIf(!existsSync('/etc/ufw/before.rules'))('ufw: the before.rules fragment loads and drops a listed address before ufw accepts ping', () => {
    const p = blocklistProject();
    const res = compile(p, resolveTarget({ distro: 'custom', tool: 'ufw', version: '0.36.2' }));
    const frag = fileText(res.files.find((f) => f.name === 'before.rules.fragment')!);
    const lines = frag.split('\n').filter((l) => l.startsWith('-'));
    expect(lines.length).toBeGreaterThan(0);
    // Paste the lines above the final COMMIT, as the fragment says, into ufw's real file.
    const before = execFileSync('cat', ['/etc/ufw/before.rules'], { encoding: 'utf8' });
    const at = before.lastIndexOf('COMMIT');
    const merged = `${before.slice(0, at)}${lines.join('\n')}\n${before.slice(at)}`;
    // ufw's file refers to chains ufw creates first; declare them so it loads on its own.
    const chains = [...new Set([...merged.matchAll(/(?:-[AI]|-j) (ufw-[\w-]+)/g)].map((m) => m[1]))].filter((c) => !merged.includes(`:${c} `));
    const file = merged.replace('*filter\n', `*filter\n${chains.map((c) => `:${c} - [0:0]`).join('\n')}\n`);
    const path = join(dir, 'before.rules');
    writeFileSync(path, file);
    expect(ns('iptables -F; iptables -X; iptables -P INPUT ACCEPT; ipset destroy 2>/dev/null; true').status).toBe(0);
    for (const c of ipsetCreate(activeLists(p), true)) expect(ns(c).status, c).toBe(0);
    const load = ns(`iptables-restore < ${path} && iptables -A INPUT -j ufw-before-input`);
    expect(load.status, load.stderr).toBe(0);
    expect(ping(), 'ping from a blocklisted address').toBe(false);
    expect(ns('ipset del ew_bl_bad_hosts_v4 10.78.0.1').status).toBe(0);
    expect(ping(), 'ufw accepts ping once the address is off the list').toBe(true);
  });
});

const hasTerraform = usable('terraform', ['version']);
describe.skipIf(!hasTerraform)('real terraform validate (SSH push export)', () => {
  for (const t of TEMPLATES) {
    it(`validates ${t.id} for every tool`, () => {
      for (const tool of TOOLS) {
        const d = join(dir, `tf-${t.id}-${tool}`);
        mkdirSync(d, { recursive: true });
        writeFileSync(join(d, 'main.tf'), fileText(terraformModule(compile(t.build(), resolveTarget({ distro: 'ubuntu-24.04', tool, version: '' })))));
        for (const args of [['init', '-input=false', '-no-color'], ['validate', '-no-color'], ['fmt', '-check', '-no-color']]) {
          const r = spawnSync('terraform', args, { cwd: d, encoding: 'utf8' });
          expect(r.status, `${tool} terraform ${args[0]}: ${r.stdout}${r.stderr}`).toBe(0);
        }
      }
    }, 60_000);
  }
});

describe('real tools availability', () => {
  it('reports what could be checked', () => {
    console.log(`real-tool checks: iptables=${hasIptables} ip6tables=${hasIp6tables} nft=${hasNft} firewalld=${!!fwOffline} ipset-netns=${canIpsetNs} terraform=${hasTerraform}`);
    expect(true).toBe(true);
  });
});
