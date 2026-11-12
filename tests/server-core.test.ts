import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { deployPlan } from '../src/core/compile/deployPlan';
import { detect, nearestKnown, readLiveConfig, zoneXmlCommand, type ProbeOutput } from '../src/core/live';
import { emptyProject, newNat, newRule } from '../src/core/model';
import { semanticDiff } from '../src/core/reach';
import { cleanText, harden } from '../src/core/safety';
import { resolveTarget, TOOLS, type Tool } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

const target = (tool: Tool, version: string) => resolveTarget({ distro: 'custom', tool, version });
const latest: Record<Tool, string> = { nftables: '1.0.9', iptables: '1.8.10', ufw: '0.36.2', firewalld: '2.3.1' };
const tmp = mkdtempSync(join(tmpdir(), 'emberwall-srv-'));
const res = (stdout: string, code = 0, stderr = '') => ({ code, stdout, stderr });

describe('input hardening', () => {
  const marker = join(tmp, 'pwned');
  const evil = `x'; touch ${marker}; echo '`;
  const evil2 = `$(touch ${marker})\`touch ${marker}\`\n touch ${marker}`;
  function hostile() {
    const p = emptyProject(`fw\n touch ${marker}`);
    p.description = evil2;
    p.policies.out = 'drop';
    p.addressGroups = [{ id: 'g', name: evil, members: ['10.0.0.0/8'] }];
    p.zones = [{ id: 'z', name: evil2, interfaces: [`eth0; touch ${marker}`, 'eth1'], networks: [], trust: 'trusted' }];
    p.blocklists = [{ id: 'b', name: evil, enabled: true, entries: ['198.51.100.0/24'] }];
    p.rules = [
      newRule({ name: evil, proto: 'tcp', ports: ['22'], src: ['@g'], log: true }),
      newRule({ name: evil2, direction: 'out', proto: 'tcp', ports: ['25'], action: 'reject' }),
      newRule({ name: 'iface', proto: 'tcp', ports: ['80'], inIface: `eth0 -j ACCEPT; touch ${marker}` }),
      newRule({ name: 'icmp', proto: 'icmp', icmpType: `echo-request; touch ${marker}` }),
      newRule({ name: 'limit', proto: 'tcp', ports: ['443'], rateLimit: { rate: `1; touch ${marker}` as unknown as number, per: 'minute', burst: 5 } }),
      newRule({ name: 'zone', direction: 'forward', proto: 'tcp', ports: ['443'], srcZone: 'z' }),
    ];
    p.nat = [
      newNat({ name: evil, kind: 'dnat', proto: 'tcp', port: '80', toAddr: `10.0.0.5; touch ${marker}` }),
      newNat({ name: 'ok', kind: 'masquerade', iface: `eth0$(touch ${marker})` }),
    ];
    return p;
  }
  it('strips quoting characters from names and rejects invalid identifiers', () => {
    expect(cleanText(`a'b"c\`d$e\\f\ng`)).toBe('a b c d e f g');
    const h = harden(hostile());
    expect(h.problems.length).toBeGreaterThanOrEqual(6);
    expect(h.project.rules.filter((r) => r.enabled).map((r) => r.name)).not.toContain('iface');
    expect(h.project.zones[0].interfaces).toEqual(['eth1']);
    expect(h.project.nat.every((n) => !n.enabled)).toBe(true);
  });
  it('generated shell scripts run nothing but firewall commands, even for a hostile project', () => {
    const stubs = 'ufw() { :; }\nfirewall-cmd() { :; }\nsed() { :; }\ncp() { :; }\nsysctl() { :; }\n';
    for (const tool of TOOLS) {
      const result = compile(hostile(), target(tool, tool === 'firewalld' ? '0.8.2' : latest[tool]));
      expect(result.diagnostics.some((d) => d.level === 'error')).toBe(true);
      for (const f of result.files.filter((x) => x.lang === 'shell' && x.name !== 'emberwall-apply.sh')) {
        const r = spawnSync('sh', [], { input: stubs + fileText(f).replace(/^set -eu$/m, 'set -u'), encoding: 'utf8' });
        expect(existsSync(marker), `${tool} ${f.name} executed injected code\n${r.stderr}`).toBe(false);
      }
      for (const f of result.files) expect(fileText(f)).not.toMatch(/\$\(touch|`touch/);
    }
    // And with the newer firewalld code path (policies instead of direct rules).
    const r2 = compile(hostile(), target('firewalld', '2.3.1'));
    spawnSync('sh', [], { input: stubs + fileText(r2.files[0]).replace(/^set -eu$/m, 'set -u'), encoding: 'utf8' });
    expect(existsSync(marker)).toBe(false);
  });
  it('a hostile project still produces rulesets the real tools accept', () => {
    const nft = spawnSync('nft', ['-c', 'list', 'ruleset']);
    if (nft.status !== 0) return;
    const f = join(tmp, 'hostile.nft');
    writeFileSync(f, fileText(compile(hostile(), target('nftables', '1.0.9')).files[0]));
    expect(spawnSync('nft', ['-c', '-f', f], { encoding: 'utf8' }).stderr).toBe('');
    const ipt = spawnSync('iptables-restore', ['--test'], { input: fileText(compile({ ...hostile(), blocklists: [] }, target('iptables', '1.8.10')).files[0]), encoding: 'utf8' });
    expect(ipt.stderr).toBe('');
  });
});

describe('live server detection', () => {
  const web = TEMPLATES[0].build();
  const nftText = fileText(compile(web, target('nftables', '1.0.9')).files[0]);
  const base: ProbeOutput = {
    uid: res('0\n'), kernel: res('6.8.0-45-generic\n'),
    os: res('PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n'),
    nftVersion: res('nftables v1.0.9 (Old Doc Yak #3)\n'), iptablesVersion: res('iptables v1.8.10 (nf_tables)\n'),
    ufwVersion: res('ufw 0.36.2\nCopyright 2008-2023 Canonical Ltd.\n'), firewalldVersion: res('', 127, 'not found'),
    firewalldState: res('', 127, 'not found'), ufwStatus: res('Status: inactive\n'), nftRuleset: res(nftText), iptablesSave: res(''), ip6tablesSave: res(''),
  };
  it('finds the tool in charge and its exact version', () => {
    const d = detect(base);
    expect(d).toMatchObject({ os: 'Ubuntu 24.04.1 LTS', activeTool: 'nftables', isRoot: true, needsPrivilege: false });
    expect(d.versions).toEqual({ nftables: '1.0.9', iptables: '1.8.10', ufw: '0.36.2' });
    expect(d.selection).toEqual({ distro: 'ubuntu-24.04', tool: 'nftables', version: '' });
    expect(detect({ ...base, ufwStatus: res('Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n') }).activeTool).toBe('ufw');
    expect(detect({ ...base, firewalldState: res('running\n'), firewalldVersion: res('1.3.4\n') }).activeTool).toBe('firewalld');
    const ipt = detect({ ...base, nftRuleset: res('table ip filter {\n}\n'), iptablesSave: res('*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n') });
    expect(ipt.activeTool).toBe('iptables');
  });
  it('falls back to the nearest known version on an unknown system', () => {
    const d = detect({ ...base, os: res('PRETTY_NAME="Gentoo Linux"\nID=gentoo\n'), nftVersion: res('nftables v1.0.8 (Old Doc Yak #2)\n') });
    expect(d.selection).toEqual({ distro: 'custom', tool: 'nftables', version: '1.0.6' });
    expect(nearestKnown('nftables', '0.8.0')).toBe('0.9.0');
    expect(nearestKnown('firewalld', '9.9.9')).toBe('2.5.2');
  });
  it('notices missing privilege', () => {
    const d = detect({ ...base, uid: res('1000\n'), nftRuleset: res('', 1, 'Operation not permitted (you must be root)') });
    expect(d.isRoot).toBe(false);
    expect(d.needsPrivilege).toBe(true);
  });
  it('reads the live ruleset back with no access difference', () => {
    const live = readLiveConfig(base, 'nftables')!;
    expect(live.report.skipped).toEqual([]);
    expect(semanticDiff(web, live.report.project)).toEqual([]);
    const v4 = fileText(compile(web, target('iptables', '1.8.10')).files[0]);
    const v6 = fileText(compile(web, target('iptables', '1.8.10')).files[1]).replace(/^# .*\n/gm, '');
    const ipt = readLiveConfig({ ...base, iptablesSave: res(v4), ip6tablesSave: res(v6) }, 'iptables')!;
    expect(semanticDiff(web, ipt.report.project)).toEqual([]);
    expect(ipt.report.project.rules.some((r) => r.family === 'both')).toBe(true);
  });
  it('reads Emberwall\'s own table alone and names other filtering tables', () => {
    const legacy = 'table inet legacy {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 23 accept\n\t}\n}\n';
    const both = readLiveConfig({ ...base, nftRuleset: res(legacy + nftText) }, 'nftables')!;
    expect(semanticDiff(web, both.report.project)).toEqual([]);
    expect(both.report.notes?.[0]).toContain('inet legacy');
    expect(both.report.project.rules.some((r) => r.ports.includes('23'))).toBe(false);
    const foreign = readLiveConfig({ ...base, nftRuleset: res(legacy + legacy.replace('legacy', 'second')) }, 'nftables')!;
    expect(foreign.report.notes?.[0]).toMatch(/2 tables that filter traffic/);
    expect(readLiveConfig(base, 'nftables')!.report.notes).toBeUndefined();
  });
  it('only builds a zone path from a safe zone name', () => {
    expect(zoneXmlCommand('public\n')).toBe('cat /etc/firewalld/zones/public.xml');
    expect(zoneXmlCommand('../../etc/shadow')).toBeNull();
    expect(zoneXmlCommand('a; reboot')).toBeNull();
  });
});

describe('guarded push plan', () => {
  it('is fixed text apart from the id and timeout, and passes sh -n', () => {
    for (const tool of TOOLS) {
      const plan = deployPlan(compile(TEMPLATES[0].build(), target(tool, latest[tool])), { id: 42, timeoutSeconds: 60 });
      expect(plan.blocked).toBeUndefined();
      expect(spawnSync('sh', ['-n'], { input: plan.script, encoding: 'utf8' }).stderr).toBe('');
      expect(plan.script).toContain('sleep 60');
      expect(plan.dir).toBe('/etc/emberwall/deploy-42');
    }
    expect(deployPlan(compile(TEMPLATES[0].build(), target('nftables', '1.0.9')), { id: 1, timeoutSeconds: 1 }).script).toContain('sleep 15');
    expect(() => deployPlan(compile(TEMPLATES[0].build(), target('nftables', '1.0.9')), { id: Number('1; reboot'), timeoutSeconds: 60 })).toThrow();
  });
  it('refuses builds with errors and iptables blocklists', () => {
    const bad = emptyProject();
    bad.rules = [newRule({ name: 'x', src: ['nope'] })];
    expect(deployPlan(compile(bad, target('nftables', '1.0.9')), { id: 1, timeoutSeconds: 60 }).blocked).toMatch(/errors/);
    const bl = TEMPLATES[0].build();
    bl.blocklists = [{ id: 'b', name: 'x', enabled: true, entries: ['198.51.100.0/24'] }];
    expect(deployPlan(compile(bl, target('iptables', '1.8.10')), { id: 1, timeoutSeconds: 60 }).blocked).toMatch(/ipset/);
  });

  const canNetns = spawnSync('unshare', ['-n', 'nft', 'list', 'ruleset']).status === 0;
  // Runs the real script with real nft inside a throwaway network namespace.
  function run(id: number, confirm: boolean, project = TEMPLATES[0].build()) {
    const etc = join(tmp, `etc-${id}`);
    const state = join(tmp, `state-${id}`);
    const plan = deployPlan(compile(project, target('nftables', '1.0.9')), { id, timeoutSeconds: 2, minTimeout: 2, etcDir: etc, stateDir: state });
    mkdirSync(plan.dir, { recursive: true });
    for (const f of plan.files) writeFileSync(join(plan.dir, f.name), f.text);
    writeFileSync(join(plan.dir, 'deploy.sh'), plan.script);
    const inner = [
      'nft add table inet previous',
      `sh '${join(plan.dir, 'deploy.sh')}'; echo "exit=$?"`,
      'echo "--- right after"; nft list tables',
      confirm ? plan.confirmCommand : 'true',
      'sleep 3.5',
      'echo "--- after timeout"; nft list tables',
      plan.statusCommand,
    ].join('\n');
    const r = spawnSync('unshare', ['-n', 'sh', '-c', inner], { encoding: 'utf8', timeout: 20000 });
    const [applied, rest] = (r.stdout ?? '').split('--- right after');
    const [right, after] = (rest ?? '').split('--- after timeout');
    return { applied, right, after, plan, stderr: r.stderr };
  }
  it.skipIf(!canNetns)('rolls back by itself when nobody confirms', () => {
    const r = run(101, false);
    expect(r.applied).toContain('exit=0');
    expect(r.right).toContain('table inet emberwall');
    expect(r.after).not.toContain('table inet emberwall');
    expect(r.after).toContain('table inet previous');
    expect(r.after.trim().split('\n').pop()).toBe('rolledback');
  }, 30000);
  it.skipIf(!canNetns)('keeps the new rules once confirmed', () => {
    const r = run(102, true);
    expect(r.right).toContain('table inet emberwall');
    expect(r.after).toContain('table inet emberwall');
    expect(r.after.trim().split('\n').pop()).toBe('confirmed');
    expect(existsSync(join(r.plan.state, 'backup.nft'))).toBe(true);
  }, 30000);
  it.skipIf(!canNetns)('changes nothing when the new rules fail the check', () => {
    const etc = join(tmp, 'etc-103');
    const state = join(tmp, 'state-103');
    const plan = deployPlan(compile(TEMPLATES[0].build(), target('nftables', '1.0.9')), { id: 103, timeoutSeconds: 2, minTimeout: 2, etcDir: etc, stateDir: state });
    mkdirSync(plan.dir, { recursive: true });
    writeFileSync(join(plan.dir, 'emberwall.nft'), 'table inet emberwall { this is not valid }\n');
    writeFileSync(join(plan.dir, 'deploy.sh'), plan.script);
    const r = spawnSync('unshare', ['-n', 'sh', '-c', `sh '${join(plan.dir, 'deploy.sh')}'; echo "exit=$?"; nft list tables`], { encoding: 'utf8', timeout: 20000 });
    expect(r.stdout).toContain('exit=1');
    expect(r.stdout).not.toContain('table inet emberwall');
    expect(r.stderr).toContain('did not pass the check');
    expect(readFileSync(join(plan.state, 'backup.nft'), 'utf8')).toBe('');
  }, 30000);
});
