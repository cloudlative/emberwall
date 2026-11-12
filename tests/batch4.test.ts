import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { fileText } from '../src/core/compile';
import { buildFleet, fleetAnsible, fleetFiles, projectForHost } from '../src/core/fleet';
import { analyzeLogs, parseLogLine, verdictNow } from '../src/core/logs';
import { coerceProject, newRule } from '../src/core/model';
import { TEMPLATES } from '../src/core/templates';

function fleet() {
  const p = TEMPLATES[0].build();
  p.hosts = [
    { id: 'web1', name: 'Web 1', address: '192.0.2.11', target: { distro: 'ubuntu-24.04', tool: 'nftables', version: '' } },
    { id: 'old1', name: 'Legacy box', target: { distro: 'centos-7', tool: 'iptables', version: '' } },
    { id: 'rh1', name: 'RHEL app', target: { distro: 'rhel-9', tool: 'ufw', version: '' } },
  ];
  p.rules.push(newRule({ name: 'Legacy admin UI', proto: 'tcp', ports: ['8443'], hosts: ['old1'] }));
  return p;
}

describe('fleet', () => {
  it('gives each host the shared rules plus its own, for its own target', () => {
    const p = fleet();
    const builds = buildFleet(p);
    expect(builds.map((b) => b.result.target.tool)).toEqual(['nftables', 'iptables', 'firewalld']); // ufw is not packaged on RHEL
    expect(builds.map((b) => b.rules)).toEqual([3, 4, 3]);
    expect(fileText(builds[0].result.files[0])).not.toContain('8443');
    expect(fileText(builds[1].result.files[0])).toContain('--dport 8443');
    expect(builds[1].result.target.version).toBe('1.4.21');
    expect(projectForHost(p, null)).toBe(p);
    expect(projectForHost(p, 'missing')).toBe(p);
  });
  it('bundles per-host files with an inventory and a playbook that parses', () => {
    const builds = buildFleet(fleet());
    const files = fleetFiles(builds);
    expect(files.map((f) => f.path)).toEqual(expect.arrayContaining(['hosts/web-1/emberwall.nft', 'hosts/legacy-box/rules.v4', 'inventory.ini', 'fleet-playbook.yml']));
    const [inv, pb] = fleetAnsible(builds);
    expect(fileText(inv)).toContain('web-1 ansible_host=192.0.2.11 emberwall_tool=nftables');
    const y = spawnSync('python3', ['-I', '-c', 'import sys,yaml; d=yaml.safe_load(sys.stdin); assert d[0]["hosts"]=="emberwall"'], { input: fileText(pb), encoding: 'utf8' });
    if (!/No module named/.test(y.stderr)) expect(y.stderr).toBe('');
  });
  it('survives a save/load round trip', () => {
    const p = coerceProject(JSON.parse(JSON.stringify(fleet())));
    expect(p.hosts.length).toBe(3);
    expect(p.rules[p.rules.length - 1].hosts).toEqual(['old1']);
  });
});

describe('log analyzer', () => {
  const log = `Nov 12 14:02:11 web1 kernel: [ 9123.11] ew-drop-in: IN=eth0 OUT= MAC=52:54 SRC=203.0.113.45 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=51422 DPT=23 SYN
Nov 12 14:02:12 web1 kernel: [ 9124.02] ew-drop-in: IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 PROTO=TCP SPT=51423 DPT=3389 SYN
Nov 12 14:02:13 web1 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=443
Nov 12 14:02:15 web1 kernel: [ 9127.40] IN=eth1 OUT=eth0 SRC=2001:db8::5 DST=2001:db8:1::9 PROTO=UDP SPT=40111 DPT=53
Nov 12 14:02:16 web1 sshd[11]: Accepted publickey for root
garbage SRC=nope DST=1.2.3.4 PROTO=TCP`;
  it('parses iptables, nftables and ufw lines', () => {
    const e = parseLogLine(log.split('\n')[0])!;
    expect(e).toMatchObject({ prefix: 'ew-drop-in', inIface: 'eth0', src: '203.0.113.45', dst: '192.0.2.10', proto: 'tcp', sport: 51422, dport: 23, direction: 'in' });
    expect(parseLogLine(log.split('\n')[2])!.prefix).toBe('[UFW BLOCK]');
    expect(parseLogLine(log.split('\n')[3])).toMatchObject({ direction: 'forward', proto: 'udp', prefix: '(no prefix)' });
  });
  it('summarises sources and ports and replays them against the ruleset', () => {
    const s = analyzeLogs(log);
    expect(s.entries.length).toBe(4);
    expect(s.unparsed).toBe(2);
    expect(s.topSources[0]).toEqual({ key: '203.0.113.45', count: 3, ports: 3 });
    expect(s.topPorts.map((p) => p.key).sort()).toEqual(['tcp/23', 'tcp/3389', 'tcp/443', 'udp/53']);
    const web = TEMPLATES[0].build();
    expect(verdictNow(web, s.entries[0]).verdict).toBe('drop');
    expect(verdictNow(web, s.entries[2]).verdict).toBe('accept');
  });
});
