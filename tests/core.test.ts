import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { diffLines, diffStats } from '../src/core/diff';
import { importIptablesSave } from '../src/core/import/iptablesSave';
import { grade, lint, score } from '../src/core/lint';
import { coerceProject, emptyProject, newNat, newRule } from '../src/core/model';
import { addrInList, cidrContains, parseCidr, parsePort, portsCover } from '../src/core/net';
import { simulate } from '../src/core/simulate';
import { capsFor, compareVersions, DISTROS, resolveTarget, TOOLS, VERSIONS, type Tool } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

const target = (tool: Tool, version: string) => resolveTarget({ distro: 'custom', tool, version });
const text = (tool: Tool, version: string, p = TEMPLATES[0].build(), file = 0) => fileText(compile(p, target(tool, version)).files[file]);

describe('net', () => {
  it('parses and compares addresses', () => {
    expect(parseCidr('10.0.0.0/8')?.family).toBe('ipv4');
    expect(parseCidr('2001:db8::/32')?.family).toBe('ipv6');
    expect(parseCidr('::ffff:1.2.3.4')?.family).toBe('ipv6');
    expect(parseCidr('300.1.1.1')).toBeNull();
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('1::2::3')).toBeNull();
    expect(cidrContains(parseCidr('10.0.0.0/8')!, parseCidr('10.2.3.4')!)).toBe(true);
    expect(cidrContains(parseCidr('10.0.0.0/8')!, parseCidr('11.2.3.4')!)).toBe(false);
    expect(addrInList('2001:db8:10::5', ['2001:db8:10::/48'])).toBe(true);
    expect(addrInList('2001:db8:11::5', ['2001:db8:10::/48'])).toBe(false);
  });
  it('parses ports', () => {
    expect(parsePort('8000:8100')).toEqual({ from: 8000, to: 8100 });
    expect(parsePort('8000-8100')).toEqual({ from: 8000, to: 8100 });
    expect(parsePort('0')).toBeNull();
    expect(parsePort('70000')).toBeNull();
    expect(portsCover(['1:1024'], ['22', '80'])).toBe(true);
    expect(portsCover(['22'], ['22', '80'])).toBe(false);
  });
});

describe('targets', () => {
  it('compares versions numerically', () => {
    expect(compareVersions('1.8.10', '1.8.9')).toBe(1);
    expect(compareVersions('0.36', '0.36.1')).toBe(-1);
    expect(compareVersions('1.0.7', '1.0.7')).toBe(0);
  });
  it('derives capabilities from versions', () => {
    expect(capsFor('nftables', '0.9.0')).toMatchObject({ inetNat: false, thExpr: false, destroy: false });
    expect(capsFor('nftables', '1.0.6').destroy).toBe(false);
    expect(capsFor('nftables', '1.0.9')).toMatchObject({ inetNat: true, thExpr: true, objectComments: true, destroy: true });
    expect(capsFor('iptables', '1.6.1')).toMatchObject({ randomFullySnat: true, randomFully: false, restoreWait: false });
    expect(capsFor('firewalld', '0.8.2')).toMatchObject({ richPriority: true, policies: false });
  });
  it('honours kernel-based overrides per distro', () => {
    expect(resolveTarget({ distro: 'rhel-8', tool: 'nftables', version: '' }).caps.inetNat).toBe(false);
    expect(resolveTarget({ distro: 'rhel-9', tool: 'nftables', version: '' }).caps.destroy).toBe(false);
  });
  it('falls back to the distro default when a tool is not packaged', () => {
    expect(resolveTarget({ distro: 'rhel-9', tool: 'ufw', version: '' }).tool).toBe('firewalld');
  });
});

describe('compile: every template on every target', () => {
  for (const t of TEMPLATES) {
    it(t.id, () => {
      for (const tool of TOOLS) {
        for (const version of VERSIONS[tool]) {
          const res = compile(t.build(), target(tool, version));
          expect(res.diagnostics.filter((d) => d.level === 'error'), `${tool} ${version}`).toEqual([]);
          for (const f of res.files) expect(f.lines.length).toBeGreaterThan(3);
        }
      }
      for (const d of DISTROS) {
        for (const tool of Object.keys(d.tools) as Tool[]) compile(t.build(), resolveTarget({ distro: d.id, tool, version: '' }));
      }
    });
  }
});

describe('compile: version-specific output', () => {
  const router = TEMPLATES.find((t) => t.id === 'router')!.build();
  const wg = TEMPLATES.find((t) => t.id === 'wireguard')!.build();
  const bastion = TEMPLATES.find((t) => t.id === 'bastion')!.build();

  it('nftables: inet NAT vs separate tables', () => {
    expect(text('nftables', '1.0.9', router)).toContain('dnat ip to 192.168.1.10:443');
    const old = text('nftables', '0.9.0', router);
    expect(old).toContain('table ip emberwall_nat {');
    expect(old).toContain('dnat to 192.168.1.10:443');
    expect(old).toContain('priority -100;');
  });
  it('nftables: th dport vs one rule per protocol', () => {
    expect(text('nftables', '1.0.9', bastion)).toContain('meta l4proto { tcp, udp } th dport 53');
    const old = text('nftables', '0.9.0', bastion);
    expect(old).toContain('tcp dport 53');
    expect(old).toContain('udp dport 53');
    expect(old).not.toContain('th dport');
  });
  it('nftables: destroy vs add+delete', () => {
    expect(text('nftables', '1.0.9')).toContain('destroy table inet emberwall');
    expect(text('nftables', '1.0.6')).toContain('add table inet emberwall\ndelete table inet emberwall');
  });
  it('nftables: address groups become named sets', () => {
    const out = text('nftables', '1.0.9');
    expect(out).toContain('set admin_networks_v4 {');
    expect(out).toContain('ip saddr @admin_networks_v4 tcp dport 22');
    expect(out).toContain('ip6 saddr @admin_networks_v6 tcp dport 22');
  });
  it('iptables: --random-fully and restore --wait', () => {
    expect(text('iptables', '1.8.10', wg)).toContain('-j MASQUERADE --random-fully');
    expect(text('iptables', '1.6.1', wg)).toContain('-j MASQUERADE --random');
    expect(text('iptables', '1.6.1', wg)).not.toContain('--random-fully');
    expect(text('iptables', '1.8.10', wg, 2)).toContain('iptables-restore -w 5 <');
    expect(text('iptables', '1.4.21', wg, 2)).toContain('iptables-restore < "$DIR/rules.v4"');
  });
  it('iptables: splits families and uses multiport', () => {
    const v4 = text('iptables', '1.8.10');
    const v6 = text('iptables', '1.8.10', undefined, 1);
    expect(v4).toContain('-s 203.0.113.0/24 -p tcp --dport 22');
    expect(v4).not.toContain('2001:db8');
    expect(v6).toContain('-s 2001:db8:10::/48 -p tcp --dport 22');
    expect(v4).toContain('-m multiport --dports 80,443');
    expect(v6).toContain('--icmpv6-type neighbour-solicitation');
  });
  it('ufw: comments and route rules depend on the version', () => {
    expect(text('ufw', '0.36.2')).toContain("comment 'HTTP + HTTPS'");
    expect(text('ufw', '0.33')).not.toContain('comment ');
    expect(text('ufw', '0.36.2', wg)).toContain('ufw route allow in on wg0');
    const old = compile(wg, target('ufw', '0.33'));
    expect(fileText(old.files[0])).not.toContain('ufw route');
    expect(fileText(old.files.find((f) => f.name === 'before.rules.fragment')!)).toContain('-A ufw-before-forward -i wg0');
  });
  it('ufw: TCP+UDP on one port needs no proto keyword', () => {
    expect(text('ufw', '0.36.2', bastion)).toContain("ufw allow out from any to any port 53 comment 'DNS out'");
  });
  it('firewalld: policies vs direct interface', () => {
    expect(text('firewalld', '1.3.3', bastion)).toContain('--new-policy=ew-out');
    const old = text('firewalld', '0.8.2', bastion);
    expect(old).not.toContain('--new-policy');
    expect(old).toContain('--direct --add-rule ipv4 filter OUTPUT');
  });
  it('firewalld: rich rule priorities keep order when actions are mixed', () => {
    const p = emptyProject();
    p.rules = [
      newRule({ name: 'block bad', action: 'drop', proto: 'any', src: ['198.51.100.7'] }),
      newRule({ name: 'web', proto: 'tcp', ports: ['443'] }),
    ];
    const withPrio = text('firewalld', '1.3.3', p);
    expect(withPrio).toContain('rule priority="-1000" family="ipv4" source address="198.51.100.7" drop');
    expect(withPrio).toContain('rule priority="-990" port port="443" protocol="tcp" accept');
    const res = compile(p, target('firewalld', '0.6.3'));
    expect(fileText(res.files[0])).not.toContain('priority=');
    expect(res.diagnostics.some((d) => d.kind === 'fallback' && d.message.includes('priorities'))).toBe(true);
  });
  it('firewalld: simple accepts use --add-port and zone XML mirrors the script', () => {
    const res = compile(TEMPLATES[0].build(), target('firewalld', '2.1.1'));
    expect(fileText(res.files[0])).toContain('--add-port=443/tcp');
    expect(fileText(res.files[1])).toContain('<port port="443" protocol="tcp"/>');
    expect(fileText(res.files[1])).toContain('<source address="203.0.113.0/24"/>');
  });
  it('maps output lines back to rules', () => {
    const p = TEMPLATES[0].build();
    const res = compile(p, target('nftables', '1.0.9'));
    const ids = new Set(res.files[0].lines.map((l) => l.ruleId).filter(Boolean));
    expect(ids).toEqual(new Set(p.rules.map((r) => r.id)));
  });
  it('reports invalid input instead of emitting it', () => {
    const p = emptyProject();
    p.rules = [newRule({ name: 'bad', src: ['not-an-ip'], ports: ['99999'] })];
    p.nat = [newNat({ name: 'fwd', kind: 'dnat', port: '80' })];
    const res = compile(p, target('iptables', '1.8.10'));
    expect(res.diagnostics.filter((d) => d.level === 'error').length).toBeGreaterThanOrEqual(3);
    expect(fileText(res.files[0])).not.toContain('not-an-ip');
  });
  it('blocks IPv6 when it is switched off', () => {
    const p = TEMPLATES[0].build();
    p.options.ipv6 = false;
    expect(text('iptables', '1.8.10', p, 1)).toContain(':INPUT DROP');
    expect(text('iptables', '1.8.10', p, 1)).not.toContain('--dport');
    expect(text('nftables', '1.0.9', p)).toContain('meta nfproto ipv6 drop');
  });
});

describe('simulate', () => {
  const web = TEMPLATES[0].build();
  const pkt = { direction: 'in' as const, src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp' as const, port: 443, state: 'new' as const, inIface: 'eth0' };
  it('accepts what a rule allows and names the rule', () => {
    const r = simulate(web, pkt);
    expect(r.verdict).toBe('accept');
    expect(r.decidedBy).toContain('HTTP + HTTPS');
  });
  it('drops by policy and honours source groups', () => {
    expect(simulate(web, { ...pkt, port: 22 }).verdict).toBe('drop');
    expect(simulate(web, { ...pkt, port: 22, src: '203.0.113.9' }).verdict).toBe('accept');
    expect(simulate(web, { ...pkt, port: 22, src: '2001:db8:10::9', dst: '2001:db8::1' }).verdict).toBe('accept');
  });
  it('handles state, loopback and ICMP preamble', () => {
    expect(simulate(web, { ...pkt, port: 5555, state: 'established' }).decidedBy).toContain('established');
    expect(simulate(web, { ...pkt, port: 5555, state: 'invalid' }).verdict).toBe('drop');
    expect(simulate(web, { ...pkt, port: 5555, inIface: 'lo' }).verdict).toBe('accept');
    expect(simulate(web, { ...pkt, proto: 'icmp', port: undefined }).verdict).toBe('accept');
  });
  it('follows a port forward into the forward chain', () => {
    const router = TEMPLATES.find((t) => t.id === 'router')!.build();
    const r = simulate(router, { ...pkt, dst: '198.51.100.1' });
    expect(r.verdict).toBe('accept');
    expect(r.steps[0].label).toContain('NAT');
    expect(r.decidedBy).toContain('Forward: web server');
  });
  it('rejects malformed packets', () => {
    expect(simulate(web, { ...pkt, src: 'nope' }).error).toBeTruthy();
  });
});

describe('lint', () => {
  it('scores the stock templates well', () => {
    for (const t of TEMPLATES) expect(score(lint(t.build())), t.id).toBeGreaterThanOrEqual(60);
  });
  it('flags an open firewall and fixes it', () => {
    const p = emptyProject();
    p.policies.in = 'accept';
    p.rules = [newRule({ name: 'all', proto: 'any' }), newRule({ name: 'redis', proto: 'tcp', ports: ['6379'] })];
    const findings = lint(p);
    expect(findings.map((f) => f.id)).toEqual(expect.arrayContaining(['policy-in-accept', `any-any:${p.rules[0].id}`]));
    expect(grade(score(findings))).toBe('F');
    const fixed = findings.find((f) => f.id === 'policy-in-accept')!.fix!(p);
    expect(fixed.policies.in).toBe('drop');
  });
  it('finds exposed services, shadowed rules and lock-out risk', () => {
    const p = emptyProject();
    p.rules = [
      newRule({ name: 'net', proto: 'tcp', src: ['10.0.0.0/8'], ports: ['80:1024'] }),
      newRule({ name: 'dup', proto: 'tcp', src: ['10.1.0.0/16'], ports: ['80'] }),
      newRule({ name: 'never', action: 'drop', proto: 'tcp', src: ['10.2.0.0/16'], ports: ['443'] }),
      newRule({ name: 'pg', proto: 'tcp', ports: ['5432'] }),
    ];
    const ids = lint(p).map((f) => f.id);
    expect(ids).toContain(`shadow:${p.rules[1].id}`);
    expect(ids).toContain(`shadow:${p.rules[2].id}`);
    expect(ids).toContain(`exposed:${p.rules[3].id}:5432`);
    expect(ids).toContain('ssh-lockout');
  });
  it('wants a forward rule for a port forward', () => {
    const p = emptyProject();
    p.nat = [newNat({ name: 'web', kind: 'dnat', proto: 'tcp', port: '80', toAddr: '10.0.0.5', toPort: '8080' })];
    const f = lint(p).find((x) => x.id.startsWith('dnat-noforward'))!;
    expect(f).toBeTruthy();
    expect(lint(f.fix!(p)).some((x) => x.id.startsWith('dnat-noforward'))).toBe(false);
  });
});

describe('import iptables-save', () => {
  it('round-trips every template through the iptables compiler', () => {
    for (const t of TEMPLATES) {
      const p = t.build();
      const res = compile(p, target('iptables', '1.8.10'));
      const back = importIptablesSave(fileText(res.files[0]) + fileText(res.files[1])).project;
      expect(back.policies, t.id).toEqual(p.policies);
      expect(back.options.allowEstablished && back.options.allowLoopback && back.options.dropInvalid && back.options.allowIcmp).toBe(true);
      expect(back.nat.length, t.id).toBe(p.nat.length);
      // Same behaviour: recompiling the import gives the same rules (comments aside).
      const again = compile(back, target('iptables', '1.8.10'));
      const strip = (s: string) => s.replace(/^#.*\n/gm, '');
      expect(strip(fileText(again.files[0])), t.id).toBe(strip(fileText(res.files[0])));
      expect(strip(fileText(again.files[1])), t.id).toBe(strip(fileText(res.files[1])));
    }
  });
  it('reports what it cannot import', () => {
    const r = importIptablesSave('*filter\n:INPUT DROP [0:0]\n:DOCKER - [0:0]\n-A INPUT ! -s 10.0.0.0/8 -j DROP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -j DOCKER\nCOMMIT\n');
    expect(r.project.rules.length).toBe(1);
    expect(r.project.rules[0].ports).toEqual(['22']);
    expect(r.skipped.length).toBe(3);
  });
});

describe('misc', () => {
  it('diffs text', () => {
    const d = diffLines('a\nb\nc', 'a\nx\nc\nd');
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
  });
  it('coerces loose JSON into a project', () => {
    const p = coerceProject({ name: 'x', rules: [{ name: 'r', ports: [22] }] });
    expect(p.rules[0].ports).toEqual(['22']);
    expect(p.policies.in).toBe('drop');
    expect(() => coerceProject({})).toThrow();
  });
});
