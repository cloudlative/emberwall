import { describe, expect, it } from 'vitest';
import { compileCloud, compileK8s, compilePf, compileWindows, EXTRA_TARGETS, type ExtraResult } from '../src/core/compile/extra';
import { fileText } from '../src/core/compile/types';
import { emptyProject, newNat, newRule, type Project } from '../src/core/model';
import { TEMPLATES } from '../src/core/templates';

const tpl = (id: string) => TEMPLATES.find((t) => t.id === id)!.build();
const text = (r: ExtraResult) => fileText(r.files[0]);
const k8sOpts = { namespace: 'prod', podSelector: { app: 'api', tier: 'backend' } };
const unsupported = (r: ExtraResult, ruleId: string) => r.diagnostics.filter((x) => x.kind === 'unsupported' && x.ruleId === ruleId);

function project(rules: Parameters<typeof newRule>[0][], patch: (p: Project) => void = () => {}): Project {
  const p = emptyProject('Test fw');
  p.rules = rules.map((r) => newRule(r));
  patch(p);
  return p;
}

describe('extra targets: every template', () => {
  it('lists the seven targets', () => {
    expect(EXTRA_TARGETS.map((t) => t.id)).toEqual(['pf-openbsd', 'pf-freebsd', 'windows', 'aws', 'azure', 'gcp', 'k8s']);
    for (const t of EXTRA_TARGETS) expect(t.label && t.description).toBeTruthy();
  });

  for (const t of TEMPLATES) {
    for (const target of EXTRA_TARGETS) {
      it(`${t.id} compiles for ${target.id}`, () => {
        const r = target.compile(t.build());
        expect(r.files.length).toBeGreaterThan(0);
        expect(r.diagnostics.filter((x) => x.level === 'error')).toEqual([]);
        for (const f of r.files) {
          expect(f.lines.length).toBeGreaterThan(5);
          expect(fileText(f)).not.toMatch(/undefined|\[object|NaN/);
          for (const l of f.lines) expect(l.text).not.toMatch(/[\r\n]/);
        }
      });
    }
  }
});

describe('pf', () => {
  it('web server: policies, tables, quick rules', () => {
    const t = text(compilePf(tpl('web')));
    expect(t).toContain('set skip on lo\n');
    expect(t).toContain('block drop in log all\npass out all\n');
    expect(t).toContain('table <ew_admin_networks> const { 203.0.113.0/24, 2001:db8:10::/48 }');
    expect(t).toContain('pass in quick proto tcp from <ew_admin_networks> to any port 22 keep state');
    expect(t).toContain('pass in quick proto tcp from any to any port { 80 443 } keep state');
    expect(t).toContain('pass in quick proto udp from any to any port 443 keep state');
    expect(t).toContain('pass in quick inet proto icmp all icmp-type echoreq keep state');
    expect(t).toMatch(/pass in quick inet6 proto icmp6 all icmp6-type \{ unreach toobig .* neighbradv \} keep state/);
  });

  it('uses quick on every rule except the default policies', () => {
    for (const id of ['web', 'router', 'bastion', 'database']) {
      const r = compilePf(tpl(id));
      const filter = r.files[0].lines.map((l) => l.text).filter((l) => /^(pass|block) /.test(l));
      const notQuick = filter.filter((l) => !/ quick /.test(l));
      expect(notQuick.length).toBe(2);
      expect(notQuick[0]).toMatch(/^(block drop in( log)? all|pass in all)$/);
      expect(notQuick[1]).toMatch(/^(block drop out( log)? all|pass out all)$/);
    }
  });

  it('drop, reject, log, families, port ranges, source ports, icmp types', () => {
    const p = project([
      { name: 'telnet', action: 'drop', ports: ['23'], log: true },
      { name: 'smtp', direction: 'out', action: 'reject', ports: ['25'], dst: ['198.51.100.0/24', '2001:db8::/32'] },
      { name: 'range', proto: 'tcpudp', ports: ['8000:8100', '9000'], src: ['10.1.2.3', '10.1.2.4'], srcPorts: ['1024:65535'] },
      { name: 'ping', proto: 'icmp', icmpType: 'echo-request', inIface: 'eth0' },
      { name: 'v6', family: 'ipv6', ports: ['8443'] },
    ]);
    const t = text(compilePf(p));
    expect(t).toContain('block drop in log quick proto tcp from any to any port 23');
    expect(t).toContain('block return out quick inet proto tcp from any to 198.51.100.0/24 port 25');
    expect(t).toContain('block return out quick inet6 proto tcp from any to 2001:db8::/32 port 25');
    expect(t).toContain('pass in quick inet proto tcp from { 10.1.2.3, 10.1.2.4 } port 1024:65535 to any port { 8000:8100 9000 } keep state');
    expect(t).toContain('pass in quick inet proto udp from { 10.1.2.3, 10.1.2.4 } port 1024:65535 to any port { 8000:8100 9000 } keep state');
    expect(t).toContain('if_eth0 = "eth0"');
    expect(t).toContain('pass in quick on $if_eth0 inet proto icmp from any to any icmp-type echoreq keep state');
    expect(t).toContain('pass in quick on $if_eth0 inet6 proto icmp6 from any to any icmp6-type echoreq keep state');
    expect(t).toContain('pass in quick inet6 proto tcp from any to any port 8443 keep state');
  });

  it('per-client limits use max-src-conn / max-src-conn-rate with overload', () => {
    const p = project([{ name: 'ssh', ports: ['22'], rateLimit: { rate: 6, per: 'minute', burst: 10, perSource: true }, connLimit: 3 }]);
    const r = compilePf(p);
    const t = text(r);
    expect(t).toContain('table <bruteforce> persist');
    expect(t).toContain('block drop in quick from <bruteforce> to any');
    expect(t).toContain('pass in quick proto tcp from any to any port 22 keep state (max-src-conn 3, max-src-conn-rate 6/60, overload <bruteforce> flush)');
    expect(t.indexOf('block drop in quick from <bruteforce>')).toBeLessThan(t.indexOf('pass in quick proto tcp'));
    expect(r.diagnostics.some((x) => x.kind === 'fallback' && /blocked on every port/.test(x.message))).toBe(true);
  });

  it('reports a shared rate limit it cannot express, and keeps the rule', () => {
    const p = project([{ name: 'ssh', ports: ['22'], rateLimit: { rate: 10, per: 'minute', burst: 20 } }]);
    const r = compilePf(p);
    expect(text(r)).toContain('pass in quick proto tcp from any to any port 22 keep state\n');
    expect(unsupported(r, p.rules[0].id)[0].message).toMatch(/WITHOUT the limit/);
  });

  it('leaves out and reports MAC, mark and schedule matches', () => {
    const p = project([
      { name: 'mac', ports: ['1111'], srcMac: 'aa:bb:cc:00:11:22' },
      { name: 'mark', ports: ['2222'], mark: '0x10' },
      { name: 'hours', ports: ['3333'], schedule: { days: [], from: '08:00', to: '18:00' } },
    ]);
    const r = compilePf(p);
    expect(text(r)).not.toMatch(/1111|2222|3333/);
    for (const rule of p.rules) expect(unsupported(r, rule.id).length).toBe(1);
  });

  it('NAT router on OpenBSD: nat-to / rdr-to and tagged forwarding', () => {
    const r = compilePf(tpl('router'), { flavor: 'openbsd' });
    const t = text(r);
    expect(t).toContain('match out on $if_eth0 inet from 192.168.1.0/24 to any nat-to ($if_eth0)');
    expect(t).toContain('match in on $if_eth0 inet proto tcp from any to any port 443 rdr-to 192.168.1.10 port 443');
    expect(t).toContain('table <ew_local> const { self, 255.255.255.255, 224.0.0.0/4, ff00::/8 }');
    expect(t).toContain('match in from any to <ew_local> tag EW_LOCAL');
    expect(t).toContain('pass out quick all tagged EW_FWD keep state');
    // Inbound rule: only packets for the router itself.
    expect(t).toContain('pass in quick on $if_eth1 from any to any tagged EW_LOCAL keep state');
    // Forward rule without an outbound interface.
    expect(t).toContain('pass in quick inet proto tcp from any to 192.168.1.10 port 443 ! tagged EW_LOCAL tag EW_FWD keep state');
    // Forward rule with an outbound interface: its own tag, passed out on that interface only.
    expect(t).toMatch(/pass in quick on \$if_eth1 from any to any ! tagged EW_LOCAL tag (EW_F_\w+) keep state/);
    expect(t).toMatch(/pass out quick on \$if_eth0 all tagged (EW_F_\w+) keep state\nblock drop out quick all tagged \1\n/);
    expect(t.trimEnd().endsWith('block drop in log quick all ! tagged EW_LOCAL')).toBe(true);
    expect(r.diagnostics.some((x) => x.kind === 'note' && /FreeBSD/.test(x.message))).toBe(true);
    expect(t).not.toMatch(/^(nat|rdr) on/m);
  });

  it('NAT router on FreeBSD: nat on / rdr on before the filter rules', () => {
    const t = text(compilePf(tpl('router'), { flavor: 'freebsd' }));
    expect(t).toContain('set skip on lo0\n');
    expect(t).toContain('nat on $if_eth0 inet from 192.168.1.0/24 to any -> ($if_eth0)');
    expect(t).toContain('rdr on $if_eth0 inet proto tcp from any to any port 443 -> 192.168.1.10 port 443');
    expect(t).not.toMatch(/nat-to|rdr-to/);
    expect(t.indexOf('rdr on')).toBeLessThan(t.indexOf('block drop in'));
  });

  it('skips disabled NAT rules and reports masquerade without an interface', () => {
    const p = project([], (x) => {
      x.nat = [
        newNat({ name: 'off', enabled: false, kind: 'snat', src: '10.9.0.0/24', toAddr: '192.0.2.1' }),
        newNat({ name: 'noif', kind: 'masquerade', src: '10.8.0.0/24' }),
        newNat({ name: 'snat', kind: 'snat', src: '10.7.0.0/24', toAddr: '192.0.2.7', iface: 'eth0' }),
      ];
    });
    const r = compilePf(p);
    const t = text(r);
    expect(t).not.toContain('10.9.0.0/24');
    expect(t).not.toContain('10.8.0.0/24');
    expect(unsupported(r, p.nat[1].id).length).toBe(1);
    expect(t).toContain('match out on $if_eth0 inet from 10.7.0.0/24 to any nat-to 192.0.2.7');
  });

  it('IPv6 switched off: inet only, IPv6 blocked', () => {
    const p = tpl('web');
    p.options.ipv6 = false;
    const t = text(compilePf(p));
    expect(t).toContain('block drop quick inet6 all');
    expect(t).toContain('table <ew_admin_networks> const { 203.0.113.0/24 }');
    expect(t).toContain('pass in quick inet proto tcp from any to any port { 80 443 } keep state');
    expect(t).not.toMatch(/icmp6|2001:db8/);
  });
});

describe('Windows', () => {
  it('web server: idempotent script with profile defaults and allow rules', () => {
    const t = text(compileWindows(tpl('web')));
    expect(t).toContain("Remove-NetFirewallRule -Group 'Emberwall' -ErrorAction SilentlyContinue");
    expect(t.indexOf('Remove-NetFirewallRule')).toBeLessThan(t.indexOf('New-NetFirewallRule'));
    expect(t).toContain('Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True');
    expect(t).toMatch(/New-NetFirewallRule -DisplayName 'Emberwall: SSH from admins' -Name 'Emberwall-1-1' -Group 'Emberwall' -Direction Inbound -Action Allow -Protocol TCP -LocalPort '22' -RemoteAddress '203\.0\.113\.0\/24','2001:db8:10::\/48' -Enabled True \| Out-Null/);
    expect(t).toMatch(/-DisplayName 'Emberwall: HTTP \+ HTTPS' .* -Protocol TCP -LocalPort '80','443' -Enabled True/);
    expect(t).toMatch(/-Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 /);
    expect(t).toMatch(/-Protocol ICMPv6 -IcmpType 1,2,3,4,128,133,134,135,136 /);
  });

  it('outbound rules use remote ports, ranges use a dash, tcpudp becomes two rules', () => {
    const p = project(
      [
        { name: 'dns', direction: 'out', proto: 'tcpudp', ports: ['53'], dst: ['9.9.9.9'] },
        { name: "o'range", proto: 'tcp', ports: ['8000:8100'], srcPorts: ['1024:65535'], inIface: 'Ethernet 2', dst: ['192.0.2.10'] },
        { name: 'ping6', proto: 'icmp', icmpType: 'echo-request', family: 'ipv6' },
        { name: 'v4 only', family: 'ipv4', ports: ['81'] },
      ],
      (x) => {
        x.policies.out = 'drop';
      },
    );
    const t = text(compileWindows(p));
    expect(t).toContain('-DefaultInboundAction Block -DefaultOutboundAction Block');
    expect(t).toContain("-DisplayName 'Emberwall: dns (TCP)' -Name 'Emberwall-1-1' -Group 'Emberwall' -Direction Outbound -Action Allow -Protocol TCP -RemotePort '53' -RemoteAddress '9.9.9.9' -Enabled True");
    expect(t).toContain("-DisplayName 'Emberwall: dns (UDP)' -Name 'Emberwall-1-2' -Group 'Emberwall' -Direction Outbound -Action Allow -Protocol UDP -RemotePort '53' -RemoteAddress '9.9.9.9' -Enabled True");
    expect(t).toContain("-DisplayName 'Emberwall: o''range' -Name 'Emberwall-2-1' -Group 'Emberwall' -Direction Inbound -Action Allow -Protocol TCP -LocalPort '8000-8100' -RemotePort '1024-65535' -LocalAddress '192.0.2.10' -InterfaceAlias 'Ethernet 2' -Enabled True");
    expect(t).toMatch(/'Emberwall: ping6' .* -Protocol ICMPv6 -IcmpType 128 -Enabled True/);
    expect(t).not.toMatch(/'Emberwall: ping6' .* -Protocol ICMPv4/);
    expect(t).toMatch(/'Emberwall: v4 only' .* -LocalPort '81' -RemoteAddress '0\.0\.0\.0-255\.255\.255\.255' /);
  });

  it('reject is reported as unsupported and emitted as Block', () => {
    const p = tpl('database');
    const smtp = p.rules.find((r) => r.action === 'reject')!;
    const r = compileWindows(p);
    expect(unsupported(r, smtp.id)[0].message).toMatch(/cannot reject/);
    expect(text(r)).toMatch(/'Emberwall: Block SMTP out' .* -Direction Outbound -Action Block -Protocol TCP -RemotePort '25' /);
  });

  it('reports rate limits, connection limits, schedules, MAC, marks, forward rules and NAT', () => {
    const p = project(
      [
        { name: 'rate', ports: ['1001'], rateLimit: { rate: 5, per: 'second', burst: 5 } },
        { name: 'conn', ports: ['1002'], connLimit: 4 },
        { name: 'sched', ports: ['1003'], schedule: { days: ['Mon'], from: '08:00', to: '18:00' } },
        { name: 'mac', ports: ['1004'], srcMac: 'aa:bb:cc:00:11:22' },
        { name: 'mark', ports: ['1005'], mark: '0x1' },
        { name: 'fwd', direction: 'forward', ports: ['1006'] },
      ],
      (x) => {
        x.nat = [newNat({ name: 'masq', kind: 'masquerade', iface: 'eth0' })];
      },
    );
    const r = compileWindows(p);
    const t = text(r);
    for (const rule of p.rules) expect(unsupported(r, rule.id).length, rule.name).toBeGreaterThan(0);
    expect(unsupported(r, p.nat[0].id).length).toBe(1);
    // Limits are dropped but the rule stays; unmatched conditions remove the rule.
    expect(t).toMatch(/1001/);
    expect(t).toMatch(/1002/);
    expect(t).not.toMatch(/1003|1004|1005|1006/);
  });

  it('warns that a block rule beats an earlier allow rule', () => {
    const p = project([
      { name: 'allow admin', ports: ['22'], src: ['10.0.0.5'] },
      { name: 'block ssh', action: 'drop', ports: ['22'] },
    ]);
    const r = compileWindows(p);
    expect(r.diagnostics.some((x) => x.kind === 'note' && /no rule order/.test(x.message))).toBe(true);
    expect(r.diagnostics.some((x) => x.kind === 'fallback' && x.ruleId === p.rules[1].id && /"allow admin"/.test(x.message))).toBe(true);
  });
});

describe('cloud (Terraform)', () => {
  it('AWS: one rule per CIDR and port range, allow-all egress for the accept policy', () => {
    const t = text(compileCloud(tpl('web'), 'aws'));
    expect(t).toContain('resource "aws_security_group" "emberwall" {');
    expect(t).toContain('vpc_id      = var.vpc_id');
    expect(t).toMatch(/resource "aws_vpc_security_group_ingress_rule" "ssh_from_admins_\d+" \{\n  security_group_id = aws_security_group\.emberwall\.id\n  description       = "SSH from admins"\n  ip_protocol       = "tcp"\n  from_port         = 22\n  to_port           = 22\n  cidr_ipv4         = "203\.0\.113\.0\/24"\n\}/);
    expect(t).toMatch(/ip_protocol       = "tcp"\n  from_port         = 22\n  to_port           = 22\n  cidr_ipv6         = "2001:db8:10::\/48"/);
    // HTTP + HTTPS: 2 ports x 2 families.
    expect(t.match(/"http_https_\d+"/g)!.length).toBe(4);
    expect(t).toMatch(/ip_protocol       = "udp"\n  from_port         = 443\n  to_port           = 443\n  cidr_ipv4         = "0\.0\.0\.0\/0"/);
    expect(t).toMatch(/resource "aws_vpc_security_group_egress_rule" "policy_out_ipv4" \{\n  security_group_id = aws_security_group\.emberwall\.id\n  description       = "outbound policy accept"\n  ip_protocol       = "-1"\n  cidr_ipv4         = "0\.0\.0\.0\/0"\n\}/);
    expect(t).not.toMatch(/"policy_in_/);
  });

  it('AWS: drop and reject rules are unsupported and left out', () => {
    const p = project([
      { name: 'web', ports: ['443'] },
      { name: 'no telnet', action: 'drop', ports: ['23'] },
      { name: 'range', proto: 'tcpudp', ports: ['8000:8100'], src: ['10.1.2.3'] },
      { name: 'ping', proto: 'icmp', icmpType: 'echo-request', family: 'ipv4' },
    ]);
    const r = compileCloud(p, 'aws');
    const t = text(r);
    expect(unsupported(r, p.rules[1].id)[0].message).toMatch(/only allow/);
    expect(t).not.toMatch(/telnet|= 23\b/);
    expect(t).toMatch(/ip_protocol       = "tcp"\n  from_port         = 8000\n  to_port           = 8100\n  cidr_ipv4         = "10\.1\.2\.3\/32"/);
    expect(t).toMatch(/ip_protocol       = "udp"\n  from_port         = 8000\n  to_port           = 8100/);
    expect(t).toMatch(/description       = "ping"\n  ip_protocol       = "icmp"\n  from_port         = 8\n  to_port           = -1/);
    const smtp = tpl('database');
    const reject = smtp.rules.find((x) => x.action === 'reject')!;
    expect(unsupported(compileCloud(smtp, 'aws'), reject.id).length).toBe(1);
  });

  it('Azure: priorities keep the order, Allow and Deny both work', () => {
    const p = project([
      { name: 'web', ports: ['80', '443'] },
      { name: 'no telnet', action: 'drop', ports: ['23'], src: ['10.0.0.0/8'] },
      { name: 'dns', direction: 'out', proto: 'udp', ports: ['53'], srcPorts: ['1024:65535'] },
    ], (x) => {
      x.options.allowIcmp = false;
    });
    const r = compileCloud(p, 'azure');
    const t = text(r);
    expect(t).toContain('resource "azurerm_network_security_group" "emberwall" {');
    expect(t).toContain('resource_group_name = var.resource_group_name');
    expect(t).toMatch(/name                       = "web-100"\n    description                = "web"\n    priority                   = 100\n    direction                  = "Inbound"\n    access                     = "Allow"\n    protocol                   = "Tcp"\n    source_port_range          = "\*"\n    destination_port_ranges    = \["80", "443"\]\n    source_address_prefix      = "\*"\n    destination_address_prefix = "\*"/);
    expect(t).toMatch(/priority                   = 110\n    direction                  = "Inbound"\n    access                     = "Deny"\n    protocol                   = "Tcp"\n    source_port_range          = "\*"\n    destination_port_range     = "23"\n    source_address_prefix      = "10\.0\.0\.0\/8"/);
    expect(t).toMatch(/priority                   = 120\n    direction                  = "Outbound"\n    access                     = "Allow"\n    protocol                   = "Udp"\n    source_port_range          = "1024-65535"\n    destination_port_range     = "53"/);
    expect(t).toMatch(/priority                   = 4095\n    direction                  = "Inbound"\n    access                     = "Deny"\n    protocol                   = "\*"/);
    expect(t).toMatch(/priority                   = 4096\n    direction                  = "Outbound"\n    access                     = "Allow"/);
    expect(unsupported(r, p.rules[1].id)).toEqual([]);
    const prios = [...t.matchAll(/priority\s+= (\d+)/g)].map((m) => Number(m[1]));
    expect(new Set(prios).size).toBe(prios.length);
    expect([...prios].sort((a, b) => a - b)).toEqual(prios);
  });

  it('GCP: allow and deny blocks, priorities, ranges per family, logging', () => {
    const p = project([
      { name: 'ssh', ports: ['22'], src: ['203.0.113.0/24', '2001:db8:10::/48'], log: true },
      { name: 'no telnet', action: 'drop', proto: 'tcpudp', ports: ['23', '8000:8100'] },
      { name: 'dns', direction: 'out', proto: 'udp', ports: ['53'], dst: ['9.9.9.9'] },
    ], (x) => {
      x.options.allowIcmp = false;
      x.policies.out = 'drop';
    });
    const t = text(compileCloud(p, 'gcp'));
    expect(t).toMatch(/resource "google_compute_firewall" "ssh_1" \{\n  name          = "\$\{var\.name_prefix\}-ssh-1"\n  description   = "ssh"\n  network       = var\.network\n  direction     = "INGRESS"\n  priority      = 1000\n  source_ranges = \["203\.0\.113\.0\/24"\]\n  target_tags   = var\.target_tags\n\n  allow \{\n    protocol = "tcp"\n    ports    = \["22"\]\n  \}\n\n  log_config \{\n    metadata = "INCLUDE_ALL_METADATA"\n  \}\n\}/);
    expect(t).toMatch(/priority      = 1000\n  source_ranges = \["2001:db8:10::\/48"\]/);
    expect(t).toMatch(/priority      = 1010\n  source_ranges = \["0\.0\.0\.0\/0"\]\n  target_tags   = var\.target_tags\n\n  deny \{\n    protocol = "tcp"\n    ports    = \["23", "8000-8100"\]\n  \}\n\n  deny \{\n    protocol = "udp"\n    ports    = \["23", "8000-8100"\]\n  \}/);
    expect(t).toMatch(/direction          = "EGRESS"\n  priority           = 1020\n  destination_ranges = \["9\.9\.9\.9\/32"\]/);
    expect(t).toMatch(/direction          = "EGRESS"\n  priority           = 65534\n  destination_ranges = \["0\.0\.0\.0\/0"\]\n  target_tags        = var\.target_tags\n\n  deny \{\n    protocol = "all"\n  \}/);
  });

  it('reports interfaces, forward rules, NAT, states and limits on every provider', () => {
    for (const provider of ['aws', 'azure', 'gcp'] as const) {
      const p = project(
        [
          { name: 'iface', ports: ['1001'], inIface: 'eth0' },
          { name: 'fwd', direction: 'forward', ports: ['1002'] },
          { name: 'state', ports: ['1003'], states: ['invalid'] },
          { name: 'rate', ports: ['1004'], rateLimit: { rate: 5, per: 'second', burst: 5 } },
        ],
        (x) => {
          x.nat = [newNat({ name: 'masq', kind: 'masquerade', iface: 'eth0' })];
        },
      );
      const r = compileCloud(p, provider);
      const t = text(r);
      for (const rule of p.rules) expect(unsupported(r, rule.id).length, `${provider} ${rule.name}`).toBe(1);
      expect(unsupported(r, p.nat[0].id).length).toBe(1);
      expect(t).not.toMatch(/100[123]/);
      expect(t).toMatch(/1004/);
    }
  });

  it('reports the ICMP type granularity Azure and GCP lack', () => {
    const p = project([{ name: 'ping', proto: 'icmp', icmpType: 'echo-request', family: 'ipv4' }]);
    for (const provider of ['azure', 'gcp'] as const) {
      const r = compileCloud(p, provider);
      expect(r.diagnostics.some((x) => x.kind === 'fallback' && x.ruleId === p.rules[0].id && /ICMP types/.test(x.message))).toBe(true);
    }
    expect(compileCloud(p, 'aws').diagnostics.some((x) => x.ruleId === p.rules[0].id)).toBe(false);
  });
});

describe('Kubernetes NetworkPolicy', () => {
  it('web server: ingress from ipBlocks with ports, no Egress', () => {
    const r = compileK8s(tpl('web'), k8sOpts);
    const t = text(r);
    expect(t).toContain('apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: emberwall-web-server\n  namespace: "prod"\n');
    expect(t).toContain('  podSelector:\n    matchLabels:\n      "app": "api"\n      "tier": "backend"\n  policyTypes:\n    - Ingress\n  ingress:\n');
    expect(t).toContain(
      '    - from:\n        - ipBlock:\n            cidr: "203.0.113.0/24"\n        - ipBlock:\n            cidr: "2001:db8:10::/48"\n      ports:\n        - protocol: TCP\n          port: 22\n',
    );
    expect(t).toContain('    - ports:\n        - protocol: TCP\n          port: 80\n        - protocol: TCP\n          port: 443\n');
    expect(t).toContain('    - ports:\n        - protocol: UDP\n          port: 443\n');
    expect(t).not.toMatch(/Egress|egress:/);
    expect(r.files[0].lang).toBe('yaml');
  });

  it('adds Egress when the outbound policy is drop or outbound rules exist', () => {
    const bastion = text(compileK8s(tpl('bastion'), k8sOpts));
    expect(bastion).toContain('  policyTypes:\n    - Ingress\n    - Egress\n');
    expect(bastion).toContain('  egress:\n    # SSH to internal\n    - to:\n        - ipBlock:\n            cidr: "10.0.0.0/8"\n      ports:\n        - protocol: TCP\n          port: 22\n');
    expect(bastion).toContain('    - ports:\n        - protocol: TCP\n          port: 53\n        - protocol: UDP\n          port: 53\n');

    const open = project([{ name: 'dns', direction: 'out', proto: 'udp', ports: ['53'] }]);
    const t = text(compileK8s(open, k8sOpts));
    expect(t).toContain('    - Egress\n');
    // Outbound policy is accept: the rule must not turn into "only DNS may leave".
    expect(t).toMatch(/  egress:\n    # dns\n    - ports:\n        - protocol: UDP\n          port: 53\n    # Outbound policy "accept": allow everything out\.\n    - \{\}\n/);

    const closed = project([], (x) => {
      x.policies.out = 'drop';
    });
    expect(text(compileK8s(closed, k8sOpts))).toMatch(/  ingress: \[\]\n(  #.*\n)?  egress: \[\]\n/);
  });

  it('port ranges use endPort, single addresses become CIDRs', () => {
    const p = project([{ name: 'range', proto: 'tcp', ports: ['8000:8100'], src: ['10.30.0.5', 'fd00::1', '10.1.2.3/24'] }]);
    const t = text(compileK8s(p, k8sOpts));
    expect(t).toContain('          port: 8000\n          endPort: 8100\n');
    expect(t).toContain('cidr: "10.30.0.5/32"');
    expect(t).toContain('cidr: "fd00::1/128"');
    expect(t).toContain('cidr: "10.1.2.0/24"');
  });

  it('drop and reject rules, ICMP, interfaces, logging and limits are reported', () => {
    const p = project([
      { name: 'drop', action: 'drop', ports: ['1001'] },
      { name: 'reject', direction: 'out', action: 'reject', ports: ['1002'] },
      { name: 'ping', proto: 'icmp' },
      { name: 'iface', ports: ['1003'], inIface: 'eth0' },
      { name: 'logged', ports: ['1004'], log: true },
      { name: 'limited', ports: ['1005'], connLimit: 5, rateLimit: { rate: 1, per: 'second', burst: 1 } },
    ]);
    const r = compileK8s(p, k8sOpts);
    const t = text(r);
    expect(unsupported(r, p.rules[0].id)[0].message).toMatch(/only allow/);
    for (const rule of p.rules) expect(unsupported(r, rule.id).length, rule.name).toBeGreaterThan(0);
    expect(unsupported(r, p.rules[5].id).length).toBe(2);
    expect(t).not.toMatch(/100[123]/);
    expect(t).toMatch(/port: 1004/);
    expect(t).toMatch(/port: 1005/);
    expect(r.diagnostics.some((x) => x.kind === 'note' && /no rule order/.test(x.message))).toBe(true);
  });
});

describe('rule ids on output lines', () => {
  const rules: Parameters<typeof newRule>[0][] = [
    { name: 'alpha', ports: ['1111'], src: ['@grp'], inIface: 'eth7', log: true, connLimit: 9 },
    { name: 'bravo', proto: 'tcpudp', ports: ['2222', '2300:2400'], src: ['10.1.0.0/16', '2001:db8:1::/48'] },
    { name: 'charlie', direction: 'out', proto: 'udp', ports: ['3333'], dst: ['192.0.2.33'] },
    { name: 'delta', action: 'drop', ports: ['4444'] },
    { name: 'echo', direction: 'out', action: 'reject', ports: ['5555'] },
    { name: 'foxtrot', direction: 'forward', ports: ['6666'], inIface: 'eth7', outIface: 'eth8' },
    { name: 'golf', proto: 'icmp', icmpType: 'echo-request' },
    { name: 'hotel', enabled: false, ports: ['7777'] },
  ];
  const build = (withRules: boolean) =>
    project(withRules ? rules : [], (x) => {
      x.options.forwarding = true;
      x.addressGroups = [{ id: 'grp', name: 'Group one', members: ['198.51.100.0/24', '2001:db8:99::/48'] }];
      if (withRules) {
        x.nat = [
          newNat({ name: 'masq', kind: 'masquerade', src: '10.88.0.0/24', iface: 'eth8' }),
          newNat({ name: 'dnat', kind: 'dnat', proto: 'tcp', port: '8088', toAddr: '10.88.0.10', toPort: '80', iface: 'eth8' }),
          newNat({ name: 'off', enabled: false, kind: 'snat', src: '10.99.0.0/24', toAddr: '192.0.2.99' }),
        ];
      }
    });
  // Markers that can only come from one rule: its port, or its NAT network.
  const markers: [RegExp, string][] = [
    [/\b1111\b/, 'alpha'], [/\b2222\b|\b2300\b/, 'bravo'], [/\b3333\b/, 'charlie'], [/\b4444\b/, 'delta'],
    [/\b5555\b/, 'echo'], [/\b6666\b/, 'foxtrot'], [/10\.88\.0\.0\/24/, 'masq'], [/\b8088\b/, 'dnat'],
  ];
  // YAML that holds the rule entries but belongs to no single rule: the list keys, the Egress
  // policy type, and the allow-all entry that stands for an "accept" policy.
  const structural = /^\s*(ingress:|egress:|- Egress|- \{\})$/;

  for (const target of EXTRA_TARGETS) {
    it(`${target.id}: every line that comes from a rule carries its id`, () => {
      const p = build(true);
      const byName = new Map([...p.rules, ...p.nat].map((x) => [x.name, x.id]));
      const ids = new Set(byName.values());
      const base = new Set(target.compile(build(false)).files.flatMap((f) => f.lines.map((l) => l.text)));
      const lines = target.compile(p).files.flatMap((f) => f.lines);

      // 1. Whatever the rules added to the output (compared with the same project without rules) is attributed.
      const added = lines.filter((l) => l.text.trim() !== '' && !l.text.trim().startsWith('#') && !base.has(l.text) && !structural.test(l.text));
      expect(added.length).toBeGreaterThan(0);
      expect(added.filter((l) => !l.ruleId).map((l) => l.text)).toEqual([]);
      // 2. Ids only ever name enabled rules of the project.
      const off = new Set([byName.get('hotel'), byName.get('off')]);
      for (const l of lines) if (l.ruleId) expect(ids.has(l.ruleId) && !off.has(l.ruleId), l.text).toBe(true);
      // 3. A line showing a rule's unique marker carries exactly that rule's id.
      for (const [re, name] of markers) {
        for (const l of lines.filter((x) => re.test(x.text) && !x.text.trim().startsWith('#'))) expect(l.ruleId, l.text).toBe(byName.get(name));
      }
      // 4. Disabled rules leave no trace.
      expect(lines.some((l) => /7777|10\.99\.0\.0/.test(l.text))).toBe(false);
    });
  }

  it('each backend attributes the rules it can express', () => {
    const p = build(true);
    const id = (name: string) => [...p.rules, ...p.nat].find((x) => x.name === name)!.id;
    const has = (r: ExtraResult, name: string) => r.files[0].lines.some((l) => l.ruleId === id(name) && !l.text.trim().startsWith('#') && l.text.trim() !== '');
    const pf = compilePf(p);
    for (const n of ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'masq', 'dnat']) expect(has(pf, n), `pf ${n}`).toBe(true);
    const win = compileWindows(p);
    for (const n of ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'golf']) expect(has(win, n), `windows ${n}`).toBe(true);
    for (const n of ['foxtrot', 'masq', 'dnat']) expect(has(win, n), `windows ${n}`).toBe(false);
    const aws = compileCloud(p, 'aws');
    for (const n of ['bravo', 'charlie', 'golf']) expect(has(aws, n), `aws ${n}`).toBe(true);
    for (const n of ['alpha', 'delta', 'echo', 'foxtrot', 'masq']) expect(has(aws, n), `aws ${n}`).toBe(false);
    for (const provider of ['azure', 'gcp'] as const) {
      const r = compileCloud(p, provider);
      for (const n of ['bravo', 'charlie', 'delta', 'echo', 'golf']) expect(has(r, n), `${provider} ${n}`).toBe(true);
    }
    const k8s = compileK8s(p, k8sOpts);
    for (const n of ['bravo', 'charlie']) expect(has(k8s, n), `k8s ${n}`).toBe(true);
    for (const n of ['alpha', 'delta', 'echo', 'foxtrot', 'golf']) expect(has(k8s, n), `k8s ${n}`).toBe(false);
  });
});
