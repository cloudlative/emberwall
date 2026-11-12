// Audit engine: finds risky, broken or redundant configuration and offers fixes.
import { newRule, type Project, type Rule } from './model';
import { addrsCover, parsePort, portInList, WELL_KNOWN_PORTS } from './net';
import { resolveAll, type ResolvedRule } from './resolve';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  ruleId?: string;
  fixLabel?: string;
  fix?: (p: Project) => Project;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Ports that should not face the whole internet, with the severity of doing so. */
const SENSITIVE: Record<number, Severity> = {
  23: 'critical', 2375: 'critical', 6379: 'critical', 11211: 'critical', 27017: 'critical', 9200: 'critical',
  3306: 'high', 5432: 'high', 1433: 'high', 1521: 'high', 3389: 'high', 5900: 'high', 2379: 'high', 10250: 'high',
  5601: 'medium', 9090: 'medium', 9100: 'medium', 2049: 'high',
};

const patchRule = (id: string, patch: Partial<Rule>) => (p: Project): Project => ({
  ...p,
  rules: p.rules.map((r) => (r.id === id ? { ...r, ...patch } : r)),
});
const removeRule = (id: string) => (p: Project): Project => ({ ...p, rules: p.rules.filter((r) => r.id !== id) });

const isAnySrc = (rr: ResolvedRule) => (!rr.v4 || rr.v4.src.length === 0) && (!rr.v6 || rr.v6.src.length === 0) && rr.rule.src.length === 0;

function protoCovers(a: Rule['proto'], b: Rule['proto']): boolean {
  if (a === 'any' || a === b) return true;
  return a === 'tcpudp' && (b === 'tcp' || b === 'udp');
}

/** True when every packet matched by `b` is also matched by `a`. */
export function covers(a: ResolvedRule, b: ResolvedRule): boolean {
  const ra = a.rule;
  const rb = b.rule;
  if (ra.direction !== rb.direction) return false;
  if (!protoCovers(ra.proto, rb.proto)) return false;
  if (ra.inIface && ra.inIface !== rb.inIface) return false;
  if (ra.outIface && ra.outIface !== rb.outIface) return false;
  if (ra.states && ra.states.length > 0 && !(rb.states && rb.states.every((s) => ra.states!.includes(s)) && rb.states.length > 0)) return false;
  if (ra.proto === 'icmp' && ra.icmpType && ra.icmpType !== rb.icmpType) return false;
  if (ra.rateLimit && ra.action === 'accept') return false; // a limited rule lets excess traffic through
  for (const fam of ['v4', 'v6'] as const) {
    const vb = b[fam];
    if (!vb) continue;
    const va = a[fam];
    if (!va) return false;
    if (!addrsCover(va.src, vb.src) || !addrsCover(va.dst, vb.dst)) return false;
  }
  const portsA = ra.proto === 'any' ? [] : a.ports;
  return portsA.length === 0 || (b.ports.length > 0 && b.ports.every((p) => {
    const r = parsePort(p);
    return !!r && portsA.some((o) => {
      const or = parsePort(o);
      return !!or && or.from <= r.from && or.to >= r.to;
    });
  }));
}

export function lint(p: Project): Finding[] {
  const f: Finding[] = [];
  const rules = resolveAll(p);
  const inbound = rules.filter((r) => r.rule.direction === 'in');
  const opt = p.options;

  for (const rr of rules) {
    for (const m of rr.problems) {
      f.push({ id: `invalid:${rr.rule.id}:${m}`, severity: 'high', title: `Rule "${rr.rule.name}" has a problem`, detail: m, ruleId: rr.rule.id });
    }
  }

  if (p.policies.in === 'accept') {
    f.push({
      id: 'policy-in-accept',
      severity: 'critical',
      title: 'Inbound traffic is accepted by default',
      detail: 'Anything not explicitly blocked reaches this host. A firewall should drop by default and allow what is needed.',
      fixLabel: 'Set inbound policy to drop',
      fix: (x) => ({ ...x, policies: { ...x.policies, in: 'drop' } }),
    });
  }
  if (p.policies.forward === 'accept') {
    f.push({
      id: 'policy-forward-accept',
      severity: opt.forwarding ? 'high' : 'medium',
      title: 'Forwarded traffic is accepted by default',
      detail: 'If forwarding is on, this host routes anything between its networks.',
      fixLabel: 'Set forward policy to drop',
      fix: (x) => ({ ...x, policies: { ...x.policies, forward: 'drop' } }),
    });
  }
  if (!opt.allowEstablished) {
    f.push({
      id: 'no-established',
      severity: 'high',
      title: 'Replies to allowed connections are not accepted',
      detail: 'Without the established/related rule, return traffic for outbound connections is dropped and most things stop working.',
      fixLabel: 'Allow established connections',
      fix: (x) => ({ ...x, options: { ...x.options, allowEstablished: true } }),
    });
  }
  if (!opt.allowLoopback) {
    f.push({
      id: 'no-loopback',
      severity: 'medium',
      title: 'Loopback traffic is not accepted',
      detail: 'Many local services talk to each other over 127.0.0.1 / ::1.',
      fixLabel: 'Allow loopback',
      fix: (x) => ({ ...x, options: { ...x.options, allowLoopback: true } }),
    });
  }
  if (!opt.dropInvalid) {
    f.push({
      id: 'no-invalid',
      severity: 'low',
      title: 'Invalid packets are not dropped',
      detail: 'Packets that match no known connection are usually scans or broken traffic.',
      fixLabel: 'Drop invalid packets',
      fix: (x) => ({ ...x, options: { ...x.options, dropInvalid: true } }),
    });
  }
  if (!opt.ipv6) {
    f.push({ id: 'ipv6-off', severity: 'info', title: 'IPv6 is switched off', detail: 'The generated rules block all IPv6 traffic except loopback. Turn IPv6 on if the host has IPv6 connectivity you rely on.' });
  }
  if (!opt.logDropped && p.policies.in === 'drop') {
    f.push({
      id: 'no-log',
      severity: 'low',
      title: 'Dropped packets are not logged',
      detail: 'A rate-limited log of dropped packets makes troubleshooting and intrusion review much easier.',
      fixLabel: 'Log dropped packets',
      fix: (x) => ({ ...x, options: { ...x.options, logDropped: true } }),
    });
  }

  for (const rr of inbound) {
    const r = rr.rule;
    // Rules pinned to an interface (LAN side, VPN) are not internet-facing.
    if (r.action !== 'accept' || !isAnySrc(rr) || r.inIface) continue;
    const open = r.proto === 'any' || ((r.proto === 'tcp' || r.proto === 'udp' || r.proto === 'tcpudp') && rr.ports.length === 0);
    if (open) {
      f.push({
        id: `any-any:${r.id}`,
        severity: 'critical',
        title: `"${r.name}" accepts everything from anywhere`,
        detail: 'This rule makes the firewall transparent for inbound traffic.',
        ruleId: r.id,
        fixLabel: 'Disable rule',
        fix: patchRule(r.id, { enabled: false }),
      });
      continue;
    }
    for (const [portText, sev] of Object.entries(SENSITIVE)) {
      const port = Number(portText);
      if (r.proto !== 'any' && !portInList(port, rr.ports)) continue;
      f.push({
        id: `exposed:${r.id}:${port}`,
        severity: sev,
        title: `${WELL_KNOWN_PORTS[port] ?? `Port ${port}`} (${port}) is open to the whole internet`,
        detail: `"${r.name}" accepts this port from any source. Restrict the source to the networks that need it.`,
        ruleId: r.id,
      });
    }
    if (r.proto !== 'any' && portInList(22, rr.ports) && !r.rateLimit) {
      f.push({
        id: `ssh-nolimit:${r.id}`,
        severity: 'low',
        title: 'SSH is open to any source without a rate limit',
        detail: 'A rate limit slows brute-force attempts. Restricting the source addresses is better still.',
        ruleId: r.id,
        fixLabel: 'Add rate limit (10/min)',
        fix: patchRule(r.id, { rateLimit: { rate: 10, per: 'minute', burst: 20 } }),
      });
    }
  }

  // Shadowed and redundant rules
  for (let j = 0; j < rules.length; j += 1) {
    for (let i = 0; i < j; i += 1) {
      if (!covers(rules[i], rules[j])) continue;
      const a = rules[i].rule;
      const b = rules[j].rule;
      const same = a.action === b.action;
      f.push({
        id: `shadow:${b.id}`,
        severity: same ? 'low' : 'medium',
        title: same ? `"${b.name}" is redundant` : `"${b.name}" can never match`,
        detail: same
          ? `"${a.name}" above already ${a.action}s everything this rule matches.`
          : `"${a.name}" above ${a.action}s the same traffic first, so this ${b.action} rule has no effect. Move it up or narrow the earlier rule.`,
        ruleId: b.id,
        fixLabel: same ? 'Remove rule' : undefined,
        fix: same ? removeRule(b.id) : undefined,
      });
      break;
    }
  }

  // Lock-out risk
  if (p.policies.in === 'drop') {
    const ssh = inbound.some((rr) => rr.rule.action === 'accept' && (rr.rule.proto === 'any' || (rr.rule.proto !== 'icmp' && rr.rule.proto !== 'udp' && (rr.ports.length === 0 || portInList(22, rr.ports)))));
    if (!ssh) {
      f.push({
        id: 'ssh-lockout',
        severity: 'medium',
        title: 'No rule allows SSH (port 22)',
        detail: 'Applying this over SSH would cut your session. Ignore this if the host is managed from a console or uses another port.',
        fixLabel: 'Add SSH rule',
        fix: (x) => ({ ...x, rules: [newRule({ name: 'SSH', proto: 'tcp', ports: ['22'], rateLimit: { rate: 10, per: 'minute', burst: 20 } }), ...x.rules] }),
      });
    }
  }

  if (p.policies.out === 'drop') {
    const out = rules.filter((r) => r.rule.direction === 'out' && r.rule.action === 'accept');
    const dns = out.some((rr) => rr.rule.proto === 'any' || (rr.rule.proto !== 'icmp' && rr.rule.proto !== 'tcp' && (rr.ports.length === 0 || portInList(53, rr.ports))));
    if (!dns) {
      f.push({
        id: 'out-no-dns',
        severity: 'medium',
        title: 'Outbound DNS is blocked',
        detail: 'The outbound policy is drop and no rule allows port 53, so name resolution will fail.',
        fixLabel: 'Allow outbound DNS',
        fix: (x) => ({ ...x, rules: [...x.rules, newRule({ name: 'DNS out', direction: 'out', proto: 'tcpudp', ports: ['53'] })] }),
      });
    }
  }

  // Port forwards need a matching forward rule
  for (const n of p.nat.filter((x) => x.enabled && x.kind === 'dnat' && x.toAddr)) {
    if (p.policies.forward === 'accept') break;
    const port = n.toPort ?? n.port;
    const ok = rules.some((rr) => {
      const r = rr.rule;
      if (r.direction !== 'forward' || r.action !== 'accept') return false;
      if (r.proto !== 'any' && n.proto !== 'any' && !protoCovers(r.proto, n.proto)) return false;
      const dstOk = [rr.v4, rr.v6].some((v) => v && addrsCover(v.dst, [n.toAddr!]));
      const portOk = r.proto === 'any' || rr.ports.length === 0 || (port ? portInList(Number(port.split(/[:-]/)[0]), rr.ports) : false);
      return dstOk && portOk;
    });
    if (!ok) {
      f.push({
        id: `dnat-noforward:${n.id}`,
        severity: 'medium',
        title: `Port forward "${n.name}" is blocked by the forward policy`,
        detail: `Traffic is rewritten to ${n.toAddr}${port ? `:${port}` : ''} but no forward rule accepts it.`,
        ruleId: n.id,
        fixLabel: 'Add forward rule',
        fix: (x) => ({
          ...x,
          options: { ...x.options, forwarding: true },
          rules: [...x.rules, newRule({ name: `Forward: ${n.name}`, direction: 'forward', proto: n.proto === 'any' ? 'any' : n.proto, dst: [n.toAddr!], ports: port && n.proto !== 'any' ? [port] : [] })],
        }),
      });
    }
  }
  if (p.nat.some((n) => n.enabled) && !opt.forwarding) {
    f.push({
      id: 'nat-no-forwarding',
      severity: 'low',
      title: 'NAT rules exist but forwarding is off',
      detail: 'NAT needs the kernel to route packets. The apply scripts switch ip_forward on anyway; turn the option on to make that explicit.',
      fixLabel: 'Turn forwarding on',
      fix: (x) => ({ ...x, options: { ...x.options, forwarding: true } }),
    });
  }

  const disabled = p.rules.filter((r) => !r.enabled).length;
  if (disabled > 0) {
    f.push({ id: 'disabled', severity: 'info', title: `${disabled} rule${disabled > 1 ? 's are' : ' is'} disabled`, detail: 'Disabled rules are kept in the project but left out of every generated ruleset.' });
  }
  if (p.rules.length === 0) {
    f.push({ id: 'empty', severity: 'info', title: 'No rules yet', detail: 'Start from a template or add your first rule.' });
  }

  return f.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

/** 0-100 posture score. */
export function score(findings: Finding[]): number {
  const penalty = findings.reduce((n, x) => n + SEVERITY_WEIGHT[x.severity], 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

export function grade(s: number): string {
  if (s >= 90) return 'A';
  if (s >= 75) return 'B';
  if (s >= 60) return 'C';
  if (s >= 40) return 'D';
  return 'F';
}
