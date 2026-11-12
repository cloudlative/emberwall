// Packet simulator: walks a packet through the IR the way the generated rulesets would.
import type { Action, ConnState, Direction, Project } from './model';
import { addrInList, familyOf, parseCidr, portInList } from './net';
import { resolveAll, type ResolvedRule } from './resolve';

export interface Packet {
  direction: Direction;
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  port?: number;
  icmpType?: string;
  inIface?: string;
  outIface?: string;
  state: ConnState;
}

export interface TraceStep {
  label: string;
  detail: string;
  matched: boolean;
  ruleId?: string;
  verdict?: Action;
}

export interface SimResult {
  verdict: Action;
  decidedBy: string;
  ruleId?: string;
  steps: TraceStep[];
  /** Set when the deciding rule has a rate limit: excess packets fall through instead. */
  rateLimited?: boolean;
  error?: string;
}

const V6_ESSENTIAL = ['echo-request', 'destination-unreachable', 'packet-too-big', 'time-exceeded', 'parameter-problem', 'neighbour-solicitation', 'neighbour-advertisement', 'router-solicitation', 'router-advertisement'];

function ifaceMatch(pattern: string, actual: string | undefined): boolean {
  if (!actual) return false;
  if (pattern.endsWith('+')) return actual.startsWith(pattern.slice(0, -1));
  return pattern === actual;
}

/** Returns null on a match, otherwise the first reason the rule does not apply. */
export function mismatch(rr: ResolvedRule, pkt: Packet): string | null {
  const r = rr.rule;
  const fam = familyOf(pkt.src) ?? 'ipv4';
  const view = fam === 'ipv4' ? rr.v4 : rr.v6;
  if (!view) return `rule does not apply to ${fam === 'ipv4' ? 'IPv4' : 'IPv6'}`;
  if (r.inIface && r.direction !== 'out' && !ifaceMatch(r.inIface, pkt.inIface)) return `inbound interface is not ${r.inIface}`;
  if (r.outIface && r.direction !== 'in' && !ifaceMatch(r.outIface, pkt.outIface)) return `outbound interface is not ${r.outIface}`;
  if (view.src.length > 0 && !addrInList(pkt.src, view.src)) return `source ${pkt.src} not in ${view.src.join(', ')}`;
  if (view.dst.length > 0 && !addrInList(pkt.dst, view.dst)) return `destination ${pkt.dst} not in ${view.dst.join(', ')}`;
  if (r.proto !== 'any') {
    const ok = r.proto === 'tcpudp' ? pkt.proto !== 'icmp' : r.proto === pkt.proto;
    if (!ok) return `protocol is ${pkt.proto}, rule wants ${r.proto === 'tcpudp' ? 'tcp/udp' : r.proto}`;
  }
  if (rr.ports.length > 0 && pkt.proto !== 'icmp') {
    if (pkt.port === undefined || !portInList(pkt.port, rr.ports)) return `port ${pkt.port ?? '-'} not in ${rr.ports.join(', ')}`;
  }
  if (r.proto === 'icmp' && r.icmpType && r.icmpType !== (pkt.icmpType ?? 'echo-request')) return `ICMP type is not ${r.icmpType}`;
  if (r.states && r.states.length > 0 && !r.states.includes(pkt.state)) return `connection state is ${pkt.state}`;
  return null;
}

export function simulate(p: Project, input: Packet): SimResult {
  const steps: TraceStep[] = [];
  const pkt: Packet = { ...input };
  const bad = (error: string): SimResult => ({ verdict: 'drop', decidedBy: 'invalid packet', steps, error });
  if (!parseCidr(pkt.src)) return bad(`"${pkt.src}" is not a valid source address`);
  if (!parseCidr(pkt.dst)) return bad(`"${pkt.dst}" is not a valid destination address`);
  if (familyOf(pkt.src) !== familyOf(pkt.dst)) return bad('Source and destination must be the same address family');
  const fam = familyOf(pkt.src)!;
  const done = (verdict: Action, decidedBy: string, extra: Partial<SimResult> = {}): SimResult => ({ verdict, decidedBy, steps, ...extra });
  const step = (label: string, matched: boolean, detail: string, verdict?: Action, ruleId?: string) =>
    steps.push({ label, matched, detail, verdict: matched ? verdict : undefined, ruleId });

  // Destination NAT happens before filtering and can turn an inbound packet into a forwarded one.
  if (pkt.direction !== 'out' && pkt.state === 'new') {
    for (const n of p.nat.filter((x) => x.enabled && x.kind === 'dnat' && x.toAddr)) {
      const hit =
        (!n.iface || ifaceMatch(n.iface, pkt.inIface)) &&
        (n.proto === 'any' || n.proto === pkt.proto) &&
        (!n.port || (pkt.port !== undefined && portInList(pkt.port, [n.port]))) &&
        (!n.src || addrInList(pkt.src, [n.src])) &&
        (!n.dst || addrInList(pkt.dst, [n.dst])) &&
        familyOf(n.toAddr!) === fam;
      if (!hit) continue;
      const newPort = n.toPort ? Number(n.toPort.split(/[:-]/)[0]) : pkt.port;
      step(`NAT: ${n.name}`, true, `destination rewritten to ${n.toAddr}${newPort ? `:${newPort}` : ''}; packet is now forwarded`, undefined, n.id);
      pkt.dst = n.toAddr!;
      pkt.port = newPort;
      pkt.direction = 'forward';
      break;
    }
  }

  const dir = pkt.direction;
  const opt = p.options;
  const lo = (dir === 'in' && pkt.inIface === 'lo') || (dir === 'out' && pkt.outIface === 'lo');

  if (opt.allowLoopback) {
    step('Loopback', lo, lo ? 'traffic on lo is always accepted' : 'not on the loopback interface', 'accept');
    if (lo) return done('accept', 'loopback rule');
  }
  if (fam === 'ipv6' && !opt.ipv6) {
    step('IPv6 switched off', true, 'all IPv6 traffic is dropped', 'drop');
    return done('drop', 'IPv6 is switched off');
  }
  if (opt.allowEstablished) {
    const est = pkt.state === 'established' || pkt.state === 'related';
    step('Established / related', est, est ? 'part of a connection that was already allowed' : `state is ${pkt.state}`, 'accept');
    if (est) return done('accept', 'established-connection rule');
  }
  if (opt.dropInvalid && dir !== 'out') {
    const inv = pkt.state === 'invalid';
    step('Invalid state', inv, inv ? 'packet does not belong to any known connection' : 'state is valid', 'drop');
    if (inv) return done('drop', 'invalid-state rule');
  }
  if (opt.allowIcmp && pkt.proto === 'icmp' && (dir === 'in' || (dir === 'out' && p.policies.out === 'drop'))) {
    const type = pkt.icmpType ?? 'echo-request';
    const ok = fam === 'ipv4' ? type === 'echo-request' : V6_ESSENTIAL.includes(type);
    step('Essential ICMP', ok, ok ? `${type} is allowed` : `${type} is not in the essential set`, 'accept');
    if (ok) return done('accept', 'essential-ICMP rule');
  }

  for (const rr of resolveAll(p).filter((x) => x.rule.direction === dir)) {
    const why = mismatch(rr, pkt);
    const r = rr.rule;
    if (why) {
      step(r.name, false, why, undefined, r.id);
      continue;
    }
    const limited = !!r.rateLimit && r.action === 'accept';
    step(
      r.name,
      true,
      limited ? `matches; accepted up to ${r.rateLimit!.rate}/${r.rateLimit!.per}, excess falls through to the next rule` : `matches${r.log ? ' (logged)' : ''}`,
      r.action,
      r.id,
    );
    return done(r.action, `rule "${r.name}"`, { ruleId: r.id, rateLimited: limited });
  }

  const policy = p.policies[dir];
  step(`Default policy (${dir})`, true, `no rule matched; policy is ${policy}`, policy);
  return done(policy, `default ${dir === 'in' ? 'inbound' : dir === 'out' ? 'outbound' : 'forward'} policy`);
}
