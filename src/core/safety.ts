// Input hardening. Generated files are run as root on real machines, so every value that reaches
// them is either validated against a strict pattern or stripped of characters that could end a
// quoted string or start a new command. Applied to every build, in the browser and on the server.
import { ICMP_TYPES, WEEKDAYS, type NatRule, type Project, type Rule } from './model';
import { parseCidr, parsePort } from './net';

const IFACE = /^[A-Za-z0-9_.-]{1,15}\+?$/;
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const MARK = /^(0x[0-9a-f]{1,8}|\d{1,10})$/i;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;

/** Free text (names, comments): one line, no quote, escape or expansion characters. */
export function cleanText(s: unknown, max = 120): string {
  return String(s ?? '').replace(/[\u0000-\u001f\u007f'"`$\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

const int = (v: unknown, min: number, max: number): number | null => {
  const n = Number(v);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
};

export interface Hardened {
  project: Project;
  /** Things that were rejected; each one is reported as an error and left out of the output. */
  problems: { message: string; ruleId?: string }[];
}

export function harden(p: Project): Hardened {
  const problems: Hardened['problems'] = [];
  const bad = (message: string, ruleId?: string) => problems.push({ message, ruleId });
  const iface = (v: string | undefined, what: string, id?: string): string | undefined => {
    if (!v) return undefined;
    if (IFACE.test(v)) return v;
    bad(`${what}: "${cleanText(v, 30)}" is not a valid interface name`, id);
    return undefined;
  };

  const rules: Rule[] = p.rules.map((r) => {
    const name = cleanText(r.name) || 'rule';
    let ok = true;
    const fail = (m: string) => {
      bad(`"${name}": ${m}`, r.id);
      ok = false;
    };
    if (!['in', 'out', 'forward'].includes(r.direction)) fail('unknown direction');
    if (!['accept', 'drop', 'reject'].includes(r.action)) fail('unknown action');
    if (!['any', 'tcp', 'udp', 'tcpudp', 'icmp'].includes(r.proto)) fail('unknown protocol');
    if (!['both', 'ipv4', 'ipv6'].includes(r.family)) fail('unknown address family');
    if (r.inIface && !IFACE.test(r.inIface)) fail(`"${cleanText(r.inIface, 30)}" is not a valid interface name`);
    if (r.outIface && !IFACE.test(r.outIface)) fail(`"${cleanText(r.outIface, 30)}" is not a valid interface name`);
    if (r.icmpType && !(ICMP_TYPES as readonly string[]).includes(r.icmpType)) fail('unknown ICMP type');
    if (r.srcMac && !MAC.test(r.srcMac)) fail('invalid MAC address');
    if (r.mark && !MARK.test(r.mark)) fail('invalid packet mark');
    if (r.states && r.states.some((s) => !['new', 'established', 'related', 'invalid'].includes(s))) fail('unknown connection state');
    let schedule = r.schedule;
    if (schedule) {
      const days = (schedule.days ?? []).filter((d) => (WEEKDAYS as readonly string[]).includes(d));
      if (!TIME.test(schedule.from) || !TIME.test(schedule.to) || days.length !== (schedule.days ?? []).length) fail('invalid schedule');
      else schedule = { days, from: schedule.from, to: schedule.to };
    }
    let rateLimit = r.rateLimit;
    if (rateLimit) {
      const rate = int(rateLimit.rate, 1, 1_000_000);
      const burst = int(rateLimit.burst, 1, 1_000_000);
      if (rate === null || burst === null || !['second', 'minute', 'hour'].includes(rateLimit.per)) fail('invalid rate limit');
      else rateLimit = { rate, burst, per: rateLimit.per, perSource: rateLimit.perSource ? true : undefined };
    }
    let connLimit = r.connLimit;
    if (connLimit !== undefined && connLimit !== null) {
      const n = int(connLimit, 1, 1_000_000);
      if (n === null) fail('invalid connection limit');
      else connLimit = n;
    }
    return { ...r, name, comment: r.comment ? cleanText(r.comment) : undefined, schedule, rateLimit, connLimit: connLimit ?? undefined, enabled: r.enabled && ok };
  });

  const nat: NatRule[] = p.nat.map((n) => {
    const name = cleanText(n.name) || 'nat';
    let ok = true;
    const fail = (m: string) => {
      bad(`NAT "${name}": ${m}`, n.id);
      ok = false;
    };
    if (!['masquerade', 'snat', 'dnat'].includes(n.kind)) fail('unknown kind');
    if (!['any', 'tcp', 'udp'].includes(n.proto)) fail('unknown protocol');
    if (n.iface && !IFACE.test(n.iface)) fail('invalid interface name');
    for (const [label, v] of [['source', n.src], ['destination', n.dst]] as const) if (v && !parseCidr(v)) fail(`invalid ${label} address`);
    if (n.toAddr && (!parseCidr(n.toAddr) || n.toAddr.includes('/'))) fail('invalid target address');
    for (const [label, v] of [['port', n.port], ['target port', n.toPort]] as const) if (v && !parsePort(v)) fail(`invalid ${label}`);
    return { ...n, name, comment: n.comment ? cleanText(n.comment) : undefined, enabled: n.enabled && ok };
  });

  const pr = p.protections ?? {};
  const protections: Project['protections'] = {};
  if (pr.synFlood) {
    const rate = int(pr.synFlood.rate, 1, 1_000_000);
    const burst = int(pr.synFlood.burst, 1, 1_000_000);
    if (rate === null || burst === null) bad('SYN flood guard: invalid rate');
    else protections.synFlood = { rate, burst };
  }
  if (pr.portScan) protections.portScan = true;
  if (pr.autoBan) {
    const seconds = int(pr.autoBan.seconds, 1, 31_536_000);
    const ports = (pr.autoBan.ports ?? []).map(String).filter((x) => !!parsePort(x));
    if (seconds === null) bad('Auto-ban: invalid duration');
    else {
      if (ports.length !== (pr.autoBan.ports ?? []).length) bad('Auto-ban: invalid trap port left out');
      protections.autoBan = { ports, seconds };
    }
  }

  const project: Project = {
    ...p,
    name: cleanText(p.name) || 'firewall',
    description: cleanText(p.description, 400),
    rules,
    nat,
    protections,
    addressGroups: p.addressGroups.map((g) => ({ ...g, name: cleanText(g.name) || 'group' })),
    portGroups: p.portGroups.map((g) => ({ ...g, name: cleanText(g.name) || 'ports' })),
    zones: (p.zones ?? []).map((z) => ({
      ...z,
      name: cleanText(z.name) || 'zone',
      interfaces: z.interfaces.filter((i) => iface(i, `Zone "${cleanText(z.name)}"`) !== undefined),
    })),
    blocklists: (p.blocklists ?? []).map((b) => ({ ...b, name: cleanText(b.name) || 'blocklist' })),
    hosts: (p.hosts ?? []).map((h) => ({ ...h, name: cleanText(h.name) || 'host' })),
  };
  return { project, problems };
}
