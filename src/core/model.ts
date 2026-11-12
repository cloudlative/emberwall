// Emberwall firewall intermediate representation (IR).
// The UI, simulator, linter and every compiler work from this one model.

export type Direction = 'in' | 'out' | 'forward';
export type Action = 'accept' | 'drop' | 'reject';
export type Proto = 'any' | 'tcp' | 'udp' | 'tcpudp' | 'icmp';
export type Family = 'both' | 'ipv4' | 'ipv6';
export type ConnState = 'new' | 'established' | 'related' | 'invalid';
export type Policy = 'accept' | 'drop';

export interface RateLimit {
  rate: number;
  per: 'second' | 'minute' | 'hour';
  burst: number;
  /** Count each client separately; clients over the rate are dropped by this rule. */
  perSource?: boolean;
}

export interface Schedule {
  /** Empty = every day. */
  days: Weekday[];
  /** "HH:MM", in the firewall host's kernel time (UTC unless configured otherwise). */
  from: string;
  to: string;
}

export const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
export type Weekday = (typeof WEEKDAYS)[number];

export interface Zone {
  id: string;
  name: string;
  interfaces: string[];
  /** Networks behind this zone; used when a rule names the zone as source or destination. */
  networks: string[];
  trust: 'untrusted' | 'dmz' | 'trusted';
}

export interface Protections {
  /** Drop clients opening new TCP connections faster than this. */
  synFlood?: { rate: number; burst: number };
  /** Drop TCP packets with flag combinations only scanners send. */
  portScan?: boolean;
  /** Clients touching one of these ports are dropped entirely for `seconds`. */
  autoBan?: { ports: string[]; seconds: number };
}

export interface PolicyTest {
  id: string;
  name: string;
  packet: {
    direction: Direction; src: string; dst: string; proto: 'tcp' | 'udp' | 'icmp'; port?: number;
    inIface?: string; outIface?: string; state: ConnState; icmpType?: string;
  };
  expect: 'accept' | 'block';
}

export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  direction: Direction;
  action: Action;
  proto: Proto;
  family: Family;
  /** CIDRs / addresses, or "@<groupId>" references. Empty = any. */
  src: string[];
  dst: string[];
  /** Destination ports: "22", "8000:8100", or "@<portGroupId>". Empty = any. */
  ports: string[];
  inIface?: string;
  outIface?: string;
  states?: ConnState[];
  /** Only for proto icmp. Empty = every type. */
  icmpType?: string;
  log?: boolean;
  rateLimit?: RateLimit;
  comment?: string;
  /** Source ports (TCP/UDP). */
  srcPorts?: string[];
  srcMac?: string;
  /** Reject clients holding more than this many concurrent connections. */
  connLimit?: number;
  schedule?: Schedule;
  /** Packet mark to match, e.g. "0x1". */
  mark?: string;
  /** Zone ids; expand to the zone's interfaces and networks. */
  srcZone?: string;
  dstZone?: string;
}

export type NatKind = 'masquerade' | 'snat' | 'dnat';

export interface NatRule {
  id: string;
  name: string;
  enabled: boolean;
  kind: NatKind;
  proto: 'any' | 'tcp' | 'udp';
  /** Outbound interface for masquerade/snat, inbound interface for dnat. */
  iface?: string;
  src?: string;
  dst?: string;
  /** Matched destination port (dnat). */
  port?: string;
  toAddr?: string;
  toPort?: string;
  randomFully?: boolean;
  comment?: string;
}

export interface AddressGroup {
  id: string;
  name: string;
  members: string[];
}

export interface PortGroup {
  id: string;
  name: string;
  ports: string[];
}

export interface Options {
  allowLoopback: boolean;
  allowEstablished: boolean;
  dropInvalid: boolean;
  /** Ping plus the ICMPv6 types IPv6 cannot work without (neighbour discovery, PMTU). */
  allowIcmp: boolean;
  logDropped: boolean;
  ipv6: boolean;
  /** Host routes packets between interfaces (enables ip_forward in generated scripts). */
  forwarding: boolean;
}

export interface Project {
  schema: 1;
  name: string;
  description: string;
  policies: Record<Direction, Policy>;
  options: Options;
  addressGroups: AddressGroup[];
  portGroups: PortGroup[];
  rules: Rule[];
  nat: NatRule[];
  zones: Zone[];
  protections: Protections;
  tests: PolicyTest[];
}

let counter = 0;
export function uid(prefix = 'r'): string {
  counter += 1;
  return `${prefix}_${Date.now().toString(36)}${counter.toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

export function newRule(partial: Partial<Rule> = {}): Rule {
  return {
    id: uid('r'),
    name: 'New rule',
    enabled: true,
    direction: 'in',
    action: 'accept',
    proto: 'tcp',
    family: 'both',
    src: [],
    dst: [],
    ports: [],
    ...partial,
  };
}

export function newNat(partial: Partial<NatRule> = {}): NatRule {
  return { id: uid('n'), name: 'New NAT rule', enabled: true, kind: 'masquerade', proto: 'any', ...partial };
}

export function emptyProject(name = 'Untitled firewall'): Project {
  return {
    schema: 1,
    name,
    description: '',
    policies: { in: 'drop', out: 'accept', forward: 'drop' },
    options: {
      allowLoopback: true,
      allowEstablished: true,
      dropInvalid: true,
      allowIcmp: true,
      logDropped: false,
      ipv6: true,
      forwarding: false,
    },
    addressGroups: [],
    portGroups: [],
    rules: [],
    nat: [],
    zones: [],
    protections: {},
    tests: [],
  };
}

/** Accepts unknown JSON and returns a well-formed project, or throws with a readable reason. */
export function coerceProject(raw: unknown): Project {
  if (!raw || typeof raw !== 'object') throw new Error('Not a project object');
  const r = raw as Record<string, any>;
  if (!Array.isArray(r.rules)) throw new Error('Missing "rules" array');
  const base = emptyProject(typeof r.name === 'string' ? r.name : 'Imported firewall');
  const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
  return {
    ...base,
    description: typeof r.description === 'string' ? r.description : '',
    policies: { ...base.policies, ...(r.policies ?? {}) },
    options: { ...base.options, ...(r.options ?? {}) },
    addressGroups: (r.addressGroups ?? []).map((g: any) => ({
      id: String(g.id ?? uid('ag')),
      name: String(g.name ?? 'group'),
      members: arr(g.members),
    })),
    portGroups: (r.portGroups ?? []).map((g: any) => ({
      id: String(g.id ?? uid('pg')),
      name: String(g.name ?? 'ports'),
      ports: arr(g.ports),
    })),
    rules: r.rules.map((x: any) =>
      newRule({ ...x, id: String(x.id ?? uid('r')), src: arr(x.src), dst: arr(x.dst), ports: arr(x.ports) }),
    ),
    nat: (r.nat ?? []).map((x: any) => newNat({ ...x, id: String(x.id ?? uid('n')) })),
    zones: (r.zones ?? []).map((z: any) => ({
      id: String(z.id ?? uid('z')),
      name: String(z.name ?? 'zone'),
      interfaces: arr(z.interfaces),
      networks: arr(z.networks),
      trust: z.trust === 'trusted' || z.trust === 'dmz' ? z.trust : 'untrusted',
    })),
    protections: r.protections && typeof r.protections === 'object' ? r.protections : {},
    tests: Array.isArray(r.tests) ? r.tests.filter((t: any) => t && t.packet).map((t: any) => ({ ...t, id: String(t.id ?? uid('t')) })) : [],
  };
}

export const ICMP_TYPES = [
  'echo-request',
  'echo-reply',
  'destination-unreachable',
  'time-exceeded',
  'parameter-problem',
] as const;

export const DIRECTION_LABEL: Record<Direction, string> = { in: 'Inbound', out: 'Outbound', forward: 'Forward' };
