// Reachability: "who can reach what", computed by running the simulator over representative packets.
import type { Action, PolicyTest, Project } from './model';
import { parsePort, portLabel, representative } from './net';
import { expandAddrs, expandPorts } from './resolve';
import { simulate, type Packet } from './simulate';

export interface Endpoint {
  id: string;
  label: string;
  detail: string;
  addr: string;
  iface?: string;
}

export interface Service {
  id: string;
  label: string;
  proto: 'tcp' | 'udp' | 'icmp';
  port?: number;
}

export interface Axes {
  sources: Endpoint[];
  /** "host" is this machine; the rest are zones reached by forwarding. */
  targets: Endpoint[];
  services: Service[];
}

export interface Cell {
  verdict: Action;
  decidedBy: string;
  ruleId?: string;
  limited?: boolean;
}

export interface ReachRow {
  target: Endpoint;
  source: Endpoint;
  cells: Cell[];
}

const INTERNET = '198.51.100.77';

function serviceId(proto: string, port?: number) {
  return `${proto}/${port ?? ''}`;
}

/** Sources, targets and services worth showing, drawn from every project passed in. */
export function buildAxes(...projects: Project[]): Axes {
  const sources = new Map<string, Endpoint>();
  const targets = new Map<string, Endpoint>();
  const services = new Map<string, Service>();
  targets.set('host', { id: 'host', label: 'This host', detail: 'local services', addr: '192.0.2.1' });

  for (const p of projects) {
    const zoned = new Set(p.zones.flatMap((z) => z.interfaces));
    const wan = p.zones.find((z) => z.trust === 'untrusted');
    if (!sources.has('internet')) {
      sources.set('internet', { id: 'internet', label: 'Internet', detail: wan?.interfaces[0] ? `via ${wan.interfaces[0]}` : 'any outside address', addr: INTERNET, iface: wan?.interfaces[0] });
    }
    for (const z of p.zones) {
      const addr = z.networks.map(representative).find(Boolean) ?? (z.trust === 'untrusted' ? INTERNET : '10.255.0.2');
      const ep: Endpoint = { id: `zone:${z.id}`, label: z.name, detail: [z.interfaces.join(', '), z.networks.join(', ')].filter(Boolean).join(' · ') || 'zone', addr, iface: z.interfaces[0] };
      // The outside zone without networks of its own is already covered by "Internet" as a source.
      if (!(z === wan && z.networks.length === 0) && !sources.has(ep.id)) sources.set(ep.id, ep);
      if (!targets.has(ep.id)) targets.set(ep.id, ep);
    }
    for (const g of p.addressGroups) {
      const addr = expandAddrs(g.members, p).filter((a) => !a.includes(':')).map(representative).find(Boolean);
      if (addr && !sources.has(`group:${g.id}`)) sources.set(`group:${g.id}`, { id: `group:${g.id}`, label: g.name, detail: g.members.slice(0, 2).join(', '), addr });
    }
    for (const r of p.rules.filter((x) => x.enabled)) {
      if (r.inIface && !zoned.has(r.inIface) && !sources.has(`if:${r.inIface}`)) {
        sources.set(`if:${r.inIface}`, { id: `if:${r.inIface}`, label: `Via ${r.inIface}`, detail: 'any host on that interface', addr: '10.254.0.2', iface: r.inIface });
      }
      for (const a of expandAddrs(r.src, p).filter((x) => !x.includes(':') && !r.src.some((s) => s.startsWith('@')))) {
        const rep = representative(a);
        if (rep && !sources.has(`addr:${a}`)) sources.set(`addr:${a}`, { id: `addr:${a}`, label: a, detail: 'source named in a rule', addr: rep });
      }
      if (r.direction === 'out') continue;
      if (r.proto === 'icmp') services.set('icmp/', { id: 'icmp/', label: 'Ping', proto: 'icmp' });
      const protos = r.proto === 'tcpudp' ? (['tcp', 'udp'] as const) : r.proto === 'tcp' || r.proto === 'udp' ? ([r.proto] as const) : [];
      for (const proto of protos) {
        for (const pt of expandPorts(r.ports, p)) {
          const range = parsePort(pt);
          if (!range) continue;
          const id = serviceId(proto, range.from);
          if (!services.has(id)) services.set(id, { id, label: `${portLabel(String(range.from)) || 'Port'} ${range.from}/${proto}`, proto, port: range.from });
        }
      }
    }
    for (const n of p.nat.filter((x) => x.enabled && x.kind === 'dnat' && x.port && x.proto !== 'any')) {
      const port = Number(n.port!.split(/[:-]/)[0]);
      const id = serviceId(n.proto, port);
      if (!services.has(id)) services.set(id, { id, label: `${portLabel(String(port)) || 'Port'} ${port}/${n.proto}`, proto: n.proto as 'tcp' | 'udp', port });
    }
  }
  if (!services.has('tcp/22')) services.set('tcp/22', { id: 'tcp/22', label: 'SSH 22/tcp', proto: 'tcp', port: 22 });
  const list = [...services.values()].sort((a, b) => (a.port ?? 0) - (b.port ?? 0)).slice(0, 24);
  return { sources: [...sources.values()].slice(0, 16), targets: [...targets.values()], services: list };
}

export function packetFor(source: Endpoint, target: Endpoint, service: Service): Packet {
  const forward = target.id !== 'host';
  return {
    direction: forward ? 'forward' : 'in',
    src: source.addr,
    dst: target.addr,
    proto: service.proto,
    port: service.port,
    state: 'new',
    inIface: source.iface,
    outIface: forward ? target.iface : undefined,
  };
}

export function reachability(p: Project, axes: Axes = buildAxes(p)): ReachRow[] {
  const rows: ReachRow[] = [];
  for (const target of axes.targets) {
    for (const source of axes.sources) {
      if (source.id === target.id) continue;
      const cells = axes.services.map((svc) => {
        const r = simulate(p, packetFor(source, target, svc));
        return { verdict: r.verdict, decidedBy: r.decidedBy, ruleId: r.ruleId, limited: r.rateLimited };
      });
      rows.push({ target, source, cells });
    }
  }
  return rows;
}

// ---- policy tests ----

export interface TestResult {
  test: PolicyTest;
  pass: boolean;
  verdict: Action;
  decidedBy: string;
  ruleId?: string;
  error?: string;
}

export function runTests(p: Project): TestResult[] {
  return (p.tests ?? []).map((test) => {
    const r = simulate(p, test.packet);
    const accepted = r.verdict === 'accept';
    return { test, pass: !r.error && accepted === (test.expect === 'accept'), verdict: r.verdict, decidedBy: r.decidedBy, ruleId: r.ruleId, error: r.error };
  });
}

// ---- semantic diff ----

export interface AccessChange {
  source: Endpoint;
  target: Endpoint;
  service: Service;
  before: Action;
  after: Action;
  /** opened: was blocked, now accepted. closed: the reverse. */
  kind: 'opened' | 'closed';
  decidedBy: string;
}

/** What traffic is treated differently by `after` compared with `before`. */
export function semanticDiff(before: Project, after: Project): AccessChange[] {
  const axes = buildAxes(before, after);
  const a = reachability(before, axes);
  const b = reachability(after, axes);
  const out: AccessChange[] = [];
  a.forEach((row, i) => {
    row.cells.forEach((cell, j) => {
      const next = b[i].cells[j];
      const was = cell.verdict === 'accept';
      const now = next.verdict === 'accept';
      if (was === now) return;
      out.push({ source: row.source, target: row.target, service: axes.services[j], before: cell.verdict, after: next.verdict, kind: now ? 'opened' : 'closed', decidedBy: next.decidedBy });
    });
  });
  return out;
}
