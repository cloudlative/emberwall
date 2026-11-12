// Firewall log analyzer: reads kernel log lines written by iptables LOG, nftables log and ufw.
import type { Project } from './model';
import { parseCidr, portLabel } from './net';
import { simulate, type Packet } from './simulate';

export interface LogEntry {
  raw: string;
  prefix: string;
  inIface?: string;
  outIface?: string;
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  sport?: number;
  dport?: number;
  direction: 'in' | 'out' | 'forward';
}

export interface LogSummary {
  entries: LogEntry[];
  unparsed: number;
  topSources: { key: string; count: number; ports: number }[];
  topPorts: { key: string; proto: string; port: number; label: string; count: number; sources: number }[];
  byPrefix: { key: string; count: number }[];
}

const field = (line: string, name: string) => new RegExp(`\\b${name}=(\\S*)`).exec(line)?.[1];

export function parseLogLine(line: string): LogEntry | null {
  if (!/\bSRC=/.test(line) || !/\bDST=/.test(line)) return null;
  const src = field(line, 'SRC') ?? '';
  const dst = field(line, 'DST') ?? '';
  if (!parseCidr(src) || !parseCidr(dst)) return null;
  const protoRaw = (field(line, 'PROTO') ?? '').toUpperCase();
  const proto = protoRaw === 'TCP' ? 'tcp' : protoRaw === 'UDP' ? 'udp' : /ICMP/.test(protoRaw) ? 'icmp' : null;
  if (!proto) return null;
  const inIface = field(line, 'IN') || undefined;
  const outIface = field(line, 'OUT') || undefined;
  // The log prefix sits between the kernel timestamp / hostname and the IN= field.
  const pm = /(?:kernel:\s*)?(?:\[\s*[\d.]+\]\s*)?([^=\n]*?)\s*IN=/.exec(line);
  let prefix = (pm?.[1] ?? '').replace(/^.*kernel:\s*/, '').replace(/^\[\s*[\d.]+\]\s*/, '').trim().replace(/:$/, '');
  if (!prefix) prefix = '(no prefix)';
  const num = (n: string) => {
    const v = field(line, n);
    return v && /^\d+$/.test(v) ? Number(v) : undefined;
  };
  return {
    raw: line.trim(), prefix, inIface, outIface, src, dst, proto,
    sport: num('SPT'), dport: num('DPT'),
    direction: inIface && outIface ? 'forward' : outIface ? 'out' : 'in',
  };
}

function top<T>(items: T[], key: (x: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    m.set(k, [...(m.get(k) ?? []), it]);
  }
  return m;
}

export function analyzeLogs(text: string): LogSummary {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  const entries: LogEntry[] = [];
  let unparsed = 0;
  for (const l of lines) {
    const e = parseLogLine(l);
    if (e) entries.push(e);
    else unparsed += 1;
  }
  const bySrc = top(entries, (e) => e.src);
  const byPort = top(entries.filter((e) => e.dport !== undefined), (e) => `${e.proto}/${e.dport}`);
  const byPrefix = top(entries, (e) => e.prefix);
  const sortDesc = <T extends { count: number }>(a: T[]) => a.sort((x, y) => y.count - x.count);
  return {
    entries,
    unparsed,
    topSources: sortDesc([...bySrc].map(([key, v]) => ({ key, count: v.length, ports: new Set(v.map((e) => e.dport)).size }))).slice(0, 15),
    topPorts: sortDesc([...byPort].map(([key, v]) => ({ key, proto: v[0].proto, port: v[0].dport!, label: portLabel(String(v[0].dport)), count: v.length, sources: new Set(v.map((e) => e.src)).size }))).slice(0, 15),
    byPrefix: sortDesc([...byPrefix].map(([key, v]) => ({ key, count: v.length }))),
  };
}

export function packetOf(e: LogEntry): Packet {
  return { direction: e.direction, src: e.src, dst: e.dst, proto: e.proto, port: e.dport, sport: e.sport, inIface: e.inIface, outIface: e.outIface, state: 'new' };
}

/** What the current ruleset would do with a logged packet. */
export function verdictNow(p: Project, e: LogEntry) {
  return simulate(p, packetOf(e));
}
