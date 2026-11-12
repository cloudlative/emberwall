// Address and port helpers shared by compilers, simulator and linter.

export interface Cidr {
  family: 'ipv4' | 'ipv6';
  addr: bigint;
  prefix: number;
  bits: number;
}

function parseV4(s: string): bigint | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

function parseV6(s: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(':')) return null;
  let text = s;
  // Embedded IPv4 tail (::ffff:1.2.3.4)
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseV4(tail);
    if (v4 === null) return null;
    text = `${text.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

export function parseCidr(input: string): Cidr | null {
  const s = input.trim();
  const [addrText, prefixText, extra] = s.split('/');
  if (extra !== undefined || !addrText) return null;
  const v4 = parseV4(addrText);
  const family = v4 !== null ? 'ipv4' : 'ipv6';
  const addr = v4 !== null ? v4 : parseV6(addrText);
  if (addr === null) return null;
  const bits = family === 'ipv4' ? 32 : 128;
  let prefix = bits;
  if (prefixText !== undefined) {
    if (!/^\d{1,3}$/.test(prefixText)) return null;
    prefix = Number(prefixText);
    if (prefix > bits) return null;
  }
  return { family, addr, prefix, bits };
}

export function familyOf(addr: string): 'ipv4' | 'ipv6' | null {
  return parseCidr(addr)?.family ?? null;
}

function network(c: Cidr): bigint {
  const host = BigInt(c.bits - c.prefix);
  return (c.addr >> host) << host;
}

/** True when `inner` is entirely inside `outer`. */
export function cidrContains(outer: Cidr, inner: Cidr): boolean {
  if (outer.family !== inner.family || outer.prefix > inner.prefix) return false;
  const host = BigInt(outer.bits - outer.prefix);
  return network(outer) >> host === inner.addr >> host;
}

export function addrInList(ip: string, list: string[]): boolean {
  const target = parseCidr(ip);
  if (!target) return false;
  return list.some((entry) => {
    const c = parseCidr(entry);
    return !!c && cidrContains(c, target);
  });
}

export interface PortRange {
  from: number;
  to: number;
}

/** Accepts "22", "8000:8100" and "8000-8100". */
export function parsePort(input: string): PortRange | null {
  const m = /^(\d{1,5})(?:[:-](\d{1,5}))?$/.exec(input.trim());
  if (!m) return null;
  const from = Number(m[1]);
  const to = m[2] === undefined ? from : Number(m[2]);
  if (from < 1 || to > 65535 || from > to) return null;
  return { from, to };
}

export function portInList(port: number, list: string[]): boolean {
  return list.some((p) => {
    const r = parsePort(p);
    return !!r && port >= r.from && port <= r.to;
  });
}

/** Normalises to colon form ("8000:8100"); callers convert for tools that want a dash. */
export function normPort(input: string): string {
  const r = parsePort(input);
  if (!r) return input.trim();
  return r.from === r.to ? String(r.from) : `${r.from}:${r.to}`;
}

export function portsCover(outer: string[], inner: string[]): boolean {
  if (outer.length === 0) return true;
  if (inner.length === 0) return false;
  return inner.every((p) => {
    const r = parsePort(p);
    if (!r) return false;
    return outer.some((o) => {
      const or = parsePort(o);
      return !!or && or.from <= r.from && or.to >= r.to;
    });
  });
}

export function addrsCover(outer: string[], inner: string[]): boolean {
  if (outer.length === 0) return true;
  if (inner.length === 0) return false;
  return inner.every((a) => {
    const c = parseCidr(a);
    if (!c) return false;
    return outer.some((o) => {
      const oc = parseCidr(o);
      return !!oc && cidrContains(oc, c);
    });
  });
}

export const WELL_KNOWN_PORTS: Record<number, string> = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP', 179: 'BGP', 443: 'HTTPS', 465: 'SMTPS', 500: 'IKE',
  514: 'Syslog', 587: 'Submission', 853: 'DNS over TLS', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN',
  1433: 'MS SQL', 1521: 'Oracle', 2049: 'NFS', 2375: 'Docker API', 2376: 'Docker TLS', 2379: 'etcd',
  2380: 'etcd peer', 3000: 'Dev server', 3306: 'MySQL', 3389: 'RDP', 4500: 'IPsec NAT-T', 5432: 'PostgreSQL',
  5601: 'Kibana', 5672: 'AMQP', 5900: 'VNC', 6379: 'Redis', 6443: 'Kubernetes API', 8080: 'HTTP alt',
  8443: 'HTTPS alt', 9090: 'Prometheus', 9100: 'Node exporter', 9200: 'Elasticsearch', 10250: 'Kubelet',
  11211: 'Memcached', 27017: 'MongoDB', 51820: 'WireGuard',
};

export function portLabel(p: string): string {
  const r = parsePort(p);
  if (r && r.from === r.to && WELL_KNOWN_PORTS[r.from]) return WELL_KNOWN_PORTS[r.from];
  return '';
}

function formatAddr(family: 'ipv4' | 'ipv6', n: bigint): string {
  if (family === 'ipv4') return [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 255n)).join('.');
  const groups: string[] = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // Collapse the longest run of zero groups.
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i += 1) {
    let j = i;
    while (j < 8 && groups[j] === '0') j += 1;
    if (j - i > bestLen && j - i > 1) {
      best = i;
      bestLen = j - i;
    }
  }
  if (best < 0) return groups.join(':');
  return `${groups.slice(0, best).join(':')}::${groups.slice(best + bestLen).join(':')}`;
}

/** A concrete host address inside a network (the first usable one), for simulation. */
export function representative(cidr: string): string | null {
  const c = parseCidr(cidr);
  if (!c) return null;
  if (c.prefix === c.bits) return formatAddr(c.family, c.addr);
  const host = BigInt(c.bits - c.prefix);
  return formatAddr(c.family, ((c.addr >> host) << host) + 1n);
}
