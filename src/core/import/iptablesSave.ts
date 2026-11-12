// Parses `iptables-save` / `ip6tables-save` output into an Emberwall project.
import { emptyProject, newNat, newRule, type ConnState, type Project, type Rule } from '../model';
import { ICMP6_ESSENTIAL } from '../compile/iptables';

export interface ImportReport {
  project: Project;
  imported: number;
  skipped: { line: string; reason: string }[];
}

function tokenize(line: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

const DIR = { INPUT: 'in', OUTPUT: 'out', FORWARD: 'forward' } as const;

interface Parsed {
  chain: string;
  target: string;
  src?: string;
  dst?: string;
  inIface?: string;
  outIface?: string;
  proto?: string;
  ports: string[];
  states: string[];
  comment?: string;
  icmpType?: string;
  limit?: string;
  burst?: string;
  to?: string;
  random?: boolean;
}

function parseLine(tokens: string[]): Parsed | string {
  const p: Parsed = { chain: tokens[1], target: '', ports: [], states: [] };
  for (let i = 2; i < tokens.length; i += 1) {
    const t = tokens[i];
    const next = () => tokens[(i += 1)];
    switch (t) {
      case '!':
        return 'negated matches (!) are not supported';
      case '-s': p.src = next(); break;
      case '-d': p.dst = next(); break;
      case '-i': p.inIface = next(); break;
      case '-o': p.outIface = next(); break;
      case '-p': p.proto = next(); break;
      case '-m': next(); break;
      case '--dport': p.ports.push(next()); break;
      case '--dports': p.ports.push(...next().split(',')); break;
      case '--ctstate':
      case '--state': p.states.push(...next().toLowerCase().split(',')); break;
      case '--comment': p.comment = next(); break;
      case '--icmp-type':
      case '--icmpv6-type': p.icmpType = next(); break;
      case '--limit': p.limit = next(); break;
      case '--limit-burst': p.burst = next(); break;
      case '-j': p.target = next(); break;
      case '--reject-with':
      case '--log-prefix':
      case '--log-level': next(); break;
      case '--to-destination':
      case '--to-source': p.to = next(); break;
      case '--random':
      case '--random-fully': p.random = true; break;
      default:
        return `unsupported option ${t}`;
    }
  }
  return p;
}

const stripHost = (a?: string) => (a ? a.replace(/\/(32|128)$/, '') : a);

export function importIptablesSave(text: string): ImportReport {
  const project = emptyProject('Imported from iptables-save');
  project.options = { ...project.options, allowLoopback: false, allowEstablished: false, dropInvalid: false, allowIcmp: false, logDropped: false };
  const skipped: ImportReport['skipped'] = [];
  let table = '';
  let family: 'ipv4' | 'ipv6' = 'ipv4';
  let sawV6 = false;
  let pendingLog: string | null = null;
  const rules: Rule[] = [];
  const skip = (line: string, reason: string) => skipped.push({ line, reason });

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      if (/ip6tables/.test(line)) {
        family = 'ipv6';
        sawV6 = true;
      } else if (/iptables-save|iptables-restore/.test(line)) family = 'ipv4';
      continue;
    }
    if (line.startsWith('*')) {
      table = line.slice(1);
      continue;
    }
    if (line === 'COMMIT') continue;
    if (line.startsWith(':')) {
      const [chain, policy] = line.slice(1).split(/\s+/);
      if (table === 'filter' && chain in DIR && (policy === 'ACCEPT' || policy === 'DROP')) {
        project.policies[DIR[chain as keyof typeof DIR]] = policy.toLowerCase() as 'accept' | 'drop';
      } else if (table === 'filter' && policy === '-') skip(line, 'custom chains are not imported');
      continue;
    }
    if (!line.startsWith('-A ')) {
      skip(line, 'not an append (-A) rule');
      continue;
    }
    if (table !== 'filter' && table !== 'nat') {
      skip(line, `table "${table}" is not imported`);
      continue;
    }
    const parsed = parseLine(tokenize(line));
    if (typeof parsed === 'string') {
      skip(line, parsed);
      continue;
    }
    const x = parsed;
    const fam = family;

    if (table === 'nat') {
      const proto = x.proto === 'tcp' || x.proto === 'udp' ? x.proto : 'any';
      if (x.chain === 'POSTROUTING' && x.target === 'MASQUERADE') {
        project.nat.push(newNat({ name: x.comment ?? 'Masquerade', kind: 'masquerade', iface: x.outIface, src: x.src, dst: x.dst, proto, randomFully: x.random }));
      } else if (x.chain === 'POSTROUTING' && x.target === 'SNAT' && x.to) {
        project.nat.push(newNat({ name: x.comment ?? 'SNAT', kind: 'snat', iface: x.outIface, src: x.src, dst: x.dst, proto, toAddr: x.to, randomFully: x.random }));
      } else if (x.chain === 'PREROUTING' && x.target === 'DNAT' && x.to) {
        const m = /^\[?([^\]]+?)\]?(?::([\d-]+))?$/.exec(x.to.includes('.') || x.to.startsWith('[') ? x.to : `[${x.to}]`);
        project.nat.push(newNat({ name: x.comment ?? 'Port forward', kind: 'dnat', iface: x.inIface, src: x.src, dst: stripHost(x.dst), proto, port: x.ports[0], toAddr: m?.[1] ?? x.to, toPort: m?.[2]?.replace('-', ':') }));
      } else {
        skip(line, 'NAT rule shape is not supported');
      }
      continue;
    }

    if (!(x.chain in DIR)) {
      skip(line, `chain ${x.chain} is not a built-in filter chain`);
      continue;
    }
    const direction = DIR[x.chain as keyof typeof DIR];
    const bare = !x.src && !x.dst && x.ports.length === 0 && !x.comment;

    // Recognise the standard preamble and fold it into project options.
    if (bare && !x.proto && (x.inIface === 'lo' || x.outIface === 'lo') && x.target === 'ACCEPT' && x.states.length === 0) {
      project.options.allowLoopback = true;
      continue;
    }
    if (bare && !x.proto && !x.inIface && !x.outIface && x.target === 'ACCEPT' && x.states.length > 0 && x.states.every((s) => s === 'related' || s === 'established')) {
      project.options.allowEstablished = true;
      continue;
    }
    if (bare && !x.proto && !x.inIface && x.target === 'DROP' && x.states.join() === 'invalid') {
      project.options.dropInvalid = true;
      continue;
    }
    const essential = fam === 'ipv4' ? x.icmpType === 'echo-request' : !!x.icmpType && ICMP6_ESSENTIAL.includes(x.icmpType);
    if (bare && (x.proto === 'icmp' || x.proto === 'ipv6-icmp' || x.proto === 'icmpv6') && essential && x.target === 'ACCEPT' && !x.inIface && !x.outIface && x.states.length === 0) {
      project.options.allowIcmp = true;
      continue;
    }
    if (x.target === 'LOG') {
      if (bare && !x.proto && !x.inIface && !x.outIface) project.options.logDropped = true;
      else pendingLog = JSON.stringify({ ...x, target: '', limit: x.limit, burst: x.burst });
      continue;
    }
    if (x.target !== 'ACCEPT' && x.target !== 'DROP' && x.target !== 'REJECT') {
      skip(line, `target ${x.target} is not supported`);
      pendingLog = null;
      continue;
    }

    let proto: Rule['proto'] = 'any';
    if (x.proto === 'tcp' || x.proto === 'udp') proto = x.proto;
    else if (x.proto === 'icmp' || x.proto === 'ipv6-icmp' || x.proto === 'icmpv6') proto = 'icmp';
    else if (x.proto && x.proto !== 'all') {
      skip(line, `protocol ${x.proto} is not supported`);
      pendingLog = null;
      continue;
    }
    const lm = x.limit ? /^(\d+)\/(sec|second|min|minute|hour)/.exec(x.limit) : null;
    const rule = newRule({
      name: x.comment ?? `${x.target.toLowerCase()} ${proto}${x.ports.length ? ` ${x.ports.join(',')}` : ''}`,
      direction,
      action: x.target.toLowerCase() as Rule['action'],
      proto,
      family: fam,
      src: x.src ? [stripHost(x.src)!] : [],
      dst: x.dst ? [stripHost(x.dst)!] : [],
      ports: x.ports,
      inIface: x.inIface,
      outIface: x.outIface,
      states: x.states.length > 0 ? (x.states as ConnState[]) : undefined,
      icmpType: x.icmpType,
      log: pendingLog === JSON.stringify({ ...x, target: '' }) ? true : undefined,
      rateLimit: lm
        ? { rate: Number(lm[1]), per: lm[2].startsWith('sec') ? 'second' : lm[2].startsWith('min') ? 'minute' : 'hour', burst: Number(x.burst ?? 5) }
        : undefined,
    });
    pendingLog = null;
    rules.push(rule);
  }

  // Merge rules that differ only by address: iptables expands one rule per source/destination pair.
  const merged: Rule[] = [];
  const shape = (r: Rule, omit: (keyof Rule)[]) => JSON.stringify({ ...r, id: '', ...Object.fromEntries(omit.map((k) => [k, null])) });
  for (const r of rules) {
    const prev = merged[merged.length - 1];
    if (prev && shape(prev, ['src']) === shape(r, ['src']) && r.src.length === 1) prev.src = [...new Set([...prev.src, ...r.src])];
    else if (prev && shape(prev, ['dst']) === shape(r, ['dst']) && r.dst.length === 1) prev.dst = [...new Set([...prev.dst, ...r.dst])];
    else merged.push(r);
  }
  // Fold IPv4 + IPv6 twins into one dual-stack rule, keeping IPv6-only rules in their original position.
  const final: Rule[] = merged.filter((r) => r.family === 'ipv4');
  let cursor = 0;
  for (const r of merged.filter((x) => x.family === 'ipv6')) {
    const idx = final.findIndex(
      (o, i) =>
        i >= cursor &&
        o.family === 'ipv4' &&
        shape(o, ['family', 'src', 'dst']) === shape(r, ['family', 'src', 'dst']) &&
        o.src.length > 0 === r.src.length > 0 &&
        o.dst.length > 0 === r.dst.length > 0,
    );
    if (idx >= 0) {
      const twin = final[idx];
      twin.family = 'both';
      twin.src = [...twin.src, ...r.src];
      twin.dst = [...twin.dst, ...r.dst];
      cursor = idx + 1;
    } else {
      final.splice(cursor, 0, r);
      cursor += 1;
    }
  }
  project.rules = final;
  project.options.ipv6 = sawV6 || final.some((r) => r.family !== 'ipv4');
  return { project, imported: final.length + project.nat.length, skipped };
}
