// Parses `nft list ruleset` output (and Emberwall's own .nft files) into a project.
import { emptyProject, newNat, newRule, type ConnState, type Direction, type Project, type Rule } from '../model';
import { familyOf } from '../net';
import { baselineOff, foldBaseline, type ImportReport } from './shared';

const HOOK_DIR: Record<string, Direction> = { input: 'in', output: 'out', forward: 'forward' };

function list(v: string): string[] {
  const t = v.trim();
  const inner = t.startsWith('{') ? t.slice(1, t.lastIndexOf('}')) : t;
  return inner.split(',').map((x) => x.trim().replace(/^"|"$/g, '')).filter(Boolean);
}

const VALUE = String.raw`(\{[^}]*\}|@[\w-]+|"[^"]*"|[^\s]+)`;

interface Ctx {
  project: Project;
  sets: Map<string, string>;
  skip: (line: string, reason: string) => void;
}

/** Consumes a rule expression left to right. Returns a reason string when something is not understood. */
function parseRule(text: string, direction: Direction, ctx: Ctx): { rule: Rule; iif?: string; icmp6Set?: boolean } | string {
  let rest = text.trim();
  const r = newRule({ name: '', direction, proto: 'any', action: 'accept' });
  let verdict = false;
  let iif: string | undefined;
  let icmp6Set = false;
  let fam: 'ipv4' | 'ipv6' | null = null;
  const eat = (re: RegExp): RegExpExecArray | null => {
    const m = re.exec(rest);
    if (m) rest = rest.slice(m[0].length).trimStart();
    return m;
  };
  const addrs = (v: string): string[] | string => {
    if (v.startsWith('@')) {
      const id = ctx.sets.get(v.slice(1));
      return id ? [`@${id}`] : `unknown set ${v}`;
    }
    return list(v);
  };
  const ports = (v: string) => list(v).map((p) => p.replace('-', ':'));
  let guard = 0;
  while (rest && (guard += 1) < 60) {
    let m: RegExpExecArray | null;
    if ((m = eat(new RegExp(`^(iifname|iif|oifname|oif) ${VALUE}`)))) {
      const name = list(m[2])[0];
      if (m[1].startsWith('i')) {
        iif = name;
        if (direction !== 'out') r.inIface = name;
      } else if (direction !== 'in') r.outIface = name;
      else iif = iif ?? name;
    } else if ((m = eat(new RegExp(`^(ip6?) (saddr|daddr) ${VALUE}`)))) {
      const a = addrs(m[3]);
      if (typeof a === 'string') return a;
      fam = m[1] === 'ip' ? 'ipv4' : 'ipv6';
      if (m[2] === 'saddr') r.src.push(...a);
      else r.dst.push(...a);
    } else if ((m = eat(/^meta nfproto (ipv4|ipv6)/))) fam = m[1] as 'ipv4' | 'ipv6';
    else if ((m = eat(/^meta l4proto \{\s*tcp\s*,\s*udp\s*\}/))) r.proto = 'tcpudp';
    else if ((m = eat(/^meta l4proto (tcp|udp)/))) r.proto = m[1] as 'tcp' | 'udp';
    else if ((m = eat(/^meta l4proto (ipv6-icmp|icmpv6|icmp)/))) r.proto = 'icmp';
    else if ((m = eat(/^ip protocol icmp/))) {
      r.proto = 'icmp';
      fam = 'ipv4';
    } else if ((m = eat(new RegExp(`^(tcp|udp|th) (dport|sport) ${VALUE}`)))) {
      if (m[1] !== 'th') r.proto = m[1] as 'tcp' | 'udp';
      if (m[2] === 'dport') r.ports.push(...ports(m[3]));
      else r.srcPorts = [...(r.srcPorts ?? []), ...ports(m[3])];
    } else if ((m = eat(new RegExp(`^(icmpv6|icmp) type ${VALUE}`)))) {
      r.proto = 'icmp';
      fam = m[1] === 'icmp' ? 'ipv4' : 'ipv6';
      const types = list(m[2]);
      if (types.length > 1) icmp6Set = true;
      r.icmpType = types[0];
    } else if ((m = eat(/^ct state ([\w,]+|\{[^}]*\})/))) r.states = list(m[1]) as ConnState[];
    else if ((m = eat(/^limit rate (\d+)\/(second|minute|hour)(?: burst (\d+) packets)?/))) {
      r.rateLimit = { rate: Number(m[1]), per: m[2] as 'second' | 'minute' | 'hour', burst: Number(m[3] ?? 5) };
    } else if ((m = eat(/^ether saddr ([0-9a-f:]{17})/i))) r.srcMac = m[1];
    else if ((m = eat(/^meta mark (0x[0-9a-f]+|\d+)/i))) r.mark = m[1];
    else if ((m = eat(/^counter(?: packets \d+ bytes \d+)?/))) continue;
    else if ((m = eat(/^log(?: prefix "[^"]*")?(?: level \w+)?(?: flags [\w ]+?(?= accept| drop| reject|$))?/))) r.log = true;
    else if ((m = eat(/^comment "([^"]*)"/))) r.name = m[1];
    else if ((m = eat(/^(accept|drop)\b/))) {
      r.action = m[1] as 'accept' | 'drop';
      verdict = true;
    } else if ((m = eat(/^reject(?: with [\w -]+?(?= comment|$))?/))) {
      r.action = 'reject';
      verdict = true;
    } else return `not understood: "${rest.slice(0, 40)}"`;
  }
  if (!verdict) return r.log ? 'log-only rule' : 'rule has no accept/drop/reject verdict';
  if (fam && r.src.length + r.dst.length === 0) r.family = fam;
  else if (fam && [...r.src, ...r.dst].every((a) => a.startsWith('@') || familyOf(a) === fam)) r.family = [...r.src, ...r.dst].some((a) => a.startsWith('@')) ? 'both' : fam;
  if (!r.name) r.name = `${r.action} ${r.proto}${r.ports.length ? ` ${r.ports.join(',')}` : ''}`;
  if (r.srcPorts && r.srcPorts.length === 0) delete r.srcPorts;
  return { rule: r, iif, icmp6Set };
}

/** Tables in a ruleset that have a filter chain attached to input, forward or output. */
export function filterTables(text: string): string[] {
  const out: string[] = [];
  let table = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const t = /^table (\w+) ([\w-]+) \{$/.exec(line);
    if (t) table = `${t[1]} ${t[2]}`;
    else if (table && /^type filter hook (input|forward|output) /.test(line) && !out.includes(table)) out.push(table);
  }
  return out;
}

/**
 * @param onlyTable "family name" of the one table to read (e.g. "inet emberwall"); others are skipped.
 */
export function importNft(text: string, onlyTable?: string): ImportReport {
  const project = baselineOff(emptyProject('Imported from nftables'));
  const skipped: ImportReport['skipped'] = [];
  const ctx: Ctx = { project, sets: new Map(), skip: (line, reason) => skipped.push({ line, reason }) };
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  let chain: { dir?: Direction; nat?: 'prerouting' | 'postrouting'; name: string } | null = null;
  let setName: string | null = null;
  let setBuf = '';
  let depth = 0;
  let sawV6 = false;
  let ignoring = false;
  const rules: Rule[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line || line.startsWith('#') || /^(add|delete|destroy|flush) /.test(line)) continue;
    let m: RegExpExecArray | null;
    if ((m = /^table (\w+) ([\w-]+) \{$/.exec(line))) {
      depth = 1;
      ignoring = !!onlyTable && `${m[1]} ${m[2]}` !== onlyTable;
      continue;
    }
    if (ignoring) continue;
    if ((m = /^set ([\w-]+) \{$/.exec(line))) {
      setName = m[1];
      setBuf = '';
      depth += 1;
      continue;
    }
    if ((m = /^chain ([\w-]+) \{$/.exec(line))) {
      chain = { name: m[1] };
      depth += 1;
      continue;
    }
    if (line === '}') {
      if (setName) {
        const em = /elements\s*=\s*\{([^}]*)\}/.exec(setBuf);
        if (em) {
          const id = setName.replace(/_v[46]$/, '');
          const members = em[1].split(',').map((x) => x.trim()).filter(Boolean);
          const existing = project.addressGroups.find((g) => g.id === id);
          if (existing) existing.members.push(...members);
          else project.addressGroups.push({ id, name: id.replace(/_/g, ' '), members });
          ctx.sets.set(setName, id);
        }
        setName = null;
      } else if (chain) chain = null;
      depth -= 1;
      continue;
    }
    if (setName) {
      setBuf += ` ${line}`;
      continue;
    }
    if (!chain) {
      if (!/^comment /.test(line)) ctx.skip(line, 'outside a chain');
      continue;
    }
    if ((m = /^type (\w+) hook (\w+) priority [^;]+;(?: policy (accept|drop);)?/.exec(line))) {
      if (m[1] === 'filter' && HOOK_DIR[m[2]]) {
        chain.dir = HOOK_DIR[m[2]];
        if (m[3]) project.policies[chain.dir] = m[3] as 'accept' | 'drop';
      } else if (m[1] === 'nat' && (m[2] === 'prerouting' || m[2] === 'postrouting')) chain.nat = m[2];
      continue;
    }
    if (/^policy (accept|drop);?$/.test(line) && chain.dir) {
      project.policies[chain.dir] = /accept/.test(line) ? 'accept' : 'drop';
      continue;
    }
    if (chain.nat) {
      const name = /comment "([^"]*)"/.exec(line)?.[1];
      const iface = /(?:iifname|oifname) "([^"]+)"/.exec(line)?.[1];
      const src = /ip6? saddr (\S+)/.exec(line)?.[1];
      const dst = /ip6? daddr (\S+)/.exec(line)?.[1];
      const pm = /(tcp|udp) dport (\S+)/.exec(line);
      const proto = (pm?.[1] ?? /meta l4proto (tcp|udp)/.exec(line)?.[1] ?? 'any') as 'tcp' | 'udp' | 'any';
      if (/\bmasquerade\b/.test(line)) project.nat.push(newNat({ name: name ?? 'Masquerade', kind: 'masquerade', iface, src, dst, proto, randomFully: /fully-random/.test(line) || undefined }));
      else if ((m = /\bsnat (?:ip6? )?to (\S+)/.exec(line))) project.nat.push(newNat({ name: name ?? 'SNAT', kind: 'snat', iface, src, dst, proto, toAddr: m[1], randomFully: /fully-random/.test(line) || undefined }));
      else if ((m = /\bdnat (?:ip6? )?to (\S+)/.exec(line))) {
        const t = /^\[?([0-9a-f:.]+?)\]?(?::([\d-]+))?$/i.exec(m[1].includes('.') || m[1].startsWith('[') ? m[1] : `[${m[1]}]`);
        project.nat.push(newNat({ name: name ?? 'Port forward', kind: 'dnat', iface, src, dst, proto, port: pm?.[2].replace('-', ':'), toAddr: t?.[1] ?? m[1], toPort: t?.[2]?.replace('-', ':') }));
      } else ctx.skip(line, 'NAT rule shape is not supported');
      continue;
    }
    if (!chain.dir) {
      ctx.skip(line, `chain "${chain.name}" is not a base filter chain`);
      continue;
    }
    if (/^limit rate \d+\/\w+(?: burst \d+ packets)? log prefix/.test(line)) {
      project.options.logDropped = true;
      continue;
    }
    if (/^meta nfproto ipv6 drop/.test(line)) {
      project.options.ipv6 = false;
      continue;
    }
    const parsed = parseRule(line, chain.dir, ctx);
    if (typeof parsed === 'string') {
      ctx.skip(line, parsed);
      continue;
    }
    const { rule, iif, icmp6Set } = parsed;
    if (rule.family === 'ipv6' || rule.src.concat(rule.dst).some((a) => a.includes(':'))) sawV6 = true;
    const bareIcmp = rule.proto === 'icmp' && rule.action === 'accept' && rule.src.length + rule.dst.length === 0 && !rule.inIface && !/comment "/.test(line);
    if (bareIcmp && (icmp6Set || rule.icmpType === 'echo-request')) {
      project.options.allowIcmp = true;
      if (icmp6Set) sawV6 = true;
      continue;
    }
    if (!/comment "/.test(line) && foldBaseline(project, rule, { iif })) continue;
    rules.push(rule);
  }

  // Emberwall writes one line per family for address-pinned rules: fold v4/v6 twins back together.
  const out: Rule[] = [];
  const shape = (r: Rule) => JSON.stringify({ ...r, id: '', family: '', src: [], dst: [] });
  for (const r of rules) {
    const prev = out[out.length - 1];
    if (prev && prev.family === 'ipv4' && r.family === 'ipv6' && shape(prev) === shape(r) && prev.src.length > 0 === r.src.length > 0 && prev.dst.length > 0 === r.dst.length > 0) {
      prev.family = 'both';
      prev.src = [...new Set([...prev.src, ...r.src])];
      prev.dst = [...new Set([...prev.dst, ...r.dst])];
    } else if (prev && r.proto !== 'tcpudp' && prev.proto !== r.proto && JSON.stringify({ ...prev, id: '', proto: '' }) === JSON.stringify({ ...r, id: '', proto: '' }) && ['tcp', 'udp'].includes(prev.proto) && ['tcp', 'udp'].includes(r.proto)) {
      prev.proto = 'tcpudp';
    } else out.push(r);
  }
  project.rules = out;
  if (project.options.ipv6) project.options.ipv6 = sawV6 || out.some((r) => r.family === 'both');
  void depth;
  return { project, imported: out.length + project.nat.length, skipped };
}
