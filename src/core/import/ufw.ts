// Parses ufw commands ("ufw show added", scripts) and "ufw status verbose" tables.
import { emptyProject, newRule, type Direction, type Rule } from '../model';
import type { ImportReport } from './shared';

const ACTION = { allow: 'accept', deny: 'drop', reject: 'reject', limit: 'accept' } as const;

function words(line: string): string[] {
  const out: string[] = [];
  const re = /'([^']*)'|"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

const addr = (v: string | undefined) => (!v || /^(any|anywhere)$/i.test(v) ? [] : [v]);

function parseCommand(w: string[]): Rule | string {
  let i = 1;
  let direction: Direction = 'in';
  if (w[i] === 'route') {
    direction = 'forward';
    i += 1;
  }
  if (w[i] === 'insert') i += 2;
  if (w[i] === 'prepend') i += 1;
  const verb = w[i] as keyof typeof ACTION;
  if (!(verb in ACTION)) return `unsupported command "${w.slice(1, 3).join(' ')}"`;
  i += 1;
  const r = newRule({ name: '', direction, action: ACTION[verb], proto: 'any' });
  if (verb === 'limit') r.rateLimit = { rate: 6, per: 'minute', burst: 6, perSource: true };
  let simple: string | null = null;
  while (i < w.length) {
    const t = w[i];
    if (t === 'in' || t === 'out') {
      if (direction !== 'forward') r.direction = t === 'in' ? 'in' : 'out';
      if (w[i + 1] === 'on') {
        if (t === 'in') r.inIface = w[i + 2];
        else r.outIface = w[i + 2];
        i += 3;
      } else i += 1;
    } else if (t === 'log' || t === 'log-all') {
      r.log = true;
      i += 1;
    } else if (t === 'proto') {
      const p = w[i + 1];
      if (p !== 'tcp' && p !== 'udp') return `protocol ${p} is not supported`;
      r.proto = p;
      i += 2;
    } else if (t === 'from' || t === 'to') {
      const list = addr(w[i + 1]);
      if (t === 'from') r.src = list;
      else r.dst = list;
      i += 2;
      if (w[i] === 'port') {
        const ports = w[i + 1].split(',');
        if (t === 'from') r.srcPorts = ports;
        else r.ports = ports;
        i += 2;
      } else if (w[i] === 'app') return 'application profiles are not supported';
    } else if (t === 'comment') {
      r.name = w[i + 1] ?? '';
      i += 2;
    } else if (simple === null && /^[\d,:]+(\/(tcp|udp))?$/.test(t)) {
      simple = t;
      i += 1;
    } else return `not understood: "${t}"`;
  }
  if (simple) {
    const [ports, proto] = simple.split('/');
    r.ports = ports.split(',');
    r.proto = (proto as 'tcp' | 'udp') ?? 'tcpudp';
  }
  if (r.proto === 'any' && r.ports.length + (r.srcPorts?.length ?? 0) > 0) r.proto = 'tcpudp';
  const all = [...r.src, ...r.dst];
  if (all.some((a) => a === '0.0.0.0/0')) r.family = 'ipv4';
  if (all.some((a) => a === '::/0')) r.family = 'ipv6';
  r.src = r.src.filter((a) => a !== '0.0.0.0/0' && a !== '::/0');
  r.dst = r.dst.filter((a) => a !== '0.0.0.0/0' && a !== '::/0');
  if (!r.name) r.name = `${verb} ${r.proto}${r.ports.length ? ` ${r.ports.join(',')}` : ''}`;
  return r;
}

export function importUfw(text: string): ImportReport {
  const project = emptyProject('Imported from ufw');
  const skipped: ImportReport['skipped'] = [];
  const rules: Rule[] = [];
  const policy = (v: string) => (/allow/i.test(v) ? 'accept' : 'drop');

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || /^(set|sed|ufw (--force )?(reset|enable|reload)|ufw status|ufw logging|Status:|Logging:|New profiles:|To\s+Action|--\s)/.test(line)) {
      if (/^ufw logging (low|medium|high|full|on)/.test(line) || /^Logging: on/.test(line)) project.options.logDropped = true;
      continue;
    }
    let m: RegExpExecArray | null;
    if ((m = /^ufw default (\w+) (incoming|outgoing|routed)/.exec(line))) {
      project.policies[m[2] === 'incoming' ? 'in' : m[2] === 'outgoing' ? 'out' : 'forward'] = policy(m[1]);
      continue;
    }
    if ((m = /^Default: (\w+) \(incoming\), (\w+) \(outgoing\)(?:, (\w+) \(routed\))?/.exec(line))) {
      project.policies.in = policy(m[1]);
      project.policies.out = policy(m[2]);
      if (m[3]) project.policies.forward = policy(m[3]);
      continue;
    }
    if (line.startsWith('ufw ')) {
      const r = parseCommand(words(line));
      if (typeof r === 'string') skipped.push({ line, reason: r });
      else rules.push(r);
      continue;
    }
    // "ufw status" table row: To / Action / From
    if ((m = /^(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s{2,}(.+?)(?:\s+#\s*(.*))?$/.exec(line))) {
      const v6 = /\(v6\)/.test(m[1]) || /\(v6\)/.test(m[4]);
      const to = m[1].replace(/\s*\(v6\)/, '').trim();
      const from = m[4].replace(/\s*\(v6\)/, '').trim();
      const tm = /^(?:(\S+?)\s+)?([\d,:]+)(?:\/(tcp|udp))?(?: on (\S+))?$/.exec(to);
      const r = newRule({
        name: m[5] ?? '',
        direction: m[3] === 'OUT' ? 'out' : m[3] === 'FWD' ? 'forward' : 'in',
        action: ACTION[m[2].toLowerCase() as keyof typeof ACTION],
        proto: 'any',
        family: v6 ? 'ipv6' : 'ipv4',
        src: addr(from.split(' ')[0]),
      });
      if (tm) {
        r.ports = tm[2].split(',');
        r.proto = (tm[3] as 'tcp' | 'udp') ?? 'tcpudp';
        if (tm[1] && !/^anywhere$/i.test(tm[1])) r.dst = [tm[1]];
        if (tm[4]) r.inIface = tm[4];
      } else if (!/^anywhere/i.test(to)) {
        skipped.push({ line, reason: 'destination column is not a port list' });
        continue;
      }
      if (m[2] === 'LIMIT') r.rateLimit = { rate: 6, per: 'minute', burst: 6, perSource: true };
      if (!r.name) r.name = `${m[2].toLowerCase()} ${r.proto}${r.ports.length ? ` ${r.ports.join(',')}` : ''}`;
      // The status table lists IPv4 and "(v6)" rows separately: fold twins.
      const twin = rules.find((o) => o.family === 'ipv4' && v6 && JSON.stringify({ ...o, id: '', family: '' }) === JSON.stringify({ ...r, id: '', family: '' }));
      if (twin) twin.family = 'both';
      else rules.push(r);
      continue;
    }
    skipped.push({ line, reason: 'not a ufw command or status row' });
  }
  project.rules = rules;
  return { project, imported: rules.length, skipped };
}
