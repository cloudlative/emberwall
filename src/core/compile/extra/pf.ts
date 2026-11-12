// pf.conf for OpenBSD and FreeBSD.
//
// How Emberwall's model maps onto pf:
//  - pf is "last match wins" unless a rule says `quick`. Every rule here is `quick`, so the
//    first matching rule decides, as in Emberwall. The default policies are the only
//    non-quick rules.
//  - pf has no separate input and forward hooks: `pass in` sees both. On hosts that route
//    (forwarding on, forward rules or NAT present) packets for the firewall itself are tagged
//    EW_LOCAL first; inbound rules require the tag, forward rules require its absence and tag
//    what they accept EW_FWD so the packet may also leave on the far side.
//  - `pass` rules keep state, so replies never need a rule.
import type { NatRule, Project, Rule } from '../../model';
import { familyOf } from '../../net';
import { expandAddrs, resolveAll, shortId, slug, type ResolvedRule } from '../../resolve';
import { natFamily } from '../iptables';
import { BANNER, Diags, Out, type OutFile } from '../types';
import type { ExtraResult } from './index';

export type PfFlavor = 'openbsd' | 'freebsd';
export interface PfOptions {
  flavor?: PfFlavor;
}

type Fam = 'ipv4' | 'ipv6';

const TAG_LOCAL = 'EW_LOCAL';
const TAG_FWD = 'EW_FWD';
const BRUTE = 'bruteforce';
const LOCAL = 'ew_local';

/** Emberwall ICMP type names in pfctl spelling (same names for icmp-type and icmp6-type). */
const ICMP_NAME: Record<string, string> = {
  'echo-request': 'echoreq',
  'echo-reply': 'echorep',
  'destination-unreachable': 'unreach',
  'time-exceeded': 'timex',
  'parameter-problem': 'paramprob',
};
/** What IPv6 needs to work: errors, ping, router and neighbour discovery. */
const ICMP6_ESSENTIAL = ['unreach', 'toobig', 'timex', 'paramprob', 'echoreq', 'routersol', 'routeradv', 'neighbrsol', 'neighbradv'];

const PER_SECONDS = { second: 1, minute: 60, hour: 3600 } as const;

function comment(text: string): string {
  return `# ${text.replace(/[\r\n\\]+/g, ' ').trim()}`;
}

function list(items: string[]): string {
  return items.length === 1 ? items[0] : `{ ${items.join(' ')} }`;
}

function join(parts: (string | false | undefined | null)[]): string {
  return parts.filter(Boolean).join(' ');
}

class Ctx {
  d = new Diags();
  /** Linux interface name -> macro name, with the rule that first used it. */
  macros = new Map<string, { macro: string; ruleId?: string }>();
  /** Address group id -> table. */
  tables = new Map<string, { name: string; members: string[]; ruleId?: string }>();
  bruteRule: string | undefined;
  needBrute = false;
  /** Out-side lines for forward rules that name an outbound interface. */
  fwdOut: { text: string; ruleId: string }[] = [];

  constructor(readonly p: Project, readonly flavor: PfFlavor, readonly router: boolean) {}

  iface(name: string, ruleId?: string): string {
    let m = this.macros.get(name);
    if (!m) {
      let macro = `if_${name.replace(/[^A-Za-z0-9_]/g, '_')}`;
      const taken = new Set([...this.macros.values()].map((x) => x.macro));
      while (taken.has(macro)) macro += '_';
      m = { macro, ruleId };
      this.macros.set(name, m);
      if (/[+*]/.test(name)) {
        this.d.fallback(`Interface "${name}" is a wildcard: pf has no wildcards, set the macro $${macro} to an interface group instead.`, ruleId);
      }
    }
    return `$${m.macro}`;
  }

  /** A table reference when the list is exactly one address group, else null. */
  table(raw: string[], ruleId: string): string | null {
    if (raw.length !== 1 || !raw[0].startsWith('@')) return null;
    const g = this.p.addressGroups.find((x) => x.id === raw[0].slice(1));
    if (!g) return null;
    let t = this.tables.get(g.id);
    if (!t) {
      const members = expandAddrs(g.members, this.p).filter((a) => this.p.options.ipv6 || familyOf(a) === 'ipv4');
      if (members.length === 0) return null;
      let name = `ew_${slug(g.name, 20).replace(/-/g, '_')}`;
      const taken = new Set([...this.tables.values()].map((x) => x.name));
      if (taken.has(name) || name === LOCAL) name = `${name}_${shortId(g.id)}`.slice(0, 31);
      t = { name, members, ruleId };
      this.tables.set(g.id, t);
    }
    return `<${t.name}>`;
  }
}

/** Reports what pf cannot match. Returns false when the rule must be left out. */
function expressible(rr: ResolvedRule, c: Ctx): boolean {
  const r = rr.rule;
  const d = c.d;
  const skip = (what: string) => {
    d.unsupported(`"${r.name}": ${what}. The rule is not in pf.conf.`, r.id);
    return false;
  };
  if (r.srcMac) return skip('pf filters at the IP layer and cannot match a source MAC address');
  if (r.mark) return skip('packet marks are a Linux netfilter concept; pf has tags, which are not interchangeable');
  if (r.schedule) return skip('pf has no time-of-day match (load a different ruleset from cron instead)');
  if (r.states && r.states.length > 0) {
    if (!r.states.includes('new')) {
      if (r.action === 'accept' && r.states.every((s) => s === 'established' || s === 'related')) {
        d.note(`"${r.name}": pf passes packets of established connections through its state table without a rule, so this rule is left out.`, r.id);
        return false;
      }
      return skip(`pf cannot match connection state ${r.states.join(',')} in a rule`);
    }
    if (r.states.length > 1) d.note(`"${r.name}": only the "new" state is matched by the pf rule; packets of existing states never reach the ruleset.`, r.id);
  }
  if (r.direction === 'forward' && r.action !== 'accept' && r.outIface) {
    return skip('a forward rule that blocks by outbound interface cannot be expressed, because pf decides on the inbound side before the route is known');
  }
  return true;
}

function ruleLines(rr: ResolvedRule, c: Ctx): string[] {
  const r = rr.rule;
  const d = c.d;
  const accept = r.action === 'accept';
  const dir = r.direction === 'out' ? 'out' : 'in';
  const ifName = r.direction === 'out' ? r.outIface : r.inIface;
  const on = ifName ? `on ${c.iface(ifName, r.id)}` : '';
  const srcTable = c.table(r.src, r.id);
  const dstTable = c.table(r.dst, r.id);

  let tagging = '';
  if (c.router && r.direction === 'in') tagging = `tagged ${TAG_LOCAL}`;
  if (c.router && r.direction === 'forward') {
    tagging = `! tagged ${TAG_LOCAL}`;
    if (accept) {
      if (r.outIface) {
        const tag = `EW_F_${shortId(r.id)}`;
        tagging += ` tag ${tag}`;
        if (!c.fwdOut.some((x) => x.ruleId === r.id)) {
          c.fwdOut.push({ text: `pass out quick on ${c.iface(r.outIface, r.id)} all tagged ${tag} keep state`, ruleId: r.id });
          c.fwdOut.push({ text: `block drop out quick all tagged ${tag}`, ruleId: r.id });
          d.fallback(`"${r.name}": pf decides on the inbound side, before the route is known. Packets matching this rule that would leave through an interface other than ${r.outIface} are dropped instead of being checked against later rules.`, r.id);
        }
      } else {
        tagging += ` tag ${TAG_FWD}`;
      }
    }
  }
  if (!accept && (r.rateLimit || r.connLimit)) {
    d.note(`"${r.name}": rate and connection limits only apply to accept rules; ignored on this ${r.action} rule.`, r.id);
  }

  const perFam: Record<Fam, string[]> = { ipv4: [], ipv6: [] };
  for (const fam of ['ipv4', 'ipv6'] as const) {
    const view = fam === 'ipv4' ? rr.v4 : rr.v6;
    if (!view) continue;
    for (const proto of rr.protos) {
      let protoText = '';
      let icmp = '';
      if (proto === 'icmp') {
        protoText = fam === 'ipv4' ? 'proto icmp' : 'proto icmp6';
        if (r.icmpType) {
          const name = ICMP_NAME[r.icmpType] ?? (/^\d{1,3}$/.test(r.icmpType) ? r.icmpType : null);
          if (!name) {
            d.unsupported(`"${r.name}": ICMP type "${r.icmpType}" has no pf name known to Emberwall. The rule is not in pf.conf.`, r.id);
            continue;
          }
          icmp = `${fam === 'ipv4' ? 'icmp-type' : 'icmp6-type'} ${name}`;
        }
      } else if (proto !== 'any') {
        protoText = `proto ${proto}`;
      }
      const hasPorts = proto === 'tcp' || proto === 'udp';
      const sport = hasPorts && rr.srcPorts.length > 0 ? ` port ${list(rr.srcPorts)}` : '';
      const dport = hasPorts && rr.ports.length > 0 ? ` port ${list(rr.ports)}` : '';
      const hosts = (table: string | null, addrs: string[]) => table ?? (addrs.length === 0 ? 'any' : addrs.length === 1 ? addrs[0] : `{ ${addrs.join(', ')} }`);
      const src = hosts(srcTable, view.src);
      const dst = hosts(dstTable, view.dst);

      let state = '';
      if (accept) {
        const opts: string[] = [];
        if (r.connLimit) {
          if (proto === 'tcp') opts.push(`max-src-conn ${r.connLimit}`);
          else {
            opts.push(`max-src-states ${r.connLimit}`);
            d.fallback(`"${r.name}": pf counts connections per client only for TCP; for ${proto === 'any' ? 'other protocols' : proto.toUpperCase()} the limit is applied to state entries (max-src-states), and clients over it are not added to <${BRUTE}>.`, r.id);
          }
        }
        if (r.rateLimit) {
          if (r.rateLimit.perSource && proto === 'tcp') {
            opts.push(`max-src-conn-rate ${r.rateLimit.rate}/${PER_SECONDS[r.rateLimit.per]}`);
            d.fallback(`"${r.name}": the per-client rate becomes max-src-conn-rate ${r.rateLimit.rate}/${PER_SECONDS[r.rateLimit.per]} (new TCP connections, moving average); the burst of ${r.rateLimit.burst} has no pf equivalent.`, r.id);
          } else if (r.rateLimit.perSource) {
            d.unsupported(`"${r.name}": pf can rate-limit per client only for TCP connections. The ${proto === 'any' ? 'non-TCP part of the' : proto.toUpperCase()} rule is emitted WITHOUT the limit.`, r.id);
          } else {
            d.unsupported(`"${r.name}": pf has no rate limit shared by all clients of a rule (only per-client max-src-conn-rate). The rule is emitted WITHOUT the limit.`, r.id);
          }
        }
        if (opts.some((o) => o.startsWith('max-src-conn'))) {
          opts.push(`overload <${BRUTE}> flush`);
          c.needBrute = true;
          c.bruteRule ??= r.id;
          d.fallback(`"${r.name}": a client over the limit is added to the <${BRUTE}> table and then blocked on every port until removed (Linux only refuses the excess connections). Expire entries from cron: pfctl -t ${BRUTE} -T expire 3600`, r.id);
        }
        state = opts.length > 0 ? `keep state (${opts.join(', ')})` : 'keep state';
      }

      perFam[fam].push(
        join([
          accept ? 'pass' : r.action === 'drop' ? 'block drop' : 'block return',
          dir,
          r.log && 'log',
          'quick',
          on,
          '\u0000',
          protoText,
          `from ${src}${sport}`,
          `to ${dst}${dport}`,
          icmp,
          tagging,
          state,
        ]),
      );
    }
  }
  const af = (lines: string[], word: string) => lines.map((l) => l.replace('\u0000', word).replace(/  +/g, ' '));
  // Identical for both families (no family-specific address or protocol): one rule without inet/inet6.
  if (rr.v4 && rr.v6 && perFam.ipv4.length > 0 && perFam.ipv4.join('\n') === perFam.ipv6.join('\n')) return af(perFam.ipv4, '');
  return [...af(perFam.ipv4, 'inet'), ...af(perFam.ipv6, 'inet6')];
}

function natRuleLines(n: NatRule, c: Ctx): string[] {
  const d = c.d;
  const fam = natFamily(n);
  if (fam === 'ipv6' && !c.p.options.ipv6) {
    d.note(`"${n.name}": IPv6 is switched off in this project, NAT rule left out.`, n.id);
    return [];
  }
  const af = fam === 'ipv4' ? 'inet' : 'inet6';
  const proto = n.proto !== 'any' ? `proto ${n.proto}` : '';
  const on = n.iface ? `on ${c.iface(n.iface, n.id)}` : '';
  const from = `from ${n.src || 'any'}`;
  if (n.randomFully) d.note(`"${n.name}": pf already randomises translated source ports; "fully random" needs no option.`, n.id);

  if (n.kind === 'dnat') {
    if (!n.toAddr) {
      d.invalid(`Port forward "${n.name}" has no destination address`, n.id);
      return [];
    }
    if (n.port && n.proto === 'any') {
      d.invalid(`Port forward "${n.name}" matches a port, so it needs TCP or UDP`, n.id);
      return [];
    }
    const to = `to ${n.dst || 'any'}${n.port ? ` port ${n.port}` : ''}`;
    // A range maps one-to-one from its first port: "port 4000:*".
    const toPort = n.toPort ? ` port ${n.toPort.includes(':') ? `${n.toPort.split(':')[0]}:*` : n.toPort}` : '';
    if (!c.router) d.note(`"${n.name}": a port forward also needs a forward rule that accepts the traffic, and routing switched on.`, n.id);
    return c.flavor === 'openbsd'
      ? [join(['match in', on, af, proto, from, to, `rdr-to ${n.toAddr}${toPort}`])]
      : [join(['rdr', on, af, proto, from, to, `-> ${n.toAddr}${toPort}`])];
  }

  const to = `to ${n.dst || 'any'}`;
  let target: string;
  if (n.kind === 'snat') {
    if (!n.toAddr) {
      d.invalid(`SNAT rule "${n.name}" has no source address to translate to`, n.id);
      return [];
    }
    target = n.toAddr;
  } else {
    if (!n.iface) {
      d.unsupported(`"${n.name}": masquerading in pf translates to the address of a named interface; set the outbound interface. The NAT rule is not in pf.conf.`, n.id);
      return [];
    }
    // Parentheses: pf follows the interface's address when it changes (DHCP).
    target = `(${c.iface(n.iface, n.id)})`;
  }
  return c.flavor === 'openbsd'
    ? [join(['match out', on, af, proto, from, to, `nat-to ${target}`])]
    : [join(['nat', on, af, proto, from, to, `-> ${target}`])];
}

export function compilePf(p: Project, opts: PfOptions = {}): ExtraResult {
  const flavor: PfFlavor = opts.flavor ?? 'openbsd';
  const rules = resolveAll(p);
  const nats = p.nat.filter((n) => n.enabled);
  const router = p.options.forwarding || nats.length > 0 || rules.some((r) => r.rule.direction === 'forward');
  const c = new Ctx(p, flavor, router);
  const d = c.d;
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));

  // Bodies first: they decide which macros and tables the header has to declare.
  const body = new Out();
  let lastId = '';
  for (const rr of rules) {
    const r: Rule = rr.rule;
    if (!expressible(rr, c)) continue;
    const lines = ruleLines(rr, c);
    if (lines.length === 0) continue;
    if (r.id !== lastId) body.push(comment(`${r.name || r.id}${r.comment ? ` - ${r.comment}` : ''}`), r.id);
    lastId = r.id;
    lines.forEach((l) => body.push(l, r.id));
  }
  const nat = new Out();
  for (const n of nats) {
    const lines = natRuleLines(n, c);
    if (lines.length === 0) continue;
    nat.push(comment(n.name || n.id), n.id);
    lines.forEach((l) => nat.push(l, n.id));
  }

  const opt = p.options;
  const pr = p.protections ?? {};
  const log = opt.logDropped ? ' log' : '';
  const local = router ? ` tagged ${TAG_LOCAL}` : '';
  const o = new Out();
  o.push(`# ${BANNER} - ${p.name.replace(/[\r\n]+/g, ' ')}`);
  o.push(`# Target: pf on ${flavor === 'openbsd' ? 'OpenBSD (match ... nat-to / rdr-to syntax)' : 'FreeBSD (nat on / rdr on syntax)'}`);
  o.push('# Check: pfctl -nf /etc/pf.conf      Load: pfctl -f /etc/pf.conf      Enable: pfctl -e');
  o.push('# Every rule is "quick": the first matching rule decides, in the order shown in Emberwall.');

  if (c.macros.size > 0) {
    o.blank();
    o.push('# Interfaces. The names come from the Emberwall project (Linux names):');
    o.push('# change the right-hand side to the interface names of this host (see ifconfig).');
    for (const [name, m] of c.macros) o.push(`${m.macro} = "${name.replace(/"/g, '')}"`, m.ruleId);
  }

  if (c.tables.size > 0 || c.needBrute || router) {
    o.blank();
    for (const t of c.tables.values()) o.push(`table <${t.name}> const { ${t.members.join(', ')} }`, t.ruleId);
    if (c.needBrute) o.push(`table <${BRUTE}> persist`, c.bruteRule);
    if (router) {
      o.push('# Addresses that mean "this host". "self" is read when the ruleset loads: reload after an address change.');
      o.push(`table <${LOCAL}> const { self, 255.255.255.255, 224.0.0.0/4${opt.ipv6 ? ', ff00::/8' : ''} }`);
    }
  }

  o.blank();
  if (opt.allowLoopback) o.push(`set skip on ${flavor === 'openbsd' ? 'lo' : 'lo0'}`);
  else d.note('Loopback traffic is filtered like any other (no "set skip on lo"): local services need their own rules.');

  if (nat.lines.length > 0) {
    o.blank();
    o.push(flavor === 'openbsd' ? '# Address translation. Later rules see the translated addresses.' : '# Address translation. Runs before filtering: filter rules see the translated addresses.');
    o.add(nat.lines);
  }

  o.blank();
  o.push('# Default policies: the only rules without "quick", so they apply when nothing below matches.');
  o.push(p.policies.in === 'drop' ? `block drop in${log} all` : 'pass in all');
  o.push(p.policies.out === 'drop' ? `block drop out${log} all` : 'pass out all');
  if (!opt.ipv6) {
    o.push('# IPv6 is switched off in this project.');
    o.push('block drop quick inet6 all');
  }

  if (router) {
    o.blank();
    o.push('# Routing host: mark packets addressed to the firewall itself. Rules for inbound traffic need');
    o.push(`# the ${TAG_LOCAL} tag; forward rules need its absence and tag what they accept.`);
    o.push(`match in from any to <${LOCAL}> tag ${TAG_LOCAL}`);
    o.push('# Forwarded packets already accepted on the way in may leave.');
    for (const l of c.fwdOut) o.push(l.text, l.ruleId);
    o.push(`pass out quick all tagged ${TAG_FWD} keep state`);
  }

  if (c.needBrute) {
    o.blank();
    o.push('# Clients that exceeded a per-client limit. Expire from cron: pfctl -t bruteforce -T expire 3600');
    o.push(`block drop in quick from <${BRUTE}> to any`, c.bruteRule);
  }

  if (pr.portScan) {
    o.blank();
    o.push('# TCP flag combinations only scanners send.');
    for (const flags of ['/FSRPAU', 'FSRPAU/FSRPAU', 'FPU/FSRPAU', 'FS/FS', 'SR/SR']) o.push(`block drop in quick proto tcp all flags ${flags}`);
  }
  if (pr.synFlood) d.unsupported('SYN flood guard: pf has no standalone per-client SYN rate rule. Use "synproxy state" or a per-client rate limit on the affected rules. Nothing was emitted for it.');
  if (pr.autoBan && pr.autoBan.ports.length > 0) d.unsupported('Auto-ban trap ports: pf can only add clients to a table after a completed TCP handshake (overload), not from a blocked packet. Nothing was emitted for it.');

  if (opt.allowIcmp) {
    o.blank();
    o.push('# Ping, and the ICMPv6 messages IPv6 cannot work without.');
    const dirs = p.policies.out === 'drop' ? ['in', 'out'] : ['in'];
    for (const dir of dirs) {
      const t = dir === 'in' ? local : '';
      o.push(`pass ${dir} quick inet proto icmp all icmp-type echoreq${t} keep state`);
      if (opt.ipv6) o.push(`pass ${dir} quick inet6 proto icmp6 all icmp6-type { ${ICMP6_ESSENTIAL.join(' ')} }${t} keep state`);
    }
  }

  if (body.lines.length > 0) {
    o.blank();
    o.push('# Rules');
    o.add(body.lines);
  }

  if (router) {
    o.blank();
    o.push(`# Forward policy: everything not addressed to this host that no rule above decided.`);
    o.push(p.policies.forward === 'drop' ? `block drop in${log} quick all ! tagged ${TAG_LOCAL}` : `pass in quick all ! tagged ${TAG_LOCAL} tag ${TAG_FWD} keep state`);
  }

  // Notes on what differs from the Linux tools.
  d.note('pf evaluates "last match wins"; every generated rule uses "quick" so the first match decides, as in Emberwall.');
  d.note(
    flavor === 'openbsd'
      ? 'NAT uses the OpenBSD syntax (match ... nat-to / rdr-to). FreeBSD 14 and older need "nat on" / "rdr on" rules: use the "pf (FreeBSD)" target there.'
      : 'NAT uses the FreeBSD syntax ("nat on" / "rdr on", placed before the filter rules). OpenBSD removed it in 4.7: use the "pf (OpenBSD)" target there.',
  );
  if (c.macros.size > 0) d.note('Interface names are macros at the top of pf.conf, filled with the names from the project. BSD interfaces are named differently (em0, vtnet0, ...): edit them before loading.');
  d.note('pf "pass" rules keep state: replies and related ICMP errors are allowed without a rule, and packets that fit no state are not matched by pass rules. "Allow established" and "drop invalid" need no rules of their own.');
  if (!opt.allowEstablished) d.fallback('"Allow established connections" is off in the project, but pf pass rules are always stateful: replies to accepted connections are allowed anyway.');
  if (opt.logDropped || rules.some((r) => r.rule.log)) d.note('Logged packets go to the pflog0 interface in pcap format (tcpdump -n -e -ttt -r /var/log/pflog), not to syslog. Log prefixes and log rate limits do not exist in pf.');
  if (router) {
    d.note(`Forwarding must be enabled outside pf.conf: ${flavor === 'openbsd' ? 'sysctl net.inet.ip.forwarding=1 (and net.inet6.ip6.forwarding=1) in /etc/sysctl.conf' : 'gateway_enable="YES" (and ipv6_gateway_enable="YES") in /etc/rc.conf'}.`);
    d.note(`Inbound and forwarded traffic are told apart with the <${LOCAL}> table ("self", broadcast and multicast). Directed subnet broadcasts (for example 192.168.1.255) are not in it and are treated as forwarded.`);
  } else if (p.policies.forward === 'accept') {
    d.note('The host does not route (forwarding is off, no forward or NAT rules), so pf.conf has no forward section.');
  }

  const file: OutFile = {
    name: 'pf.conf',
    path: '/etc/pf.conf',
    lang: 'conf',
    description: `pf ruleset for ${flavor === 'openbsd' ? 'OpenBSD' : 'FreeBSD'}`,
    lines: o.lines,
  };
  return { files: [file], diagnostics: d.list };
}
