import type { NatRule, Project, Rule } from '../model';
import { familyOf } from '../net';
import { expandAddrs, resolveAll, shortId, slug, type ResolvedRule } from '../resolve';
import type { Target } from '../targets';
import { safeApplyScript } from './apply';
import { activeLists, blocklistUpdater } from './blocklists';
import { sysctlFile } from '../sysctl';
import { logPrefix, natFamily } from './iptables';
import { BANNER, Diags, Out, type CompileResult, type OutFile } from './types';

type Fam = 'ipv4' | 'ipv6';
const TABLE = 'emberwall';
const IND = '    ';

const ICMP6_ESSENTIAL =
  'destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert';

function q(s: string): string {
  return `"${s.replace(/["\\]/g, '').slice(0, 120)}"`;
}

function setOf(items: string[]): string {
  return items.length === 1 ? items[0] : `{ ${items.join(', ')} }`;
}

const nftPort = (p: string) => p.replace(':', '-');

interface SetDef {
  name: string;
  fam: Fam;
  members: string[];
}

class SetRegistry {
  defs = new Map<string, SetDef>();
  /** Sets filled by rules at run time (per-client limits, bans). */
  dynamic = new Map<string, { name: string; fam: Fam; timeout: string | null }>();
  constructor(private p: Project) {}
  /** Returns "@name" when the list is exactly one group reference, else an inline set. */
  expr(raw: string[], resolved: string[], fam: Fam): string {
    if (raw.length === 1 && raw[0].startsWith('@')) {
      const g = this.p.addressGroups.find((x) => x.id === raw[0].slice(1));
      if (g) {
        const name = `${slug(g.name, 24).replace(/-/g, '_')}_${fam === 'ipv4' ? 'v4' : 'v6'}`;
        const members = expandAddrs(g.members, this.p).filter((a) => familyOf(a) === fam);
        if (members.length > 0) {
          this.defs.set(name, { name, fam, members });
          return `@${name}`;
        }
      }
    }
    return setOf(resolved);
  }
}

function verdict(r: Rule, proto: string): string {
  if (r.action === 'accept') return 'accept';
  if (r.action === 'drop') return 'drop';
  return proto === 'tcp' ? 'reject with tcp reset' : 'reject';
}

const DAY_NAME: Record<string, string> = { Mon: 'Monday', Tue: 'Tuesday', Wed: 'Wednesday', Thu: 'Thursday', Fri: 'Friday', Sat: 'Saturday', Sun: 'Sunday' };

/**
 * A statement that tracks state per client address: a dynamic set on current nftables,
 * the older meter syntax before 0.9.7.
 */
function perClient(sets: SetRegistry, target: Target, name: string, fam: Fam, expr: string, timeout: string | null = '1m'): string {
  const ipk = fam === 'ipv6' ? 'ip6' : 'ip';
  const set = `${name}_${fam === 'ipv4' ? 'v4' : 'v6'}`;
  if (target.caps.dynSets) {
    sets.dynamic.set(set, { name: set, fam, timeout });
    return `add @${set} { ${ipk} saddr ${expr} }`;
  }
  return `meter ${set} { ${ipk} saddr ${expr} }`;
}

function ruleLines(rr: ResolvedRule, sets: SetRegistry, target: Target, d: Diags): string[] {
  const r = rr.rule;
  const lines: string[] = [];
  const hasAddr = (v: { src: string[]; dst: string[] } | null) => !!v && (v.src.length > 0 || v.dst.length > 0);
  const familyFree = rr.v4 && rr.v6 && !hasAddr(rr.v4) && !hasAddr(rr.v6) && r.proto !== 'icmp';
  const fams: (Fam | null)[] = familyFree ? [null] : ([rr.v4 ? 'ipv4' : null, rr.v6 ? 'ipv6' : null].filter(Boolean) as Fam[]);

  // Protocol variants: one combined TCP+UDP rule when the target can express it.
  let variants: string[][];
  const anyPorts = rr.ports.length > 0 || rr.srcPorts.length > 0;
  if (r.proto === 'tcpudp' && anyPorts && !target.caps.thExpr) {
    variants = [['tcp'], ['udp']];
    d.fallback(`"${r.name}": "th dport" needs nftables 0.9.2+, emitting separate TCP and UDP rules for ${target.version}`, r.id);
  } else if (r.proto === 'tcpudp') {
    variants = [['tcp', 'udp']];
  } else {
    variants = [[r.proto]];
  }

  let schedule = '';
  if (r.schedule) {
    if (target.caps.timeMatch) {
      schedule = `meta hour "${r.schedule.from}"-"${r.schedule.to}"`;
      if (r.schedule.days.length > 0) schedule += ` meta day ${setOf(r.schedule.days.map((x) => `"${DAY_NAME[x]}"`))}`;
    } else {
      d.unsupported(`"${r.name}": schedules need nftables 0.9.3+ (meta hour / meta day); the rule is active at all times on ${target.version}.`, r.id);
    }
  }
  const perSource = !!r.rateLimit?.perSource && r.action === 'accept';
  let connLimit = r.action === 'accept' ? r.connLimit : undefined;
  if (connLimit && !target.caps.ctCount) {
    connLimit = undefined;
    d.unsupported(`"${r.name}": connection limits need nftables 0.9.1+ (ct count); left out for ${target.version}.`, r.id);
  }
  if ((perSource || connLimit) && !target.caps.dynSets) {
    d.fallback(`"${r.name}": per-client tracking uses the older meter syntax on nftables ${target.version} (dynamic sets updated from rules need 0.9.7+).`, r.id);
  }

  for (const fam of fams) {
    const view = fam === 'ipv4' ? rr.v4 : fam === 'ipv6' ? rr.v6 : null;
    const ipk = fam === 'ipv6' ? 'ip6' : 'ip';
    for (const protos of variants) {
      const m: string[] = [];
      if (r.inIface && r.direction !== 'out') m.push(`iifname ${q(r.inIface)}`);
      if (r.outIface && r.direction !== 'in') m.push(`oifname ${q(r.outIface)}`);
      if (r.srcMac && r.direction !== 'out') m.push(`ether saddr ${r.srcMac.toLowerCase()}`);
      const proto = protos[0];
      let familyPinned = false;
      if (view && view.src.length > 0) {
        m.push(`${ipk} saddr ${sets.expr(r.src, view.src, fam as Fam)}`);
        familyPinned = true;
      }
      if (view && view.dst.length > 0) {
        m.push(`${ipk} daddr ${sets.expr(r.dst, view.dst, fam as Fam)}`);
        familyPinned = true;
      }
      if (proto === 'icmp') {
        if (fam === 'ipv4') m.push(r.icmpType ? `icmp type ${r.icmpType}` : 'ip protocol icmp');
        else m.push(r.icmpType ? `icmpv6 type ${r.icmpType}` : 'meta nfproto ipv6 meta l4proto ipv6-icmp');
        familyPinned = true;
      }
      if (fam && !familyPinned) m.unshift(`meta nfproto ${fam}`);
      if (proto === 'tcp' || proto === 'udp') {
        const ports = rr.ports.map(nftPort);
        const sports = rr.srcPorts.map(nftPort);
        const key = protos.length === 2 ? 'th' : proto;
        if (protos.length === 2) m.push('meta l4proto { tcp, udp }');
        else if (ports.length === 0 && sports.length === 0) m.push(`meta l4proto ${proto}`);
        if (sports.length > 0) m.push(`${key} sport ${setOf(sports)}`);
        if (ports.length > 0) m.push(`${key} dport ${setOf(ports)}`);
      }
      if (r.mark) m.push(`meta mark ${r.mark}`);
      if (schedule) m.push(schedule);
      if (r.states && r.states.length > 0) m.push(`ct state ${r.states.join(',')}`);

      // Per-client guards run before the accept: clients over the limit are stopped here.
      const guardFams: Fam[] = fam ? [fam] : ['ipv4', 'ipv6'];
      // A meter belongs to one rule, so split TCP/UDP rules need their own.
      const tag = variants.length > 1 ? `_${proto}` : '';
      const c = `comment ${q(r.name || r.id)}`;
      for (const gf of guardFams) {
        const pin = fam ? '' : `meta nfproto ${gf} `;
        if (perSource) {
          const rl = r.rateLimit!;
          lines.push(`${pin}${m.join(' ')} ${perClient(sets, target, `ew_rl_${shortId(r.id)}${tag}`, gf, `limit rate over ${rl.rate}/${rl.per} burst ${rl.burst} packets`)} counter drop ${c}`.replace(/  +/g, ' '));
        }
        if (connLimit) {
          lines.push(`${pin}${m.join(' ')} ${perClient(sets, target, `ew_cl_${shortId(r.id)}${tag}`, gf, `ct count over ${connLimit}`, null)} counter ${proto === 'tcp' && protos.length === 1 ? 'reject with tcp reset' : 'drop'} ${c}`.replace(/  +/g, ' '));
        }
      }
      if (r.rateLimit && r.action === 'accept' && !perSource) {
        m.push(`limit rate ${r.rateLimit.rate}/${r.rateLimit.per} burst ${r.rateLimit.burst} packets`);
      }
      m.push('counter');
      if (r.log) m.push(`log prefix ${q(logPrefix(r.name || r.id))}`);
      m.push(verdict(r, protos.length === 1 ? proto : 'mixed'));
      m.push(c);
      lines.push(m.join(' '));
    }
  }
  return lines;
}

/** Scanner, flood and auto-ban rules for one chain. `early` goes before the established accept. */
function protectionLines(p: Project, sets: SetRegistry, target: Target, d: Diags, dir: 'in' | 'forward'): { early: string[]; late: string[] } {
  const pr = p.protections ?? {};
  const early: string[] = [];
  const late: string[] = [];
  const fams: Fam[] = p.options.ipv6 ? ['ipv4', 'ipv6'] : ['ipv4'];
  if (pr.autoBan && pr.autoBan.ports.length > 0 && dir === 'in') {
    if (!target.caps.dynSets) {
      d.unsupported(`Auto-ban needs nftables 0.9.7+ (sets updated from rules); left out for ${target.version}.`);
    } else {
      for (const fam of fams) {
        const ipk = fam === 'ipv6' ? 'ip6' : 'ip';
        const set = `ew_banned_${fam === 'ipv4' ? 'v4' : 'v6'}`;
        sets.dynamic.set(set, { name: set, fam, timeout: `${pr.autoBan.seconds}s` });
        early.push(`${ipk} saddr @${set} counter drop comment "auto-ban: banned client"`);
        late.push(`meta nfproto ${fam} tcp dport ${setOf(pr.autoBan.ports.map(nftPort))} add @${set} { ${ipk} saddr } counter drop comment "auto-ban: trap port"`);
      }
    }
  }
  if (pr.portScan) {
    const all = '(fin | syn | rst | psh | ack | urg)';
    for (const expr of [`tcp flags & ${all} == 0x0`, `tcp flags & ${all} == fin | syn | rst | psh | ack | urg`, `tcp flags & ${all} == fin | psh | urg`, 'tcp flags & (fin | syn) == fin | syn', 'tcp flags & (syn | rst) == syn | rst']) {
      late.push(`${expr} counter drop comment "scan: impossible TCP flags"`);
    }
  }
  if (pr.synFlood && dir === 'in') {
    for (const fam of fams) {
      late.push(`meta nfproto ${fam} tcp flags & (fin | syn | rst | ack) == syn ${perClient(sets, target, 'ew_syn', fam, `limit rate over ${pr.synFlood.rate}/second burst ${pr.synFlood.burst} packets`)} counter drop comment "SYN flood guard"`);
    }
  }
  return { early, late };
}

function natStatement(n: NatRule, fam: Fam, inet: boolean, d: Diags, target: Target): string | null {
  const ipk = fam === 'ipv6' ? 'ip6' : 'ip';
  const m: string[] = [];
  let pinned = false;
  if (n.iface) m.push(`${n.kind === 'dnat' ? 'iifname' : 'oifname'} ${q(n.iface)}`);
  if (n.src) {
    m.push(`${ipk} saddr ${n.src}`);
    pinned = true;
  }
  if (n.dst) {
    m.push(`${ipk} daddr ${n.dst}`);
    pinned = true;
  }
  if (inet && !pinned) m.unshift(`meta nfproto ${fam}`);
  const fam2 = inet ? `${ipk} ` : '';
  if (n.kind === 'dnat') {
    if (!n.toAddr) {
      d.invalid(`Port forward "${n.name}" has no destination address`, n.id);
      return null;
    }
    if (n.port && n.proto === 'any') {
      d.invalid(`Port forward "${n.name}" matches a port, so it needs TCP or UDP`, n.id);
      return null;
    }
    if (n.proto !== 'any') m.push(n.port ? `${n.proto} dport ${nftPort(n.port)}` : `meta l4proto ${n.proto}`);
    const addr = fam === 'ipv6' && n.toPort ? `[${n.toAddr}]` : n.toAddr;
    m.push(`dnat ${fam2}to ${addr}${n.toPort ? `:${nftPort(n.toPort)}` : ''}`);
  } else {
    if (n.proto !== 'any') m.push(`meta l4proto ${n.proto}`);
    const rand = n.randomFully ? ' fully-random' : '';
    if (n.kind === 'snat') {
      if (!n.toAddr) {
        d.invalid(`SNAT rule "${n.name}" has no source address to translate to`, n.id);
        return null;
      }
      m.push(`snat ${fam2}to ${n.toAddr}${rand}`);
    } else {
      m.push(`masquerade${rand}`);
    }
  }
  void target;
  m.push(`comment ${q(n.name || n.id)}`);
  return m.join(' ');
}

function reset(o: Out, family: string, table: string, target: Target) {
  if (target.caps.destroy) o.push(`destroy table ${family} ${table}`);
  else o.push(`add table ${family} ${table}`).push(`delete table ${family} ${table}`);
}

export function nftPersistHints(target: Target): string[] {
  switch (target.persistence) {
    case 'rhel':
      return [
        'install -m 600 emberwall.nft /etc/nftables/emberwall.nft',
        `echo 'include "/etc/nftables/emberwall.nft"' >> /etc/sysconfig/nftables.conf`,
        'systemctl disable --now firewalld; systemctl enable --now nftables',
      ];
    case 'alpine':
      return ['install -m 600 emberwall.nft /etc/nftables.d/emberwall.nft', 'rc-update add nftables && rc-service nftables restart'];
    case 'debian':
    case 'arch':
      return [
        'install -m 600 emberwall.nft /etc/nftables.conf   # replaces the distro default file',
        'systemctl enable --now nftables',
      ];
    default:
      return ['Load emberwall.nft with "nft -f" at boot (most distros: /etc/nftables.conf + nftables.service).'];
  }
}

export function compileNftables(p: Project, target: Target): CompileResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));
  const sets = new SetRegistry(p);
  const caps = target.caps;
  const prio = (name: 'filter' | 'dstnat' | 'srcnat') =>
    caps.namedPriority ? name : { filter: '0', dstnat: '-100', srcnat: '100' }[name];
  if (!caps.namedPriority) d.fallback(`Named chain priorities need nftables 0.9.1+; using numeric priorities for ${target.version}.`);

  // Build chain bodies first so the set registry is complete before the table header is written.
  const body: Record<'in' | 'forward' | 'out', Out> = { in: new Out(), forward: new Out(), out: new Out() };
  const opt = p.options;
  const hookName = { in: 'input', forward: 'forward', out: 'output' } as const;
  const lists = activeLists(p, d);
  for (const dir of ['in', 'forward', 'out'] as const) {
    const o = body[dir];
    o.push(`${IND}${IND}type filter hook ${hookName[dir]} priority ${prio('filter')}; policy ${p.policies[dir]};`);
    if (opt.allowLoopback && dir === 'in') o.push(`${IND}${IND}iifname "lo" accept`);
    if (opt.allowLoopback && dir === 'out') o.push(`${IND}${IND}oifname "lo" accept`);
    if (!opt.ipv6) o.push(`${IND}${IND}meta nfproto ipv6 drop comment "IPv6 is switched off in this project"`);
    for (const l of lists) {
      const c = `comment ${q(`blocklist: ${l.name}`)}`;
      for (const [ipk, sfx] of (opt.ipv6 ? [['ip', 'v4'], ['ip6', 'v6']] : [['ip', 'v4']]) as [string, string][]) {
        if (dir !== 'out') o.push(`${IND}${IND}${ipk} saddr @${l.set}_${sfx} counter drop ${c}`);
        if (dir !== 'in' && l.outbound) o.push(`${IND}${IND}${ipk} daddr @${l.set}_${sfx} counter drop ${c}`);
      }
    }
    const prot = dir === 'out' ? { early: [], late: [] } : protectionLines(p, sets, target, d, dir);
    for (const l of prot.early) o.push(`${IND}${IND}${l}`);
    if (opt.allowEstablished) o.push(`${IND}${IND}ct state established,related accept`);
    if (opt.dropInvalid && dir !== 'out') o.push(`${IND}${IND}ct state invalid drop`);
    if (opt.allowIcmp && (dir === 'in' || (dir === 'out' && p.policies.out === 'drop'))) {
      o.push(`${IND}${IND}icmp type echo-request accept`);
      if (opt.ipv6) o.push(`${IND}${IND}icmpv6 type { ${ICMP6_ESSENTIAL} } accept`);
    }
    for (const l of prot.late) o.push(`${IND}${IND}${l}`);
  }
  for (const rr of rules) {
    for (const line of ruleLines(rr, sets, target, d)) body[rr.rule.direction].push(`${IND}${IND}${line}`, rr.rule.id);
  }
  if (opt.logDropped) {
    for (const dir of ['in', 'forward', 'out'] as const) {
      if (p.policies[dir] === 'drop') {
        body[dir].push(`${IND}${IND}limit rate 5/minute burst 10 packets log prefix "ew-drop-${dir}: "`);
      }
    }
  }

  const nat = p.nat.filter((n) => n.enabled);
  const o = new Out();
  o.push('#!/usr/sbin/nft -f');
  o.push(`# ${BANNER} - ${p.name}`);
  o.push(`# Target: ${target.label}`);
  o.push('# Emberwall owns one table and leaves every other table alone.');
  o.blank();
  reset(o, 'inet', TABLE, target);
  if (!caps.destroy) d.fallback(`"destroy table" needs nftables 1.0.7+ and kernel 6.3+; using the add + delete idiom for ${target.version} so reloads stay idempotent.`);
  o.blank();
  o.push(`table inet ${TABLE} {`);
  if (caps.objectComments) o.push(`${IND}comment ${q(p.name)}`);
  else d.fallback(`Table and chain comments need nftables 0.9.7+; left out for ${target.version}.`);

  for (const s of sets.defs.values()) {
    o.blank();
    o.push(`${IND}set ${s.name} {`);
    o.push(`${IND}${IND}type ${s.fam === 'ipv4' ? 'ipv4_addr' : 'ipv6_addr'}; flags interval;`);
    o.push(`${IND}${IND}elements = { ${s.members.join(', ')} }`);
    o.push(`${IND}}`);
  }
  for (const l of lists) {
    for (const [type, sfx, members] of (opt.ipv6 ? [['ipv4_addr', 'v4', l.v4], ['ipv6_addr', 'v6', l.v6]] : [['ipv4_addr', 'v4', l.v4]]) as [string, string, string[]][]) {
      o.blank();
      o.push(`${IND}set ${l.set}_${sfx} {`);
      o.push(`${IND}${IND}type ${type}; flags interval; auto-merge;`);
      if (members.length > 0) o.push(`${IND}${IND}elements = { ${members.join(', ')} }`);
      o.push(`${IND}}`);
    }
  }
  for (const s of sets.dynamic.values()) {
    o.blank();
    o.push(`${IND}set ${s.name} {`);
    // Connection-count sets must not time out: the kernel removes entries when connections close.
    o.push(`${IND}${IND}type ${s.fam === 'ipv4' ? 'ipv4_addr' : 'ipv6_addr'}; size 65535; ${s.timeout ? `flags dynamic,timeout; timeout ${s.timeout};` : 'flags dynamic;'}`);
    o.push(`${IND}}`);
  }
  for (const dir of ['in', 'forward', 'out'] as const) {
    o.blank();
    o.push(`${IND}chain ${hookName[dir]} {`);
    o.add(body[dir].lines);
    o.push(`${IND}}`);
  }

  const natChains = (out: Out, fam: Fam | null, inet: boolean) => {
    for (const hook of ['prerouting', 'postrouting'] as const) {
      const mine = nat.filter((n) => (hook === 'prerouting') === (n.kind === 'dnat') && (fam === null || natFamily(n) === fam));
      out.blank();
      out.push(`${IND}chain ${hook} {`);
      out.push(`${IND}${IND}type nat hook ${hook} priority ${prio(hook === 'prerouting' ? 'dstnat' : 'srcnat')}; policy accept;`);
      for (const n of mine) {
        const st = natStatement(n, natFamily(n), inet, d, target);
        if (st) out.push(`${IND}${IND}${st}`, n.id);
      }
      out.push(`${IND}}`);
    }
  };

  if (nat.length > 0 && caps.inetNat) natChains(o, null, true);
  o.push('}');

  if (nat.length > 0 && !caps.inetNat) {
    d.fallback(`NAT in the inet family needs nftables 0.9.1+ (kernel 5.2+); NAT is written to separate ip / ip6 tables for ${target.version}.`);
    for (const fam of ['ipv4', 'ipv6'] as const) {
      if (!nat.some((n) => natFamily(n) === fam)) continue;
      const family = fam === 'ipv4' ? 'ip' : 'ip6';
      o.blank();
      reset(o, family, `${TABLE}_nat`, target);
      o.push(`table ${family} ${TABLE}_nat {`);
      const inner = new Out();
      natChains(inner, fam, false);
      o.add(inner.lines);
      o.push('}');
    }
  }

  if (target.distro && target.distro.defaultTool !== 'nftables' && target.distro.defaultTool !== 'iptables') {
    d.note(`${target.distro.name} ships ${target.distro.defaultTool} as its firewall manager. Disable it before loading this ruleset so two managers do not fight.`);
  }
  if (rules.some((r) => r.rule.rateLimit && !r.rule.rateLimit.perSource && r.rule.action === 'accept')) {
    d.note('Rate limits without "per client" use "limit rate", which is shared by all clients of the rule.');
  }

  const sysctl: string[] = [];
  if (opt.forwarding || nat.length > 0) {
    sysctl.push('sysctl -w net.ipv4.ip_forward=1 >/dev/null');
    if (opt.ipv6) sysctl.push('sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null');
  }

  const files: OutFile[] = [
    { name: 'emberwall.nft', path: '/etc/nftables.conf', lang: 'nft', description: 'nftables ruleset (nft -f)', lines: o.lines },
    safeApplyScript({
      toolLabel: target.label,
      backup: ['nft list ruleset > "$BACKUP/ruleset.nft"'],
      check: ['nft -c -f "$DIR/emberwall.nft"'],
      apply: [...sysctl, 'nft -f "$DIR/emberwall.nft"'],
      rollback: ['nft flush ruleset', 'nft -f "$BACKUP/ruleset.nft"'],
      persist: nftPersistHints(target),
    }),
  ];
  files.push(...blocklistUpdater(lists, 'nftables', opt.ipv6));
  if (lists.some((l) => l.url)) d.note('Downloaded blocklists start empty: run emberwall-blocklists.sh after loading the ruleset, and enable the timer to keep them fresh. Reloading the ruleset empties them again until the next refresh.');
  const sys = sysctlFile(p);
  if (sys) files.push(sys);
  return { target, files, diagnostics: d.list };
}
