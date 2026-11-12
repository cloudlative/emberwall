import type { NatRule, Project } from '../model';
import { familyOf } from '../net';
import { cartesian, orAny, resolveAll, shortId, slug, type ResolvedRule } from '../resolve';
import type { Target } from '../targets';
import { safeApplyScript } from './apply';
import { activeLists, blocklistUpdater, ipsetCreate, ipsetSpecs, type ActiveList } from './blocklists';
import { sysctlFile } from '../sysctl';
import { BANNER, Diags, Out, type CompileResult, type OutFile, type OutLine } from './types';

type Fam = 'ipv4' | 'ipv6';

const CHAIN = { in: 'INPUT', out: 'OUTPUT', forward: 'FORWARD' } as const;
/** ICMPv6 types IPv6 needs to function, in ip6tables spelling. */
export const ICMP6_ESSENTIAL = [
  'destination-unreachable',
  'packet-too-big',
  'time-exceeded',
  'parameter-problem',
  'echo-request',
  'router-solicitation',
  'router-advertisement',
  'neighbour-solicitation',
  'neighbour-advertisement',
];

const LOG_PREFIX_MAX = 29;

export function logPrefix(tag: string): string {
  const p = `ew-${slug(tag, LOG_PREFIX_MAX - 5)}: `;
  return p.slice(0, LOG_PREFIX_MAX);
}

function quote(s: string): string {
  return `"${s.replace(/["\\]/g, '').slice(0, 240)}"`;
}

/** multiport takes at most 15 port slots; a range uses two. */
function chunkPorts(ports: string[]): string[][] {
  const chunks: string[][] = [];
  let cur: string[] = [];
  let used = 0;
  for (const p of ports) {
    const cost = p.includes(':') ? 2 : 1;
    if (used + cost > 15) {
      chunks.push(cur);
      cur = [];
      used = 0;
    }
    cur.push(p);
    used += cost;
  }
  if (cur.length > 0) chunks.push(cur);
  return chunks.length > 0 ? chunks : [[]];
}

export function rejectTarget(fam: Fam, proto: string): string {
  if (proto === 'tcp') return 'REJECT --reject-with tcp-reset';
  return fam === 'ipv4' ? 'REJECT --reject-with icmp-port-unreachable' : 'REJECT --reject-with icmp6-port-unreachable';
}

/**
 * iptables rule specifications (everything after "-A CHAIN") for one rule and family.
 * Also used by the firewalld compiler for direct-interface fallbacks.
 */
export function ruleSpecs(rr: ResolvedRule, fam: Fam): string[] {
  const view = fam === 'ipv4' ? rr.v4 : rr.v6;
  if (!view) return [];
  const r = rr.rule;
  const out: string[] = [];
  for (const proto of rr.protos) {
    for (const [src, dst] of cartesian(orAny(view.src), orAny(view.dst))) {
      for (const ports of chunkPorts(proto === 'tcp' || proto === 'udp' ? rr.ports : [])) {
        const m: string[] = [];
        if (r.inIface && r.direction !== 'out') m.push(`-i ${r.inIface}`);
        if (r.outIface && r.direction !== 'in') m.push(`-o ${r.outIface}`);
        if (src) m.push(`-s ${src}`);
        if (dst) m.push(`-d ${dst}`);
        if (proto === 'icmp') {
          m.push(fam === 'ipv4' ? '-p icmp' : '-p ipv6-icmp');
          if (r.icmpType) m.push(fam === 'ipv4' ? `--icmp-type ${r.icmpType}` : `--icmpv6-type ${r.icmpType}`);
        } else if (proto !== 'any') {
          m.push(`-p ${proto}`);
          if (ports.length === 1) m.push(`--dport ${ports[0]}`);
          else if (ports.length > 1) m.push(`-m multiport --dports ${ports.join(',')}`);
        }
        if ((proto === 'tcp' || proto === 'udp') && rr.srcPorts.length > 0) {
          m.push(rr.srcPorts.length === 1 ? `--sport ${rr.srcPorts[0]}` : `-m multiport --sports ${rr.srcPorts.slice(0, 15).join(',')}`);
        }
        if (r.srcMac && r.direction !== 'out') m.push(`-m mac --mac-source ${r.srcMac}`);
        if (r.mark) m.push(`-m mark --mark ${r.mark}`);
        if (r.schedule) {
          m.push(`-m time --timestart ${r.schedule.from} --timestop ${r.schedule.to}${r.schedule.days.length > 0 ? ` --weekdays ${r.schedule.days.join(',')}` : ''}`);
        }
        if (r.states && r.states.length > 0) {
          m.push(`-m conntrack --ctstate ${r.states.map((s) => s.toUpperCase()).join(',')}`);
        }
        const c = `-m comment --comment ${quote(r.name || r.id)}`;
        const guards: string[] = [];
        const perSource = !!r.rateLimit?.perSource && r.action === 'accept';
        if (perSource) {
          const rl = r.rateLimit!;
          guards.push(`-m hashlimit --hashlimit-above ${rl.rate}/${rl.per} --hashlimit-burst ${rl.burst} --hashlimit-mode srcip --hashlimit-name ew_${shortId(r.id)} ${c} -j DROP`);
        }
        if (r.connLimit && r.action === 'accept') {
          guards.push(`-m connlimit --connlimit-above ${r.connLimit} ${c} -j ${proto === 'tcp' ? 'REJECT --reject-with tcp-reset' : 'DROP'}`);
        }
        const pre = m.join(' ');
        for (const g of guards) out.push(`${pre} ${g}`.trim());
        if (r.rateLimit && r.action === 'accept' && !perSource) {
          m.push(`-m limit --limit ${r.rateLimit.rate}/${r.rateLimit.per} --limit-burst ${r.rateLimit.burst}`);
        }
        m.push(c);
        const match = m.join(' ');
        if (r.log) out.push(`${match} -j LOG --log-prefix ${quote(logPrefix(r.name || r.id))}`);
        const verdict =
          r.action === 'accept' ? 'ACCEPT' : r.action === 'drop' ? 'DROP' : rejectTarget(fam, proto);
        out.push(`${match} -j ${verdict}`);
      }
    }
  }
  return out;
}

/**
 * Scanner / flood / auto-ban rules as iptables rule specs.
 * `early` goes before the established-connection accept, `late` just before the user's rules.
 */
export function protectionSpecs(p: Project): { early: string[]; late: string[]; forwardToo: string[] } {
  const pr = p.protections ?? {};
  const early: string[] = [];
  const late: string[] = [];
  const forwardToo: string[] = [];
  if (pr.autoBan && pr.autoBan.ports.length > 0) {
    early.push(`-m recent --name ew_ban --rcheck --seconds ${pr.autoBan.seconds} -m comment --comment "auto-ban: banned client" -j DROP`);
    const ports = pr.autoBan.ports.slice(0, 15).join(',');
    late.push(`-p tcp -m multiport --dports ${ports} -m recent --name ew_ban --set -m comment --comment "auto-ban: trap port" -j DROP`);
  }
  if (pr.portScan) {
    for (const flags of ['ALL NONE', 'ALL ALL', 'ALL FIN,PSH,URG', 'SYN,FIN SYN,FIN', 'SYN,RST SYN,RST']) {
      forwardToo.push(`-p tcp --tcp-flags ${flags} -m comment --comment "scan: impossible TCP flags" -j DROP`);
    }
  }
  if (pr.synFlood) {
    late.unshift(`-p tcp --syn -m hashlimit --hashlimit-above ${pr.synFlood.rate}/second --hashlimit-burst ${pr.synFlood.burst} --hashlimit-mode srcip --hashlimit-name ew_syn -m comment --comment "SYN flood guard" -j DROP`);
  }
  return { early, late, forwardToo };
}

export function natFamily(n: NatRule): Fam {
  for (const a of [n.toAddr, n.src, n.dst]) {
    const f = a ? familyOf(a) : null;
    if (f) return f;
  }
  return 'ipv4';
}

/** NAT table rules. `randomFully` says whether the consuming tool understands --random-fully. */
export function natLines(p: Project, fam: Fam, randomFully: { snat: boolean; masquerade: boolean }, d: Diags): OutLine[] {
  const o = new Out();
  for (const n of p.nat.filter((x) => x.enabled && natFamily(x) === fam)) {
    const m: string[] = [];
    const c = `-m comment --comment ${quote(n.name || n.id)}`;
    if (n.kind === 'dnat') {
      if (!n.toAddr) {
        d.invalid(`Port forward "${n.name}" has no destination address`, n.id);
        continue;
      }
      if (n.port && n.proto === 'any') {
        d.invalid(`Port forward "${n.name}" matches a port, so it needs TCP or UDP`, n.id);
        continue;
      }
      if (n.iface) m.push(`-i ${n.iface}`);
      if (n.src) m.push(`-s ${n.src}`);
      if (n.dst) m.push(`-d ${n.dst}`);
      if (n.proto !== 'any') m.push(`-p ${n.proto}`);
      if (n.port) m.push(`--dport ${n.port}`);
      const addr = fam === 'ipv6' && n.toPort ? `[${n.toAddr}]` : n.toAddr;
      const to = n.toPort ? `${addr}:${n.toPort.replace(':', '-')}` : addr;
      o.push(`-A PREROUTING ${m.join(' ')} ${c} -j DNAT --to-destination ${to}`.replace(/  +/g, ' '), n.id);
    } else {
      if (n.iface) m.push(`-o ${n.iface}`);
      if (n.src) m.push(`-s ${n.src}`);
      if (n.dst) m.push(`-d ${n.dst}`);
      if (n.proto !== 'any') m.push(`-p ${n.proto}`);
      let rand = '';
      if (n.randomFully) {
        if (n.kind === 'snat' ? randomFully.snat : randomFully.masquerade) rand = ' --random-fully';
        else {
          rand = ' --random';
          d.fallback(`"${n.name}": --random-fully for ${n.kind === 'snat' ? 'SNAT needs iptables 1.6.0+' : 'MASQUERADE needs iptables 1.6.2+'}, using --random instead`, n.id);
        }
      }
      if (n.kind === 'snat') {
        if (!n.toAddr) {
          d.invalid(`SNAT rule "${n.name}" has no source address to translate to`, n.id);
          continue;
        }
        o.push(`-A POSTROUTING ${m.join(' ')} ${c} -j SNAT --to-source ${n.toAddr}${rand}`.replace(/  +/g, ' '), n.id);
      } else {
        o.push(`-A POSTROUTING ${m.join(' ')} ${c} -j MASQUERADE${rand}`.replace(/  +/g, ' '), n.id);
      }
    }
  }
  return o.lines;
}

function restoreFile(p: Project, rules: ResolvedRule[], fam: Fam, target: Target, d: Diags, lists: ActiveList[] = []): OutLine[] {
  const o = new Out();
  const v6 = fam === 'ipv6';
  const pol = (x: 'accept' | 'drop') => x.toUpperCase();
  o.push(`# ${BANNER} - ${p.name}`);
  o.push(`# Target: ${target.label} (${v6 ? 'ip6tables' : 'iptables'}-restore format)`);
  o.push('*filter');

  if (v6 && !p.options.ipv6) {
    o.push(':INPUT DROP [0:0]').push(':FORWARD DROP [0:0]').push(':OUTPUT DROP [0:0]');
    o.push('# IPv6 is switched off in this project: allow loopback only.');
    o.push('-A INPUT -i lo -j ACCEPT').push('-A OUTPUT -o lo -j ACCEPT').push('COMMIT');
    return o.lines;
  }

  o.push(`:INPUT ${pol(p.policies.in)} [0:0]`);
  o.push(`:FORWARD ${pol(p.policies.forward)} [0:0]`);
  o.push(`:OUTPUT ${pol(p.policies.out)} [0:0]`);
  const { options: opt } = p;
  if (opt.allowLoopback) {
    o.push('-A INPUT -i lo -j ACCEPT').push('-A OUTPUT -o lo -j ACCEPT');
  }
  const bl = ipsetSpecs(lists, fam);
  for (const sp of bl.input) o.push(`-A INPUT ${sp}`);
  for (const sp of bl.forward) o.push(`-A FORWARD ${sp}`);
  for (const sp of bl.output) o.push(`-A OUTPUT ${sp}`);
  const prot = protectionSpecs(p);
  for (const sp of prot.early) o.push(`-A INPUT ${sp}`);
  if (opt.allowEstablished) {
    for (const ch of ['INPUT', 'FORWARD', 'OUTPUT']) o.push(`-A ${ch} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`);
  }
  if (opt.dropInvalid) {
    for (const ch of ['INPUT', 'FORWARD']) o.push(`-A ${ch} -m conntrack --ctstate INVALID -j DROP`);
  }
  if (opt.allowIcmp) {
    const chains = p.policies.out === 'drop' ? ['INPUT', 'OUTPUT'] : ['INPUT'];
    for (const ch of chains) {
      if (!v6) o.push(`-A ${ch} -p icmp --icmp-type echo-request -j ACCEPT`);
      else for (const t of ICMP6_ESSENTIAL) o.push(`-A ${ch} -p ipv6-icmp --icmpv6-type ${t} -j ACCEPT`);
    }
  }
  for (const sp of prot.forwardToo) o.push(`-A INPUT ${sp}`).push(`-A FORWARD ${sp}`);
  for (const sp of prot.late) o.push(`-A INPUT ${sp}`);
  for (const rr of rules) {
    for (const spec of ruleSpecs(rr, fam)) o.push(`-A ${CHAIN[rr.rule.direction]} ${spec}`, rr.rule.id);
  }
  if (opt.logDropped) {
    for (const dir of ['in', 'forward', 'out'] as const) {
      if (p.policies[dir] !== 'drop') continue;
      o.push(`-A ${CHAIN[dir]} -m limit --limit 5/minute --limit-burst 10 -j LOG --log-prefix "ew-drop-${dir}: "`);
    }
  }
  o.push('COMMIT');

  const nat = natLines(p, fam, { snat: !!target.caps.randomFullySnat, masquerade: !!target.caps.randomFully }, d);
  if (nat.length > 0) {
    o.push('*nat');
    o.push(':PREROUTING ACCEPT [0:0]').push(':INPUT ACCEPT [0:0]').push(':OUTPUT ACCEPT [0:0]').push(':POSTROUTING ACCEPT [0:0]');
    o.add(nat);
    o.push('COMMIT');
  }
  return o.lines;
}

export function persistHints(target: Target): string[] {
  switch (target.persistence) {
    case 'debian':
      return [
        'apt install iptables-persistent',
        'install -m 600 rules.v4 /etc/iptables/rules.v4',
        'install -m 600 rules.v6 /etc/iptables/rules.v6',
        'systemctl enable netfilter-persistent',
      ];
    case 'rhel':
      return [
        'dnf install iptables-services   # yum on EL7',
        'install -m 600 rules.v4 /etc/sysconfig/iptables',
        'install -m 600 rules.v6 /etc/sysconfig/ip6tables',
        'systemctl disable --now firewalld; systemctl enable --now iptables ip6tables',
      ];
    case 'alpine':
      return [
        'rc-service iptables save && rc-update add iptables',
        'rc-service ip6tables save && rc-update add ip6tables',
      ];
    case 'arch':
      return [
        'install -m 600 rules.v4 /etc/iptables/iptables.rules',
        'install -m 600 rules.v6 /etc/iptables/ip6tables.rules',
        'systemctl enable --now iptables ip6tables',
      ];
    default:
      return ['Load rules.v4 / rules.v6 with iptables-restore / ip6tables-restore from a boot script or unit.'];
  }
}

export function compileIptables(p: Project, target: Target): CompileResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));

  const lists = activeLists(p, d);
  const v4 = restoreFile(p, rules, 'ipv4', target, d, lists);
  const v6 = restoreFile(p, rules, 'ipv6', target, d, lists);
  const ipsets = ipsetCreate(lists, p.options.ipv6);
  if (lists.length > 0) d.note('Blocklists use ipset: install the ipset package. The apply script creates the sets; save them for boot with "ipset save > /etc/ipset.conf" or your distribution\'s ipset service.');

  const backend = target.distro?.iptablesBackend ?? (target.caps.nftBackend ? null : 'legacy');
  if (backend === 'nft') {
    d.note(`On ${target.distro!.name} the iptables command is iptables-nft (nf_tables backend): these rules end up in the kernel's nftables and show in "nft list ruleset".`);
  } else if (backend === null) {
    d.note(`iptables ${target.version} can run on either backend (iptables-nft or iptables-legacy). The files work with both; check which one you have with "iptables -V".`);
  }
  if (target.distro?.note) d.note(target.distro.note);
  d.note('iptables-restore replaces the whole filter (and nat) table. On Docker or Kubernetes hosts, restart the daemon afterwards so it re-creates its chains.');
  const wait = target.caps.restoreWait ? ' -w 5' : '';
  if (!target.caps.restoreWait) {
    d.fallback(`iptables-restore --wait needs 1.6.2+; the apply script for ${target.version} restores without waiting for the xtables lock.`);
  }
  if (rules.some((r) => r.rule.rateLimit && !r.rule.rateLimit.perSource && r.rule.action === 'accept')) {
    d.note('Rate limits without "per client" use "-m limit", which is shared by all clients of the rule.');
  }
  if (rules.some((r) => r.rule.schedule)) d.note('Schedules use "-m time", which reads the kernel clock in UTC unless the host sets a kernel timezone.');

  const sysctl: string[] = [];
  if (p.options.forwarding || p.nat.some((n) => n.enabled)) {
    sysctl.push('sysctl -w net.ipv4.ip_forward=1 >/dev/null');
    if (p.options.ipv6) sysctl.push('sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null');
  }

  const files: OutFile[] = [
    { name: 'rules.v4', path: '/etc/iptables/rules.v4', lang: 'iptables', description: 'IPv4 ruleset (iptables-restore)', lines: v4 },
    { name: 'rules.v6', path: '/etc/iptables/rules.v6', lang: 'iptables', description: 'IPv6 ruleset (ip6tables-restore)', lines: v6 },
    safeApplyScript({
      toolLabel: target.label,
      backup: ['iptables-save > "$BACKUP/rules.v4"', 'ip6tables-save > "$BACKUP/rules.v6"'],
      check: [...ipsets, 'iptables-restore --test < "$DIR/rules.v4"', 'ip6tables-restore --test < "$DIR/rules.v6"'],
      apply: [...sysctl, `iptables-restore${wait} < "$DIR/rules.v4"`, `ip6tables-restore${wait} < "$DIR/rules.v6"`],
      rollback: ['iptables-restore < "$BACKUP/rules.v4"', 'ip6tables-restore < "$BACKUP/rules.v6"'],
      persist: persistHints(target),
    }),
  ];
  files.push(...blocklistUpdater(lists, 'iptables', p.options.ipv6));
  const sys = sysctlFile(p);
  if (sys) files.push(sys);
  return { target, files, diagnostics: d.list };
}
