import type { Project } from '../model';
import { cartesian, orAny, resolveAll, type ResolvedRule } from '../resolve';
import type { Target } from '../targets';
import { safeApplyScript } from './apply';
import { natLines, ruleSpecs } from './iptables';
import { BANNER, Diags, Out, shQuote, type CompileResult, type OutFile } from './types';

type Fam = 'ipv4' | 'ipv6';

const ufwAction = { accept: 'allow', drop: 'deny', reject: 'reject' } as const;

/** ufw port lists share the 15-slot multiport limit. */
function chunk(ports: string[]): string[][] {
  const out: string[][] = [];
  let cur: string[] = [];
  let used = 0;
  for (const p of ports) {
    const cost = p.includes(':') ? 2 : 1;
    if (used + cost > 15) {
      out.push(cur);
      cur = [];
      used = 0;
    }
    cur.push(p);
    used += cost;
  }
  if (cur.length > 0) out.push(cur);
  return out.length > 0 ? out : [[]];
}

function commands(rr: ResolvedRule, target: Target, d: Diags): string[] {
  const r = rr.rule;
  const cmds: string[] = [];
  let action: string = ufwAction[r.action];
  if (r.rateLimit && r.action === 'accept') {
    if (r.direction === 'in' && r.proto !== 'any') {
      action = 'limit';
      d.fallback(`"${r.name}": ufw's limit is fixed at 6 connections per 30 seconds per source; the configured ${r.rateLimit.rate}/${r.rateLimit.per} is not used.`, r.id);
    } else {
      d.unsupported(`"${r.name}": ufw can only rate-limit inbound TCP/UDP rules; the limit is left out.`, r.id);
    }
  }

  const head: string[] = ['ufw'];
  if (r.direction === 'forward') head.push('route');
  head.push(action);
  if (r.direction === 'forward') {
    if (r.inIface) head.push(`in on ${r.inIface}`);
    if (r.outIface) head.push(`out on ${r.outIface}`);
  } else if (r.direction === 'in') {
    head.push(r.inIface ? `in on ${r.inIface}` : 'in');
  } else {
    head.push(r.outIface ? `out on ${r.outIface}` : 'out');
  }
  if (r.log) head.push('log');

  const both = rr.v4 && rr.v6;
  const noAddr = (v: { src: string[]; dst: string[] } | null) => !v || (v.src.length === 0 && v.dst.length === 0);
  // One family-neutral command when nothing pins the family.
  const views: [Fam | null, { src: string[]; dst: string[] }][] =
    both && noAddr(rr.v4) && noAddr(rr.v6)
      ? [[null, { src: [], dst: [] }]]
      : ([['ipv4', rr.v4], ['ipv6', rr.v6]].filter((x) => x[1]) as [Fam, { src: string[]; dst: string[] }][]);

  // TCP+UDP on a single plain port needs no proto keyword in ufw.
  const single = rr.ports.length === 1 && !rr.ports[0].includes(':');
  const protoSets: (string | null)[] =
    r.proto === 'any' ? [null] : r.proto === 'tcpudp' ? (single || rr.ports.length === 0 ? [null] : ['tcp', 'udp']) : [r.proto];
  if (r.proto === 'tcpudp' && rr.ports.length === 0) {
    d.fallback(`"${r.name}": ufw cannot match "TCP or UDP" without a port; the rule covers every protocol.`, r.id);
  }

  for (const [fam, view] of views) {
    const anyAddr = fam === null ? 'any' : fam === 'ipv4' ? '0.0.0.0/0' : '::/0';
    // When only one family applies and no address pins it, a literal any-address does.
    const pin = fam !== null && !both && noAddr(view);
    for (const proto of protoSets) {
      for (const [src, dst] of cartesian(orAny(view.src), orAny(view.dst))) {
        for (const ports of chunk(rr.ports)) {
          const c = [...head];
          if (proto) c.push(`proto ${proto}`);
          c.push(`from ${src ?? (pin ? anyAddr : 'any')}`);
          c.push(`to ${dst ?? 'any'}`);
          if (ports.length > 0) c.push(`port ${ports.join(',')}`);
          if (target.caps.comment && r.name) c.push(`comment ${shQuote(r.name.replace(/'/g, ''))}`);
          cmds.push(c.join(' '));
        }
      }
    }
  }
  return cmds;
}

export function compileUfw(p: Project, target: Target): CompileResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));
  const opt = p.options;
  const o = new Out();
  const frag4 = new Out();
  const frag6 = new Out();
  const chainFor = (dir: 'in' | 'out' | 'forward', v6: boolean) =>
    `${v6 ? 'ufw6' : 'ufw'}-before-${dir === 'in' ? 'input' : dir === 'out' ? 'output' : 'forward'}`;

  o.push('#!/bin/sh');
  o.push(`# ${BANNER} - ${p.name}`);
  o.push(`# Target: ${target.label}`);
  o.push('# Rebuilds the ufw rule set from scratch. Run as root.');
  o.push('set -eu');
  o.blank();
  o.push('ufw --force reset');
  o.push(`sed -i 's/^IPV6=.*/IPV6=${opt.ipv6 ? 'yes' : 'no'}/' /etc/default/ufw`);
  o.push(`ufw default ${p.policies.in === 'drop' ? 'deny' : 'allow'} incoming`);
  o.push(`ufw default ${p.policies.out === 'drop' ? 'deny' : 'allow'} outgoing`);
  if (target.caps.route) {
    o.push(`ufw default ${p.policies.forward === 'drop' ? 'deny' : 'allow'} routed`);
  } else {
    o.push(`sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="${p.policies.forward === 'drop' ? 'DROP' : 'ACCEPT'}"/' /etc/default/ufw`);
  }
  const needsForward = opt.forwarding || p.nat.some((n) => n.enabled);
  if (needsForward) {
    o.push(`sed -i 's|^#\\{0,1\\}net/ipv4/ip_forward=.*|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf`);
    if (opt.ipv6) o.push(`sed -i 's|^#\\{0,1\\}net/ipv6/conf/all/forwarding=.*|net/ipv6/conf/all/forwarding=1|' /etc/ufw/sysctl.conf`);
  }
  o.blank();

  let commentWarned = false;
  for (const rr of rules) {
    const r = rr.rule;
    const toFragment =
      r.proto === 'icmp' || (r.states && r.states.length > 0) || (r.direction === 'forward' && !target.caps.route);
    if (toFragment) {
      const why =
        r.proto === 'icmp'
          ? 'the ufw command line has no ICMP rules'
          : r.direction === 'forward' && !target.caps.route
            ? `"ufw route" needs ufw 0.34+ (target is ${target.version})`
            : 'the ufw command line cannot match connection state';
      d.fallback(`"${r.name}": ${why}; written to the before.rules fragment instead. Fragment rules run before all ufw command rules.`, r.id);
      for (const s of ruleSpecs(rr, 'ipv4')) frag4.push(`-A ${chainFor(r.direction, false)} ${s}`, r.id);
      for (const s of ruleSpecs(rr, 'ipv6')) frag6.push(`-A ${chainFor(r.direction, true)} ${s}`, r.id);
      continue;
    }
    if (!target.caps.comment && r.name) {
      o.push(`# ${r.name}`, r.id);
      if (!commentWarned) {
        d.fallback(`Rule comments need ufw 0.35+; names are kept as shell comments for ${target.version}.`);
        commentWarned = true;
      }
    }
    for (const c of commands(rr, target, d)) o.push(c, r.id);
  }

  o.blank();
  o.push(`ufw logging ${opt.logDropped ? 'low' : 'off'}`);
  o.push('ufw --force enable');
  o.push('ufw status verbose');

  if (!opt.allowLoopback || !opt.allowEstablished || !opt.dropInvalid) {
    d.note('ufw always accepts loopback and established traffic and drops invalid packets (its before.rules). Those toggles have no effect on this target.');
  }
  if (!opt.allowIcmp) {
    d.unsupported('ufw accepts ping by default. To block it, change the "--icmp-type echo-request" lines in /etc/ufw/before.rules to DROP.');
  }

  const files: OutFile[] = [
    { name: 'emberwall-ufw.sh', path: './emberwall-ufw.sh', lang: 'shell', description: 'ufw commands', lines: o.lines },
  ];

  const nat4 = natLines(p, 'ipv4', { snat: true, masquerade: true }, d);
  const nat6 = natLines(p, 'ipv6', { snat: true, masquerade: true }, d);
  const fragment = (rulesOut: Out, nat: typeof nat4, v6: boolean): OutFile | null => {
    if (rulesOut.lines.length === 0 && nat.length === 0) return null;
    const f = new Out();
    const file = v6 ? '/etc/ufw/before6.rules' : '/etc/ufw/before.rules';
    f.push(`# ${BANNER} - additions for ${file}`);
    f.push('# ufw has no command for these, so they are added to its rules file by hand.');
    if (nat.length > 0) {
      f.blank();
      f.push(`# 1) Paste this block at the very top of ${file} (before *filter):`);
      f.push('*nat');
      f.push(':PREROUTING ACCEPT [0:0]').push(':POSTROUTING ACCEPT [0:0]');
      f.push('-F');
      f.add(nat);
      f.push('COMMIT');
    }
    if (rulesOut.lines.length > 0) {
      f.blank();
      f.push(`# ${nat.length > 0 ? '2) ' : ''}Paste these lines just above the final COMMIT of the *filter section:`);
      f.add(rulesOut.lines);
    }
    f.blank();
    f.push('# Then run: ufw reload');
    return {
      name: v6 ? 'before6.rules.fragment' : 'before.rules.fragment',
      path: file,
      lang: 'iptables',
      description: `Manual additions for ${file}`,
      lines: f.lines,
    };
  };
  if (nat4.length + nat6.length > 0) {
    d.fallback('ufw has no NAT commands; NAT rules are written to the before.rules fragment.');
  }
  for (const f of [fragment(frag4, nat4, false), fragment(frag6, nat6, true)]) if (f) files.push(f);

  files.push(
    safeApplyScript({
      toolLabel: target.label,
      backup: ['cp -a /etc/ufw "$BACKUP/ufw"', 'cp -a /etc/default/ufw "$BACKUP/default-ufw"'],
      check: [],
      apply: ['sh "$DIR/emberwall-ufw.sh"'],
      rollback: ['rm -rf /etc/ufw && cp -a "$BACKUP/ufw" /etc/ufw', 'cp -a "$BACKUP/default-ufw" /etc/default/ufw', 'ufw reload'],
      persist: ['ufw stores its rules itself; "ufw enable" already makes them start at boot.'],
    }),
  );
  return { target, files, diagnostics: d.list };
}
