import type { Direction, Project } from '../model';
import { cartesian, orAny, resolveAll, type ResolvedRule } from '../resolve';
import type { Target } from '../targets';
import { safeApplyScript } from './apply';
import { activeLists, blocklistUpdater } from './blocklists';
import { sysctlFile } from '../sysctl';
import { logPrefix, natFamily, natLines, ruleSpecs } from './iptables';
import { BANNER, Diags, Out, shQuote, type CompileResult, type OutFile } from './types';

type Fam = 'ipv4' | 'ipv6';
const ZONE = 'emberwall';

type Element =
  | { kind: 'port'; port: string; proto: string }
  | { kind: 'protocol'; value: string }
  | { kind: 'icmp'; name: string }
  | { kind: 'masquerade' }
  | { kind: 'source-port'; port: string; proto: string }
  | { kind: 'forward-port'; port: string; proto: string; toPort?: string; toAddr?: string };

/** Structured rich rule, rendered both as firewall-cmd text and as zone XML. */
interface Rich {
  ruleId?: string;
  priority?: number;
  family?: Fam;
  src?: string;
  srcMac?: string;
  srcIpset?: string;
  dst?: string;
  element?: Element;
  log?: string;
  action?: 'accept' | 'drop' | 'reject';
  limit?: string;
}

const dash = (p: string) => p.replace(':', '-');

function richText(r: Rich): string {
  const t: string[] = ['rule'];
  if (r.priority !== undefined) t.push(`priority="${r.priority}"`);
  if (r.family) t.push(`family="${r.family}"`);
  if (r.srcIpset) t.push(`source ipset="${r.srcIpset}"`);
  else if (r.srcMac) t.push(`source mac="${r.srcMac}"`);
  else if (r.src) t.push(`source address="${r.src}"`);
  if (r.dst) t.push(`destination address="${r.dst}"`);
  const e = r.element;
  if (e?.kind === 'port') t.push(`port port="${e.port}" protocol="${e.proto}"`);
  if (e?.kind === 'source-port') t.push(`source-port port="${e.port}" protocol="${e.proto}"`);
  if (e?.kind === 'protocol') t.push(`protocol value="${e.value}"`);
  if (e?.kind === 'icmp') t.push(`icmp-type name="${e.name}"`);
  if (e?.kind === 'masquerade') t.push('masquerade');
  if (e?.kind === 'forward-port') {
    t.push(`forward-port port="${e.port}" protocol="${e.proto}"${e.toPort ? ` to-port="${e.toPort}"` : ''}${e.toAddr ? ` to-addr="${e.toAddr}"` : ''}`);
  }
  if (r.log) t.push(`log prefix="${r.log}" level="info"`);
  if (r.action) t.push(r.action);
  if (r.limit) t.push(`limit value="${r.limit}"`);
  return t.join(' ');
}

function richXml(r: Rich, ind: string): string[] {
  const attrs = [r.priority !== undefined ? ` priority="${r.priority}"` : '', r.family ? ` family="${r.family}"` : ''].join('');
  const x: string[] = [`${ind}<rule${attrs}>`];
  if (r.srcIpset) x.push(`${ind}  <source ipset="${r.srcIpset}"/>`);
  else if (r.srcMac) x.push(`${ind}  <source mac="${r.srcMac}"/>`);
  else if (r.src) x.push(`${ind}  <source address="${r.src}"/>`);
  if (r.dst) x.push(`${ind}  <destination address="${r.dst}"/>`);
  const e = r.element;
  if (e?.kind === 'port') x.push(`${ind}  <port port="${e.port}" protocol="${e.proto}"/>`);
  if (e?.kind === 'source-port') x.push(`${ind}  <source-port port="${e.port}" protocol="${e.proto}"/>`);
  if (e?.kind === 'protocol') x.push(`${ind}  <protocol value="${e.value}"/>`);
  if (e?.kind === 'icmp') x.push(`${ind}  <icmp-type name="${e.name}"/>`);
  if (e?.kind === 'masquerade') x.push(`${ind}  <masquerade/>`);
  if (e?.kind === 'forward-port') {
    x.push(`${ind}  <forward-port port="${e.port}" protocol="${e.proto}"${e.toPort ? ` to-port="${e.toPort}"` : ''}${e.toAddr ? ` to-addr="${e.toAddr}"` : ''}/>`);
  }
  if (r.log) x.push(`${ind}  <log prefix="${r.log}" level="info"/>`);
  if (r.action) {
    if (r.limit) x.push(`${ind}  <${r.action}>`, `${ind}    <limit value="${r.limit}"/>`, `${ind}  </${r.action}>`);
    else x.push(`${ind}  <${r.action}/>`);
  }
  x.push(`${ind}</rule>`);
  return x;
}

/** Expands one rule into rich rules (one per family / address pair / port). */
function toRich(rr: ResolvedRule, priority: number | undefined, d: Diags): Rich[] {
  const r = rr.rule;
  const out: Rich[] = [];
  const both = rr.v4 && rr.v6;
  const noAddr = (v: { src: string[]; dst: string[] } | null) => !v || (v.src.length === 0 && v.dst.length === 0);
  const neutral = both && noAddr(rr.v4) && noAddr(rr.v6) && !(r.proto === 'icmp' && !r.icmpType);
  const views: [Fam | undefined, { src: string[]; dst: string[] }][] = neutral
    ? [[undefined, { src: [], dst: [] }]]
    : ([['ipv4', rr.v4], ['ipv6', rr.v6]].filter((x) => x[1]) as [Fam, { src: string[]; dst: string[] }][]);

  if (r.states && r.states.length > 0) d.unsupported(`"${r.name}": firewalld rich rules cannot match connection state; the state match is left out.`, r.id);
  const limit = r.rateLimit && r.action === 'accept' ? `${r.rateLimit.rate}/${r.rateLimit.per[0]}` : undefined;
  if (r.rateLimit?.perSource && r.action === 'accept') d.unsupported(`"${r.name}": firewalld limits are shared by all clients; the per-client setting is not applied.`, r.id);
  if (r.connLimit) d.unsupported(`"${r.name}": firewalld has no per-client connection limit; left out.`, r.id);
  if (r.schedule) d.unsupported(`"${r.name}": firewalld has no time-based rules; the rule is active at all times.`, r.id);
  if (r.mark) d.unsupported(`"${r.name}": firewalld rich rules cannot match a packet mark; left out.`, r.id);
  if (rr.srcPorts.length > 0 && rr.ports.length > 0) d.unsupported(`"${r.name}": a rich rule takes either a source port or a destination port; the source-port match is left out.`, r.id);
  if (limit && r.rateLimit!.burst > 0) d.note(`"${r.name}": the burst value is not passed to firewalld: no release up to 2.5.2 accepts a burst on rich-rule limits.`, r.id);

  for (const [family, view] of views) {
    const elements: (Element | undefined)[] = [];
    for (const proto of rr.protos) {
      if (proto === 'any') elements.push(undefined);
      else if (proto === 'icmp') {
        if (r.icmpType) elements.push({ kind: 'icmp', name: r.icmpType });
        else elements.push({ kind: 'protocol', value: family === 'ipv6' ? 'ipv6-icmp' : 'icmp' });
      } else if (rr.ports.length === 0 && rr.srcPorts.length > 0) for (const port of rr.srcPorts) elements.push({ kind: 'source-port', port: dash(port), proto });
      else if (rr.ports.length === 0) elements.push({ kind: 'protocol', value: proto });
      else for (const port of rr.ports) elements.push({ kind: 'port', port: dash(port), proto });
    }
    for (const element of elements) {
      for (const [src, dst] of cartesian(orAny(view.src), orAny(view.dst))) {
        if (!element && !src && !dst && !r.srcMac) {
          // A rich rule needs an element or an address: spell "any address" out per family.
          for (const fam of (family ? [family] : (['ipv4', 'ipv6'] as Fam[]))) {
            if (fam === 'ipv4' ? !rr.v4 : !rr.v6) continue;
            out.push({ ruleId: r.id, priority, family: fam, src: fam === 'ipv4' ? '0.0.0.0/0' : '::/0', log: r.log ? logPrefix(r.name || r.id) : undefined, action: r.action, limit });
          }
          continue;
        }
        out.push({
          ruleId: r.id,
          priority,
          family: r.srcMac && !src && !dst ? undefined : family,
          src,
          srcMac: !src ? r.srcMac : undefined,
          dst,
          element,
          log: r.log ? logPrefix(r.name || r.id) : undefined,
          action: r.action,
          limit,
        });
      }
    }
  }
  return out;
}

function isSimplePort(rr: ResolvedRule): boolean {
  const r = rr.rule;
  return (
    r.action === 'accept' && !!rr.v4 && !!rr.v6 && rr.v4.src.length + rr.v4.dst.length + rr.v6.src.length + rr.v6.dst.length === 0 &&
    r.proto !== 'any' && r.proto !== 'icmp' && rr.ports.length > 0 && rr.srcPorts.length === 0 && !r.srcMac && !r.schedule && !r.connLimit && !r.mark && !r.log && !r.rateLimit && !(r.states && r.states.length > 0)
  );
}

interface Section {
  ports: { port: string; proto: string; ruleId: string }[];
  rich: Rich[];
}

export function compileFirewalld(p: Project, target: Target): CompileResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));
  const caps = target.caps;
  const opt = p.options;
  const byDir = (dir: Direction) => rules.filter((r) => r.rule.direction === dir);

  /** Builds ports + rich rules for one direction, keeping rule order where the version allows. */
  const build = (dir: Direction): Section => {
    const list = byDir(dir);
    const sec: Section = { ports: [], rich: [] };
    const ordered = new Set(list.map((r) => r.rule.action)).size > 1;
    if (ordered && !caps.richPriority) {
      d.fallback(`firewalld ${target.version} has no rich-rule priorities (0.7.0+): it evaluates log, then deny, then allow rules, so the order of your ${dir === 'in' ? 'inbound' : dir} rules is not preserved.`);
    }
    list.forEach((rr, i) => {
      if (rr.rule.inIface || rr.rule.outIface) {
        d.unsupported(`"${rr.rule.name}": firewalld matches interfaces by binding them to a zone, not per rule; the interface match is left out.`, rr.rule.id);
      }
      if (!ordered && dir === 'in' && isSimplePort(rr)) {
        for (const proto of rr.protos) for (const port of rr.ports) sec.ports.push({ port: dash(port), proto, ruleId: rr.rule.id });
      } else {
        sec.rich.push(...toRich(rr, ordered && caps.richPriority ? -1000 + i * 10 : undefined, d));
      }
    });
    return sec;
  };

  const zone = build('in');
  const zonePre: Rich[] = [];
  if (!opt.ipv6) {
    zonePre.push({ family: 'ipv6', action: 'drop', priority: caps.richPriority ? -32000 : undefined });
    d.note('IPv6 is switched off in this project: a rich rule drops all IPv6 traffic reaching the zone.');
  }
  if (opt.allowIcmp && p.policies.in === 'drop') {
    zonePre.push({ element: { kind: 'icmp', name: 'echo-request' }, action: 'accept', priority: caps.richPriority ? -31000 : undefined });
  }
  const lists = activeLists(p, d);
  const ipsetCmds: string[] = [];
  for (const l of lists) {
    for (const [fam, sfx, members] of (opt.ipv6 ? [['ipv4', 'v4', l.v4], ['ipv6', 'v6', l.v6]] : [['ipv4', 'v4', l.v4]]) as [Fam, string, string[]][]) {
      const set = `${l.set}_${sfx}`;
      ipsetCmds.push(`firewall-cmd --permanent --delete-ipset=${set} >/dev/null 2>&1 || true`);
      ipsetCmds.push(`firewall-cmd --permanent --new-ipset=${set} --type=hash:net${fam === 'ipv6' ? ' --option=family=inet6' : ''}`);
      members.forEach((e) => ipsetCmds.push(`firewall-cmd --permanent --ipset=${set} --add-entry=${e}`));
      zonePre.unshift({ family: fam, srcIpset: set, action: 'drop', priority: caps.richPriority ? -32500 : undefined });
    }
    if (l.outbound) d.unsupported(`Blocklist "${l.name}": firewalld output only blocks traffic coming from the list, not going to it.`);
  }
  zone.rich.unshift(...zonePre);

  // NAT
  let masquerade = false;
  const forwardPorts: { port: string; proto: string; toPort?: string; toAddr?: string; ruleId: string }[] = [];
  const directNat: { fam: Fam; spec: string; ruleId?: string }[] = [];
  for (const n of p.nat.filter((x) => x.enabled)) {
    const fam = natFamily(n);
    if (n.kind === 'masquerade') {
      if (n.src) zone.rich.push({ ruleId: n.id, family: fam, src: n.src, element: { kind: 'masquerade' } });
      else masquerade = true;
      if (n.iface) d.note(`"${n.name}": masquerading is switched on for the ${ZONE} zone; bind ${n.iface} to that zone.`, n.id);
    } else if (n.kind === 'dnat') {
      if (!n.port || n.proto === 'any' || !n.toAddr) {
        d.unsupported(`"${n.name}": firewalld port forwards need a protocol, a port and a target address.`, n.id);
        continue;
      }
      const fp = { port: dash(n.port), proto: n.proto, toPort: n.toPort ? dash(n.toPort) : undefined, toAddr: n.toAddr };
      if (n.src || n.dst) zone.rich.push({ ruleId: n.id, family: fam, src: n.src, dst: n.dst, element: { kind: 'forward-port', ...fp } });
      else forwardPorts.push({ ...fp, ruleId: n.id });
    } else {
      d.fallback(`"${n.name}": firewalld has no SNAT setting; emitted through the direct interface (iptables syntax).`, n.id);
      const only = { ...p, nat: [n] };
      for (const l of natLines(only, fam, { snat: true, masquerade: true }, d)) directNat.push({ fam, spec: l.text.replace(/^-A POSTROUTING /, ''), ruleId: n.id });
    }
  }

  // Outbound / forward
  const needOut = byDir('out').length > 0 || p.policies.out === 'drop';
  const needFwd = byDir('forward').length > 0;
  const outSec = needOut && caps.policies ? build('out') : null;
  const fwdSec = needFwd && caps.policies ? build('forward') : null;
  if ((needOut || needFwd) && !caps.policies) {
    d.fallback(`firewalld ${target.version} has no policy objects (0.9.0+); outbound and forward rules use the direct interface (iptables syntax).`);
  }

  // ---- shell script ----
  const o = new Out();
  const cmd = 'firewall-cmd --permanent';
  o.push('#!/bin/sh');
  o.push(`# ${BANNER} - ${p.name}`);
  o.push(`# Target: ${target.label}`);
  o.push(`# Creates the "${ZONE}" zone and makes it the default zone. Run as root.`);
  o.push('set -eu');
  o.blank();
  o.push(`${cmd} --delete-zone=${ZONE} >/dev/null 2>&1 || true`);
  ipsetCmds.forEach((c) => o.push(c));
  o.push(`${cmd} --new-zone=${ZONE}`);
  o.push(`${cmd} --zone=${ZONE} --set-target=${p.policies.in === 'drop' ? 'DROP' : 'ACCEPT'}`);
  for (const pt of zone.ports) o.push(`${cmd} --zone=${ZONE} --add-port=${pt.port}/${pt.proto}`, pt.ruleId);
  for (const r of zone.rich) o.push(`${cmd} --zone=${ZONE} --add-rich-rule=${shQuote(richText(r))}`, r.ruleId);
  if (masquerade) o.push(`${cmd} --zone=${ZONE} --add-masquerade`);
  for (const f of forwardPorts) {
    o.push(`${cmd} --zone=${ZONE} --add-forward-port=port=${f.port}:proto=${f.proto}${f.toPort ? `:toport=${f.toPort}` : ''}:toaddr=${f.toAddr}`, f.ruleId);
  }

  const policy = (name: string, ingress: string, egress: string, tgt: string, sec: Section) => {
    o.blank();
    o.push(`${cmd} --delete-policy=${name} >/dev/null 2>&1 || true`);
    o.push(`${cmd} --new-policy=${name}`);
    o.push(`${cmd} --policy=${name} --add-ingress-zone=${ingress}`);
    o.push(`${cmd} --policy=${name} --add-egress-zone=${egress}`);
    o.push(`${cmd} --policy=${name} --set-target=${tgt}`);
    for (const r of sec.rich) o.push(`${cmd} --policy=${name} --add-rich-rule=${shQuote(richText(r))}`, r.ruleId);
  };
  if (outSec) policy('ew-out', 'HOST', 'ANY', p.policies.out === 'drop' ? 'DROP' : 'CONTINUE', outSec);
  if (fwdSec) policy('ew-fwd', 'ANY', 'ANY', p.policies.forward === 'drop' ? 'DROP' : 'CONTINUE', fwdSec);

  const direct: string[] = [];
  if (!caps.policies) {
    const fams: Fam[] = opt.ipv6 ? ['ipv4', 'ipv6'] : ['ipv4'];
    for (const fam of fams) {
      if (needOut && p.policies.out === 'drop') {
        o.push(`${cmd} --direct --add-rule ${fam} filter OUTPUT 0 -o lo -j ACCEPT`);
        o.push(`${cmd} --direct --add-rule ${fam} filter OUTPUT 0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`);
      }
      for (const dir of ['out', 'forward'] as const) {
        byDir(dir).forEach((rr, i) => {
          for (const s of ruleSpecs(rr, fam)) {
            const line = `${cmd} --direct --add-rule ${fam} filter ${dir === 'out' ? 'OUTPUT' : 'FORWARD'} ${i + 1} ${s.replace(/"/g, "'")}`;
            o.push(line, rr.rule.id);
            direct.push(line);
          }
        });
      }
      if (needOut && p.policies.out === 'drop') o.push(`${cmd} --direct --add-rule ${fam} filter OUTPUT 999 -j DROP`);
    }
  }
  for (const n of directNat) o.push(`${cmd} --direct --add-rule ${n.fam} nat POSTROUTING 0 ${n.spec.replace(/"/g, "'")}`, n.ruleId);

  o.blank();
  o.push(`firewall-cmd --set-log-denied=${opt.logDropped ? 'all' : 'off'}`);
  o.push('firewall-cmd --reload');
  o.push(`firewall-cmd --set-default-zone=${ZONE}`);
  o.push('firewall-cmd --list-all');
  o.blank();
  o.push('# Bind interfaces explicitly if you use more than one zone:');
  o.push(`#   firewall-cmd --permanent --zone=${ZONE} --change-interface=eth0 && firewall-cmd --reload`);

  // ---- zone XML ----
  const x = new Out();
  x.push('<?xml version="1.0" encoding="utf-8"?>');
  x.push(`<!-- ${BANNER} - ${p.name}. Target: ${target.label} -->`);
  x.push(`<zone target="${p.policies.in === 'drop' ? 'DROP' : 'ACCEPT'}">`);
  x.push('  <short>Emberwall</short>');
  x.push(`  <description>${(p.description || p.name).replace(/[<>&]/g, '')}</description>`);
  for (const pt of zone.ports) x.push(`  <port port="${pt.port}" protocol="${pt.proto}"/>`, pt.ruleId);
  if (masquerade) x.push('  <masquerade/>');
  for (const f of forwardPorts) {
    x.push(`  <forward-port port="${f.port}" protocol="${f.proto}"${f.toPort ? ` to-port="${f.toPort}"` : ''} to-addr="${f.toAddr}"/>`, f.ruleId);
  }
  for (const r of zone.rich) for (const l of richXml(r, '  ')) x.push(l, r.ruleId);
  x.push('</zone>');

  const pr = p.protections ?? {};
  if (pr.synFlood || pr.portScan || pr.autoBan) {
    d.unsupported('firewalld has no settings for scan, flood or auto-ban protection; they are not part of this output. Use the nftables or iptables target for those.');
  }
  if (!opt.allowLoopback || !opt.allowEstablished || !opt.dropInvalid) {
    d.note('firewalld always accepts loopback and established traffic and drops invalid packets. Those toggles have no effect on this target.');
  }
  if (p.policies.forward === 'accept' && !fwdSec) {
    d.unsupported('firewalld rejects forwarded traffic between zones unless a policy allows it; a default-accept forward policy is not emitted.');
  }

  const files: OutFile[] = [
    { name: 'emberwall-firewalld.sh', path: './emberwall-firewalld.sh', lang: 'shell', description: 'firewall-cmd commands', lines: o.lines },
    {
      name: `${ZONE}.xml`,
      path: `/etc/firewalld/zones/${ZONE}.xml`,
      lang: 'xml',
      description: 'Zone file (alternative to the script, inbound part)',
      lines: x.lines,
    },
    safeApplyScript({
      toolLabel: target.label,
      backup: ['cp -a /etc/firewalld "$BACKUP/firewalld"', 'firewall-cmd --get-default-zone > "$BACKUP/default-zone"'],
      check: ['firewall-cmd --state'],
      apply: ['sh "$DIR/emberwall-firewalld.sh"'],
      rollback: [
        'rm -rf /etc/firewalld && cp -a "$BACKUP/firewalld" /etc/firewalld',
        'firewall-cmd --reload',
        'firewall-cmd --set-default-zone="$(cat "$BACKUP/default-zone")"',
      ],
      persist: ['Everything is written with --permanent, so it already survives a reboot.'],
    }),
  ];
  void direct;
  files.push(...blocklistUpdater(lists, 'firewalld', opt.ipv6));
  const sys = sysctlFile(p);
  if (sys) files.push(sys);
  return { target, files, diagnostics: d.list };
}
