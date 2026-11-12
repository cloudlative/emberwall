// Expands group references and splits a rule by address family.
import type { Project, Rule } from './model';
import { familyOf, normPort, parseCidr, parsePort } from './net';

export interface FamilyView {
  src: string[];
  dst: string[];
}

export interface ResolvedRule {
  rule: Rule;
  /** null when the rule does not apply to that family. */
  v4: FamilyView | null;
  v6: FamilyView | null;
  ports: string[];
  srcPorts: string[];
  /** Concrete protocols: tcpudp becomes ['tcp','udp']. */
  protos: ('any' | 'tcp' | 'udp' | 'icmp')[];
  problems: string[];
}

export function expandAddrs(list: string[], p: Project, problems: string[] = []): string[] {
  const out: string[] = [];
  for (const entry of list) {
    const e = entry.trim();
    if (!e) continue;
    if (e.startsWith('@')) {
      const g = p.addressGroups.find((x) => x.id === e.slice(1));
      if (!g) problems.push(`unknown address group ${e}`);
      else out.push(...expandAddrs(g.members, { ...p, addressGroups: p.addressGroups.filter((x) => x.id !== g.id) }, problems));
    } else if (!parseCidr(e)) {
      problems.push(`invalid address "${e}"`);
    } else {
      out.push(e);
    }
  }
  return [...new Set(out)];
}

export function expandPorts(list: string[], p: Project, problems: string[] = []): string[] {
  const out: string[] = [];
  for (const entry of list) {
    const e = entry.trim();
    if (!e) continue;
    if (e.startsWith('@')) {
      const g = p.portGroups.find((x) => x.id === e.slice(1));
      if (!g) problems.push(`unknown port group ${e}`);
      else out.push(...expandPorts(g.ports, { ...p, portGroups: [] }, problems));
    } else if (!parsePort(e)) {
      problems.push(`invalid port "${e}"`);
    } else {
      out.push(normPort(e));
    }
  }
  return [...new Set(out)];
}

export function resolveRule(rule: Rule, p: Project): ResolvedRule {
  const problems: string[] = [];
  const src = expandAddrs(rule.src, p, problems);
  const dst = expandAddrs(rule.dst, p, problems);
  const hasPorts = rule.proto === 'tcp' || rule.proto === 'udp' || rule.proto === 'tcpudp';
  const ports = hasPorts ? expandPorts(rule.ports, p, problems) : [];
  const srcPorts = hasPorts ? expandPorts(rule.srcPorts ?? [], p, problems) : [];
  if (rule.srcMac && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(rule.srcMac)) problems.push(`invalid MAC address "${rule.srcMac}"`);
  if (rule.schedule && !(/^\d\d:\d\d$/.test(rule.schedule.from) && /^\d\d:\d\d$/.test(rule.schedule.to))) problems.push('schedule times must be HH:MM');
  if (rule.mark && !/^(0x[0-9a-f]+|\d+)$/i.test(rule.mark)) problems.push(`invalid packet mark "${rule.mark}"`);
  if (!hasPorts && rule.ports.length > 0) problems.push('ports are ignored unless the protocol is TCP or UDP');

  const view = (fam: 'ipv4' | 'ipv6'): FamilyView | null => {
    if (rule.family !== 'both' && rule.family !== fam) return null;
    if (fam === 'ipv6' && !p.options.ipv6) return null;
    const s = src.filter((a) => familyOf(a) === fam);
    const d = dst.filter((a) => familyOf(a) === fam);
    // Addresses were given, but none of this family: the rule cannot match here.
    if ((src.length > 0 && s.length === 0) || (dst.length > 0 && d.length === 0)) return null;
    return { src: s, dst: d };
  };

  const v4 = view('ipv4');
  const v6 = view('ipv6');
  if (!v4 && !v6) problems.push('rule matches no address family (check addresses against the IPv4/IPv6 setting)');

  const protos: ResolvedRule['protos'] = rule.proto === 'tcpudp' ? ['tcp', 'udp'] : [rule.proto];
  return { rule, v4, v6, ports, srcPorts, protos, problems };
}

/**
 * Turns zone references into concrete interface and network matches.
 * A zone with several interfaces yields one rule per interface (same rule id).
 */
export function expandZones(rule: Rule, p: Project, problems: string[] = []): Rule[] {
  if (!rule.srcZone && !rule.dstZone) return [rule];
  const zone = (id?: string) => {
    if (!id) return null;
    const z = p.zones.find((x) => x.id === id);
    if (!z) problems.push(`unknown zone "${id}"`);
    return z ?? null;
  };
  const sz = rule.direction !== 'out' ? zone(rule.srcZone) : null;
  const dz = rule.direction !== 'in' ? zone(rule.dstZone) : null;
  const base: Rule = {
    ...rule,
    src: sz && sz.networks.length > 0 ? [...rule.src, ...sz.networks] : rule.src,
    dst: dz && dz.networks.length > 0 ? [...rule.dst, ...dz.networks] : rule.dst,
  };
  const ins = sz && sz.interfaces.length > 0 && !rule.inIface ? sz.interfaces : [rule.inIface];
  const outs = dz && dz.interfaces.length > 0 && !rule.outIface ? dz.interfaces : [rule.outIface];
  return cartesian(ins, outs).map(([inIface, outIface]) => ({ ...base, inIface, outIface }));
}

export function resolveAll(p: Project): ResolvedRule[] {
  return p.rules.filter((r) => r.enabled).flatMap((r) => {
    const problems: string[] = [];
    return expandZones(r, p, problems).map((x) => {
      const rr = resolveRule(x, p);
      rr.problems.unshift(...problems);
      return rr;
    });
  });
}

/** Stable short id for kernel object names (hashlimit names, set names). */
export function shortId(id: string): string {
  let h = 2166136261;
  for (let i = 0; i < id.length; i += 1) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  return (h >>> 0).toString(36);
}

/** Short tag safe for log prefixes, set names and comments. */
export function slug(text: string, max = 20): string {
  const s = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return (s || 'rule').slice(0, max).replace(/-+$/, '');
}

export function cartesian<A, B>(a: A[], b: B[]): [A, B][] {
  const out: [A, B][] = [];
  for (const x of a) for (const y of b) out.push([x, y]);
  return out;
}

/** Empty list means "any": iterate once with undefined. */
export function orAny<T>(list: T[]): (T | undefined)[] {
  return list.length === 0 ? [undefined] : list;
}
