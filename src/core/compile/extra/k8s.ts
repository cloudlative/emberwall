// Kubernetes NetworkPolicy (networking.k8s.io/v1) for one set of pods.
//
// A NetworkPolicy is an allow-list. Once a pod is selected for a direction, everything in that
// direction is denied except what some policy allows. There are no deny rules, no order,
// no interfaces, no logging and no limits; ICMP behaviour is left to the network plugin.
import type { Project } from '../../model';
import { parseCidr } from '../../net';
import { resolveAll, slug, type ResolvedRule } from '../../resolve';
import { BANNER, Diags, Out, type OutFile } from '../types';
import type { ExtraResult } from './index';

export interface K8sOptions {
  namespace: string;
  podSelector: Record<string, string>;
}

/** ipBlock.cidr must be a CIDR with the host bits cleared. */
function toCidr(a: string): string {
  const c = parseCidr(a);
  if (!c) return a;
  const text = a.trim().split('/')[0];
  const host = BigInt(c.bits - c.prefix);
  const net = (c.addr >> host) << host;
  if (net === c.addr) return `${text}/${c.prefix}`;
  if (c.family === 'ipv4') return `${[24n, 16n, 8n, 0n].map((s) => String((net >> s) & 255n)).join('.')}/${c.prefix}`;
  const groups: string[] = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(((net >> BigInt(i * 16)) & 0xffffn).toString(16));
  return `${groups.join(':')}/${c.prefix}`;
}

/** YAML double-quoted scalar (JSON strings are valid YAML). */
function y(s: string): string {
  return JSON.stringify(s);
}

function yamlComment(text: string): string {
  return `# ${text.replace(/[\r\n]+/g, ' ')}`;
}

function expressible(rr: ResolvedRule, d: Diags): boolean {
  const r = rr.rule;
  const skip = (why: string) => {
    d.unsupported(`"${r.name}": ${why}. The rule is not in the policy.`, r.id);
    return false;
  };
  if (r.direction === 'forward') return skip('a NetworkPolicy covers traffic to and from pods; there is no forwarding');
  if (r.action !== 'accept') {
    return skip(`a NetworkPolicy can only allow. A ${r.action} rule cannot be expressed; traffic it would block is still blocked only if no allow rule (in any NetworkPolicy selecting the pods) matches it`);
  }
  if (r.inIface || r.outIface) return skip(`a NetworkPolicy cannot match an interface (${r.inIface ?? r.outIface})`);
  if (r.srcMac) return skip('a NetworkPolicy cannot match a MAC address');
  if (r.mark) return skip('packet marks only exist inside a Linux host');
  if (r.schedule) return skip('a NetworkPolicy has no schedules');
  if (rr.protos.includes('icmp')) return skip('a NetworkPolicy only knows TCP, UDP and SCTP ports; whether ICMP is filtered at all depends on the network plugin');
  if (rr.srcPorts.length > 0) return skip('a NetworkPolicy cannot match source ports');
  if (r.states && r.states.length > 0 && !r.states.includes('new')) {
    if (r.states.every((s) => s === 'established' || s === 'related')) {
      d.note(`"${r.name}": NetworkPolicy is stateful and allows replies without a rule, so this rule is left out.`, r.id);
      return false;
    }
    return skip(`a NetworkPolicy cannot match connection state ${r.states.join(',')}`);
  }
  return true;
}

/** YAML lines (already indented under "ingress:" / "egress:") for one rule. */
function ruleEntry(rr: ResolvedRule, d: Diags): string[] {
  const r = rr.rule;
  const inbound = r.direction === 'in';
  if (r.rateLimit) d.unsupported(`"${r.name}": a NetworkPolicy has no rate limits. The rule is emitted WITHOUT the limit.`, r.id);
  if (r.connLimit) d.unsupported(`"${r.name}": a NetworkPolicy has no connection limits. The rule is emitted WITHOUT the limit.`, r.id);
  if (r.log) d.unsupported(`"${r.name}": a NetworkPolicy cannot log. The rule is emitted without logging.`, r.id);
  if (r.states && r.states.length > 0) d.note(`"${r.name}": connection states cannot be matched; the rule applies to new connections and replies are always allowed.`, r.id);

  const views = [rr.v4, rr.v6].filter((v): v is NonNullable<typeof v> => !!v);
  if (views.length === 0) return [];
  const local = views.flatMap((v) => (inbound ? v.dst : v.src));
  if (local.length > 0) {
    d.fallback(`"${r.name}": a NetworkPolicy selects pods by label, not by their address; the ${inbound ? 'destination' : 'source'} address is ignored and the rule applies to all selected pods.`, r.id);
  }
  let peers = views.flatMap((v) => (inbound ? v.src : v.dst)).map(toCidr);
  // One family only and no address named: pin the rule to that family.
  if (peers.length === 0 && !(rr.v4 && rr.v6)) peers = [rr.v4 ? '0.0.0.0/0' : '::/0'];

  const lines: string[] = [];
  lines.push(`    ${yamlComment(r.name || r.id)}`);
  let first = true;
  const key = (text: string) => {
    lines.push(`    ${first ? '- ' : '  '}${text}`);
    first = false;
  };
  if (peers.length > 0) {
    key(inbound ? 'from:' : 'to:');
    for (const cidr of peers) {
      lines.push('        - ipBlock:');
      lines.push(`            cidr: ${y(cidr)}`);
    }
  }
  const ports: string[] = [];
  for (const proto of rr.protos) {
    if (proto !== 'tcp' && proto !== 'udp') continue;
    const P = proto.toUpperCase();
    if (rr.ports.length === 0) {
      ports.push(`        - protocol: ${P}`);
      continue;
    }
    for (const port of rr.ports) {
      const [from, to] = port.split(':');
      ports.push(`        - protocol: ${P}`);
      ports.push(`          port: ${from}`);
      if (to !== undefined) ports.push(`          endPort: ${to}`);
    }
  }
  if (ports.length > 0) {
    key('ports:');
    lines.push(...ports);
  }
  // No peers and no ports: the empty rule, which allows everything in this direction.
  if (first) lines.push('    - {}');
  return lines;
}

export function compileK8s(p: Project, opts: K8sOptions): ExtraResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));

  const ingress = new Out();
  const egress = new Out();
  for (const rr of rules) {
    if (!expressible(rr, d)) continue;
    const target = rr.rule.direction === 'in' ? ingress : egress;
    ruleEntry(rr, d).forEach((l) => target.push(l, rr.rule.id));
  }
  const withEgress = p.policies.out === 'drop' || egress.lines.length > 0;

  const name = `emberwall-${slug(p.name, 40)}`;
  const o = new Out();
  o.push(yamlComment(`${BANNER} - ${p.name}`));
  o.push('# Target: Kubernetes NetworkPolicy (networking.k8s.io/v1)');
  o.push(`# Apply: kubectl apply -f ${name}.yaml      (needs a network plugin that enforces NetworkPolicy)`);
  o.push('# NetworkPolicy is an allow-list: the selected pods accept only what is listed here');
  o.push('# (plus whatever other NetworkPolicies selecting them allow).');
  o.push('apiVersion: networking.k8s.io/v1');
  o.push('kind: NetworkPolicy');
  o.push('metadata:');
  o.push(`  name: ${name}`);
  o.push(`  namespace: ${y(opts.namespace)}`);
  o.push('spec:');
  const labels = Object.entries(opts.podSelector);
  if (labels.length === 0) {
    o.push('  # Empty selector: every pod in the namespace.');
    o.push('  podSelector: {}');
  } else {
    o.push('  podSelector:');
    o.push('    matchLabels:');
    for (const [k, v] of labels) o.push(`      ${y(k)}: ${y(v)}`);
  }
  o.push('  policyTypes:');
  o.push('    - Ingress');
  if (withEgress) o.push('    - Egress');

  if (p.policies.in === 'accept') {
    o.push('  ingress:');
    o.add(ingress.lines);
    o.push('    # Inbound policy "accept": allow everything in.');
    o.push('    - {}');
    d.note('Inbound policy "accept" becomes an allow-all ingress rule; the other ingress rules are then redundant.');
  } else if (ingress.lines.length > 0) {
    o.push('  ingress:');
    o.add(ingress.lines);
  } else {
    o.push('  # No inbound rules: all ingress to the selected pods is denied.');
    o.push('  ingress: []');
  }

  if (withEgress) {
    if (p.policies.out === 'accept') {
      o.push('  egress:');
      o.add(egress.lines);
      o.push('    # Outbound policy "accept": allow everything out.');
      o.push('    - {}');
      d.note('Outbound policy "accept" becomes an allow-all egress rule after the outbound rules, which are then redundant.');
    } else if (egress.lines.length > 0) {
      o.push('  egress:');
      o.add(egress.lines);
    } else {
      o.push('  # Outbound policy "drop" and no outbound rules: all egress from the selected pods is denied.');
      o.push('  egress: []');
    }
    if (p.policies.out === 'drop') {
      d.note('Outbound policy "drop": the pods lose DNS unless an outbound rule allows port 53 (TCP and UDP) to the cluster DNS service.');
    }
  } else {
    d.note('Outbound policy "accept" and no outbound rules: the policy does not list Egress, so egress from the pods stays unrestricted.');
  }

  d.note('NetworkPolicy is allow-only and has no rule order: drop and reject rules cannot be expressed, and a rule cannot carve an exception out of a broader allow.');
  d.note('The inbound policy "drop" is what listing Ingress in policyTypes does: everything not allowed here (or by another NetworkPolicy selecting the same pods) is denied.');
  d.note('Traffic to and from the node a pod runs on is always allowed, and ipBlock matching of cluster-internal addresses depends on the network plugin (source addresses may be rewritten). Use ipBlock for addresses outside the cluster.');
  if (rules.some((r) => r.ports.some((x) => x.includes(':')))) d.note('Port ranges use endPort (stable since Kubernetes 1.25); the network plugin must support it, otherwise only the first port of the range is allowed.');
  if (p.options.allowIcmp) d.unsupported('"Allow ping / ICMP": NetworkPolicy cannot express ICMP; whether ping works depends on the network plugin. Nothing was emitted for it.');
  if (p.options.logDropped) d.unsupported('"Log dropped packets": NetworkPolicy has no logging (some network plugins offer their own). Nothing was emitted for it.');
  if (!p.options.allowEstablished) d.fallback('"Allow established connections" is off in the project, but NetworkPolicy always allows replies to permitted connections.');
  if (p.options.forwarding || p.policies.forward === 'accept') d.note('The forward policy and the forwarding option have no equivalent in a NetworkPolicy.');
  for (const n of p.nat.filter((x) => x.enabled)) {
    d.unsupported(`NAT rule "${n.name}": a NetworkPolicy does not translate addresses (use a Service or Ingress). Nothing was emitted for it.`, n.id);
  }
  const pr = p.protections ?? {};
  if (pr.synFlood || pr.portScan || (pr.autoBan && pr.autoBan.ports.length > 0)) {
    d.unsupported('Protections (SYN flood guard, port-scan drops, auto-ban) cannot be expressed in a NetworkPolicy. Nothing was emitted for them.');
  }
  if (!p.options.ipv6) d.note('IPv6 is switched off in the project: rules without addresses are pinned to 0.0.0.0/0.');

  const file: OutFile = {
    name: `${name}.yaml`,
    path: `${name}.yaml`,
    lang: 'yaml',
    description: `Kubernetes NetworkPolicy for pods ${labels.map(([k, v]) => `${k}=${v}`).join(',') || '(all)'} in namespace ${opts.namespace}`,
    lines: o.lines,
  };
  return { files: [file], diagnostics: d.list };
}
