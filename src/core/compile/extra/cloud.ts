// Cloud firewalls as Terraform (HCL): AWS security groups, Azure network security groups
// and Google Cloud VPC firewall rules.
//
// These filter traffic of virtual machines from outside the guest: there are no interfaces,
// no forward chain, no NAT and no connection-state matches. They are all stateful.
//  - AWS security groups only allow. No deny rules, no order.
//  - Azure NSG rules allow or deny and are evaluated by ascending priority.
//  - GCP firewall rules allow or deny and are evaluated by ascending priority.
import type { Project, Rule } from '../../model';
import { parseCidr } from '../../net';
import { resolveAll, slug, type ResolvedRule } from '../../resolve';
import { BANNER, Diags, Out, type OutFile } from '../types';
import type { ExtraResult } from './index';

export type CloudProvider = 'aws' | 'azure' | 'gcp';

const LABEL: Record<CloudProvider, string> = { aws: 'AWS security group', azure: 'Azure network security group', gcp: 'Google Cloud VPC firewall' };
/** With the indefinite article, for messages. */
const A: Record<CloudProvider, string> = { aws: 'an AWS security group', azure: 'an Azure network security group', gcp: 'a Google Cloud VPC firewall' };

const ICMP4: Record<string, number> = { 'echo-request': 8, 'echo-reply': 0, 'destination-unreachable': 3, 'time-exceeded': 11, 'parameter-problem': 12 };
const ICMP6: Record<string, number> = { 'echo-request': 128, 'echo-reply': 129, 'destination-unreachable': 1, 'time-exceeded': 3, 'parameter-problem': 4 };

type Fam = 'ipv4' | 'ipv6';
const ANY: Record<Fam, string> = { ipv4: '0.0.0.0/0', ipv6: '::/0' };

/** Address as a CIDR block with the host bits cleared, which cloud APIs insist on. */
export function toCidr(a: string): string {
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

/** HCL quoted string; "${" and "%{" would start a template sequence. */
function q(s: string): string {
  return JSON.stringify(s.replace(/[\r\n\t]+/g, ' ')).replace(/\$\{/g, '$$${').replace(/%\{/g, '%%{');
}
const qList = (items: string[]) => `[${items.map(q).join(', ')}]`;

type Item = [key: string, value: string] | { block: string; items: Item[] };

/** Writes blocks the way `terraform fmt` lays them out (aligned "=" within a run of attributes). */
class Hcl {
  o = new Out();
  block(header: string, items: Item[], ruleId?: string, depth = 0): this {
    const pad = '  '.repeat(depth);
    this.o.push(`${pad}${header} {`, ruleId);
    let i = 0;
    while (i < items.length) {
      const it = items[i];
      if (Array.isArray(it)) {
        let j = i;
        while (j < items.length && Array.isArray(items[j])) j += 1;
        const run = items.slice(i, j) as [string, string][];
        const width = Math.max(...run.map(([k]) => k.length));
        for (const [k, v] of run) this.o.push(`${pad}  ${k.padEnd(width)} = ${v}`, ruleId);
        i = j;
      } else {
        if (i > 0) this.o.push('', ruleId);
        this.block(it.block, it.items, ruleId, depth + 1);
        i += 1;
      }
    }
    this.o.push(`${pad}}`, ruleId);
    return this;
  }
  blank(): this {
    this.o.blank();
    return this;
  }
  comment(text: string, ruleId?: string): this {
    this.o.push(`# ${text.replace(/[\r\n]+/g, ' ')}`, ruleId);
    return this;
  }
}

interface View {
  fam: Fam;
  /** The other end: source of inbound traffic, destination of outbound traffic. */
  remote: string[];
  /** This end: the instances the firewall is attached to. */
  local: string[];
}

interface CloudRule {
  rr: ResolvedRule;
  rule: Rule;
  inbound: boolean;
  allow: boolean;
  views: View[];
  /** Dash form: "8000-8100". */
  ports: string[];
  srcPorts: string[];
}

function ident(name: string, n: number): string {
  const s = slug(name, 30).replace(/-/g, '_');
  return `${/^[a-z]/.test(s) ? s : `r_${s}`}_${n}`;
}

/** Applies what every provider lacks. Returns the rules that can be expressed at all. */
function prepare(p: Project, provider: CloudProvider, d: Diags): CloudRule[] {
  const out: CloudRule[] = [];
  const what = A[provider];
  for (const rr of resolveAll(p)) {
    const r = rr.rule;
    rr.problems.forEach((m) => d.invalid(`"${r.name}": ${m}`, r.id));
    const skip = (why: string) => d.unsupported(`"${r.name}": ${why}. The rule is not in the output.`, r.id);
    if (r.direction === 'forward') {
      skip(`${what} filters traffic to and from instances; there is no forwarding (routing is done by route tables and gateways)`);
      continue;
    }
    if (r.inIface || r.outIface) {
      skip(`${what} is attached to instances or subnets and cannot match an interface name (${r.inIface ?? r.outIface})`);
      continue;
    }
    if (r.srcMac) {
      skip(`${what} cannot match a MAC address`);
      continue;
    }
    if (r.mark) {
      skip('packet marks only exist inside a Linux host');
      continue;
    }
    if (r.schedule) {
      skip(`${what} has no schedules`);
      continue;
    }
    if (r.states && r.states.length > 0 && !r.states.includes('new')) {
      if (r.action === 'accept' && r.states.every((s) => s === 'established' || s === 'related')) {
        d.note(`"${r.name}": ${what} is stateful and allows replies without a rule, so this rule is left out.`, r.id);
      } else {
        skip(`${what} cannot match connection state ${r.states.join(',')}`);
      }
      continue;
    }
    if (r.states && r.states.length > 0) d.note(`"${r.name}": connection states cannot be matched; the rule applies to new connections and replies are allowed by the provider's state tracking.`, r.id);
    if (r.action !== 'accept' && provider === 'aws') {
      skip(`AWS security groups can only allow. A ${r.action} rule cannot be expressed (use a network ACL for explicit denies); traffic it would block is still blocked only if no allow rule matches it`);
      continue;
    }
    if (rr.srcPorts.length > 0 && provider !== 'azure') {
      skip(`${what} cannot match source ports`);
      continue;
    }
    if (r.action === 'reject') d.fallback(`"${r.name}": ${what} cannot reject (answer with a reset or ICMP error); the rule is emitted as a silent deny.`, r.id);
    if (r.rateLimit) d.unsupported(`"${r.name}": ${what} has no rate limits. The rule is emitted WITHOUT the limit.`, r.id);
    if (r.connLimit) d.unsupported(`"${r.name}": ${what} has no connection limits. The rule is emitted WITHOUT the limit.`, r.id);
    if (r.log && provider === 'aws') d.unsupported(`"${r.name}": security groups cannot log per rule (use VPC Flow Logs). The rule is emitted without logging.`, r.id);
    if (r.log && provider === 'azure') d.unsupported(`"${r.name}": NSG rules cannot log individually (enable NSG / VNet flow logs on the group). The rule is emitted without logging.`, r.id);

    const inbound = r.direction === 'in';
    const views: View[] = [];
    for (const [fam, v] of [['ipv4', rr.v4], ['ipv6', rr.v6]] as const) {
      if (!v) continue;
      views.push({ fam, remote: (inbound ? v.src : v.dst).map(toCidr), local: (inbound ? v.dst : v.src).map(toCidr) });
    }
    if (views.length === 0) continue;
    const dash = (xs: string[]) => xs.map((x) => x.replace(':', '-'));
    out.push({ rr, rule: r, inbound, allow: r.action === 'accept', views, ports: dash(rr.ports), srcPorts: dash(rr.srcPorts) });
  }
  return out;
}

function commonNotes(p: Project, provider: CloudProvider, d: Diags) {
  const what = A[provider];
  d.note(`${what[0].toUpperCase()}${what.slice(1)} is stateful and sits outside the guest: loopback, established/related and invalid-packet handling need no rules.`);
  if (!p.options.allowEstablished) d.fallback(`"Allow established connections" is off in the project, but ${what} always allows replies to permitted connections.`);
  if (p.options.forwarding || p.policies.forward === 'accept') d.note(`The forward policy and the forwarding option have no equivalent in ${what}.`);
  for (const n of p.nat.filter((x) => x.enabled)) {
    d.unsupported(`NAT rule "${n.name}": ${what} does not translate addresses (use a NAT gateway or load balancer). Nothing was emitted for it.`, n.id);
  }
  const pr = p.protections ?? {};
  if (pr.synFlood) d.unsupported(`SYN flood guard: ${what} has no rate limits. Nothing was emitted for it.`);
  if (pr.portScan) d.unsupported(`Port-scan protection (TCP flag matches) cannot be expressed in ${what}. Nothing was emitted for it.`);
  if (pr.autoBan && pr.autoBan.ports.length > 0) d.unsupported(`Auto-ban trap ports cannot be expressed in ${what}. Nothing was emitted for it.`);
}

function header(h: Hcl, p: Project, provider: CloudProvider, source: string) {
  h.comment(`${BANNER} - ${p.name}`);
  h.comment(`Target: ${LABEL[provider]} (Terraform)`);
  h.comment('Usage: terraform init && terraform plan');
  h.block('terraform', [{ block: 'required_providers', items: [{ block: `${source.split('/')[1]} =`, items: [['source', q(source)]] }] }]);
}

// ---------------------------------------------------------------------------------------------
// AWS

function compileAws(p: Project, d: Diags): OutFile {
  const h = new Hcl();
  const rules = prepare(p, 'aws', d);
  const v6 = p.options.ipv6;
  header(h, p, 'aws', 'hashicorp/aws');
  h.blank().block('variable "vpc_id"', [['type', 'string'], ['description', q('VPC the security group is created in')]]);
  h.blank().block('variable "name"', [['type', 'string'], ['default', q(`emberwall-${slug(p.name, 40)}`)], ['description', q('Name of the security group')]]);
  h.blank().comment('Security groups only allow: whatever no rule below allows is denied, in both directions.');
  h.block('resource "aws_security_group" "emberwall"', [
    ['name', 'var.name'],
    ['description', q(`${BANNER}: ${awsText(p.name)}`.slice(0, 255))],
    ['vpc_id', 'var.vpc_id'],
  ]);

  let n = 0;
  let count = 0;
  /** Comment to print above the next resource. */
  let pending = '';
  const one = (inbound: boolean, label: string, desc: string, proto: string, from: number | null, to: number | null, fam: Fam, cidr: string, ruleId?: string) => {
    if (ruleId) n += 1;
    count += 1;
    const items: Item[] = [
      ['security_group_id', 'aws_security_group.emberwall.id'],
      ['description', q(awsText(desc).slice(0, 255))],
      ['ip_protocol', q(proto)],
    ];
    if (from !== null && to !== null) items.push(['from_port', String(from)], ['to_port', String(to)]);
    items.push([fam === 'ipv4' ? 'cidr_ipv4' : 'cidr_ipv6', q(cidr)]);
    h.blank();
    if (pending) h.comment(pending, ruleId);
    pending = '';
    // Rules get a running number (names may repeat); built-in resources have fixed names.
    const resName = ruleId ? ident(label, n) : slug(label, 40).replace(/-/g, '_');
    h.block(`resource "aws_vpc_security_group_${inbound ? 'ingress' : 'egress'}_rule" "${resName}"`, items, ruleId);
  };
  const fams: Fam[] = v6 ? ['ipv4', 'ipv6'] : ['ipv4'];

  if (p.options.allowIcmp) {
    for (const inbound of p.policies.out === 'drop' ? [true, false] : [true]) {
      const dir = inbound ? 'in' : 'out';
      one(inbound, `ping_v4_${dir}`, `ping (${dir})`, 'icmp', 8, -1, 'ipv4', ANY.ipv4);
      if (v6) one(inbound, `ping_v6_${dir}`, `ping IPv6 (${dir})`, 'icmpv6', 128, -1, 'ipv6', ANY.ipv6);
    }
  }

  for (const cr of rules) {
    const r = cr.rule;
    if (cr.views.some((v) => v.local.length > 0)) {
      d.fallback(`"${r.name}": security group rules cannot match the instance's own address (${cr.inbound ? 'destination' : 'source'}); the rule applies to every address of the attached instances.`, r.id);
    }
    pending = r.name || r.id;
    for (const view of cr.views) {
      for (const proto of cr.rr.protos) {
        const cidrs = view.remote.length > 0 ? view.remote : [ANY[view.fam]];
        for (const cidr of cidrs) {
          if (proto === 'any') {
            one(cr.inbound, r.name, r.name, '-1', null, null, view.fam, cidr, r.id);
          } else if (proto === 'icmp') {
            const map = view.fam === 'ipv4' ? ICMP4 : ICMP6;
            let type = -1;
            if (r.icmpType) {
              const t = map[r.icmpType] ?? (/^\d{1,3}$/.test(r.icmpType) ? Number(r.icmpType) : undefined);
              if (t === undefined) {
                d.unsupported(`"${r.name}": ICMP type "${r.icmpType}" has no number known to Emberwall. That part of the rule is not in the output.`, r.id);
                continue;
              }
              type = t;
            }
            one(cr.inbound, r.name, r.name, view.fam === 'ipv4' ? 'icmp' : 'icmpv6', type, -1, view.fam, cidr, r.id);
          } else if (cr.ports.length === 0) {
            one(cr.inbound, r.name, r.name, proto, 0, 65535, view.fam, cidr, r.id);
          } else {
            for (const port of cr.ports) {
              const [from, to] = port.split('-').map(Number);
              one(cr.inbound, r.name, r.name, proto, from, to ?? from, view.fam, cidr, r.id);
            }
          }
        }
      }
    }
  }

  if (p.policies.in === 'accept') {
    pending = 'Inbound policy "accept": allow everything in.';
    for (const fam of fams) one(true, `policy_in_${fam}`, 'inbound policy accept', '-1', null, null, fam, ANY[fam]);
    d.note('Inbound policy "accept" becomes an allow-all ingress rule; the other ingress rules are then redundant.');
  } else {
    d.note('Inbound policy "drop" is implicit: a security group denies whatever no ingress rule allows.');
  }
  if (p.policies.out === 'accept') {
    pending = 'Outbound policy "accept": allow everything out. (Terraform removes the default egress rule AWS adds.)';
    for (const fam of fams) one(false, `policy_out_${fam}`, 'outbound policy accept', '-1', null, null, fam, ANY[fam]);
  } else {
    d.note('Outbound policy "drop": only the egress rules listed are allowed. Instances then also need rules for DNS, NTP and package mirrors.');
  }

  h.blank().block('output "security_group_id"', [['value', 'aws_security_group.emberwall.id']]);

  d.note('AWS security groups are allow-only and have no rule order: there are no drop or reject rules, and a rule cannot carve an exception out of a broader allow.');
  d.note('One security group rule is emitted per CIDR block, protocol and port range.');
  if (count > 60) d.fallback(`${count} security group rules are generated; the default quota is 60 inbound and 60 outbound rules per security group.`);
  if (p.options.logDropped) d.unsupported('"Log dropped packets": security groups do not log. Enable VPC Flow Logs (REJECT records) separately.');
  if (!v6) d.note('IPv6 is switched off in the project: no IPv6 rules are generated, so IPv6 traffic is denied.');
  commonNotes(p, 'aws', d);
  return { name: 'emberwall-aws.tf', path: 'emberwall-aws.tf', lang: 'hcl', description: 'Terraform: AWS security group', lines: h.o.lines };
}

/** AWS allows only a small character set in descriptions. */
function awsText(s: string): string {
  return s.replace(/[^a-zA-Z0-9. _\-:/()#,@[\]+=&;{}!$*]/g, ' ').replace(/  +/g, ' ').trim() || 'rule';
}

// ---------------------------------------------------------------------------------------------
// Azure

function compileAzure(p: Project, d: Diags): OutFile {
  const h = new Hcl();
  const rules = prepare(p, 'azure', d);
  header(h, p, 'azure', 'hashicorp/azurerm');
  h.blank().block('variable "resource_group_name"', [['type', 'string'], ['description', q('Resource group the network security group is created in')]]);
  h.blank().block('variable "location"', [['type', 'string'], ['description', q('Azure region, for example westeurope')]]);
  h.blank().block('variable "name"', [['type', 'string'], ['default', q(`emberwall-${slug(p.name, 40)}`)], ['description', q('Name of the network security group')]]);

  const blocks: { items: Item[]; ruleId?: string; title?: string }[] = [];
  let priority = 100;
  let full = false;
  const names = new Set<string>();
  const add = (
    title: string, name: string, desc: string, inbound: boolean, allow: boolean, protocol: string,
    sports: string[], dports: string[], src: string[], dst: string[], ruleId?: string, fixedPriority?: number,
  ) => {
    let prio = fixedPriority;
    if (prio === undefined) {
      if (priority > 4000) {
        if (!full) d.unsupported('An Azure NSG holds priorities 100-4096: more rules were generated than fit in steps of 10. The remaining rules are not in the output.', ruleId);
        full = true;
        return;
      }
      prio = priority;
      priority += 10;
    }
    let ruleName = `${slug(name, 60)}-${prio}`;
    while (names.has(ruleName)) ruleName += 'x';
    names.add(ruleName);
    const one = (key: string, values: string[], any: string): Item => (values.length <= 1 ? [key, q(values[0] ?? any)] : [`${key}${key.endsWith('prefix') ? 'es' : 's'}`, qList(values)]);
    blocks.push({
      title,
      ruleId,
      items: [
        ['name', q(ruleName)],
        ['description', q(desc.replace(/[\r\n]+/g, ' ').slice(0, 140))],
        ['priority', String(prio)],
        ['direction', q(inbound ? 'Inbound' : 'Outbound')],
        ['access', q(allow ? 'Allow' : 'Deny')],
        ['protocol', q(protocol)],
        one('source_port_range', sports, '*'),
        one('destination_port_range', dports, '*'),
        one('source_address_prefix', src, '*'),
        one('destination_address_prefix', dst, '*'),
      ],
    });
  };

  if (p.options.allowIcmp) {
    add('Ping (Azure cannot select ICMP types: all of ICMP is allowed)', 'icmp-in', 'ICMP in', true, true, 'Icmp', [], [], [], []);
    if (p.policies.out === 'drop') add('ICMP out', 'icmp-out', 'ICMP out', false, true, 'Icmp', [], [], [], []);
    d.note('"Allow ping" becomes a rule for all of ICMP: Azure NSG rules cannot select ICMP types.');
  }

  for (const cr of rules) {
    const r = cr.rule;
    // One rule can cover both families only when it names no address at all.
    const merged = cr.views.length === 2 && cr.views.every((v) => v.remote.length === 0 && v.local.length === 0);
    const views: (View | null)[] = merged ? [null] : cr.views;
    for (const view of views) {
      for (const proto of cr.rr.protos) {
        let protocol = '*';
        if (proto === 'tcp') protocol = 'Tcp';
        else if (proto === 'udp') protocol = 'Udp';
        else if (proto === 'icmp') {
          protocol = 'Icmp';
          if (view?.fam === 'ipv6') {
            d.unsupported(`"${r.name}": Azure NSG rules have no ICMPv6 protocol selector. The IPv6 part of the rule is not in the output.`, r.id);
            continue;
          }
          if (merged) d.note(`"${r.name}": the Azure "Icmp" protocol covers ICMPv4; ICMPv6 has no selector in an NSG rule.`, r.id);
          if (r.icmpType) d.fallback(`"${r.name}": Azure NSG rules cannot select ICMP types; the rule covers all of ICMP instead of "${r.icmpType}".`, r.id);
        }
        const tcpudp = proto === 'tcp' || proto === 'udp';
        let remote = view ? view.remote : [];
        const local = view ? view.local : [];
        // Pin a single-family rule without addresses to its family.
        if (view && !merged && remote.length === 0 && local.length === 0 && cr.views.length === 1) remote = [ANY[view.fam]];
        const suffix = `${cr.rr.protos.length > 1 ? `-${proto}` : ''}${views.length > 1 && view ? `-${view.fam === 'ipv4' ? 'v4' : 'v6'}` : ''}`;
        add(
          r.name || r.id, `${r.name || 'rule'}${suffix}`, r.comment || r.name || r.id, cr.inbound, cr.allow, protocol,
          tcpudp ? cr.srcPorts : [], tcpudp ? cr.ports : [],
          cr.inbound ? remote : local, cr.inbound ? local : remote, r.id,
        );
      }
    }
  }

  add(`Inbound policy: ${p.policies.in}`, 'policy-inbound', `Emberwall inbound policy: ${p.policies.in}`, true, p.policies.in === 'accept', '*', [], [], [], [], undefined, 4095);
  add(`Outbound policy: ${p.policies.out}`, 'policy-outbound', `Emberwall outbound policy: ${p.policies.out}`, false, p.policies.out === 'accept', '*', [], [], [], [], undefined, 4096);

  h.blank().comment('Rules are evaluated by ascending priority; the first match decides.');
  const items: Item[] = [['name', 'var.name'], ['location', 'var.location'], ['resource_group_name', 'var.resource_group_name']];
  // Rendered by hand so each security_rule block carries its rule id.
  const o = h.o;
  o.push('resource "azurerm_network_security_group" "emberwall" {');
  const width = Math.max(...items.map((i) => (i as [string, string])[0].length));
  for (const [k, v] of items as [string, string][]) o.push(`  ${k.padEnd(width)} = ${v}`);
  for (const b of blocks) {
    o.push('', b.ruleId);
    if (b.title) o.push(`  # ${b.title.replace(/[\r\n]+/g, ' ')}`, b.ruleId);
    h.block('security_rule', b.items, b.ruleId, 1);
  }
  o.push('}');
  h.blank().block('output "network_security_group_id"', [['value', 'azurerm_network_security_group.emberwall.id']]);

  d.note('Azure evaluates NSG rules by priority (100, 110, ...), lowest first, which preserves the Emberwall order. The policies are explicit rules at priority 4095 (inbound) and 4096 (outbound).');
  d.note('The explicit policy rules take precedence over Azure\'s built-in rules (AllowVnetInBound, AllowAzureLoadBalancerInBound, AllowInternetOutBound at 65000+). With an inbound "drop" policy, load balancer health probes need their own allow rule from the AzureLoadBalancer service tag.');
  d.note('The file declares no provider block: add provider "azurerm" { features {} } in your root module, and attach the group to a subnet or network interface.');
  if (p.options.logDropped) d.unsupported('"Log dropped packets": NSG rules do not log. Enable NSG / VNet flow logs separately.');
  if (!p.options.ipv6) d.fallback('IPv6 is switched off in the project. Rules are generated for IPv4 only, but the policy rules at 4095/4096 match both families: with an "accept" policy IPv6 is allowed too.');
  commonNotes(p, 'azure', d);
  return { name: 'emberwall-azure.tf', path: 'emberwall-azure.tf', lang: 'hcl', description: 'Terraform: Azure network security group', lines: h.o.lines };
}

// ---------------------------------------------------------------------------------------------
// GCP

function compileGcp(p: Project, d: Diags): OutFile {
  const h = new Hcl();
  const rules = prepare(p, 'gcp', d);
  const v6 = p.options.ipv6;
  header(h, p, 'gcp', 'hashicorp/google');
  h.blank().block('variable "network"', [['type', 'string'], ['description', q('Name or self_link of the VPC network')]]);
  h.blank().block('variable "name_prefix"', [['type', 'string'], ['default', q(`ew-${slug(p.name, 20)}`)], ['description', q('Prefix for the firewall rule names')]]);
  h.blank().block('variable "target_tags"', [['type', 'list(string)'], ['default', 'null'], ['description', q('Network tags of the instances the rules apply to (null = every instance in the network)')]]);

  let n = 0;
  let priority = 1000;
  /** Comment to print above the next resource. */
  let pending = '';
  const fw = (
    label: string, desc: string, inbound: boolean, allow: boolean, prio: number, fam: Fam,
    remote: string[], local: string[], protos: { protocol: string; ports: string[] }[], log: boolean, ruleId?: string,
  ) => {
    if (ruleId) n += 1;
    const suffix = ruleId ? `-${n}` : '';
    const remoteRanges = remote.length > 0 ? remote : [ANY[fam]];
    const items: Item[] = [
      ['name', `"\${var.name_prefix}-${slug(label, 30)}${suffix}"`],
      ['description', q(desc.replace(/[\r\n]+/g, ' ').slice(0, 250))],
      ['network', 'var.network'],
      ['direction', q(inbound ? 'INGRESS' : 'EGRESS')],
      ['priority', String(prio)],
      [inbound ? 'source_ranges' : 'destination_ranges', qList(remoteRanges)],
    ];
    if (local.length > 0) items.push([inbound ? 'destination_ranges' : 'source_ranges', qList(local)]);
    items.push(['target_tags', 'var.target_tags']);
    for (const pr of protos) {
      const inner: Item[] = [['protocol', q(pr.protocol)]];
      if (pr.ports.length > 0) inner.push(['ports', qList(pr.ports)]);
      items.push({ block: allow ? 'allow' : 'deny', items: inner });
    }
    if (log) items.push({ block: 'log_config', items: [['metadata', q('INCLUDE_ALL_METADATA')]] });
    h.blank();
    if (pending) h.comment(pending, ruleId);
    pending = '';
    h.block(`resource "google_compute_firewall" "${ruleId ? ident(label, n) : slug(label, 40).replace(/-/g, '_')}"`, items, ruleId);
  };
  const fams: Fam[] = v6 ? ['ipv4', 'ipv6'] : ['ipv4'];
  const icmpProto = (fam: Fam) => (fam === 'ipv4' ? 'icmp' : '58');

  if (p.options.allowIcmp) {
    for (const inbound of p.policies.out === 'drop' ? [true, false] : [true]) {
      for (const fam of fams) fw(`icmp-${inbound ? 'in' : 'out'}-${fam}`, `ICMP ${inbound ? 'in' : 'out'} (${fam})`, inbound, true, priority, fam, [], [], [{ protocol: icmpProto(fam), ports: [] }], false);
      priority += 10;
    }
    d.note('"Allow ping" becomes a rule for all of ICMP: GCP firewall rules cannot select ICMP types.');
  }

  for (const cr of rules) {
    const r = cr.rule;
    if (r.icmpType && cr.rr.protos.includes('icmp')) d.fallback(`"${r.name}": GCP firewall rules cannot select ICMP types; the rule covers all of ICMP instead of "${r.icmpType}".`, r.id);
    pending = r.name || r.id;
    for (const view of cr.views) {
      const protos = cr.rr.protos.map((proto) => ({
        protocol: proto === 'any' ? 'all' : proto === 'icmp' ? icmpProto(view.fam) : proto,
        ports: proto === 'tcp' || proto === 'udp' ? cr.ports : [],
      }));
      fw(r.name || 'rule', r.comment || r.name || r.id, cr.inbound, cr.allow, priority, view.fam, view.remote, view.local, protos, !!r.log, r.id);
    }
    priority += 10;
  }

  if (p.policies.in === 'accept') {
    pending = 'Inbound policy "accept": allow everything in, after all other rules.';
    for (const fam of fams) fw(`policy-in-${fam}`, 'Emberwall inbound policy: accept', true, true, 65534, fam, [], [], [{ protocol: 'all', ports: [] }], false);
  } else {
    d.note('Inbound policy "drop" is the implied rule of every VPC network (deny ingress, priority 65535); nothing is emitted for it.');
  }
  if (p.policies.out === 'drop') {
    pending = 'Outbound policy "drop": deny everything out that no rule above allows.';
    for (const fam of fams) fw(`policy-out-${fam}`, 'Emberwall outbound policy: drop', false, false, 65534, fam, [], [], [{ protocol: 'all', ports: [] }], false);
    d.note('Outbound policy "drop": instances then also need egress rules for DNS, NTP, package mirrors and Google APIs.');
  } else {
    d.note('Outbound policy "accept" is the implied rule of every VPC network (allow egress, priority 65535); nothing is emitted for it.');
  }

  d.note('GCP evaluates firewall rules by priority (1000, 1010, ...), lowest first, which preserves the Emberwall order. A rule holds either IPv4 or IPv6 ranges, so rules for both families are emitted twice with the same priority.');
  d.note('The rules apply to every instance in the network unless var.target_tags is set.');
  if (p.options.logDropped) d.unsupported('"Log dropped packets": the implied deny rule cannot log. Only rules with "log" set get a log_config block.');
  if (!v6) d.note('IPv6 is switched off in the project: no IPv6 rules are generated, so IPv6 follows the implied rules (ingress denied, egress allowed).');
  commonNotes(p, 'gcp', d);
  return { name: 'emberwall-gcp.tf', path: 'emberwall-gcp.tf', lang: 'hcl', description: 'Terraform: Google Cloud VPC firewall rules', lines: h.o.lines };
}

export function compileCloud(p: Project, provider: CloudProvider): ExtraResult {
  const d = new Diags();
  const file = provider === 'aws' ? compileAws(p, d) : provider === 'azure' ? compileAzure(p, d) : compileGcp(p, d);
  return { files: [file], diagnostics: d.list };
}
