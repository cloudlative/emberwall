// Windows Defender Firewall: a PowerShell script built on the NetSecurity module
// (New-NetFirewallRule, Set-NetFirewallProfile).
//
// The big difference from Linux: Windows has no rule order. A matching Block rule always
// beats a matching Allow rule, and the profile's default action applies when no rule matches.
import type { Project } from '../../model';
import { resolveAll, type ResolvedRule } from '../../resolve';
import { BANNER, Diags, Out, type OutFile } from '../types';
import type { ExtraResult } from './index';

const GROUP = 'Emberwall';

const ICMP4: Record<string, string> = { 'echo-request': '8', 'echo-reply': '0', 'destination-unreachable': '3', 'time-exceeded': '11', 'parameter-problem': '12' };
const ICMP6: Record<string, string> = { 'echo-request': '128', 'echo-reply': '129', 'destination-unreachable': '1', 'time-exceeded': '3', 'parameter-problem': '4' };
/** ICMPv6 types IPv6 needs: unreachable, too big, time exceeded, parameter problem, echo, RS, RA, NS, NA. */
const ICMP6_ESSENTIAL = ['1', '2', '3', '4', '128', '133', '134', '135', '136'];

const ALL_V4 = '0.0.0.0-255.255.255.255';
const ALL_V6 = '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff';

/** PowerShell single-quoted string: no expansion, a quote is doubled. */
export function psQuote(s: string): string {
  return `'${s.replace(/[\r\n\t]+/g, ' ').replace(/[\u2018\u2019\u201a\u201b]/g, "'").replace(/'/g, "''")}'`;
}

/** Comma-separated PowerShell string array. */
function psList(items: string[]): string {
  return items.map(psQuote).join(',');
}

function expressible(rr: ResolvedRule, d: Diags): boolean {
  const r = rr.rule;
  const skip = (what: string) => {
    d.unsupported(`"${r.name}": ${what}. The rule is not in the script.`, r.id);
    return false;
  };
  if (r.direction === 'forward') return skip('Windows Firewall filters traffic of the host only; forward rules have no equivalent (routing is done by RRAS / Hyper-V switches)');
  if (r.srcMac) return skip('Windows Firewall cannot match a source MAC address');
  if (r.mark) return skip('packet marks are a Linux netfilter concept');
  if (r.schedule) return skip('Windows Firewall rules have no schedule (enable and disable the rule from Task Scheduler instead)');
  if (r.states && r.states.length > 0 && !r.states.includes('new')) {
    if (r.action === 'accept' && r.states.every((s) => s === 'established' || s === 'related')) {
      d.note(`"${r.name}": Windows Firewall is stateful and allows replies without a rule, so this rule is left out.`, r.id);
      return false;
    }
    return skip(`Windows Firewall cannot match connection state ${r.states.join(',')}`);
  }
  return true;
}

function ruleCommands(rr: ResolvedRule, n: number, d: Diags): string[] {
  const r = rr.rule;
  const inbound = r.direction === 'in';
  const out: string[] = [];

  if (r.action === 'reject') {
    d.unsupported(`"${r.name}": Windows Firewall cannot reject (answer with a TCP reset or ICMP error). The rule is emitted as Block, which drops silently.`, r.id);
  }
  if (r.rateLimit) d.unsupported(`"${r.name}": Windows Firewall has no rate limits. The rule is emitted WITHOUT the limit.`, r.id);
  if (r.connLimit) d.unsupported(`"${r.name}": Windows Firewall has no per-client connection limit. The rule is emitted WITHOUT the limit.`, r.id);
  if (r.log) d.unsupported(`"${r.name}": Windows Firewall cannot log per rule; logging is per profile (Set-NetFirewallProfile -LogAllowed / -LogBlocked). The rule is emitted without logging.`, r.id);

  const iface = inbound ? r.inIface : r.outIface;
  if (iface) d.note(`"${r.name}": -InterfaceAlias uses the interface name from the project ("${iface}"). Windows names differ (see Get-NetAdapter): edit it before running.`, r.id);

  const emit = (protocol: string | null, remote: string[], local: string[], icmpType?: string) => {
    const tcpudp = protocol === 'TCP' || protocol === 'UDP';
    const dash = (ports: string[]) => ports.map((x) => x.replace(':', '-'));
    // Destination ports are local for inbound traffic and remote for outbound traffic.
    const dports = tcpudp ? dash(rr.ports) : [];
    const sports = tcpudp ? dash(rr.srcPorts) : [];
    const localPorts = inbound ? dports : sports;
    const remotePorts = inbound ? sports : dports;
    const suffix = rr.protos.length > 1 && protocol ? ` (${protocol})` : '';
    const parts = [
      'New-NetFirewallRule',
      `-DisplayName ${psQuote(`${GROUP}: ${r.name || r.id}${suffix}`)}`,
      `-Name ${psQuote(`${GROUP}-${n}-${out.length + 1}`)}`,
      `-Group ${psQuote(GROUP)}`,
      r.comment ? `-Description ${psQuote(r.comment)}` : '',
      `-Direction ${inbound ? 'Inbound' : 'Outbound'}`,
      `-Action ${r.action === 'accept' ? 'Allow' : 'Block'}`,
      protocol ? `-Protocol ${protocol}` : '',
      icmpType ? `-IcmpType ${icmpType}` : '',
      localPorts.length > 0 ? `-LocalPort ${psList(localPorts)}` : '',
      remotePorts.length > 0 ? `-RemotePort ${psList(remotePorts)}` : '',
      remote.length > 0 ? `-RemoteAddress ${psList(remote)}` : '',
      local.length > 0 ? `-LocalAddress ${psList(local)}` : '',
      iface ? `-InterfaceAlias ${psQuote(iface)}` : '',
      '-Enabled True',
      '| Out-Null',
    ];
    out.push(parts.filter(Boolean).join(' '));
  };

  // Remote = the other end: source for inbound, destination for outbound.
  const remoteOf = (v: { src: string[]; dst: string[] }) => (inbound ? v.src : v.dst);
  const localOf = (v: { src: string[]; dst: string[] }) => (inbound ? v.dst : v.src);

  for (const proto of rr.protos) {
    if (proto === 'icmp') {
      // ICMPv4 and ICMPv6 are different protocols with different type numbers.
      for (const [view, name, map] of [[rr.v4, 'ICMPv4', ICMP4], [rr.v6, 'ICMPv6', ICMP6]] as const) {
        if (!view) continue;
        let type: string | undefined;
        if (r.icmpType) {
          type = map[r.icmpType] ?? (/^\d{1,3}$/.test(r.icmpType) ? r.icmpType : undefined);
          if (!type) {
            d.unsupported(`"${r.name}": ICMP type "${r.icmpType}" has no ${name} number known to Emberwall. That part of the rule is not in the script.`, r.id);
            continue;
          }
        }
        emit(name, remoteOf(view), localOf(view), type);
      }
      continue;
    }
    const protocol = proto === 'any' ? null : proto.toUpperCase();
    const remote = [...(rr.v4 ? remoteOf(rr.v4) : []), ...(rr.v6 ? remoteOf(rr.v6) : [])];
    const local = [...(rr.v4 ? localOf(rr.v4) : []), ...(rr.v6 ? localOf(rr.v6) : [])];
    // A Windows rule covers IPv4 and IPv6 at once. When the rule is for one family only and
    // names no address, pin it to that family with a whole-family address range.
    if (!(rr.v4 && rr.v6) && remote.length === 0 && local.length === 0) {
      if (rr.v4) remote.push(ALL_V4);
      else if (rr.v6) remote.push(ALL_V6);
    }
    if (!rr.v4 && !rr.v6) continue;
    emit(protocol, remote, local);
  }
  return out;
}

export function compileWindows(p: Project): ExtraResult {
  const d = new Diags();
  const rules = resolveAll(p);
  for (const rr of rules) rr.problems.forEach((m) => d.invalid(`"${rr.rule.name}": ${m}`, rr.rule.id));
  const opt = p.options;
  const action = (x: 'accept' | 'drop') => (x === 'drop' ? 'Block' : 'Allow');

  const o = new Out();
  o.push('#Requires -RunAsAdministrator');
  o.push(`# ${BANNER} - ${p.name.replace(/[\r\n]+/g, ' ')}`);
  o.push('# Target: Windows Defender Firewall (PowerShell NetSecurity module, Windows 8 / Server 2012 or later)');
  o.push('# Run from an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File .\\emberwall-windows.ps1');
  o.push('#');
  o.push('# Windows has NO rule order: a matching Block rule always wins over a matching Allow rule,');
  o.push('# and the default action applies only when no rule matches.');
  o.push("$ErrorActionPreference = 'Stop'");
  o.blank();
  o.push('# Start clean so the script can be run again: remove the rules of an earlier run.');
  o.push(`Remove-NetFirewallRule -Group ${psQuote(GROUP)} -ErrorAction SilentlyContinue`);
  o.blank();
  o.push('# Default actions for traffic no rule matches, on every profile.');
  o.push(
    `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction ${action(p.policies.in)} -DefaultOutboundAction ${action(p.policies.out)}${opt.logDropped ? ' -LogBlocked True' : ''}`,
  );

  const base = (name: string, dir: 'Inbound' | 'Outbound', protocol: string, types: string[], key: string) =>
    o.push(
      `New-NetFirewallRule -DisplayName ${psQuote(`${GROUP}: ${name}`)} -Name ${psQuote(`${GROUP}-${key}`)} -Group ${psQuote(GROUP)} -Direction ${dir} -Action Allow -Protocol ${protocol} -IcmpType ${types.join(',')} -Enabled True | Out-Null`,
    );
  if (opt.allowIcmp) {
    o.blank();
    o.push('# Ping, and the ICMPv6 messages IPv6 cannot work without.');
    const dirs = p.policies.out === 'drop' ? (['Inbound', 'Outbound'] as const) : (['Inbound'] as const);
    for (const dir of dirs) {
      const k = dir === 'Inbound' ? 'in' : 'out';
      base(`ping (${dir.toLowerCase()})`, dir, 'ICMPv4', ['8'], `icmp4-${k}`);
      if (opt.ipv6) base(`ICMPv6 essentials (${dir.toLowerCase()})`, dir, 'ICMPv6', ICMP6_ESSENTIAL, `icmp6-${k}`);
    }
  }

  const emitted: { rr: ResolvedRule; index: number }[] = [];
  let n = 0;
  let lastId = '';
  let header = false;
  for (const rr of rules) {
    const r = rr.rule;
    if (!expressible(rr, d)) continue;
    n += 1;
    const cmds = ruleCommands(rr, n, d);
    if (cmds.length === 0) continue;
    if (!header) {
      o.blank();
      o.push('# Rules');
      header = true;
    }
    if (r.id !== lastId) o.push(`# ${(r.name || r.id).replace(/[\r\n]+/g, ' ')}`, r.id);
    lastId = r.id;
    cmds.forEach((c) => o.push(c, r.id));
    emitted.push({ rr, index: n });
  }
  o.blank();
  o.push(`Write-Host ('Emberwall: {0} firewall rules active.' -f @(Get-NetFirewallRule -Group ${psQuote(GROUP)}).Count)`);

  // Order: a block rule also beats allow rules that Emberwall would have matched first.
  emitted.forEach(({ rr }, i) => {
    const r = rr.rule;
    if (r.action === 'accept') return;
    const earlier = emitted.slice(0, i).filter((e) => e.rr.rule.action === 'accept' && e.rr.rule.direction === r.direction && e.rr.rule.id !== r.id);
    if (earlier.length > 0) {
      d.fallback(`"${r.name}": Windows applies Block rules before Allow rules whatever their order. Traffic matching both this rule and an earlier allow rule (${earlier.slice(0, 3).map((e) => `"${e.rr.rule.name}"`).join(', ')}${earlier.length > 3 ? ', ...' : ''}) is blocked on Windows but accepted on Linux.`, r.id);
    }
  });

  d.note('Windows Firewall has no rule order: block rules always win over allow rules, and the profile default applies when nothing matches. Check any project that relies on an allow rule placed before a broader block rule.');
  d.note(`The script first removes every rule in the "${GROUP}" group and then re-creates them, so it is safe to run again. Rules outside that group (including the built-in Windows rules) are left alone and still apply.`);
  d.note('Windows Firewall is stateful and never filters loopback: "allow loopback", "allow established" and "drop invalid" need no rules.');
  if (!opt.allowEstablished) d.fallback('"Allow established connections" is off in the project, but Windows Firewall always allows replies to permitted connections.');
  if (p.policies.out === 'drop') d.note('Default outbound action Block also stops Windows services (updates, DNS, time, domain logon) unless a rule allows them. The built-in outbound rules that stay enabled keep working.');
  if (p.policies.in === 'accept') d.note('Default inbound action Allow: Windows then accepts all inbound traffic that no Block rule matches.');
  if (opt.logDropped) d.note('Dropped packets are logged to %windir%\\system32\\logfiles\\firewall\\pfirewall.log (profile setting -LogBlocked).');
  if (opt.forwarding || p.policies.forward === 'accept') d.note('Windows Firewall does not filter routed traffic: the forward policy and the forwarding option have no equivalent.');
  if (!opt.ipv6) d.fallback('IPv6 is switched off in the project. The rules are pinned to IPv4, but Windows keeps filtering IPv6 with the same default actions and its built-in rules: with an "accept" policy IPv6 traffic is still allowed (Linux targets drop it).');
  for (const n of p.nat.filter((x) => x.enabled)) {
    d.unsupported(`NAT rule "${n.name}": Windows Firewall does not translate addresses (use New-NetNat or "netsh interface portproxy" separately). Nothing was emitted for it.`, n.id);
  }
  const pr = p.protections ?? {};
  if (pr.synFlood) d.unsupported('SYN flood guard: Windows Firewall has no rate limits. Nothing was emitted for it.');
  if (pr.portScan) d.unsupported('Port-scan protection (TCP flag matches) cannot be expressed in Windows Firewall rules. Nothing was emitted for it.');
  if (pr.autoBan && pr.autoBan.ports.length > 0) d.unsupported('Auto-ban trap ports cannot be expressed in Windows Firewall. Nothing was emitted for it.');
  if (rules.some((r) => !(r.v4 && r.v6) && (r.v4 || r.v6))) {
    d.note(`Rules for a single address family that name no address are pinned to it with -RemoteAddress ${ALL_V4} (IPv4) or ${ALL_V6} (IPv6).`);
  }

  const file: OutFile = {
    name: 'emberwall-windows.ps1',
    path: 'C:\\ProgramData\\Emberwall\\emberwall-windows.ps1',
    lang: 'powershell',
    description: 'PowerShell script for Windows Defender Firewall',
    lines: o.lines,
  };
  return { files: [file], diagnostics: d.list };
}
