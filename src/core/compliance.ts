// Compliance profiles: named sets of checks over a project, each with evidence.
// These are Emberwall's reading of the firewall-related intent of each framework,
// not the frameworks' official wording, and passing them is not a certification.
import { lint } from './lint';
import type { Project } from './model';
import { portInList } from './net';
import { runTests } from './reach';
import { resolveAll, type ResolvedRule } from './resolve';
import { RECOMMENDED_HARDENING } from './sysctl';

export type ControlStatus = 'pass' | 'fail' | 'na';

export interface ControlResult {
  id: string;
  title: string;
  /** What the framework is after, in plain words. */
  intent: string;
  status: ControlStatus;
  evidence: string;
}

interface Control {
  id: string;
  title: string;
  intent: string;
  check: (p: Project, ctx: Ctx) => { status: ControlStatus; evidence: string };
}

interface Ctx {
  rules: ResolvedRule[];
  world: ResolvedRule[];
}

const ok = (evidence: string) => ({ status: 'pass' as const, evidence });
const bad = (evidence: string) => ({ status: 'fail' as const, evidence });
const na = (evidence: string) => ({ status: 'na' as const, evidence });

const opensPort = (rr: ResolvedRule, port: number) => rr.rule.proto === 'any' || (rr.rule.proto !== 'icmp' && (rr.ports.length === 0 || portInList(port, rr.ports)));
const names = (list: ResolvedRule[]) => [...new Set(list.map((r) => `"${r.rule.name}"`))].join(', ');

const C: Record<string, Control> = {
  denyIn: {
    id: 'default-deny-inbound', title: 'Inbound traffic is denied by default', intent: 'Only explicitly allowed traffic may reach the system.',
    check: (p) => (p.policies.in === 'drop' ? ok('Inbound policy is drop.') : bad('Inbound policy is accept.')),
  },
  denyFwd: {
    id: 'default-deny-forward', title: 'Forwarded traffic is denied by default', intent: 'A host must not route traffic it was not told to route.',
    check: (p) => (p.policies.forward === 'drop' ? ok('Forward policy is drop.') : bad('Forward policy is accept.')),
  },
  denyOut: {
    id: 'default-deny-outbound', title: 'Outbound traffic is restricted', intent: 'Outbound connections are limited to what the system needs.',
    check: (p, { rules }) => {
      if (p.policies.out === 'drop') return ok('Outbound policy is drop with explicit allowances.');
      const blocks = rules.filter((r) => r.rule.direction === 'out' && r.rule.action !== 'accept');
      return blocks.length > 0 ? bad(`Outbound policy is accept; only ${blocks.length} outbound block rule(s) exist.`) : bad('Outbound policy is accept and nothing outbound is restricted.');
    },
  },
  loopback: {
    id: 'loopback', title: 'Loopback traffic is handled explicitly', intent: 'Local inter-process traffic keeps working and is not confused with network traffic.',
    check: (p) => (p.options.allowLoopback ? ok('Loopback interface traffic is accepted by the baseline.') : bad('The loopback baseline rule is off.')),
  },
  stateful: {
    id: 'stateful', title: 'Stateful inspection is used', intent: 'Only replies to established connections are let back in; invalid packets are dropped.',
    check: (p) => (p.options.allowEstablished && p.options.dropInvalid ? ok('Established/related accepted, invalid dropped.') : bad(`${p.options.allowEstablished ? '' : 'Established-connection rule is off. '}${p.options.dropInvalid ? '' : 'Invalid packets are not dropped.'}`.trim())),
  },
  ipv6: {
    id: 'ipv6', title: 'IPv6 is filtered like IPv4', intent: 'A second protocol must not bypass the firewall.',
    check: (p, { rules }) => {
      if (!p.options.ipv6) return ok('IPv6 is switched off: the ruleset drops all IPv6 traffic.');
      const v4only = rules.filter((r) => r.rule.direction === 'in' && r.rule.action !== 'accept' && !r.v6);
      return v4only.length === 0 ? ok('The same default policy and rules apply to IPv6.') : bad(`Block rules that do not cover IPv6: ${names(v4only)}.`);
    },
  },
  noAnyAny: {
    id: 'no-any-any', title: 'No rule allows everything', intent: 'Each allowance is specific about protocol and port.',
    check: (_p, { world }) => {
      const open = world.filter((r) => r.rule.proto === 'any' || (r.rule.proto !== 'icmp' && r.ports.length === 0));
      return open.length === 0 ? ok('Every internet-facing rule names its ports.') : bad(`Open to everything: ${names(open)}.`);
    },
  },
  insecure: {
    id: 'insecure-services', title: 'Insecure services are not exposed', intent: 'Clear-text protocols (Telnet, FTP, rsh, TFTP) are not reachable from untrusted networks.',
    check: (_p, { world }) => {
      const hit = world.filter((r) => [21, 23, 69, 512, 513, 514].some((port) => r.ports.length > 0 && portInList(port, r.ports)));
      return hit.length === 0 ? ok('No internet-facing rule opens Telnet, FTP, TFTP or r-services.') : bad(`Exposed by: ${names(hit)}.`);
    },
  },
  admin: {
    id: 'admin-access', title: 'Administrative access is restricted to known sources', intent: 'Management interfaces are reachable only from administrative networks.',
    check: (_p, { world }) => {
      const hit = world.filter((r) => [22, 3389, 5900].some((port) => opensPort(r, port)));
      return hit.length === 0 ? ok('SSH, RDP and VNC are not open to arbitrary sources.') : bad(`Open to any source: ${names(hit)}.`);
    },
  },
  data: {
    id: 'data-stores', title: 'Data stores are not reachable from untrusted networks', intent: 'Systems holding sensitive data sit behind the firewall, not on it.',
    check: (_p, { world }) => {
      const hit = world.filter((r) => [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017].some((port) => r.ports.length > 0 && portInList(port, r.ports)));
      return hit.length === 0 ? ok('No database or cache port is open to arbitrary sources.') : bad(`Open to any source: ${names(hit)}.`);
    },
  },
  logging: {
    id: 'logging', title: 'Denied traffic is logged', intent: 'There is a record to review when something is blocked or probed.',
    check: (p) => (p.options.logDropped ? ok('Policy drops are logged (rate limited).') : bad('Dropped packets are not logged.')),
  },
  documented: {
    id: 'documented', title: 'Every rule has a stated purpose', intent: 'Rules can be reviewed because each one says what it is for.',
    check: (p) => {
      const anon = p.rules.filter((r) => r.enabled && /^(new rule|unnamed rule|accept |drop |reject |port )/i.test(r.name.trim()));
      if (p.rules.length === 0) return na('No rules to document.');
      return anon.length === 0 ? ok(`All ${p.rules.filter((r) => r.enabled).length} rules carry a descriptive name.`) : bad(`${anon.length} rule(s) have a generic name, e.g. "${anon[0].name}".`);
    },
  },
  tested: {
    id: 'tested', title: 'Changes are validated against stated expectations', intent: 'Rule changes are tested before they are approved.',
    check: (p) => {
      const res = runTests(p);
      if (res.length === 0) return bad('No policy tests are defined.');
      const failing = res.filter((r) => !r.pass).length;
      return failing === 0 ? ok(`${res.length} policy test(s) pass.`) : bad(`${failing} of ${res.length} policy tests fail.`);
    },
  },
  hardening: {
    id: 'kernel-hardening', title: 'Network stack is hardened', intent: 'Spoofed, redirected and source-routed packets are refused by the kernel.',
    check: (p) => {
      const missing = RECOMMENDED_HARDENING.filter((id) => !(p.hardening ?? []).includes(id));
      return missing.length === 0 ? ok('All recommended sysctl settings are enabled.') : bad(`Not enabled: ${missing.join(', ')}.`);
    },
  },
  bruteforce: {
    id: 'brute-force', title: 'Public login services are throttled', intent: 'Repeated access attempts are slowed or blocked.',
    check: (_p, { world }) => {
      const ssh = world.filter((r) => r.ports.length > 0 && portInList(22, r.ports));
      if (ssh.length === 0) return na('No login service is open to arbitrary sources.');
      const loose = ssh.filter((r) => !r.rule.rateLimit && !r.rule.connLimit);
      return loose.length === 0 ? ok('Internet-facing SSH rules are rate or connection limited.') : bad(`No limit on: ${names(loose)}.`);
    },
  },
  noShadow: {
    id: 'no-dead-rules', title: 'The ruleset has no dead or conflicting rules', intent: 'Rule sets are reviewed and unnecessary rules removed.',
    check: (p) => {
      const dead = lint(p).filter((f) => f.id.startsWith('shadow:'));
      const off = p.rules.filter((r) => !r.enabled).length;
      return dead.length + off === 0 ? ok('No shadowed, redundant or disabled rules.') : bad(`${dead.length} shadowed/redundant and ${off} disabled rule(s).`);
    },
  },
};

export interface Profile {
  id: string;
  name: string;
  about: string;
  controls: Control[];
}

export const PROFILES: Profile[] = [
  {
    id: 'cis', name: 'CIS-style host firewall',
    about: 'Follows the intent of the host-firewall sections of the CIS Linux benchmarks: default deny, loopback, stateful rules, IPv6 parity, logging.',
    controls: [C.denyIn, C.denyFwd, C.denyOut, C.loopback, C.stateful, C.ipv6, C.noAnyAny, C.insecure, C.logging, C.hardening],
  },
  {
    id: 'pci', name: 'PCI DSS-style network controls',
    about: 'Follows the intent of PCI DSS Requirement 1 (network security controls): restrict inbound and outbound to what is necessary, protect data stores, document and review rules.',
    controls: [C.denyIn, C.denyOut, C.denyFwd, C.stateful, C.noAnyAny, C.insecure, C.admin, C.data, C.documented, C.tested, C.noShadow, C.logging],
  },
  {
    id: 'internet', name: 'Internet-facing server baseline',
    about: 'Emberwall\'s own baseline for a host on a public address.',
    controls: [C.denyIn, C.denyFwd, C.stateful, C.ipv6, C.noAnyAny, C.insecure, C.admin, C.data, C.bruteforce, C.logging, C.hardening, C.tested],
  },
];

export interface ComplianceReport {
  profile: Profile;
  results: ControlResult[];
  passed: number;
  failed: number;
  /** 0-100 over applicable controls. */
  percent: number;
}

export function assess(p: Project, profileId: string): ComplianceReport {
  const profile = PROFILES.find((x) => x.id === profileId) ?? PROFILES[0];
  const rules = resolveAll(p);
  // Internet-facing: inbound accepts with no source restriction and no interface pin.
  const world = rules.filter((r) => r.rule.direction === 'in' && r.rule.action === 'accept' && r.rule.src.length === 0 && !r.rule.inIface && !r.rule.srcZone);
  const results = profile.controls.map((c) => ({ id: c.id, title: c.title, intent: c.intent, ...c.check(p, { rules, world }) }));
  const passed = results.filter((r) => r.status === 'pass').length;
  const failed = results.filter((r) => r.status === 'fail').length;
  return { profile, results, passed, failed, percent: passed + failed === 0 ? 100 : Math.round((passed / (passed + failed)) * 100) };
}
