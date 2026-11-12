// Target profiles: which tool, which version, and what that version can do.
// Compilers branch on capability flags only, never on raw version numbers.

export type Tool = 'iptables' | 'nftables' | 'ufw' | 'firewalld';

export const TOOLS: Tool[] = ['nftables', 'iptables', 'ufw', 'firewalld'];

export const TOOL_LABEL: Record<Tool, string> = {
  iptables: 'iptables',
  nftables: 'nftables',
  ufw: 'ufw',
  firewalld: 'firewalld',
};

export interface Capability {
  key: string;
  tool: Tool;
  /** First version that has the feature. */
  since: string;
  label: string;
  /** What Emberwall emits when the feature is missing. */
  fallback: string;
  /** Minimum kernel, where the feature also depends on one. */
  kernel?: string;
  /** Upstream commit that introduced it (git.netfilter.org / github.com/firewalld) or changelog entry. */
  source: string;
}

export const CAPABILITIES: Capability[] = [
  // iptables
  { key: 'restoreWait', tool: 'iptables', since: '1.6.2', label: 'iptables-restore --wait (xtables lock)', fallback: 'restore runs without waiting for the xtables lock', source: 'iptables 999eaa24' },
  { key: 'randomFullySnat', tool: 'iptables', since: '1.6.0', label: 'SNAT --random-fully', fallback: 'falls back to --random', source: 'iptables 3cefc136' },
  { key: 'randomFully', tool: 'iptables', since: '1.6.2', label: 'MASQUERADE --random-fully', fallback: 'falls back to --random', source: 'iptables 8b0da213' },
  { key: 'nftBackend', tool: 'iptables', since: '1.8.0', label: 'nf_tables backend (iptables-nft / iptables-legacy split)', fallback: 'legacy xtables backend only', source: 'iptables be70918e' },
  // nftables
  { key: 'inetNat', tool: 'nftables', since: '0.9.1', kernel: '5.2', label: 'NAT chains in the inet family', fallback: 'NAT goes into separate ip / ip6 tables', source: 'nftables fbe27464' },
  { key: 'namedPriority', tool: 'nftables', since: '0.9.1', label: 'named chain priorities (filter, dstnat, srcnat)', fallback: 'numeric priorities', source: 'nftables c8a0e8c9' },
  { key: 'thExpr', tool: 'nftables', since: '0.9.2', label: 'th dport (one rule for TCP and UDP)', fallback: 'one rule per protocol', source: 'nftables a43a6964' },
  { key: 'objectComments', tool: 'nftables', since: '0.9.7', label: 'comments on tables and chains', fallback: 'left out', source: 'nftables c156232a, 702ac2b7' },
  { key: 'destroy', tool: 'nftables', since: '1.0.7', kernel: '6.3', label: 'destroy table (idempotent reload)', fallback: 'add table + delete table idiom', source: 'nftables e1dfd5cc' },
  { key: 'ctCount', tool: 'nftables', since: '0.9.1', label: 'ct count (connection limits per client)', fallback: 'connection limit left out', source: 'nftables tests, first in v0.9.1' },
  { key: 'timeMatch', tool: 'nftables', since: '0.9.3', label: 'meta hour / meta day (schedules)', fallback: 'schedule left out', source: 'nftables tests, first in v0.9.3' },
  { key: 'dynSets', tool: 'nftables', since: '0.9.7', label: 'dynamic sets updated from rules (add @set { … })', fallback: 'meter syntax for per-client limits; no auto-ban', source: 'nftables tests, first in v0.9.7' },
  // ufw
  { key: 'route', tool: 'ufw', since: '0.34', label: 'ufw route (forwarding rules)', fallback: 'forward rules written as before.rules fragment', source: 'ufw ChangeLog 0.34' },
  { key: 'comment', tool: 'ufw', since: '0.35', label: 'rule comments', fallback: 'comments kept as shell comments', source: 'ufw ChangeLog 0.35' },
  // firewalld
  { key: 'richPriority', tool: 'firewalld', since: '0.7.0', label: 'rich rule priorities (ordered rules)', fallback: 'firewalld orders rich rules itself: log, deny, allow', source: 'firewalld aeac7508' },
  { key: 'policies', tool: 'firewalld', since: '0.9.0', label: 'policy objects (outbound / forward filtering)', fallback: 'outbound and forward rules use the direct interface', source: 'firewalld 623fc5b6' },
];

export const VERSIONS: Record<Tool, string[]> = {
  iptables: ['1.4.21', '1.6.1', '1.8.4', '1.8.5', '1.8.7', '1.8.9', '1.8.10', '1.8.11'],
  nftables: ['0.9.0', '0.9.3', '0.9.8', '1.0.2', '1.0.4', '1.0.6', '1.0.9', '1.1.3', '1.1.5', '1.1.6'],
  ufw: ['0.33', '0.35', '0.36', '0.36.1', '0.36.2'],
  firewalld: ['0.6.3', '0.8.2', '0.9.3', '0.9.11', '1.1.1', '1.3.3', '1.3.4', '2.1.1', '2.3.1', '2.4.0', '2.5.2'],
};

export type Persistence = 'debian' | 'rhel' | 'alpine' | 'arch' | 'generic';

export interface Distro {
  id: string;
  name: string;
  /** Version each tool ships at; a missing key means the tool is not packaged. */
  tools: Partial<Record<Tool, string>>;
  defaultTool: Tool;
  persistence: Persistence;
  /** Capability keys forced off regardless of version (kernel older than the feature needs). */
  disable?: string[];
  /** Backend the distro's default `iptables` binary uses. */
  iptablesBackend?: 'nft' | 'legacy';
  note?: string;
}

// Package versions were read from each distro's package index (RHEL rows from CentOS Stream specs).
export const DISTROS: Distro[] = [
  { id: 'ubuntu-26.04', name: 'Ubuntu 26.04 LTS', tools: { iptables: '1.8.11', nftables: '1.1.6', ufw: '0.36.2', firewalld: '2.3.1' }, defaultTool: 'ufw', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'ubuntu-24.04', name: 'Ubuntu 24.04 LTS', tools: { iptables: '1.8.10', nftables: '1.0.9', ufw: '0.36.2', firewalld: '2.1.1' }, defaultTool: 'ufw', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'ubuntu-22.04', name: 'Ubuntu 22.04 LTS', tools: { iptables: '1.8.7', nftables: '1.0.2', ufw: '0.36.1', firewalld: '1.1.1' }, defaultTool: 'ufw', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'ubuntu-20.04', name: 'Ubuntu 20.04 LTS', tools: { iptables: '1.8.4', nftables: '0.9.3', ufw: '0.36', firewalld: '0.8.2' }, defaultTool: 'ufw', persistence: 'debian', iptablesBackend: 'legacy' },
  { id: 'debian-13', name: 'Debian 13 (trixie)', tools: { iptables: '1.8.11', nftables: '1.1.3', ufw: '0.36.2', firewalld: '2.3.1' }, defaultTool: 'nftables', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'debian-12', name: 'Debian 12 (bookworm)', tools: { iptables: '1.8.9', nftables: '1.0.6', ufw: '0.36.2', firewalld: '1.3.3' }, defaultTool: 'nftables', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'debian-11', name: 'Debian 11 (bullseye)', tools: { iptables: '1.8.7', nftables: '0.9.8', ufw: '0.36', firewalld: '0.9.3' }, defaultTool: 'nftables', persistence: 'debian', iptablesBackend: 'nft' },
  { id: 'rhel-10', name: 'RHEL / Alma / Rocky 10', tools: { iptables: '1.8.11', nftables: '1.1.5', firewalld: '2.4.0' }, defaultTool: 'firewalld', persistence: 'rhel', iptablesBackend: 'nft', note: 'iptables is shipped as iptables-nft only and is no longer maintained by Red Hat.' },
  // Kernel 5.14: "destroy" needs 6.3.
  { id: 'rhel-9', name: 'RHEL / Alma / Rocky 9', tools: { iptables: '1.8.10', nftables: '1.0.9', firewalld: '1.3.4' }, defaultTool: 'firewalld', persistence: 'rhel', iptablesBackend: 'nft', disable: ['destroy'] },
  // Kernel 4.18: inet NAT needs 5.2.
  { id: 'rhel-8', name: 'RHEL / Alma / Rocky 8', tools: { iptables: '1.8.5', nftables: '1.0.4', firewalld: '0.9.11' }, defaultTool: 'firewalld', persistence: 'rhel', iptablesBackend: 'nft', disable: ['inetNat'] },
  { id: 'centos-7', name: 'CentOS / RHEL 7', tools: { iptables: '1.4.21', firewalld: '0.6.3' }, defaultTool: 'firewalld', persistence: 'rhel', iptablesBackend: 'legacy' },
  { id: 'alpine-3.20', name: 'Alpine 3.20', tools: { iptables: '1.8.10', nftables: '1.0.9', ufw: '0.36.2' }, defaultTool: 'nftables', persistence: 'alpine', iptablesBackend: 'nft' },
  { id: 'arch', name: 'Arch Linux (rolling)', tools: { iptables: '1.8.11', nftables: '1.1.5', ufw: '0.36.2', firewalld: '2.4.0' }, defaultTool: 'nftables', persistence: 'arch', iptablesBackend: 'nft', note: 'Rolling release: versions shown are a recent snapshot.' },
];

export interface TargetSelection {
  /** A distro id, or 'custom' to pick tool and version by hand. */
  distro: string;
  tool: Tool;
  /** Only used when distro is 'custom'. */
  version: string;
}

export interface Target {
  tool: Tool;
  version: string;
  distro: Distro | null;
  persistence: Persistence;
  caps: Record<string, boolean>;
  label: string;
}

export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function capsFor(tool: Tool, version: string, disable: string[] = []): Record<string, boolean> {
  const caps: Record<string, boolean> = {};
  for (const c of CAPABILITIES) {
    if (c.tool !== tool) continue;
    caps[c.key] = compareVersions(version, c.since) >= 0 && !disable.includes(c.key);
  }
  return caps;
}

export function latestVersion(tool: Tool): string {
  const list = VERSIONS[tool];
  return list[list.length - 1];
}

export function toolsFor(sel: TargetSelection): Tool[] {
  const distro = DISTROS.find((d) => d.id === sel.distro);
  if (!distro) return TOOLS;
  return TOOLS.filter((t) => distro.tools[t] !== undefined);
}

export function resolveTarget(sel: TargetSelection): Target {
  const distro = DISTROS.find((d) => d.id === sel.distro) ?? null;
  let tool = sel.tool;
  let version = sel.version || latestVersion(tool);
  if (distro) {
    if (distro.tools[tool] === undefined) tool = distro.defaultTool;
    version = distro.tools[tool] as string;
  }
  return {
    tool,
    version,
    distro,
    persistence: distro?.persistence ?? 'generic',
    caps: capsFor(tool, version, distro?.disable),
    label: `${TOOL_LABEL[tool]} ${version}${distro ? ` · ${distro.name}` : ''}`,
  };
}

export const DEFAULT_SELECTION: TargetSelection = { distro: 'ubuntu-26.04', tool: 'nftables', version: '1.1.6' };

/** Manual pages the emitted syntax was last checked against (Ubuntu 26.04 manpages, upstream sources). */
export const DOCS_CHECKED: { tool: Tool; pages: string; version: string }[] = [
  { tool: 'nftables', pages: 'nft(8)', version: '1.1.6' },
  { tool: 'iptables', pages: 'iptables(8), iptables-extensions(8)', version: '1.8.11' },
  { tool: 'ufw', pages: 'ufw(8), upstream ChangeLog', version: '0.36.2' },
  { tool: 'firewalld', pages: 'firewall-cmd(1), firewalld.richlanguage(5), firewalld.policy(5)', version: '2.3.1 (source tree 2.5.2)' },
];
