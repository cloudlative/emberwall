// Live servers: the fixed set of commands Emberwall runs over SSH, and how their output is read.
// Pure functions only (no network), shared by the server, the browser and the tests.
import { importFirewalldXml } from './import/firewalldXml';
import { importIptablesSave } from './import/iptablesSave';
import { filterTables, importNft } from './import/nft';
import type { ImportReport } from './import/shared';
import { importUfw } from './import/ufw';
import { compareVersions, DISTROS, VERSIONS, type TargetSelection, type Tool } from './targets';

/** Read-only commands. Nothing from the browser is ever added to these strings. */
export const PROBE_COMMANDS = {
  uid: 'id -u',
  os: 'cat /etc/os-release',
  kernel: 'uname -r',
  nftVersion: 'nft --version',
  iptablesVersion: 'iptables --version',
  ufwVersion: 'ufw version',
  firewalldVersion: 'firewall-cmd --version',
  firewalldState: 'firewall-cmd --state',
  ufwStatus: 'ufw status verbose',
  ufwAdded: 'ufw show added',
  nftRuleset: 'nft list ruleset',
  iptablesSave: 'iptables-save',
  ip6tablesSave: 'ip6tables-save',
  firewalldZone: 'firewall-cmd --get-default-zone',
} as const;

export type ProbeKey = keyof typeof PROBE_COMMANDS | 'firewalldZoneXml';

/** Commands that need root (run through "sudo -n" for a non-root login). */
export const NEEDS_ROOT: ProbeKey[] = ['ufwStatus', 'ufwAdded', 'nftRuleset', 'iptablesSave', 'ip6tablesSave', 'firewalldState', 'firewalldZone', 'firewalldZoneXml'];

/** The zone name comes from the server, so it is checked before it goes into a path. */
export function zoneXmlCommand(zone: string): string | null {
  const z = zone.trim();
  return /^[A-Za-z0-9_-]{1,40}$/.test(z) ? `cat /etc/firewalld/zones/${z}.xml` : null;
}

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export type ProbeOutput = Partial<Record<ProbeKey, CommandResult>>;

export interface Detected {
  os: string;
  kernel: string;
  /** Version of each installed tool. */
  versions: Partial<Record<Tool, string>>;
  /** The firewall manager that is actually in charge. */
  activeTool: Tool | null;
  reason: string;
  selection: TargetSelection | null;
  isRoot: boolean;
  /** Reading the ruleset failed for lack of privilege. */
  needsPrivilege: boolean;
}

const ok = (r?: CommandResult) => !!r && r.code === 0;
const ver = (r: CommandResult | undefined, re: RegExp) => (ok(r) ? re.exec(r!.stdout)?.[1] : undefined);

/** Closest known version at or below the detected one, so capability flags err on the safe side. */
export function nearestKnown(tool: Tool, version: string): string {
  const known = [...VERSIONS[tool]].sort(compareVersions);
  let pick = known[0];
  for (const k of known) if (compareVersions(k, version) <= 0) pick = k;
  return pick;
}

function distroId(osRelease: string): string | null {
  const get = (k: string) => new RegExp(`^${k}="?([^"\\n]*)"?$`, 'm').exec(osRelease)?.[1] ?? '';
  const id = get('ID').toLowerCase();
  const v = get('VERSION_ID');
  const major = v.split('.')[0];
  const candidates =
    id === 'ubuntu' ? [`ubuntu-${v}`]
    : id === 'debian' ? [`debian-${major}`]
    : ['rhel', 'almalinux', 'rocky', 'centos', 'ol'].includes(id) ? [major === '7' ? 'centos-7' : `rhel-${major}`]
    : id === 'alpine' ? [`alpine-${v.split('.').slice(0, 2).join('.')}`]
    : id === 'arch' ? ['arch']
    : [];
  return candidates.find((c) => DISTROS.some((d) => d.id === c)) ?? null;
}

export function detect(out: ProbeOutput): Detected {
  const osText = ok(out.os) ? out.os!.stdout : '';
  const pretty = /^PRETTY_NAME="?([^"\n]*)"?$/m.exec(osText)?.[1] ?? 'Unknown system';
  const versions: Detected['versions'] = {};
  const nft = ver(out.nftVersion, /v(\d+\.\d+(?:\.\d+)?)/);
  const ipt = ver(out.iptablesVersion, /v(\d+\.\d+(?:\.\d+)?)/);
  const ufw = ver(out.ufwVersion, /ufw (\d+\.\d+(?:\.\d+)?)/);
  const fwd = ver(out.firewalldVersion, /(\d+\.\d+(?:\.\d+)?)/);
  if (nft) versions.nftables = nft;
  if (ipt) versions.iptables = ipt;
  if (ufw) versions.ufw = ufw;
  if (fwd) versions.firewalld = fwd;

  const denied = [out.nftRuleset, out.iptablesSave, out.ufwStatus].some((r) => !!r && r.code !== 0 && /permission denied|operation not permitted|must be root|need to be root|a password is required|sudo:/i.test(r.stderr + r.stdout));
  const ruleset = ok(out.nftRuleset) ? out.nftRuleset!.stdout : '';
  // Tables created by iptables-nft are not a native nftables configuration.
  const nativeNft = /^table (inet|ip|ip6|bridge|netdev) (?!filter\b|nat\b|mangle\b|raw\b|security\b)[\w-]+ \{/m.test(ruleset) || (/^table inet /m.test(ruleset) && !/# Warning: table .* is managed by iptables-nft/.test(ruleset));
  const iptRules = ok(out.iptablesSave) && /^-A /m.test(out.iptablesSave!.stdout);

  let activeTool: Tool | null = null;
  let reason = 'No active firewall was found.';
  if (ok(out.firewalldState) && /running/.test(out.firewalldState!.stdout)) {
    activeTool = 'firewalld';
    reason = 'firewalld is running.';
  } else if (ok(out.ufwStatus) && /^Status: active/m.test(out.ufwStatus!.stdout)) {
    activeTool = 'ufw';
    reason = 'ufw is active.';
  } else if (nativeNft && versions.nftables) {
    activeTool = 'nftables';
    reason = 'A native nftables ruleset is loaded.';
  } else if (iptRules && versions.iptables) {
    activeTool = 'iptables';
    reason = 'iptables rules are loaded.';
  } else if (versions.nftables) {
    activeTool = 'nftables';
    reason = 'No rules are loaded; nftables is installed.';
  } else if (versions.iptables) {
    activeTool = 'iptables';
    reason = 'No rules are loaded; iptables is installed.';
  }

  let selection: TargetSelection | null = null;
  if (activeTool && versions[activeTool]) {
    const d = distroId(osText);
    const distro = DISTROS.find((x) => x.id === d);
    // Use the distribution preset only when it really ships this exact version.
    if (distro && distro.tools[activeTool] === versions[activeTool]) selection = { distro: distro.id, tool: activeTool, version: '' };
    else selection = { distro: 'custom', tool: activeTool, version: nearestKnown(activeTool, versions[activeTool]!) };
  }
  return { os: pretty, kernel: ok(out.kernel) ? out.kernel!.stdout.trim() : '', versions, activeTool, reason, selection, isRoot: ok(out.uid) && out.uid!.stdout.trim() === '0', needsPrivilege: denied };
}

export interface LiveConfig {
  tool: Tool;
  /** The text shown in the raw viewer. */
  raw: { name: string; text: string }[];
  report: ImportReport;
}

/** Runs the right importer over what the server returned. */
export function readLiveConfig(out: ProbeOutput, tool: Tool): LiveConfig | null {
  const text = (k: ProbeKey) => (ok(out[k]) ? out[k]!.stdout : '');
  if (tool === 'nftables') {
    const t = text('nftRuleset');
    // Every table with a filter chain gets a say: a packet must be accepted by all of them.
    // That cannot be shown as one rule list, so read Emberwall's own table when it is there.
    const tables = filterTables(t);
    const own = tables.find((x) => x === 'inet emberwall');
    const report = importNft(t, own && tables.length > 1 ? own : undefined);
    const others = tables.filter((x) => x !== own);
    if (own && others.length > 0) report.notes = [`Showing the "${own}" table. ${others.length === 1 ? 'Another table also filters' : 'Other tables also filter'} traffic on this server and ${others.length === 1 ? 'is' : 'are'} not part of this view: ${others.join(', ')}. A packet has to be accepted by every one of them.`];
    else if (!own && tables.length > 1) report.notes = [`This server has ${tables.length} tables that filter traffic (${tables.join(', ')}). A packet has to be accepted by every one of them; the rules below list them one after another, so treat the audit and drift results as approximate.`];
    return { tool, raw: [{ name: 'nft list ruleset', text: t }], report };
  }
  if (tool === 'iptables') {
    const v4 = text('iptablesSave');
    const v6 = text('ip6tablesSave');
    // The importer tells the families apart by the "Generated by ip6tables-save" header.
    const v6marked = v6 && !/ip6tables/.test(v6.split('\n')[0] ?? '') ? `# Generated by ip6tables-save\n${v6}` : v6;
    return { tool, raw: [{ name: 'iptables-save', text: v4 }, { name: 'ip6tables-save', text: v6 }], report: importIptablesSave(`${v4}\n${v6marked}`) };
  }
  if (tool === 'ufw') {
    const added = text('ufwAdded');
    const status = text('ufwStatus');
    // "show added" has the rules as commands; the status header has the default policies.
    const policy = status.split('\n').filter((l) => /^(Default:|Logging:)/.test(l)).join('\n');
    const rules = added.split('\n').filter((l) => l.startsWith('ufw ')).join('\n');
    return { tool, raw: [{ name: 'ufw status verbose', text: status }, { name: 'ufw show added', text: added }], report: importUfw(rules ? `${policy}\n${rules}` : status) };
  }
  const xml = text('firewalldZoneXml');
  return { tool, raw: [{ name: `zone ${text('firewalldZone').trim() || '?'}`, text: xml }], report: importFirewalldXml(xml) };
}
