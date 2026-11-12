// Blocklists: large address sets dropped before any other rule, optionally refreshed from a URL.
import type { Project } from '../model';
import { familyOf, parseCidr } from '../net';
import { slug } from '../resolve';
import type { Tool } from '../targets';
import { BANNER, Out, shQuote, type Diags, type OutFile } from './types';

export interface ActiveList {
  id: string;
  name: string;
  /** Kernel set name without the family suffix. */
  set: string;
  v4: string[];
  v6: string[];
  url?: string;
  outbound: boolean;
}

export function activeLists(p: Project, d?: Diags): ActiveList[] {
  const out: ActiveList[] = [];
  const used = new Set<string>();
  for (const b of (p.blocklists ?? []).filter((x) => x.enabled)) {
    const valid = b.entries.map((e) => e.trim()).filter(Boolean).filter((e) => {
      const ok = !!parseCidr(e);
      if (!ok) d?.invalid(`Blocklist "${b.name}": "${e}" is not an address or CIDR`);
      return ok;
    });
    if (b.url && !/^https?:\/\/[^\s'"`$\\]+$/.test(b.url)) {
      d?.invalid(`Blocklist "${b.name}": the URL must be a plain http(s) address`);
      continue;
    }
    if (valid.length === 0 && !b.url) continue;
    let set = `ew_bl_${slug(b.name, 14).replace(/-/g, '_')}`;
    while (used.has(set)) set += '_';
    used.add(set);
    out.push({
      id: b.id, name: b.name, set, url: b.url, outbound: !!b.outbound,
      v4: [...new Set(valid.filter((e) => familyOf(e) === 'ipv4'))],
      v6: p.options.ipv6 ? [...new Set(valid.filter((e) => familyOf(e) === 'ipv6'))] : [],
    });
  }
  return out;
}

/** iptables rule specs (also used for ufw fragments). Needs the ipsets to exist first. */
export function ipsetSpecs(lists: ActiveList[], fam: 'ipv4' | 'ipv6'): { input: string[]; forward: string[]; output: string[] } {
  const sfx = fam === 'ipv4' ? 'v4' : 'v6';
  const input: string[] = [];
  const forward: string[] = [];
  const output: string[] = [];
  for (const l of lists) {
    const c = `-m comment --comment "blocklist: ${l.name.replace(/["\\]/g, '')}"`;
    input.push(`-m set --match-set ${l.set}_${sfx} src ${c} -j DROP`);
    forward.push(`-m set --match-set ${l.set}_${sfx} src ${c} -j DROP`);
    if (l.outbound) {
      output.push(`-m set --match-set ${l.set}_${sfx} dst ${c} -j DROP`);
      forward.push(`-m set --match-set ${l.set}_${sfx} dst ${c} -j DROP`);
    }
  }
  return { input, forward, output };
}

/** Shell commands that create the ipsets and load the entries stored in the project. */
export function ipsetCreate(lists: ActiveList[], ipv6: boolean): string[] {
  const cmds: string[] = [];
  for (const l of lists) {
    cmds.push(`ipset create ${l.set}_v4 hash:net family inet -exist`);
    l.v4.forEach((e) => cmds.push(`ipset add ${l.set}_v4 ${e} -exist`));
    if (ipv6) {
      cmds.push(`ipset create ${l.set}_v6 hash:net family inet6 -exist`);
      l.v6.forEach((e) => cmds.push(`ipset add ${l.set}_v6 ${e} -exist`));
    }
  }
  return cmds;
}

/**
 * Script + systemd units that refresh URL-backed lists on the firewall host.
 * Downloads are filtered to lines that look like addresses before anything is loaded.
 */
export function blocklistUpdater(lists: ActiveList[], tool: Tool, ipv6: boolean): OutFile[] {
  const remote = lists.filter((l) => l.url);
  if (remote.length === 0) return [];
  const o = new Out();
  o.push('#!/bin/sh');
  o.push(`# ${BANNER} - refreshes downloaded blocklists (${tool}).`);
  o.push('# Run as root, by hand or from emberwall-blocklists.timer. A failed download keeps the old entries.');
  o.push('set -eu');
  o.blank();
  o.push('fetch() {');
  o.push('  # $1 = url, $2 = output file with one address or CIDR per line');
  o.push('  curl -fsSL --max-time 120 "$1" -o "$2.raw" || return 1');
  o.push(`  grep -Eo '^[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?' "$2.raw" | sort -u > "$2.v4" || true`);
  o.push(`  grep -Eio '^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}(/[0-9]{1,3})?' "$2.raw" | sort -u > "$2.v6" || true`);
  o.push('  [ -s "$2.v4" ] || [ -s "$2.v6" ]');
  o.push('}');
  o.blank();
  o.push('TMP="$(mktemp -d)"');
  o.push(`trap 'rm -rf "$TMP"' EXIT`);
  for (const l of remote) {
    o.blank();
    o.push(`# ${l.name}`);
    o.push(`if fetch ${shQuote(l.url!)} "$TMP/${l.set}"; then`);
    const fams: ['v4' | 'v6', string[], string][] = ipv6 ? [['v4', l.v4, 'inet'], ['v6', l.v6, 'inet6']] : [['v4', l.v4, 'inet']];
    for (const [sfx, keep, fam] of fams) {
      const set = `${l.set}_${sfx}`;
      keep.forEach((e) => o.push(`  echo ${shQuote(e)} >> "$TMP/${l.set}.${sfx}"`));
      if (tool === 'nftables') {
        o.push('  {');
        o.push(`    echo "flush set inet emberwall ${set}"`);
        o.push(`    [ -s "$TMP/${l.set}.${sfx}" ] && echo "add element inet emberwall ${set} { $(paste -sd, "$TMP/${l.set}.${sfx}") }"`);
        o.push('  } | nft -f -');
      } else if (tool === 'firewalld') {
        o.push(`  firewall-cmd --permanent --ipset=${set} --get-entries > "$TMP/${set}.old"`);
        o.push(`  [ -s "$TMP/${set}.old" ] && firewall-cmd --permanent --ipset=${set} --remove-entries-from-file="$TMP/${set}.old" >/dev/null`);
        o.push(`  [ -s "$TMP/${l.set}.${sfx}" ] && firewall-cmd --permanent --ipset=${set} --add-entries-from-file="$TMP/${l.set}.${sfx}" >/dev/null`);
      } else {
        o.push(`  ipset create ${set}_new hash:net family ${fam} -exist && ipset flush ${set}_new`);
        o.push(`  while read -r net; do ipset add ${set}_new "$net" -exist; done < "$TMP/${l.set}.${sfx}"`);
        o.push(`  ipset create ${set} hash:net family ${fam} -exist`);
        o.push(`  ipset swap ${set}_new ${set} && ipset destroy ${set}_new`);
      }
    }
    o.push(`  echo "updated ${l.name}"`);
    o.push('else');
    o.push(`  echo "download failed for ${l.name}; keeping the current entries" >&2`);
    o.push('fi');
  }
  if (tool === 'firewalld') {
    o.blank();
    o.push('firewall-cmd --reload >/dev/null');
  }

  const unit = (lines: string[]): { text: string }[] => lines.map((text) => ({ text }));
  return [
    { name: 'emberwall-blocklists.sh', path: '/usr/local/sbin/emberwall-blocklists.sh', lang: 'shell', description: 'Refreshes downloaded blocklists', lines: o.lines },
    {
      name: 'emberwall-blocklists.service', path: '/etc/systemd/system/emberwall-blocklists.service', lang: 'conf', description: 'systemd service for the refresh',
      lines: unit(['[Unit]', 'Description=Refresh Emberwall blocklists', 'After=network-online.target', 'Wants=network-online.target', '', '[Service]', 'Type=oneshot', 'ExecStart=/usr/local/sbin/emberwall-blocklists.sh']),
    },
    {
      name: 'emberwall-blocklists.timer', path: '/etc/systemd/system/emberwall-blocklists.timer', lang: 'conf', description: 'Runs the refresh daily (systemctl enable --now emberwall-blocklists.timer)',
      lines: unit(['[Unit]', 'Description=Daily refresh of Emberwall blocklists', '', '[Timer]', 'OnBootSec=2min', 'OnUnitActiveSec=1d', 'RandomizedDelaySec=30min', 'Persistent=true', '', '[Install]', 'WantedBy=timers.target']),
    },
  ];
}
