// Kernel network hardening: a catalogue of sysctl settings and the drop-in file built from it.
import { BANNER, Out, type OutFile } from './compile/types';
import type { Project } from './model';

export interface HardeningSetting {
  id: string;
  label: string;
  why: string;
  /** key = value lines. IPv6 keys are written with a leading "-" so hosts without IPv6 skip them. */
  lines: [string, string][];
  recommended: boolean;
  /** Shown when the setting can break a routing setup. */
  caution?: string;
}

export const HARDENING: HardeningSetting[] = [
  {
    id: 'rp_filter', label: 'Reverse-path filter', recommended: true,
    why: 'Drops packets whose source address could not be reached through the interface they arrived on (spoofing).',
    lines: [['net.ipv4.conf.all.rp_filter', '1'], ['net.ipv4.conf.default.rp_filter', '1']],
    caution: 'Strict mode breaks asymmetric routing (multi-homed hosts, some VPN and policy-routing setups).',
  },
  {
    id: 'syncookies', label: 'TCP SYN cookies', recommended: true,
    why: 'Keeps accepting connections during a SYN flood instead of filling the backlog.',
    lines: [['net.ipv4.tcp_syncookies', '1']],
  },
  {
    id: 'no_redirects', label: 'Ignore ICMP redirects', recommended: true,
    why: 'Redirects let another host on the link rewrite this machine\'s routes.',
    lines: [
      ['net.ipv4.conf.all.accept_redirects', '0'], ['net.ipv4.conf.default.accept_redirects', '0'],
      ['net.ipv4.conf.all.secure_redirects', '0'],
      ['-net.ipv6.conf.all.accept_redirects', '0'], ['-net.ipv6.conf.default.accept_redirects', '0'],
    ],
  },
  {
    id: 'no_send_redirects', label: 'Do not send ICMP redirects', recommended: true,
    why: 'Only routers that share a link with better gateways need to send them.',
    lines: [['net.ipv4.conf.all.send_redirects', '0'], ['net.ipv4.conf.default.send_redirects', '0']],
  },
  {
    id: 'no_source_route', label: 'Refuse source-routed packets', recommended: true,
    why: 'Source routing lets the sender choose the path and bypass filtering.',
    lines: [
      ['net.ipv4.conf.all.accept_source_route', '0'], ['net.ipv4.conf.default.accept_source_route', '0'],
      ['-net.ipv6.conf.all.accept_source_route', '0'],
    ],
  },
  {
    id: 'icmp_hygiene', label: 'ICMP hygiene', recommended: true,
    why: 'Ignores broadcast pings (smurf amplification) and bogus ICMP error replies.',
    lines: [['net.ipv4.icmp_echo_ignore_broadcasts', '1'], ['net.ipv4.icmp_ignore_bogus_error_responses', '1']],
  },
  {
    id: 'log_martians', label: 'Log impossible addresses', recommended: false,
    why: 'Writes a kernel log line for packets with addresses that cannot be valid on the interface.',
    lines: [['net.ipv4.conf.all.log_martians', '1']],
    caution: 'Can be noisy on busy or misconfigured networks.',
  },
  {
    id: 'rfc1337', label: 'TIME-WAIT assassination protection', recommended: false,
    why: 'Drops RST packets for sockets in TIME-WAIT (RFC 1337).',
    lines: [['net.ipv4.tcp_rfc1337', '1']],
  },
  {
    id: 'conntrack_strict', label: 'Strict connection tracking', recommended: false,
    why: 'Stops conntrack from picking up connections mid-stream, so only connections seen from their first packet count as established.',
    lines: [['-net.netfilter.nf_conntrack_tcp_loose', '0']],
    caution: 'Established connections are cut when the firewall restarts or the conntrack table is flushed.',
  },
];

export const RECOMMENDED_HARDENING = HARDENING.filter((h) => h.recommended).map((h) => h.id);

export function sysctlFile(p: Project): OutFile | null {
  const enabled = HARDENING.filter((h) => (p.hardening ?? []).includes(h.id));
  if (enabled.length === 0) return null;
  const o = new Out();
  o.push(`# ${BANNER} - kernel network hardening for ${p.name}`);
  o.push('# Install as /etc/sysctl.d/99-emberwall.conf, then run: sysctl --system');
  o.push('# A leading "-" tells sysctl to skip the key quietly where it does not exist.');
  for (const h of enabled) {
    o.blank();
    o.push(`# ${h.label}: ${h.why}`);
    if (h.caution) o.push(`# Caution: ${h.caution}`);
    for (const [k, v] of h.lines) o.push(`${k} = ${v}`);
  }
  o.blank();
  const fwd = p.options.forwarding || p.nat.some((n) => n.enabled);
  o.push(`# Routing: ${fwd ? 'this host forwards packets' : 'this host is not a router'}`);
  o.push(`net.ipv4.ip_forward = ${fwd ? 1 : 0}`);
  o.push(`-net.ipv6.conf.all.forwarding = ${fwd && p.options.ipv6 ? 1 : 0}`);
  return { name: '99-emberwall.conf', path: '/etc/sysctl.d/99-emberwall.conf', lang: 'conf', description: 'Kernel hardening (sysctl drop-in)', lines: o.lines };
}
