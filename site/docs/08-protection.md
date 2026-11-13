---
title: Protection
description: Attack protection (SYN flood guard, port-scan filter, auto-ban), blocklists and country blocking with a scheduled updater, and kernel hardening with sysctl.
section: Design
---

Beyond allow and deny rules, Emberwall can add three layers of protection: attack protection rules, blocklists, and kernel network hardening.

## Attack protection

The **Attack protection** panel is on the **Rules** page. It works natively on nftables and iptables; on ufw the rules go into the `before.rules` fragment.

| Protection | Default when switched on | What it does |
|---|---|---|
| **SYN flood guard** | 25 per second per client, burst 50 | Drops clients opening new TCP connections faster than the rate. Inbound only. |
| **Port-scan filter** | on / off | Drops TCP packets with flag combinations only scanners send (for example no flags, all flags, SYN+FIN, SYN+RST). Inbound and forwarded traffic. |
| **Auto-ban** | trap ports `23, 3389, 5900`, ban for 3600 seconds | A client that touches one of the TCP trap ports is dropped entirely, on every port, for the ban time. Inbound only. |

### Auto-ban

Choose trap ports that you do not serve. Banned clients are dropped early, before established connections are accepted, so a ban also cuts their open connections.

> [!WARNING]
> If an accept rule opens one of the trap ports, clients are banned before they reach that rule and the service becomes unreachable. The audit reports this as **"..." opens an auto-ban trap port** (high severity).

Version and backend notes:

- **nftables:** auto-ban needs 0.9.7 or newer (sets updated from rules). On older versions it is left out and reported. Per-client tracking for the SYN flood guard uses the older `meter` syntax before 0.9.7.
- **iptables:** uses `-m hashlimit` for the SYN flood guard and `-m recent` for auto-ban.
- **ufw:** has no commands for these, so they are written to the `before.rules` fragment.
- **firewalld:** has no settings for scan, flood or auto-ban protection. They are not part of the output; use the nftables or iptables target if you need them.

The packet simulator models auto-ban trap ports. It does not model the SYN flood guard or the port-scan filter.

## Blocklists

A blocklist is a set of addresses dropped before every other rule, even for established connections. Use it for known-bad addresses, abusive networks, or countries you never serve.

![Blocklists page](shot:blocklists)

### Create a blocklist

1. Open **Blocklists** in the sidebar and press **Blocklist**.
2. Name it.
3. Under **Addresses in the project**, paste addresses and CIDRs. You can paste many at once, separated by spaces, commas or new lines.
4. Optionally set a **Download URL**: a list with one address or CIDR per line, fetched on the firewall host.
5. Switch on **Block outbound too** to also drop traffic going *to* these addresses.

Each blocklist has an **Enabled** switch. An enabled list with no valid entries and no URL is skipped.

### Block a country

Under **Block a country**, enter a two-letter country code (for example `KP`) and press **Add country list**. Emberwall adds a blocklist named "Country KP" with a download URL of the form:

```text
https://www.ipdeny.com/ipblocks/data/aggregated/kp-aggregated.zone
```

> [!WARNING]
> Country data comes from a third-party site (ipdeny.com) that your server fetches itself. Emberwall does not bundle or check it. Review the URL before you rely on it.

### How blocklists are built

| Backend | How the addresses are held |
|---|---|
| nftables | Named sets in the `inet emberwall` table, one for IPv4 and one for IPv6 |
| iptables | `ipset` sets (`hash:net`). The apply script creates them. |
| ufw | `ipset` sets, matched from the `before.rules` fragment. Create the sets before ufw starts (for example from `/etc/ufw/before.init`) with the commands at the top of the fragment. |
| firewalld | firewalld ipsets. firewalld output only blocks traffic coming *from* the list, not going to it. |

On iptables and ufw, install the `ipset` package. To keep the sets across reboots, save them, for example with `ipset save > /etc/ipset.conf`, or use your distribution's ipset service.

### Downloaded lists: the updater

When any enabled blocklist has a download URL, the build adds three files:

| File | Install path | Purpose |
|---|---|---|
| `emberwall-blocklists.sh` | `/usr/local/sbin/emberwall-blocklists.sh` | Downloads each list and loads it |
| `emberwall-blocklists.service` | `/etc/systemd/system/emberwall-blocklists.service` | One-shot systemd service that runs the script |
| `emberwall-blocklists.timer` | `/etc/systemd/system/emberwall-blocklists.timer` | Runs the service 2 minutes after boot and then daily (with up to 30 minutes of random delay) |

The script needs `curl`. It keeps only lines that look like addresses, keeps the entries stored in the project, and replaces the set contents. If a download fails, the current entries stay.

To install it on the firewall host, as root:

```sh
install -m 700 emberwall-blocklists.sh /usr/local/sbin/emberwall-blocklists.sh
install -m 644 emberwall-blocklists.service emberwall-blocklists.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now emberwall-blocklists.timer
```

> [!NOTE]
> On nftables, downloaded blocklists start empty when the ruleset loads. Run `emberwall-blocklists.sh` once after loading the ruleset. Reloading the ruleset empties them again until the next refresh.

Limits to keep in mind:

- The download URL must be a plain `http://` or `https://` address.
- The simulator only checks the entries stored in the project, not downloaded ones.
- [Guarded push](doc:live-servers) refuses iptables and ufw builds with blocklists, because the `ipset` sets must be created by hand. Blocklist units are never installed by a push.

## Kernel hardening

Some protections belong in the kernel, not in firewall rules: refusing spoofed, redirected and source-routed packets, for example. The **Kernel hardening** page lists these settings. Enabled ones are written to a sysctl drop-in that ships with every build.

![Kernel hardening page](shot:hardening)

- **Enable recommended** switches on every setting marked *recommended*.
- **Clear** switches them all off.
- Settings that can break a routing setup show a caution.

{{sysctl}}

### Install the sysctl file

The build includes `99-emberwall.conf` when at least one setting is enabled. Install it and load it:

```sh
install -m 644 99-emberwall.conf /etc/sysctl.d/99-emberwall.conf
sysctl --system
```

Keys for IPv6 and connection tracking are written with a leading `-`, which tells `sysctl` to skip them quietly on hosts where they do not exist.

The file also sets `net.ipv4.ip_forward` (and `net.ipv6.conf.all.forwarding` when IPv6 is on) from the **Routing** option: `1` if the host forwards packets or has NAT rules, `0` otherwise.

The audit reports **Recommended kernel hardening is not enabled** while any recommended setting is off, and offers **Enable recommended** as a fix. The CIS-style and internet-server compliance profiles include the same check.

> [!NOTE]
> The live server view does not read a server's own sysctl values. Kernel hardening is a project setting. The sysctl file is not installed by a guarded push either; install it by hand.
