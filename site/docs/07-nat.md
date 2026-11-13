---
title: NAT and port forwarding
description: Configure masquerade, source NAT and port forwards (DNAT) in Emberwall, including IPv6 NAT and randomised source ports.
section: Design
---

The **NAT** page handles address translation for routers, gateways and container hosts. A plain server needs none; add NAT when this host routes traffic for other machines.

![NAT page](shot:nat)

## Kinds of NAT

| Kind | Button | Use it to |
|---|---|---|
| Masquerade | **Masquerade** | Hide a network behind this host's outgoing address. Use it when that address is dynamic. |
| Source NAT | **Source NAT** | Rewrite the source to a fixed address. Use it when the host has a static IP. |
| Port forward | **Port forward** | Send traffic arriving on a port to an internal host (destination NAT). |

Each NAT rule has an **Enabled** switch, a **Name**, and a kind selector, so you can change its kind later.

## Masquerade

To let a LAN reach the internet through this host:

1. Press **Masquerade**.
2. Set **Outbound interface** to the internet-facing interface, for example `eth0`.
3. Set **Source** to the internal network, for example `192.168.1.0/24`.
4. Optionally set **Protocol** (Any, TCP or UDP) and **Destination**.

The masqueraded traffic also passes the **forward** chain, so you need a forward rule that accepts it (or a forward policy of accept). The *NAT router* and *WireGuard gateway* templates show a working setup.

## Source NAT

Source NAT works like masquerade but rewrites the source to the address in **Translate to**, for example `203.0.113.5`. A source NAT rule without a **Translate to** address is reported as an error and left out.

## Port forwards

To forward a public port to an internal server:

1. Press **Port forward**. New port forwards start with protocol TCP.
2. Set **Inbound interface** to the interface the traffic arrives on, for example `eth0`.
3. Set **Port** to the public port, for example `443`.
4. Set **Forward to address**, for example `192.168.1.10`.
5. Set **Forward to port** if it differs. Empty means the same port.
6. Optionally restrict **Source** and **Original destination**.

> [!WARNING]
> A port forward only rewrites the destination. The packet is then filtered as **forwarded** traffic, so it also needs a forward rule that accepts it. The audit finding **Port forward ... is blocked by the forward policy** offers a one-click **Add forward rule** fix.

Rules for port forwards:

- A port forward needs a **Forward to address**; without one it is an error.
- A port forward that matches a port needs protocol TCP or UDP, not Any.
- **Forward to address** must be a single address, not a network.
- On firewalld, a port forward needs a protocol, a port and a target address; otherwise it is left out and reported.

## Forwarding must be on

NAT needs the kernel to route packets. When any NAT rule is enabled, or the **Routing** option is on, On nftables and iptables, `emberwall-apply.sh` switches on `net.ipv4.ip_forward` (and IPv6 forwarding when IPv6 is on) for the running system. To keep it after a reboot, enable at least one [kernel hardening](doc:protection#kernel-hardening) setting: the build then includes the sysctl drop-in `99-emberwall.conf`, which also sets forwarding. On ufw, the generated script enables forwarding in `/etc/ufw/sysctl.conf`.

If NAT rules exist but **Routing** is off, the audit reports **NAT rules exist but forwarding is off** and can turn it on for you.

## IPv6 NAT

Each NAT rule applies to one address family. Emberwall takes it from the first address it finds in **Forward to address** / **Translate to**, **Source** or **Destination**. If none of them is set, the rule is IPv4.

To NAT IPv6 traffic, use IPv6 addresses in those fields, for example a source of `fd00:10::/64`.

On nftables 0.9.1 or newer (with kernel 5.2 or newer), NAT goes into the same `inet` table as the filter rules. On older versions, or on RHEL 8 whose kernel is too old, NAT is written to separate `ip` and `ip6` tables.

## Randomised source ports

Masquerade and source NAT rules have a **Randomise source ports** switch. It randomises the source port mapping fully:

| Backend | Output |
|---|---|
| nftables | `fully-random` |
| iptables, SNAT | `--random-fully` from iptables 1.6.0, `--random` before |
| iptables, MASQUERADE | `--random-fully` from iptables 1.6.2, `--random` before |

When Emberwall falls back to `--random`, the compiler notes say so.

## Backend notes

- **ufw** has no NAT commands. NAT rules go into a `*nat` block in the `before.rules` fragment, which you paste at the top of `/etc/ufw/before.rules` (and `before6.rules` for IPv6).
- **firewalld** turns masquerade into `<masquerade/>` or a rich rule, and port forwards into `<forward-port>` entries or rich rules. It has no source NAT setting, so source NAT is written through the direct interface in iptables syntax.
- The cloud, Windows and Kubernetes targets do not translate addresses; NAT rules are listed as not expressible. See [More targets](doc:more-targets).
