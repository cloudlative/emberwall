---
title: Concepts
description: The Emberwall project model - directions, default policies, actions, the built-in baseline options, and how rules are ordered and evaluated.
section: Design
---

Everything in Emberwall works from one model of your firewall, called the project. The editor, simulator, audit, reachability matrix and every compiler read the same project. This page explains its parts and the order in which a packet meets them.

## The project

A project holds:

- **Default policies** for each direction.
- **Options**: a baseline of common rules you switch on or off.
- **Rules**, in order, per direction.
- **NAT rules**: masquerade, source NAT and port forwards.
- **Objects**: reusable address groups and port groups.
- **Zones**: named network sides such as WAN and LAN.
- **Attack protection**, **blocklists** and **kernel hardening**.
- **Policy tests** and, for fleets, **hosts**.

You can export the whole project as JSON; see [Project file format](doc:project-format).

## Directions

Every rule belongs to one direction:

| Direction | Label in the app | Traffic |
|---|---|---|
| `in` | Inbound | Packets addressed to this host. |
| `out` | Outbound | Packets this host sends. |
| `forward` | Forward | Packets this host routes between interfaces (routers, gateways, container hosts). |

## Default policies

Each direction has a default policy, `accept` or `drop`. It applies to every packet that no rule matched. On the **Rules** page each direction ends with a line such as "Then: **drop** everything else".

A new project starts with:

| Direction | Default policy |
|---|---|
| Inbound | `drop` |
| Outbound | `accept` |
| Forward | `drop` |

A firewall should drop inbound traffic by default and allow what is needed. The audit flags an inbound `accept` policy as critical.

## Actions

A rule has one of three actions:

| Action | Effect |
|---|---|
| `accept` | Let the packet through. |
| `drop` | Discard it silently. |
| `reject` | Discard it and tell the sender. TCP rules answer with a TCP reset where the backend supports it. |

## Baseline options

The **Default policies and baseline** panel on the **Rules** page holds switches for rules almost every firewall needs. They run before your own rules.

| Option | Label | Default | What it does |
|---|---|---|---|
| `allowEstablished` | Established connections | on | Accept replies to traffic that was already allowed. |
| `allowLoopback` | Loopback | on | Accept traffic on `lo`. |
| `dropInvalid` | Drop invalid | on | Drop packets with no valid connection state. |
| `allowIcmp` | Essential ICMP | on | Accept ping, plus the ICMPv6 types IPv6 cannot work without (neighbour discovery, packet-too-big and errors). |
| `ipv6` | IPv6 | on | When off, all IPv6 traffic is blocked. |
| `forwarding` | Routing | off | The host forwards packets between interfaces. The nftables, iptables and ufw outputs switch on IP forwarding, and the sysctl drop-in sets it. |
| `logDropped` | Log dropped | off | Write a rate-limited kernel log line for packets dropped by a default policy. |

> [!NOTE]
> ufw and firewalld always accept loopback and established traffic and drop invalid packets. Switching those options off has no effect on those targets, and the compiler notes say so.

## How a packet is evaluated

In each direction, a packet meets these steps in order. The first step that decides stops evaluation.

1. **Loopback**: traffic on `lo` is accepted (if the option is on).
2. **IPv6 switched off**: any IPv6 packet is dropped (if the IPv6 option is off).
3. **Blocklists**: addresses on an enabled blocklist are dropped, even for established connections. Clients already banned by auto-ban are dropped here too.
4. **Established / related**: replies to allowed connections are accepted.
5. **Invalid state**: packets with no valid state are dropped (not on outbound).
6. **Essential ICMP**: ping and essential ICMPv6 are accepted (inbound, and outbound when the outbound policy is drop).
7. **Attack protection**: auto-ban trap ports, the port-scan filter and the SYN flood guard.
8. **Your rules**, top to bottom. The first rule that matches decides.
9. **Default policy** of the direction.

The **Packet flow** page draws the baseline steps, your rules and the default policy of each chain for the open project, and the [simulator](doc:simulator) shows every step for a given packet.

### Ordering rules

Rules are evaluated per direction, so only their order within a direction matters. To move a rule, use the **Move up** and **Move down** buttons or drag it onto another rule in the same direction.

A broad rule above a narrow one can hide it. The audit reports such rules as "can never match" (different action) or "redundant" (same action).

### Disabled rules

Each rule has an on/off switch. Disabled rules stay in the project but are left out of every generated ruleset, the simulator and the audit's other checks.

## Destination NAT comes first

Port forwards (destination NAT) are applied before filtering. A new inbound packet that matches a port forward is rewritten to the internal address and then filtered as **forwarded** traffic, so it needs a forward rule that accepts it. The audit reports port forwards without one. See [NAT](doc:nat).

## The target is separate from the design

The project does not say which tool or version it runs on. You choose the target in the top bar, on the **Build** page, per host in a [fleet](doc:fleet), or on the command line. The same project can be built for any supported target; see [Targets and versions](doc:targets-and-versions).
