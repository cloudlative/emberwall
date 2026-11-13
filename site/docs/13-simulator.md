---
title: Packet simulator and packet flow
description: Send a test packet through the Emberwall ruleset, read the step-by-step trace, use presets, save results as policy tests, and see where each rule sits on the Packet flow page.
section: Verify
---

The packet simulator answers "what happens to this packet?" before anything touches a server. Describe a packet, and Emberwall shows the verdict, the rule that decided it, and every check the packet passed on the way.

![Packet simulator](shot:simulator)

## Simulate a packet

1. Open **Simulator** in the sidebar (under *Verify*).
2. Pick a preset, or fill in the packet:

| Field | Values |
|---|---|
| **Direction** | Inbound, Outbound, Forwarded |
| **Source address** | an IPv4 or IPv6 address |
| **Destination address** | an address of the same family |
| **Protocol** | TCP, UDP, ICMP |
| **Destination port** | for TCP and UDP |
| **ICMP type** | for ICMP |
| **Arrives on interface** | for example `eth0` (inbound and forwarded) |
| **Leaves on interface** | for example `eth0` (outbound and forwarded) |
| **Connection state** | New, Established, Related, Invalid |

The result updates live as you type. It shows whether the packet is accepted or blocked, and by what: a rule, a baseline option, a blocklist or the default policy.

If the source or destination is not a valid address, or the two are of different families, the result says **Cannot simulate** and why.

### Presets

| Preset | Packet |
|---|---|
| HTTPS from internet | inbound TCP to port 443, new connection |
| SSH from internet | inbound TCP to port 22, new connection |
| SSH over IPv6 | inbound TCP to port 22 over IPv6 |
| Ping | inbound ICMP |
| DNS lookup out | outbound UDP to port 53 |
| Reply traffic | inbound UDP that belongs to an established connection |

## Read the trace

The **Trace** panel lists every check the packet went through, in order, with the reason each one did or did not match. For example: "port 22 not in 80, 443" or "matches; each client may send 10/minute, faster clients are dropped".

The order is the one described in [Concepts](doc:concepts#how-a-packet-is-evaluated): loopback, IPv6 switch, blocklists, established/related, invalid state, essential ICMP, auto-ban trap ports, then your rules and finally the default policy.

When a rule decides, **Show rule** opens it in the editor.

### Port forwards

A new inbound or forwarded packet that matches a port forward is rewritten first. The trace shows the NAT step ("destination rewritten to 192.168.1.10:443; packet is now forwarded") and the packet continues as forwarded traffic.

## What the simulator assumes

The simulator models the ruleset, not a running kernel. Some matches cannot be decided from a single packet description:

- **Source ports** are not part of the form, so source-port matches are assumed to hold.
- **Schedules, connection limits and MAC matches** are assumed to hold; the trace mentions them as caveats ("only Mon/Tue 08:00-18:00", "at most 20 connections per client", "only from MAC ...").
- **Packet marks:** a simulated packet carries no mark, so rules that match a mark never match.
- **Shared rate limits:** the matching rule accepts, and the result notes that traffic over the limit falls through to the next rule.
- **Blocklists:** only the entries stored in the project are checked, not downloaded ones.
- **SYN flood guard and port-scan filter** are not simulated. Auto-ban trap ports are.

## Save as a policy test

Press **Save as test** to keep the packet and its current verdict as a [policy test](doc:policy-tests). The test name describes the packet, for example "TCP 22 from 198.51.100.20 is blocked". From then on, any change that alters this verdict makes the test fail.

## Packet flow

The **Packet flow** page shows where each rule sits on a packet's way through the kernel. It reads left to right and top to bottom:

1. **Packet arrives** from the network.
2. **Prerouting (destination NAT):** your port forwards.
3. **Routing decision:** for this host, or forwarded (when **Routing** is on).
4. Three chains side by side: **Inbound** (`input`, to local services), **Forward** (`forward`, routed through) and **Outbound** (`output`, from local services). Each lists the baseline steps that apply, your rules in order, and the default policy.
5. **Postrouting (source NAT):** masquerade and source NAT rules.
6. **Packet leaves** to the network.

Within a chain, the first match wins. Click a rule or NAT entry to open it.

![Packet flow page](shot:flow)
