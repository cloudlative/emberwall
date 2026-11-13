---
title: Rules
description: Every field of an Emberwall rule, including advanced matches, rate and connection limits, schedules and logging, and how input is validated.
section: Design
---

Rules decide what the firewall accepts, drops or rejects. You manage them on the **Rules** page, which lists rules per direction in the order they are evaluated, next to the generated output for the current target.

![Rules page with live output](shot:rules)

## Working with rules

- **Add a rule:** press **Add rule**, fill in the editor and press **Add rule** again. You can also choose **Add rule** in the command palette (**Ctrl+K**).
- **Edit:** click the rule, or use its **Edit** button. Press **Save changes** when done.
- **Reorder:** use **Move up** / **Move down**, or drag the rule onto another rule in the same direction. Order matters: the first match decides.
- **Duplicate:** creates a copy named "<name> (copy)".
- **Enable or disable:** the switch at the start of each row. Disabled rules are kept but left out of the output.
- **Delete:** the **Delete** button. Undo (**Ctrl+Z**) brings it back.

Badges on a row show at a glance whether a rule is logged, rate-limited, connection-limited or scheduled.

Selecting a rule highlights the lines it produced in the output panel. Clicking a line in the output selects the rule that produced it. See [Build output](doc:build-output#line-linking).

## Basic fields

| Field | Values | Meaning |
|---|---|---|
| **Name** | free text | What the rule is for. Used in comments and log prefixes in the output. |
| **Direction** | Inbound, Outbound, Forward | Which traffic the rule applies to. See [Concepts](doc:concepts#directions). |
| **Action** | Accept, Drop, Reject | What happens to a matching packet. |
| **Protocol** | TCP, UDP, TCP + UDP, ICMP / ICMPv6, Any protocol | The protocol to match. |
| **Address family** | IPv4 + IPv6, IPv4, IPv6 | Which IP versions the rule covers. |
| **Destination ports** | `22`, `443`, `8000:8100`, or a port group | Shown for TCP, UDP and TCP + UDP. Empty means every port. |
| **ICMP type** | Every type, `echo-request`, `echo-reply`, `destination-unreachable`, `time-exceeded`, `parameter-problem` | Shown for ICMP. |
| **Source** | addresses, CIDRs or address groups | Empty means anywhere. |
| **Destination** | addresses, CIDRs or address groups | Empty means any address. |
| **Inbound interface** | for example `eth0` | Shown for inbound and forward rules. Empty means any. |
| **Outbound interface** | for example `eth0` | Shown for outbound and forward rules. Empty means any. |
| **Connection state** | new, established, related, invalid | Leave empty to match every state. |
| **Log matches** | on / off | Write a kernel log line for every match. |
| **Rate limit** | rate, per second/minute/hour, burst, per client | See [Rate limits](#rate-limits). |

Ports and addresses are entered as tags. Type a value and confirm it; invalid values are refused. Ranges can be written `8000:8100` or `8000-8100`.

An address list can mix IPv4 and IPv6. With **IPv4 + IPv6**, the IPv4 addresses produce IPv4 rules and the IPv6 addresses produce IPv6 rules. If a rule names addresses of only one family, it does not apply to the other.

To use an address or port group, pick it from the suggestions. See [Objects and zones](doc:objects-and-zones).

## Rate limits

Switch on **Rate limit** to accept matching traffic only up to a rate. The defaults are 10 per minute with a burst of 20.

There are two kinds:

| Setting | Behaviour |
|---|---|
| **Per client** off | One shared limit for all clients of the rule. Packets over the limit are not accepted by this rule; they fall through to the next rules and, if nothing else matches, the default policy. |
| **Per client** on | Each client address is counted separately. Clients over the rate are dropped by this rule. |

Rate limits only apply to accept rules.

How each backend expresses them:

- **nftables:** `limit rate` for a shared limit; a per-client set (or the older `meter` syntax before nftables 0.9.7) for per-client limits.
- **iptables:** `-m limit` for a shared limit, `-m hashlimit` per client.
- **ufw:** uses its own `limit` action, which is fixed at 6 connections per 30 seconds per source, and only for inbound TCP/UDP rules. Your configured rate is not used, and the compiler notes say so.
- **firewalld:** limits are shared by all clients; the per-client setting and the burst value are not applied.

## Advanced matches

Press **Advanced matches** in the editor to show these fields. The section opens by itself when a rule already uses one of them.

| Field | Shown when | Meaning |
|---|---|---|
| **Source zone** | the project has zones; inbound or forward rule | Match traffic from a zone's interfaces and networks. |
| **Destination zone** | the project has zones; outbound or forward rule | Match traffic to a zone. |
| **Source ports** | TCP or UDP | Match the sender's port. Rarely needed: replies usually match by connection state. |
| **Connections per client** | always | Clients holding more concurrent connections than this are rejected. Empty means no limit. |
| **Source MAC address** | inbound or forward rule | Format `aa:bb:cc:dd:ee:ff`. |
| **Hosts** | the project has fleet hosts | Limit the rule to some hosts. Leave all unselected to apply it to every host. See [Fleet](doc:fleet). |
| **Packet mark** | always | Match a packet mark, for example `0x1`. |
| **Schedule** | always | Make the rule active only in a weekly time window. |

### Connection limits

**Connections per client** applies to accept rules. A client over the limit is refused before the rule accepts: TCP connections get a reset, other protocols are dropped. nftables needs version 0.9.1 or newer (`ct count`); on older versions the limit is left out and reported. firewalld has no per-client connection limit.

### Schedules

Switch on **Schedule** to pick weekdays and a time window (**From** and **To**, `HH:MM`). The default is Monday to Friday, 08:00 to 18:00. With no days selected, the window applies every day.

The time is the firewall host's kernel clock, which is UTC unless the host configures otherwise. nftables needs version 0.9.3 or newer (`meta hour` / `meta day`); on older versions the rule is active at all times and the compiler notes say so. firewalld has no time-based rules.

### Interface names

Interface names follow the Linux rules: up to 15 letters, digits, `_`, `.` or `-`, optionally followed by `+`. A trailing `+` is a wildcard: `wg+` matches every interface whose name starts with `wg`, in the simulator and in the output.

| Target | How `wg+` is written |
|---|---|
| iptables, ufw | `wg+` (the iptables wildcard; ufw passes it through) |
| nftables | `"wg*"` (nftables' own wildcard). Importing an nftables ruleset turns `"wg*"` back into `wg+`. |
| firewalld | `wg+`, with a warning: whether firewalld binds a zone to a wildcard name depends on its version and backend and has not been verified. List the interfaces one by one if the zone does not take effect. |
| pf | A macro you set to an interface group; pf has no prefix wildcards. |

## Logging

With **Log matches** on, each match writes a kernel log line with a prefix of the form `ew-<rule-name>: `. You can paste these lines into the [log analyzer](doc:log-analyzer).

To log packets dropped by a default policy, turn on **Log dropped** in the baseline panel. That adds a rate-limited log rule (5 per minute, burst 10) with the prefix `ew-drop-in: `, `ew-drop-out: ` or `ew-drop-forward: ` to each direction whose policy is drop.

## Comments

A rule can carry a `comment` field in the [project file](doc:project-format). The rule editor does not show it. Comments are kept through imports and appear in the pf and Windows Firewall outputs; the Linux outputs use the rule name as their comment.

## What each backend can express

Some matches cannot be written for every tool. Emberwall never changes a rule silently: anything it adapts or leaves out is listed in the **Compiler notes**, marked *version fallback*, *not expressible* or *invalid*.

In short:

- **nftables and iptables** express every field natively, subject to the version notes above.
- **ufw** sends rules with connection limits, schedules, MAC or mark matches, ICMP rules and state matches to a `before.rules` fragment, because its command line cannot express them.
- **firewalld** cannot express connection state matches, per-client limits, connection limits, schedules or packet marks in rich rules; those parts are left out and reported.

See [Known limits](doc:limits) for the full list.

## Validation and input hardening

Generated files run as root on real machines, so every build first checks the project. This happens in the browser, on the command line and in server mode alike.

- **Names and comments** are cut to one line. Quote, backslash, backtick and `$` characters and control characters are removed, and names are limited to 120 characters.
- **Interfaces, MAC addresses, packet marks, schedules, ICMP types and connection states** must match strict formats.
- **Rate, burst and connection limits** must be whole numbers from 1 to 1,000,000.
- **Ports** must be 1 to 65535, written as a single port or a range.
- **Addresses** must be valid IPv4 or IPv6 addresses or CIDRs, or a reference to an existing group.

A rule that fails a check is reported as an **error** and left out of the output; the rest of the project still builds. The audit lists the same problems as "Rule ... has a problem".

> [!NOTE]
> A build with errors exits with status 1 on the [CLI](doc:cli), and [guarded push](doc:live-servers) refuses it.
