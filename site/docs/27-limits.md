---
title: Known limits
description: What Emberwall cannot do or only does partly - backend differences, zones on firewalld, the reachability model, importers, the live view, fleets, extra targets and server mode.
section: Reference
---

Emberwall tells you when it adapts or drops something, in the compiler notes, the **What carries over** panel, or the import report. This page collects the known limits in one place.

## Backends

- **Per-client rate limits, connection limits, schedules, MAC and mark matches and the attack protections** are native on nftables and iptables. ufw gets them through a `before.rules` fragment (its own `limit` has a fixed rate of 6 connections per 30 seconds per source). firewalld cannot express most of them and says so.
- **ufw:** ICMP rules and connection-state matches go to a `before.rules` fragment. ufw always accepts loopback and established traffic, drops invalid packets, and accepts ping by default; the matching options have no effect.
- **firewalld:** drops per-rule state matches, has no per-client limits, connection limits, schedules or packet marks in rich rules, and does not pass the rate-limit burst. Before firewalld 0.7.0 it orders rich rules itself (log, deny, allow), so rule order is not preserved. Its blocklists only block traffic *from* the listed addresses. It has no attack protection settings.
- **Blocklists** on iptables and ufw rely on `ipset`. Country lists are downloaded by your server from a third-party site that Emberwall does not check.
- **nftables:** older versions lose features listed in [Targets and versions](doc:targets-and-versions): connection limits before 0.9.1, schedules before 0.9.3, auto-ban before 0.9.7.
- **iptables-restore** replaces the whole filter and nat tables. Docker and Kubernetes need to re-create their chains afterwards.
- **Names:** rule and group names lose quote, backslash, backtick and `$` characters in generated output.

## Zones

Zones expand to interface and network matches. On firewalld, each zone with interfaces becomes a real firewalld zone (`ew-<name>`) with those interfaces bound, and so does any interface a rule names outside a zone. Forward and outbound rules go into zone-to-zone policies (firewalld 0.9+). If NetworkManager manages an interface, also set the zone on its connection.

## Simulator, reachability and semantic diff

- The reachability matrix and semantic diff cover IPv4 and IPv6 paths for the sources and services the rules mention. They are a model of the ruleset, not a scan of a live host.
- Each source and destination is represented by one address, and a port range by its first port. The matrix shows up to 16 sources and 24 services.
- The simulator assumes schedules, connection limits, MAC and source-port matches hold; treats packets as unmarked; checks only blocklist entries stored in the project; and does not model the SYN flood guard or port-scan filter.

## Importers

Importers cover the common rule shapes. Negated matches, custom chains, jumps, firewalld services outside a built-in list and other unusual constructs are listed as skipped, not guessed.

## Live servers

- The live view models one rule list per direction. Servers with several nftables tables, custom chains or jumps are only partly represented; every line that was not understood is listed.
- On a firewalld server, the live view reads the default zone only. Rules in other zones (such as the `ew-*` zones Emberwall creates for interfaces) and in policies are not imported, so they show up as drift.
- A server's own sysctl values are not read.
- A push replaces only what Emberwall manages. On nftables that is the `inet emberwall` table; other tables keep filtering.
- Pushing is refused for iptables and ufw builds with blocklists. Fragments, the sysctl file and blocklist units are never installed by a push.

## Fleets

Fleet hosts share objects and zones. Per host you can set the target, override the default policies and options, and leave shared rules out; anything else is shared.

## Extra targets

- Cloud security groups and Kubernetes NetworkPolicy are allow-only. Windows Firewall has no rule order (block beats allow). pf rate limits ban the client on all ports.
- Each difference is reported next to the output.
- Treat pf output as unverified until you run `pfctl -nf` on it.
- Extra targets are available in the web app only, not on the CLI.

## Compliance

Compliance profiles are Emberwall's reading of each framework's firewall-related intent. They support a review; they are not official benchmark content or a certification.

## Distributions

Distribution versions are a snapshot; rolling releases move. If your version differs, pick a custom version.

## Assistant

The assistant's API calls are type-checked against the official SDK and its output validation is unit-tested, but it has not been exercised against the live API in Emberwall's own tests.
