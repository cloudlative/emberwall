---
title: Reachability and topology
description: See who can reach what with the Emberwall reachability matrix, and view the allowed flows between sources, the firewall and the networks behind it on the topology diagram.
section: Verify
---

The reachability matrix and the topology diagram answer "who can reach what?" for the whole ruleset at once. Both are computed by sending representative packets through the [simulator](doc:simulator).

## Reachability matrix

Open **Reachability** in the sidebar (under *Verify*).

![Reachability matrix](shot:reach)

Every cell is a new connection from a source to a destination on a service, sent through the simulator. Green cells are accepted; the others are dropped or rejected. Hover over a cell to see what decided it, and click an open or blocked cell to open the rule behind it.

The header counts the **Paths checked**, how many are **Open** and **Blocked**, and the number of **Destinations**. Switch between **IPv4** and **IPv6** at the top. If IPv6 is switched off in the project, every IPv6 path is blocked, and the page says so.

### What the axes contain

The axes are built from the project:

- **Sources:** the Internet, your zones, your address groups, interfaces that rules name outside a zone ("Via eth1"), and addresses named in rules.
- **Destinations:** *This host* (services on the firewall itself, inbound) and each zone (traffic forwarded into it).
- **Services:** the ports your inbound and forward rules mention, the ports of port forwards, *Ping* if a rule matches ICMP, and always *SSH 22/tcp*.

Each source and destination is represented by one address: the first address of a zone's networks or a group's members, for example. A port range is represented by its first port. The matrix shows up to 16 sources and 24 services.

The first zone with trust *Outside* is where Internet traffic arrives: its first interface is used as the inbound interface for Internet packets. See [Zones](doc:objects-and-zones#zones).

> [!NOTE]
> The matrix is a model of the ruleset, not a scan of a live host. It covers IPv4 and IPv6 paths for the sources and services the rules mention.

## Topology

The **Topology** page draws the same information as a diagram: sources on the left, this firewall in the middle, and the networks behind it on the right.

![Topology diagram](shot:topology)

- A **solid line** means at least one service is allowed on that path.
- Click a line to see which services are allowed ("3 of 8 services allowed") and which are not.

If nothing is allowed through yet, the page says so.

## Semantic diff

The same engine powers the semantic diff between two versions of a project: instead of listing changed lines, it lists which access **opened** (was blocked, now accepted) and which **closed**, for IPv4 and IPv6. You find it in two places:

- **Snapshots:** **Diff with current** shows "What changed for traffic" between a snapshot and the current project. See [Workspace](doc:workspace#snapshots-and-semantic-diff).
- **Live server:** "Access that differs" compares a running server with the project. See [Live servers](doc:live-servers#drift).
