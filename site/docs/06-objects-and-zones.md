---
title: Objects and zones
description: Reuse addresses and ports with address and port groups, and name the sides of a firewall with zones such as WAN, LAN, DMZ and VPN.
section: Design
---

Objects and zones let you name things once and refer to them from many rules. Change the group or zone, and every rule that uses it follows.

## Address groups

An address group is a named list of IPv4 and IPv6 addresses and CIDRs, for example an "Admin networks" group used by every management rule.

To create one:

1. Open **Objects** in the sidebar.
2. Under **Address groups**, press **Group**.
3. Enter a **Group name** and add members such as `10.0.0.0/8` or `2001:db8::/32`.

Use it in a rule by picking it from the suggestions in **Source** or **Destination**. Each group shows how many rules use it.

![Objects page](shot:objects)

Members are expanded into the rules when the project is built; duplicates are removed.

### Named sets in nftables

On nftables, when a rule's source or destination is exactly one address group, the group becomes a named set in the output (for example `set admin_networks_v4`), with one set per address family. Other backends write the addresses into the rules.

## Port groups

A port group is a named list of ports and ranges, for example "Web" = `80`, `443`, `8080`.

To create one, press **Group** under **Port groups** on the **Objects** page, name it and add ports such as `80`, `443` or `8000:8100`. Use it in a rule's **Destination ports** field.

## Deleting a group

Press **Delete group**. Emberwall removes the reference from the rules that used it.

> [!WARNING]
> If the group was the only entry in a rule's source, destination or ports, that field becomes empty, which means *any*. Check those rules, or run the audit, after deleting a group.

## Zones

Zones name each side of the firewall once, such as WAN, LAN, DMZ or VPN. Rules can then say "from LAN to WAN" instead of repeating interfaces and networks.

A single server does not need zones. They pay off on routers, gateways and hosts with more than one network.

![Zones page](shot:zones)

### Create zones

Open **Zones** in the sidebar.

- **Add WAN + LAN** creates two zones in one step: *WAN* on `eth0` (Outside), and *LAN* on `eth1` with the network `192.168.1.0/24` (Trusted). Adjust them to your interfaces.
- **Zone** adds an empty zone.

Each zone has:

| Field | Meaning |
|---|---|
| Name | Shown in rules and in the reachability matrix. |
| Trust | *Outside*, *DMZ* or *Trusted*. |
| Interfaces | One or more interface names, for example `eth0, wg0`. |
| Networks behind this zone | Optional CIDRs, for example `192.168.1.0/24`. |

### Use zones in rules

In the rule editor, open **Advanced matches** and set **Source zone** (inbound and forward rules) or **Destination zone** (outbound and forward rules).

When the project is built, a zone expands to concrete matches:

- its **interfaces** become the inbound or outbound interface match. A zone with several interfaces produces one rule per interface;
- its **networks** are added to the rule's source or destination addresses.

If the rule already names an interface, that interface is kept.

### What trust does

The trust level does not change the generated rules. It is used by the [reachability matrix and topology](doc:reachability-and-topology): the first *Outside* zone is treated as the Internet side, and its first interface is where Internet traffic arrives.

### Zones on firewalld

On firewalld, each zone with interfaces becomes a real firewalld zone named `ew-<name>` with those interfaces bound to it. Any interface a rule names outside a zone gets its own zone too. Other interfaces use the `emberwall` default zone. Forward and outbound rules go into zone-to-zone policies, which need firewalld 0.9 or newer.

> [!NOTE]
> If NetworkManager manages an interface, also set the zone on its connection, or NetworkManager may move the interface back:
>
> ```sh
> nmcli connection modify <name> connection.zone <zone>
> ```

The compiler notes list which interface is bound to which zone.
