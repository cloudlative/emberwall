---
title: Fleet
description: Manage many hosts with one Emberwall policy - shared and host-scoped rules, per-host overrides, a per-host build for each tool and version, and an Ansible inventory and playbook.
section: Operate
---

A fleet is one policy for many machines. Every host gets the shared rules plus the rules scoped to it, compiled for its own firewall tool and version. Without hosts, Emberwall builds a single ruleset for the target in the top bar.

![Fleet page](shot:fleet)

## Add hosts

1. Open **Fleet** in the sidebar (under *Operate*).
2. Press **Host**. New hosts are named `host-1`, `host-2`, ... and start on Ubuntu 24.04 with nftables.
3. For each host, set:
   - **Host name**;
   - **Address**, an IP address or DNS name used in the Ansible inventory;
   - **Distribution**;
   - **Firewall tool**. Only the tools the distribution packages are offered, with the version it ships.

Each host row shows its rule count, its audit score and grade, how many things are adapted for its target, and any errors.

The overview at the top shows the number of **Hosts**, **Shared rules** (and how many are scoped to specific hosts), the **Lowest score**, and **Hosts with fallbacks**.

## Scope rules to hosts

By default a rule applies to every host. To limit it:

1. Open the rule in the editor.
2. Open **Advanced matches**.
3. Under **Hosts**, select the hosts it applies to. Leave all unselected to apply it everywhere.

Deleting a host removes it from every rule's host list.

## Overrides

Hosts share the project's objects, zones, NAT, blocklists and protections. Per host you can change three things. Press **Overrides** on a host to open them; a badge counts how many are set.

| Override | What it does |
|---|---|
| **Default policies** | Set a different inbound, outbound or forward policy for this host. |
| **Options** | Set any baseline option (*Allow loopback*, *Allow established*, *Drop invalid*, *Allow ping / ICMPv6*, *Log dropped*, *IPv6*, *Forwarding*) on or off for this host. |
| **Shared rules on this host** | Leave a shared rule out on this host. |

Anything not overridden follows the shared policy.

## See one host's view

Use the host selector in the top bar: **All hosts (shared policy)** or **Host: <name>**. With a host selected, the rules, output, audit and simulator show that host's view and target. On the Rules page, rules that do not apply to the host are dimmed.

**Open** on a host row selects it and goes to the **Build** page.

## Download and roll out

### Per host

The download button on a host row saves that host's main file, named `<host>-<file>`, for example `web-1-emberwall.nft`.

### Fleet bundle

**Download fleet bundle** saves `emberwall-fleet.sh`, a shell archive. Run it in an empty directory to unpack:

```sh
sh emberwall-fleet.sh
```

It unpacks this layout:

```text
hosts/
  <host-name>/
    <every generated file for that host>
inventory.ini
fleet-playbook.yml
```

Host directory names are the host names in lower case with other characters replaced by `-`.

### Ansible

`inventory.ini` lists every host in an `[emberwall]` group, with `ansible_host` set to the host's address (or its name, if it has no address) and `emberwall_tool` set to its firewall tool.

`fleet-playbook.yml` runs on the `emberwall` group, one host at a time (`serial: 1`), with `become: true`. For each host it copies `hosts/<inventory name>/` to `/etc/emberwall/` (mode 0600) and, if anything changed, loads the firewall with the command for that host's tool.

Roll out to one host first:

```sh
ansible-playbook -i inventory.ini fleet-playbook.yml --limit one-host
```

You can also download `inventory.ini` and `fleet-playbook.yml` on their own from the **Rolling it out** panel.

> [!WARNING]
> The fleet playbook has no automatic rollback. Roll out to one host first with `--limit`, and keep console access.

## Fleet on the command line

```sh
emberwall fleet project.json --out fleet/
```

This prints one line per host with its target, rule count, score, and an `ERRORS` count if its build has errors. With `--out`, it writes the same layout as the bundle (`hosts/<name>/...`, `inventory.ini`, `fleet-playbook.yml`) directly into the directory. It exits with status 1 if any host's build has errors, and with status 2 if the project has no hosts. See [CLI](doc:cli).

## Host targets in the project file

In the UI, a host's target is a distribution preset. In the [project file](doc:project-format), a host's `target` can also use `"distro": "custom"` with a specific `tool` and `version`.
