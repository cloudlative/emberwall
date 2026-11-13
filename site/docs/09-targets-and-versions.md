---
title: Targets and versions
description: How Emberwall adapts output to a distribution and tool version, which features need which versions, how fallbacks are reported, and how to use the Version matrix and strict mode.
section: Ship
---

The same project can be built for nftables, iptables, ufw or firewalld, at the version your server actually runs. Emberwall uses newer syntax where the version has it and a working fallback where it does not, and tells you which it chose.

## Pick a target

The target picker appears in the top bar and on the **Build** page. It has three parts:

1. **Target system:** a distribution preset, or **Custom tool version…**.
2. **Tool:** nftables, iptables, ufw or firewalld. Only the tools the distribution packages are offered.
3. **Version:** with a preset, a badge shows the version that distribution ships. With **Custom tool version…**, pick any known version from a list.

If you switch to a distribution that does not package the selected tool, Emberwall switches to that distribution's default firewall manager.

Every page that shows generated output, and the Dashboard, follows the selected target. In a [fleet](doc:fleet), each host has its own target.

You can also run **Target: ...** commands from the command palette (**Ctrl+K**).

## Supported distributions

Package versions were read from each distribution's package index. The default firewall manager is marked.

{{distros}}

Some presets force a feature off regardless of the tool version, because the distribution's kernel is too old:

- **RHEL / Alma / Rocky 9** (kernel 5.14): `destroy table` is off; it needs kernel 6.3.
- **RHEL / Alma / Rocky 8** (kernel 4.18): NAT in the `inet` family is off; it needs kernel 5.2.

Other notes from the presets:

- **RHEL / Alma / Rocky 10:** iptables is shipped as iptables-nft only and is no longer maintained by Red Hat.
- **Arch Linux (rolling):** versions shown are a recent snapshot.

Distribution versions are a snapshot; rolling releases move. If your version differs, use **Custom tool version…**.

## Version-dependent features

Capabilities are data, not scattered conditions in the compilers. Each entry names the first version that has the feature, the kernel it needs where relevant, and what Emberwall emits without it.

{{capabilities}}

Some of these depend on both the tool and the kernel. For example, nftables NAT in the `inet` family needs nftables 0.9.1 **and** kernel 5.2.

## Known versions

These are the versions you can pick under **Custom tool version…** and with `<tool>@<version>` on the [CLI](doc:cli).

{{versions}}

## Compiler notes

Every build lists its notes under **Compiler notes** in the output panel. Each note has a level:

| Marker | Meaning |
|---|---|
| (info) | Something you should know, for example that iptables on this distribution is iptables-nft, or that a rate limit is shared by all clients. |
| **version fallback** | The feature is written differently for this version, or adapted to what the tool can do. |
| **not expressible** | The tool cannot express this at all. The part is left out, and the note says what was dropped. |
| **invalid** | The rule or NAT rule failed validation and is left out of the output. This is an error. |

Click a note that belongs to a rule to select that rule. When every rule maps cleanly, the panel says "Every rule maps cleanly onto this target."

The Dashboard shows the number of version fallbacks for the current target, and a **Build target** panel with each capability marked available or the version it needs.

## Version matrix page

Open **Version matrix** in the sidebar (under *Ship*) to see:

- a table per tool of every feature against every known version, with the minimum kernel where it matters;
- what each distribution ships, including which backend its `iptables` command uses (`nft` or `legacy`);
- the manual pages the emitted syntax was last checked against.

The current target's version is highlighted.

![Version matrix page](shot:versions)

## Strict mode

On the command line, `--strict` makes `emberwall build` exit with status 1 when the build has any version fallback or anything that could not be expressed. Use it in CI to make sure the output is the full ruleset, unchanged, for a given target:

```sh
emberwall build project.json --target nftables@1.0.9 --strict
```

A build with errors exits with status 1 with or without `--strict`. See [CLI](doc:cli).

## Comparing targets

To see what changes between two versions or two tools, use the **Compare** page. See [Build output](doc:build-output#compare-targets).
