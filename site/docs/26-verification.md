---
title: How the output was checked
description: How Emberwall's generated rulesets, scripts, extra targets, importers, CLI and server mode are tested, which real tools validate them, and what has not been tested.
section: Reference
---

Generated firewall rules run as root on real machines, so Emberwall's output is checked by the real tools wherever possible. This page lists what the test suite covers, and what it does not.

## Rulesets

- `npm test` compiles every template and an edge-case project for every known tool version.
- When `iptables-restore`, `ip6tables-restore` and `nft` are installed, the tests feed the generated rulesets to `iptables-restore --test` and `nft -c -f` and require zero errors. These tests are skipped automatically where the binaries are missing or unusable.
- When firewalld's `firewall-offline-cmd` is installed, the tests run the generated firewalld script against it in a private configuration directory: every template plus the edge-case project, for firewalld 2.1.1, 0.9.3 and 0.8.2. They check that each zone gets its interfaces and that zone-to-zone policies are created.
- ufw commands were parsed with the upstream ufw parser during development.
- Every generated shell script passes `sh -n`. The IPv4 sysctl keys were checked against a running kernel.

## Blocklists

With root, `ipset` and network namespaces available, the iptables blocklist and the ufw `before.rules` fragment are loaded for real in a private network namespace. A ping from a listed address is dropped, and goes through once the address leaves the set. The generated updater refreshes the set from a downloaded list and keeps the project's own entries.

## Hostile input

Generated scripts are executed in tests with a deliberately hostile project, with shell metacharacters in every name and field, to confirm that nothing but firewall commands runs.

## Importers

Importer tests compile each template, import the result, and require that no access changes.

## Automation exports and fleet

- The generated Ansible playbooks pass `ansible-playbook --syntax-check`.
- The Terraform SSH-push file passes `terraform validate` and `terraform fmt -check` for every template and tool.
- The fleet playbook and inventory parse.

## Extra targets

- The Terraform output for AWS, Azure and Google Cloud passes `terraform fmt -check` and `terraform validate` with the `aws`, `azurerm` and `google` providers.
- The PowerShell output passes the PowerShell 7 parser and runs against stub cmdlets built from Microsoft's documented syntax.
- The NetworkPolicy YAML parses.

> [!WARNING]
> pf output has not been run through `pfctl`, because there is no pf on Linux. Nothing was applied to a real cloud account, Windows host or Kubernetes cluster.

## CLI

The CLI is covered by tests, and its nftables output was checked with `nft -c`.

## Web app

- Offline loading was tested in a browser with the network switched off.
- `npm run check:layout` checks every page at three sizes for overlapping cards and sideways scrolling, in a real browser.

## Server mode

- Server mode is tested end to end over real HTTP and real SSH (an in-process SSH server): sign-in, roles on every route, lock-out after wrong passwords, session expiry, credential encryption, host-key pinning and mismatch, and the fixed command list.
- Where the environment allows a private network namespace, the same tests read a real nftables ruleset and run the guarded push with real `nft`: confirming keeps the rules, no confirmation restores the old ones, and a ruleset that fails the check changes nothing.
- A browser run covers setup, users, adding a server, live read, audit, drift, push and confirm, and the viewer restrictions.

### Guarded push against real OpenSSH

An opt-in test (`tests/ssh-e2e.test.ts`, enabled with `EMBERWALL_E2E_SSH=1`, needs root) runs the guarded push for **nftables, iptables, ufw and firewalld** against the system's real OpenSSH server inside a private network namespace, so the SSH traffic itself crosses the firewall being pushed. For each tool:

- a ruleset that keeps SSH open is confirmed over a new connection and stays;
- a ruleset that shuts SSH out cannot be confirmed, and the server rolls itself back within the timeout, after which SSH works again.

It also applies the Terraform SSH-push export for real. CI runs it on GitHub's Ubuntu runners for all tools except firewalld, whose package would start a daemon on the runner.

## Manual pages

The emitted syntax was read against the current manual pages:

| Tool | Pages | Version |
|---|---|---|
| nftables | `nft(8)` | 1.1.6 |
| iptables | `iptables(8)`, `iptables-extensions(8)` | 1.8.11 |
| ufw | `ufw(8)` | 0.36.2 |
| firewalld | `firewall-cmd(1)`, `firewalld.richlanguage(5)`, `firewalld.policy(5)` | 2.3.1, plus the firewalld 2.5.2 source tree |

The minimum version of each capability was checked against the upstream commit that introduced it. See [Targets and versions](doc:targets-and-versions).

## What has not been tested

Nothing here has been applied to a live production host by the test suite, and nothing was tested against a remote production server.

> [!WARNING]
> Use the safe-apply script or guarded push, and keep console access the first time you load a ruleset on a remote machine.
