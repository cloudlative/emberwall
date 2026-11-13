---
title: Introduction
description: What Emberwall is, how it differs from other firewall generators, and how a ruleset goes from design to a running server.
section: Getting started
---

Emberwall is a firewall builder for Linux. You describe your policy once, in one visual model, and Emberwall generates ready-to-apply output for **nftables, iptables, ufw and firewalld**, adapted to the exact tool version on the machine you deploy to. The app runs in your browser, and your rulesets are never uploaded.

![The Emberwall dashboard](shot:dashboard)

## Why it is different

Most online firewall generators turn a form into text for one tool. Emberwall keeps a single model of your policy and builds the tooling around it:

- **Version-aware output.** Pick a distribution (Ubuntu, Debian, RHEL/Alma/Rocky, CentOS 7, Alpine, Arch) or a specific tool version. The compiler uses newer syntax where the version supports it, uses a working fallback where it does not, and tells you which one it chose.
- **One ruleset, four backends.** The same project compiles to `nft -f` files, `iptables-restore` files (IPv4 and IPv6), ufw commands plus `before.rules` fragments, or a `firewall-cmd` script plus zone XML.
- **Checks before anything touches a server.** A packet simulator, a reachability matrix, policy tests, an audit with a 0–100 score, and compliance profiles all work on the same model.
- **Safe apply.** Every build includes a script that backs up the running rules, applies the new ones, and rolls back on its own unless you confirm. The rollback still happens if your SSH session drops.
- **More than Linux.** The same ruleset can also be written for pf, Windows Firewall, AWS / Azure / Google Cloud security groups (Terraform) and Kubernetes NetworkPolicy, each with a list of what does not carry over.

## How it works

A ruleset goes through four stages.

1. **Design.** Write rules on the **Rules** page, add NAT, reusable objects, zones, blocklists, attack protection and kernel hardening. See [Concepts](doc:concepts) for how the model works.
2. **Build.** Pick a target system in the top bar or on the **Build** page. Emberwall compiles the project for that tool and version and lists every adaptation in the compiler notes. See [Targets and versions](doc:targets-and-versions).
3. **Verify.** Send test packets through the [simulator](doc:simulator), check the [reachability matrix](doc:reachability-and-topology), save [policy tests](doc:policy-tests), and read the [audit](doc:audit-and-compliance).
4. **Apply.** Copy the files to the server and run `emberwall-apply.sh`, use the Ansible, Terraform or cloud-init export, or push from the browser in [server mode](doc:server-mode). See [Build output and safe apply](doc:build-output).

## Where things run

Emberwall comes in three forms. All of them use the same engine.

| Form | What runs where |
|---|---|
| Web app | Everything runs in your browser. Projects, snapshots and settings are kept in the browser's local storage. Works offline after the first visit. |
| `emberwall` binary | The command-line interface for CI (`build`, `fleet`, `audit`, `test`, `compliance`, `targets`), plus `emberwall serve` for server mode. |
| Server mode | An optional small server you run yourself. It adds sign-in with roles, a shared server inventory, team projects, an activity log, live reads of running firewalls over SSH, and guarded pushes. |

See [Install](doc:install) for each option.

## Privacy

In the web app, nothing you design leaves your browser:

- Rulesets, snapshots and settings are stored in your browser's local storage.
- Imports and log analysis are parsed in the page.
- Share links carry the project in the part of the URL after `#`, which browsers do not send to a server.

There is one opt-in exception: the [assistant](doc:assistant). It stays off until you enter your own Anthropic API key. When you press one of its buttons, your request and a summary of the project go from your browser to the Anthropic API, and the page shows exactly what is sent.

Server mode is different by design: projects you save for your team, the server inventory and the activity log are stored on the Emberwall server you run. See [Security](doc:security).

## Next steps

- [Quick start](doc:quick-start) walks through a first ruleset in a few minutes.
- [Install](doc:install) covers the web app, the binary and running from source.
