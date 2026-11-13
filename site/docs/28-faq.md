---
title: FAQ
description: Answers to common questions about Emberwall - privacy, lock-out, nftables versus iptables-nft, Docker and Kubernetes hosts, firewalld with NetworkManager, offline use and licensing.
section: Reference
---

## Does Emberwall upload my rules?

No, not in the web app. Everything runs in your browser: projects and snapshots stay in its local storage, and imports and logs are parsed in the page. Share links keep the project after the `#` in the URL, which browsers do not send to a server.

Two features send data, and only when you use them:

- The [assistant](doc:assistant), after you add your own Anthropic API key and press a button. The page shows exactly what is sent.
- [Server mode](doc:server-mode), which you run yourself. Projects you save for the team, the server inventory and the activity log are stored on that server.

## Can a ruleset lock me out?

It can, if it blocks the way you connect. Emberwall gives you several safety nets:

- The audit warns **No rule allows SSH (port 22)** when the inbound policy is drop and nothing accepts SSH.
- `emberwall-apply.sh` rolls back automatically unless you type `yes` within the timeout, and its watchdog still runs if your SSH session drops. See [Build output and safe apply](doc:build-output).
- A [guarded push](doc:live-servers#guarded-push) is only kept if Emberwall can open a *new* SSH connection after applying; otherwise the target rolls back on its own.

The Ansible, Terraform, cloud-init and fleet exports have no rollback. Test them on one host first, and keep console access the first time you load a ruleset on a remote machine.

## Should I choose nftables or iptables?

Pick what your distribution uses. The setup wizard and the distribution presets select each distribution's default firewall manager, and `emberwall targets` marks it with `*`.

On most current distributions the `iptables` command is **iptables-nft**: it uses the kernel's nftables backend, and rules loaded with it show up in `nft list ruleset`. Emberwall's iptables files work with both iptables-nft and iptables-legacy, and the compiler notes tell you which backend the selected distribution uses. On RHEL / Alma / Rocky 10, iptables is shipped as iptables-nft only and is no longer maintained by Red Hat.

To move from iptables to nftables, see [Import and migration](doc:import#migrate-from-iptables-to-nftables).

## Can I use Emberwall on a Docker or Kubernetes host?

Yes, with care. The *Docker host* and *Kubernetes node* templates are starting points.

- **iptables target:** `iptables-restore` replaces the whole filter and nat tables, which removes the chains Docker or Kubernetes created. Restart the daemon afterwards so it re-creates them. The compiler notes say this on every iptables build.
- **nftables target:** Emberwall owns only the `inet emberwall` table and leaves every other table alone, so other tables keep their rules. A packet must be accepted by every table that filters it, so container traffic that is forwarded through the host also needs to be allowed by Emberwall's forward chain. The Docker template includes forward rules for the container network and a masquerade rule for container egress.
- **Kubernetes:** CNI plugins manage their own rules next to Emberwall's.

## Does it work with firewalld and NetworkManager?

Yes. On firewalld, each zone with interfaces becomes a firewalld zone named `ew-<name>` with those interfaces bound. If NetworkManager manages an interface, also set the zone on its connection, or it may move the interface back:

```sh
nmcli connection modify <name> connection.zone <zone>
```

The compiler notes list which interface goes to which zone.

## Will it keep my existing ufw rules?

No. The generated `emberwall-ufw.sh` rebuilds the ufw rule set from scratch, starting with `ufw --force reset`. Import your current rules first if you want to keep them: paste the output of `ufw show added` or `ufw status` into **Import / export**.

## Do the rules survive a reboot?

ufw and firewalld keep them on their own. For nftables and iptables, follow the commands at the end of `emberwall-apply.sh`, which are specific to your distribution. See [Making the rules permanent](doc:build-output#making-the-rules-permanent).

## Does it handle IPv6?

Yes. Rules apply to IPv4 and IPv6 by default, essential ICMPv6 is allowed by the baseline, and NAT, the simulator, the reachability matrix and the semantic diff all cover IPv6. If you switch the **IPv6** option off, all IPv6 traffic except loopback is blocked.

## Does it work offline?

Yes. After the first visit, the web app opens without a network, and you can install it as an app. The assistant and server mode need a connection. The `emberwall` binary needs no network for building, auditing or testing.

## Can I use it on macOS or Windows?

You can design firewalls in the web app on any system with a modern browser, and the `emberwall` binary runs on Linux, macOS and Windows. The rulesets themselves are for the targets you build for: Linux (nftables, iptables, ufw, firewalld), plus pf, Windows Firewall, cloud security groups and Kubernetes on the [More targets](doc:more-targets) page.

## How do I run checks in CI?

Export the project as JSON, commit it, and run `emberwall test`, `emberwall audit --min-score`, `emberwall compliance --min` and `emberwall build --strict` in your pipeline. Each exits with status 1 when a check fails. See [CLI](doc:cli#ci-examples).

## Is a passing compliance profile a certification?

No. The profiles are Emberwall's reading of each framework's firewall-related intent. They support a review; they are not official benchmark content or a certification.

## What does it cost, and what is the license?

Emberwall is free and open source under the MIT License. The source is on GitHub at `cloudlative/emberwall`.

## Where do I report a bug?

Open an issue in the GitHub repository `cloudlative/emberwall`. Leave out credentials, keys and real server addresses.
