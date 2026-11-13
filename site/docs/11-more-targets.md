---
title: More targets
description: Build the same Emberwall ruleset for pf (OpenBSD and FreeBSD), Windows Firewall, AWS, Azure and Google Cloud security groups via Terraform, and Kubernetes NetworkPolicy, and see what does not carry over.
section: Ship
---

The **More targets** page builds the same ruleset for platforms beyond the four Linux tools. These platforms filter differently from Linux, so each output comes with a **What carries over** panel. Anything that does not carry over is listed there, never dropped silently.

![More targets page](shot:targets)

## Using the page

1. Open **More targets** in the sidebar (under *Ship*).
2. Pick a target from the list on the left.
3. Copy or download the file. The path shown above the code is where it normally goes.
4. Read **What carries over**. Its header says how many things this platform cannot express.

As on the Build page, clicking a line selects the rule that produced it, and clicking a note selects its rule.

These targets are available in the web app. They are not part of the version matrix, and the CLI's `build` command covers the Linux tools only.

## The targets

{{extra-targets}}

The generated files are:

- pf (OpenBSD and FreeBSD): `pf.conf`, for `/etc/pf.conf`;
- Windows Firewall: `emberwall-windows.ps1`, for `C:\ProgramData\Emberwall\`;
- AWS, Azure and Google Cloud: `emberwall-aws.tf`, `emberwall-azure.tf` and `emberwall-gcp.tf`;
- Kubernetes: `emberwall-<project-name>.yaml`.

## What generally does not carry over

These rule features are Linux-specific or have no equivalent on most of the extra targets. Where a whole rule cannot be expressed, it is left out and listed; where only part of it cannot, the rule is emitted without that part and the note says so in capitals ("emitted WITHOUT the limit").

- **Packet marks, MAC address matches and schedules:** not supported on any extra target.
- **Forward rules:** Windows Firewall, the cloud security groups and NetworkPolicy have no forwarding.
- **NAT:** only pf translates addresses. The others list NAT rules as not expressible.
- **Attack protection** (SYN flood guard, port-scan filter, auto-ban): not available on Windows, cloud or Kubernetes. pf expresses the port-scan filter but not the other two.
- **Rate and connection limits:** Windows, the cloud groups and NetworkPolicy have none. pf has per-client TCP limits only.
- **Rules that only accept established/related traffic** are left out everywhere: every one of these platforms is stateful and allows replies by itself.
- **The baseline options** for loopback, established and invalid traffic need no rules on these platforms.

## pf (OpenBSD and FreeBSD)

> [!WARNING]
> pf output has not been run through `pfctl` in Emberwall's tests, because there is no pf on Linux. Treat it as unverified until you check it on the target host.

To load it on the BSD host:

```sh
pfctl -nf /etc/pf.conf   # check only
pfctl -f /etc/pf.conf    # load
pfctl -e                 # enable pf
```

Things to know:

- pf normally applies the *last* matching rule. Every generated rule uses `quick`, so the first match decides, as in Emberwall.
- Interface names are macros at the top of `pf.conf`, filled with the names from the project. BSD interfaces are named differently (`em0`, `vtnet0`, ...), so edit them before loading.
- Per-client limits ban the client on **all ports**: a client over the limit is added to the `<bruteforce>` table and blocked until removed. Expire entries from cron, for example `pfctl -t bruteforce -T expire 3600`.
- Logged packets go to the `pflog0` interface in pcap format, not to syslog.
- On a routing host, forwarding must be enabled outside `pf.conf` (`sysctl` on OpenBSD, `gateway_enable` in `/etc/rc.conf` on FreeBSD); the notes give the exact setting.
- Loopback is filtered like any other interface unless the baseline loopback option is on.

## Windows Firewall

Run the script from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\emberwall-windows.ps1
```

It targets the PowerShell NetSecurity module (Windows 8 / Server 2012 or later).

- **No rule order:** a matching Block rule always wins over a matching Allow rule, and the default action applies only when nothing matches. The notes flag block rules that would also block traffic an earlier allow rule accepts in Emberwall.
- **Reject** becomes Block, which drops silently.
- The script first removes every rule in the `Emberwall` group, then creates them again, so it is safe to run more than once. Rules outside that group, including the built-in Windows rules, are left alone and still apply.
- Interface names come from the project; Windows names differ (see `Get-NetAdapter`). Edit them before running.
- Logging is per profile, not per rule.
- If IPv6 is switched off in the project, the rules are pinned to IPv4, but Windows keeps filtering IPv6 with the same default actions.

## AWS, Azure and Google Cloud (Terraform)

Each cloud target is a Terraform file. Run `terraform init` and `terraform plan` as usual.

| Provider | Variables | Rule order |
|---|---|---|
| AWS | `vpc_id`, `name` | None. Security groups are **allow-only**: there are no drop or reject rules. |
| Azure | `resource_group_name`, `location`, `name` | By priority from 100 in steps of 10, which keeps the Emberwall order. The default policies become explicit rules at 4095 (inbound) and 4096 (outbound). |
| Google Cloud | `network`, `name_prefix`, `target_tags` | By priority from 1000 in steps of 10. Rules for both address families are emitted twice with the same priority. |

Notes per provider:

- **AWS:** one security group rule is emitted per CIDR block, protocol and port range. The notes warn when the count passes the default quota of 60 inbound and 60 outbound rules. Security groups cannot log; use VPC Flow Logs.
- **Azure:** the file declares no provider block. Add `provider "azurerm" { features {} }` in your root module and attach the group to a subnet or network interface. With an inbound drop policy, load balancer health probes need their own allow rule. NSG rules cannot select ICMP types.
- **Google Cloud:** the rules apply to every instance in the network unless `target_tags` is set. An inbound drop and outbound accept policy are the network's implied rules, so nothing is emitted for them. Rules cannot select ICMP types.

Nothing in these files has been applied to a real cloud account by Emberwall's tests. They pass `terraform fmt -check` and `terraform validate`.

## Kubernetes NetworkPolicy

Apply it with `kubectl apply -f <file>.yaml`. It needs a network plugin that enforces NetworkPolicy.

- The policy selects pods labelled `app=web` in the `default` namespace. Edit the selector for your workload.
- NetworkPolicy is **allow-only** and has **no rule order**. Drop and reject rules cannot be expressed, and a rule cannot carve an exception out of a broader allow.
- Rules match pods by label, not by address: the pod-side address in a rule is ignored.
- Interfaces, source ports and ICMP cannot be matched.
- Port ranges use `endPort`; the network plugin must support it, otherwise only the first port is allowed.
- With an outbound drop policy, pods lose DNS unless an outbound rule allows port 53 (TCP and UDP) to the cluster DNS service.
