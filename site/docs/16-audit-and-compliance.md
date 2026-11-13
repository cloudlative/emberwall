---
title: Audit and compliance
description: How the Emberwall audit finds risky, broken and redundant rules, how the 0-100 posture score and grade are calculated, one-click fixes, and the CIS-style, PCI DSS-style and internet-server compliance profiles.
section: Verify
---

The audit checks the project for exposure, broken connectivity, lock-out risk and rules that can never match. Compliance profiles check it against a named set of controls and show the evidence for each one.

## Audit

Open **Audit** in the sidebar (under *Verify*), or click the **Score** badge in the top bar. A red badge on **Audit** in the sidebar counts critical and high findings.

![Audit page](shot:audit)

Findings are sorted most severe first. Each one explains the problem and, where it concerns a rule, links to it with **Show**.

### Checks

{{audit-checks}}

A few checks need more explanation:

- **Exposed services.** An inbound accept rule with no source restriction and no inbound interface counts as open to the whole internet. Rules pinned to an interface (a LAN or VPN side) are not counted. Sensitive ports such as Telnet, Docker API, Redis, Memcached, MongoDB and Elasticsearch are critical; databases, RDP, VNC, etcd, kubelet and NFS are high.
- **Shadowed and redundant rules.** A rule is reported when an earlier rule in the same direction matches everything it matches. With the same action it is *redundant*; with a different action it *can never match*. Rules with a schedule, MAC, mark or source-port match, and accept rules with a rate limit, are never treated as covering a later rule.
- **Lock-out risk.** With an inbound drop policy and no rule that allows TCP port 22, applying the ruleset over SSH would cut your session. Ignore it if the host is managed from a console or SSH listens on another port.
- **Broken DNS.** With an outbound drop policy and no outbound rule for port 53, name resolution fails.
- **Port forwards without a forward rule.** A port forward whose rewritten traffic no forward rule accepts.

### Score and grade

The posture score starts at 100 and loses points for each finding:

| Severity | Points per finding |
|---|---|
| critical | 30 |
| high | 15 |
| medium | 7 |
| low | 3 |
| info | 0 |

The result is kept between 0 and 100. The grade follows from the score:

| Grade | Score |
|---|---|
| A | 90 or more |
| B | 75 to 89 |
| C | 60 to 74 |
| D | 40 to 59 |
| F | below 40 |

The same score appears on the Dashboard, in the top bar, per host on the Fleet page, for the running ruleset on the Live server page, and from `emberwall audit` on the CLI.

### One-click fixes

Many findings have a fix button, for example:

| Finding | Fix |
|---|---|
| Inbound traffic is accepted by default | Set inbound policy to drop |
| Forwarded traffic is accepted by default | Set forward policy to drop |
| Replies to allowed connections are not accepted | Allow established connections |
| Loopback traffic is not accepted | Allow loopback |
| Invalid packets are not dropped | Drop invalid packets |
| Dropped packets are not logged | Log dropped packets |
| "..." accepts everything from anywhere | Disable rule |
| SSH is open to any source without a rate limit | Limit to 10/min per client |
| "..." is redundant | Remove rule |
| No rule allows SSH (port 22) | Add SSH rule |
| Outbound DNS is blocked | Allow outbound DNS |
| Port forward ... is blocked by the forward policy | Add forward rule |
| NAT rules exist but forwarding is off | Turn forwarding on |
| Recommended kernel hardening is not enabled | Enable recommended |

**Fix all** applies every available fix at once. Every fix is a normal edit: **Ctrl+Z** undoes it.

> [!TIP]
> Fixes that add rules use safe defaults (for example, the added SSH rule is rate-limited). Review them, and restrict sources where you can.

### Audit in CI

```sh
emberwall audit project.json --min-score 80
```

This prints every finding with its severity and the score with its grade, and exits with status 1 if the score is below the minimum. See [CLI](doc:cli).

## Compliance profiles

Open **Compliance** in the sidebar. Pick a profile to see each control with its intent, its status (pass, fail or not applicable) and the evidence from the project.

![Compliance page](shot:compliance)

{{compliance-profiles}}

The result is the share of applicable controls that pass: passed ÷ (passed + failed), rounded to a whole percent. Controls that do not apply (for example, *Public login services are throttled* when no login service is public) are left out. If no control applies, the result is 100%.

Several controls look at **internet-facing** rules: inbound accept rules with no source address, no inbound interface and no source zone.

> [!NOTE]
> The profiles are Emberwall's reading of each framework's firewall-related intent. They support a review; they are not official benchmark content or a certification.

### Print or save as PDF

Press **Print / save as PDF** to open your browser's print dialog. The printout carries the project name, the build target and the date. Choose "Save as PDF" as the printer to keep a file for a review.

### Compliance in CI

```sh
emberwall compliance project.json --profile pci --min 90
```

Profiles are `cis`, `pci` and `internet`; the default is `cis`. The command prints each control as `PASS`, `FAIL` or `NA` with its evidence, then the percentage, and exits with status 1 if it is below `--min`.

## Live servers

In server mode, the **Live server** page runs the same audit and a compliance profile on the ruleset a server is actually running. Kernel hardening and policy tests are project settings, so the server's own sysctl values are not read. See [Live servers](doc:live-servers).
