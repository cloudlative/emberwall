---
title: Changelog
description: Release notes for Emberwall.
section: Reference
---

This page lists what each Emberwall release contains.

## 1.0.0

The first release. It contains:

**Design**

- One project model with inbound, outbound and forward rules, default policies and baseline options.
- Advanced matches: source ports, MAC address, packet mark, weekly schedules, per-client rate limits and connection limits.
- NAT: masquerade, source NAT and port forwarding, including IPv6.
- Address and port groups, and zones (WAN, LAN, DMZ, VPN).
- Attack protection: SYN flood guard, port-scan filter and auto-ban trap ports.
- Blocklists and country blocking, with a generated updater script and systemd timer.
- Kernel hardening as a sysctl drop-in.
- Starter templates and a first-run setup wizard.

**Ship**

- Version-aware compilers for nftables, iptables, ufw and firewalld, with distribution presets, custom versions, and compiler notes for every fallback.
- `emberwall-apply.sh` safe apply with automatic rollback.
- Automation export: Ansible, Terraform (SSH push) and cloud-init.
- Compare page, Version matrix and line linking between rules and output.
- More targets: pf (OpenBSD and FreeBSD), Windows Firewall, AWS, Azure and Google Cloud security groups via Terraform, and Kubernetes NetworkPolicy.
- Importers for iptables-save, nft list ruleset, ufw and firewalld zone files.

**Verify**

- Packet simulator with trace, packet flow view, reachability matrix and topology diagram.
- Policy tests, audit with a 0–100 posture score and one-click fixes, and CIS-style, PCI DSS-style and internet-server compliance profiles.

**Operate**

- Fleet: shared and host-scoped rules, per-host overrides, per-host builds and an Ansible inventory and playbook.
- Log analyzer.
- Optional assistant using your own Anthropic API key.
- Command palette, undo and redo, snapshots with semantic diff, share links, JSON import and export, light and dark themes, offline use.

**CLI and server mode**

- `emberwall build`, `fleet`, `audit`, `test`, `compliance` and `targets` with exit codes for CI.
- Server mode (`emberwall serve`): sign-in with admin, operator and viewer roles, encrypted SSH inventory, team projects, activity log, live read with audit and drift, and guarded push with a rollback timer on the target.
