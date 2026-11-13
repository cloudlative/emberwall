---
title: Quick start
description: Build, check and safely apply your first firewall with Emberwall in a few minutes.
section: Getting started
---

This page takes you from an empty browser tab to a ruleset running on a server. You need a Linux server you can reach over SSH and, the first time, a way to reach its console in case something goes wrong.

## 1. Open the app

[Open the app](app:). It runs entirely in your browser; nothing is installed. After the first visit it also works offline (see [Install](doc:install)).

## 2. Answer the setup wizard

On the first visit a short wizard titled **Welcome to Emberwall** asks three questions:

1. **What is this machine?** Pick a starting point such as *Web server*, *SSH bastion* or *Docker host*, or *Something else* for an empty default-deny ruleset.
2. **Which system does it run?** Pick the distribution. Emberwall selects that distribution's default firewall tool and the exact version it ships. You can change both later.
3. **Where do you administer it from?** Optionally enter the addresses or networks allowed to use SSH, for example `203.0.113.0/24`. Leave it empty to keep the template's choice. A checkbox, on by default, enables the recommended kernel hardening.

Press **Create ruleset**. The wizard replaces the open project (undo brings it back) and takes you to the **Rules** page.

To skip it, press **Skip, I'll explore**. To run it again later, open the command palette with **Ctrl+K** and choose **Run the setup wizard**.

## 3. Or load a template

Instead of the wizard, you can open **Templates** in the sidebar (under *Library*) and load a starting point. Loading a template replaces the current ruleset; undo brings it back.

![Templates page](shot:templates)

## 4. Add a rule

1. Open **Rules** and press **Add rule**.
2. Enter a name, for example `HTTPS from anywhere`.
3. Keep **Direction** at *Inbound* and **Action** at *Accept*.
4. Set **Protocol** to *TCP* and type `443` in **Destination ports**.
5. Leave **Source** empty to allow any address, or enter networks or an address group.
6. Press **Add rule**.

Rules are checked from top to bottom in each direction, and the first match decides. Use the arrows or drag a rule to reorder it. See [Rules](doc:rules) for every field.

## 5. Pick a target

The target picker in the top bar decides what the output looks like. Choose a distribution preset (for example *Debian 12 (bookworm)*) and a tool (nftables, iptables, ufw or firewalld). The version badge shows what that distribution ships. To pick a version by hand, choose **Custom tool version…**.

## 6. Check it

Before you build, look at:

- the **Score** badge in the top bar, which opens the **Audit** page with findings and one-click fixes;
- the **Simulator**, where you describe a packet (for example *SSH from internet*) and see which rule decides it.

> [!WARNING]
> If the audit reports **No rule allows SSH (port 22)** and you manage the server over SSH, fix that first. Applying the ruleset would cut your session.

## 7. Build and apply safely

1. Open **Build** and press **Download all files**.
2. Copy every file to the server, into one directory.
3. Run the safe-apply script as root:

   ```sh
   sudo sh emberwall-apply.sh
   ```

4. The script backs up the running rules, checks the new ones and applies them.
5. Open a **second** SSH session to confirm you can still get in, then type `yes` in the first one.
6. If you do not answer within 60 seconds, the script rolls back to the previous rules, even if your session was cut.

> [!WARNING]
> Keep console access the first time you load a ruleset on a remote machine.

The applied rules are not yet permanent. The end of `emberwall-apply.sh` lists the commands that make them survive a reboot on your distribution. See [Build output and safe apply](doc:build-output).

## Where to go next

- [Concepts](doc:concepts) explains directions, policies and evaluation order.
- [Policy tests](doc:policy-tests) keep important guarantees true as you edit.
- [CLI](doc:cli) runs the same checks in CI.
