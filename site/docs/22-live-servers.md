---
title: Live servers and guarded push
description: Connect Emberwall to servers over SSH, read and audit the running firewall, see drift against the project, and push a build with a rollback timer that only a fresh reconnection can cancel.
section: Server mode
---

In [server mode](doc:server-mode), Emberwall can connect to your servers over SSH. It reads the running firewall with a fixed set of read-only commands, shows its rules, audit and compliance results and how it differs from your project, and can push a build with automatic rollback.

## Prepare the server

Use a dedicated SSH user and key for Emberwall.

The account needs **root**, or **passwordless sudo**. Emberwall runs commands through `sudo -n` when it is not root, so sudo must not ask for a password.

- **Reading** needs root for: `nft list ruleset`, `iptables-save`, `ip6tables-save`, `ufw status verbose`, `ufw show added`, `firewall-cmd --state`, `firewall-cmd --get-default-zone`, and reading the default zone's file under `/etc/firewalld/zones/`.
- **Pushing** runs `sh` through sudo: to write the uploaded files, to run the deploy script, and to confirm. In practice the push account is root-equivalent; treat its key accordingly.

If the account cannot read the ruleset, the live view says "The SSH user could not read the ruleset. Connect as root, or give this user passwordless sudo for the firewall commands", and pushing is refused.

## Add a server

On the **Servers** page, press **Add server** (operators and admins) and fill in:

| Field | Notes |
|---|---|
| **Name** | Letters, digits, spaces, dots, dashes and underscores, up to 60 characters. Must be unique. |
| **Tags** | Optional, for example `prod, web`. |
| **Address** | A host name or IP address. |
| **SSH port** | Default `22`. |
| **SSH user** | The account Emberwall signs in as. |
| **Sign in with** | **Private key** (OpenSSH or PEM format, with an optional **Key passphrase**) or **Password**. |
| **Notes** | Optional. |

The credential is encrypted with the server's master key before it is stored, and it is never sent back to the browser. When you edit a server, leave the key or password field empty to keep the stored one.

If the Emberwall server has no master key, saving a credential fails; the form warns you.

Deleting a server removes its stored credential and history from Emberwall. Nothing changes on the server itself.

## Approve the host key

The first time Emberwall connects, it shows the server's host key fingerprint (`SHA256:...`) and asks you to approve it. Compare it with the server's own fingerprint, from its console:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

If the server presents a different key type, check the matching `.pub` file. Press **It matches, trust it** only if the fingerprints match. The key is then pinned: a different key later blocks the connection.

If the key changes, Emberwall shows **Host key has changed** with the approved and presented fingerprints. If you know why (for example, the server was reinstalled), press **The server was reinstalled: forget the old key**, then read again to review the new key.

Changing a server's address or port also forgets its pinned key.

## Read the live configuration

Open **Live server**, pick the server, and press **Read live config** (operators and admins). Only read-only commands are run:

{{probe-commands}}

On a firewalld server, Emberwall also reads the default zone's file, `/etc/firewalld/zones/<zone>.xml`, after checking that the zone name is a plain name.

![Live audit of a running server](shot:live-audit)

The page shows:

| Item | Meaning |
|---|---|
| **System** | The OS and kernel. |
| **Firewall in charge** | The tool and version that actually manages the firewall, and why Emberwall thinks so. |
| **Live audit score** | The audit score and grade of the running ruleset. |
| **Differs from project** | How many access paths differ from the open project. |

### Which tool is in charge

Emberwall decides in this order: firewalld if it is running; ufw if it is active; nftables if a native nftables ruleset is loaded; iptables if iptables rules are loaded; otherwise nftables or iptables if installed. Tables created by iptables-nft do not count as a native nftables configuration.

### Tabs

- **Rules:** the running ruleset, imported with the same importers as [Import](doc:import). Lines that were not understood are listed.
- **Raw config:** the command output exactly as the server returned it.
- **Audit:** the [audit](doc:audit-and-compliance) findings and a compliance profile applied to what the server actually runs. Kernel hardening and policy tests are project settings; the server's own sysctl values are not read.
- **Drift:** how the server differs from the open project. See [Drift](#drift).
- **Push:** push a build (operators and admins).
- **History:** earlier pushes to this server.

Viewers see the last read made by an operator. Emberwall keeps the last 20 reads per server.

### Use as build target and adopt as project

- **Use as build target** sets the build target to the exact tool and version found. If the server's distribution preset ships exactly that version, the preset is used; otherwise a custom target with the closest known version at or below the detected one.
- **Adopt as project** replaces the open project with the rules read from the server (undo brings yours back).

## Drift

The **Drift** tab compares the running server with the open project:

- **Access that differs:** which traffic the server allows or blocks differently from the project, for IPv4 and IPv6, using the [semantic diff](doc:reachability-and-topology#semantic-diff). If nothing differs, it says so.
- **Configuration diff:** a line diff between the server's configuration and the project's build. Red lines are only on the server, green only in the project's build. This needs the project to be built for the same tool the server runs; otherwise use **Use as build target** first.

## Guarded push

A push deploys the open project to the server from the browser, with a rollback timer that runs **on the target**. Only a fresh, successful SSH connection can cancel it, so a ruleset that locks Emberwall out rolls itself back.

![Guarded push waiting for confirmation](shot:live-push)

### 1. Check

The **Push** tab first shows what will happen: the project and target, whether the build's tool matches the tool the server runs, whether the versions match, any build errors, and how many things are adapted for the target. On nftables, it also warns when other tables will keep filtering alongside Emberwall's.

### 2. Push

1. Type the server name to enable the push.
2. Choose **Roll back after**: 30, 60, 120 or 300 seconds (default 60).
3. Press **Push to <server>**.

The Emberwall server then:

1. Builds the project on the server side for the selected target.
2. Connects and reads the server again, to check the tool and privileges.
3. Uploads the main ruleset files and a deploy script to `/etc/emberwall/deploy-<id>/` (created with `umask 077`). State goes to `/var/lib/emberwall/deploy-<id>/`.
4. Runs the deploy script, which:
   - backs up the running rules (if the backup fails, nothing is changed);
   - checks the new rules (`nft -c -f`, `iptables-restore --test`, or `firewall-cmd --state`); if the check fails, nothing is changed;
   - writes a rollback script and arms a timer in the background that survives the SSH session ending;
   - applies the new rules. If applying fails, it rolls back at once.
5. Shows **Applied. Confirm to keep the new rules.** with a countdown.

### 3. Confirm

Press **Confirm: keep the new rules**. Emberwall opens a **new** SSH connection and runs the confirm script on the target.

- If the connection succeeds before the timer ends, the push is confirmed: "Confirmed. The new rules are live." The confirmation and the timer are decided exactly once on the target, so a confirmation that arrives while the timer is already rolling back is reported as too late, never as confirmed.
- If the new rules block Emberwall, the new connection fails, the push cannot be confirmed, and the target restores its previous rules when the timer ends.
- If you do nothing, the target rolls back on its own: "Not confirmed in time. The server restored its previous rules on its own." Read the server again to verify.

Only one push per server can wait for confirmation at a time.

### Rollback per tool

| Tool | Backup and rollback |
|---|---|
| nftables | `nft list ruleset` is saved; rollback runs `nft flush ruleset` and loads the backup |
| iptables | `iptables-save` / `ip6tables-save`; rollback restores both |
| ufw | copies of `/etc/ufw` and `/etc/default/ufw` and the ufw state; rollback restores them, then reloads ufw, or disables it if it was inactive before |
| firewalld | a copy of `/etc/firewalld` and the default zone; rollback restores them, reloads and sets the default zone |

### What a push installs

A push installs only the main ruleset:

| Tool | Files |
|---|---|
| nftables | `emberwall.nft` |
| iptables | `rules.v4`, `rules.v6` |
| ufw | `emberwall-ufw.sh` |
| firewalld | `emberwall-firewalld.sh` |

The result lists the other generated files under **Not installed by this push**: the ufw `before.rules` fragments, firewalld zone XML files, the sysctl file `99-emberwall.conf` and the blocklist updater units. Install them by hand if you need them.

> [!NOTE]
> A push loads the rules into the running firewall. ufw and firewalld keep them across reboots on their own. For nftables and iptables, follow the persistence steps in [Build output](doc:build-output#making-the-rules-permanent). A push also does not switch on `ip_forward`; install the sysctl file for routing hosts.

### What is refused

A push is refused when:

- the build has errors;
- the server is managed by a different tool than the build targets (fetch the server and use it as the build target);
- the SSH user cannot manage the firewall (needs root or passwordless sudo);
- the build is for iptables or ufw and uses blocklists (the `ipset` sets must be created by hand);
- another push to the same server is still waiting for confirmation;
- the typed server name does not match.

### What a push replaces

A push replaces only what Emberwall manages. On nftables that is the `inet emberwall` table: other tables keep filtering, and a packet has to be accepted by every one of them. The live view and the push check tell you when other tables exist.

## History

The **History** tab lists earlier pushes to the server with their status (confirmed, pending, expired or failed) and the log of each step. Every push and confirmation is also in the [activity log](doc:server-mode#activity).

## Limits of the live view

- The live view models one rule list per direction. Servers with several nftables tables, custom chains or jumps are only partly represented; every line that was not understood is listed.
- On a firewalld server, only the default zone is read. Rules in other zones (such as the `ew-*` zones Emberwall creates for interfaces) and in policies are not imported, so they show up as drift.
- Emberwall has been tested against real OpenSSH servers in private network namespaces, not against remote production servers. Keep console access the first time you push to a machine.
