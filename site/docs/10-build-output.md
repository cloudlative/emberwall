---
title: Build output and safe apply
description: The files Emberwall generates for each backend, how emberwall-apply.sh applies them with automatic rollback, how to make rules permanent, and the Ansible, Terraform and cloud-init exports.
section: Ship
---

The **Build** page compiles the project for the selected target and gives you every file you need, a safe way to apply them, and the same build wrapped for automation tools.

![Build page](shot:build)

## The Build page

- The target picker at the top chooses the tool and version. See [Targets and versions](doc:targets-and-versions).
- **Generated output** shows each file in a tab, with **Copy** and **Download** buttons and the compiler notes below.
- **Files in this build** lists every file with its description and the path where it normally lives on the target system.
- **Download all files** downloads them one by one.
- **Automation** lists the Ansible, Terraform and cloud-init versions of the build. **View** opens one.
- **Share link** copies a link that contains the whole project. See [Workspace](doc:workspace#share-links).

## Files per backend

Every build includes `emberwall-apply.sh`. The other files depend on the tool.

### nftables

| File | Usual path | Contents |
|---|---|---|
| `emberwall.nft` | `/etc/nftables.conf` | The ruleset, loaded with `nft -f`. |

Emberwall owns one table, `inet emberwall`, and leaves every other table alone. Reloading the file replaces only that table: with `destroy table` on nftables 1.0.7+ (kernel 6.3+), otherwise with an `add table` + `delete table` pair, so reloads stay idempotent. On targets without NAT in the `inet` family, NAT goes into extra `ip emberwall_nat` / `ip6 emberwall_nat` tables.

### iptables

| File | Usual path | Contents |
|---|---|---|
| `rules.v4` | `/etc/iptables/rules.v4` | IPv4 ruleset for `iptables-restore` |
| `rules.v6` | `/etc/iptables/rules.v6` | IPv6 ruleset for `ip6tables-restore` |

The files work with both iptables backends (`iptables-nft` and `iptables-legacy`); check yours with `iptables -V`.

> [!WARNING]
> `iptables-restore` replaces the whole filter (and nat) table. On Docker or Kubernetes hosts, restart the daemon afterwards so it re-creates its chains.

### ufw

| File | Usual path | Contents |
|---|---|---|
| `emberwall-ufw.sh` | `./emberwall-ufw.sh` | ufw commands |
| `before.rules.fragment` | `/etc/ufw/before.rules` | Manual additions for IPv4, only when needed |
| `before6.rules.fragment` | `/etc/ufw/before6.rules` | Manual additions for IPv6, only when needed |

`emberwall-ufw.sh` rebuilds the ufw rule set from scratch: it starts with `ufw --force reset`, sets the default policies and IPv6 setting, adds the rules, and ends with `ufw --force enable`.

The fragments hold what the ufw command line cannot express: NAT, ICMP rules, state matches, connection limits, schedules, MAC and mark matches, attack protection and blocklists. Each fragment says where to paste each block. Run `ufw reload` afterwards. Fragment rules run before all ufw command rules.

### firewalld

| File | Usual path | Contents |
|---|---|---|
| `emberwall-firewalld.sh` | `./emberwall-firewalld.sh` | `firewall-cmd` commands |
| `emberwall.xml` | `/etc/firewalld/zones/emberwall.xml` | Zone file for the default `emberwall` zone (alternative to the script, inbound part) |
| `ew-<name>.xml` | `/etc/firewalld/zones/ew-<name>.xml` | One zone file per zone with interfaces (inbound part) |

The script writes everything with `--permanent`, reloads firewalld and sets `emberwall` as the default zone. Outbound and forward rules go into firewalld policy objects (0.9.0+), or the direct interface on older versions.

### Extra files

| File | When | See |
|---|---|---|
| `99-emberwall.conf` | At least one kernel hardening setting is enabled | [Kernel hardening](doc:protection#kernel-hardening) |
| `emberwall-blocklists.sh`, `.service`, `.timer` | An enabled blocklist has a download URL | [Blocklists](doc:protection#blocklists) |

## Safe apply with emberwall-apply.sh

`emberwall-apply.sh` applies the ruleset and rolls back automatically unless you confirm, so a mistake cannot lock you out.

To use it:

1. Copy every generated file to the server, into one directory.
2. Run it as root from that directory:

   ```sh
   sudo sh emberwall-apply.sh
   ```

3. When it says *Applied*, open a **new** SSH session and check that you can still get in.
4. Type `yes` in the first session within the timeout to keep the rules.

### What it does, step by step

1. Refuses to run unless it is root.
2. **Backs up** the running rules into a new directory `/tmp/emberwall-backup.XXXXXX`:

   | Tool | Backup |
   |---|---|
   | nftables | `nft list ruleset` |
   | iptables | `iptables-save` and `ip6tables-save` |
   | ufw | copies of `/etc/ufw` and `/etc/default/ufw` |
   | firewalld | a copy of `/etc/firewalld` and the current default zone |

3. **Checks** the new rules without changing anything: `nft -c -f` for nftables; `iptables-restore --test` and `ip6tables-restore --test` for iptables (after creating any blocklist `ipset` sets); `firewall-cmd --state` for firewalld. ufw has no check step. If a check fails, the script stops before anything changes.
4. **Starts a watchdog** in the background: it ignores hang-ups, sleeps for `$TIMEOUT` seconds, then restores the backup.
5. **Applies** the new rules. If the apply fails, it stops the watchdog, rolls back at once and exits with status 1. On nftables and iptables, if the project forwards packets or has NAT, it also switches on `net.ipv4.ip_forward` (and IPv6 forwarding) with `sysctl -w`.
6. **Asks** you to type `yes`.
   - `yes`: the watchdog is stopped and the rules stay. The backup is kept in the `/tmp/emberwall-backup.*` directory.
   - Anything else: the script rolls back at once.

### The timeout

The default timeout is 60 seconds. To change it, set `TIMEOUT` (in seconds):

```sh
sudo env TIMEOUT=180 sh emberwall-apply.sh
```

### If your session drops

Because the watchdog ignores hang-ups, it keeps running when the new rules cut the SSH session that started the script. When the timeout runs out, it restores the backup on its own.

> [!WARNING]
> Type `yes` before the timeout ends. Once the watchdog has rolled back, a late `yes` does not bring the new rules back; run the script again.

### Rollback

| Tool | Rollback |
|---|---|
| nftables | `nft flush ruleset`, then load the backup |
| iptables | `iptables-restore` and `ip6tables-restore` from the backup |
| ufw | restore `/etc/ufw` and `/etc/default/ufw`, then `ufw reload` |
| firewalld | restore `/etc/firewalld`, `firewall-cmd --reload`, restore the default zone |

## Making the rules permanent

`emberwall-apply.sh` changes the running firewall. Whether that survives a reboot depends on the tool. The exact commands for the selected distribution are at the end of the script, under `# --- Make it permanent (survive reboot) ---`.

- **ufw** stores its rules itself; `ufw enable` already makes them start at boot.
- **firewalld:** everything is written with `--permanent`, so it already survives a reboot.
- **nftables and iptables** need the steps below.

### nftables

| Distribution family | Steps |
|---|---|
| Debian, Ubuntu, Arch | `install -m 600 emberwall.nft /etc/nftables.conf` (this replaces the distribution's default file), then `systemctl enable --now nftables` |
| RHEL, Alma, Rocky | `install -m 600 emberwall.nft /etc/nftables/emberwall.nft`, add `include "/etc/nftables/emberwall.nft"` to `/etc/sysconfig/nftables.conf`, then `systemctl disable --now firewalld; systemctl enable --now nftables` |
| Alpine | `install -m 600 emberwall.nft /etc/nftables.d/emberwall.nft`, then `rc-update add nftables && rc-service nftables restart` |
| Custom version | Load `emberwall.nft` with `nft -f` at boot (most distributions: `/etc/nftables.conf` and `nftables.service`) |

### iptables

| Distribution family | Steps |
|---|---|
| Debian, Ubuntu | `apt install iptables-persistent`, install `rules.v4` and `rules.v6` to `/etc/iptables/`, `systemctl enable netfilter-persistent` |
| RHEL, Alma, Rocky, CentOS | `dnf install iptables-services` (`yum` on EL7), install to `/etc/sysconfig/iptables` and `/etc/sysconfig/ip6tables`, `systemctl disable --now firewalld; systemctl enable --now iptables ip6tables` |
| Alpine | `rc-service iptables save && rc-update add iptables`, and the same for `ip6tables` |
| Arch | install to `/etc/iptables/iptables.rules` and `/etc/iptables/ip6tables.rules`, `systemctl enable --now iptables ip6tables` |
| Custom version | Load the files with `iptables-restore` / `ip6tables-restore` from a boot script or unit |

> [!NOTE]
> When the target is nftables or iptables on a distribution whose default manager is ufw or firewalld, the compiler notes remind you to disable that manager first, so two managers do not fight.

## Automation export

The **Automation** panel wraps the same build for your tooling. On the CLI, `emberwall build ... --out <dir> --iac` writes the same three files.

| File | Format | What it does |
|---|---|---|
| `emberwall-playbook.yml` | Ansible playbook | Creates `/etc/emberwall` (mode 0700), copies the files there (mode 0600), then checks and loads the ruleset through a handler. Runs on `hosts: all` with `become: true`. |
| `emberwall.tf` | Terraform (SSH push) | Copies the files to `/etc/emberwall` over SSH and loads them. Variables: `host`, `user` (default `root`) and `private_key_path`. Requires Terraform 1.4+ (`terraform_data`). |
| `emberwall-cloud-init.yaml` | cloud-init user data | Writes the files to `/etc/emberwall` and loads the firewall on the first boot of a new instance. |

The exports carry the ruleset and the extra files, but not `emberwall-apply.sh`, the ufw fragments or the firewalld zone XML files. Extra files such as the sysctl file and blocklist updater are copied to `/etc/emberwall/` but not installed to their system paths.

Run them as usual:

```sh
ansible-playbook -i inventory emberwall-playbook.yml
terraform init
terraform apply -var host=203.0.113.10 -var private_key_path=~/.ssh/id_ed25519
```

> [!WARNING]
> The exports load the ruleset without the confirm-or-rollback step. Test on one host first.

For many hosts with different targets, use the [fleet](doc:fleet) bundle instead.

## Line linking

The output panel links rules and lines in both directions:

- Click a rule on the **Rules** or **NAT** page, and the lines it produced are highlighted.
- Click a line in the output, and the rule that produced it is selected.
- Click a compiler note that belongs to a rule to select that rule.

## Compare targets

The **Compare** page compiles the same project for two targets and shows the main output file of each. Use it to plan an upgrade, or a move from iptables to nftables.

![Compare page](shot:compare)

1. Pick the **Left target** and **Right target**. Every distribution/tool pair and every known tool version is in the list. The default compares nftables 0.9.0 with nftables 1.1.5.
2. Choose **Diff** or **Side by side**.

In **Diff** mode, red lines exist only on the left target and green lines only on the right, with a count of added and removed lines. The compiler notes for both targets are shown next to the diff.
