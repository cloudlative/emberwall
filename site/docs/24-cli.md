---
title: CLI reference
description: Every emberwall command and flag - build, fleet, audit, test, compliance, targets and serve - with output, exit codes, and CI examples for GitHub Actions and GitLab.
section: Reference
---

The `emberwall` command runs the same engine as the web app outside the browser, for scripts and CI. It reads the project JSON files you export from **Import / export** in the app.

To install it, see [Install](doc:install#the-emberwall-binary). From a source checkout, use `npm run cli -- <command> ...` instead of `emberwall <command> ...`.

## Help

{{cli-help}}

`emberwall --help`, `emberwall -h` and `emberwall help` print this text and exit with status 0. Running `emberwall` with no command prints it and exits with status 2.

`emberwall --version` prints the version of the binary.

## Shell completion

Press Tab to complete commands, flags, every `--target` (`debian-12:nftables`, `nftables@1.1.6` and the rest), `--profile` names, project files (`.json`) and `--out` folders.

The [install script](doc:install#the-emberwall-binary) sets it up for bash and fish. To set it up yourself, `emberwall completion <shell>` prints the script:

| Shell | Set up once |
| --- | --- |
| bash | `emberwall completion bash > ~/.local/share/bash-completion/completions/emberwall` (needs the bash-completion package), or add `source <(emberwall completion bash)` to `~/.bashrc` |
| zsh | add `source <(emberwall completion zsh)` to `~/.zshrc`, after `compinit` |
| fish | `emberwall completion fish > ~/.config/fish/completions/emberwall.fish` |

`emberwall completion` with no shell name uses your login shell (`$SHELL`). The lists are written into the script, so Tab never starts Emberwall itself; after upgrading, run the command again to pick up new targets.

## Exit status

| Status | Meaning |
|---|---|
| `0` | Everything passed. |
| `1` | A check failed: the build has errors (or, with `--strict`, fallbacks), a policy test failed, the score or compliance result is below the minimum, or a fleet host's build has errors. |
| `2` | Usage or input error: unknown command, missing or unreadable project file, missing or unknown target, unknown profile, or a fleet command on a project without hosts. The error and the help text are printed to stderr. |

Flags take their value after a space: `--min-score 80`, not `--min-score=80`.

## targets

Lists the distribution presets and the tool versions each ships. `*` marks the distribution's default firewall manager.

```sh
emberwall targets
```

{{cli-targets}}

## build

Compiles a project for one target.

```text
emberwall build <project.json> --target <target> [--out <dir>] [--iac] [--strict]
```

| Flag | Meaning |
|---|---|
| `--target <target>` | Required. See below. |
| `--out <dir>` | Write every generated file into this directory (created if needed). Without it, only the main file is printed to stdout. |
| `--iac` | Also write `emberwall-playbook.yml`, `emberwall.tf` and `emberwall-cloud-init.yaml`. Only with `--out`. |
| `--strict` | Exit with status 1 when the build has version fallbacks or features the target cannot express. |

### Target syntax

| Form | Example | Meaning |
|---|---|---|
| `<distro>:<tool>` | `debian-12:nftables`, `ubuntu-24.04:ufw` | The tool at the version that distribution ships. |
| `<distro>` | `rhel-9` | The distribution's default firewall manager. |
| `<tool>@<version>` | `nftables@1.0.9`, `iptables@1.8.10` | A specific version. It must be one of the known versions (see `emberwall targets` and [Targets and versions](doc:targets-and-versions#known-versions)). |

Tools are `nftables`, `iptables`, `ufw` and `firewalld`. A distribution that does not package the tool is an error (for example `rhel-9:ufw`).

### Output

Errors and warnings from the compiler notes are printed to stderr as `error: ...` and `warning: ...`. Informational notes are not printed. With `--out`, a summary of the form `wrote <n> files to out/ for nftables 1.0.6 · Debian 12 (bookworm)` goes to stderr.

### Examples

```sh
# Print the nftables ruleset for Debian 12
emberwall build project.json --target debian-12:nftables

# Write all files plus Ansible, Terraform and cloud-init
emberwall build project.json --target debian-12:nftables --out out/ --iac

# Fail if anything has to fall back on nftables 1.0.9
emberwall build project.json --target nftables@1.0.9 --strict
```

### Exit status

`1` if the build has errors (invalid rules are left out of the output). With `--strict`, also `1` if there is any warning: a version fallback or something the target cannot express. Otherwise `0`.

## fleet

Builds every host of a [fleet](doc:fleet) for its own target.

```text
emberwall fleet <project.json> [--out <dir>]
```

It prints one line per host: name, target, number of rules, audit score, and `ERRORS <n>` when the host's build has errors. With `--out`, it writes `hosts/<name>/<files>`, `inventory.ini` and `fleet-playbook.yml` into the directory.

```sh
emberwall fleet project.json --out fleet/
```

Exit status `1` if any host's build has errors; `2` if the project has no hosts.

## audit

Runs the [audit](doc:audit-and-compliance).

```text
emberwall audit <project.json> [--min-score <0-100>]
```

It prints each finding as `SEVERITY title`, most severe first, then `score <n>/100 (grade <A-F>)`.

```sh
emberwall audit project.json --min-score 80
```

Exit status `1` if the score is below `--min-score` (default 0).

## test

Runs the project's [policy tests](doc:policy-tests).

```text
emberwall test <project.json>
```

It prints `PASS` or `FAIL` per test (failures show the expected and actual verdict and what decided it), then `<passed>/<total> passed`. A project without tests prints `no policy tests in this project`.

Exit status `1` if any test fails.

## compliance

Checks the project against a [compliance profile](doc:audit-and-compliance#compliance-profiles).

```text
emberwall compliance <project.json> [--profile cis|pci|internet] [--min <0-100>]
```

| Flag | Default | Meaning |
|---|---|---|
| `--profile` | `cis` | `cis` (CIS-style host firewall), `pci` (PCI DSS-style network controls) or `internet` (internet-facing server baseline). |
| `--min` | `0` | Minimum percentage of applicable controls that must pass. |

It prints each control as `PASS`, `FAIL` or `NA` with its title and evidence, then the profile name, the percentage and the pass/fail counts.

```sh
emberwall compliance project.json --profile pci --min 90
```

Exit status `1` if the result is below `--min`; `2` for an unknown profile.

## serve

Runs [server mode](doc:server-mode) with the web app built in. It is configured with environment variables, not flags:

```sh
EMBERWALL_SECRET_FILE=/etc/emberwall-server/master.key emberwall serve
```

From source, the equivalent is `npm run server`.

## CI examples

These examples keep the project file in the repository as `firewall/project.json`, export it again from the app whenever you change it, and fail the pipeline when a check fails.

### GitHub Actions

```yaml
name: Firewall
on: [push, pull_request]

jobs:
  firewall:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Emberwall
        run: |
          base=https://github.com/cloudlative/emberwall/releases/latest/download
          curl -fsSLO "$base/emberwall-linux-x64"
          curl -fsSLO "$base/SHA256SUMS"
          sha256sum -c SHA256SUMS --ignore-missing
          chmod +x emberwall-linux-x64
          mv emberwall-linux-x64 emberwall

      - name: Policy tests
        run: ./emberwall test firewall/project.json

      - name: Audit
        run: ./emberwall audit firewall/project.json --min-score 80

      - name: Compliance
        run: ./emberwall compliance firewall/project.json --profile internet --min 90

      - name: Build
        run: ./emberwall build firewall/project.json --target debian-12:nftables --out out/ --iac --strict

      - uses: actions/upload-artifact@v4
        with:
          name: firewall
          path: out/
```

### GitLab CI

```yaml
firewall:
  image: debian:12
  before_script:
    - apt-get update && apt-get install -y curl ca-certificates
    - base=https://github.com/cloudlative/emberwall/releases/latest/download
    - curl -fsSLO "$base/emberwall-linux-x64"
    - curl -fsSLO "$base/SHA256SUMS"
    - sha256sum -c SHA256SUMS --ignore-missing
    - chmod +x emberwall-linux-x64 && mv emberwall-linux-x64 emberwall
  script:
    - ./emberwall test firewall/project.json
    - ./emberwall audit firewall/project.json --min-score 80
    - ./emberwall build firewall/project.json --target debian-12:nftables --out out/ --strict
  artifacts:
    paths:
      - out/
```

> [!TIP]
> To pin a release instead of always using the latest, replace `releases/latest/download` with `releases/download/<tag>` in the URL.

For a fleet, replace the build step with `emberwall fleet firewall/project.json --out fleet/` and publish the `fleet/` directory.
