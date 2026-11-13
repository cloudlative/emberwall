---
title: Install
description: Use Emberwall as an offline web app, install the single emberwall binary on Linux, macOS or Windows, or run it from source.
section: Getting started
---

Emberwall is distributed in three ways. Pick the one that fits how you work:

| Option | Use it for |
|---|---|
| Web app | Designing, checking and building rulesets in the browser. Nothing to install. |
| `emberwall` binary | The CLI in scripts and CI, and `emberwall serve` for server mode. One self-contained file, no Node.js needed. |
| From source | Development, or building everything yourself. |

## Web app

[Open the app](app:). It runs entirely in your browser and needs no account.

### Offline use

After the first visit, the app works without a network. A service worker caches the whole app when it installs, so the next visit opens even when you are offline. Pages are fetched from the network when it is available, so updates arrive on your next online visit.

The one feature that needs a network is the optional [assistant](doc:assistant), which talks to the Anthropic API.

### Install as an app

The web app is installable as a progressive web app (PWA). Use your browser's install option (usually in the address bar or the browser menu) to add Emberwall as a standalone window.

### Where your data lives

The web app keeps the open project, the target selection, snapshots, theme and current page in your browser's local storage. Clearing the site data for Emberwall removes them. Export your project as JSON from **Import / export** if you want a copy outside the browser. See [Workspace](doc:workspace).

## The emberwall binary

The binary contains:

- the CLI: `emberwall build`, `fleet`, `audit`, `test`, `compliance` and `targets` (see [CLI](doc:cli));
- `emberwall serve`, which runs [server mode](doc:server-mode) with the web app built in;
- `emberwall --version`.

It is published for these platforms:

| OS | Architectures |
|---|---|
| Linux | x64, arm64 |
| macOS | arm64, x64 |
| Windows | x64 |

### Install on Linux or macOS

Run the install script:

{{install}}

The script detects your OS and architecture, downloads the matching binary, verifies its checksum, and installs it to `/usr/local/bin` or `~/.local/bin`.

Check that it works:

```sh
emberwall --version
emberwall targets
```

If your shell cannot find `emberwall`, make sure the directory it was installed to is on your `PATH`.

### Manual download

Each release on the GitHub Releases page of `cloudlative/emberwall` has:

- one binary per platform: `emberwall-linux-x64`, `emberwall-linux-arm64`, `emberwall-macos-arm64` (Apple silicon), `emberwall-macos-x64` (Intel) and `emberwall-windows-x64.exe`;
- a `SHA256SUMS` file with the checksum of each binary;
- `THIRD_PARTY_NOTICES.txt`, the licenses of the bundled components (also printed by `emberwall licenses`).

The [download page](../../download/) links each one directly.

To install by hand on Linux or macOS:

1. Download the binary for your platform and `SHA256SUMS` into the same directory.
2. Verify the checksum. On Linux, the line for your file must say `OK`:

   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   ```

   On macOS, compute the hash and compare it with the line for your file in `SHA256SUMS`:

   ```sh
   shasum -a 256 emberwall-<os>-<arch>
   grep 'emberwall-<os>-<arch>$' SHA256SUMS
   ```

3. Make it executable, rename it and move it onto your `PATH`:

   ```sh
   chmod +x emberwall-<os>-<arch>
   sudo mv emberwall-<os>-<arch> /usr/local/bin/emberwall
   ```

Replace `emberwall-<os>-<arch>` with the name of the file you downloaded.

> [!NOTE]
> The macOS binaries are signed ad hoc but not notarized. A file downloaded with a browser is quarantined by Gatekeeper and will not open until you allow it. Remove the quarantine flag once:
>
> ```sh
> xattr -d com.apple.quarantine emberwall-macos-*
> ```
>
> Files downloaded with `curl` (including by the install script) are not quarantined.

### Install on Windows

1. Download `emberwall-windows-x64.exe` and `SHA256SUMS`.
2. Compute the checksum in PowerShell and compare it with the matching line in `SHA256SUMS`:

   ```powershell
   Get-FileHash .\emberwall-windows-x64.exe -Algorithm SHA256
   Select-String -Path .\SHA256SUMS -Pattern "emberwall-windows-x64.exe"
   ```

   `Get-FileHash` prints the hash in upper case and `SHA256SUMS` in lower case; the characters must otherwise match.

3. Rename the file to `emberwall.exe` and put it in a folder on your `PATH`, or run it from its folder:

   ```powershell
   .\emberwall.exe targets
   ```

The executable is not code-signed, so Windows SmartScreen may warn the first time you run it; choose **More info → Run anyway** if the checksum matched.

The Windows binary runs the CLI and server mode. The rulesets it builds are for the target systems you choose, not for the Windows machine it runs on. For Windows Firewall output, see [More targets](doc:more-targets).

## From source

You need Node.js 22.13 or newer. Emberwall is developed and tested on Node 26 (the repository's `.nvmrc` pins it). Server mode uses Node's built-in SQLite, which is one reason for the minimum version.

```sh
git clone https://github.com/cloudlative/emberwall.git
cd emberwall
npm install
npm run dev        # http://localhost:5173
```

Other scripts:

```sh
npm test           # unit tests + real-tool checks
npm run build      # type-check and production build into dist/
npm run preview    # serve the production build
npm run build:cli  # single-file CLI bundle: dist-cli/emberwall.mjs
```

The production build in `dist/` is a static site that can be hosted anywhere.

### npm equivalents of the binary

The rest of this documentation uses the binary. From a source checkout, use these instead:

| Binary | From source |
|---|---|
| `emberwall <command> ...` | `npm run cli -- <command> ...` |
| `emberwall serve` | `npm run server` (builds the app and the server, then starts it) |

Server mode reads the same environment variables either way. For development, `npm run server:dev` runs the API and `npm run dev` proxies `/api` to it.

## Upgrading

- **Web app:** reload it while online. New versions are fetched from the network and replace the cached copy.
- **Binary:** run the install script again, or download the new release and replace the file. Verify the checksum as above.
- **From source:** pull the latest changes, then run `npm install` and rebuild.

Server mode keeps its data in the SQLite file set by `EMBERWALL_DB`. The server upgrades the database schema itself when it starts. Back up the database and your master key before upgrading; see [Server mode](doc:server-mode#backups).

## Uninstalling

- **Web app:** if you installed it as an app, remove it the way your browser or OS removes installed web apps. To delete your local projects and snapshots, clear the site data for Emberwall in your browser.
- **Binary:** delete the `emberwall` file from `/usr/local/bin`, `~/.local/bin`, or wherever you put it.
- **Server mode:** stop the service and delete its database file (by default `./data/emberwall.db`, relative to the directory the server was started in) and the master key. Deleting them removes all users, stored SSH credentials, team projects and history. Nothing changes on the servers in the inventory.
