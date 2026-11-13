---
title: Security
description: Emberwall's privacy model in the browser, the threat model and hardening of server mode (credential encryption, sessions, throttling, CSRF checks, roles, fixed commands), input hardening of generated scripts, and how to report issues.
section: Server mode
---

This page describes how Emberwall protects your data and your servers, and what you should do to run it safely.

## The browser app

In the web app, everything runs in your browser:

- Projects, snapshots and settings are stored in the browser's local storage. Nothing is uploaded.
- Imports and log lines are parsed in the page.
- Share links carry the project after the `#` in the URL, which browsers do not send to a server. Anyone who has the link can read the ruleset, so share it like the ruleset itself.
- The offline cache (service worker) only handles same-origin `GET` requests. It never caches API calls or requests to other origins.

The only exception is the optional [assistant](doc:assistant). Once you add your own Anthropic API key and press a button, your request and a description of the project go from your browser to the Anthropic API. The page shows exactly what is sent. The key stays in the tab unless you tick "Remember on this device".

## Generated scripts: input hardening

Generated files run as root on real machines. Every build, in the browser, on the CLI and in server mode, starts from a hardened copy of the project:

- Names and comments are reduced to one line, and quote, backslash, backtick, `$` and control characters are removed.
- Interface names, MAC addresses, packet marks, schedules, ICMP types, connection states, addresses, ports and numeric limits are checked against strict patterns or ranges.
- Blocklist download URLs must be plain `http(s)` addresses.
- Anything that fails a check is reported as an error and left out of the output.

The test suite executes the generated scripts with a deliberately hostile project (shell metacharacters in every name and field) to confirm that nothing but firewall commands runs.

## Server mode: threat model

A server-mode instance holds SSH access to your servers and can change their firewalls. Treat it like any other system with root access to your fleet:

- Run it on a machine you trust and restrict who can reach it.
- It listens on `127.0.0.1` by default. Anything else needs HTTPS in front (a reverse proxy) and `EMBERWALL_HTTPS=1`. See [Server mode](doc:server-mode#put-it-behind-a-tls-reverse-proxy).
- Use a dedicated SSH user and key for Emberwall. Reading needs root or passwordless sudo for the firewall commands; pushing runs `sh` through sudo, so the account is effectively root.

### Stored credentials

- SSH private keys, passphrases and passwords are encrypted with **AES-256-GCM** before they are written to the database.
- The encryption key is derived (HKDF-SHA256) from the master key in `EMBERWALL_SECRET` or `EMBERWALL_SECRET_FILE`. The master key itself is never stored in the database.
- A master key shorter than 32 characters is refused, not stretched. Without a valid key, credentials cannot be saved.
- Credentials are never sent back to the browser.
- Anyone holding both the database file and the master key can decrypt the credentials. Keep them apart, including in backups. Losing the master key means re-entering every credential.

### Passwords and sessions

- Passwords are hashed with scrypt and a random salt. They must be 10 to 200 characters.
- A successful sign-in creates a random session token. The browser gets it in the `ew_session` cookie (`HttpOnly`, `SameSite=Strict`, and `Secure` when `EMBERWALL_HTTPS=1`). Only a hash of the token is stored.
- A session ends after **12 hours** without activity, and at the latest **7 days** after sign-in.
- Changing your password signs out your other sessions. Resetting a user's password, changing their role or disabling them ends their sessions.

### Sign-in throttling

- After 8 failed sign-ins for the same user name within 10 minutes, or 40 from the same client address, further attempts are refused with "Too many attempts. Wait ten minutes and try again."
- The counters are kept in memory and reset when the server restarts.
- The client address is the TCP peer, or the first `X-Forwarded-For` entry when `EMBERWALL_TRUST_PROXY=1`. Only set that behind your own proxy, and make the proxy overwrite the header.
- A password hash is computed even for unknown user names, so response times do not reveal which names exist. Failed sign-ins are recorded in the activity log.

### Cross-site request forgery

Every request that changes data must:

- carry the `X-Emberwall: 1` header, which a browser cannot add cross-origin without a CORS preflight (the server never approves one);
- have an `Origin`, if present, whose host matches the `Host` header;
- send JSON.

Together with the `SameSite=Strict` cookie, this blocks requests from other sites.

### Roles

Every API route names the lowest role it needs (`viewer`, `operator` or `admin`), and the server checks it on every request. Only health, first-run setup, sign-in and sign-out are reachable without a session, and setup only works while there are no users. The last enabled administrator cannot be removed or demoted.

### Fixed commands on your servers

- The commands for reading a server are fixed strings in Emberwall's code. Nothing from the browser is added to them. The firewalld zone name read from the server is checked before it is used in a file path.
- A push uploads files with fixed names into a directory named after a numeric push id. The deploy, rollback and confirm scripts are generated from fixed text; their only inputs are the id, the timeout (clamped to 15–600 seconds) and the tool.
- Host keys are pinned on first use. A changed key blocks the connection until someone with the operator role deliberately forgets the old one.
- Command output is capped in size, and commands time out.

### Other hardening

- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. API responses are not cached.
- Request bodies are limited to 2 MB.
- Uploads to the target are written with `umask 077`.

## What has been tested

Server mode is tested end to end over real HTTP and real SSH: sign-in, roles on every route, lock-out after wrong passwords, session expiry, credential encryption, host-key pinning and mismatch, and the fixed command list. Guarded pushes are tested for nftables, iptables, ufw and firewalld against a real OpenSSH server inside private network namespaces, including a ruleset that shuts SSH out and must roll itself back. Nothing was tested against a remote production server. See [How the output was checked](doc:verification).

## Report an issue

To report a bug or a security concern, open an issue in the GitHub repository `cloudlative/emberwall`. Do not include credentials, private keys, real server addresses or other sensitive details in a public issue.
