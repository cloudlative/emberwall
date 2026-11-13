---
title: Server mode
description: Run Emberwall as a small team server with emberwall serve - configuration, first-run setup, users and roles, team projects, the activity log, systemd, a TLS reverse proxy and backups.
section: Server mode
---

The web app needs no backend. Server mode adds one for teams: sign-in with roles, a shared server inventory, team projects and an activity log, stored in SQLite. It also lets Emberwall connect to your servers over SSH to [read their running firewall and push builds](doc:live-servers).

> [!WARNING]
> A server-mode instance holds SSH access to your servers and can change their firewalls. Run it on a machine you trust and restrict who can reach it. Read [Security](doc:security) before using it for real.

## What it adds

When the app is served by an Emberwall server, it signs you in and shows a **Team** group in the sidebar:

| Page | What it is for |
|---|---|
| **Servers** | The machines Emberwall can reach over SSH. |
| **Live server** | Read a server's running firewall, audit it, compare it with the project, and push a build. |
| **Team projects** | Rulesets saved on the server and shared by everyone who signs in. |
| **Users** | Who can sign in and what they may do (admins only). |
| **Activity** | Sign-ins, server connections, pushes and changes to accounts and inventory (operators and admins). |

Everything else works as in the browser-only app.

## Start the server

Generate a master key and start the server:

```sh
export EMBERWALL_SECRET="$(head -c 48 /dev/urandom | base64)"
emberwall serve
```

It listens on `http://127.0.0.1:8787` and prints the address and database path. The web app is built into the binary; open the address in a browser.

From a source checkout, run `npm run server` instead (it builds the app and the server first). See [Install](doc:install#from-source).

> [!WARNING]
> Keep the master key. Stored SSH credentials are encrypted with it, and without the same key they cannot be read again. See [Backups](#backups).

## Configuration

Server mode is configured with environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `EMBERWALL_SECRET` | none | Master key that encrypts stored SSH credentials. Must be at least 32 characters; a shorter value is ignored. Without a key, credentials cannot be saved. |
| `EMBERWALL_SECRET_FILE` | none | Read the master key from this file instead (surrounding whitespace is trimmed). Used only when `EMBERWALL_SECRET` is not set. |
| `EMBERWALL_DB` | `./data/emberwall.db` | SQLite database file. Its directory is created if needed. A relative path is relative to the directory the server is started in. |
| `PORT` | `8787` | Listen port. `EMBERWALL_PORT` is read if `PORT` is not set. |
| `EMBERWALL_HOST` | `127.0.0.1` | Listen address. |
| `EMBERWALL_HTTPS` | off | Set to `1` when a TLS reverse proxy is in front. Marks the session cookie `Secure`. |
| `EMBERWALL_TRUST_PROXY` | off | Set to `1` to use the `X-Forwarded-For` header for sign-in throttling. Only behind your own proxy. |

At start-up the server warns when:

- no master key is set, or it is shorter than 32 characters;
- it listens beyond localhost without `EMBERWALL_HTTPS=1`.

Without a master key, the app shows "The server was started without EMBERWALL_SECRET, so SSH credentials cannot be saved until it is set." Everything except storing credentials still works.

## First-run setup

The first visit to a new server shows **Set up Emberwall**:

1. Choose a user name: 2 to 32 letters, digits, dots, dashes or underscores.
2. Choose a password of at least 10 characters and repeat it.
3. Press **Create administrator**.

You are signed in as the first administrator. Setup is only possible while the server has no users.

## Users and roles

There are three roles. The server checks the role on every request; hiding a button in the browser is not what protects an action.

| Role | Can |
|---|---|
| `viewer` | Read only: see the server inventory, the last live read of each server and its push history, and open team projects. |
| `operator` | Everything a viewer can, plus: add, edit and delete servers, read live configurations, push builds and confirm them, save and delete team projects, and see the activity log. |
| `admin` | Everything, including managing users. |

### Manage users

On the **Users** page (admins only):

- **Add a user** with a user name, an **Initial password** (at least 10 characters) and a **Role**. Ask them to change the password after signing in.
- Change a user's role.
- **Reset password** sets a new password and ends the user's sessions.
- Disable or enable a user. Disabling ends their sessions.
- Delete a user.

You cannot delete your own account, and the last enabled administrator cannot be demoted, disabled or deleted.

### Your account

The account chip in the top bar shows who is signed in. From there you can **Change password** (your other sessions are signed out) and **Sign out**.

## Team projects

The project you edit always lives in your browser until you save it to the server. On the **Team projects** page:

- **Save current as new** saves the open project for the team.
- **Open** loads a saved project into your browser. The page then shows "Open now: <name>".
- **Save "<name>"** writes your changes back to the project you opened.
- Delete removes it for everyone.

If a colleague saved the same project after you opened it, your save is refused with "Someone else saved this project after you opened it. Reload it, or save as a new project." Nothing is overwritten silently.

Saving and deleting need the operator role; viewers can open projects.

## Activity

The **Activity** page shows the audit log, newest first: the last 300 entries. It records sign-ins and failed sign-ins (with the client address), sign-outs, password changes, user changes, server inventory changes, approved host keys, live reads, pushes (applied, confirmed, failed) and project saves and deletions. Press **Refresh** to reload it.

## Run as a systemd service

For a long-running instance, run Emberwall as its own unprivileged user with the master key in a file.

1. Create a system user and directories:

   ```sh
   sudo useradd --system --home-dir /var/lib/emberwall-server --create-home --shell /usr/sbin/nologin emberwall
   sudo install -d -m 750 -o root -g emberwall /etc/emberwall-server
   ```

2. Create the master key file, readable only by root and the service:

   ```sh
   head -c 48 /dev/urandom | base64 | sudo tee /etc/emberwall-server/master.key >/dev/null
   sudo chown root:emberwall /etc/emberwall-server/master.key
   sudo chmod 640 /etc/emberwall-server/master.key
   ```

3. Create `/etc/systemd/system/emberwall.service`:

   ```ini
   [Unit]
   Description=Emberwall server
   After=network-online.target
   Wants=network-online.target
   
   [Service]
   User=emberwall
   Group=emberwall
   WorkingDirectory=/var/lib/emberwall-server
   Environment=EMBERWALL_DB=/var/lib/emberwall-server/emberwall.db
   Environment=EMBERWALL_SECRET_FILE=/etc/emberwall-server/master.key
   Environment=EMBERWALL_HOST=127.0.0.1
   Environment=PORT=8787
   # Behind a TLS reverse proxy on the same machine:
   Environment=EMBERWALL_HTTPS=1
   Environment=EMBERWALL_TRUST_PROXY=1
   ExecStart=/usr/local/bin/emberwall serve
   Restart=on-failure
   
   [Install]
   WantedBy=multi-user.target
   ```

   Adjust `ExecStart` if the binary is installed elsewhere. Leave out the last two `Environment` lines if you do not use a reverse proxy.

4. Start it:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now emberwall
   journalctl -u emberwall
   ```

The paths above are only an example. The service needs to read the key file and write the database directory. The example uses `-server` in the names to keep them apart from `/etc/emberwall` and `/var/lib/emberwall`, which guarded push uses on the target servers.

## Put it behind a TLS reverse proxy

Server mode listens on localhost by default. To reach it from other machines, put a reverse proxy with HTTPS in front, keep Emberwall on `127.0.0.1`, and set `EMBERWALL_HTTPS=1`.

Requirements for the proxy:

- **Pass the original `Host` header.** For requests that change data, Emberwall checks that the browser's `Origin` matches the `Host` header, and refuses cross-origin requests.
- **Overwrite `X-Forwarded-For`** with the client address if you set `EMBERWALL_TRUST_PROXY=1`. Emberwall uses the first address in that header for sign-in throttling, so a header passed through from the client could be forged.
- **Allow long requests.** A push waits for the deploy script on the target, which can take up to two minutes.

### nginx

```text
server {
    listen 443 ssl;
    server_name emberwall.example.com;

    ssl_certificate     /etc/ssl/certs/emberwall.example.com.pem;
    ssl_certificate_key /etc/ssl/private/emberwall.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 180s;
    }
}
```

### Caddy

```text
emberwall.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Caddy obtains a certificate and passes the `Host` header by default. Check how your Caddy version handles an `X-Forwarded-For` header sent by the client before you set `EMBERWALL_TRUST_PROXY=1`.

> [!WARNING]
> Do not expose the server directly to the internet. Restrict who can reach the proxy, for example to a VPN or office network.

## Backups

Two things make up a server-mode installation, and you need both to restore it:

| What | Where | Notes |
|---|---|---|
| The database | `EMBERWALL_DB` (default `./data/emberwall.db`) | Users, server inventory with encrypted credentials and pinned host keys, team projects, live-read history, push history, activity log. |
| The master key | `EMBERWALL_SECRET` or `EMBERWALL_SECRET_FILE` | Needed to decrypt the stored SSH credentials. |

The database runs in SQLite's WAL mode, so it may have `-wal` and `-shm` files next to it. To back it up, either stop the service and copy the database file together with those files, or use SQLite's online backup, for example `sqlite3 emberwall.db ".backup emberwall-backup.db"` if the `sqlite3` tool is installed.

> [!WARNING]
> Store the master key separately from database backups. Anyone holding both can decrypt every stored credential. If you lose the master key, users and projects remain, but every server credential has to be entered again.

The server upgrades the database schema itself when a newer version starts. Take a backup before upgrading.
