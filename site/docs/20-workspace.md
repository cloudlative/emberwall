---
title: Workspace
description: Find your way around the Emberwall app - dashboard, command palette, undo and redo, snapshots and semantic diff, share links, JSON import and export, themes, offline use and local storage.
section: Operate
---

This page covers the parts of the app that are not tied to one feature: navigation, history, saving and sharing.

## Layout

The sidebar groups the pages:

| Group | Pages |
|---|---|
| Design | Dashboard, Rules, NAT, Objects, Zones, Blocklists, Kernel hardening |
| Ship | Build, Compare, More targets, Version matrix |
| Verify | Simulator, Reachability, Policy tests, Audit, Compliance, Packet flow, Topology |
| Operate | Fleet, Log analyzer, Assistant |
| Library | Templates, Snapshots, Import / export |
| Team | Servers, Live server, Team projects, Users, Activity (server mode only) |

The top bar holds the project name (click to rename), the **Score** badge, the fleet host selector (when the project has hosts), a failing-tests badge, the target picker, undo and redo, **Search** (the command palette), and the theme toggle.

## Dashboard

The **Dashboard** summarises the open project for the current target:

- the posture score and grade, with the number of findings;
- counts of **Rules**, NAT rules and objects, inbound allowances **Open to the internet**, **Output lines** and **Version fallbacks**;
- **Inbound exposure**: each port the host accepts, its service, protocol, and where it is reachable from;
- **Traffic policy**: the default verdict and rule count per direction;
- **Build target**: each version-dependent feature, available or the version it needs;
- **Top findings** from the audit.

## Command palette

Press **Ctrl+K** (**Cmd+K** on macOS), or the **Search** button, to open the command palette. Type a few words to filter, use the arrow keys to move, **Enter** to run, and **Esc** to close.

It can:

- **Add rule**;
- **Go to** any page;
- **Run the setup wizard**;
- **Undo**, **Redo**, **Toggle light / dark theme**, **Save snapshot**;
- switch the target to any distribution and tool (**Target: ...**);
- **Load template: ...**;
- **Edit rule: ...** for any rule in the project.

## Undo and redo

Every change to the project can be undone.

| Action | Keys |
|---|---|
| Undo | **Ctrl+Z** |
| Redo | **Ctrl+Shift+Z** or **Ctrl+Y** |

On macOS, **Cmd** works in place of **Ctrl**. The shortcuts do not act while you are typing in a text field, so the field's own undo works there. The undo buttons in the top bar do the same.

The history holds the last 60 changes and is kept only for the current page session; reloading the page clears it. Loading a template, an import, a share link, a snapshot or a team project is also a change you can undo.

## Snapshots and semantic diff

A snapshot is a named copy of the project (and the target selection), kept in your browser. Save one before a risky change so you can compare and roll back.

![Snapshots page](shot:snapshots)

- **Save a snapshot:** on the **Snapshots** page, type a name such as "Before opening port 8443" and press **Save snapshot**. From the command palette, **Save snapshot** saves one with a default name ("Snapshot 3").
- **Diff with current:** shows two things for the snapshot against the current project:
  - a line diff of the main output file for the current target;
  - **What changed for traffic**: which access opened or closed, per source, destination and service, for IPv4 and IPv6. If nothing changed for the sources and services the rules mention, it says so.
- **Restore:** replaces the current project with the snapshot. Undo brings the previous state back.
- **Delete** removes the snapshot.

## Share links

A share link carries the whole project and the target selection in the URL itself, after the `#`. Browsers never send that part to a server.

- To create one, press **Share link** on the **Build** page or **Copy share link** under **Share link** on the **Import / export** page.
- Opening a share link replaces the open project with the shared one (undo brings yours back), and the data is removed from the address bar.

> [!WARNING]
> Anyone with the link sees the ruleset. Treat it like the ruleset itself.

## Import and export JSON

The **Project file** panel on the **Import / export** page saves and opens the whole project, with every rule, object and option.

- **Export JSON** downloads `<project-name>.emberwall.json`.
- **Open JSON…** loads such a file and replaces the current project.

These are the files the [CLI](doc:cli) reads. See [Project file format](doc:project-format). To import an iptables, nftables, ufw or firewalld configuration instead, see [Import and migration](doc:import).

## Themes

Emberwall has a dark theme (the default) and a light theme. Switch with the sun/moon button in the top bar or **Toggle light / dark theme** in the command palette. Your choice is remembered.

![Dashboard in the light theme](shot:dashboard-light)

## Offline use

After the first visit, the app opens without a network. It is installable as an app from your browser. Only the [assistant](doc:assistant) and [server mode](doc:server-mode) need a connection. See [Install](doc:install#web-app).

## What is stored in your browser

| Key | Contents |
|---|---|
| `emberwall` (local storage) | The open project, target selection, snapshots, theme and current page |
| `emberwall-welcome-seen` (local storage) | Set once the setup wizard has been finished or skipped |
| `emberwall-ai-key` | Your Anthropic API key, only if you entered one: in session storage, or in local storage when **Remember on this device** is ticked |

Apart from the offline copy of the app itself, the web app keeps nothing else, and none of it is sent anywhere. Clearing the site data for Emberwall removes all of it. Export important projects as JSON, or save them as [team projects](doc:server-mode#team-projects) in server mode.
