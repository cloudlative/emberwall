---
title: Assistant
description: The optional Emberwall assistant drafts rules from plain English and answers questions about your ruleset, using your own Anthropic API key. What is sent, where the key is stored, and how proposals are checked.
section: Operate
---

The assistant is optional. With your own Anthropic API key, you can describe a policy in plain English and review the rules it proposes, or ask a question about the current ruleset. It stays off until you add a key.

![Assistant page](shot:assistant)

## Add your key

1. Open **Assistant** in the sidebar (under *Operate*).
2. Paste your key into **Anthropic API key** (it starts with `sk-ant-`).
3. Optionally tick **Remember on this device**.

Where the key is kept:

| Remember on this device | Storage | Lifetime |
|---|---|---|
| off (default) | the tab's session storage | Forgotten when the tab closes |
| on | the browser's local storage | Kept until you press **Forget key** or clear the site data |

**Forget key** removes it from both places. The key is sent only to the Anthropic API, from your browser. It never goes to an Emberwall server, including in [server mode](doc:server-mode).

## Propose rules

1. Choose **Propose rules**.
2. Describe what you want, for example: "Allow the monitoring server 10.30.0.5 to scrape node exporter, and let the office network reach the admin panel on 8443 during work hours only."
3. Press **Propose rules**.

The answer has a short summary, warnings about risks or assumptions, and the proposed rules. Nothing is added until you choose:

- Tick **Include** for the rules you want.
- Press **Add *N* selected** to append them to the project, or **Discard**.

Adding rules is a normal edit; **Ctrl+Z** undoes it.

Proposals are checked by the same validation as hand-written rules, and any problem is shown next to the rule. At most 40 rules are taken from one answer. The assistant can only set these fields: name, direction, action, protocol, ports, source, destination, interfaces, zones (only zones that exist in the project), logging, a per-client rate limit per minute, and a connection limit.

> [!TIP]
> Treat proposals like a colleague's draft. Check them in the [simulator](doc:simulator), run the [audit](doc:audit-and-compliance), and add [policy tests](doc:policy-tests) for anything important.

## Ask about the ruleset

Choose **Ask about this ruleset**, type a question such as "Can anything on the internet reach the database?", and send it. The answer streams in as plain text. If the answer depends on things the project does not show (the network outside the host, which services are running), the assistant is instructed to say so.

Check answers against the simulator before relying on them.

## Exactly what is sent

Press **See exactly what is sent** to view the JSON that goes with each request. Each request contains:

- that JSON, describing the project;
- your typed request or question;
- a fixed instruction text.

The JSON holds the project's:

- name, default policies and options;
- zones (id, name, interfaces, networks, trust);
- address groups and port groups;
- rules, with their position in the list, without internal ids;
- NAT rules, without internal ids;
- attack protection settings;
- blocklists, as name, enabled flag, **number** of entries and download URL (not the addresses themselves).

Snapshots, policy tests, hosts and the API key itself are not part of the JSON. The key is used to authenticate the request.

The request goes from your browser straight to the Anthropic API. The app's offline cache never stores these requests.

## Errors

The page explains common failures:

- the key was rejected, or is not allowed to use the model;
- rate limited by the API (wait and retry);
- `api.anthropic.com` could not be reached from the browser, for example because of the network or a content blocker;
- the model declined the request, or the answer was cut off (try a narrower request).

## Limits

- The assistant needs a network connection, unlike the rest of the app.
- Its API calls have been type-checked against the official SDK and its output validation is unit-tested, but it has not been exercised against the live API in Emberwall's own tests.
