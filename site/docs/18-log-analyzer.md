---
title: Log analyzer
description: Paste kernel firewall logs into Emberwall to see the top sources and ports, what the current ruleset would do with them, and block or allow in one click.
section: Operate
---

The log analyzer reads kernel firewall log lines and shows who is knocking and on which ports. It also tells you what the current ruleset would do with each packet. Parsing happens in the page; nothing is uploaded.

![Log analyzer](shot:logs)

## Get log lines

First, make the firewall write log lines:

- Turn on **Log dropped** in the baseline panel on the **Rules** page. Packets dropped by a default policy are then logged with the prefix `ew-drop-in: `, `ew-drop-out: ` or `ew-drop-forward: ` (rate-limited to 5 per minute, burst 10).
- Turn on **Log matches** on individual rules. Their lines carry the prefix `ew-<rule-name>: `.

Then collect the lines on the server, for example from `journalctl -k`, `/var/log/kern.log` or `ufw.log`:

```sh
journalctl -k --since today | grep ' SRC='
```

The analyzer understands the iptables `LOG`, nftables `log` and ufw formats: any line with `SRC=`, `DST=` and a TCP, UDP or ICMP `PROTO=` field.

## Analyze them

1. Open **Log analyzer** in the sidebar (under *Operate*).
2. Paste the lines into **Log lines**. **Paste sample** fills in an example.
3. The panel shows how many lines were parsed and how many were not recognised, and a count per log prefix.

The direction of each packet is taken from the `IN=` and `OUT=` fields: both set means forwarded, only `OUT=` means outbound, otherwise inbound.

### Top sources

The addresses with the most logged packets, with the number of packets and the number of different ports each one tried. Sources that tried three or more ports are marked **scan-like**.

Press **Block** to add the address to a blocklist named "From logs". The list is created the first time and enabled if it was off.

### Top destination ports

What the logged packets were trying to reach: port, service name, packet count, number of sources, and **Now**, what the current ruleset would do with such a packet (computed with the simulator, as a new connection). Hover over the verdict to see which rule or policy decides it.

For ports the ruleset does not accept, **Allow** adds an inbound rule named "Allow tcp/8080 (from logs)" (with the actual protocol and port) at the end of the rule list.

> [!WARNING]
> Only allow a port if it is a service you mean to offer. Logged traffic is mostly probes.

Both lists show the top 15 entries.

## Tips

- Review the new rule or blocklist entry in **Rules** or **Blocklists** before you build. **Open blocklists** takes you there.
- Logged lines record what was dropped by the ruleset that was running then. **Now** shows what the project you have open would do, so you can check that a change has the intended effect.
