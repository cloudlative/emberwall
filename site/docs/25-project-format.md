---
title: Project file format
description: Reference for the Emberwall project JSON file - every field of the project, rules, NAT, groups, zones, protections, blocklists, policy tests and fleet hosts, with types, defaults and a full example.
section: Reference
---

A project file is the JSON you get from **Export JSON** on the **Import / export** page. The [CLI](doc:cli) reads the same files, and server mode stores team projects in this format.

## Loading rules

When a file is opened (in the app, on the CLI or in server mode), Emberwall fills in anything missing:

- The file must be a JSON object with a `rules` array. Anything else is refused with a readable reason ("Not a project object", "Missing \"rules\" array").
- Missing top-level fields take the defaults below. `policies` and `options` are merged with the defaults, so you can set only the keys you need.
- Missing ids are generated.
- Every value is validated again when the project is built; see [Validation](doc:rules#validation-and-input-hardening).

## Top level

| Field | Type | Default | Meaning |
|---|---|---|---|
| `schema` | `1` | `1` | Format version. |
| `name` | string | `"Imported firewall"` when missing | Project name. Used in comments in the output. |
| `description` | string | `""` | Free text. |
| `policies` | object | see [policies](#policies) | Default policy per direction. |
| `options` | object | see [options](#options) | Baseline options. |
| `rules` | array of [Rule](#rule) | required | Filter rules, in evaluation order. |
| `nat` | array of [NatRule](#natrule) | `[]` | NAT rules. |
| `addressGroups` | array of [AddressGroup](#addressgroup) | `[]` | Reusable address lists. |
| `portGroups` | array of [PortGroup](#portgroup) | `[]` | Reusable port lists. |
| `zones` | array of [Zone](#zone) | `[]` | Named network sides. |
| `protections` | [Protections](#protections) | `{}` | Attack protection. |
| `blocklists` | array of [Blocklist](#blocklist) | `[]` | Address sets dropped before all rules. |
| `hardening` | array of string | `[]` | Ids of enabled kernel hardening settings. See [hardening](#hardening). |
| `tests` | array of [PolicyTest](#policytest) | `[]` | Policy tests. |
| `hosts` | array of [Host](#host) | `[]` | Fleet hosts. |

## policies

An object with one entry per direction. Each value is `"accept"` or `"drop"`.

| Key | Default |
|---|---|
| `in` | `"drop"` |
| `out` | `"accept"` |
| `forward` | `"drop"` |

## options

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allowLoopback` | boolean | `true` | Accept traffic on `lo`. |
| `allowEstablished` | boolean | `true` | Accept established and related traffic. |
| `dropInvalid` | boolean | `true` | Drop packets with an invalid connection state. |
| `allowIcmp` | boolean | `true` | Accept ping and the ICMPv6 types IPv6 needs. |
| `logDropped` | boolean | `false` | Log packets dropped by a default policy (rate-limited). |
| `ipv6` | boolean | `true` | When `false`, all IPv6 traffic except loopback is dropped. |
| `forwarding` | boolean | `false` | The host routes packets between interfaces. |

## Rule

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | generated | Unique id. Used by host scoping, overrides and line linking. |
| `name` | string | `"New rule"` | Rule name. |
| `enabled` | boolean | `true` | Disabled rules are left out of the output. |
| `direction` | `"in"` \| `"out"` \| `"forward"` | `"in"` | Direction. |
| `action` | `"accept"` \| `"drop"` \| `"reject"` | `"accept"` | Verdict. |
| `proto` | `"any"` \| `"tcp"` \| `"udp"` \| `"tcpudp"` \| `"icmp"` | `"tcp"` | Protocol. `tcpudp` is TCP and UDP. |
| `family` | `"both"` \| `"ipv4"` \| `"ipv6"` | `"both"` | Address families. |
| `src` | array of string | `[]` | Source addresses or CIDRs, or `"@<addressGroupId>"`. Empty means any. |
| `dst` | array of string | `[]` | Destination addresses, same format. |
| `ports` | array of string | `[]` | Destination ports: `"22"`, `"8000:8100"` (or `"8000-8100"`), or `"@<portGroupId>"`. Empty means any. Only used for TCP and UDP. |
| `inIface` | string | none | Inbound interface: up to 15 letters, digits, `_`, `.` or `-`, optionally followed by `+`. |
| `outIface` | string | none | Outbound interface, same format. |
| `states` | array of `"new"` \| `"established"` \| `"related"` \| `"invalid"` | none | Connection states to match. Missing or empty matches every state. |
| `icmpType` | string | none | For `proto: "icmp"`: `echo-request`, `echo-reply`, `destination-unreachable`, `time-exceeded` or `parameter-problem`. Missing means every type. |
| `log` | boolean | none | Log every match. |
| `rateLimit` | [RateLimit](#ratelimit) | none | Rate limit for accept rules. |
| `comment` | string | none | Free text. Used in the pf and Windows outputs. |
| `srcPorts` | array of string | none | Source ports (TCP/UDP), same format as `ports`. |
| `srcMac` | string | none | Source MAC address, `aa:bb:cc:dd:ee:ff`. |
| `connLimit` | integer | none | Maximum concurrent connections per client (1 to 1,000,000). |
| `schedule` | [Schedule](#schedule) | none | Weekly time window. |
| `mark` | string | none | Packet mark: hexadecimal `0x1` (up to 8 hex digits) or decimal. |
| `srcZone` | string | none | Zone id; expands to the zone's interfaces and networks. Used on inbound and forward rules. |
| `dstZone` | string | none | Zone id. Used on outbound and forward rules. |
| `hosts` | array of string | none | Host ids the rule is limited to. Missing or empty means every host. |

### RateLimit

| Field | Type | Meaning |
|---|---|---|
| `rate` | integer (1 to 1,000,000) | Allowed rate. |
| `per` | `"second"` \| `"minute"` \| `"hour"` | Time unit. |
| `burst` | integer (1 to 1,000,000) | Burst size. |
| `perSource` | boolean, optional | Count each client separately; clients over the rate are dropped. |

### Schedule

| Field | Type | Meaning |
|---|---|---|
| `days` | array of `"Mon"` ... `"Sun"` | Days the rule is active. Empty means every day. |
| `from` | string `"HH:MM"` | Start, in the firewall host's kernel time (UTC unless configured otherwise). |
| `to` | string `"HH:MM"` | End. |

## NatRule

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | generated | Unique id. |
| `name` | string | `"New NAT rule"` | Name. |
| `enabled` | boolean | `true` | On or off. |
| `kind` | `"masquerade"` \| `"snat"` \| `"dnat"` | `"masquerade"` | `dnat` is a port forward. |
| `proto` | `"any"` \| `"tcp"` \| `"udp"` | `"any"` | Protocol. |
| `iface` | string | none | Outbound interface for masquerade and SNAT; inbound interface for DNAT. |
| `src` | string | none | Source address or CIDR to match. |
| `dst` | string | none | Destination address or CIDR to match. |
| `port` | string | none | Destination port to match (DNAT). |
| `toAddr` | string | none | Address to translate to: the internal host for DNAT, the new source for SNAT. A single address, not a network. |
| `toPort` | string | none | Port to translate to (DNAT). Missing means the same port. |
| `randomFully` | boolean | none | Fully randomise source ports (masquerade and SNAT). |
| `comment` | string | none | Free text. |

The address family of a NAT rule comes from the first address set in `toAddr`, `src` or `dst`; without any, it is IPv4.

## AddressGroup

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Referenced from rules as `"@<id>"`. |
| `name` | string | Display name. |
| `members` | array of string | IPv4 and IPv6 addresses and CIDRs. |

## PortGroup

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Referenced from rules as `"@<id>"`. |
| `name` | string | Display name. |
| `ports` | array of string | Ports and ranges. |

## Zone

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | generated | Referenced from rules in `srcZone` / `dstZone`. |
| `name` | string | `"zone"` | Display name. |
| `interfaces` | array of string | `[]` | Interfaces of the zone. |
| `networks` | array of string | `[]` | Networks behind the zone. |
| `trust` | `"untrusted"` \| `"dmz"` \| `"trusted"` | `"untrusted"` | Shown as Outside, DMZ and Trusted in the app. |

## Protections

All fields are optional; a missing field means the protection is off.

| Field | Type | Meaning |
|---|---|---|
| `synFlood` | `{ "rate": integer, "burst": integer }` | Drop clients opening new TCP connections faster than `rate` per second. |
| `portScan` | boolean | Drop TCP packets with flag combinations only scanners send. |
| `autoBan` | `{ "ports": string[], "seconds": integer }` | Clients touching one of the TCP `ports` are dropped for `seconds` (1 to 31,536,000). |

## Blocklist

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | generated | Unique id. |
| `name` | string | `"blocklist"` | Name. Also used to name the kernel sets. |
| `enabled` | boolean | `true` | On or off. |
| `entries` | array of string | `[]` | Addresses and CIDRs kept in the project. |
| `url` | string | none | Optional `http(s)` URL of a list to download on the firewall host, one address or CIDR per line. |
| `outbound` | boolean | none | Also block traffic going to these addresses. |

## hardening

An array of kernel hardening setting ids:

| Id | Recommended |
|---|---|
| `rp_filter` | yes |
| `syncookies` | yes |
| `no_redirects` | yes |
| `no_send_redirects` | yes |
| `no_source_route` | yes |
| `icmp_hygiene` | yes |
| `log_martians` | no |
| `rfc1337` | no |
| `conntrack_strict` | no |

See [Kernel hardening](doc:protection#kernel-hardening) for what each one sets.

## PolicyTest

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique id (generated when missing). |
| `name` | string | Test name. |
| `packet` | object | The packet; required, tests without it are dropped. |
| `packet.direction` | `"in"` \| `"out"` \| `"forward"` | Direction. |
| `packet.src` | string | Source address. |
| `packet.dst` | string | Destination address (same family as `src`). |
| `packet.proto` | `"tcp"` \| `"udp"` \| `"icmp"` | Protocol. |
| `packet.port` | integer, optional | Destination port. |
| `packet.inIface` | string, optional | Inbound interface. |
| `packet.outIface` | string, optional | Outbound interface. |
| `packet.state` | `"new"` \| `"established"` \| `"related"` \| `"invalid"` | Connection state. |
| `packet.icmpType` | string, optional | ICMP type; `echo-request` when missing. |
| `expect` | `"accept"` \| `"block"` | Expected result. `block` passes for drop and reject. |

## Host

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | generated | Referenced from rules in `hosts`. |
| `name` | string | `"host"` | Host name; also the directory name in the fleet bundle. |
| `address` | string | none | Address or DNS name for the Ansible inventory. |
| `note` | string | none | Free text. |
| `target` | object | required | Hosts without a target are dropped. |
| `target.distro` | string | `"custom"` | A distribution id from `emberwall targets`, or `"custom"`. |
| `target.tool` | `"nftables"` \| `"iptables"` \| `"ufw"` \| `"firewalld"` | | Firewall tool. |
| `target.version` | string | `""` | Tool version; used when `distro` is `"custom"`. |
| `overrides` | object | none | Where this host differs. |
| `overrides.policies` | object | none | Any of `in`, `out`, `forward` set to `"accept"` or `"drop"`. |
| `overrides.options` | object | none | Any [option](#options) set to `true` or `false`. |
| `overrides.excludeRules` | array of string | none | Ids of shared rules this host leaves out. |

## Full example

```json
{
  "schema": 1,
  "name": "Web server",
  "description": "Public HTTPS, SSH from the admin network only.",
  "policies": { "in": "drop", "out": "accept", "forward": "drop" },
  "options": {
    "allowLoopback": true,
    "allowEstablished": true,
    "dropInvalid": true,
    "allowIcmp": true,
    "logDropped": true,
    "ipv6": true,
    "forwarding": false
  },
  "addressGroups": [
    { "id": "admins", "name": "Admin networks", "members": ["203.0.113.0/24", "2001:db8:10::/48"] }
  ],
  "portGroups": [
    { "id": "web", "name": "Web", "ports": ["80", "443"] }
  ],
  "rules": [
    {
      "id": "r_ssh",
      "name": "SSH from admins",
      "enabled": true,
      "direction": "in",
      "action": "accept",
      "proto": "tcp",
      "family": "both",
      "src": ["@admins"],
      "dst": [],
      "ports": ["22"],
      "rateLimit": { "rate": 10, "per": "minute", "burst": 20, "perSource": true }
    },
    {
      "id": "r_web",
      "name": "HTTP + HTTPS",
      "enabled": true,
      "direction": "in",
      "action": "accept",
      "proto": "tcp",
      "family": "both",
      "src": [],
      "dst": [],
      "ports": ["@web"],
      "connLimit": 100
    },
    {
      "id": "r_smtp",
      "name": "Block SMTP out",
      "enabled": true,
      "direction": "out",
      "action": "reject",
      "proto": "tcp",
      "family": "both",
      "src": [],
      "dst": [],
      "ports": ["25"]
    }
  ],
  "nat": [],
  "zones": [],
  "protections": {
    "portScan": true,
    "autoBan": { "ports": ["23", "3389"], "seconds": 3600 }
  },
  "blocklists": [
    { "id": "bl_bad", "name": "Known bad", "enabled": true, "entries": ["198.18.0.0/15"] }
  ],
  "hardening": ["rp_filter", "syncookies", "no_redirects", "no_send_redirects", "no_source_route", "icmp_hygiene"],
  "tests": [
    {
      "id": "t_db",
      "name": "Database is not public",
      "packet": { "direction": "in", "src": "198.51.100.20", "dst": "192.0.2.10", "proto": "tcp", "port": 5432, "state": "new" },
      "expect": "block"
    }
  ],
  "hosts": []
}
```

Build it from the command line:

```sh
emberwall build project.json --target debian-12:nftables
```
