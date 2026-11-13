---
title: Policy tests
description: Write assertions such as "the database is never public" that Emberwall checks on every change, in the app and in CI.
section: Verify
---

A policy test is a statement about your firewall that must stay true, such as "Telnet from the internet is blocked" or "the database is not public". Emberwall checks every test on every change. A later edit that breaks one shows up at once.

![Policy tests page](shot:tests)

## How a test works

A test is a packet plus an expected result:

- **Packet:** direction, source and destination address, protocol (TCP, UDP or ICMP), port, connection state, and optionally the inbound or outbound interface and ICMP type.
- **Expectation:** *accepted* or *blocked*.

Emberwall runs the packet through the [simulator](doc:simulator). A test passes when the verdict matches: *accepted* means the packet is accepted; *blocked* means it is dropped or rejected. A test whose packet cannot be simulated (for example, an invalid address) fails.

## Add tests

On the **Policy tests** page:

- **Telnet blocked** adds "Telnet from the internet is blocked": inbound TCP to port 23 from an outside address, expected blocked.
- **DB not public** adds "Database is not public": inbound TCP to port 5432 from an outside address, expected blocked.
- **New from simulator** opens the simulator. Describe a packet there and press **Save as test**. The test expects the verdict the packet has right now.

For each test you can edit the **Test name**, switch the expectation between **accepted** and **blocked**, or delete it.

> [!TIP]
> Write tests for the guarantees that matter before a risky change: "SSH from the admin network is accepted", "nothing reaches port 6379 from the internet". Then edit freely.

## Where failures show up

A failing test explains itself, for example "Expected blocked, but the verdict is accept (rule "Any from LAN")", with a link to the rule.

Failures also appear:

- as a red badge on **Policy tests** in the sidebar and a "*N* tests failing" badge in the top bar;
- in the **Audit**, as a high-severity finding (*N* policy tests fail), which lowers the score;
- in the *Changes are validated against stated expectations* control of the PCI DSS-style and internet-server [compliance profiles](doc:audit-and-compliance#compliance-profiles). That control fails when no tests exist at all.

## Run tests in CI

Tests are stored in the project file, so the CLI can run them:

```sh
emberwall test project.json
```

It prints `PASS` or `FAIL` for each test and a summary such as `3/4 passed`, and exits with status 1 if any test fails. A project without tests prints `no policy tests in this project` and exits 0. See [CLI](doc:cli).

## Tests and fleets

The **Policy tests** page and the CLI run tests against the shared project. In a [fleet](doc:fleet), to see how a packet fares on one host, pick that host in the top bar and use the simulator.
