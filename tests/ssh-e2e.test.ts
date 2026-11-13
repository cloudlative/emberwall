// Guarded push against a real OpenSSH server, one private network namespace per firewall tool.
//
// Each "server" is a network namespace joined to the test by a veth pair, running the system's
// sshd. The SSH traffic itself crosses the firewall being pushed, so a ruleset that locks SSH out
// really does lock Emberwall out, and the server has to roll itself back.
//
// Opt-in: it needs root, sshd, ip and the firewall tools, and it writes to /etc/emberwall,
// /var/lib/emberwall and (for ufw) /etc/ufw on the machine running the tests.
//   EMBERWALL_E2E_SSH=1 npx vitest run tests/ssh-e2e.test.ts
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ssh2 from 'ssh2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../server/app';
import { openDb } from '../server/db';
import { Vault } from '../server/secrets';
import { compile, fileText } from '../src/core/compile';
import { terraformModule } from '../src/core/compile/iac';
import { emptyProject, newRule, type Project } from '../src/core/model';
import { resolveTarget, type Tool } from '../src/core/targets';

const has = (cmd: string) => spawnSync('sh', ['-c', `command -v ${cmd}`]).status === 0;
const enabled =
  process.env.EMBERWALL_E2E_SSH === '1' && process.getuid?.() === 0 && existsSync('/usr/sbin/sshd') && has('ip') && has('nsenter') && has('unshare');

const tmp = mkdtempSync(join(tmpdir(), 'emberwall-e2e-'));
const userKey = ssh2.utils.generateKeyPairSync('ed25519', { comment: 'emberwall-e2e' });

interface Target {
  ip: string;
  pid: number;
  run: (cmd: string) => { code: number; out: string };
  stop: () => void;
}

const started: Target[] = [];

/** A namespace with its own sshd on 10.77.<n>.2, reachable from the test at 10.77.<n>.1. */
async function startTarget(n: number): Promise<Target> {
  const holder: ChildProcess = spawn('unshare', ['-n', 'sleep', '3600'], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 200));
  const pid = holder.pid!;
  const sh = (c: string) => {
    const r = spawnSync('sh', ['-c', c], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`${c}: ${r.stderr}`);
  };
  const run = (cmd: string) => {
    const r = spawnSync('nsenter', ['-t', String(pid), '-n', 'sh', '-c', cmd], { encoding: 'utf8' });
    return { code: r.status ?? 1, out: (r.stdout ?? '') + (r.stderr ?? '') };
  };
  const host = `ewe${n}h`;
  spawnSync('ip', ['link', 'del', host]);
  sh(`ip link add ${host} type veth peer name ewe${n}t && ip link set ewe${n}t netns ${pid}`);
  sh(`ip addr add 10.77.${n}.1/30 dev ${host} && ip link set ${host} up`);
  const inside = run(`ip link set lo up && ip addr add 10.77.${n}.2/30 dev ewe${n}t && ip link set ewe${n}t up`);
  if (inside.code !== 0) throw new Error(inside.out);

  const dir = join(tmp, `sshd${n}`);
  mkdirSync(dir, { recursive: true });
  mkdirSync('/run/sshd', { recursive: true });
  sh(`ssh-keygen -q -t ed25519 -N '' -f ${dir}/host_key`);
  writeFileSync(join(dir, 'authorized_keys'), `${userKey.public}\n`, { mode: 0o600 });
  writeFileSync(
    join(dir, 'sshd_config'),
    [
      'ListenAddress 0.0.0.0',
      'Port 22',
      `HostKey ${dir}/host_key`,
      `AuthorizedKeysFile ${dir}/authorized_keys`,
      'PermitRootLogin prohibit-password',
      'PasswordAuthentication no',
      'KbdInteractiveAuthentication no',
      'StrictModes no',
      'UsePAM no',
      `PidFile ${dir}/sshd.pid`,
    ].join('\n') + '\n',
  );
  const sshd = spawn('nsenter', ['-t', String(pid), '-n', '/usr/sbin/sshd', '-D', '-e', '-f', join(dir, 'sshd_config')], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 500));
  const t: Target = {
    ip: `10.77.${n}.2`,
    pid,
    run,
    stop: () => {
      sshd.kill();
      holder.kill();
      spawnSync('ip', ['link', 'del', host]);
    },
  };
  started.push(t);
  return t;
}

let http: HttpServer;
let base = '';
let cookie = '';

async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, {
    method,
    headers: { ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Emberwall': '1' }), ...(cookie ? { Cookie: cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const set = res.headers.get('set-cookie');
  if (set) cookie = set.split(';')[0];
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Allows SSH and a marker port; everything else inbound is dropped. */
function good(tag: string): Project {
  const p = emptyProject(`e2e ${tag}`);
  p.rules = [newRule({ name: 'ssh', proto: 'tcp', ports: ['22'] }), newRule({ name: `marker ${tag}`, proto: 'tcp', ports: ['7001'], comment: `marker-${tag}` })];
  return p;
}

/** Drops everything inbound except the marker port: new SSH connections cannot get in. */
function lockout(tag: string): Project {
  const p = emptyProject(`e2e lockout ${tag}`);
  p.rules = [newRule({ name: `lockout ${tag}`, proto: 'tcp', ports: ['7002'] })];
  return p;
}

// The ufw and firewalld cases change those tools' config files; put them back afterwards.
const KEEP = ['/etc/ufw', '/etc/firewalld', '/etc/default/ufw'].filter((x) => existsSync(x));

beforeAll(async () => {
  if (!enabled) return;
  for (const [i, path] of KEEP.entries()) spawnSync('cp', ['-a', path, join(tmp, `keep-${i}`)]);
  const db = openDb(':memory:');
  const app = createApp({ db, vault: new Vault('e2e-master-key-0123456789-abcdefghijklmnop') });
  http = createServer((req, res) => void app(req, res));
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  expect((await call('POST', '/api/setup', { username: 'admin', password: 'correct horse battery' })).status).toBe(200);
});

afterAll(() => {
  http?.close();
  for (const t of started) t.stop();
  if (!enabled) return;
  for (const [i, path] of KEEP.entries()) {
    if (!existsSync(join(tmp, `keep-${i}`))) continue;
    spawnSync('rm', ['-rf', path]);
    spawnSync('cp', ['-a', join(tmp, `keep-${i}`), path]);
  }
});

/** Adds the server, accepts its host key, and returns its id and detected build target. */
async function enroll(name: string, t: Target) {
  const created = await call('POST', '/api/servers', { name, host: t.ip, port: 22, username: 'root', authKind: 'key', secret: userKey.private });
  expect(created.status, JSON.stringify(created.body)).toBe(200);
  const id = created.body.id as number;
  const first = await call('POST', `/api/servers/${id}/probe`, {});
  expect(first.status, JSON.stringify(first.body)).toBe(409);
  expect(first.body.code).toBe('host_key');
  const ok = await call('POST', `/api/servers/${id}/probe`, { trustFingerprint: first.body.fingerprint });
  expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  return id;
}

/** Push, confirm over a new connection; then push a lockout and wait for the server to undo it. */
async function pushCycle(tool: Tool, t: Target, name: string, show: string, marker: RegExp) {
  const id = await enroll(name, t);
  const probe = await call('POST', `/api/servers/${id}/probe`, {});
  const { detect } = await import('../src/core/live');
  const d = detect(probe.body.output);
  expect(d.activeTool, d.reason).toBe(tool);
  expect(d.isRoot).toBe(true);

  // 1) a ruleset that keeps SSH open: confirmed over a fresh connection, and it stays
  const a = await call('POST', `/api/servers/${id}/deploy`, { project: good(tool), selection: d.selection, timeoutSeconds: 30, confirmName: name });
  expect(a.body.status, a.body.log ?? a.body.error).toBe('pending');
  expect(t.run(show).out).toMatch(marker);
  const confirmed = await call('POST', `/api/deployments/${a.body.id}/confirm`, {});
  expect(confirmed.body.status, JSON.stringify(confirmed.body)).toBe('confirmed');
  await sleep(1500);
  expect(t.run(show).out).toMatch(marker);

  // 2) a ruleset that shuts SSH out: the confirmation cannot connect, and the server rolls back
  const b = await call('POST', `/api/servers/${id}/deploy`, { project: lockout(tool), selection: d.selection, timeoutSeconds: 20, confirmName: name });
  expect(b.body.status, b.body.log ?? b.body.error).toBe('pending');
  expect(t.run(show).out).not.toMatch(marker);
  const started = Date.now();
  const refused = await call('POST', `/api/deployments/${b.body.id}/confirm`, {});
  expect(refused.status, JSON.stringify(refused.body)).toBe(502);
  expect(refused.body.error).toMatch(/roll back on its own/);
  await sleep(Math.max(0, 20_000 - (Date.now() - started)) + 6000);
  expect(t.run(show).out, 'the confirmed ruleset is back').toMatch(marker);
  const again = await call('POST', `/api/servers/${id}/probe`, {});
  expect(again.status, 'SSH works again after the rollback').toBe(200);
  const list = (await call('GET', `/api/deployments?server=${id}`)).body as { id: number; status: string }[];
  expect(list.find((x) => x.id === a.body.id)!.status).toBe('confirmed');
  expect(list.find((x) => x.id === b.body.id)!.status).toBe('expired');
}

describe.skipIf(!enabled)('guarded push over real OpenSSH', () => {
  it('nftables', async () => {
    const t = await startTarget(1);
    await pushCycle('nftables', t, 'nft-box', 'nft list ruleset', /dport 7001/);
  }, 120_000);

  it.skipIf(!has('iptables-restore'))('iptables', async () => {
    const t = await startTarget(2);
    // Make iptables the manager in charge: some rules loaded, no native nftables table.
    expect(t.run('iptables -A INPUT -p tcp --dport 22 -j ACCEPT').code).toBe(0);
    await pushCycle('iptables', t, 'ipt-box', 'iptables-save', /--dport 7001/);
  }, 120_000);

  it.skipIf(!has('ufw'))('ufw', async () => {
    const t = await startTarget(3);
    expect(t.run('ufw --force enable && ufw allow 22/tcp').code).toBe(0);
    await pushCycle('ufw', t, 'ufw-box', 'ufw status', /7001\/tcp/);
  }, 150_000);

  // firewalld needs its daemon (and the system D-Bus) running inside the namespace.
  const fwVersion = spawnSync('firewall-cmd', ['--version'], { encoding: 'utf8' });
  const canFirewalld = has('firewalld') && has('dbus-daemon') && /FirewallD is not running|^\d/m.test(`${fwVersion.stdout ?? ''}${fwVersion.stderr ?? ''}`);
  it.skipIf(!canFirewalld)('firewalld', async () => {
    const t = await startTarget(4);
    if (!existsSync('/run/dbus/system_bus_socket')) {
      mkdirSync('/run/dbus', { recursive: true });
      spawnSync('dbus-daemon', ['--system', '--fork']);
    }
    const fwd = spawn('nsenter', ['-t', String(t.pid), '-n', 'firewalld', '--nofork', '--nopid'], { stdio: 'ignore' });
    try {
      let state = '';
      for (let i = 0; i < 40 && !/running/.test(state); i += 1) {
        await sleep(500);
        state = t.run('firewall-cmd --state').out;
      }
      expect(state).toMatch(/running/);
      await pushCycle('firewalld', t, 'fwd-box', 'firewall-cmd --list-all', /7001\/tcp/);
    } finally {
      fwd.kill();
    }
  }, 180_000);

  // The Terraform export pushes over SSH with no rollback; apply it for real and check the result.
  it.skipIf(!has('terraform'))('terraform SSH push', async () => {
    const cases: [Tool, number, string, RegExp, string][] = [
      ['nftables', 5, 'nft list ruleset', /dport 7001/, '1.0.9'],
      ['iptables', 6, 'iptables-save', /--dport 7001/, '1.8.10'],
    ];
    for (const [tool, n, show, marker, version] of cases) {
      const t = await startTarget(n);
      const dir = join(tmp, `tf-${tool}`);
      mkdirSync(dir, { recursive: true });
      const keyFile = join(dir, 'id_ed25519');
      writeFileSync(keyFile, userKey.private, { mode: 0o600 });
      writeFileSync(join(dir, 'main.tf'), fileText(terraformModule(compile(good(tool), resolveTarget({ distro: 'custom', tool, version })))));
      const tf = (args: string[]) => spawnSync('terraform', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, TF_IN_AUTOMATION: '1' } });
      const init = tf(['init', '-input=false', '-no-color']);
      expect(init.status, init.stderr).toBe(0);
      const apply = tf(['apply', '-auto-approve', '-input=false', '-no-color', `-var=host=${t.ip}`, `-var=private_key_path=${keyFile}`]);
      expect(apply.status, apply.stdout.slice(-2000) + apply.stderr).toBe(0);
      expect(t.run(show).out, tool).toMatch(marker);
    }
  }, 180_000);
});
