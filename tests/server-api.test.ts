// End-to-end tests of the server: real HTTP, real SSH (an in-process SSH server), and where the
// environment allows it, real nft inside a private network namespace.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ssh2 from 'ssh2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../server/app';
import { ABSOLUTE_MS, IDLE_MS, createSession, hashPassword, sessionUser, Throttle, verifyPassword } from '../server/auth';
import { openDb, type Db } from '../server/db';
import { Vault } from '../server/secrets';
import { fingerprintOf } from '../server/ssh';
import { detect, readLiveConfig } from '../src/core/live';
import { TEMPLATES } from '../src/core/templates';

const { Server: SshServer, utils } = ssh2;
const tmp = mkdtempSync(join(tmpdir(), 'emberwall-api-'));
const hostKey = utils.generateKeyPairSync('ed25519');
const otherHostKey = utils.generateKeyPairSync('ed25519');
const userKey = utils.generateKeyPairSync('ed25519');
const SECRET = 'test-master-key-0123456789-abcdefghijklmnop';

// A private network namespace kept alive by a sleeping process; every SSH command runs inside it.
const canNetns = spawnSync('unshare', ['-n', 'nft', 'list', 'ruleset']).status === 0 && spawnSync('which', ['nsenter']).status === 0;
let holder: ChildProcess | null = null;
let fakeUid: string | null = null;
const commandsSeen: string[] = [];

function startSsh(key: string): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = new SshServer({ hostKeys: [key] }, (client) => {
      client.on('authentication', (ctx) => {
        if (ctx.username === 'ops' && ctx.method === 'password' && ctx.password === 'correct horse') return ctx.accept();
        if (ctx.username === 'ops' && ctx.method === 'publickey') return ctx.accept();
        ctx.reject(['password', 'publickey']);
      });
      client.on('ready', () => {
        client.on('session', (accept) => {
          accept().on('exec', (acc, _rej, info) => {
            const stream = acc();
            commandsSeen.push(info.command);
            if (fakeUid && info.command === 'id -u') {
              stream.write(`${fakeUid}\n`);
              stream.exit(0);
              stream.end();
              return;
            }
            // Keep the test's files out of the real /etc and /var.
            const rewrite = (s: string) => s.split('/etc/emberwall').join(`${tmp}/etc`).split('/var/lib/emberwall').join(`${tmp}/state`);
            const child = holder
              ? spawn('nsenter', ['-t', String(holder.pid), '-n', 'sh', '-c', rewrite(info.command)])
              : spawn('sh', ['-c', rewrite(info.command)]);
            let input = '';
            child.stdin.on('error', () => undefined); // the command may exit without reading its input
            stream.on('data', (d: Buffer) => { input += d.toString('utf8'); });
            stream.on('end', () => child.stdin.end(rewrite(input)));
            child.stdout.on('data', (d) => stream.write(d));
            child.stderr.on('data', (d) => stream.stderr.write(d));
            child.on('close', (code) => {
              stream.exit(code ?? 1);
              stream.end();
            });
          });
        });
      });
      client.on('error', () => undefined);
    });
    server.listen(0, '127.0.0.1', () => resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() }));
  });
}

let db: Db;
let http: HttpServer;
let base = '';
let clock = Date.now();
let sshd: { port: number; close: () => void };
let impostor: { port: number; close: () => void };

class Client {
  cookie = '';
  async call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
    const res = await fetch(base + path, {
      method,
      headers: { ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Emberwall': '1' }), ...(this.cookie ? { Cookie: this.cookie } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0];
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null, setCookie: set ?? '' };
  }
}

const admin = new Client();
const operator = new Client();
const viewer = new Client();
const anon = new Client();

beforeAll(async () => {
  if (canNetns) {
    holder = spawn('unshare', ['-n', 'sleep', '300'], { stdio: 'ignore' });
    await new Promise((r) => setTimeout(r, 300));
  }
  db = openDb(':memory:');
  const app = createApp({ db, vault: new Vault(SECRET), now: () => clock });
  http = createServer((req, res) => void app(req, res));
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  sshd = await startSsh(hostKey.private);
  impostor = await startSsh(otherHostKey.private);
});

afterAll(() => {
  http?.close();
  sshd?.close();
  impostor?.close();
  holder?.kill();
});

describe('passwords, sessions, throttling, vault', () => {
  it('hashes with a salt and verifies', () => {
    const a = hashPassword('correct horse battery');
    const b = hashPassword('correct horse battery');
    expect(a.hash).not.toBe(b.hash);
    expect(verifyPassword('correct horse battery', a.salt, a.hash)).toBe(true);
    expect(verifyPassword('correct horse batterx', a.salt, a.hash)).toBe(false);
  });
  it('expires sessions when idle and at the absolute limit', () => {
    const d = openDb(':memory:');
    const { salt, hash } = hashPassword('a-long-password');
    d.prepare("INSERT INTO users (username, pass_hash, salt, role, created_at) VALUES ('u', ?, ?, 'viewer', 0)").run(hash, salt);
    const t0 = 1_000_000;
    const token = createSession(d, 1, t0);
    expect(sessionUser(d, token, t0 + 1000)?.username).toBe('u');
    expect(sessionUser(d, 'not-a-token', t0)).toBeNull();
    expect(sessionUser(d, token, t0 + IDLE_MS + 1)).toBeNull();
    const t2 = createSession(d, 1, t0);
    for (let t = t0; t < t0 + ABSOLUTE_MS; t += IDLE_MS / 2) expect(sessionUser(d, t2, t)).not.toBeNull();
    expect(sessionUser(d, t2, t0 + ABSOLUTE_MS + 1)).toBeNull();
    expect((d.prepare('SELECT COUNT(*) n FROM sessions').get() as { n: number }).n).toBe(0);
    // The token itself is not in the database.
    const t3 = createSession(d, 1, t0);
    expect(JSON.stringify(d.prepare('SELECT * FROM sessions').all())).not.toContain(t3);
  });
  it('throttles after repeated failures', () => {
    const t = new Throttle(3, 1000);
    t.fail('a', 0); t.fail('a', 10); expect(t.blocked('a', 20)).toBe(false);
    t.fail('a', 30); expect(t.blocked('a', 40)).toBe(true);
    expect(t.blocked('a', 1100)).toBe(false);
  });
  it('encrypts credentials and refuses without a proper master key', () => {
    const v = new Vault(SECRET);
    const blob = v.encrypt('-----BEGIN KEY-----\nsecret\n');
    expect(blob).not.toContain('secret');
    expect(v.decrypt(blob)).toBe('-----BEGIN KEY-----\nsecret\n');
    expect(v.encrypt('x')).not.toBe(v.encrypt('x'));
    expect(() => new Vault(SECRET + 'different').decrypt(blob)).toThrow(/master key is different/);
    const tampered = blob.slice(0, -4) + (blob.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    expect(() => v.decrypt(tampered)).toThrow();
    expect(new Vault('short').configured).toBe(false);
    expect(() => new Vault(undefined).encrypt('x')).toThrow(/No master key/);
  });
});

describe('login and roles', () => {
  it('requires setup first, once', async () => {
    expect((await anon.call('GET', '/api/health')).body).toMatchObject({ setupNeeded: true, vault: true, user: null });
    expect((await anon.call('GET', '/api/servers')).status).toBe(401);
    expect((await admin.call('POST', '/api/setup', { username: 'root', password: 'short' })).status).toBe(400);
    const r = await admin.call('POST', '/api/setup', { username: 'alice', password: 'correct horse battery' });
    expect(r.status).toBe(200);
    expect(r.setCookie).toMatch(/HttpOnly; SameSite=Strict/);
    expect((await anon.call('POST', '/api/setup', { username: 'mallory', password: 'correct horse battery' })).status).toBe(403);
    expect((await admin.call('GET', '/api/health')).body.user).toEqual({ username: 'alice', role: 'admin' });
  });
  it('rejects state-changing requests without the anti-forgery header or from another origin', async () => {
    const res = await fetch(`${base}/api/logout`, { method: 'POST', headers: { Cookie: admin.cookie, 'Content-Type': 'application/json' }, body: '{}' });
    expect(res.status).toBe(403);
    expect((await admin.call('POST', '/api/users', { username: 'x1', password: 'correct horse battery', role: 'viewer' }, { Origin: 'https://evil.example' })).status).toBe(403);
    expect((await admin.call('GET', '/api/health')).body.user.username).toBe('alice');
  });
  it('creates users and enforces roles on the server', async () => {
    expect((await admin.call('POST', '/api/users', { username: 'oscar', password: 'correct horse battery', role: 'operator' })).status).toBe(200);
    expect((await admin.call('POST', '/api/users', { username: 'vera', password: 'correct horse battery', role: 'viewer' })).status).toBe(200);
    expect((await admin.call('POST', '/api/users', { username: 'oscar', password: 'correct horse battery', role: 'viewer' })).status).toBe(409);
    expect((await admin.call('POST', '/api/users', { username: 'bad name!', password: 'correct horse battery', role: 'viewer' })).status).toBe(400);
    expect((await operator.call('POST', '/api/login', { username: 'oscar', password: 'correct horse battery' })).body.role).toBe('operator');
    expect((await viewer.call('POST', '/api/login', { username: 'VERA', password: 'correct horse battery' })).body.role).toBe('viewer');
    expect((await viewer.call('GET', '/api/servers')).status).toBe(200);
    expect((await viewer.call('POST', '/api/servers', { name: 'x', host: 'h', username: 'u' })).status).toBe(403);
    expect((await viewer.call('GET', '/api/activity')).status).toBe(403);
    expect((await operator.call('GET', '/api/users')).status).toBe(403);
    expect((await operator.call('GET', '/api/activity')).status).toBe(200);
    expect((await viewer.call('POST', '/api/projects', { project: TEMPLATES[0].build() })).status).toBe(403);
  });
  it('protects the last administrator and signs out demoted or disabled users', async () => {
    const users = (await admin.call('GET', '/api/users')).body as { id: number; username: string }[];
    const id = (n: string) => users.find((u) => u.username === n)!.id;
    expect((await admin.call('PATCH', `/api/users/${id('alice')}`, { role: 'viewer' })).status).toBe(400);
    expect((await admin.call('DELETE', `/api/users/${id('alice')}`)).status).toBe(400);
    expect(JSON.stringify(users)).not.toMatch(/pass_hash|salt/);
    const temp = new Client();
    await admin.call('POST', '/api/users', { username: 'temp', password: 'correct horse battery', role: 'operator' });
    await temp.call('POST', '/api/login', { username: 'temp', password: 'correct horse battery' });
    expect((await temp.call('GET', '/api/servers')).status).toBe(200);
    const tid = ((await admin.call('GET', '/api/users')).body as { id: number; username: string }[]).find((u) => u.username === 'temp')!.id;
    await admin.call('PATCH', `/api/users/${tid}`, { disabled: true });
    expect((await temp.call('GET', '/api/servers')).status).toBe(401);
    expect((await temp.call('POST', '/api/login', { username: 'temp', password: 'correct horse battery' })).status).toBe(401);
    expect((await admin.call('DELETE', `/api/users/${tid}`)).status).toBe(200);
  });
  it('locks an account after repeated wrong passwords, and unlocks later', async () => {
    const c = new Client();
    for (let i = 0; i < 8; i += 1) expect((await c.call('POST', '/api/login', { username: 'vera', password: 'wrong password!' })).status).toBe(401);
    expect((await c.call('POST', '/api/login', { username: 'vera', password: 'correct horse battery' })).status).toBe(429);
    clock += 11 * 60 * 1000;
    expect((await c.call('POST', '/api/login', { username: 'vera', password: 'correct horse battery' })).status).toBe(200);
    expect((await c.call('POST', '/api/login', { username: 'nobody', password: 'whatever-it-is' })).body.error).toBe('Wrong user name or password.');
  });
  it('changes a password and logs out', async () => {
    const c = new Client();
    await c.call('POST', '/api/login', { username: 'vera', password: 'correct horse battery' });
    expect((await c.call('POST', '/api/me/password', { current: 'nope', password: 'another long password' })).status).toBe(400);
    expect((await c.call('POST', '/api/me/password', { current: 'correct horse battery', password: 'another long password' })).status).toBe(200);
    expect((await viewer.call('GET', '/api/servers')).status).toBe(401); // other sessions of that user are ended
    expect((await viewer.call('POST', '/api/login', { username: 'vera', password: 'another long password' })).status).toBe(200);
    await c.call('POST', '/api/logout', {});
    expect((await c.call('GET', '/api/servers')).status).toBe(401);
  });
});

describe('inventory and live servers over SSH', () => {
  let id = 0;
  it('stores credentials encrypted and never returns them', async () => {
    const r = await operator.call('POST', '/api/servers', { name: 'web-1', host: '127.0.0.1', port: sshd.port, username: 'ops', authKind: 'password', secret: 'correct horse', tags: 'prod web' });
    expect(r.status).toBe(200);
    id = r.body.id;
    expect(r.body).toMatchObject({ name: 'web-1', hasSecret: true, hostKeyFingerprint: null });
    expect(JSON.stringify(r.body)).not.toContain('correct horse');
    expect(JSON.stringify((await viewer.call('GET', '/api/servers')).body)).not.toMatch(/correct horse|secret_enc/);
    const stored = db.prepare('SELECT secret_enc FROM servers WHERE id = ?').get(id) as { secret_enc: string };
    expect(stored.secret_enc).toMatch(/^v1\./);
    expect(stored.secret_enc).not.toContain('correct horse');
    expect((await operator.call('POST', '/api/servers', { name: 'bad', host: 'a b;rm', username: 'ops' })).status).toBe(400);
    expect((await operator.call('POST', '/api/servers', { name: 'bad', host: 'h', username: 'ops; id' })).status).toBe(400);
    expect((await operator.call('POST', '/api/servers', { name: 'web-1', host: 'h', username: 'ops' })).status).toBe(409);
  });
  it('asks before trusting an unknown host key, then pins it', async () => {
    const first = await operator.call('POST', `/api/servers/${id}/probe`, {});
    expect(first.status).toBe(409);
    expect(first.body).toMatchObject({ code: 'host_key', kind: 'unknown' });
    expect(first.body.fingerprint).toBe(fingerprintOf((utils.parseKey(hostKey.public) as ssh2.ParsedKey).getPublicSSH()));
    expect((await operator.call('POST', `/api/servers/${id}/probe`, { trustFingerprint: 'SHA256:somethingelse' })).status).toBe(409);
    const ok = await operator.call('POST', `/api/servers/${id}/probe`, { trustFingerprint: first.body.fingerprint });
    expect(ok.status).toBe(200);
    expect(ok.body.server.hostKeyFingerprint).toBe(first.body.fingerprint);
    expect((await operator.call('POST', `/api/servers/${id}/probe`, {})).status).toBe(200);
  });
  it('refuses a server whose host key changed', async () => {
    await operator.call('PATCH', `/api/servers/${id}`, {}); // no-op keeps the pin
    db.prepare('UPDATE servers SET port = ? WHERE id = ?').run(impostor.port, id); // same name, different machine answering
    const r = await operator.call('POST', `/api/servers/${id}/probe`, { trustFingerprint: fingerprintOf((utils.parseKey(otherHostKey.public) as ssh2.ParsedKey).getPublicSSH()) });
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ code: 'host_key', kind: 'changed' });
    db.prepare('UPDATE servers SET port = ? WHERE id = ?').run(sshd.port, id);
  });
  it('reports wrong credentials and unreachable hosts plainly', async () => {
    const bad = await operator.call('POST', '/api/servers', { name: 'wrong-pw', host: '127.0.0.1', port: sshd.port, username: 'ops', authKind: 'password', secret: 'nope' });
    const fp = fingerprintOf((utils.parseKey(hostKey.public) as ssh2.ParsedKey).getPublicSSH());
    const r = await operator.call('POST', `/api/servers/${bad.body.id}/probe`, { trustFingerprint: fp });
    expect(r.status).toBe(502);
    expect(r.body.error).toMatch(/Authentication failed/);
    const dead = await operator.call('POST', '/api/servers', { name: 'dead', host: '127.0.0.1', port: 1, username: 'ops', authKind: 'password', secret: 'x' });
    expect((await operator.call('POST', `/api/servers/${dead.body.id}/probe`, {})).status).toBe(502);
    const key = await operator.call('POST', '/api/servers', { name: 'with-key', host: '127.0.0.1', port: sshd.port, username: 'ops', authKind: 'key', secret: userKey.private });
    expect((await operator.call('POST', `/api/servers/${key.body.id}/probe`, { trustFingerprint: fp })).status).toBe(200);
    expect((await viewer.call('POST', `/api/servers/${id}/probe`, {})).status).toBe(403);
  });
  it('runs only its fixed commands, and prefixes sudo for a non-root login', async () => {
    commandsSeen.length = 0;
    fakeUid = '1000';
    await operator.call('POST', `/api/servers/${id}/probe`, {});
    fakeUid = null;
    expect(commandsSeen).toContain('sudo -n nft list ruleset');
    expect(commandsSeen).toContain('sudo -n iptables-save');
    expect(commandsSeen).toContain('nft --version');
    for (const c of commandsSeen) expect(c).toMatch(/^(sudo -n )?(id -u|cat \/etc\/(os-release|firewalld\/zones\/[\w-]+\.xml)|uname -r|nft (--version|list ruleset)|ip6?tables(-save| --version)|ufw (version|status verbose|show added)|firewall-cmd (--version|--state|--get-default-zone))$/);
  });

  it.skipIf(!canNetns)('fetches the running nftables config, then pushes with confirm and with timeout', async () => {
    // What is on the "server" before Emberwall touches it.
    const legacy = join(tmp, 'legacy.nft');
    writeFileSync(legacy, 'table inet legacy {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport { 22, 8080 } accept\n }\n}\n');
    spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'nft', '-f', legacy]);
    const direct = spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'nft', 'list', 'tables'], { encoding: 'utf8' });
    expect(direct.stdout + direct.stderr, `holder pid ${holder!.pid} exit ${holder!.exitCode}`).toContain('table inet legacy');
    const fetched = await operator.call('POST', `/api/servers/${id}/probe`, {});
    expect(fetched.status).toBe(200);
    const d = detect(fetched.body.output);
    expect(fetched.body.output.nftRuleset, JSON.stringify(fetched.body.output.nftRuleset)).toMatchObject({ code: 0 });
    expect(fetched.body.output.nftRuleset.stdout, JSON.stringify({ o: fetched.body.output.nftVersion, k: fetched.body.output.kernel, cmds: commandsSeen.slice(-16) })).toContain('table inet legacy');
    expect(d.activeTool).toBe('nftables');
    expect(d.isRoot).toBe(true);
    const live = readLiveConfig(fetched.body.output, 'nftables')!;
    expect(live.report.project.policies.in).toBe('accept');
    expect(live.report.project.rules[0].ports).toEqual(['22', '8080']);
    expect((await viewer.call('GET', `/api/servers/${id}/snapshot`)).body.output.nftRuleset.stdout).toContain('table inet legacy');

    const project = TEMPLATES[0].build();
    const push = { project, selection: d.selection, timeoutSeconds: 15 };
    expect((await operator.call('POST', `/api/servers/${id}/deploy`, { ...push, confirmName: 'web-2' })).status).toBe(400);
    expect((await viewer.call('POST', `/api/servers/${id}/deploy`, { ...push, confirmName: 'web-1' })).status).toBe(403);
    expect((await operator.call('POST', `/api/servers/${id}/deploy`, { ...push, selection: { distro: 'custom', tool: 'ufw', version: '0.36.2' }, confirmName: 'web-1' })).status).toBe(409);

    // 1) push and confirm
    const a = await operator.call('POST', `/api/servers/${id}/deploy`, { ...push, confirmName: 'web-1' });
    expect(a.body.status, a.body.log ?? a.body.error).toBe('pending');
    expect(a.body.log).toContain('== Applied. Waiting for confirmation');
    const tables = () => spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'nft', 'list', 'tables'], { encoding: 'utf8' }).stdout;
    expect(tables()).toContain('table inet emberwall');
    expect((await operator.call('POST', `/api/servers/${id}/deploy`, { ...push, confirmName: 'web-1' })).status).toBe(409); // one at a time
    expect((await viewer.call('POST', `/api/deployments/${a.body.id}/confirm`, {})).status).toBe(403);
    expect((await operator.call('POST', `/api/deployments/${a.body.id}/confirm`, {})).body.status).toBe('confirmed');
    await new Promise((r) => setTimeout(r, 300));
    expect(tables()).toContain('table inet emberwall');
    expect((await operator.call('POST', `/api/deployments/${a.body.id}/confirm`, {})).status).toBe(409);

    // 2) push and let the timer run out: the server restores what it had (legacy + the confirmed table)
    const changed = { ...project, rules: project.rules.slice(0, 1) };
    const b = await operator.call('POST', `/api/servers/${id}/deploy`, { ...push, project: changed, confirmName: 'web-1' });
    expect(b.body.status).toBe('pending');
    const during = spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'nft', 'list', 'ruleset'], { encoding: 'utf8' }).stdout;
    expect(during).not.toContain('"HTTP + HTTPS"');
    await new Promise((r) => setTimeout(r, 16500));
    const after = spawnSync('nsenter', ['-t', String(holder!.pid), '-n', 'nft', 'list', 'ruleset'], { encoding: 'utf8' }).stdout;
    expect(after).toContain('"HTTP + HTTPS"');
    expect(after).toContain('table inet legacy');
    clock += 30_000;
    const late = await operator.call('POST', `/api/deployments/${b.body.id}/confirm`, {});
    expect(late.status).toBe(409);
    expect(late.body.error).toMatch(/rolled back/);
    const list = (await viewer.call('GET', `/api/deployments?server=${id}`)).body as { id: number; status: string; log: string }[];
    expect(list.find((x) => x.id === a.body.id)!.status).toBe('confirmed');
    expect(list.find((x) => x.id === b.body.id)!.status).toBe('expired');
    const acts = ((await admin.call('GET', '/api/activity')).body as { action: string }[]).map((x) => x.action);
    expect(acts).toEqual(expect.arrayContaining(['setup.create_admin', 'login', 'login.failed', 'server.create', 'server.trust_host_key', 'server.fetch', 'deploy.applied', 'deploy.confirmed']));
  }, 60000);
});

describe('shared projects', () => {
  it('saves, lists, loads, and refuses to overwrite a newer save', async () => {
    const p = TEMPLATES[0].build();
    const saved = await operator.call('POST', '/api/projects', { project: p });
    expect(saved.status).toBe(200);
    expect((await viewer.call('GET', '/api/projects')).body[0]).toMatchObject({ name: 'Web server', updatedBy: 'oscar' });
    const loaded = await viewer.call('GET', `/api/projects/${saved.body.id}`);
    expect(loaded.body.data.rules.length).toBe(p.rules.length);
    clock += 1000;
    const again = await admin.call('PUT', `/api/projects/${saved.body.id}`, { project: { ...p, name: 'Web server v2' }, baseUpdatedAt: saved.body.updatedAt });
    expect(again.status).toBe(200);
    expect((await operator.call('PUT', `/api/projects/${saved.body.id}`, { project: p, baseUpdatedAt: saved.body.updatedAt })).status).toBe(409);
    expect((await operator.call('POST', '/api/projects', { project: { nonsense: true } })).status).toBe(400);
    expect((await operator.call('DELETE', `/api/projects/${saved.body.id}`)).status).toBe(200);
  });
  it('rejects oversized and malformed requests', async () => {
    const big = await fetch(`${base}/api/projects`, { method: 'POST', headers: { Cookie: operator.cookie, 'Content-Type': 'application/json', 'X-Emberwall': '1' }, body: JSON.stringify({ pad: 'x'.repeat(3 * 1024 * 1024) }) }).then((r) => r.status).catch(() => 413);
    expect(big).toBe(413);
    const bad = await fetch(`${base}/api/projects`, { method: 'POST', headers: { Cookie: operator.cookie, 'Content-Type': 'application/json', 'X-Emberwall': '1' }, body: '{not json' });
    expect(bad.status).toBe(400);
    expect((await anon.call('GET', '/api/nope')).status).toBe(404);
  });
});
