// HTTP API. Every route names the role it needs; nothing is reachable without a session
// except health, first-run setup and login.
import { createReadStream, existsSync, statSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { compile } from '../src/core/compile';
import { deployPlan } from '../src/core/compile/deployPlan';
import { detect, NEEDS_ROOT, PROBE_COMMANDS, zoneXmlCommand, type ProbeKey, type ProbeOutput } from '../src/core/live';
import { coerceProject } from '../src/core/model';
import { cleanText } from '../src/core/safety';
import { resolveTarget, TOOLS, type TargetSelection } from '../src/core/targets';
import {
  atLeast, createSession, destroySession, destroyUserSessions, hashPassword, passwordProblem, sessionUser, Throttle, validUsername, verifyPassword, type User,
} from './auth';
import { logAction, ROLES, type Db, type Role } from './db';
import { Vault } from './secrets';
import { connect, HostKeyError, SshError, type Session, type SshTarget } from './ssh';

export interface AppOptions {
  db: Db;
  vault: Vault;
  staticDir?: string;
  /** Send the session cookie with the Secure flag (set when served over HTTPS). */
  secureCookies?: boolean;
  /** Trust X-Forwarded-For from a reverse proxy for login throttling. */
  trustProxy?: boolean;
  now?: () => number;
}

class HttpError extends Error {
  constructor(public status: number, message: string, public extra: Record<string, unknown> = {}) {
    super(message);
  }
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  user: User | null;
  params: string[];
  body: any;
  query: URLSearchParams;
  ip: string;
}

type Handler = (c: Ctx) => unknown | Promise<unknown>;
interface Route {
  method: string;
  pattern: RegExp;
  /** null = public. */
  role: Role | null;
  handler: Handler;
}

const COOKIE = 'ew_session';
const MAX_BODY = 2 * 1024 * 1024;
const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.ico': 'image/x-icon', '.map': 'application/json',
};

const str = (v: unknown, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

interface ServerRow {
  id: number; name: string; host: string; port: number; username: string; auth_kind: 'key' | 'password'; secret_enc: string | null;
  host_key_fp: string | null; tags: string; notes: string; last_tool: string | null; last_version: string | null; last_os: string | null; last_fetch_at: number | null;
}

/** What the browser may see of a server: never the credential. */
const publicServer = (r: ServerRow) => ({
  id: r.id, name: r.name, host: r.host, port: r.port, username: r.username, authKind: r.auth_kind, hasSecret: !!r.secret_enc,
  hostKeyFingerprint: r.host_key_fp, tags: r.tags, notes: r.notes, lastTool: r.last_tool, lastVersion: r.last_version, lastOs: r.last_os, lastFetchAt: r.last_fetch_at,
});

export function createApp(opts: AppOptions) {
  const { db, vault } = opts;
  const now = opts.now ?? Date.now;
  const loginByUser = new Throttle(8, 10 * 60 * 1000);
  const loginByIp = new Throttle(40, 10 * 60 * 1000);
  const userCount = () => (db.prepare('SELECT COUNT(*) n FROM users').get() as { n: number }).n;
  const adminCount = () => (db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND disabled = 0").get() as { n: number }).n;
  const getServer = (id: string): ServerRow => {
    const row = db.prepare('SELECT * FROM servers WHERE id = ?').get(Number(id)) as ServerRow | undefined;
    if (!row) throw new HttpError(404, 'Server not found.');
    return row;
  };

  function serverInput(b: any, existing?: ServerRow) {
    const name = cleanText(b.name ?? existing?.name, 60);
    const host = str(b.host ?? existing?.host, 253);
    const port = Number(b.port ?? existing?.port ?? 22);
    const username = str(b.username ?? existing?.username, 32);
    const authKind = (b.authKind ?? existing?.auth_kind) === 'password' ? 'password' : 'key';
    if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,59}$/.test(name)) throw new HttpError(400, 'Name: use letters, digits, spaces, dots, dashes and underscores.');
    if (!/^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$/.test(host)) throw new HttpError(400, 'Address must be a host name or IP address.');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(400, 'Port must be between 1 and 65535.');
    if (!/^[a-z_][a-z0-9_.-]{0,31}$/i.test(username)) throw new HttpError(400, 'SSH user name is not valid.');
    let secretEnc: string | null | undefined;
    if (typeof b.secret === 'string' && b.secret.length > 0) {
      if (b.secret.length > 20000) throw new HttpError(400, 'Credential is too large.');
      if (!vault.configured) throw new HttpError(400, 'The server has no master key (EMBERWALL_SECRET), so credentials cannot be stored.');
      secretEnc = vault.encrypt(JSON.stringify({ secret: b.secret, passphrase: typeof b.passphrase === 'string' ? b.passphrase : '' }));
    } else if (existing && authKind !== existing.auth_kind) secretEnc = null;
    return { name, host, port, username, authKind, secretEnc, tags: cleanText(b.tags ?? existing?.tags, 200), notes: cleanText(b.notes ?? existing?.notes, 1000) };
  }

  function sshTarget(row: ServerRow, trust?: string | null): SshTarget {
    if (!row.secret_enc) throw new HttpError(400, 'This server has no stored credential. Edit it and add one.');
    let cred: { secret: string; passphrase: string };
    try {
      cred = JSON.parse(vault.decrypt(row.secret_enc));
    } catch (e) {
      throw new HttpError(500, (e as Error).message);
    }
    return {
      host: row.host, port: row.port, username: row.username, pinned: row.host_key_fp, trust: trust ?? null,
      ...(row.auth_kind === 'key' ? { privateKey: cred.secret, passphrase: cred.passphrase } : { password: cred.secret }),
    };
  }

  /** Connects, turning SSH failures into API errors and pinning a newly approved host key. */
  async function open(row: ServerRow, user: User, trust?: string | null): Promise<Session> {
    try {
      const s = await connect(sshTarget(row, trust));
      if (!row.host_key_fp) {
        db.prepare('UPDATE servers SET host_key_fp = ? WHERE id = ?').run(s.fingerprint, row.id);
        row.host_key_fp = s.fingerprint;
        logAction(db, user.username, 'server.trust_host_key', `${row.name} ${s.fingerprint}`);
      }
      return s;
    } catch (e) {
      if (e instanceof HostKeyError) throw new HttpError(409, e.message, { code: 'host_key', kind: e.kind, fingerprint: e.fingerprint, pinned: e.pinned ?? null });
      if (e instanceof SshError) throw new HttpError(502, e.message);
      throw e;
    }
  }

  async function probe(s: Session): Promise<ProbeOutput> {
    const out: ProbeOutput = {};
    out.uid = await s.exec(PROBE_COMMANDS.uid);
    const root = out.uid.code === 0 && out.uid.stdout.trim() === '0';
    const run = (key: ProbeKey, cmd: string) => s.exec(!root && NEEDS_ROOT.includes(key) ? `sudo -n ${cmd}` : cmd);
    for (const key of Object.keys(PROBE_COMMANDS) as (keyof typeof PROBE_COMMANDS)[]) {
      if (key === 'uid') continue;
      out[key] = await run(key, PROBE_COMMANDS[key]);
    }
    if (out.firewalldZone?.code === 0) {
      const cmd = zoneXmlCommand(out.firewalldZone.stdout);
      if (cmd) out.firewalldZoneXml = await run('firewalldZoneXml', cmd);
    }
    return out;
  }

  const routes: Route[] = [];
  const route = (method: string, path: string, role: Role | null, handler: Handler) =>
    routes.push({ method, pattern: new RegExp(`^${path.replace(/:id/g, '(\\d+)')}$`), role, handler });

  // ---- public ----
  route('GET', '/api/health', null, (c) => ({ ok: true, setupNeeded: userCount() === 0, vault: vault.configured, user: c.user ? { username: c.user.username, role: c.user.role } : null }));

  route('POST', '/api/setup', null, (c) => {
    if (userCount() > 0) throw new HttpError(403, 'Setup has already been completed.');
    if (!validUsername(c.body.username)) throw new HttpError(400, 'User name: 2-32 letters, digits, dots, dashes or underscores.');
    const problem = passwordProblem(c.body.password);
    if (problem) throw new HttpError(400, problem);
    const { salt, hash } = hashPassword(c.body.password);
    const info = db.prepare("INSERT INTO users (username, pass_hash, salt, role, created_at) VALUES (?, ?, ?, 'admin', ?)").run(c.body.username, hash, salt, now());
    logAction(db, c.body.username, 'setup.create_admin');
    setCookie(c.res, createSession(db, Number(info.lastInsertRowid), now()));
    return { username: c.body.username, role: 'admin' };
  });

  route('POST', '/api/login', null, (c) => {
    const username = str(c.body.username, 40);
    const key = username.toLowerCase();
    if (loginByUser.blocked(key, now()) || loginByIp.blocked(c.ip, now())) throw new HttpError(429, 'Too many attempts. Wait ten minutes and try again.');
    const row = db.prepare('SELECT id, username, pass_hash, salt, role, disabled FROM users WHERE username = ?').get(username) as
      | { id: number; username: string; pass_hash: string; salt: string; role: Role; disabled: number } | undefined;
    // Hash even when the user does not exist, so timing does not reveal which names are real.
    const ok = row ? verifyPassword(String(c.body.password ?? ''), row.salt, row.pass_hash) : (hashPassword(String(c.body.password ?? ''), '00'), false);
    if (!row || !ok || row.disabled) {
      loginByUser.fail(key, now());
      loginByIp.fail(c.ip, now());
      logAction(db, username || '?', 'login.failed', c.ip);
      throw new HttpError(401, 'Wrong user name or password.');
    }
    loginByUser.clear(key);
    setCookie(c.res, createSession(db, row.id, now()));
    logAction(db, row.username, 'login', c.ip);
    return { username: row.username, role: row.role };
  });

  route('POST', '/api/logout', null, (c) => {
    destroySession(db, cookieOf(c.req));
    c.res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    if (c.user) logAction(db, c.user.username, 'logout');
    return { ok: true };
  });

  // ---- account ----
  route('POST', '/api/me/password', 'viewer', (c) => {
    const row = db.prepare('SELECT pass_hash, salt FROM users WHERE id = ?').get(c.user!.id) as { pass_hash: string; salt: string };
    if (!verifyPassword(String(c.body.current ?? ''), row.salt, row.pass_hash)) throw new HttpError(400, 'Current password is wrong.');
    const problem = passwordProblem(c.body.password);
    if (problem) throw new HttpError(400, problem);
    const { salt, hash } = hashPassword(c.body.password);
    db.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').run(hash, salt, c.user!.id);
    destroyUserSessions(db, c.user!.id);
    setCookie(c.res, createSession(db, c.user!.id, now()));
    logAction(db, c.user!.username, 'password.change');
    return { ok: true };
  });

  // ---- users (admin) ----
  route('GET', '/api/users', 'admin', () => db.prepare('SELECT id, username, role, disabled, created_at AS createdAt FROM users ORDER BY username').all());
  route('POST', '/api/users', 'admin', (c) => {
    if (!validUsername(c.body.username)) throw new HttpError(400, 'User name: 2-32 letters, digits, dots, dashes or underscores.');
    if (!ROLES.includes(c.body.role)) throw new HttpError(400, 'Unknown role.');
    const problem = passwordProblem(c.body.password);
    if (problem) throw new HttpError(400, problem);
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(c.body.username)) throw new HttpError(409, 'That user name is taken.');
    const { salt, hash } = hashPassword(c.body.password);
    const info = db.prepare('INSERT INTO users (username, pass_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)').run(c.body.username, hash, salt, c.body.role, now());
    logAction(db, c.user!.username, 'user.create', `${c.body.username} (${c.body.role})`);
    return { id: Number(info.lastInsertRowid) };
  });
  route('PATCH', '/api/users/:id', 'admin', (c) => {
    const id = Number(c.params[0]);
    const row = db.prepare('SELECT id, username, role, disabled FROM users WHERE id = ?').get(id) as { id: number; username: string; role: Role; disabled: number } | undefined;
    if (!row) throw new HttpError(404, 'User not found.');
    const role: Role = c.body.role === undefined ? row.role : c.body.role;
    const disabled = c.body.disabled === undefined ? !!row.disabled : !!c.body.disabled;
    if (!ROLES.includes(role)) throw new HttpError(400, 'Unknown role.');
    const losesAdmin = row.role === 'admin' && !row.disabled && (role !== 'admin' || disabled);
    if (losesAdmin && adminCount() <= 1) throw new HttpError(400, 'This is the last administrator; it cannot be demoted or disabled.');
    db.prepare('UPDATE users SET role = ?, disabled = ? WHERE id = ?').run(role, disabled ? 1 : 0, id);
    if (typeof c.body.password === 'string') {
      const problem = passwordProblem(c.body.password);
      if (problem) throw new HttpError(400, problem);
      const { salt, hash } = hashPassword(c.body.password);
      db.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').run(hash, salt, id);
      destroyUserSessions(db, id);
    }
    if (disabled || role !== row.role) destroyUserSessions(db, id);
    logAction(db, c.user!.username, 'user.update', `${row.username}: role ${role}${disabled ? ', disabled' : ''}${typeof c.body.password === 'string' ? ', password reset' : ''}`);
    return { ok: true };
  });
  route('DELETE', '/api/users/:id', 'admin', (c) => {
    const id = Number(c.params[0]);
    const row = db.prepare('SELECT username, role, disabled FROM users WHERE id = ?').get(id) as { username: string; role: Role; disabled: number } | undefined;
    if (!row) throw new HttpError(404, 'User not found.');
    if (id === c.user!.id) throw new HttpError(400, 'You cannot delete your own account.');
    if (row.role === 'admin' && !row.disabled && adminCount() <= 1) throw new HttpError(400, 'This is the last administrator.');
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    logAction(db, c.user!.username, 'user.delete', row.username);
    return { ok: true };
  });

  // ---- inventory ----
  route('GET', '/api/servers', 'viewer', () => (db.prepare('SELECT * FROM servers ORDER BY name').all() as unknown as ServerRow[]).map(publicServer));
  route('POST', '/api/servers', 'operator', (c) => {
    const v = serverInput(c.body);
    if (db.prepare('SELECT 1 FROM servers WHERE name = ?').get(v.name)) throw new HttpError(409, 'A server with that name already exists.');
    const info = db
      .prepare('INSERT INTO servers (name, host, port, username, auth_kind, secret_enc, tags, notes, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(v.name, v.host, v.port, v.username, v.authKind, v.secretEnc ?? null, v.tags, v.notes, now(), c.user!.username);
    logAction(db, c.user!.username, 'server.create', `${v.name} (${v.username}@${v.host}:${v.port})`);
    return publicServer(getServer(String(info.lastInsertRowid)));
  });
  route('PATCH', '/api/servers/:id', 'operator', (c) => {
    const row = getServer(c.params[0]);
    const v = serverInput(c.body, row);
    // A different address is a different machine: the pinned host key no longer applies.
    const moved = v.host !== row.host || v.port !== row.port;
    db.prepare('UPDATE servers SET name = ?, host = ?, port = ?, username = ?, auth_kind = ?, secret_enc = ?, tags = ?, notes = ?, host_key_fp = ? WHERE id = ?').run(
      v.name, v.host, v.port, v.username, v.authKind, v.secretEnc === undefined ? row.secret_enc : v.secretEnc, v.tags, v.notes, moved || c.body.forgetHostKey ? null : row.host_key_fp, row.id,
    );
    logAction(db, c.user!.username, 'server.update', `${v.name}${moved ? ' (address changed, host key forgotten)' : ''}${c.body.forgetHostKey ? ' (host key forgotten)' : ''}${v.secretEnc ? ' (credential replaced)' : ''}`);
    return publicServer(getServer(c.params[0]));
  });
  route('DELETE', '/api/servers/:id', 'operator', (c) => {
    const row = getServer(c.params[0]);
    db.prepare('DELETE FROM servers WHERE id = ?').run(row.id);
    logAction(db, c.user!.username, 'server.delete', row.name);
    return { ok: true };
  });

  // ---- live ----
  route('POST', '/api/servers/:id/probe', 'operator', async (c) => {
    const row = getServer(c.params[0]);
    const s = await open(row, c.user!, str(c.body.trustFingerprint, 100) || null);
    try {
      const output = await probe(s);
      const d = detect(output);
      const at = now();
      db.prepare('INSERT INTO snapshots (server_id, fetched_at, by_user, output) VALUES (?, ?, ?, ?)').run(row.id, at, c.user!.username, JSON.stringify(output));
      db.prepare('DELETE FROM snapshots WHERE server_id = ? AND id NOT IN (SELECT id FROM snapshots WHERE server_id = ? ORDER BY id DESC LIMIT 20)').run(row.id, row.id);
      db.prepare('UPDATE servers SET last_tool = ?, last_version = ?, last_os = ?, last_fetch_at = ? WHERE id = ?').run(d.activeTool, d.activeTool ? d.versions[d.activeTool] ?? null : null, d.os, at, row.id);
      logAction(db, c.user!.username, 'server.fetch', `${row.name}: ${d.activeTool ?? 'no firewall'} ${d.activeTool ? d.versions[d.activeTool] ?? '' : ''}`);
      return { server: publicServer(getServer(c.params[0])), output, fetchedAt: at, by: c.user!.username };
    } finally {
      s.close();
    }
  });
  route('GET', '/api/servers/:id/snapshot', 'viewer', (c) => {
    const row = getServer(c.params[0]);
    const snap = db.prepare('SELECT fetched_at, by_user, output FROM snapshots WHERE server_id = ? ORDER BY id DESC LIMIT 1').get(row.id) as { fetched_at: number; by_user: string; output: string } | undefined;
    return snap ? { server: publicServer(row), output: JSON.parse(snap.output), fetchedAt: snap.fetched_at, by: snap.by_user } : { server: publicServer(row), output: null };
  });

  // ---- guarded push ----
  const sweep = () => {
    db.prepare("UPDATE deployments SET status = 'expired', log = log || ? WHERE status = 'pending' AND deadline < ?").run(
      '\n== Not confirmed in time. The server rolled back to its previous rules on its own.\n', now() - 5000,
    );
  };
  route('POST', '/api/servers/:id/deploy', 'operator', async (c) => {
    const row = getServer(c.params[0]);
    if (str(c.body.confirmName) !== row.name) throw new HttpError(400, 'Type the server name exactly to confirm the push.');
    sweep();
    if (db.prepare("SELECT 1 FROM deployments WHERE server_id = ? AND status = 'pending'").get(row.id)) throw new HttpError(409, 'A push to this server is still waiting for confirmation.');
    let project;
    try {
      project = coerceProject(c.body.project);
    } catch (e) {
      throw new HttpError(400, `Project is not valid: ${(e as Error).message}`);
    }
    const sel = c.body.selection as TargetSelection;
    if (!sel || !TOOLS.includes(sel.tool)) throw new HttpError(400, 'Build target is missing.');
    const result = compile(project, resolveTarget({ distro: str(sel.distro, 40) || 'custom', tool: sel.tool, version: str(sel.version, 20) }));

    const s = await open(row, c.user!);
    let id = 0;
    try {
      const live = detect(await probe(s));
      if (live.activeTool && live.activeTool !== result.target.tool) {
        throw new HttpError(409, `This server is managed by ${live.activeTool}, but the build is for ${result.target.tool}. Fetch the server and build for its firewall.`);
      }
      if (live.needsPrivilege) throw new HttpError(400, 'The SSH user cannot manage the firewall (needs root or passwordless sudo).');
      const info = db.prepare("INSERT INTO deployments (server_id, project_name, tool, started_at, by_user, status) VALUES (?, ?, ?, ?, ?, 'running')").run(row.id, project.name, result.target.tool, now(), c.user!.username);
      id = Number(info.lastInsertRowid);
      const plan = deployPlan(result, { id, timeoutSeconds: Number(c.body.timeoutSeconds) || 60 });
      if (plan.blocked) {
        db.prepare("UPDATE deployments SET status = 'failed', log = ? WHERE id = ?").run(plan.blocked, id);
        throw new HttpError(400, plan.blocked);
      }
      const sudo = live.isRoot ? '' : 'sudo -n ';
      let log = `== Push ${id} to ${row.name} (${result.target.label}) by ${c.user!.username}\n`;
      // File names come from a fixed list in deployPlan; the directory from a numeric id.
      for (const f of [...plan.files, { name: 'deploy.sh', text: plan.script }]) {
        const up = await s.exec(`${sudo}sh -c 'umask 077; mkdir -p ${plan.dir} && cat > ${plan.dir}/${f.name}'`, { stdin: f.text });
        if (up.code !== 0) {
          log += `!! upload of ${f.name} failed: ${up.stderr.trim()}\n`;
          db.prepare("UPDATE deployments SET status = 'failed', log = ? WHERE id = ?").run(log, id);
          throw new HttpError(502, `Could not upload ${f.name}: ${up.stderr.trim() || 'unknown error'}`);
        }
        log += `== Uploaded ${f.name}\n`;
      }
      const run = await s.exec(`${sudo}sh ${plan.scriptPath}`, { timeoutMs: 120000 });
      log += run.stdout + (run.stderr ? run.stderr : '');
      if (run.code !== 0) {
        db.prepare("UPDATE deployments SET status = 'failed', log = ? WHERE id = ?").run(log, id);
        logAction(db, c.user!.username, 'deploy.failed', `${row.name} #${id}`);
        return { id, status: 'failed', log, manual: plan.manual };
      }
      const deadline = now() + plan.timeoutSeconds * 1000;
      db.prepare("UPDATE deployments SET status = 'pending', log = ?, deadline = ?, confirm_command = ? WHERE id = ?").run(log, deadline, `${sudo}${plan.confirmCommand}`, id);
      logAction(db, c.user!.username, 'deploy.applied', `${row.name} #${id} (${result.target.tool})`);
      return { id, status: 'pending', log, deadline, timeoutSeconds: plan.timeoutSeconds, manual: plan.manual };
    } catch (e) {
      if (id && !(e instanceof HttpError)) db.prepare("UPDATE deployments SET status = 'failed', log = log || ? WHERE id = ? AND status = 'running'").run(`\n!! ${(e as Error).message}\n`, id);
      throw e instanceof SshError ? new HttpError(502, e.message) : e;
    } finally {
      s.close();
    }
  });
  route('POST', '/api/deployments/:id/confirm', 'operator', async (c) => {
    sweep();
    const dep = db.prepare('SELECT id, server_id, status, confirm_command, log FROM deployments WHERE id = ?').get(Number(c.params[0])) as
      | { id: number; server_id: number; status: string; confirm_command: string | null; log: string } | undefined;
    if (!dep) throw new HttpError(404, 'Push not found.');
    if (dep.status !== 'pending' || !dep.confirm_command) throw new HttpError(409, dep.status === 'expired' ? 'Too late: the server already rolled back.' : `This push is ${dep.status}.`);
    const row = getServer(String(dep.server_id));
    // A fresh connection on purpose: it only succeeds if the new rules still let Emberwall in.
    let s: Session;
    try {
      s = await open(row, c.user!);
    } catch (e) {
      throw new HttpError(502, `Could not reconnect to ${row.name}: ${(e as Error).message} The server will roll back on its own when the timer runs out.`);
    }
    try {
      const r = await s.exec(dep.confirm_command);
      const answer = r.stdout.trim();
      if (answer === 'confirmed') {
        db.prepare("UPDATE deployments SET status = 'confirmed', log = log || ? WHERE id = ?").run(`== Confirmed by ${c.user!.username} over a new connection. The new rules stay.\n`, dep.id);
        logAction(db, c.user!.username, 'deploy.confirmed', `${row.name} #${dep.id}`);
        return { id: dep.id, status: 'confirmed' };
      }
      db.prepare("UPDATE deployments SET status = 'expired', log = log || ? WHERE id = ?").run('== The server had already rolled back before the confirmation arrived.\n', dep.id);
      return { id: dep.id, status: 'expired' };
    } finally {
      s.close();
    }
  });
  route('GET', '/api/deployments', 'viewer', (c) => {
    sweep();
    const serverId = Number(c.query.get('server') ?? 0);
    const rows = serverId
      ? db.prepare('SELECT d.id, d.server_id AS serverId, s.name AS server, d.project_name AS project, d.tool, d.started_at AS startedAt, d.deadline, d.by_user AS by, d.status, d.log FROM deployments d JOIN servers s ON s.id = d.server_id WHERE d.server_id = ? ORDER BY d.id DESC LIMIT 30').all(serverId)
      : db.prepare('SELECT d.id, d.server_id AS serverId, s.name AS server, d.project_name AS project, d.tool, d.started_at AS startedAt, d.deadline, d.by_user AS by, d.status, d.log FROM deployments d JOIN servers s ON s.id = d.server_id ORDER BY d.id DESC LIMIT 50').all();
    return rows;
  });

  // ---- shared projects ----
  route('GET', '/api/projects', 'viewer', () => db.prepare('SELECT id, name, updated_at AS updatedAt, updated_by AS updatedBy FROM projects ORDER BY updated_at DESC').all());
  route('GET', '/api/projects/:id', 'viewer', (c) => {
    const row = db.prepare('SELECT id, name, data, updated_at AS updatedAt, updated_by AS updatedBy FROM projects WHERE id = ?').get(Number(c.params[0])) as { data: string } | undefined;
    if (!row) throw new HttpError(404, 'Project not found.');
    return { ...row, data: JSON.parse(row.data) };
  });
  const saveProject = (c: Ctx, id?: number) => {
    let project;
    try {
      project = coerceProject(c.body.project);
    } catch (e) {
      throw new HttpError(400, `Project is not valid: ${(e as Error).message}`);
    }
    const name = cleanText(project.name, 80) || 'firewall';
    const data = JSON.stringify(project);
    if (id) {
      const cur = db.prepare('SELECT updated_at FROM projects WHERE id = ?').get(id) as { updated_at: number } | undefined;
      if (!cur) throw new HttpError(404, 'Project not found.');
      // Do not silently overwrite a colleague's newer save.
      if (c.body.baseUpdatedAt && Number(c.body.baseUpdatedAt) !== cur.updated_at) throw new HttpError(409, 'Someone else saved this project after you opened it. Reload it, or save as a new project.');
      db.prepare('UPDATE projects SET name = ?, data = ?, updated_at = ?, updated_by = ? WHERE id = ?').run(name, data, now(), c.user!.username, id);
    } else {
      id = Number(db.prepare('INSERT INTO projects (name, data, updated_at, updated_by) VALUES (?, ?, ?, ?)').run(name, data, now(), c.user!.username).lastInsertRowid);
    }
    logAction(db, c.user!.username, 'project.save', name);
    return db.prepare('SELECT id, name, updated_at AS updatedAt, updated_by AS updatedBy FROM projects WHERE id = ?').get(id);
  };
  route('POST', '/api/projects', 'operator', (c) => saveProject(c));
  route('PUT', '/api/projects/:id', 'operator', (c) => saveProject(c, Number(c.params[0])));
  route('DELETE', '/api/projects/:id', 'operator', (c) => {
    const row = db.prepare('SELECT name FROM projects WHERE id = ?').get(Number(c.params[0])) as { name: string } | undefined;
    if (!row) throw new HttpError(404, 'Project not found.');
    db.prepare('DELETE FROM projects WHERE id = ?').run(Number(c.params[0]));
    logAction(db, c.user!.username, 'project.delete', row.name);
    return { ok: true };
  });

  route('GET', '/api/activity', 'operator', () => db.prepare('SELECT id, at, username, action, detail FROM audit_log ORDER BY id DESC LIMIT 300').all());

  // ---- plumbing ----
  function cookieOf(req: IncomingMessage): string | undefined {
    const m = new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`).exec(req.headers.cookie ?? '');
    return m?.[1];
  }
  function setCookie(res: ServerResponse, token: string) {
    res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 24 * 3600}${opts.secureCookies ? '; Secure' : ''}`);
  }
  function send(res: ServerResponse, status: number, body: unknown) {
    const text = JSON.stringify(body ?? null);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(text) });
    res.end(text);
  }
  function readBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolveBody, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (d: Buffer) => {
        size += d.length;
        if (size > MAX_BODY) {
          reject(new HttpError(413, 'Request is too large.'));
          req.destroy();
        } else chunks.push(d);
      });
      req.on('end', () => {
        if (size === 0) return resolveBody({});
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolveBody(v && typeof v === 'object' ? v : {});
        } catch {
          reject(new HttpError(400, 'Request body is not valid JSON.'));
        }
      });
      req.on('error', reject);
    });
  }

  function serveStatic(req: IncomingMessage, res: ServerResponse, path: string) {
    const root = opts.staticDir ? resolve(opts.staticDir) : null;
    if (!root || !existsSync(root)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Emberwall API server. The web app has not been built (run "npm run build").');
      return;
    }
    let file = resolve(join(root, normalize(decodeURIComponent(path))));
    if (!file.startsWith(root)) file = join(root, 'index.html');
    if (!existsSync(file) || statSync(file).isDirectory()) file = join(root, 'index.html');
    const hashed = /\/assets\//.test(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Cache-Control': hashed ? 'public, max-age=31536000, immutable' : 'no-cache' });
    if (req.method === 'HEAD') res.end();
    else createReadStream(file).pipe(res);
  }

  return async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (!url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405);
        res.end();
        return;
      }
      serveStatic(req, res, url.pathname);
      return;
    }
    try {
      const method = req.method ?? 'GET';
      let match: RegExpExecArray | null = null;
      const r = routes.find((x) => x.method === method && (match = x.pattern.exec(url.pathname)));
      if (!r || !match) throw new HttpError(404, 'Not found.');
      if (method !== 'GET') {
        // Cross-site request forgery: browsers cannot add this header cross-origin without a CORS
        // preflight (which this server never approves), and the cookie is SameSite=Strict as well.
        if (req.headers['x-emberwall'] !== '1') throw new HttpError(403, 'Missing request header.');
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-origin request refused.');
        if (!/^application\/json/.test(req.headers['content-type'] ?? 'application/json')) throw new HttpError(415, 'Send JSON.');
      }
      const user = sessionUser(db, cookieOf(req), now());
      if (r.role) {
        if (!user) throw new HttpError(401, 'Sign in first.');
        if (!atLeast(user, r.role)) throw new HttpError(403, `This needs the ${r.role} role.`);
      }
      const fwd = opts.trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() : '';
      const ctx: Ctx = { req, res, user, params: (match as RegExpExecArray).slice(1), body: method === 'GET' ? {} : await readBody(req), query: url.searchParams, ip: fwd || req.socket.remoteAddress || '?' };
      send(res, 200, await r.handler(ctx));
    } catch (e) {
      if (e instanceof HttpError) send(res, e.status, { error: e.message, ...e.extra });
      else {
        console.error(e);
        send(res, 500, { error: 'Internal error.' });
      }
    }
  };
}
