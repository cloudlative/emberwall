// Passwords (scrypt), sessions (random tokens, stored hashed) and login throttling.
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Db, Role } from './db';

export interface User {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
}

export const MIN_PASSWORD = 10;
export const IDLE_MS = 12 * 60 * 60 * 1000;
export const ABSOLUTE_MS = 7 * 24 * 60 * 60 * 1000;

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

export function hashPassword(password: string, salt = randomBytes(16).toString('hex')) {
  return { salt, hash: scryptSync(password.normalize('NFKC'), salt, 32, SCRYPT).toString('hex') };
}

export function verifyPassword(password: string, salt: string, hash: string): boolean {
  const got = Buffer.from(hashPassword(password, salt).hash, 'hex');
  const want = Buffer.from(hash, 'hex');
  return got.length === want.length && timingSafeEqual(got, want);
}

export function validUsername(u: unknown): u is string {
  return typeof u === 'string' && /^[A-Za-z0-9_.-]{2,32}$/.test(u);
}

export function passwordProblem(p: unknown): string | null {
  if (typeof p !== 'string' || p.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters.`;
  if (p.length > 200) return 'Password is too long.';
  return null;
}

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/** Returns the token to put in the cookie. Only its hash is stored. */
export function createSession(db: Db, userId: number, now = Date.now()): string {
  const token = randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)').run(sha(token), userId, now, now);
  return token;
}

export function sessionUser(db: Db, token: string | undefined, now = Date.now()): User | null {
  if (!token) return null;
  const h = sha(token);
  const row = db
    .prepare('SELECT s.created_at, s.last_seen, u.id, u.username, u.role, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?')
    .get(h) as { created_at: number; last_seen: number; id: number; username: string; role: Role; disabled: number } | undefined;
  if (!row) return null;
  if (row.disabled || now - row.last_seen > IDLE_MS || now - row.created_at > ABSOLUTE_MS) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(h);
    return null;
  }
  if (now - row.last_seen > 60_000) db.prepare('UPDATE sessions SET last_seen = ? WHERE token_hash = ?').run(now, h);
  return { id: row.id, username: row.username, role: row.role, disabled: false };
}

export function destroySession(db: Db, token: string | undefined) {
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token));
}

export function destroyUserSessions(db: Db, userId: number) {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

/** Sliding-window attempt counter, kept in memory. */
export class Throttle {
  private hits = new Map<string, number[]>();
  constructor(private max: number, private windowMs: number) {}
  blocked(key: string, now = Date.now()): boolean {
    const list = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    this.hits.set(key, list);
    return list.length >= this.max;
  }
  fail(key: string, now = Date.now()) {
    this.hits.set(key, [...(this.hits.get(key) ?? []), now]);
  }
  clear(key: string) {
    this.hits.delete(key);
  }
}

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
export const atLeast = (user: User, role: Role) => RANK[user.role] >= RANK[role];
