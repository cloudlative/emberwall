// SQLite storage (Node's built-in driver). One file; schema versioned with PRAGMA user_version.
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createRequire } from 'node:module';
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite';

// Loaded through require so bundlers and test runners that do not know this newer built-in leave it alone.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

export type Role = 'admin' | 'operator' | 'viewer';
export const ROLES: Role[] = ['admin', 'operator', 'viewer'];

const MIGRATIONS: string[] = [
  `
  CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, pass_hash TEXT NOT NULL, salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')), disabled INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
  );
  CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
  );
  CREATE TABLE servers (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL,
    auth_kind TEXT NOT NULL CHECK (auth_kind IN ('key','password')), secret_enc TEXT, host_key_fp TEXT,
    tags TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
    last_tool TEXT, last_version TEXT, last_os TEXT, last_fetch_at INTEGER, created_at INTEGER NOT NULL, created_by TEXT NOT NULL
  );
  CREATE TABLE projects (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL
  );
  CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    fetched_at INTEGER NOT NULL, by_user TEXT NOT NULL, output TEXT NOT NULL
  );
  CREATE INDEX snapshots_server ON snapshots(server_id, fetched_at DESC);
  CREATE TABLE deployments (
    id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE, project_name TEXT NOT NULL,
    tool TEXT NOT NULL, started_at INTEGER NOT NULL, deadline INTEGER, by_user TEXT NOT NULL,
    status TEXT NOT NULL, log TEXT NOT NULL DEFAULT '', confirm_command TEXT
  );
  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY, at INTEGER NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
  );
  `,
];

export type Db = DatabaseSyncType;

export function openDb(path: string): Db {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const current = (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  for (let v = current; v < MIGRATIONS.length; v += 1) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]);
      db.exec(`PRAGMA user_version = ${v + 1}`);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}

export function logAction(db: Db, username: string, action: string, detail = '') {
  db.prepare('INSERT INTO audit_log (at, username, action, detail) VALUES (?, ?, ?, ?)').run(Date.now(), username, action, detail.slice(0, 500));
}
