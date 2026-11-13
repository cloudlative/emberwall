// Starts the Emberwall server from environment variables. Used by server/index.ts (source checkout,
// web app read from disk) and by the single-file binary (web app embedded in the executable).
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createApp, type StaticFiles } from './app';
import { openDb } from './db';
import { Vault } from './secrets';

export interface StartOptions {
  /** Directory holding the built web app (used when `files` is not given). */
  staticDir?: string;
  /** In-memory web app, keyed by path relative to the app root (e.g. "index.html"). */
  files?: StaticFiles;
  env?: NodeJS.ProcessEnv;
}

export function startServer(opts: StartOptions = {}): Server {
  const env = opts.env ?? process.env;
  const port = Number(env.PORT ?? env.EMBERWALL_PORT ?? 8787);
  const host = env.EMBERWALL_HOST ?? '127.0.0.1';
  const dbPath = env.EMBERWALL_DB ?? './data/emberwall.db';
  const secret = env.EMBERWALL_SECRET ?? (env.EMBERWALL_SECRET_FILE ? readFileSync(env.EMBERWALL_SECRET_FILE, 'utf8').trim() : undefined);

  const vault = new Vault(secret);
  const app = createApp({
    db: openDb(dbPath), vault, staticDir: opts.staticDir, staticFiles: opts.files, secureCookies: env.EMBERWALL_HTTPS === '1', trustProxy: env.EMBERWALL_TRUST_PROXY === '1',
  });

  return createServer((req, res) => void app(req, res)).listen(port, host, () => {
    console.log(`Emberwall server on http://${host}:${port}  (database: ${dbPath})`);
    if (secret && !vault.configured) console.log('EMBERWALL_SECRET is shorter than 32 characters and was ignored.');
    if (!vault.configured) console.log('No master key: set EMBERWALL_SECRET (32+ random characters) to store SSH credentials.');
    if (host !== '127.0.0.1' && host !== 'localhost' && env.EMBERWALL_HTTPS !== '1') console.log('Warning: listening beyond localhost without HTTPS. Put a TLS reverse proxy in front and set EMBERWALL_HTTPS=1.');
  });
}
