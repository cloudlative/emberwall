#!/usr/bin/env node
// Emberwall server: serves the web app and the API. Configuration comes from the environment.
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './app';
import { openDb } from './db';
import { Vault } from './secrets';

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const port = Number(env.PORT ?? env.EMBERWALL_PORT ?? 8787);
const host = env.EMBERWALL_HOST ?? '127.0.0.1';
const dbPath = env.EMBERWALL_DB ?? './data/emberwall.db';
const secret = env.EMBERWALL_SECRET ?? (env.EMBERWALL_SECRET_FILE ? readFileSync(env.EMBERWALL_SECRET_FILE, 'utf8').trim() : undefined);
// dist/ sits next to the bundle (dist-server/) and one level above server/ in a source checkout.
const staticDir = env.EMBERWALL_STATIC ?? join(here, '..', 'dist');

const vault = new Vault(secret);
const app = createApp({ db: openDb(dbPath), vault, staticDir, secureCookies: env.EMBERWALL_HTTPS === '1', trustProxy: env.EMBERWALL_TRUST_PROXY === '1' });

createServer((req, res) => void app(req, res)).listen(port, host, () => {
  console.log(`Emberwall server on http://${host}:${port}  (database: ${dbPath})`);
  if (secret && !vault.configured) console.log('EMBERWALL_SECRET is shorter than 32 characters and was ignored.');
  if (!vault.configured) console.log('No master key: set EMBERWALL_SECRET (32+ random characters) to store SSH credentials.');
  if (host !== '127.0.0.1' && host !== 'localhost' && env.EMBERWALL_HTTPS !== '1') console.log('Warning: listening beyond localhost without HTTPS. Put a TLS reverse proxy in front and set EMBERWALL_HTTPS=1.');
});
