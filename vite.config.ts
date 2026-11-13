import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { join, relative } from 'node:path';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

/**
 * Writes the list of built files into dist/sw.js so the service worker can cache the whole
 * app when it installs. Without this, a first visit loads its assets before the worker is in
 * control and the app would not open offline until a second online visit.
 */
function precache(): Plugin {
  return {
    name: 'emberwall-precache',
    apply: 'build',
    closeBundle() {
      const dist = join(process.cwd(), 'dist');
      const walk = (dir: string): string[] =>
        readdirSync(dir).flatMap((name) => {
          const full = join(dir, name);
          return statSync(full).isDirectory() ? walk(full) : [full];
        });
      let files: string[];
      try {
        files = walk(dist);
      } catch {
        return;
      }
      const assets = files
        .map((f) => relative(dist, f).split('\\').join('/'))
        .filter((f) => f !== 'sw.js' && f !== 'index.html')
        .map((f) => `./${f}`);
      const hash = createHash('sha256');
      for (const f of files.filter((x) => !x.endsWith('sw.js'))) hash.update(readFileSync(f));
      const sw = join(dist, 'sw.js');
      const text = readFileSync(sw, 'utf8')
        .replace(/\/\*__PRECACHE__\*\/ \[[^\]]*\]/, JSON.stringify(['./', ...assets]))
        .replace(/\/\*__VERSION__\*\/ 'dev'/, JSON.stringify(hash.digest('hex').slice(0, 12)));
      writeFileSync(sw, text);
    },
  };
}

const API_HOST = '127.0.0.1';
const API_PORT = 8787;
let apiChecked = 0;
let apiUp = false;

/** Whether the development API is listening; the answer is reused for a second. */
function apiIsUp(): Promise<boolean> {
  if (Date.now() - apiChecked < 1000) return Promise.resolve(apiUp);
  return new Promise((resolve) => {
    const socket = connect({ host: API_HOST, port: API_PORT });
    const finish = (up: boolean) => {
      socket.destroy();
      apiChecked = Date.now();
      apiUp = up;
      resolve(up);
    };
    socket.setTimeout(500, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

export default defineConfig({
  base: './',
  plugins: [react(), precache()],
  // In development the API is served by `npm run server:dev`; without it the app runs browser-only.
  // When it is not running, answer 404 quietly (the app reads that as "no server") rather than
  // letting the proxy log a connection error for every request.
  server: { proxy: { '/api': { target: `http://${API_HOST}:${API_PORT}`, changeOrigin: false, bypass: async () => ((await apiIsUp()) ? undefined : false) } } },
  test: { environment: 'node', include: ['tests/**/*.test.ts'] },
});
