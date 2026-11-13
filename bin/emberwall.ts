// Entry point of the standalone executable (Node.js single executable application, built by
// scripts/build-bin.mjs). Adds "serve" and "licenses" to the regular CLI. Inside the executable the
// web app and the license notices are SEA assets; run from source they are read from disk.
import './mark';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as nodeSea from 'node:sea';
import { main } from '../cli/emberwall';
import { startServer } from '../server/start';

type Sea = typeof nodeSea;

function webFiles(s: Sea) {
  const keys = new Set(s.getAssetKeys());
  return (path: string) => {
    const key = `web/${path}`;
    return keys.has(key) ? new Uint8Array(s.getRawAsset(key)) : undefined;
  };
}

const [cmd] = process.argv.slice(2);
const s = nodeSea.isSea() ? nodeSea : null;
if (cmd === 'serve') {
  if (s) startServer({ files: webFiles(s) });
  else startServer({ staticDir: process.env.EMBERWALL_STATIC ?? join(process.cwd(), 'dist') });
} else if (cmd === 'licenses') {
  // Long output; piping into "head" closes stdout early, which is fine.
  process.stdout.on('error', (e: NodeJS.ErrnoException) => process.exit(e.code === 'EPIPE' ? 0 : 1));
  if (s) process.stdout.write(s.getAsset('THIRD_PARTY_NOTICES.txt', 'utf8'));
  else {
    const file = join(process.cwd(), 'dist-bin', 'THIRD_PARTY_NOTICES.txt');
    if (!existsSync(file)) {
      console.error('No notices file: run "npm run build:bin" first.');
      process.exit(2);
    }
    process.stdout.write(readFileSync(file, 'utf8'));
  }
} else {
  process.exit(main(process.argv.slice(2)));
}
