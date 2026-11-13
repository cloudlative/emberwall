#!/usr/bin/env node
// Builds the standalone executable for the current platform with Node's single executable
// applications (node --build-sea, Node 25.5+): dist-bin/emberwall-<os>-<arch>[.exe].
// Expects the web app in dist/ ("npm run build:bin" runs "npm run build" first).
// https://nodejs.org/api/single-executable-applications.html
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist-bin');
const work = join(out, '.work');
const web = join(root, 'dist');

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 25 || (major === 25 && minor < 5)) throw new Error(`node --build-sea needs Node 25.5 or newer (this is ${process.version})`);
if (!existsSync(join(web, 'index.html'))) throw new Error('dist/index.html is missing: run "npm run build" first');

const os = { linux: 'linux', darwin: 'macos', win32: 'windows' }[process.platform];
const arch = { x64: 'x64', arm64: 'arm64' }[process.arch];
if (!os || !arch) throw new Error(`unsupported platform ${process.platform}-${process.arch}`);
const exe = join(out, `emberwall-${os}-${arch}${os === 'windows' ? '.exe' : ''}`);

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });

// 1. One CommonJS file (SEA's injected require only loads builtins, so everything is bundled).
// ssh2's optional native parts (its crypto addon and cpu-features) stay out: their require() is in a
// try/catch inside ssh2 and fails at runtime, so ssh2 uses its pure-JS code paths.
const bundle = join(work, 'emberwall.cjs');
await build({
  entryPoints: [join(root, 'bin', 'emberwall.ts')],
  outfile: bundle,
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: `node${major}`,
  external: ['*.node', 'cpu-features'],
  // server/db.ts uses createRequire(import.meta.url) for node:sqlite; give CommonJS a value for it
  // (inside the executable __filename is the executable's own path).
  define: { 'import.meta.url': '__emberwallMetaUrl' },
  banner: { js: "var __emberwallMetaUrl = require('node:url').pathToFileURL(__filename).href;" },
  legalComments: 'none',
  logLevel: 'warning',
});

// 2. Third-party notices: Node.js itself plus every production dependency (server bundle and web app).
// Optional packages (cpu-features and its build helpers) are native-only and never bundled.
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const pkgs = [...new Set(Object.entries(lock.packages)
  .filter(([p, info]) => p.startsWith('node_modules/') && !info.dev && !info.devOptional && !info.optional)
  .map(([p]) => p))]
  .sort();
const licenseText = (dir) => {
  const f = existsSync(dir) ? readdirSync(dir).find((n) => /^(licen[cs]e|copying)(\.|$)/i.test(n)) : undefined;
  return f ? readFileSync(join(dir, f), 'utf8').trim() : null;
};
const sections = [];
const nodeLicense = [join(dirname(process.execPath), '..', 'LICENSE'), join(dirname(process.execPath), 'LICENSE')].find(existsSync);
sections.push(`Node.js ${process.version} (the runtime this executable is built on)\nhttps://github.com/nodejs/node/blob/${process.version}/LICENSE\n\n${nodeLicense ? readFileSync(nodeLicense, 'utf8').trim() : 'MIT License, plus the licenses of its bundled dependencies; see the link above.'}`);
for (const p of pkgs) {
  const dir = join(root, p);
  const meta = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  sections.push(`${meta.name} ${meta.version} (${meta.license ?? 'see below'})\n\n${licenseText(dir) ?? `License: ${meta.license ?? 'unknown'} (no license file in the package)`}`);
}
const notices = `Emberwall ${JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version} - third-party notices\n\nThis executable contains the following third-party software.\n\n${sections.map((x) => `${'='.repeat(78)}\n${x}\n`).join('\n')}`;
const noticesFile = join(out, 'THIRD_PARTY_NOTICES.txt');
writeFileSync(noticesFile, notices);

// 3. SEA config: the bundle plus the web app and notices as assets.
const assets = { 'THIRD_PARTY_NOTICES.txt': noticesFile };
const walk = (dir) => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : [join(dir, n)]));
for (const f of walk(web)) assets[`web/${relative(web, f).split(sep).join('/')}`] = f;
const config = join(work, 'sea-config.json');
writeFileSync(config, JSON.stringify({
  main: bundle,
  mainFormat: 'commonjs',
  output: exe,
  disableExperimentalSEAWarning: true,
  useCodeCache: true, // built on the target platform itself, so the code cache is valid
  useSnapshot: false,
  execArgvExtension: 'none', // NODE_OPTIONS from the environment does not change the binary
  assets,
}, null, 2));

rmSync(exe, { force: true });
execFileSync(process.execPath, ['--build-sea', config], { stdio: 'inherit' });
// macOS refuses to run the modified binary until it is signed again (ad hoc is enough locally).
if (process.platform === 'darwin') execFileSync('codesign', ['--sign', '-', '--force', exe], { stdio: 'inherit' });

rmSync(work, { recursive: true, force: true });
console.log(`built ${relative(root, exe)} (${(statSync(exe).size / 1048576).toFixed(1)} MB, ${Object.keys(assets).length - 1} web files, ${pkgs.length} third-party packages)`);
