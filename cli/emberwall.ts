#!/usr/bin/env node
// Emberwall command line: build, audit and test project files outside the browser (for CI).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, fileText } from '../src/core/compile';
import { iacFiles } from '../src/core/compile/iac';
import { assess, PROFILES } from '../src/core/compliance';
import { buildFleet, fleetFiles } from '../src/core/fleet';
import { grade, lint, score } from '../src/core/lint';
import { coerceProject, type Project } from '../src/core/model';
import { runTests } from '../src/core/reach';
import { DISTROS, resolveTarget, TOOLS, VERSIONS, type Target, type Tool } from '../src/core/targets';
import { version as pkgVersion } from '../package.json';

const HELP = `emberwall - firewall builder CLI

Usage:
  emberwall build <project.json> --target <target> [--out <dir>] [--iac] [--strict]
  emberwall fleet <project.json> [--out <dir>]
  emberwall audit <project.json> [--min-score <0-100>]
  emberwall test  <project.json>
  emberwall compliance <project.json> [--profile cis|pci|internet] [--min <0-100>]
  emberwall targets
  emberwall serve        start server mode (web app + API; standalone binary only,
                         from a source checkout use "npm run server")
  emberwall licenses     third-party license notices (standalone binary)
  emberwall --version

Targets:
  <distro>:<tool>      e.g. debian-12:nftables, ubuntu-24.04:ufw
  <tool>@<version>     e.g. nftables@1.0.9, iptables@1.8.10

Options:
  --out <dir>     write files there (default: print the main file)
  --iac           also write the Ansible, Terraform and cloud-init files
  --strict        exit 1 when the build has version fallbacks or unsupported features

Exit status: 0 ok, 1 a check failed, 2 usage or input error.`;

class UsageError extends Error {}

function parseTarget(spec: string | undefined): Target {
  if (!spec) throw new UsageError('--target is required (see "emberwall targets")');
  if (spec.includes('@')) {
    const [tool, version] = spec.split('@');
    if (!TOOLS.includes(tool as Tool)) throw new UsageError(`unknown tool "${tool}"`);
    if (!VERSIONS[tool as Tool].includes(version)) throw new UsageError(`unknown ${tool} version "${version}" (known: ${VERSIONS[tool as Tool].join(', ')})`);
    return resolveTarget({ distro: 'custom', tool: tool as Tool, version });
  }
  const [distroId, tool] = spec.split(':');
  const distro = DISTROS.find((d) => d.id === distroId);
  if (!distro) throw new UsageError(`unknown distribution "${distroId}"`);
  const t = (tool ?? distro.defaultTool) as Tool;
  if (distro.tools[t] === undefined) throw new UsageError(`${distro.name} does not package ${t}`);
  return resolveTarget({ distro: distro.id, tool: t, version: '' });
}

function load(path: string | undefined): Project {
  if (!path) throw new UsageError('missing project file');
  try {
    return coerceProject(JSON.parse(readFileSync(path, 'utf8')));
  } catch (e) {
    throw new UsageError(`cannot read ${path}: ${(e as Error).message}`);
  }
}

function writeAll(dir: string, files: { path: string; text: string }[]) {
  for (const f of files) {
    const full = join(dir, f.path);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, f.text);
  }
}

export function main(argv: string[], out: (s: string) => void = console.log, err: (s: string) => void = console.error): number {
  const [cmd, ...rest] = argv;
  const flags: Record<string, string | true> = {};
  const pos: string[] = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith('--') && !['iac', 'strict'].includes(a.slice(2))) flags[a.slice(2)] = rest[(i += 1)];
      else flags[a.slice(2)] = true;
    } else pos.push(a);
  }
  const str = (k: string) => (typeof flags[k] === 'string' ? (flags[k] as string) : undefined);
  try {
    switch (cmd) {
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        out(HELP);
        return cmd ? 0 : 2;
      case '--version':
      case '-v':
      case 'version':
        out(pkgVersion);
        return 0;
      case 'serve':
      case 'licenses':
        throw new UsageError(`"${cmd}" is part of the standalone binary; from a source checkout use "npm run server" (see README)`);
      case 'targets':
        for (const d of DISTROS) out(`${d.id.padEnd(14)} ${Object.entries(d.tools).map(([t, v]) => `${t}@${v}${t === d.defaultTool ? '*' : ''}`).join('  ')}`);
        out('\n(* = the distribution\'s default firewall manager)');
        return 0;
      case 'build': {
        const p = load(pos[0]);
        const result = compile(p, parseTarget(str('target')));
        const issues = result.diagnostics.filter((d) => d.level !== 'info');
        for (const d of issues) err(`${d.level === 'error' ? 'error' : 'warning'}: ${d.message}`);
        const dir = str('out');
        if (dir) {
          const files = [...result.files, ...(flags.iac ? iacFiles(result) : [])];
          writeAll(dir, files.map((f) => ({ path: f.name, text: fileText(f) })));
          err(`wrote ${files.length} files to ${dir} for ${result.target.label}`);
        } else out(fileText(result.files[0]).trimEnd());
        if (result.diagnostics.some((d) => d.level === 'error')) return 1;
        return flags.strict && issues.length > 0 ? 1 : 0;
      }
      case 'fleet': {
        const p = load(pos[0]);
        if (p.hosts.length === 0) throw new UsageError('this project has no hosts');
        const builds = buildFleet(p);
        for (const b of builds) out(`${b.host.name.padEnd(20)} ${b.result.target.label.padEnd(44)} rules ${String(b.rules).padStart(3)}  score ${b.score}${b.errors ? `  ERRORS ${b.errors}` : ''}`);
        const dir = str('out');
        if (dir) {
          writeAll(dir, fleetFiles(builds));
          err(`wrote the fleet bundle to ${dir}`);
        }
        return builds.some((b) => b.errors > 0) ? 1 : 0;
      }
      case 'audit': {
        const findings = lint(load(pos[0]));
        const s = score(findings);
        for (const f of findings) out(`${f.severity.toUpperCase().padEnd(8)} ${f.title}`);
        out(`\nscore ${s}/100 (grade ${grade(s)})`);
        const min = Number(str('min-score') ?? 0);
        return s < min ? 1 : 0;
      }
      case 'test': {
        const results = runTests(load(pos[0]));
        if (results.length === 0) {
          out('no policy tests in this project');
          return 0;
        }
        for (const r of results) out(`${r.pass ? 'PASS' : 'FAIL'}  ${r.test.name}${r.pass ? '' : `  (expected ${r.test.expect}, got ${r.verdict} by ${r.decidedBy})`}`);
        const failed = results.filter((r) => !r.pass).length;
        out(`\n${results.length - failed}/${results.length} passed`);
        return failed > 0 ? 1 : 0;
      }
      case 'compliance': {
        const profile = str('profile') ?? 'cis';
        if (!PROFILES.some((x) => x.id === profile)) throw new UsageError(`unknown profile "${profile}"`);
        const rep = assess(load(pos[0]), profile);
        for (const r of rep.results) out(`${r.status.toUpperCase().padEnd(5)} ${r.title} - ${r.evidence}`);
        out(`\n${rep.profile.name}: ${rep.percent}% (${rep.passed} passed, ${rep.failed} failed)`);
        return rep.percent < Number(str('min') ?? 0) ? 1 : 0;
      }
      default:
        throw new UsageError(`unknown command "${cmd}"`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err(`emberwall: ${e.message}\n`);
      err(HELP);
      return 2;
    }
    throw e;
  }
}

// Run only when executed as a script (directly, bundled, or through vite-node, which strips the
// script name from argv), not when imported by tests or by the standalone binary (bin/emberwall.ts).
if (!process.env.VITEST && !(globalThis as { __emberwallBin?: boolean }).__emberwallBin && /(emberwall(\.ts|\.mjs)?|vite-node)$/.test(process.argv[1] ?? '')) {
  process.exit(main(process.argv.slice(2)));
}
