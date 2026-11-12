// Feeds generated rulesets to the real binaries when they are installed and usable.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { resolveTarget } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

function usable(cmd: string, args: string[], input?: string): boolean {
  const r = spawnSync(cmd, args, { input, encoding: 'utf8' });
  return r.status === 0;
}

const dir = mkdtempSync(join(tmpdir(), 'emberwall-'));
const probe = '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n';
const hasIptables = usable('iptables-restore', ['--test'], probe);
const hasIp6tables = usable('ip6tables-restore', ['--test'], probe);
const hasNft = usable('nft', ['-c', 'list', 'ruleset']);

function check(cmd: string, args: string[], input?: string) {
  const r = spawnSync(cmd, args, { input, encoding: 'utf8' });
  expect(r.stderr + r.stdout, `${cmd} ${args.join(' ')}`).toBe('');
  expect(r.status).toBe(0);
}

describe.skipIf(!hasIptables)('real iptables-restore --test', () => {
  for (const t of TEMPLATES) {
    it(`accepts ${t.id}`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'iptables', version: '1.8.10' }));
      check('iptables-restore', ['--test'], fileText(res.files[0]));
      if (hasIp6tables) check('ip6tables-restore', ['--test'], fileText(res.files[1]));
    });
  }
});

describe.skipIf(!hasNft)('real nft --check', () => {
  const installed = execFileSync('nft', ['--version'], { encoding: 'utf8' }).match(/v(\d+\.\d+\.\d+)/)?.[1] ?? '1.0.0';
  for (const t of TEMPLATES) {
    it(`accepts ${t.id} (nft ${installed})`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'nftables', version: installed }));
      const f = join(dir, `${t.id}.nft`);
      writeFileSync(f, fileText(res.files[0]));
      check('nft', ['-c', '-f', f]);
    });
    it(`accepts ${t.id} with every fallback active`, () => {
      const res = compile(t.build(), resolveTarget({ distro: 'custom', tool: 'nftables', version: '0.9.0' }));
      const f = join(dir, `${t.id}-old.nft`);
      writeFileSync(f, fileText(res.files[0]));
      check('nft', ['-c', '-f', f]);
    });
  }
});

describe('real tools availability', () => {
  it('reports what could be checked', () => {
    console.log(`real-tool checks: iptables=${hasIptables} ip6tables=${hasIp6tables} nft=${hasNft}`);
    expect(true).toBe(true);
  });
});
