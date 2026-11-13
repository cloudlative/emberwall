// Runs the generated emberwall-apply.sh for real (with stand-in firewall commands) to check that
// keeping and rolling back are decided exactly once, including when the answer comes too late.
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { compile } from '../src/core/compile';
import { safeApplyScript } from '../src/core/compile/apply';
import { deployPlan } from '../src/core/compile/deployPlan';
import { fileText } from '../src/core/compile/types';
import { resolveTarget } from '../src/core/targets';
import { TEMPLATES } from '../src/core/templates';

const root = mkdtempSync(join(tmpdir(), 'ew-apply-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

// The script insists on root; a stand-in `id` lets it run unprivileged.
const bin = join(root, 'bin');
mkdirSync(bin);
writeFileSync(join(bin, 'id'), '#!/bin/sh\necho 0\n');
chmodSync(join(bin, 'id'), 0o755);

let n = 0;
/** Runs the script with TIMEOUT=1, types `answer` after `delayMs`, and returns its output and the action log. */
function run(answer: string, delayMs: number): Promise<{ code: number | null; out: string; log: string[] }> {
  const dir = join(root, `run-${(n += 1)}`);
  mkdirSync(dir);
  const script = safeApplyScript({
    toolLabel: 'test',
    backup: ['echo backup >> "$DIR/log"'],
    check: [],
    apply: ['echo apply >> "$DIR/log"'],
    rollback: ['echo rollback >> "$DIR/log"'],
    persist: [],
  });
  writeFileSync(join(dir, 'apply.sh'), fileText(script));
  return new Promise((resolve) => {
    const child = spawn('sh', [join(dir, 'apply.sh')], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TIMEOUT: '1' } });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    setTimeout(() => child.stdin.end(`${answer}\n`), delayMs);
    child.on('close', (code) => {
      // Give a still-armed watchdog time to fire, so a second rollback would show up in the log.
      setTimeout(() => resolve({ code, out, log: readFileSync(join(dir, 'log'), 'utf8').trim().split('\n') }), 1600);
    });
  });
}

describe('safe apply script', () => {
  it('keeps the rules when confirmed in time, and the timer never fires', async () => {
    const r = await run('yes', 100);
    expect(r.code).toBe(0);
    expect(r.out).toContain('Kept.');
    expect(r.log).toEqual(['backup', 'apply']);
  }, 10000);

  it('says so, instead of "Kept", when the answer comes after the timer rolled back', async () => {
    const r = await run('yes', 2200);
    expect(r.code).toBe(1);
    expect(r.out).toContain('Too late');
    expect(r.out).not.toContain('Kept.');
    expect(r.log).toEqual(['backup', 'apply', 'rollback']);
  }, 10000);

  it('rolls back exactly once when the answer is not yes', async () => {
    const r = await run('no', 100);
    expect(r.code).toBe(0);
    expect(r.log).toEqual(['backup', 'apply', 'rollback']);
  }, 10000);
});

describe('guarded push confirmation', () => {
  /** The bodies of confirm.sh and status.sh, as the push script writes them. */
  function scripts(id: number) {
    const state = join(root, `push-${id}`);
    const plan = deployPlan(compile(TEMPLATES[0].build(), resolveTarget({ distro: 'custom', tool: 'nftables', version: '1.0.9' })), { id, timeoutSeconds: 60, etcDir: join(root, `etc-${id}`), stateDir: state });
    const body = (name: string) => new RegExp(`cat > "\\$S/${name}.sh" <<'EMBERWALL_[A-Z]+'\\n([\\s\\S]*?)\\nEMBERWALL_`).exec(plan.script)![1];
    mkdirSync(plan.state, { recursive: true });
    const sh = (src: string) => execFileSync('sh', ['-c', src], { encoding: 'utf8' }).trim();
    return { plan, confirm: () => sh(body('confirm')), status: () => sh(body('status')) };
  }
  it('confirms once and stays confirmed', () => {
    const s = scripts(1);
    expect(s.status()).toBe('pending');
    expect(s.confirm()).toBe('confirmed');
    expect(s.confirm()).toBe('confirmed');
    expect(s.status()).toBe('confirmed');
  });
  it('refuses a confirmation once the timer has started rolling back', () => {
    const s = scripts(2);
    mkdirSync(join(s.plan.state, 'decided')); // what the watchdog does before it rolls back
    expect(s.status()).toBe('rollingback');
    expect(s.confirm()).toBe('rolledback');
    writeFileSync(join(s.plan.state, 'rolledback'), '');
    expect(s.status()).toBe('rolledback');
  });
});
