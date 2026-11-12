import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../cli/emberwall';
import { projectContext, sanitizeDraft } from '../src/core/ai';
import { newRule } from '../src/core/model';
import { TEMPLATES } from '../src/core/templates';

const dir = mkdtempSync(join(tmpdir(), 'emberwall-cli-'));
const file = join(dir, 'web.json');
const p = TEMPLATES[0].build();
p.tests = [{ id: 't1', name: 'telnet blocked', packet: { direction: 'in', src: '8.8.8.8', dst: '192.0.2.1', proto: 'tcp', port: 23, state: 'new' }, expect: 'block' }];
p.hosts = [{ id: 'a', name: 'web-a', target: { distro: 'debian-12', tool: 'nftables', version: '' } }, { id: 'b', name: 'old', target: { distro: 'centos-7', tool: 'iptables', version: '' } }];
writeFileSync(file, JSON.stringify(p));

function run(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = main(argv, (s) => out.push(s), (s) => err.push(s));
  return { code, out: out.join('\n'), err: err.join('\n') };
}

describe('cli', () => {
  it('builds to stdout and to a directory', () => {
    const a = run('build', file, '--target', 'nftables@1.0.9');
    expect(a.code).toBe(0);
    expect(a.out).toContain('table inet emberwall {');
    const outDir = join(dir, 'out');
    const b = run('build', file, '--target', 'debian-12:nftables', '--out', outDir, '--iac');
    expect(b.code).toBe(0);
    expect(readdirSync(outDir).sort()).toEqual(['emberwall-apply.sh', 'emberwall-cloud-init.yaml', 'emberwall-playbook.yml', 'emberwall.nft', 'emberwall.tf']);
    expect(readFileSync(join(outDir, 'emberwall.nft'), 'utf8')).toContain('add table inet emberwall'); // Debian 12: nftables 1.0.6 has no destroy
  });
  it('--strict fails a build that needed fallbacks', () => {
    expect(run('build', file, '--target', 'nftables@0.9.0', '--strict').code).toBe(1);
    expect(run('build', file, '--target', 'nftables@1.1.6', '--strict').code).toBe(0);
  });
  it('audits, tests and checks compliance with thresholds', () => {
    expect(run('audit', file).code).toBe(0);
    expect(run('audit', file, '--min-score', '100').code).toBe(1);
    const t = run('test', file);
    expect(t.code).toBe(0);
    expect(t.out).toContain('PASS  telnet blocked');
    const broken = join(dir, 'broken.json');
    writeFileSync(broken, JSON.stringify({ ...p, rules: [...p.rules, newRule({ name: 'oops', proto: 'tcp', ports: ['23'] })] }));
    expect(run('test', broken).code).toBe(1);
    expect(run('compliance', file, '--profile', 'pci', '--min', '100').code).toBe(1);
  });
  it('builds a fleet', () => {
    const outDir = join(dir, 'fleet');
    const r = run('fleet', file, '--out', outDir);
    expect(r.code).toBe(0);
    expect(r.out).toContain('iptables 1.4.21');
    expect(readdirSync(join(outDir, 'hosts')).sort()).toEqual(['old', 'web-a']);
  });
  it('rejects bad input with exit status 2', () => {
    expect(run('build', file).code).toBe(2);
    expect(run('build', file, '--target', 'nope:nftables').code).toBe(2);
    expect(run('build', file, '--target', 'rhel-9:ufw').code).toBe(2);
    expect(run('build', join(dir, 'missing.json'), '--target', 'nftables@1.0.9').code).toBe(2);
    expect(run('frobnicate').code).toBe(2);
    expect(run('targets').out).toContain('ubuntu-26.04');
  });
});

describe('assistant plumbing (no network)', () => {
  it('sends rules and structure, not snapshots, tests or hosts', () => {
    const ctx = JSON.parse(projectContext(p));
    expect(Object.keys(ctx).sort()).toEqual(['addressGroups', 'blocklists', 'name', 'nat', 'options', 'policies', 'portGroups', 'protections', 'rules', 'zones']);
    expect(ctx.rules[0].id).toBeUndefined();
  });
  it('validates model output like hand-written rules', () => {
    const d = sanitizeDraft({
      summary: 'x', warnings: ['careful', 7],
      rules: [
        { name: 'ok', direction: 'in', action: 'accept', proto: 'tcp', ports: ['443'], src: ['@admins'], dst: [], perClientRatePerMinute: 30 },
        { name: 'bad addr', direction: 'sideways', action: 'explode', proto: 'tcp', ports: ['99999'], src: ['not-an-ip; rm -rf /'], dst: [], inIface: 'eth0; reboot', srcZone: 'ghost' },
      ],
    }, p);
    expect(d.rules[0].problems).toEqual([]);
    expect(d.rules[0].rule.rateLimit).toEqual({ rate: 30, per: 'minute', burst: 60, perSource: true });
    expect(d.rules[1].rule).toMatchObject({ direction: 'in', action: 'drop', inIface: undefined, srcZone: undefined });
    expect(d.rules[1].problems.length).toBeGreaterThanOrEqual(2);
    expect(d.warnings).toEqual(['careful', '7']);
    expect(sanitizeDraft(null, p).rules).toEqual([]);
  });
});
