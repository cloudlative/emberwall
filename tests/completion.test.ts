// Shell completion: the bash script is exercised for real (bash is always there); zsh and fish
// scripts are syntax-checked when those shells are installed.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { main } from '../cli/emberwall';
import { COMMANDS, completionScript, targetWords } from '../cli/completion';
import { DISTROS, VERSIONS } from '../src/core/targets';

const dir = mkdtempSync(join(tmpdir(), 'ew-complete-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
mkdirSync(join(dir, 'out'));
for (const f of ['web.json', 'my project.json', 'notes.txt']) writeFileSync(join(dir, f), '{}');
const bashFile = join(dir, 'emberwall.bash');
writeFileSync(bashFile, completionScript('bash'));

/** What bash offers on Tab at the end of `line`. */
function tab(line: string): string[] {
  const script = 'source "$1"; COMP_LINE="$2"; COMP_POINT=${#COMP_LINE}; _emberwall; printf "%s\\n" "${COMPREPLY[@]}"';
  return execFileSync('bash', ['-c', script, '_', bashFile, line], { cwd: dir, encoding: 'utf8' }).split('\n').filter(Boolean).sort();
}

const has = (shell: string) => spawnSync(shell, ['-c', 'true']).status === 0;

describe('shell completion', () => {
  it('prints a script per shell, and refuses an unknown one', () => {
    const out: string[] = [];
    expect(main(['completion', 'zsh'], (s) => out.push(s), () => {})).toBe(0);
    expect(out.join('\n')).toContain('compdef _emberwall emberwall');
    expect(main(['completion', 'tcsh'], () => {}, () => {})).toBe(2);
  });

  it('knows every command the help lists', () => {
    const help: string[] = [];
    main(['--help'], (s) => help.push(s));
    const listed = [...help.join('\n').matchAll(/^ {2}emberwall ([a-z]+)/gm)].map((m) => m[1]);
    for (const c of listed) expect(COMMANDS.map((x) => x.name)).toContain(c);
  });

  it('offers every distribution and tool version as a target', () => {
    const words = targetWords();
    for (const d of DISTROS) expect(words).toContain(`${d.id}:${d.defaultTool}`);
    expect(words).toContain(`nftables@${VERSIONS.nftables[VERSIONS.nftables.length - 1]}`);
  });

  it('bash: commands, flags and values', () => {
    expect(tab('emberwall b')).toEqual(['build']);
    expect(tab('emberwall build web.json --')).toEqual(['--iac', '--out', '--strict', '--target']);
    expect(tab('emberwall build web.json --target nft --')).toEqual(['--iac', '--out', '--strict']);
    expect(tab('emberwall build x --target nftables@1.1')).toEqual(['nftables@1.1.3', 'nftables@1.1.5', 'nftables@1.1.6']);
    expect(tab('emberwall compliance x --profile ')).toEqual(['cis', 'internet', 'pci']);
    expect(tab('emberwall completion ')).toEqual(['bash', 'fish', 'zsh']);
    expect(tab('emberwall targets ')).toEqual([]);
  });

  it('bash: completes after the colon of distro:tool', () => {
    // bash splits words at ":", so the reply must be only the part after it.
    expect(tab('emberwall build x --target debian-12:nf')).toEqual(['nftables']);
  });

  it('bash: offers project files and folders, not other files', () => {
    expect(tab('emberwall audit ')).toEqual(['my project.json', 'out', 'web.json']);
    expect(tab('emberwall fleet x --out ')).toEqual(['out']);
  });

  it.runIf(has('zsh'))('zsh: script parses', () => {
    const f = join(dir, '_emberwall');
    writeFileSync(f, completionScript('zsh'));
    expect(spawnSync('zsh', ['-n', f]).status).toBe(0);
  });

  it.runIf(has('fish'))('fish: script parses', () => {
    const f = join(dir, 'emberwall.fish');
    writeFileSync(f, completionScript('fish'));
    expect(spawnSync('fish', ['--no-execute', f]).status).toBe(0);
  });
});
