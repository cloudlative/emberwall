import { Out, type OutFile } from './types';

export interface ApplyPlan {
  toolLabel: string;
  /** Commands that save the running ruleset into $BACKUP. */
  backup: string[];
  /** Dry-run / syntax checks; a failure aborts before anything changes. */
  check: string[];
  apply: string[];
  /** Commands that restore the ruleset from $BACKUP. */
  rollback: string[];
  /** Shown as a comment block: how to make the rules survive a reboot. */
  persist: string[];
}

/**
 * A POSIX sh script that applies the ruleset and reverts it automatically unless the
 * operator confirms. The watchdog runs detached, so the rollback still happens when the
 * new rules cut the SSH session that started the script.
 */
export function safeApplyScript(plan: ApplyPlan): OutFile {
  const o = new Out();
  o.push('#!/bin/sh');
  o.push(`# Emberwall safe apply for ${plan.toolLabel}.`);
  o.push('# Backs up the running rules, applies the new ones, and rolls back after');
  o.push('# $TIMEOUT seconds unless you confirm - so a mistake cannot lock you out.');
  o.push('# Run as root from the directory that holds the generated files.');
  o.push('set -eu');
  o.blank();
  o.push('TIMEOUT="${TIMEOUT:-60}"');
  o.push('DIR="$(cd "$(dirname "$0")" && pwd)"');
  o.push('BACKUP="$(mktemp -d /tmp/emberwall-backup.XXXXXX)"');
  o.blank();
  o.push('[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }');
  o.blank();
  o.push('echo "==> Backing up current rules to $BACKUP"');
  plan.backup.forEach((c) => o.push(c));
  o.blank();
  o.push('rollback() {');
  plan.rollback.forEach((c) => o.push(`  ${c}`));
  o.push('  echo "==> Rolled back to the previous rules."');
  o.push('}');
  if (plan.check.length > 0) {
    o.blank();
    o.push('echo "==> Checking the new rules"');
    plan.check.forEach((c) => o.push(c));
  }
  o.blank();
  // Keeping and rolling back are decided exactly once: whoever creates $BACKUP/decided first
  // (mkdir is atomic) wins, so a late "yes" can never claim the rules were kept after the timer
  // has already restored the old ones.
  o.push('decide() { mkdir "$BACKUP/decided" 2>/dev/null; }');
  o.blank();
  o.push('echo "==> Applying"');
  o.push('( trap "" HUP; sleep "$TIMEOUT"; if decide; then rollback; fi ) >/dev/null 2>&1 &');
  o.push('WATCHDOG=$!');
  o.push('if ! (');
  plan.apply.forEach((c) => o.push(`  ${c}`));
  o.push('); then');
  o.push('  if decide; then kill "$WATCHDOG" 2>/dev/null || true; rollback; fi');
  o.push('  exit 1');
  o.push('fi');
  o.blank();
  o.push('printf \'Applied. Open a NEW session to check access, then type "yes" within %s seconds to keep: \' "$TIMEOUT"');
  o.push('read -r answer || answer=""');
  o.push('if ! decide; then');
  o.push('  echo "==> Too late: the timer ran out and the previous rules were restored. Nothing was kept."');
  o.push('  exit 1');
  o.push('fi');
  o.push('kill "$WATCHDOG" 2>/dev/null || true');
  o.push('if [ "$answer" = "yes" ]; then');
  o.push('  echo "==> Kept. The backup stays in $BACKUP"');
  o.push('else');
  o.push('  rollback');
  o.push('fi');
  if (plan.persist.length > 0) {
    o.blank();
    o.push('# --- Make it permanent (survive reboot) ---');
    plan.persist.forEach((c) => o.push(`#   ${c}`));
  }
  return {
    name: 'emberwall-apply.sh',
    path: './emberwall-apply.sh',
    lang: 'shell',
    description: 'Safe apply with automatic rollback',
    lines: o.lines,
  };
}
