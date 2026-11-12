import type { Project } from '../model';
import { harden } from '../safety';
import type { Target } from '../targets';
import { compileFirewalld } from './firewalld';
import { compileIptables } from './iptables';
import { compileNftables } from './nftables';
import type { CompileResult } from './types';
import { compileUfw } from './ufw';

export * from './types';

export function compile(input: Project, target: Target): CompileResult {
  // Every build starts from a hardened copy: see safety.ts.
  const { project, problems } = harden(input);
  const result = build(project, target);
  if (problems.length > 0) {
    result.diagnostics.unshift(...problems.map((x) => ({ level: 'error' as const, kind: 'invalid' as const, message: `${x.message} (left out of the output)`, ruleId: x.ruleId })));
  }
  return result;
}

function build(project: Project, target: Target): CompileResult {
  switch (target.tool) {
    case 'iptables':
      return compileIptables(project, target);
    case 'nftables':
      return compileNftables(project, target);
    case 'ufw':
      return compileUfw(project, target);
    case 'firewalld':
      return compileFirewalld(project, target);
  }
}
