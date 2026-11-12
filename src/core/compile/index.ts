import type { Project } from '../model';
import type { Target } from '../targets';
import { compileFirewalld } from './firewalld';
import { compileIptables } from './iptables';
import { compileNftables } from './nftables';
import type { CompileResult } from './types';
import { compileUfw } from './ufw';

export * from './types';

export function compile(project: Project, target: Target): CompileResult {
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
