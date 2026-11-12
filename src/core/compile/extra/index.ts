// Extra output backends beyond the Linux tools: BSD pf, Windows Firewall,
// cloud firewalls (Terraform) and Kubernetes NetworkPolicy.
import type { Project } from '../../model';
import type { Diagnostic, OutFile } from '../types';
import { compileCloud } from './cloud';
import { compileK8s } from './k8s';
import { compilePf } from './pf';
import { compileWindows } from './windows';

export interface ExtraResult {
  files: OutFile[];
  diagnostics: Diagnostic[];
}

export interface ExtraTarget {
  id: string;
  label: string;
  description: string;
  compile: (p: Project) => ExtraResult;
}

export { compileCloud, type CloudProvider } from './cloud';
export { compileK8s, type K8sOptions } from './k8s';
export { compilePf, type PfFlavor, type PfOptions } from './pf';
export { compileWindows } from './windows';

export const EXTRA_TARGETS: ExtraTarget[] = [
  {
    id: 'pf-openbsd',
    label: 'pf (OpenBSD)',
    description: 'pf.conf with match ... nat-to / rdr-to translation rules',
    compile: (p) => compilePf(p, { flavor: 'openbsd' }),
  },
  {
    id: 'pf-freebsd',
    label: 'pf (FreeBSD)',
    description: 'pf.conf with nat on / rdr on translation rules',
    compile: (p) => compilePf(p, { flavor: 'freebsd' }),
  },
  {
    id: 'windows',
    label: 'Windows Firewall',
    description: 'PowerShell script using New-NetFirewallRule (no rule order: block wins over allow)',
    compile: (p) => compileWindows(p),
  },
  {
    id: 'aws',
    label: 'AWS security group',
    description: 'Terraform: aws_security_group with ingress / egress rules (allow-only)',
    compile: (p) => compileCloud(p, 'aws'),
  },
  {
    id: 'azure',
    label: 'Azure NSG',
    description: 'Terraform: azurerm_network_security_group with prioritised allow / deny rules',
    compile: (p) => compileCloud(p, 'azure'),
  },
  {
    id: 'gcp',
    label: 'Google Cloud firewall',
    description: 'Terraform: google_compute_firewall rules with priorities',
    compile: (p) => compileCloud(p, 'gcp'),
  },
  {
    id: 'k8s',
    label: 'Kubernetes NetworkPolicy',
    description: 'NetworkPolicy for pods labelled app=web in the default namespace (allow-only)',
    compile: (p) => compileK8s(p, { namespace: 'default', podSelector: { app: 'web' } }),
  },
];
