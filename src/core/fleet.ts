// Fleet: one shared policy, many hosts, each with its own target and its own subset of rules.
import { compile, fileText, Out, type CompileResult, type OutFile } from './compile';
import { lint, score } from './lint';
import type { Host, Project, Rule } from './model';
import { slug } from './resolve';
import { resolveTarget } from './targets';

export const appliesTo = (r: Rule, hostId: string) => !r.hosts || r.hosts.length === 0 || r.hosts.includes(hostId);

/** The project as one host sees it: shared rules plus the rules scoped to that host. */
export function projectForHost(p: Project, hostId: string | null): Project {
  if (!hostId) return p;
  const host = p.hosts.find((h) => h.id === hostId);
  if (!host) return p;
  const o = host.overrides ?? {};
  const excluded = new Set(o.excludeRules ?? []);
  return {
    ...p,
    name: `${p.name} - ${host.name}`,
    policies: { ...p.policies, ...o.policies },
    options: { ...p.options, ...o.options },
    rules: p.rules.filter((r) => appliesTo(r, host.id) && !excluded.has(r.id)),
  };
}

export interface HostBuild {
  host: Host;
  project: Project;
  result: CompileResult;
  score: number;
  rules: number;
  fallbacks: number;
  errors: number;
}

export function buildFleet(p: Project): HostBuild[] {
  return p.hosts.map((host) => {
    const project = projectForHost(p, host.id);
    const result = compile(project, resolveTarget(host.target));
    return {
      host,
      project,
      result,
      score: score(lint(project)),
      rules: project.rules.filter((r) => r.enabled).length,
      fallbacks: result.diagnostics.filter((d) => d.kind === 'fallback' || d.kind === 'unsupported').length,
      errors: result.diagnostics.filter((d) => d.level === 'error').length,
    };
  });
}

export const hostDir = (h: Host) => slug(h.name, 40) || h.id;

/** Ansible inventory + a playbook that pushes each host's own files. */
export function fleetAnsible(builds: HostBuild[]): OutFile[] {
  const inv = new Out();
  inv.push('# Emberwall fleet inventory');
  inv.push('[emberwall]');
  for (const b of builds) inv.push(`${hostDir(b.host)} ansible_host=${b.host.address ?? b.host.name} emberwall_tool=${b.result.target.tool}`);

  const pb = new Out();
  pb.push('---');
  pb.push('# Pushes each host\'s generated files from ./hosts/<name>/ and loads them.');
  pb.push('# Layout expected next to this playbook: hosts/<inventory name>/<generated files>');
  pb.push('# There is no automatic rollback here: roll out to one host first (--limit).');
  pb.push('- name: Deploy Emberwall fleet');
  pb.push('  hosts: emberwall');
  pb.push('  become: true');
  pb.push('  serial: 1');
  pb.push('  vars:');
  pb.push('    emberwall_load:');
  pb.push('      nftables: "nft -c -f /etc/emberwall/emberwall.nft && nft -f /etc/emberwall/emberwall.nft"');
  pb.push('      iptables: "iptables-restore --test < /etc/emberwall/rules.v4 && iptables-restore < /etc/emberwall/rules.v4 && ip6tables-restore < /etc/emberwall/rules.v6"');
  pb.push('      ufw: "sh /etc/emberwall/emberwall-ufw.sh"');
  pb.push('      firewalld: "sh /etc/emberwall/emberwall-firewalld.sh"');
  pb.push('  tasks:');
  pb.push('    - name: Copy this host\'s files');
  pb.push('      ansible.builtin.copy:');
  pb.push('        src: "hosts/{{ inventory_hostname }}/"');
  pb.push('        dest: /etc/emberwall/');
  pb.push('        mode: "0600"');
  pb.push('      register: emberwall_files');
  pb.push('    - name: Load the firewall');
  pb.push('      ansible.builtin.shell: "{{ emberwall_load[emberwall_tool] }}"');
  pb.push('      args:');
  pb.push('        executable: /bin/sh');
  pb.push('      when: emberwall_files.changed');
  return [
    { name: 'inventory.ini', path: './inventory.ini', lang: 'conf', description: 'Ansible inventory for the fleet', lines: inv.lines },
    { name: 'fleet-playbook.yml', path: './fleet-playbook.yml', lang: 'yaml', description: 'Ansible playbook for the fleet', lines: pb.lines },
  ];
}

/** Every file of every host, with a path prefix, for download. */
export function fleetFiles(builds: HostBuild[]): { path: string; text: string }[] {
  const out: { path: string; text: string }[] = [];
  for (const b of builds) for (const f of b.result.files) out.push({ path: `hosts/${hostDir(b.host)}/${f.name}`, text: fileText(f) });
  for (const f of fleetAnsible(builds)) out.push({ path: f.name, text: fileText(f) });
  return out;
}
