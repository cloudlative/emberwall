// Wraps a build in automation formats: Ansible, Terraform and cloud-init.
import { BANNER, fileText, Out, type CompileResult, type OutFile } from './types';

const DEST = '/etc/emberwall';

/** The files the host needs (everything except the interactive safe-apply script). */
function payload(result: CompileResult): OutFile[] {
  return result.files.filter((f) => f.name !== 'emberwall-apply.sh' && !f.name.endsWith('.fragment') && !f.name.endsWith('.xml'));
}

/** Non-interactive commands that validate and load the ruleset from DEST. */
function loadCommands(result: CompileResult): { check: string[]; apply: string[] } {
  switch (result.target.tool) {
    case 'nftables':
      return { check: [`nft -c -f ${DEST}/emberwall.nft`], apply: [`nft -f ${DEST}/emberwall.nft`] };
    case 'iptables':
      return {
        check: [`iptables-restore --test < ${DEST}/rules.v4`, `ip6tables-restore --test < ${DEST}/rules.v6`],
        apply: [`iptables-restore < ${DEST}/rules.v4`, `ip6tables-restore < ${DEST}/rules.v6`],
      };
    case 'ufw':
      return { check: [], apply: [`sh ${DEST}/emberwall-ufw.sh`] };
    case 'firewalld':
      return { check: ['firewall-cmd --state'], apply: [`sh ${DEST}/emberwall-firewalld.sh`] };
  }
}

function indent(text: string, n: number): string[] {
  const pad = ' '.repeat(n);
  return text.replace(/\n$/, '').split('\n').map((l) => (l ? pad + l : ''));
}

export function ansiblePlaybook(result: CompileResult): OutFile {
  const o = new Out();
  const { check, apply } = loadCommands(result);
  o.push('---');
  o.push(`# ${BANNER} - Ansible playbook for ${result.target.label}`);
  o.push('# Usage: ansible-playbook -i inventory emberwall-playbook.yml');
  o.push('# Unlike emberwall-apply.sh there is no automatic rollback: test on one host first.');
  o.push('- name: Apply Emberwall firewall');
  o.push('  hosts: all');
  o.push('  become: true');
  o.push('  tasks:');
  o.push('    - name: Create the Emberwall directory');
  o.push('      ansible.builtin.file:');
  o.push(`        path: ${DEST}`);
  o.push('        state: directory');
  o.push('        mode: "0700"');
  for (const f of payload(result)) {
    o.blank();
    o.push(`    - name: Install ${f.name}`);
    o.push('      ansible.builtin.copy:');
    o.push(`        dest: ${DEST}/${f.name}`);
    o.push('        mode: "0600"');
    o.push('        content: |');
    indent(fileText(f), 10).forEach((l) => o.push(l));
    o.push('      notify: Load firewall');
  }
  o.blank();
  o.push('  handlers:');
  o.push('    - name: Load firewall');
  o.push('      ansible.builtin.shell: |');
  [...check, ...apply].forEach((c) => o.push(`        ${c}`));
  o.push('      args:');
  o.push('        executable: /bin/sh');
  return { name: 'emberwall-playbook.yml', path: './emberwall-playbook.yml', lang: 'yaml', description: 'Ansible playbook', lines: o.lines };
}

export function terraformModule(result: CompileResult): OutFile {
  const o = new Out();
  const { check, apply } = loadCommands(result);
  const files = payload(result);
  o.push(`# ${BANNER} - Terraform for ${result.target.label}`);
  o.push('# Pushes the ruleset over SSH and loads it. Requires Terraform 1.4+ (terraform_data).');
  o.push('# There is no automatic rollback: test on one host first.');
  o.blank();
  o.push('variable "host" {').push('  type        = string').push('  description = "Address of the server"').push('}');
  o.push('variable "user" {').push('  type    = string').push('  default = "root"').push('}');
  o.push('variable "private_key_path" {').push('  type = string').push('}');
  o.blank();
  o.push('locals {');
  o.push('  emberwall_files = {');
  files.forEach((f) => {
    o.push(`    "${f.name}" = <<-EMBERWALL`);
    // Terraform heredocs interpolate ${...} and %{...}: escape both.
    indent(fileText(f).replace(/\$\{/g, '$$${').replace(/%\{/g, '%%{'), 6).forEach((l) => o.push(l));
    o.push('    EMBERWALL');
  });
  o.push('  }');
  o.push('}');
  o.blank();
  o.push('resource "terraform_data" "emberwall" {');
  o.push('  triggers_replace = sha256(jsonencode(local.emberwall_files))');
  o.blank();
  o.push('  connection {').push('    type        = "ssh"').push('    host        = var.host').push('    user        = var.user').push('    private_key = file(var.private_key_path)').push('  }');
  o.blank();
  o.push('  provisioner "remote-exec" {').push(`    inline = ["mkdir -p ${DEST}", "chmod 700 ${DEST}"]`).push('  }');
  files.forEach((f) => {
    o.blank();
    o.push('  provisioner "file" {');
    o.push(`    content     = local.emberwall_files["${f.name}"]`);
    o.push(`    destination = "${DEST}/${f.name}"`);
    o.push('  }');
  });
  o.blank();
  o.push('  provisioner "remote-exec" {');
  o.push('    inline = [');
  [...check, ...apply].forEach((c) => o.push(`      "${c.replace(/"/g, '\\"')}",`));
  o.push('    ]');
  o.push('  }');
  o.push('}');
  return { name: 'emberwall.tf', path: './emberwall.tf', lang: 'hcl', description: 'Terraform (SSH push)', lines: o.lines };
}

export function cloudInit(result: CompileResult): OutFile {
  const o = new Out();
  const { check, apply } = loadCommands(result);
  o.push('#cloud-config');
  o.push(`# ${BANNER} - cloud-init user data for ${result.target.label}`);
  o.push('# Loads the firewall on first boot of a new instance.');
  o.push('write_files:');
  for (const f of payload(result)) {
    o.push(`  - path: ${DEST}/${f.name}`);
    o.push('    permissions: "0600"');
    o.push('    content: |');
    indent(fileText(f), 6).forEach((l) => o.push(l));
  }
  o.push('runcmd:');
  [...check, ...apply].forEach((c) => o.push(`  - ${JSON.stringify(c)}`));
  return { name: 'emberwall-cloud-init.yaml', path: 'user-data', lang: 'yaml', description: 'cloud-init user data', lines: o.lines };
}

export function iacFiles(result: CompileResult): OutFile[] {
  return [ansiblePlaybook(result), terraformModule(result), cloudInit(result)];
}
