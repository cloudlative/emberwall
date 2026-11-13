// Interface names ending in "+" are prefix wildcards (the iptables spelling, used in projects).
import { describe, expect, it } from 'vitest';
import { compile, fileText } from '../src/core/compile';
import { importNft } from '../src/core/import/nft';
import { emptyProject, newNat, newRule } from '../src/core/model';
import { simulate } from '../src/core/simulate';
import { resolveTarget, type Tool } from '../src/core/targets';

const project = () => {
  const p = emptyProject('Wildcards');
  p.options.forwarding = true;
  p.rules = [newRule({ name: 'WireGuard peers', proto: 'udp', ports: ['51820'], inIface: 'wg+' })];
  p.nat = [newNat({ name: 'Out via PPP', kind: 'masquerade', iface: 'ppp+' })];
  return p;
};
const build = (tool: Tool, version: string) => compile(project(), resolveTarget({ distro: 'custom', tool, version }));

describe('wildcard interface names', () => {
  it('nftables writes its own wildcard, "*"', () => {
    const text = fileText(build('nftables', '1.1.6').files[0]);
    expect(text).toContain('iifname "wg*"');
    expect(text).toContain('oifname "ppp*"');
    expect(text).not.toMatch(/ifname "[^"]*\+"/);
  });

  it('iptables keeps "+", its native wildcard', () => {
    const v4 = fileText(build('iptables', '1.8.11').files[0]);
    expect(v4).toContain('-i wg+');
    expect(v4).toContain('-o ppp+');
  });

  it('survives a round trip through the nftables importer', () => {
    const imported = importNft(fileText(build('nftables', '1.1.6').files[0])).project;
    expect(imported.rules.find((r) => r.ports.includes('51820'))?.inIface).toBe('wg+');
    expect(imported.nat[0]?.iface).toBe('ppp+');
    expect(fileText(compile(imported, resolveTarget({ distro: 'custom', tool: 'nftables', version: '1.1.6' })).files[0])).toContain('iifname "wg*"');
  });

  it('firewalld says it cannot promise wildcard zone bindings', () => {
    expect(build('firewalld', '2.3.1').diagnostics.some((d) => d.kind === 'unsupported' && /wg\+/.test(d.message))).toBe(true);
  });

  it('the simulator treats it as a prefix match', () => {
    const pkt = { direction: 'in' as const, src: '198.51.100.9', dst: '192.0.2.1', proto: 'udp' as const, port: 51820, state: 'new' as const };
    const p = project();
    p.policies.in = 'drop';
    expect(simulate(p, { ...pkt, inIface: 'wg3' }).verdict).toBe('accept');
    expect(simulate(p, { ...pkt, inIface: 'eth0' }).verdict).toBe('drop');
  });
});
