// Parses a firewalld zone XML file into a project (inbound side; zones carry no outbound rules).
import { emptyProject, newNat, newRule, type Rule } from '../model';
import type { ImportReport } from './shared';

/** The firewalld services people use most; anything else is reported as skipped. */
const SERVICES: Record<string, { proto: Rule['proto']; ports: string[] }> = {
  ssh: { proto: 'tcp', ports: ['22'] }, http: { proto: 'tcp', ports: ['80'] }, https: { proto: 'tcp', ports: ['443'] },
  dns: { proto: 'tcpudp', ports: ['53'] }, ntp: { proto: 'udp', ports: ['123'] }, smtp: { proto: 'tcp', ports: ['25'] },
  smtps: { proto: 'tcp', ports: ['465'] }, imaps: { proto: 'tcp', ports: ['993'] }, mysql: { proto: 'tcp', ports: ['3306'] },
  postgresql: { proto: 'tcp', ports: ['5432'] }, cockpit: { proto: 'tcp', ports: ['9090'] }, 'dhcpv6-client': { proto: 'udp', ports: ['546'] },
  mdns: { proto: 'udp', ports: ['5353'] }, wireguard: { proto: 'udp', ports: ['51820'] }, 'kube-apiserver': { proto: 'tcp', ports: ['6443'] },
  samba: { proto: 'tcpudp', ports: ['137:139', '445'] }, nfs: { proto: 'tcp', ports: ['2049'] }, redis: { proto: 'tcp', ports: ['6379'] },
};

const attr = (tag: string, name: string) => new RegExp(`\\b${name}="([^"]*)"`).exec(tag)?.[1];

export function importFirewalldXml(text: string): ImportReport {
  const project = emptyProject('Imported from firewalld');
  const skipped: ImportReport['skipped'] = [];
  const xml = text.replace(/<!--[\s\S]*?-->/g, '');
  const zone = /<zone\b[^>]*>/.exec(xml);
  if (!zone) return { project, imported: 0, skipped: [{ line: text.slice(0, 80), reason: 'no <zone> element found' }] };
  const target = attr(zone[0], 'target');
  project.policies.in = target === 'ACCEPT' ? 'accept' : 'drop';
  // Zones with the default target accept ICMP; DROP zones do not.
  project.options.allowIcmp = target !== 'DROP' && target !== '%%REJECT%%';
  const short = /<short>([^<]*)<\/short>/.exec(xml)?.[1];
  if (short) project.name = `${short} (firewalld zone)`;
  project.description = /<description>([^<]*)<\/description>/.exec(xml)?.[1] ?? '';

  const rules: Rule[] = [];
  const richBlocks: string[] = [];
  const top = xml.replace(/<rule\b[^>]*>[\s\S]*?<\/rule>/g, (b) => {
    richBlocks.push(b);
    return '';
  });

  for (const m of top.matchAll(/<service\b[^>]*\/?>/g)) {
    const name = attr(m[0], 'name') ?? '';
    const svc = SERVICES[name];
    if (svc) rules.push(newRule({ name, proto: svc.proto, ports: svc.ports }));
    else skipped.push({ line: m[0], reason: `service "${name}" is not in the built-in list; add its ports by hand` });
  }
  for (const m of top.matchAll(/<port\b[^>]*\/?>/g)) {
    const port = (attr(m[0], 'port') ?? '').replace('-', ':');
    const proto = attr(m[0], 'protocol');
    if (proto !== 'tcp' && proto !== 'udp') {
      skipped.push({ line: m[0], reason: `protocol ${proto} is not supported` });
      continue;
    }
    const prev = rules.find((r) => r.name.startsWith('port ') && r.proto === proto && r.src.length === 0);
    if (prev) {
      prev.ports.push(port);
      prev.name = `port ${prev.ports.join(',')}/${proto}`;
    } else rules.push(newRule({ name: `port ${port}/${proto}`, proto, ports: [port] }));
  }
  if (/<masquerade\s*\/>/.test(top)) project.nat.push(newNat({ name: 'Masquerade', kind: 'masquerade' }));
  for (const m of top.matchAll(/<forward-port\b[^>]*\/?>/g)) {
    project.nat.push(newNat({ name: `Forward ${attr(m[0], 'port')}`, kind: 'dnat', proto: (attr(m[0], 'protocol') as 'tcp' | 'udp') ?? 'tcp', port: attr(m[0], 'port')?.replace('-', ':'), toAddr: attr(m[0], 'to-addr'), toPort: attr(m[0], 'to-port')?.replace('-', ':') }));
  }
  for (const m of top.matchAll(/<(interface|source)\b[^>]*\/?>/g)) {
    skipped.push({ line: m[0], reason: 'zone bindings (interface/source) are not rules; model them as an Emberwall zone if needed' });
  }

  const rich: { rule: Rule; priority: number }[] = [];
  for (const block of richBlocks) {
    const head = /<rule\b[^>]*>/.exec(block)![0];
    const family = attr(head, 'family');
    const act = /<(accept|drop|reject)\b/.exec(block)?.[1] as Rule['action'] | undefined;
    const one = (tag: string) => new RegExp(`<${tag}\\b[^>]*>`).exec(block)?.[0];
    if (one('masquerade')) {
      project.nat.push(newNat({ name: 'Masquerade', kind: 'masquerade', src: attr(one('source') ?? '', 'address') }));
      continue;
    }
    const fp = one('forward-port');
    if (fp) {
      project.nat.push(newNat({ name: `Forward ${attr(fp, 'port')}`, kind: 'dnat', proto: (attr(fp, 'protocol') as 'tcp' | 'udp') ?? 'tcp', port: attr(fp, 'port')?.replace('-', ':'), toAddr: attr(fp, 'to-addr'), toPort: attr(fp, 'to-port')?.replace('-', ':'), src: attr(one('source') ?? '', 'address') }));
      continue;
    }
    if (!act) {
      skipped.push({ line: block.replace(/\s+/g, ' '), reason: 'rich rule without accept/drop/reject' });
      continue;
    }
    const any = (a?: string) => (!a || a === '0.0.0.0/0' || a === '::/0' ? [] : [a]);
    const r = newRule({ name: '', action: act, proto: 'any', family: family === 'ipv4' || family === 'ipv6' ? family : 'both' });
    const srcTag = one('source') ?? '';
    r.src = any(attr(srcTag, 'address'));
    if (attr(srcTag, 'mac')) r.srcMac = attr(srcTag, 'mac');
    r.dst = any(attr(one('destination') ?? '', 'address'));
    const port = one('port');
    const sport = one('source-port');
    const protoTag = one('protocol');
    const icmp = one('icmp-type');
    if (port) {
      r.proto = attr(port, 'protocol') as 'tcp' | 'udp';
      r.ports = [(attr(port, 'port') ?? '').replace('-', ':')];
    } else if (sport) {
      r.proto = attr(sport, 'protocol') as 'tcp' | 'udp';
      r.srcPorts = [(attr(sport, 'port') ?? '').replace('-', ':')];
    } else if (protoTag) {
      const v = attr(protoTag, 'value');
      if (v === 'tcp' || v === 'udp') r.proto = v;
      else if (v === 'icmp' || v === 'ipv6-icmp') r.proto = 'icmp';
      else {
        skipped.push({ line: block.replace(/\s+/g, ' '), reason: `protocol ${v} is not supported` });
        continue;
      }
    } else if (icmp) {
      r.proto = 'icmp';
      r.icmpType = attr(icmp, 'name');
    }
    if (one('log')) r.log = true;
    const lim = /<limit\b[^>]*value="(\d+)\/([smh])"/.exec(block);
    if (lim && act === 'accept') r.rateLimit = { rate: Number(lim[1]), per: lim[2] === 's' ? 'second' : lim[2] === 'm' ? 'minute' : 'hour', burst: 5 };
    if (r.proto === 'icmp' && r.icmpType === 'echo-request' && act === 'accept' && r.src.length + r.dst.length === 0) {
      project.options.allowIcmp = true;
      continue;
    }
    if (act === 'drop' && family === 'ipv6' && r.proto === 'any' && r.src.length + r.dst.length === 0) {
      project.options.ipv6 = false;
      continue;
    }
    r.name = `${act} ${r.proto}${r.ports.length ? ` ${r.ports.join(',')}` : ''}${r.src.length ? ` from ${r.src[0]}` : ''}`;
    rich.push({ rule: r, priority: Number(attr(head, 'priority') ?? 0) });
  }
  // Without priorities firewalld evaluates deny rules before allow rules.
  const allZero = rich.every((x) => x.priority === 0);
  rich.sort((a, b) => (allZero ? Number(a.rule.action === 'accept') - Number(b.rule.action === 'accept') : a.priority - b.priority));
  const negative = rich.filter((x) => x.priority < 0).map((x) => x.rule);
  const rest = rich.filter((x) => x.priority >= 0).map((x) => x.rule);
  project.rules = [...negative, ...rules, ...rest];
  return { project, imported: project.rules.length + project.nat.length, skipped };
}
