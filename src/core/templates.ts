import { emptyProject, newNat, newRule, type Project } from './model';

export interface Template {
  id: string;
  name: string;
  icon: string;
  summary: string;
  build: () => Project;
}

const ssh = (src: string[] = []) =>
  newRule({ name: 'SSH', proto: 'tcp', ports: ['22'], src, rateLimit: src.length === 0 ? { rate: 10, per: 'minute', burst: 20 } : undefined });

const base = (name: string, description: string): Project => ({ ...emptyProject(name), description, options: { ...emptyProject().options, logDropped: true } });

export const TEMPLATES: Template[] = [
  {
    id: 'web',
    name: 'Web server',
    icon: 'globe',
    summary: 'HTTP/HTTPS open to the world, SSH from an admin network only.',
    build: () => {
      const p = base('Web server', 'Public web server with restricted management access.');
      p.addressGroups = [{ id: 'admins', name: 'Admin networks', members: ['203.0.113.0/24', '2001:db8:10::/48'] }];
      p.rules = [
        newRule({ name: 'SSH from admins', proto: 'tcp', ports: ['22'], src: ['@admins'] }),
        newRule({ name: 'HTTP + HTTPS', proto: 'tcp', ports: ['80', '443'] }),
        newRule({ name: 'HTTP/3 (QUIC)', proto: 'udp', ports: ['443'] }),
      ];
      return p;
    },
  },
  {
    id: 'bastion',
    name: 'SSH bastion',
    icon: 'key',
    summary: 'Only SSH in, rate-limited and logged; outbound limited to SSH, DNS and updates.',
    build: () => {
      const p = base('SSH bastion', 'Jump host: one way in, tightly limited ways out.');
      p.policies.out = 'drop';
      p.addressGroups = [{ id: 'internal', name: 'Internal hosts', members: ['10.0.0.0/8'] }];
      p.rules = [
        newRule({ name: 'SSH in', proto: 'tcp', ports: ['22'], log: true, rateLimit: { rate: 6, per: 'minute', burst: 10 } }),
        newRule({ name: 'SSH to internal', direction: 'out', proto: 'tcp', ports: ['22'], dst: ['@internal'] }),
        newRule({ name: 'DNS out', direction: 'out', proto: 'tcpudp', ports: ['53'] }),
        newRule({ name: 'NTP out', direction: 'out', proto: 'udp', ports: ['123'] }),
        newRule({ name: 'Updates (HTTP/S)', direction: 'out', proto: 'tcp', ports: ['80', '443'] }),
      ];
      return p;
    },
  },
  {
    id: 'database',
    name: 'Database server',
    icon: 'database',
    summary: 'PostgreSQL / MySQL reachable from the app subnet only.',
    build: () => {
      const p = base('Database server', 'Database ports are reachable from application servers only.');
      p.addressGroups = [
        { id: 'apps', name: 'App servers', members: ['10.20.0.0/24'] },
        { id: 'admins', name: 'Admin networks', members: ['10.99.0.0/24'] },
      ];
      p.portGroups = [{ id: 'db', name: 'Database ports', ports: ['5432', '3306'] }];
      p.rules = [
        newRule({ name: 'SSH from admins', proto: 'tcp', ports: ['22'], src: ['@admins'] }),
        newRule({ name: 'Databases from apps', proto: 'tcp', ports: ['@db'], src: ['@apps'] }),
        newRule({ name: 'Metrics from monitoring', proto: 'tcp', ports: ['9100', '9187'], src: ['10.30.0.5'] }),
        newRule({ name: 'Block SMTP out', direction: 'out', action: 'reject', proto: 'tcp', ports: ['25'] }),
      ];
      return p;
    },
  },
  {
    id: 'docker',
    name: 'Docker host',
    icon: 'box',
    summary: 'Published services, forwarding for container networks, masquerade out.',
    build: () => {
      const p = base('Docker host', 'Container host. Docker adds its own chains: restart it after loading iptables rules.');
      p.options.forwarding = true;
      p.rules = [
        ssh(),
        newRule({ name: 'HTTP + HTTPS', proto: 'tcp', ports: ['80', '443'] }),
        newRule({ name: 'Containers to anywhere', direction: 'forward', proto: 'any', src: ['172.17.0.0/16'], family: 'ipv4' }),
        newRule({ name: 'Published web containers', direction: 'forward', proto: 'tcp', dst: ['172.17.0.0/16'], ports: ['80', '443', '8080'], family: 'ipv4' }),
      ];
      p.nat = [newNat({ name: 'Container egress', kind: 'masquerade', src: '172.17.0.0/16', iface: 'eth0' })];
      return p;
    },
  },
  {
    id: 'k8s',
    name: 'Kubernetes node',
    icon: 'boxes',
    summary: 'API server, kubelet, etcd and NodePorts restricted to the cluster network.',
    build: () => {
      const p = base('Kubernetes node', 'Control-plane / worker node. CNI plugins manage their own rules next to these.');
      p.options.forwarding = true;
      p.policies.forward = 'accept';
      p.addressGroups = [
        { id: 'cluster', name: 'Cluster nodes', members: ['10.0.0.0/24'] },
        { id: 'pods', name: 'Pod + service CIDRs', members: ['10.244.0.0/16', '10.96.0.0/12'] },
      ];
      p.rules = [
        ssh(['@cluster']),
        newRule({ name: 'Kubernetes API', proto: 'tcp', ports: ['6443'] }),
        newRule({ name: 'etcd', proto: 'tcp', ports: ['2379:2380'], src: ['@cluster'] }),
        newRule({ name: 'Kubelet + scheduler + controller', proto: 'tcp', ports: ['10250', '10257', '10259'], src: ['@cluster'] }),
        newRule({ name: 'NodePort services', proto: 'tcpudp', ports: ['30000:32767'] }),
        newRule({ name: 'Overlay (VXLAN)', proto: 'udp', ports: ['4789', '8472'], src: ['@cluster'] }),
        newRule({ name: 'Pod network', proto: 'any', src: ['@pods'] }),
      ];
      return p;
    },
  },
  {
    id: 'wireguard',
    name: 'WireGuard gateway',
    icon: 'shield',
    summary: 'VPN endpoint that routes clients to the LAN and the internet.',
    build: () => {
      const p = base('WireGuard gateway', 'VPN concentrator: clients on wg0 reach the LAN and go out through eth0.');
      p.options.forwarding = true;
      p.rules = [
        ssh(),
        newRule({ name: 'WireGuard', proto: 'udp', ports: ['51820'] }),
        newRule({ name: 'DNS for VPN clients', proto: 'tcpudp', ports: ['53'], inIface: 'wg0' }),
        newRule({ name: 'VPN clients to anywhere', direction: 'forward', proto: 'any', inIface: 'wg0' }),
      ];
      p.nat = [newNat({ name: 'VPN egress', kind: 'masquerade', src: '10.8.0.0/24', iface: 'eth0', randomFully: true })];
      return p;
    },
  },
  {
    id: 'router',
    name: 'NAT router',
    icon: 'router',
    summary: 'LAN behind one public address with a port forward to an internal server.',
    build: () => {
      const p = base('NAT router', 'eth0 is WAN, eth1 is LAN. LAN is trusted, WAN gets nothing but the port forward.');
      p.options.forwarding = true;
      p.rules = [
        newRule({ name: 'LAN to router', proto: 'any', inIface: 'eth1' }),
        newRule({ name: 'LAN to internet', direction: 'forward', proto: 'any', inIface: 'eth1', outIface: 'eth0' }),
        newRule({ name: 'Forward: web server', direction: 'forward', proto: 'tcp', dst: ['192.168.1.10'], ports: ['443'], family: 'ipv4' }),
      ];
      p.nat = [
        newNat({ name: 'LAN egress', kind: 'masquerade', src: '192.168.1.0/24', iface: 'eth0' }),
        newNat({ name: 'Web server', kind: 'dnat', iface: 'eth0', proto: 'tcp', port: '443', toAddr: '192.168.1.10', toPort: '443' }),
      ];
      return p;
    },
  },
  {
    id: 'workstation',
    name: 'Workstation',
    icon: 'laptop',
    summary: 'Nothing in, everything out. Local discovery allowed on the LAN.',
    build: () => {
      const p = base('Workstation', 'Desktop or laptop: no listening services exposed.');
      p.rules = [
        newRule({ name: 'mDNS on LAN', proto: 'udp', ports: ['5353'], src: ['192.168.0.0/16', 'fe80::/10'] }),
        newRule({ name: 'DHCPv6 client', proto: 'udp', ports: ['546'], src: ['fe80::/10'], family: 'ipv6' }),
      ];
      return p;
    },
  },
];

export function templateById(id: string): Template | undefined {
  return TEMPLATES.find((t) => t.id === id);
}
