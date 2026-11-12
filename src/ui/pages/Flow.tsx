import { ArrowDown, ArrowRight, Cpu, Globe } from 'lucide-react';
import type { ReactNode } from 'react';
import { DIRECTION_LABEL, type Direction } from '../../core/model';
import { useStore, useEffectiveProject } from '../../store/useStore';
import { ActionBadge, PageHeader } from '../components/ui';

function Node({ icon, title, sub }: { icon: ReactNode; title: string; sub: string }) {
  return (
    <div className="tile flex items-center gap-2.5 px-3 py-2.5">
      <span className="text-ember-400">{icon}</span>
      <div><div className="text-[13px] font-semibold">{title}</div><div className="text-[11.5px] text-mute">{sub}</div></div>
    </div>
  );
}

function Step({ label, verdict, muted, onClick }: { label: string; verdict?: 'accept' | 'drop' | 'reject'; muted?: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} className={`flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-[12.5px] ${onClick ? 'cursor-pointer hover:bg-white/5' : ''} ${muted ? 'text-mute' : ''}`} style={{ border: '1px solid var(--line)' }}>
      <span className="truncate">{label}</span>
      {verdict && <ActionBadge action={verdict} />}
    </div>
  );
}

/** The path a packet takes through netfilter, with this project's rules placed on it. */
export function FlowPage() {
  const project = useEffectiveProject();
  const { selectRule, setPage } = useStore.getState();
  const opt = project.options;
  const dnat = project.nat.filter((n) => n.enabled && n.kind === 'dnat');
  const snat = project.nat.filter((n) => n.enabled && n.kind !== 'dnat');
  const open = (id: string, page: 'rules' | 'nat') => () => {
    selectRule(id);
    setPage(page);
  };

  const chain = (dir: Direction, hook: string, note: string) => {
    const rules = project.rules.filter((r) => r.enabled && r.direction === dir);
    return (
      <section className="glass flex flex-col px-4 py-3.5">
        <div className="mb-2.5 flex items-baseline justify-between">
          <h2 className="text-[14px] font-semibold">{DIRECTION_LABEL[dir]} <span className="ml-1 font-mono text-[11px] font-normal text-mute">{hook}</span></h2>
          <span className="text-[11.5px] text-mute">{note}</span>
        </div>
        <div className="space-y-1.5">
          {opt.allowLoopback && dir !== 'forward' && <Step label="Loopback traffic" verdict="accept" muted />}
          {!opt.ipv6 && <Step label="Any IPv6 packet" verdict="drop" muted />}
          {opt.allowEstablished && <Step label="Established / related connections" verdict="accept" muted />}
          {opt.dropInvalid && dir !== 'out' && <Step label="Invalid connection state" verdict="drop" muted />}
          {opt.allowIcmp && (dir === 'in' || (dir === 'out' && project.policies.out === 'drop')) && <Step label="Essential ICMP (ping, IPv6 ND)" verdict="accept" muted />}
          {rules.map((r, i) => <Step key={r.id} label={`${i + 1}. ${r.name}`} verdict={r.action} onClick={open(r.id, 'rules')} />)}
          {rules.length === 0 && <div className="py-1 text-center text-[12px] text-mute">no rules</div>}
          <div className="flex items-center justify-center py-0.5 text-mute"><ArrowDown size={14} /></div>
          <Step label="Default policy: everything else" verdict={project.policies[dir]} />
        </div>
      </section>
    );
  };

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Packet flow" sub="Where each rule sits on a packet's way through the kernel. Within a column, the first match wins." />
      <div className="mb-4 flex flex-wrap items-stretch gap-2">
        <Node icon={<Globe size={18} />} title="Packet arrives" sub="from the network" />
        <div className="flex items-center text-mute"><ArrowRight size={16} /></div>
        <div className="tile min-w-[220px] flex-1 px-3 py-2.5">
          <div className="text-[13px] font-semibold">Prerouting <span className="font-mono text-[11px] font-normal text-mute">destination NAT</span></div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {dnat.length === 0 ? <span className="text-[12px] text-mute">no port forwards</span> : dnat.map((n) => (
              <button key={n.id} className="chip" onClick={open(n.id, 'nat')}>{n.name}: {n.port ?? '*'} → {n.toAddr}{n.toPort ? `:${n.toPort}` : ''}</button>
            ))}
          </div>
        </div>
        <div className="flex items-center text-mute"><ArrowRight size={16} /></div>
        <Node icon={<Cpu size={18} />} title="Routing decision" sub={opt.forwarding ? 'for this host, or forward' : 'forwarding is off'} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {chain('in', 'input', 'to local services')}
        {chain('forward', 'forward', opt.forwarding ? 'routed through' : 'routing is off')}
        {chain('out', 'output', 'from local services')}
      </div>
      <div className="mt-4 flex flex-wrap items-stretch gap-2 pb-2">
        <div className="tile min-w-[220px] flex-1 px-3 py-2.5">
          <div className="text-[13px] font-semibold">Postrouting <span className="font-mono text-[11px] font-normal text-mute">source NAT</span></div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {snat.length === 0 ? <span className="text-[12px] text-mute">no source NAT</span> : snat.map((n) => (
              <button key={n.id} className="chip" onClick={open(n.id, 'nat')}>{n.name}: {n.src ?? 'any'} → {n.kind === 'snat' ? n.toAddr : `masquerade${n.iface ? ` via ${n.iface}` : ''}`}</button>
            ))}
          </div>
        </div>
        <div className="flex items-center text-mute"><ArrowRight size={16} /></div>
        <Node icon={<Globe size={18} />} title="Packet leaves" sub="to the network" />
      </div>
    </div>
  );
}
