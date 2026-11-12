import { ArrowLeftRight, Plus, Trash2 } from 'lucide-react';
import { newNat, type NatKind, type NatRule } from '../../core/model';
import { useStore } from '../../store/useStore';
import { OutputPanel } from '../components/OutputPanel';
import { Empty, Field, PageHeader, Segmented, Switch } from '../components/ui';

const KIND_LABEL: Record<NatKind, string> = { masquerade: 'Masquerade', snat: 'Source NAT', dnat: 'Port forward' };
const KIND_HELP: Record<NatKind, string> = {
  masquerade: 'Hide a network behind this host\'s outgoing address (dynamic IP).',
  snat: 'Rewrite the source to a fixed address (static IP).',
  dnat: 'Send traffic arriving on a port to an internal host.',
};

function NatCard({ n }: { n: NatRule }) {
  const update = useStore((s) => s.update);
  const selected = useStore((s) => s.selectedRuleId === n.id);
  const selectRule = useStore((s) => s.selectRule);
  const set = (patch: Partial<NatRule>) => update((p) => ({ ...p, nat: p.nat.map((x) => (x.id === n.id ? { ...x, ...patch } : x)) }));
  const text = (k: keyof NatRule, placeholder: string, mono = true) => (
    <input className={`field ${mono ? 'font-mono' : ''}`} value={(n[k] as string) ?? ''} placeholder={placeholder} onChange={(e) => set({ [k]: e.target.value.trim() || undefined } as Partial<NatRule>)} />
  );
  return (
    <div className={`tile p-3.5 ${n.enabled ? '' : 'opacity-55'}`} style={selected ? { borderColor: 'rgba(255,143,92,0.6)' } : undefined} onClick={() => selectRule(n.id)}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Switch label="Enabled" checked={n.enabled} onChange={(enabled) => set({ enabled })} />
        <input className="field !w-auto min-w-[180px] flex-1 font-medium" value={n.name} onChange={(e) => set({ name: e.target.value })} aria-label="Name" />
        <Segmented<NatKind> size="sm" value={n.kind} onChange={(kind) => set({ kind })} options={(['masquerade', 'snat', 'dnat'] as NatKind[]).map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
        <button className="btn btn-ghost btn-icon" aria-label="Delete" onClick={() => update((p) => ({ ...p, nat: p.nat.filter((x) => x.id !== n.id) }))}><Trash2 size={14} /></button>
      </div>
      <p className="mb-3 text-[12px] text-mute">{KIND_HELP[n.kind]}</p>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Field label={n.kind === 'dnat' ? 'Inbound interface' : 'Outbound interface'}>{text('iface', 'eth0')}</Field>
        <Field label="Protocol">
          <select className="field" value={n.proto} onChange={(e) => set({ proto: e.target.value as NatRule['proto'] })}>
            <option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option>
          </select>
        </Field>
        <Field label="Source">{text('src', 'any (e.g. 10.0.0.0/24)')}</Field>
        {n.kind === 'dnat' ? (
          <>
            <Field label="Port">{text('port', '443')}</Field>
            <Field label="Original destination">{text('dst', 'any')}</Field>
            <Field label="Forward to address">{text('toAddr', '192.168.1.10')}</Field>
            <Field label="Forward to port">{text('toPort', 'same port')}</Field>
          </>
        ) : (
          <>
            <Field label="Destination">{text('dst', 'any')}</Field>
            {n.kind === 'snat' && <Field label="Translate to">{text('toAddr', '203.0.113.5')}</Field>}
            <div className="flex items-end gap-2 pb-1.5">
              <Switch label="Randomise source ports" checked={!!n.randomFully} onChange={(v) => set({ randomFully: v || undefined })} />
              <span className="text-[12.5px]">Randomise source ports</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export function NatPage() {
  const nat = useStore((s) => s.project.nat);
  const update = useStore((s) => s.update);
  const add = (kind: NatKind) => update((p) => ({ ...p, nat: [...p.nat, newNat({ kind, name: KIND_LABEL[kind], proto: kind === 'dnat' ? 'tcp' : 'any' })] }));
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="NAT and port forwarding" sub="Address translation for routers, gateways and container hosts.">
        <button className="btn" onClick={() => add('masquerade')}><Plus size={15} /> Masquerade</button>
        <button className="btn" onClick={() => add('snat')}><Plus size={15} /> Source NAT</button>
        <button className="btn btn-primary" onClick={() => add('dnat')}><Plus size={15} /> Port forward</button>
      </PageHeader>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:overflow-visible xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="glass p-4 xl:min-h-0 xl:overflow-y-auto">
          {nat.length === 0 ? (
            <Empty icon={<ArrowLeftRight size={22} />} title="No NAT rules">A plain server needs none. Add one when this host routes for other machines.</Empty>
          ) : (
            <div className="space-y-3">{nat.map((n) => <NatCard key={n.id} n={n} />)}</div>
          )}
        </div>
        <OutputPanel className="h-[620px] xl:h-auto xl:min-h-0" />
      </div>
    </div>
  );
}
