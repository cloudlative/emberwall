import { ArrowRight, Check, CircleSlash, Minus, Play } from 'lucide-react';
import { useMemo, useState } from 'react';
import { ICMP_TYPES, type ConnState, type Direction } from '../../core/model';
import { simulate, type Packet } from '../../core/simulate';
import { useStore } from '../../store/useStore';
import { ActionBadge, Field, PageHeader, Panel, Segmented } from '../components/ui';

const PRESETS: { label: string; pkt: Partial<Packet> }[] = [
  { label: 'HTTPS from internet', pkt: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 443, state: 'new' } },
  { label: 'SSH from internet', pkt: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 22, state: 'new' } },
  { label: 'SSH over IPv6', pkt: { direction: 'in', src: '2001:db8:10::7', dst: '2001:db8::1', proto: 'tcp', port: 22, state: 'new' } },
  { label: 'Ping', pkt: { direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'icmp', state: 'new' } },
  { label: 'DNS lookup out', pkt: { direction: 'out', src: '192.0.2.10', dst: '9.9.9.9', proto: 'udp', port: 53, state: 'new' } },
  { label: 'Reply traffic', pkt: { direction: 'in', src: '9.9.9.9', dst: '192.0.2.10', proto: 'udp', port: 40212, state: 'established' } },
];

export function SimulatorPage() {
  const project = useStore((s) => s.project);
  const [pkt, setPkt] = useState<Packet>({ direction: 'in', src: '198.51.100.20', dst: '192.0.2.10', proto: 'tcp', port: 443, state: 'new', inIface: 'eth0' });
  const set = (patch: Partial<Packet>) => setPkt((p) => ({ ...p, ...patch }));
  const result = useMemo(() => simulate(project, pkt), [project, pkt]);
  const tone = result.verdict === 'accept' ? 'var(--ok)' : result.verdict === 'drop' ? 'var(--bad)' : 'var(--warn)';

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Packet simulator" sub="Describe a packet and see which rule decides its fate, before anything touches a server." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Panel title="Packet" hint="Updates live as you type">
          <div className="mb-4 flex flex-wrap gap-1.5">
            {PRESETS.map((p) => (
              <button key={p.label} className="chip !py-1 text-mute hover:text-ink" onClick={() => setPkt({ ...pkt, port: undefined, inIface: p.pkt.direction === 'out' ? undefined : 'eth0', outIface: p.pkt.direction === 'out' ? 'eth0' : undefined, ...p.pkt } as Packet)}>
                <Play size={10} /> {p.label}
              </button>
            ))}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Direction" className="sm:col-span-2">
              <Segmented<Direction> value={pkt.direction} onChange={(direction) => set({ direction })} options={[{ value: 'in', label: 'Inbound' }, { value: 'out', label: 'Outbound' }, { value: 'forward', label: 'Forwarded' }]} />
            </Field>
            <Field label="Source address"><input className="field font-mono" value={pkt.src} onChange={(e) => set({ src: e.target.value.trim() })} /></Field>
            <Field label="Destination address"><input className="field font-mono" value={pkt.dst} onChange={(e) => set({ dst: e.target.value.trim() })} /></Field>
            <Field label="Protocol">
              <Segmented value={pkt.proto} onChange={(proto) => set({ proto })} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'ICMP' }]} />
            </Field>
            {pkt.proto === 'icmp' ? (
              <Field label="ICMP type">
                <select className="field" value={pkt.icmpType ?? 'echo-request'} onChange={(e) => set({ icmpType: e.target.value })}>
                  {ICMP_TYPES.map((t) => <option key={t}>{t}</option>)}
                </select>
              </Field>
            ) : (
              <Field label="Destination port"><input type="number" min={1} max={65535} className="field font-mono" value={pkt.port ?? ''} onChange={(e) => set({ port: e.target.value ? Number(e.target.value) : undefined })} /></Field>
            )}
            {pkt.direction !== 'out' && <Field label="Arrives on interface"><input className="field font-mono" value={pkt.inIface ?? ''} placeholder="eth0" onChange={(e) => set({ inIface: e.target.value.trim() || undefined })} /></Field>}
            {pkt.direction !== 'in' && <Field label="Leaves on interface"><input className="field font-mono" value={pkt.outIface ?? ''} placeholder="eth0" onChange={(e) => set({ outIface: e.target.value.trim() || undefined })} /></Field>}
            <Field label="Connection state" className="sm:col-span-2">
              <Segmented<ConnState> value={pkt.state} onChange={(state) => set({ state })} options={[{ value: 'new', label: 'New' }, { value: 'established', label: 'Established' }, { value: 'related', label: 'Related' }, { value: 'invalid', label: 'Invalid' }]} />
            </Field>
          </div>
        </Panel>

        <div className="flex flex-col gap-4">
          <section className="glass flex items-center gap-4 px-5 py-4" style={{ borderColor: `color-mix(in srgb, ${tone} 45%, transparent)` }}>
            <div className="grid h-14 w-14 flex-none place-items-center rounded-2xl" style={{ background: `color-mix(in srgb, ${tone} 16%, transparent)`, color: tone }}>
              {result.verdict === 'accept' ? <Check size={28} /> : <CircleSlash size={28} />}
            </div>
            <div className="min-w-0">
              {result.error ? (
                <>
                  <div className="text-[17px] font-semibold">Cannot simulate</div>
                  <div className="text-[13px] text-mute">{result.error}</div>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-2 text-[17px] font-semibold">Packet is {result.verdict === 'accept' ? 'accepted' : result.verdict === 'drop' ? 'dropped' : 'rejected'} <ActionBadge action={result.verdict} /></div>
                  <div className="text-[13px] text-mute">Decided by the {result.decidedBy}.{result.rateLimited ? ' Above the rate limit it would fall through to later rules.' : ''}</div>
                </>
              )}
            </div>
            {result.ruleId && (
              <button className="btn ml-auto flex-none" onClick={() => { useStore.getState().selectRule(result.ruleId!); useStore.getState().setPage('rules'); }}>Show rule <ArrowRight size={14} /></button>
            )}
          </section>
          <Panel title="Trace" hint="Every check the packet went through, in order">
            <ol className="space-y-1.5">
              {result.steps.map((st, i) => (
                <li key={i} className="tile flex items-start gap-3 px-3 py-2" style={st.matched ? { borderColor: `color-mix(in srgb, ${st.verdict === 'accept' ? 'var(--ok)' : st.verdict ? 'var(--bad)' : 'var(--info)'} 45%, transparent)` } : { opacity: 0.7 }}>
                  <span className="mt-0.5 w-5 flex-none text-center font-mono text-[11px] text-mute">{i + 1}</span>
                  {st.matched ? <Check size={15} className="mt-0.5 flex-none" style={{ color: 'var(--ok)' }} /> : <Minus size={15} className="mt-0.5 flex-none text-mute" />}
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium">{st.label}</div>
                    <div className="text-[12px] text-mute">{st.matched ? '' : 'Skipped: '}{st.detail}</div>
                  </div>
                  {st.verdict && <ActionBadge action={st.verdict} />}
                </li>
              ))}
            </ol>
          </Panel>
        </div>
      </div>
    </div>
  );
}
