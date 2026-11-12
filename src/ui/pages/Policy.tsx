import { ArrowRight, Check, FlaskConical, Grid3x3, Layers, Plus, Trash2, X } from 'lucide-react';
import { useMemo } from 'react';
import { uid, type Zone } from '../../core/model';
import { parseCidr } from '../../core/net';
import { buildAxes, reachability, runTests } from '../../core/reach';
import { useStore, useEffectiveProject } from '../../store/useStore';
import { ActionBadge, Empty, PageHeader, Panel, Segmented, Stat, TagInput } from '../components/ui';

const TRUST_LABEL: Record<Zone['trust'], string> = { untrusted: 'Outside', dmz: 'DMZ', trusted: 'Trusted' };

export function ZonesPage() {
  const zones = useStore((s) => s.project.zones);
  const rules = useStore((s) => s.project.rules);
  const update = useStore((s) => s.update);
  const set = (id: string, patch: Partial<Zone>) => update((p) => ({ ...p, zones: p.zones.map((z) => (z.id === id ? { ...z, ...patch } : z)) }));
  const add = (z: Partial<Zone>) => update((p) => ({ ...p, zones: [...p.zones, { id: uid('z'), name: 'New zone', interfaces: [], networks: [], trust: 'untrusted', ...z }] }));
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Zones" sub="Name each side of the firewall once (WAN, LAN, DMZ, VPN). Rules can then say “from LAN to WAN” instead of repeating interfaces and networks.">
        {zones.length === 0 && (
          <button className="btn" onClick={() => { add({ name: 'WAN', interfaces: ['eth0'], trust: 'untrusted' }); add({ name: 'LAN', interfaces: ['eth1'], networks: ['192.168.1.0/24'], trust: 'trusted' }); }}>Add WAN + LAN</button>
        )}
        <button className="btn btn-primary" onClick={() => add({})}><Plus size={15} /> Zone</button>
      </PageHeader>
      {zones.length === 0 ? (
        <div className="glass"><Empty icon={<Layers size={22} />} title="No zones yet">A single server does not need zones. They pay off on routers, gateways and hosts with more than one network.</Empty></div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {zones.map((z) => {
            const uses = rules.filter((r) => r.srcZone === z.id || r.dstZone === z.id).length;
            return (
              <section key={z.id} className="glass p-4">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <input aria-label="Zone name" className="field !w-auto min-w-[140px] flex-1 font-medium" value={z.name} onChange={(e) => set(z.id, { name: e.target.value })} />
                  <Segmented<Zone['trust']> size="sm" value={z.trust} onChange={(trust) => set(z.id, { trust })} options={(['untrusted', 'dmz', 'trusted'] as const).map((t) => ({ value: t, label: TRUST_LABEL[t] }))} />
                  <span className="badge badge-mute whitespace-nowrap">{uses} rule{uses === 1 ? '' : 's'}</span>
                  <button className="btn btn-ghost btn-icon" aria-label="Delete zone" onClick={() => update((p) => ({
                    ...p,
                    zones: p.zones.filter((x) => x.id !== z.id),
                    rules: p.rules.map((r) => ({ ...r, srcZone: r.srcZone === z.id ? undefined : r.srcZone, dstZone: r.dstZone === z.id ? undefined : r.dstZone })),
                  }))}><Trash2 size={14} /></button>
                </div>
                <label className="label">Interfaces</label>
                <TagInput value={z.interfaces} placeholder="eth0, wg0" onChange={(interfaces) => set(z.id, { interfaces })} />
                <label className="label mt-3">Networks behind this zone</label>
                <TagInput value={z.networks} placeholder="192.168.1.0/24 (optional)" validate={(v) => !!parseCidr(v)} onChange={(networks) => set(z.id, { networks })} />
                <p className="mt-2 text-[12px] text-mute">A rule naming this zone matches {z.interfaces.length > 0 ? `traffic on ${z.interfaces.join(', ')}` : 'any interface'}{z.networks.length > 0 ? `, limited to ${z.networks.join(', ')}` : ''}.</p>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function ReachabilityPage() {
  const project = useEffectiveProject();
  const { axes, rows } = useMemo(() => {
    const a = buildAxes(project);
    return { axes: a, rows: reachability(project, a) };
  }, [project]);
  const open = rows.reduce((n, r) => n + r.cells.filter((c) => c.verdict === 'accept').length, 0);
  const total = rows.length * axes.services.length;
  const show = (ruleId?: string) => {
    if (!ruleId) return;
    const st = useStore.getState();
    st.selectRule(ruleId);
    st.setPage('rules');
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Reachability" sub="Who can reach what. Every cell is a new connection sent through the simulator; click an open or blocked cell to see the rule behind it." />
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Paths checked" value={total} sub={`${axes.sources.length} sources × ${axes.services.length} services`} />
        <Stat label="Open" value={open} tone={open === 0 ? 'ok' : undefined} sub="accepted" />
        <Stat label="Blocked" value={total - open} sub="dropped or rejected" />
        <Stat label="Destinations" value={axes.targets.length} sub={axes.targets.map((t) => t.label).join(', ')} />
      </div>
      {axes.targets.map((target) => {
        const mine = rows.filter((r) => r.target.id === target.id);
        if (mine.length === 0) return null;
        return (
          <Panel key={target.id} className="mb-4" title={<>To: {target.label}</>} hint={target.id === 'host' ? 'Services on the firewall host itself (inbound)' : `Forwarded traffic into ${target.detail}`}>
            <div className="overflow-x-auto">
              <table className="w-full border-separate text-[12px]" style={{ borderSpacing: 3 }}>
                <thead>
                  <tr>
                    <th className="pb-1 pr-3 text-left text-[11px] font-semibold uppercase tracking-wider text-mute">From</th>
                    {axes.services.map((s) => <th key={s.id} className="whitespace-nowrap px-1 pb-1 text-center text-[11px] font-medium text-mute">{s.label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {mine.map((row) => (
                    <tr key={row.source.id}>
                      <td className="whitespace-nowrap pr-3">
                        <div className="font-medium">{row.source.label}</div>
                        <div className="text-[11px] text-mute">{row.source.detail}</div>
                      </td>
                      {row.cells.map((c, i) => {
                        const ok = c.verdict === 'accept';
                        return (
                          <td key={i} className="p-0 text-center">
                            <button
                              onClick={() => show(c.ruleId)}
                              title={`${row.source.label} → ${target.label}, ${axes.services[i].label}: ${c.verdict} by the ${c.decidedBy}${c.limited ? ' (rate limited)' : ''}`}
                              aria-label={`${row.source.label} to ${target.label} ${axes.services[i].label}: ${c.verdict}`}
                              className="grid h-8 w-full min-w-[54px] place-items-center rounded-md transition hover:brightness-125"
                              style={{ background: `color-mix(in srgb, ${ok ? 'var(--ok)' : 'var(--bad)'} ${ok ? 22 : 9}%, transparent)`, border: `1px solid color-mix(in srgb, ${ok ? 'var(--ok)' : 'var(--bad)'} ${ok ? 45 : 18}%, transparent)`, cursor: c.ruleId ? 'pointer' : 'default' }}
                            >
                              {ok ? <Check size={14} style={{ color: 'var(--ok)' }} /> : <X size={12} style={{ color: 'var(--bad)', opacity: 0.7 }} />}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        );
      })}
      <p className="pb-2 text-[12px] text-mute"><Grid3x3 size={12} className="mr-1 inline" />Sources are the Internet, your zones, address groups and addresses named in rules; services are the ports your rules mention. IPv4 paths only.</p>
    </div>
  );
}

export function TestsPage() {
  const project = useStore((s) => s.project);
  const update = useStore((s) => s.update);
  const setPage = useStore((s) => s.setPage);
  const results = useMemo(() => runTests(project), [project]);
  const failing = results.filter((r) => !r.pass).length;
  const quick = (name: string, port: number, expect: 'accept' | 'block', src = '198.51.100.20') =>
    update((p) => ({ ...p, tests: [...p.tests, { id: uid('t'), name, packet: { direction: 'in', src, dst: '192.0.2.10', proto: 'tcp', port, state: 'new' }, expect }] }));
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Policy tests" sub="Statements that must stay true, checked on every change. A later edit that breaks one shows up here, on the dashboard and in the audit.">
        <button className="btn" onClick={() => quick('Telnet from the internet is blocked', 23, 'block')}><Plus size={14} /> Telnet blocked</button>
        <button className="btn" onClick={() => quick('Database is not public', 5432, 'block')}><Plus size={14} /> DB not public</button>
        <button className="btn btn-primary" onClick={() => setPage('simulator')}><FlaskConical size={15} /> New from simulator</button>
      </PageHeader>
      <div className="mb-4 grid grid-cols-3 gap-4">
        <Stat label="Tests" value={results.length} />
        <Stat label="Passing" value={results.length - failing} tone="ok" />
        <Stat label="Failing" value={failing} tone={failing ? 'bad' : 'ok'} />
      </div>
      <Panel title="Assertions">
        {results.length === 0 ? (
          <Empty icon={<FlaskConical size={22} />} title="No tests yet">Open the simulator, describe a packet, and press “Save as test”. Or add a common one with the buttons above.</Empty>
        ) : (
          <ul className="space-y-2">
            {results.map((r) => {
              const pk = r.test.packet;
              return (
                <li key={r.test.id} className="tile flex flex-wrap items-center gap-3 px-3.5 py-2.5" style={{ borderColor: r.pass ? undefined : 'color-mix(in srgb, var(--bad) 50%, transparent)' }}>
                  <span className={`badge ${r.pass ? 'badge-ok' : 'badge-bad'}`}>{r.pass ? 'pass' : 'fail'}</span>
                  <div className="min-w-[220px] flex-1">
                    <input aria-label="Test name" className="w-full rounded bg-transparent text-[13.5px] font-semibold outline-none hover:bg-white/5 focus:bg-white/5" value={r.test.name} onChange={(e) => update((p) => ({ ...p, tests: p.tests.map((t) => (t.id === r.test.id ? { ...t, name: e.target.value } : t)) }))} />
                    <div className="font-mono text-[11.5px] text-mute">{pk.direction} {pk.proto}{pk.port ? `/${pk.port}` : ''} {pk.src} → {pk.dst}{pk.inIface ? ` in ${pk.inIface}` : ''}{pk.outIface ? ` out ${pk.outIface}` : ''}</div>
                    {!r.pass && <div className="mt-0.5 text-[12px]" style={{ color: 'var(--bad)' }}>{r.error ?? `Expected ${r.test.expect === 'accept' ? 'accepted' : 'blocked'}, but the verdict is ${r.verdict} (${r.decidedBy}).`}</div>}
                  </div>
                  <div className="flex items-center gap-1.5 text-[12px] text-mute">must be
                    <Segmented size="sm" value={r.test.expect} onChange={(expect) => update((p) => ({ ...p, tests: p.tests.map((t) => (t.id === r.test.id ? { ...t, expect } : t)) }))} options={[{ value: 'accept', label: 'accepted' }, { value: 'block', label: 'blocked' }]} />
                    now <ActionBadge action={r.verdict} />
                  </div>
                  {r.ruleId && <button className="btn" onClick={() => { useStore.getState().selectRule(r.ruleId!); setPage('rules'); }}>Rule <ArrowRight size={13} /></button>}
                  <button className="btn btn-ghost btn-icon" aria-label="Delete test" onClick={() => update((p) => ({ ...p, tests: p.tests.filter((t) => t.id !== r.test.id) }))}><Trash2 size={14} /></button>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </div>
  );
}
