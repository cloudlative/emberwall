import { ArrowRight, Check, FlaskConical, LayoutTemplate, Minus, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useMemo } from 'react';
import { grade, score, SEVERITY_ORDER } from '../../core/lint';
import { DIRECTION_LABEL, type Direction } from '../../core/model';
import { portLabel } from '../../core/net';
import { resolveAll } from '../../core/resolve';
import { CAPABILITIES } from '../../core/targets';
import { useCompiled, useFindings, useStore, useTarget, useEffectiveProject } from '../../store/useStore';
import { ActionBadge, PageHeader, Panel, SeverityBadge, Stat } from '../components/ui';
import { TargetPicker } from '../components/TargetPicker';

function ScoreRing({ value }: { value: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const color = value >= 75 ? 'var(--ok)' : value >= 50 ? 'var(--warn)' : 'var(--bad)';
  return (
    <div className="relative h-[136px] w-[136px] flex-none" role="img" aria-label={`Posture score ${value} of 100, grade ${grade(value)}`}>
      <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
        <circle cx="64" cy="64" r={r} fill="none" stroke="var(--line)" strokeWidth="9" />
        <circle cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${(value / 100) * c} ${c}`} style={{ transition: 'stroke-dasharray .5s ease', filter: `drop-shadow(0 0 8px ${color})` }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-[34px] font-semibold leading-none tracking-tight">{value}</div>
          <div className="mt-1 text-[11px] font-semibold uppercase tracking-widest text-mute">Grade {grade(value)}</div>
        </div>
      </div>
    </div>
  );
}

export function DashboardPage() {
  const project = useEffectiveProject();
  const setPage = useStore((s) => s.setPage);
  const findings = useFindings();
  const compiled = useCompiled();
  const target = useTarget();
  const s = score(findings);
  const resolved = useMemo(() => resolveAll(project), [project]);

  const exposure = useMemo(() => {
    const rows: { key: string; port: string; proto: string; label: string; scope: string; world: boolean; ruleId: string }[] = [];
    for (const rr of resolved) {
      const r = rr.rule;
      if (r.direction !== 'in' || r.action !== 'accept') continue;
      const world = r.src.length === 0 && !r.inIface;
      const scope = r.src.length === 0 ? (r.inIface ? `via ${r.inIface}` : 'anywhere') : `${[...(rr.v4?.src ?? []), ...(rr.v6?.src ?? [])].length} source range(s)`;
      const ports = rr.ports.length > 0 ? rr.ports : ['all'];
      for (const port of ports) rows.push({ key: `${r.id}:${port}`, port, proto: r.proto === 'tcpudp' ? 'tcp+udp' : r.proto, label: portLabel(port) || r.name, scope, world, ruleId: r.id });
    }
    return rows;
  }, [resolved]);

  const sevCount = SEVERITY_ORDER.map((sev) => ({ sev, n: findings.filter((f) => f.severity === sev).length })).filter((x) => x.n > 0 && x.sev !== 'info');
  const fallbacks = compiled.diagnostics.filter((d) => d.kind === 'fallback' || d.kind === 'unsupported').length;
  const lines = compiled.files[0].lines.length;
  const caps = CAPABILITIES.filter((c) => c.tool === target.tool);
  const worldOpen = exposure.filter((e) => e.world).length;

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title={project.name} sub={project.description || 'Design once, compile for the exact firewall version you run.'}>
        <button className="btn" onClick={() => setPage('templates')}><LayoutTemplate size={15} /> Templates</button>
        <button className="btn" onClick={() => setPage('simulator')}><FlaskConical size={15} /> Test a packet</button>
        <button className="btn btn-primary" onClick={() => setPage('build')}>Build output <ArrowRight size={15} /></button>
      </PageHeader>

      <div className="grid gap-4 lg:grid-cols-[auto_minmax(0,1fr)]">
        <section className="glass flex items-center gap-5 px-5 py-4">
          <ScoreRing value={s} />
          <div className="min-w-[180px]">
            <div className="flex items-center gap-2 text-[15px] font-semibold">
              {s >= 75 ? <ShieldCheck size={18} style={{ color: 'var(--ok)' }} /> : <ShieldAlert size={18} style={{ color: s >= 50 ? 'var(--warn)' : 'var(--bad)' }} />}
              {s >= 90 ? 'Strong posture' : s >= 75 ? 'Good posture' : s >= 50 ? 'Needs attention' : 'At risk'}
            </div>
            <p className="mt-1 max-w-[230px] text-[12.5px] text-mute">
              {sevCount.length === 0 ? 'The audit found nothing to fix.' : 'Score is 100 minus a penalty for each audit finding.'}
            </p>
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {sevCount.map((x) => (
                <span key={x.sev} className="inline-flex items-center gap-1.5 text-[12px]"><SeverityBadge severity={x.sev} /> <b className="font-semibold">{x.n}</b></span>
              ))}
            </div>
            <button className="btn mt-3" onClick={() => setPage('audit')}>Open audit <ArrowRight size={14} /></button>
          </div>
        </section>

        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          <Stat label="Rules" value={project.rules.filter((r) => r.enabled).length} sub={`${project.nat.filter((n) => n.enabled).length} NAT · ${project.addressGroups.length + project.portGroups.length} objects`} />
          <Stat label="Open to the internet" value={worldOpen} tone={worldOpen === 0 ? 'ok' : 'warn'} sub={`${exposure.length} inbound allowance${exposure.length === 1 ? '' : 's'} in total`} />
          <Stat label="Output lines" value={lines} sub={compiled.files[0].name} />
          <Stat label="Version fallbacks" value={fallbacks} tone={fallbacks === 0 ? 'ok' : 'warn'} sub={fallbacks === 0 ? 'Full feature set on this target' : 'Adapted for this version'} />
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Inbound exposure" hint="What this host accepts, and from where" className="xl:col-span-2">
          {exposure.length === 0 ? (
            <p className="py-6 text-center text-[13px] text-mute">Nothing is accepted from outside. Only replies to outbound connections get in.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12.5px]">
                <thead className="text-[11px] uppercase tracking-wider text-mute">
                  <tr><th className="pb-2 font-semibold">Port</th><th className="pb-2 font-semibold">Service</th><th className="pb-2 font-semibold">Protocol</th><th className="pb-2 font-semibold">Reachable from</th></tr>
                </thead>
                <tbody>
                  {exposure.map((e) => (
                    <tr key={e.key} className="cursor-pointer border-t hover:bg-white/5" style={{ borderColor: 'var(--line)' }} onClick={() => { useStore.getState().selectRule(e.ruleId); setPage('rules'); }}>
                      <td className="py-1.5 font-mono">{e.port}</td>
                      <td className="py-1.5">{e.label}</td>
                      <td className="py-1.5 font-mono uppercase text-mute">{e.proto}</td>
                      <td className="py-1.5"><span className={`badge ${e.world ? 'badge-warn' : 'badge-ok'}`}>{e.world ? 'Internet' : 'Restricted'}</span> <span className="ml-1 text-mute">{e.scope}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Traffic policy" hint="Default verdict and rule count per direction">
          <div className="space-y-2">
            {(['in', 'out', 'forward'] as Direction[]).map((d) => {
              const list = project.rules.filter((r) => r.direction === d && r.enabled);
              return (
                <div key={d} className="tile flex items-center justify-between px-3 py-2.5">
                  <div>
                    <div className="text-[13px] font-medium">{DIRECTION_LABEL[d]}</div>
                    <div className="text-[12px] text-mute">{list.length} rule{list.length === 1 ? '' : 's'} · {list.filter((r) => r.action === 'accept').length} accept · {list.filter((r) => r.action !== 'accept').length} block</div>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-mute">default <ActionBadge action={project.policies[d]} /></div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 pb-2 xl:grid-cols-3">
        <Panel title="Build target" hint="Output is tailored to this version" className="xl:col-span-2">
          <TargetPicker />
          <div className="mt-3 grid gap-1.5 sm:grid-cols-2">
            {caps.map((c) => {
              const on = target.caps[c.key];
              return (
                <div key={c.key} className="tile flex items-start gap-2 px-3 py-2">
                  {on ? <Check size={15} className="mt-0.5 flex-none" style={{ color: 'var(--ok)' }} /> : <Minus size={15} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />}
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium">{c.label}</div>
                    <div className="text-[11.5px] text-mute">{on ? `Available (since ${c.since})` : `Needs ${c.since}${c.kernel ? ` / kernel ${c.kernel}` : ''} — ${c.fallback}`}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
        <Panel title="Top findings" actions={<button className="btn btn-ghost" onClick={() => setPage('audit')}>All <ArrowRight size={13} /></button>}>
          {findings.filter((f) => f.severity !== 'info').length === 0 ? (
            <p className="py-6 text-center text-[13px] text-mute">No findings. Nice.</p>
          ) : (
            <ul className="space-y-2">
              {findings.filter((f) => f.severity !== 'info').slice(0, 5).map((f) => (
                <li key={f.id} className="flex items-start gap-2 text-[12.5px]">
                  <SeverityBadge severity={f.severity} />
                  <span className="leading-snug">{f.title}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
