import { Ban, Check, Minus, Plus, Printer, ShieldCheck, Trash2, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { assess, PROFILES } from '../../core/compliance';
import { uid, type Blocklist } from '../../core/model';
import { parseCidr } from '../../core/net';
import { HARDENING, RECOMMENDED_HARDENING } from '../../core/sysctl';
import { useStore, useTarget, useEffectiveProject } from '../../store/useStore';
import { OutputPanel } from '../components/OutputPanel';
import { Empty, Field, PageHeader, Panel, Segmented, Stat, Switch, TagInput } from '../components/ui';

export function BlocklistsPage() {
  const lists = useStore((s) => s.project.blocklists);
  const update = useStore((s) => s.update);
  const set = (id: string, patch: Partial<Blocklist>) => update((p) => ({ ...p, blocklists: p.blocklists.map((b) => (b.id === id ? { ...b, ...patch } : b)) }));
  const add = (b: Partial<Blocklist>) => update((p) => ({ ...p, blocklists: [...p.blocklists, { id: uid('bl'), name: 'New blocklist', enabled: true, entries: [], ...b }] }));
  const [cc, setCc] = useState('');
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Blocklists" sub="Address sets dropped before every other rule, even for established connections. Keep them in the project, or let the server download them on a schedule.">
        <button className="btn btn-primary" onClick={() => add({})}><Plus size={15} /> Blocklist</button>
      </PageHeader>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] xl:overflow-visible">
        <div className="flex flex-col gap-4 pr-1 xl:min-h-0 xl:overflow-y-auto">
          <section className="glass flex-none px-4 py-3.5">
            <div className="mb-1 text-[13px] font-semibold">Block a country</div>
            <p className="mb-2.5 text-[12px] leading-snug text-mute">Adds a downloaded list for a two-letter country code. The address data comes from a third-party site (ipdeny.com) that the server fetches itself; Emberwall does not bundle or check it, so review the URL before you rely on it.</p>
            <div className="flex flex-wrap items-center gap-2">
              <input aria-label="Country code" className="field !w-24 font-mono uppercase" maxLength={2} placeholder="e.g. KP" value={cc} onChange={(e) => setCc(e.target.value.replace(/[^a-zA-Z]/g, ''))} />
              <button className="btn" disabled={cc.length !== 2} onClick={() => { add({ name: `Country ${cc.toUpperCase()}`, url: `https://www.ipdeny.com/ipblocks/data/aggregated/${cc.toLowerCase()}-aggregated.zone` }); setCc(''); }}><Plus size={14} /> Add country list</button>
            </div>
          </section>
          {lists.length === 0 ? (
            <div className="glass"><Empty icon={<Ban size={22} />} title="No blocklists">Use one for known-bad addresses, abusive networks, or whole countries you never serve.</Empty></div>
          ) : (
            lists.map((b) => (
              <section key={b.id} className={`glass flex-none p-4 ${b.enabled ? '' : 'opacity-60'}`}>
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <Switch label="Enabled" checked={b.enabled} onChange={(enabled) => set(b.id, { enabled })} />
                  <input aria-label="Blocklist name" className="field !w-auto min-w-[160px] flex-1 font-medium" value={b.name} onChange={(e) => set(b.id, { name: e.target.value })} />
                  <label className="flex items-center gap-1.5 text-[12.5px]" title="Also drop traffic going to these addresses"><Switch label="Block outbound too" checked={!!b.outbound} onChange={(v) => set(b.id, { outbound: v || undefined })} /> outbound too</label>
                  <button className="btn btn-ghost btn-icon" aria-label="Delete blocklist" onClick={() => update((p) => ({ ...p, blocklists: p.blocklists.filter((x) => x.id !== b.id) }))}><Trash2 size={14} /></button>
                </div>
                <Field label={`Addresses in the project (${b.entries.length})`} hint="Paste many at once, separated by spaces, commas or new lines.">
                  <TagInput value={b.entries} placeholder="198.51.100.0/24, 2001:db8::/32" validate={(v) => !!parseCidr(v)} onChange={(entries) => set(b.id, { entries })} />
                </Field>
                <Field label="Download URL (optional)" hint="One address or CIDR per line. The server fetches it; lines that are not addresses are ignored." className="mt-3">
                  <input className="field font-mono" value={b.url ?? ''} placeholder="https://example.org/list.txt" onChange={(e) => set(b.id, { url: e.target.value.trim() || undefined })} />
                </Field>
              </section>
            ))
          )}
        </div>
        <OutputPanel className="h-[620px] xl:h-auto xl:min-h-0" />
      </div>
    </div>
  );
}

export function HardeningPage() {
  const enabled = useStore((s) => s.project.hardening);
  const forwarding = useStore((s) => s.project.options.forwarding);
  const update = useStore((s) => s.update);
  const toggle = (id: string, on: boolean) => update((p) => ({ ...p, hardening: on ? [...new Set([...p.hardening, id])] : p.hardening.filter((x) => x !== id) }));
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Kernel hardening" sub="Network settings the firewall rules cannot cover. Enabled ones are written to a sysctl drop-in that ships with every build.">
        <button className="btn" onClick={() => update((p) => ({ ...p, hardening: [] }))}>Clear</button>
        <button className="btn btn-primary" onClick={() => update((p) => ({ ...p, hardening: [...new Set([...p.hardening, ...RECOMMENDED_HARDENING])] }))}><ShieldCheck size={15} /> Enable recommended</button>
      </PageHeader>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] xl:overflow-visible">
        <div className="glass p-4 xl:min-h-0 xl:overflow-y-auto">
          <div className="space-y-2">
            {HARDENING.map((h) => {
              const on = enabled.includes(h.id);
              return (
                <div key={h.id} className="tile flex items-start justify-between gap-3 px-3.5 py-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-[13.5px] font-semibold">{h.label}{h.recommended && <span className="badge badge-info">recommended</span>}</div>
                    <div className="mt-0.5 text-[12.5px] leading-snug text-mute">{h.why}</div>
                    {h.caution && (on || (h.id === 'rp_filter' && forwarding)) && <div className="mt-1 text-[12px] leading-snug" style={{ color: 'var(--warn)' }}>Caution: {h.caution}</div>}
                    <div className="mt-1.5 flex flex-wrap gap-1">{h.lines.map(([k, v]) => <span key={k} className="chip">{k.replace(/^-/, '')} = {v}</span>)}</div>
                  </div>
                  <Switch label={h.label} checked={on} onChange={(v) => toggle(h.id, v)} />
                </div>
              );
            })}
          </div>
          <p className="mt-3 text-[12px] text-mute">Install the generated <span className="font-mono">99-emberwall.conf</span> in <span className="font-mono">/etc/sysctl.d/</span> and run <span className="font-mono">sysctl --system</span>. The file also sets <span className="font-mono">ip_forward</span> from the Routing option.</p>
        </div>
        <OutputPanel className="h-[620px] xl:h-auto xl:min-h-0" />
      </div>
    </div>
  );
}

export function CompliancePage() {
  const project = useEffectiveProject();
  const target = useTarget();
  const [profileId, setProfileId] = useState(PROFILES[0].id);
  const report = useMemo(() => assess(project, profileId), [project, profileId]);
  const tone = report.percent >= 90 ? 'ok' : report.percent >= 60 ? 'warn' : 'bad';
  return (
    <div className="print-page h-full overflow-y-auto pr-1">
      <PageHeader title="Compliance" sub="Checks the ruleset against a named profile and shows the evidence for each control.">
        <span className="no-print"><Segmented value={profileId} onChange={setProfileId} options={PROFILES.map((p) => ({ value: p.id, label: p.name.split(' ')[0] }))} /></span>
        <button className="btn btn-primary no-print" onClick={() => window.print()}><Printer size={15} /> Print / save as PDF</button>
      </PageHeader>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Result" value={`${report.percent}%`} tone={tone} sub={report.profile.name} />
        <Stat label="Passed" value={report.passed} tone="ok" />
        <Stat label="Failed" value={report.failed} tone={report.failed ? 'bad' : 'ok'} />
        <Stat label="Not applicable" value={report.results.length - report.passed - report.failed} />
      </div>
      <Panel title={report.profile.name} hint={`${project.name} · ${target.label} · ${new Date().toLocaleDateString()}`}>
        <p className="mb-3 text-[12.5px] leading-snug text-mute">{report.profile.about} This is Emberwall's interpretation of the framework's firewall-related intent. It supports a review; it is not an official assessment or a certification.</p>
        <ul className="space-y-2">
          {report.results.map((r, i) => (
            <li key={r.id} className="tile flex items-start gap-3 px-3.5 py-3" style={r.status === 'fail' ? { borderColor: 'color-mix(in srgb, var(--bad) 40%, transparent)' } : undefined}>
              <span className="mt-0.5 w-6 flex-none text-center font-mono text-[11px] text-mute">{i + 1}</span>
              <span className="mt-0.5 flex-none">
                {r.status === 'pass' ? <Check size={16} style={{ color: 'var(--ok)' }} /> : r.status === 'fail' ? <X size={16} style={{ color: 'var(--bad)' }} /> : <Minus size={16} className="text-mute" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[13.5px] font-semibold">{r.title}</div>
                <div className="text-[12px] text-mute">{r.intent}</div>
                <div className="mt-1 text-[12.5px]">{r.evidence}</div>
              </div>
              <span className={`badge ${r.status === 'pass' ? 'badge-ok' : r.status === 'fail' ? 'badge-bad' : 'badge-mute'}`}>{r.status === 'na' ? 'n/a' : r.status}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
