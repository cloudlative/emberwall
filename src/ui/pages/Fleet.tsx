import { ArrowRight, Ban, Download, Eye, FileSearch, Globe, Plus, Server, Shield, Trash2 } from 'lucide-react';
import { useMemo, useState } from 'react';
import { fileText } from '../../core/compile';
import { buildFleet, fleetAnsible, fleetFiles, hostDir } from '../../core/fleet';
import { grade } from '../../core/lint';
import { analyzeLogs, verdictNow } from '../../core/logs';
import { newRule, uid, type Host } from '../../core/model';
import { buildAxes, reachability } from '../../core/reach';
import { DISTROS, TOOL_LABEL, type Tool } from '../../core/targets';
import { download, useEffectiveProject, useStore } from '../../store/useStore';
import { ActionBadge, Empty, PageHeader, Panel, Stat } from '../components/ui';

/** A POSIX shell archive: one file that recreates the whole fleet directory tree. */
function shellArchive(files: { path: string; text: string }[]): string {
  const out = ['#!/bin/sh', '# Emberwall fleet bundle. Run "sh emberwall-fleet.sh" in an empty directory to unpack.', 'set -eu', ''];
  files.forEach((f, i) => {
    const mark = `EMBERWALL_EOF_${i}`;
    const dir = f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '';
    if (dir) out.push(`mkdir -p '${dir}'`);
    out.push(`cat > '${f.path}' <<'${mark}'`, f.text.replace(/\n$/, ''), mark, '');
  });
  out.push(`echo "Unpacked ${files.length} files."`);
  return out.join('\n') + '\n';
}

export function FleetPage() {
  const project = useStore((s) => s.project);
  const activeHostId = useStore((s) => s.activeHostId);
  const { update, setActiveHost, setPage, toast } = useStore.getState();
  const builds = useMemo(() => buildFleet(project), [project]);
  const set = (id: string, patch: Partial<Host>) => update((p) => ({ ...p, hosts: p.hosts.map((h) => (h.id === id ? { ...h, ...patch } : h)) }));
  const add = () => update((p) => ({ ...p, hosts: [...p.hosts, { id: uid('h'), name: `host-${p.hosts.length + 1}`, target: { distro: 'ubuntu-24.04', tool: 'nftables', version: '' } }] }));
  const shared = project.rules.filter((r) => !r.hosts || r.hosts.length === 0).length;

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Fleet" sub="One policy, many machines. Every host gets the shared rules plus the rules scoped to it, compiled for its own firewall and version.">
        {builds.length > 0 && (
          <button className="btn" onClick={() => { download('emberwall-fleet.sh', shellArchive(fleetFiles(builds))); toast('Fleet bundle downloaded'); }}><Download size={15} /> Download fleet bundle</button>
        )}
        <button className="btn btn-primary" onClick={add}><Plus size={15} /> Host</button>
      </PageHeader>
      {builds.length === 0 ? (
        <div className="glass"><Empty icon={<Server size={22} />} title="No hosts yet">Add the machines this policy runs on. Without hosts, Emberwall builds a single ruleset for the target in the top bar.</Empty></div>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Hosts" value={builds.length} />
            <Stat label="Shared rules" value={shared} sub={`${project.rules.length - shared} scoped to specific hosts`} />
            <Stat label="Lowest score" value={Math.min(...builds.map((b) => b.score))} tone={Math.min(...builds.map((b) => b.score)) >= 75 ? 'ok' : 'warn'} />
            <Stat label="Hosts with fallbacks" value={builds.filter((b) => b.fallbacks > 0).length} tone={builds.some((b) => b.errors > 0) ? 'bad' : undefined} sub={builds.some((b) => b.errors > 0) ? 'some builds have errors' : 'version or tool adaptations'} />
          </div>
          <div className="space-y-3">
            {builds.map((b) => {
              const h = b.host;
              const distro = DISTROS.find((d) => d.id === h.target.distro);
              const tools = (distro ? Object.keys(distro.tools) : ['nftables', 'iptables', 'ufw', 'firewalld']) as Tool[];
              return (
                <section key={h.id} className="glass flex flex-wrap items-center gap-3 px-4 py-3" style={activeHostId === h.id ? { borderColor: 'rgba(255,143,92,0.6)' } : undefined}>
                  <Server size={18} className="flex-none text-ember-400" />
                  <input aria-label="Host name" className="field !w-40 font-medium" value={h.name} onChange={(e) => set(h.id, { name: e.target.value })} />
                  <input aria-label="Address" className="field !w-44 font-mono" placeholder="address or DNS name" value={h.address ?? ''} onChange={(e) => set(h.id, { address: e.target.value.trim() || undefined })} />
                  <select aria-label="Distribution" className="field !w-auto" value={h.target.distro} onChange={(e) => {
                    const d = DISTROS.find((x) => x.id === e.target.value)!;
                    set(h.id, { target: { distro: d.id, tool: d.tools[h.target.tool] ? h.target.tool : d.defaultTool, version: '' } });
                  }}>
                    {DISTROS.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
                  </select>
                  <select aria-label="Firewall tool" className="field !w-auto" value={b.result.target.tool} onChange={(e) => set(h.id, { target: { ...h.target, tool: e.target.value as Tool } })}>
                    {tools.map((t) => <option key={t} value={t}>{TOOL_LABEL[t]} {distro?.tools[t] ?? ''}</option>)}
                  </select>
                  <div className="ml-auto flex flex-wrap items-center gap-1.5 text-[12px] text-mute">
                    <span className="badge badge-mute">{b.rules} rules</span>
                    <span className={`badge ${b.score >= 75 ? 'badge-ok' : b.score >= 50 ? 'badge-warn' : 'badge-bad'}`}>score {b.score} · {grade(b.score)}</span>
                    {b.fallbacks > 0 && <span className="badge badge-warn">{b.fallbacks} adapted</span>}
                    {b.errors > 0 && <span className="badge badge-bad">{b.errors} errors</span>}
                    <button className="btn" onClick={() => { setActiveHost(h.id); setPage('build'); }}><Eye size={14} /> Open</button>
                    <button className="btn btn-icon" aria-label={`Download files for ${h.name}`} title="Download this host's main file" onClick={() => download(`${hostDir(h)}-${b.result.files[0].name}`, fileText(b.result.files[0]))}><Download size={14} /></button>
                    <button className="btn btn-ghost btn-icon" aria-label="Delete host" onClick={() => {
                      if (activeHostId === h.id) setActiveHost(null);
                      update((p) => ({ ...p, hosts: p.hosts.filter((x) => x.id !== h.id), rules: p.rules.map((r) => (r.hosts ? { ...r, hosts: r.hosts.filter((x) => x !== h.id) } : r)) }));
                    }}><Trash2 size={14} /></button>
                  </div>
                </section>
              );
            })}
          </div>
          <Panel className="mt-4" title="Rolling it out" hint="The bundle contains hosts/<name>/ for every machine, an Ansible inventory and a playbook">
            <ol className="list-decimal space-y-1 pl-4 text-[12.5px] leading-relaxed text-ink/90">
              <li>Scope a rule to hosts in the rule editor under <b>Advanced matches → Hosts</b>; unscoped rules go everywhere.</li>
              <li>Pick a host in the top bar to see its rules, output, audit and simulator results.</li>
              <li>Download the bundle, run <code className="chip">sh emberwall-fleet.sh</code> to unpack, then <code className="chip">ansible-playbook -i inventory.ini fleet-playbook.yml --limit one-host</code>.</li>
            </ol>
            <div className="mt-3 flex flex-wrap gap-2">
              {fleetAnsible(builds).map((f) => <button key={f.name} className="btn" onClick={() => download(f.name, fileText(f))}><Download size={14} /> {f.name}</button>)}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

interface Pt { x: number; y: number }

export function TopologyPage() {
  const project = useEffectiveProject();
  const [picked, setPicked] = useState<string | null>(null);
  const { axes, rows } = useMemo(() => {
    const a = buildAxes(project);
    return { axes: a, rows: reachability(project, a) };
  }, [project]);

  const sources = axes.sources;
  const zones = axes.targets.filter((t) => t.id !== 'host');
  const H = Math.max(420, Math.max(sources.length, zones.length + 1) * 92 + 60);
  const W = 780;
  const colY = (i: number, n: number) => (H / (n + 1)) * (i + 1);
  const pos = new Map<string, Pt>();
  sources.forEach((s, i) => pos.set(`s:${s.id}`, { x: 105, y: colY(i, sources.length) }));
  pos.set('t:host', { x: W / 2, y: H / 2 });
  zones.forEach((z, i) => pos.set(`t:${z.id}`, { x: W - 105, y: colY(i, zones.length) }));

  const edges = rows.map((r) => {
    const open = r.cells.map((c, i) => ({ c, svc: axes.services[i] })).filter((x) => x.c.verdict === 'accept');
    return { id: `${r.source.id}>${r.target.id}`, row: r, open, from: pos.get(`s:${r.source.id}`)!, to: pos.get(`t:${r.target.id}`)! };
  }).filter((e) => e.from && e.to);
  const sel = edges.find((e) => e.id === picked) ?? null;

  const node = (p: Pt, label: string, detail: string, icon: 'globe' | 'shield' | 'server', key: string) => (
    <g key={key} transform={`translate(${p.x - 95},${p.y - 28})`}>
      <rect width="190" height="56" rx="14" fill="var(--glass-strong)" stroke="var(--line-strong)" />
      <foreignObject x="12" y="8" width="170" height="44">
        <div className="flex h-full items-center gap-2.5">
          <span className="flex-none text-ember-400">{icon === 'globe' ? <Globe size={18} /> : icon === 'shield' ? <Shield size={18} /> : <Server size={18} />}</span>
          <div className="min-w-0">
            <div className="truncate text-[12.5px] font-semibold">{label}</div>
            <div className="truncate text-[10.5px] text-mute">{detail}</div>
          </div>
        </div>
      </foreignObject>
    </g>
  );

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Topology" sub="Sources on the left, this firewall in the middle, the networks behind it on the right. A solid line means at least one service is allowed; click a line to see which." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.9fr)_minmax(0,1fr)]">
        <section className="glass overflow-x-auto p-2">
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[640px]" role="img" aria-label="Network topology with allowed flows">
            <defs>
              <marker id="arr-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--ok)" /></marker>
              <marker id="arr-no" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--line-strong)" /></marker>
            </defs>
            {edges.map((e) => {
              const ok = e.open.length > 0;
              const through = e.row.target.id !== 'host';
              const a = { x: e.from.x + 95, y: e.from.y };
              const b = { x: e.to.x - 95, y: e.to.y };
              const mid = through ? { x: W / 2, y: H / 2 + (e.to.y - H / 2) * 0.35 - 46 } : { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
              const d = through ? `M${a.x},${a.y} Q${mid.x},${mid.y - 40} ${b.x},${b.y}` : `M${a.x},${a.y} L${b.x},${b.y}`;
              const active = picked === e.id;
              return (
                <g key={e.id} onClick={() => setPicked(e.id)} style={{ cursor: 'pointer' }}>
                  <path d={d} fill="none" stroke="transparent" strokeWidth="16" />
                  <path d={d} fill="none" stroke={ok ? 'var(--ok)' : 'var(--line-strong)'} strokeWidth={active ? 3.5 : ok ? 2 : 1.2} strokeDasharray={ok ? undefined : '5 6'} markerEnd={`url(#${ok ? 'arr-ok' : 'arr-no'})`} opacity={ok ? 0.9 : 0.7} />
                  {ok && !through && (
                    <g transform={`translate(${mid.x},${mid.y})`}>
                      <rect x="-15" y="-10" width="30" height="20" rx="10" fill="var(--glass-strong)" stroke="var(--ok)" />
                      <text textAnchor="middle" y="4" fontSize="11" fontWeight="600" fill="rgb(var(--ink))">{e.open.length}</text>
                    </g>
                  )}
                </g>
              );
            })}
            {sources.map((s) => node(pos.get(`s:${s.id}`)!, s.label, s.detail, s.id === 'internet' ? 'globe' : 'server', `s:${s.id}`))}
            {node(pos.get('t:host')!, 'This firewall', project.name, 'shield', 'host')}
            {zones.map((z) => node(pos.get(`t:${z.id}`)!, z.label, z.detail, 'server', `t:${z.id}`))}
          </svg>
        </section>
        <Panel title={sel ? `${sel.row.source.label} → ${sel.row.target.label}` : 'Flows'} hint={sel ? `${sel.open.length} of ${axes.services.length} services allowed` : 'Click a line in the diagram'}>
          {!sel ? (
            <ul className="space-y-1.5 text-[12.5px]">
              {edges.filter((e) => e.open.length > 0).map((e) => (
                <li key={e.id}><button className="tile flex w-full items-center justify-between gap-2 px-3 py-2 text-left" onClick={() => setPicked(e.id)}><span>{e.row.source.label} → {e.row.target.label}</span><span className="badge badge-ok">{e.open.length} open</span></button></li>
              ))}
              {edges.every((e) => e.open.length === 0) && <li className="py-6 text-center text-mute">Nothing is allowed through yet.</li>}
            </ul>
          ) : (
            <ul className="space-y-1.5">
              {sel.row.cells.map((c, i) => (
                <li key={i} className="tile flex items-center justify-between gap-2 px-3 py-1.5 text-[12.5px]">
                  <span>{axes.services[i].label}</span>
                  <span className="flex items-center gap-2"><span className="max-w-[150px] truncate text-[11.5px] text-mute" title={c.decidedBy}>{c.decidedBy}</span><ActionBadge action={c.verdict} /></span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

const SAMPLE_LOG = `Nov 12 14:02:11 web1 kernel: [ 9123.11] ew-drop-in: IN=eth0 OUT= MAC=52:54:00:aa:bb:cc SRC=203.0.113.45 DST=192.0.2.10 LEN=60 TTL=51 PROTO=TCP SPT=51422 DPT=23 SYN
Nov 12 14:02:12 web1 kernel: [ 9124.02] ew-drop-in: IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=51423 DPT=3389 SYN
Nov 12 14:02:15 web1 kernel: [ 9127.40] ew-drop-in: IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40111 DPT=5432 SYN
Nov 12 14:03:01 web1 kernel: [ 9173.90] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 LEN=40 PROTO=TCP SPT=51500 DPT=8080 SYN
Nov 12 14:03:30 web1 kernel: [ 9202.10] ew-drop-in: IN=eth0 OUT= SRC=192.0.2.77 DST=192.0.2.10 LEN=76 PROTO=UDP SPT=123 DPT=123
`;

export function LogsPage() {
  const project = useEffectiveProject();
  const { update, toast, setPage } = useStore.getState();
  const [text, setText] = useState('');
  const sum = useMemo(() => analyzeLogs(text), [text]);
  const blockSource = (addr: string) => {
    update((p) => {
      const existing = p.blocklists.find((b) => b.name === 'From logs');
      if (existing) return { ...p, blocklists: p.blocklists.map((b) => (b === existing ? { ...b, enabled: true, entries: [...new Set([...b.entries, addr])] } : b)) };
      return { ...p, blocklists: [...p.blocklists, { id: uid('bl'), name: 'From logs', enabled: true, entries: [addr] }] };
    });
    toast(`${addr} added to the "From logs" blocklist`);
  };
  const allowPort = (proto: string, port: number) => {
    update((p) => ({ ...p, rules: [...p.rules, newRule({ name: `Allow ${proto}/${port} (from logs)`, proto: proto as 'tcp' | 'udp', ports: [String(port)] })] }));
    toast(`Rule added for ${proto}/${port}`);
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Log analyzer" sub="Paste firewall log lines from the server (journalctl -k, /var/log/kern.log, ufw.log). Nothing is uploaded; parsing happens in this page.">
        <button className="btn" onClick={() => setText(SAMPLE_LOG)}>Paste sample</button>
      </PageHeader>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
        <Panel title="Log lines" hint={text ? `${sum.entries.length} parsed, ${sum.unparsed} not recognised` : 'iptables LOG, nftables log and ufw formats'}>
          <textarea className="field h-72 resize-y font-mono text-[11.5px] leading-relaxed" spellCheck={false} placeholder="… kernel: ew-drop-in: IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 PROTO=TCP SPT=51422 DPT=23 …" value={text} onChange={(e) => setText(e.target.value)} />
          {sum.byPrefix.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">{sum.byPrefix.map((p) => <span key={p.key} className="chip">{p.key} · {p.count}</span>)}</div>
          )}
        </Panel>
        {sum.entries.length === 0 ? (
          <div className="glass"><Empty icon={<FileSearch size={22} />} title="No log entries yet">Turn on “Log dropped” in Rules so the firewall writes these lines, then paste them here to see who is knocking and on which ports.</Empty></div>
        ) : (
          <div className="flex flex-col gap-4">
            <Panel title="Top sources" hint="Addresses with the most logged packets">
              <table className="w-full text-left text-[12.5px]">
                <thead className="text-[11px] uppercase tracking-wider text-mute"><tr><th className="pb-1.5 font-semibold">Source</th><th className="pb-1.5 font-semibold">Packets</th><th className="pb-1.5 font-semibold">Ports tried</th><th /></tr></thead>
                <tbody>
                  {sum.topSources.map((s) => (
                    <tr key={s.key} className="border-t" style={{ borderColor: 'var(--line)' }}>
                      <td className="py-1.5 font-mono">{s.key}</td><td className="py-1.5">{s.count}</td><td className="py-1.5">{s.ports}{s.ports >= 3 && <span className="badge badge-warn ml-2">scan-like</span>}</td>
                      <td className="py-1 text-right"><button className="btn" onClick={() => blockSource(s.key)}><Ban size={13} /> Block</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
            <Panel title="Top destination ports" hint="What the logged packets were trying to reach, and what the current ruleset would do with them">
              <table className="w-full text-left text-[12.5px]">
                <thead className="text-[11px] uppercase tracking-wider text-mute"><tr><th className="pb-1.5 font-semibold">Port</th><th className="pb-1.5 font-semibold">Service</th><th className="pb-1.5 font-semibold">Packets</th><th className="pb-1.5 font-semibold">Sources</th><th className="pb-1.5 font-semibold">Now</th><th /></tr></thead>
                <tbody>
                  {sum.topPorts.map((pt) => {
                    const sample = sum.entries.find((e) => e.proto === pt.proto && e.dport === pt.port)!;
                    const now = verdictNow(project, sample);
                    return (
                      <tr key={pt.key} className="border-t" style={{ borderColor: 'var(--line)' }}>
                        <td className="py-1.5 font-mono">{pt.port}/{pt.proto}</td><td className="py-1.5">{pt.label || <span className="text-mute">—</span>}</td><td className="py-1.5">{pt.count}</td><td className="py-1.5">{pt.sources}</td>
                        <td className="py-1.5" title={now.decidedBy}><ActionBadge action={now.verdict} /></td>
                        <td className="py-1 text-right">{now.verdict !== 'accept' && <button className="btn" title="Only if this is a service you mean to offer" onClick={() => allowPort(pt.proto, pt.port)}><Plus size={13} /> Allow</button>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <button className="btn mt-3" onClick={() => setPage('blocklists')}>Open blocklists <ArrowRight size={13} /></button>
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}
