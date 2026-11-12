import { Box, Boxes, Camera, Check, Database, FileDown, FileUp, Globe, KeyRound, Laptop, Link2, Minus, Router, RotateCcw, Shield, Trash2, Upload } from 'lucide-react';
import { useMemo, useRef, useState, type ReactNode } from 'react';
import { compile, fileText } from '../../core/compile';
import { diffLines, diffStats } from '../../core/diff';
import { importIptablesSave, type ImportReport } from '../../core/import/iptablesSave';
import { grade, lint, score } from '../../core/lint';
import { coerceProject, emptyProject } from '../../core/model';
import { CAPABILITIES, DISTROS, DOCS_CHECKED, TOOL_LABEL, TOOLS, VERSIONS, capsFor, compareVersions, type Tool } from '../../core/targets';
import { TEMPLATES } from '../../core/templates';
import { copyText, download, shareUrl, useStore, useTarget } from '../../store/useStore';
import { DiffView } from '../components/CodeView';
import { Empty, Modal, PageHeader, Panel, Segmented } from '../components/ui';

const ICONS: Record<string, ReactNode> = {
  globe: <Globe size={20} />, key: <KeyRound size={20} />, database: <Database size={20} />, box: <Box size={20} />,
  boxes: <Boxes size={20} />, shield: <Shield size={20} />, router: <Router size={20} />, laptop: <Laptop size={20} />,
};

export function TemplatesPage() {
  const { replaceProject, setPage, toast } = useStore.getState();
  const use = (build: () => ReturnType<typeof emptyProject>, name: string) => {
    replaceProject(build());
    toast(`Loaded "${name}" (undo with Ctrl+Z)`);
    setPage('rules');
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Templates" sub="Reviewed starting points. Loading one replaces the current ruleset; undo brings it back.">
        <button className="btn" onClick={() => use(() => emptyProject(), 'Blank firewall')}>Start blank</button>
      </PageHeader>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {TEMPLATES.map((t) => {
          const p = t.build();
          const s = score(lint(p));
          return (
            <button key={t.id} onClick={() => use(t.build, t.name)} className="glass group flex flex-col p-4 text-left transition hover:-translate-y-0.5" style={{ transitionProperty: 'transform, border-color' }}>
              <div className="mb-3 flex items-center justify-between">
                <span className="grid h-10 w-10 place-items-center rounded-xl text-ember-400" style={{ background: 'var(--glass-hover)', border: '1px solid var(--line)' }}>{ICONS[t.icon]}</span>
                <span className="badge badge-mute">Grade {grade(s)}</span>
              </div>
              <div className="text-[14.5px] font-semibold">{t.name}</div>
              <p className="mt-1 flex-1 text-[12.5px] leading-snug text-mute">{t.summary}</p>
              <div className="mt-3 flex flex-wrap gap-1 text-[11.5px] text-mute">
                <span className="chip">{p.rules.length} rules</span>
                {p.nat.length > 0 && <span className="chip">{p.nat.length} NAT</span>}
                {p.addressGroups.length > 0 && <span className="chip">{p.addressGroups.length} groups</span>}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function VersionsPage() {
  const target = useTarget();
  const [tool, setTool] = useState<Tool>(target.tool);
  const caps = CAPABILITIES.filter((c) => c.tool === tool);
  const versions = VERSIONS[tool];
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Version matrix" sub="What each release can express. Emberwall reads this table to decide which syntax to emit and where to fall back.">
        <Segmented<Tool> value={tool} onChange={setTool} options={TOOLS.map((t) => ({ value: t, label: TOOL_LABEL[t] }))} />
      </PageHeader>
      <Panel title={`${TOOL_LABEL[tool]} features by version`} hint="Each minimum version was checked against the upstream commit that introduced the feature">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-[12.5px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-mute">
                <th className="pb-2 pr-3 font-semibold">Feature</th>
                {versions.map((v) => <th key={v} className={`pb-2 text-center font-mono font-semibold ${v === target.version && tool === target.tool ? 'text-ember-400' : ''}`}>{v}</th>)}
              </tr>
            </thead>
            <tbody>
              {caps.map((c) => (
                <tr key={c.key} className="border-t" style={{ borderColor: 'var(--line)' }}>
                  <td className="py-2 pr-3">
                    <div className="font-medium">{c.label}</div>
                    <div className="text-[11.5px] text-mute">since {c.since}{c.kernel ? `, kernel ${c.kernel}+` : ''} · without it: {c.fallback} · <span className="font-mono">{c.source}</span></div>
                  </td>
                  {versions.map((v) => (
                    <td key={v} className="py-2 text-center">
                      {capsFor(tool, v)[c.key]
                        ? <Check size={15} className="inline" style={{ color: 'var(--ok)' }} aria-label="supported" />
                        : <Minus size={15} className="inline text-mute" aria-label="not supported" />}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <Panel title="What each distribution ships" className="mt-4" hint="Selecting a distribution in the target picker uses these versions">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-[12.5px]">
            <thead className="text-[11px] uppercase tracking-wider text-mute">
              <tr><th className="pb-2 font-semibold">Distribution</th>{TOOLS.map((t) => <th key={t} className="pb-2 font-semibold">{TOOL_LABEL[t]}</th>)}<th className="pb-2 font-semibold">iptables backend</th></tr>
            </thead>
            <tbody>
              {DISTROS.map((d) => (
                <tr key={d.id} className="border-t" style={{ borderColor: 'var(--line)' }}>
                  <td className="py-1.5 font-medium">{d.name}</td>
                  {TOOLS.map((t) => <td key={t} className="py-1.5 font-mono">{d.tools[t] ?? <span className="text-mute">—</span>}{d.defaultTool === t && <span className="badge badge-info ml-1.5 font-sans">default</span>}</td>)}
                  <td className="py-1.5 text-mute">{d.iptablesBackend === 'nft' ? 'nf_tables' : 'legacy'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[12px] text-mute">
          Syntax last checked against: {DOCS_CHECKED.map((d) => `${d.pages} ${d.version}`).join('; ')}.
        </p>
        <p className="mt-1.5 text-[12px] text-mute">
          Newest versions known here: {TOOLS.map((t) => `${TOOL_LABEL[t]} ${[...VERSIONS[t]].sort(compareVersions).pop()}`).join(', ')}. For anything else, choose “Custom tool version” and pick the closest release at or below yours.
        </p>
      </Panel>
    </div>
  );
}

export function SnapshotsPage() {
  const { snapshots, project } = useStore();
  const target = useTarget();
  const { addSnapshot, restoreSnapshot, deleteSnapshot, toast } = useStore.getState();
  const [name, setName] = useState('');
  const [diffId, setDiffId] = useState<string | null>(null);
  const snap = snapshots.find((s) => s.id === diffId);
  const diff = useMemo(() => {
    if (!snap) return null;
    const a = compile(snap.project, target).files[0];
    const b = compile(project, target).files[0];
    return { lines: diffLines(fileText(a).trimEnd(), fileText(b).trimEnd()), lang: b.lang };
  }, [snap, project, target]);
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Snapshots" sub="Named versions of this ruleset, kept in your browser. Diff one against the current state or roll back to it." />
      <div className="glass mb-4 flex flex-wrap items-center gap-2 px-4 py-3">
        <input className="field min-w-[220px] flex-1" placeholder="Snapshot name, e.g. Before opening port 8443" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { addSnapshot(name.trim()); setName(''); } }} />
        <button className="btn btn-primary" onClick={() => { addSnapshot(name.trim()); setName(''); toast('Snapshot saved'); }}><Camera size={15} /> Save snapshot</button>
      </div>
      <Panel title={`${snapshots.length} snapshot${snapshots.length === 1 ? '' : 's'}`}>
        {snapshots.length === 0 ? (
          <Empty icon={<Camera size={22} />} title="No snapshots yet">Save one before a risky change so you can compare and roll back.</Empty>
        ) : (
          <ul className="space-y-2">
            {snapshots.map((s) => (
              <li key={s.id} className="tile flex flex-wrap items-center gap-3 px-3.5 py-2.5">
                <div className="min-w-[200px] flex-1">
                  <div className="text-[13.5px] font-semibold">{s.name}</div>
                  <div className="text-[12px] text-mute">{new Date(s.at).toLocaleString()} · {s.project.rules.length} rules · {s.project.nat.length} NAT</div>
                </div>
                <button className="btn" onClick={() => setDiffId(s.id)}>Diff with current</button>
                <button className="btn" onClick={() => { restoreSnapshot(s.id); toast(`Restored "${s.name}"`); }}><RotateCcw size={14} /> Restore</button>
                <button className="btn btn-ghost btn-icon" aria-label="Delete snapshot" onClick={() => deleteSnapshot(s.id)}><Trash2 size={14} /></button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Modal open={!!snap && !!diff} onClose={() => setDiffId(null)} wide title={snap ? `"${snap.name}" → current (${target.label})` : ''}>
        {diff && (
          <>
            <p className="mb-2 text-[12.5px] text-mute">
              <span style={{ color: 'var(--ok)' }}>+{diffStats(diff.lines).added}</span> / <span style={{ color: 'var(--bad)' }}>−{diffStats(diff.lines).removed}</span> lines in the generated output
            </p>
            <DiffView lines={diff.lines} lang={diff.lang} className="max-h-[56vh]" />
          </>
        )}
      </Modal>
    </div>
  );
}

const SAMPLE = `# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -s 203.0.113.0/24 -m comment --comment "SSH from office" -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -p udp --dport 51820 -j ACCEPT
COMMIT
`;

export function TransferPage() {
  const project = useStore((s) => s.project);
  const selection = useStore((s) => s.selection);
  const { replaceProject, toast, setPage } = useStore.getState();
  const [text, setText] = useState('');
  const [report, setReport] = useState<ImportReport | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const loadJson = async (file: File) => {
    try {
      replaceProject(coerceProject(JSON.parse(await file.text())));
      toast(`Opened ${file.name}`);
      setPage('rules');
    } catch (e) {
      toast(`Could not open file: ${(e as Error).message}`, 'bad');
    }
  };

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Import and export" sub="Bring an existing ruleset in, or take this project elsewhere. Nothing leaves your browser." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <Panel title="Import from iptables-save" hint="Paste the output of iptables-save (and ip6tables-save) to migrate it to any target" actions={<button className="btn btn-ghost" onClick={() => setText(SAMPLE)}>Paste sample</button>}>
          <textarea className="field h-64 resize-y font-mono text-[12px] leading-relaxed" spellCheck={false} placeholder="# iptables-save output…" value={text} onChange={(e) => { setText(e.target.value); setReport(null); }} />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button className="btn" disabled={!text.trim()} onClick={() => setReport(importIptablesSave(text))}>Preview import</button>
            <button className="btn btn-primary" disabled={!report || report.imported === 0} onClick={() => { replaceProject(report!.project); toast(`Imported ${report!.imported} rules`); setPage('rules'); }}><Upload size={15} /> Replace project with import</button>
          </div>
          {report && (
            <div className="mt-3 space-y-2 text-[12.5px]">
              <div className="flex flex-wrap gap-1.5">
                <span className="badge badge-ok">{report.project.rules.length} rules</span>
                <span className="badge badge-ok">{report.project.nat.length} NAT</span>
                <span className={`badge ${report.skipped.length > 0 ? 'badge-warn' : 'badge-mute'}`}>{report.skipped.length} skipped</span>
                <span className="badge badge-mute">inbound policy {report.project.policies.in}</span>
              </div>
              {report.skipped.length > 0 && (
                <div className="code max-h-44 overflow-auto p-3">
                  {report.skipped.map((s, i) => (
                    <div key={i} className="mb-1.5"><span style={{ color: 'var(--warn)' }}>{s.reason}</span><br /><span className="text-mute">{s.line}</span></div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Panel>
        <div className="flex flex-col gap-4">
          <Panel title="Project file" hint="A JSON file with every rule, object and option">
            <div className="flex flex-wrap gap-2">
              <button className="btn btn-primary" onClick={() => download(`${project.name.replace(/[^\w-]+/g, '-').toLowerCase() || 'emberwall'}.emberwall.json`, JSON.stringify(project, null, 2), 'application/json')}><FileDown size={15} /> Export JSON</button>
              <button className="btn" onClick={() => fileRef.current?.click()}><FileUp size={15} /> Open JSON…</button>
              <input ref={fileRef} type="file" accept=".json,application/json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) void loadJson(f); e.target.value = ''; }} />
            </div>
          </Panel>
          <Panel title="Share link" hint="The whole project is packed into the link itself">
            <p className="mb-3 text-[12.5px] leading-snug text-mute">The data sits after the # in the URL, which browsers never send to a server. Anyone with the link sees the ruleset, so treat it like the ruleset itself.</p>
            <button className="btn" onClick={async () => toast((await copyText(shareUrl(project, selection))) ? 'Share link copied' : 'Copy failed')}><Link2 size={15} /> Copy share link</button>
          </Panel>
        </div>
      </div>
    </div>
  );
}
