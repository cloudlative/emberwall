import { Download, Link2 } from 'lucide-react';
import { useMemo, useState } from 'react';
import { compile, fileText } from '../../core/compile';
import { iacFiles } from '../../core/compile/iac';
import { diffLines, diffStats } from '../../core/diff';
import { DISTROS, resolveTarget, TOOL_LABEL, VERSIONS, type TargetSelection, type Tool } from '../../core/targets';
import { copyText, download, shareUrl, useCompiled, useStore } from '../../store/useStore';
import { CodeView, DiffView } from '../components/CodeView';
import { DiagnosticList, OutputPanel } from '../components/OutputPanel';
import { Modal, PageHeader, Panel, Segmented } from '../components/ui';
import { TargetPicker } from '../components/TargetPicker';

export function BuildPage() {
  const result = useCompiled();
  const project = useStore((s) => s.project);
  const selection = useStore((s) => s.selection);
  const toast = useStore((s) => s.toast);
  const automation = useMemo(() => iacFiles(result), [result]);
  const [preview, setPreview] = useState<number | null>(null);
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Build" sub="Pick the system you are deploying to. The output changes with the tool and its version.">
        <button className="btn" onClick={async () => toast((await copyText(shareUrl(project, selection))) ? 'Share link copied' : 'Copy failed')}><Link2 size={15} /> Share link</button>
        <button className="btn btn-primary" onClick={() => result.files.forEach((f, i) => setTimeout(() => download(f.name, fileText(f)), i * 250))}><Download size={15} /> Download all files</button>
      </PageHeader>
      <div className="glass mb-4 flex-none px-4 py-3"><TargetPicker /></div>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:overflow-visible xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <OutputPanel className="h-[620px] xl:h-auto xl:min-h-0" />
        <div className="flex flex-col gap-4 pr-1 xl:min-h-0 xl:overflow-y-auto">
          <Panel title="Files in this build">
            <ul className="space-y-2">
              {result.files.map((f) => (
                <li key={f.name} className="tile flex items-center justify-between gap-3 px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px]">{f.name}</div>
                    <div className="truncate text-[12px] text-mute">{f.description} · <span className="font-mono">{f.path}</span></div>
                  </div>
                  <button className="btn btn-icon" aria-label={`Download ${f.name}`} onClick={() => download(f.name, fileText(f))}><Download size={14} /></button>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Automation" hint="The same build wrapped for your tooling">
            <ul className="space-y-2">
              {automation.map((f, i) => (
                <li key={f.name} className="tile flex items-center justify-between gap-3 px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px]">{f.name}</div>
                    <div className="truncate text-[12px] text-mute">{f.description}</div>
                  </div>
                  <div className="flex flex-none gap-1.5">
                    <button className="btn" onClick={() => setPreview(i)}>View</button>
                    <button className="btn btn-icon" aria-label={`Download ${f.name}`} onClick={() => download(f.name, fileText(f))}><Download size={14} /></button>
                  </div>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[12px] leading-snug text-mute">These load the ruleset without the confirm-or-rollback step, so try them on one host first.</p>
          </Panel>
          <Panel title="How to apply safely">
            <ol className="list-decimal space-y-1.5 pl-4 text-[12.5px] leading-relaxed text-ink/90">
              <li>Copy every file to the server, into one directory.</li>
              <li>Run <code className="chip">sudo sh emberwall-apply.sh</code>. It backs up the running rules and checks the new ones first.</li>
              <li>Open a second session to confirm you can still get in, then type <code className="chip">yes</code>.</li>
              <li>No answer within 60 seconds rolls everything back, even if your session was cut.</li>
            </ol>
          </Panel>
        </div>
      </div>
      <Modal open={preview !== null} onClose={() => setPreview(null)} wide title={preview !== null ? automation[preview].name : ''}>
        {preview !== null && <CodeView lines={automation[preview].lines} lang={automation[preview].lang} className="max-h-[62vh]" />}
      </Modal>
    </div>
  );
}

const pickerOptions = (): { value: string; label: string }[] => [
  ...DISTROS.flatMap((d) => (Object.keys(d.tools) as Tool[]).map((t) => ({ value: `${d.id}|${t}|`, label: `${d.name} — ${TOOL_LABEL[t]} ${d.tools[t]}` }))),
  ...(Object.keys(VERSIONS) as Tool[]).flatMap((t) => VERSIONS[t].map((v) => ({ value: `custom|${t}|${v}`, label: `${TOOL_LABEL[t]} ${v}` }))),
];
const parseSel = (v: string): TargetSelection => {
  const [distro, tool, version] = v.split('|');
  return { distro, tool: tool as Tool, version };
};

export function ComparePage() {
  const project = useStore((s) => s.project);
  const [a, setA] = useState('custom|nftables|0.9.0');
  const [b, setB] = useState('custom|nftables|1.1.5');
  const [mode, setMode] = useState<'side' | 'diff'>('diff');
  const options = useMemo(pickerOptions, []);
  const ra = useMemo(() => compile(project, resolveTarget(parseSel(a))), [project, a]);
  const rb = useMemo(() => compile(project, resolveTarget(parseSel(b))), [project, b]);
  const diff = useMemo(() => diffLines(fileText(ra.files[0]).trimEnd(), fileText(rb.files[0]).trimEnd()), [ra, rb]);
  const stats = diffStats(diff);
  const select = (value: string, onChange: (v: string) => void, label: string) => (
    <select aria-label={label} className="field" value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Compare targets" sub="The same ruleset compiled for two systems. Use it to plan an upgrade or a migration between tools.">
        <Segmented value={mode} onChange={setMode} options={[{ value: 'diff', label: 'Diff' }, { value: 'side', label: 'Side by side' }]} />
      </PageHeader>
      <div className="glass mb-4 grid flex-none items-center gap-3 px-4 py-3 md:grid-cols-[1fr_auto_1fr]">
        {select(a, setA, 'Left target')}
        <span className="text-center text-[12px] text-mute"><span style={{ color: 'var(--ok)' }}>+{stats.added}</span> / <span style={{ color: 'var(--bad)' }}>−{stats.removed}</span> lines</span>
        {select(b, setB, 'Right target')}
      </div>
      {mode === 'diff' ? (
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:overflow-visible xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <Panel title={`${ra.files[0].name} → ${rb.files[0].name}`} hint="Red lines exist only on the left target, green only on the right" className="h-[560px] xl:h-auto xl:min-h-0">
            <DiffView lines={diff} lang={rb.files[0].lang} className="h-full" />
          </Panel>
          <div className="flex flex-col gap-4 pr-1 xl:min-h-0 xl:overflow-y-auto">
            <Panel title={`Notes: ${ra.target.label}`}><DiagnosticList items={ra.diagnostics} /></Panel>
            <Panel title={`Notes: ${rb.target.label}`}><DiagnosticList items={rb.diagnostics} /></Panel>
          </div>
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto lg:grid-cols-2 lg:overflow-visible">
          {[ra, rb].map((r, i) => (
            <Panel key={i} title={r.target.label} hint={r.files[0].name} className="h-[560px] xl:h-auto xl:min-h-0">
              <CodeView lines={r.files[0].lines} lang={r.files[0].lang} className="h-full" />
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
