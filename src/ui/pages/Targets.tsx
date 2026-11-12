import { Copy, Download } from 'lucide-react';
import { useMemo, useState } from 'react';
import { fileText } from '../../core/compile';
import { EXTRA_TARGETS } from '../../core/compile/extra';
import { copyText, download, useEffectiveProject, useStore } from '../../store/useStore';
import { CodeView } from '../components/CodeView';
import { DiagnosticList } from '../components/OutputPanel';
import { PageHeader, Panel } from '../components/ui';

/** Backends beyond the four Linux tools. They share the ruleset but not the version matrix. */
export function TargetsPage() {
  const project = useEffectiveProject();
  const selected = useStore((s) => s.selectedRuleId);
  const { selectRule, toast } = useStore.getState();
  const [id, setId] = useState(EXTRA_TARGETS[0].id);
  const [tab, setTab] = useState(0);
  const target = EXTRA_TARGETS.find((t) => t.id === id) ?? EXTRA_TARGETS[0];
  const result = useMemo(() => target.compile(project), [target, project]);
  const file = result.files[Math.min(tab, result.files.length - 1)];
  const unsupported = result.diagnostics.filter((d) => d.kind === 'unsupported').length;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="More targets" sub="The same ruleset for BSD, Windows, cloud security groups and Kubernetes. These platforms filter differently from Linux, so read the notes: anything that does not carry over is listed, never dropped silently." />
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:grid-cols-[260px_minmax(0,1.6fr)_minmax(0,1fr)] xl:overflow-visible">
        <div className="glass p-2 xl:min-h-0 xl:overflow-y-auto">
          {EXTRA_TARGETS.map((t) => (
            <button key={t.id} onClick={() => { setId(t.id); setTab(0); }} aria-pressed={t.id === id} className="nav-item !items-start !py-2 text-left" aria-current={t.id === id ? 'page' : undefined}>
              <span className="min-w-0">
                <span className="block text-[13px] font-semibold text-ink">{t.label}</span>
                <span className="block text-[11.5px] leading-snug text-mute">{t.description}</span>
              </span>
            </button>
          ))}
        </div>
        <section className="glass flex h-[620px] min-h-0 flex-col xl:h-auto">
          <header className="flex flex-none flex-wrap items-center justify-between gap-2 px-4 pb-2 pt-3.5">
            <div className="min-w-0">
              <h2 className="text-[13px] font-semibold tracking-wide">{target.label}</h2>
              <p className="mt-0.5 truncate font-mono text-[12px] text-mute">{file.path}</p>
            </div>
            <div className="flex items-center gap-1.5">
              <button className="btn" onClick={async () => toast((await copyText(fileText(file))) ? `Copied ${file.name}` : 'Copy failed')}><Copy size={14} /> Copy</button>
              <button className="btn" onClick={() => download(file.name, fileText(file))}><Download size={14} /> Download</button>
            </div>
          </header>
          {result.files.length > 1 && (
            <div className="flex flex-none gap-1 overflow-x-auto px-4 pb-2">
              {result.files.map((f, i) => (
                <button key={f.name} onClick={() => setTab(i)} aria-pressed={i === tab} title={f.description} className={`chip whitespace-nowrap !py-1 ${i === tab ? '!border-ember-400/70 text-ink' : 'text-mute hover:text-ink'}`}>{f.name}</button>
              ))}
            </div>
          )}
          <div className="min-h-0 flex-1 px-4 pb-4">
            <CodeView lines={file.lines} lang={file.lang} activeRuleId={selected} onPick={selectRule} className="h-full" />
          </div>
        </section>
        <Panel title="What carries over" hint={unsupported === 0 ? 'Everything in this ruleset maps onto this platform' : `${unsupported} thing${unsupported === 1 ? '' : 's'} this platform cannot express`} className="xl:min-h-0 xl:overflow-hidden">
          <div className="pr-1 xl:max-h-full xl:overflow-y-auto"><DiagnosticList items={result.diagnostics} onPick={selectRule} /></div>
        </Panel>
      </div>
    </div>
  );
}
