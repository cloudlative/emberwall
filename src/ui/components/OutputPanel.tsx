import { AlertTriangle, Check, Copy, Download, Info, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fileText, type Diagnostic } from '../../core/compile';
import { copyText, download, useCompiled, useStore } from '../../store/useStore';
import { CodeView } from './CodeView';

export function DiagnosticList({ items, onPick }: { items: Diagnostic[]; onPick?: (ruleId: string) => void }) {
  if (items.length === 0) {
    return (
      <div className="flex items-center gap-2 text-[12.5px] text-mute">
        <Check size={14} style={{ color: 'var(--ok)' }} /> Every rule maps cleanly onto this target.
      </div>
    );
  }
  return (
    <ul className="space-y-1.5">
      {items.map((d, i) => {
        const Icon = d.level === 'error' ? XCircle : d.level === 'warn' ? AlertTriangle : Info;
        const color = d.level === 'error' ? 'var(--bad)' : d.level === 'warn' ? 'var(--warn)' : 'var(--info)';
        return (
          <li key={i} className={`flex gap-2 text-[12.5px] leading-snug ${d.ruleId && onPick ? 'cursor-pointer hover:text-ink' : ''}`} onClick={d.ruleId && onPick ? () => onPick(d.ruleId!) : undefined}>
            <Icon size={14} className="mt-0.5 flex-none" style={{ color }} />
            <span>
              {d.kind === 'fallback' && <span className="badge badge-warn mr-1.5">version fallback</span>}
              {d.kind === 'unsupported' && <span className="badge badge-warn mr-1.5">not expressible</span>}
              {d.kind === 'invalid' && <span className="badge badge-bad mr-1.5">invalid</span>}
              <span className="text-ink/90">{d.message}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** Compiled output for the current target: file tabs, linked lines, diagnostics. */
export function OutputPanel({ className = '' }: { className?: string }) {
  const result = useCompiled();
  const selected = useStore((s) => s.selectedRuleId);
  const selectRule = useStore((s) => s.selectRule);
  const toast = useStore((s) => s.toast);
  const [tab, setTab] = useState(0);
  useEffect(() => setTab(0), [result.target.tool]);
  const file = result.files[Math.min(tab, result.files.length - 1)];
  const warn = result.diagnostics.filter((d) => d.level !== 'info').length;

  return (
    <section className={`glass flex min-h-0 flex-col ${className}`}>
      <header className="flex flex-none flex-wrap items-center justify-between gap-2 px-4 pb-2 pt-3.5">
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold tracking-wide">Generated output</h2>
          <p className="mt-0.5 truncate text-[12px] text-mute">{result.target.label}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button className="btn" onClick={async () => toast((await copyText(fileText(file))) ? `Copied ${file.name}` : 'Copy failed', 'ok')}>
            <Copy size={14} /> Copy
          </button>
          <button className="btn" onClick={() => download(file.name, fileText(file))}>
            <Download size={14} /> Download
          </button>
        </div>
      </header>
      <div className="flex flex-none gap-1 overflow-x-auto px-4 pb-2">
        {result.files.map((f, i) => (
          <button key={f.name} onClick={() => setTab(i)} aria-pressed={i === tab} title={f.description} className={`chip whitespace-nowrap !py-1 transition ${i === tab ? '!border-ember-400/70 text-ink' : 'text-mute hover:text-ink'}`}>
            {f.name}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 px-4">
        <CodeView lines={file.lines} lang={file.lang} activeRuleId={selected} onPick={selectRule} className="h-full" />
      </div>
      <div className="flex-none px-4 pb-4 pt-3">
        <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-mute">
          Compiler notes
          {warn > 0 && <span className="badge badge-warn">{warn}</span>}
        </div>
        <div className="max-h-36 overflow-y-auto pr-1">
          <DiagnosticList items={result.diagnostics} onPick={selectRule} />
        </div>
      </div>
    </section>
  );
}
