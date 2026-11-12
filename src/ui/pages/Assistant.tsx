import { AlertTriangle, KeyRound, Loader2, Plus, Sparkles, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { AI_MODEL, ask, draftRules, projectContext, type Draft } from '../../core/ai';
import { DIRECTION_LABEL } from '../../core/model';
import { useStore } from '../../store/useStore';
import { ruleSummary } from './Rules';
import { ActionBadge, Field, Modal, PageHeader, Panel, Segmented } from '../components/ui';

const KEY_SLOT = 'emberwall-ai-key';
const readKey = () => {
  try {
    return sessionStorage.getItem(KEY_SLOT) ?? localStorage.getItem(KEY_SLOT) ?? '';
  } catch {
    return '';
  }
};

export function AssistantPage() {
  const project = useStore((s) => s.project);
  const { update, toast, setPage } = useStore.getState();
  const [key, setKey] = useState(readKey);
  const [remember, setRemember] = useState(() => { try { return !!localStorage.getItem(KEY_SLOT); } catch { return false; } });
  const [mode, setMode] = useState<'draft' | 'ask'>('draft');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [draft, setDraft] = useState<Draft | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [answer, setAnswer] = useState('');
  const [showData, setShowData] = useState(false);

  const saveKey = (value: string, keep: boolean) => {
    setKey(value);
    setRemember(keep);
    try {
      sessionStorage.removeItem(KEY_SLOT);
      localStorage.removeItem(KEY_SLOT);
      if (value) (keep ? localStorage : sessionStorage).setItem(KEY_SLOT, value);
    } catch { /* storage unavailable: the key lives in this page only */ }
  };

  const run = async () => {
    setBusy(true);
    setError('');
    try {
      if (mode === 'draft') {
        setDraft(null);
        const d = await draftRules(key.trim(), text.trim(), project);
        setDraft(d);
        setPicked(new Set(d.rules.filter((r) => r.problems.length === 0).map((r) => r.rule.id)));
      } else {
        setAnswer('');
        await ask(key.trim(), text.trim(), project, setAnswer);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const addPicked = () => {
    if (!draft) return;
    const rules = draft.rules.filter((r) => picked.has(r.rule.id)).map((r) => r.rule);
    update((p) => ({ ...p, rules: [...p.rules, ...rules] }));
    toast(`Added ${rules.length} rule${rules.length === 1 ? '' : 's'} (undo with Ctrl+Z)`);
    setDraft(null);
    setPage('rules');
  };

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Assistant" sub="Optional. Describe a policy in plain English and review the rules it proposes, or ask a question about the current ruleset." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
        <div className="flex flex-col gap-4">
          <Panel title="Your API key" hint="The assistant is off until you add one">
            <div className="mb-3 flex gap-2 rounded-xl px-3 py-2.5 text-[12.5px] leading-snug" style={{ background: 'color-mix(in srgb, var(--warn) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--warn) 30%, transparent)' }}>
              <AlertTriangle size={15} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />
              <span>Using the assistant sends your request and this project's rules, zones, groups and NAT settings from your browser to the Anthropic API ({AI_MODEL}), billed to your key. Everything else in Emberwall stays local. <button className="underline" onClick={() => setShowData(true)}>See exactly what is sent</button>.</span>
            </div>
            <Field label="Anthropic API key">
              <div className="flex gap-2">
                <input type="password" autoComplete="off" className="field font-mono" placeholder="sk-ant-…" value={key} onChange={(e) => saveKey(e.target.value, remember)} />
                {key && <button className="btn btn-icon" aria-label="Forget key" onClick={() => saveKey('', false)}><Trash2 size={14} /></button>}
              </div>
            </Field>
            <label className="mt-2 flex items-center gap-2 text-[12.5px] text-mute">
              <input type="checkbox" checked={remember} onChange={(e) => saveKey(key, e.target.checked)} /> Remember on this device (otherwise the key is forgotten when the tab closes)
            </label>
          </Panel>
          <Panel title="Request">
            <div className="mb-3"><Segmented value={mode} onChange={setMode} options={[{ value: 'draft', label: 'Propose rules' }, { value: 'ask', label: 'Ask about this ruleset' }]} /></div>
            <textarea className="field h-36 resize-y" placeholder={mode === 'draft' ? 'e.g. Allow the monitoring server 10.30.0.5 to scrape node exporter, and let the office network reach the admin panel on 8443 during work hours only.' : 'e.g. Can anything on the internet reach the database? Which rule would a packet to port 8443 hit?'} value={text} onChange={(e) => setText(e.target.value)} />
            <div className="mt-3 flex items-center gap-2">
              <button className="btn btn-primary" disabled={busy || !key.trim() || !text.trim()} onClick={run}>
                {busy ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />} {busy ? 'Working…' : mode === 'draft' ? 'Propose rules' : 'Ask'}
              </button>
              {!key.trim() && <span className="flex items-center gap-1.5 text-[12px] text-mute"><KeyRound size={13} /> Add a key first</span>}
            </div>
            {error && <p className="mt-3 text-[12.5px]" style={{ color: 'var(--bad)' }}>{error}</p>}
          </Panel>
        </div>

        <Panel title={mode === 'draft' ? 'Proposed rules' : 'Answer'} hint={mode === 'draft' ? 'Nothing is added until you choose' : 'Check it against the simulator before relying on it'}>
          {mode === 'ask' ? (
            answer ? <div className="whitespace-pre-wrap text-[13px] leading-relaxed">{answer}</div> : <p className="py-10 text-center text-[13px] text-mute">{busy ? 'Thinking…' : 'The answer appears here.'}</p>
          ) : !draft ? (
            <p className="py-10 text-center text-[13px] text-mute">{busy ? 'Drafting rules…' : 'Proposed rules appear here for review.'}</p>
          ) : (
            <>
              {draft.summary && <p className="mb-3 text-[13px] leading-relaxed">{draft.summary}</p>}
              {draft.warnings.length > 0 && (
                <ul className="mb-3 space-y-1">{draft.warnings.map((w, i) => <li key={i} className="flex gap-2 text-[12.5px]"><AlertTriangle size={14} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />{w}</li>)}</ul>
              )}
              {draft.rules.length === 0 ? <p className="py-6 text-center text-[13px] text-mute">No rules were proposed.</p> : (
                <ul className="space-y-1.5">
                  {draft.rules.map(({ rule, problems }) => {
                    const s = ruleSummary(rule, project);
                    return (
                      <li key={rule.id} className="tile flex items-start gap-3 px-3 py-2">
                        <input type="checkbox" className="mt-1" aria-label={`Include ${rule.name}`} disabled={problems.length > 0} checked={picked.has(rule.id)} onChange={(e) => setPicked((prev) => { const n = new Set(prev); if (e.target.checked) n.add(rule.id); else n.delete(rule.id); return n; })} />
                        <div className="min-w-0 flex-1">
                          <div className="text-[13px] font-medium">{rule.name}</div>
                          <div className="mt-0.5 flex flex-wrap items-center gap-1 text-[11.5px] text-mute">
                            <span className="chip">{DIRECTION_LABEL[rule.direction]}</span><span className="chip">{rule.proto}</span>
                            {s.ports.map((p) => <span key={p} className="chip">{p}</span>)}
                            <span>{s.src} → {s.dst}</span>
                            {rule.rateLimit && <span className="chip">{rule.rateLimit.rate}/min per client</span>}
                          </div>
                          {problems.map((m) => <div key={m} className="mt-1 text-[12px]" style={{ color: 'var(--bad)' }}>Not usable: {m}</div>)}
                        </div>
                        <ActionBadge action={rule.action} />
                      </li>
                    );
                  })}
                </ul>
              )}
              <div className="mt-3 flex gap-2">
                <button className="btn btn-primary" disabled={picked.size === 0} onClick={addPicked}><Plus size={15} /> Add {picked.size} selected</button>
                <button className="btn" onClick={() => setDraft(null)}>Discard</button>
              </div>
              <p className="mt-2 text-[12px] text-mute">Proposals are checked by the same validation as hand-written rules. Review them, then run the audit and simulator as usual.</p>
            </>
          )}
        </Panel>
      </div>
      <Modal open={showData} onClose={() => setShowData(false)} wide title="Data sent with each request">
        <p className="mb-2 text-[12.5px] text-mute">This JSON, your typed request and a fixed instruction text. Snapshots, policy tests, hosts and the API key itself are not part of it.</p>
        <pre className="code max-h-[56vh] overflow-auto p-3 text-[11.5px]">{projectContext(project)}</pre>
      </Modal>
    </div>
  );
}
