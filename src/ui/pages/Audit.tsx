import { ArrowRight, ShieldCheck, Wand2 } from 'lucide-react';
import { grade, lint, score, SEVERITY_ORDER, SEVERITY_WEIGHT } from '../../core/lint';
import type { Project } from '../../core/model';
import { useFindings, useStore } from '../../store/useStore';
import { Empty, PageHeader, Panel, SeverityBadge, Stat } from '../components/ui';

const fixableOf = (p: Project) => lint(p).filter((f) => f.fix);

export function AuditPage() {
  const findings = useFindings();
  const update = useStore((s) => s.update);
  const toast = useStore((s) => s.toast);
  const s = score(findings);
  const fixable = findings.filter((f) => f.fix);
  const fixAll = () => {
    update((p) => {
      // Re-lint after every fix: one fix can remove or change the others.
      let cur = p;
      for (let i = 0; i < 40; i += 1) {
        const next = fixableOf(cur)[0];
        if (!next) break;
        cur = next.fix!(cur);
      }
      return cur;
    });
    toast('Applied every available fix (undo with Ctrl+Z)');
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Audit" sub="Checks for exposure, broken connectivity, lock-out risk and rules that can never match.">
        <button className="btn btn-primary" disabled={fixable.length === 0} onClick={fixAll}><Wand2 size={15} /> Fix all ({fixable.length})</button>
      </PageHeader>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label="Posture score" value={`${s}`} sub={`Grade ${grade(s)}`} tone={s >= 75 ? 'ok' : s >= 50 ? 'warn' : 'bad'} />
        {SEVERITY_ORDER.filter((x) => x !== 'info').map((sev) => {
          const n = findings.filter((f) => f.severity === sev).length;
          return <Stat key={sev} label={sev} value={n} sub={`−${SEVERITY_WEIGHT[sev]} points each`} tone={n === 0 ? 'ok' : sev === 'low' ? 'warn' : 'bad'} />;
        })}
      </div>
      <Panel title="Findings" hint={`${findings.length} item${findings.length === 1 ? '' : 's'}, most severe first`}>
        {findings.length === 0 ? (
          <Empty icon={<ShieldCheck size={22} />} title="Nothing to report">This ruleset passes every check.</Empty>
        ) : (
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={f.id} className="tile flex flex-wrap items-start gap-3 px-3.5 py-3">
                <div className="w-[76px] flex-none pt-0.5"><SeverityBadge severity={f.severity} /></div>
                <div className="min-w-[220px] flex-1">
                  <div className="text-[13.5px] font-semibold">{f.title}</div>
                  <div className="mt-0.5 text-[12.5px] leading-snug text-mute">{f.detail}</div>
                </div>
                <div className="flex flex-none items-center gap-1.5">
                  {f.ruleId && (
                    <button className="btn" onClick={() => {
                      const st = useStore.getState();
                      st.selectRule(f.ruleId!);
                      st.setPage(st.project.nat.some((n) => n.id === f.ruleId) ? 'nat' : 'rules');
                    }}>Show <ArrowRight size={13} /></button>
                  )}
                  {f.fix && <button className="btn btn-primary" onClick={() => { update(f.fix!); toast(`${f.fixLabel}: done`); }}><Wand2 size={13} /> {f.fixLabel}</button>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

