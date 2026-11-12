import { ArrowRight, Check } from 'lucide-react';
import { useState } from 'react';
import { emptyProject, newRule } from '../../core/model';
import { parseCidr } from '../../core/net';
import { RECOMMENDED_HARDENING } from '../../core/sysctl';
import { DISTROS } from '../../core/targets';
import { TEMPLATES } from '../../core/templates';
import { useStore } from '../../store/useStore';
import { Field, Modal } from './ui';

const SEEN = 'emberwall-welcome-seen';
export const wizardSeen = () => {
  try {
    return !!localStorage.getItem(SEEN);
  } catch {
    return true;
  }
};

/** First-run setup: three questions, then a ready ruleset. Skippable, re-openable from the command palette. */
export function Wizard({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [step, setStep] = useState(0);
  const [role, setRole] = useState('web');
  const [distro, setDistro] = useState('ubuntu-24.04');
  const [admin, setAdmin] = useState('');
  const [harden, setHarden] = useState(true);
  const adminOk = !admin.trim() || admin.split(/[\s,]+/).filter(Boolean).every((a) => !!parseCidr(a));
  const done = () => {
    try {
      localStorage.setItem(SEEN, '1');
    } catch { /* ignore */ }
    onClose();
  };
  const finish = () => {
    const st = useStore.getState();
    const tpl = TEMPLATES.find((t) => t.id === role);
    const p = tpl ? tpl.build() : emptyProject('My firewall');
    const sources = admin.split(/[\s,]+/).filter(Boolean);
    if (sources.length > 0) {
      const group = p.addressGroups.find((g) => g.id === 'admins');
      if (group) group.members = sources;
      else {
        p.addressGroups.push({ id: 'admins', name: 'Admin networks', members: sources });
        const ssh = p.rules.find((r) => r.direction === 'in' && r.ports.includes('22'));
        if (ssh) {
          ssh.src = ['@admins'];
          ssh.rateLimit = undefined;
        } else p.rules.unshift(newRule({ name: 'SSH from admins', proto: 'tcp', ports: ['22'], src: ['@admins'] }));
      }
    }
    if (harden) p.hardening = [...RECOMMENDED_HARDENING];
    const d = DISTROS.find((x) => x.id === distro)!;
    st.replaceProject(p);
    st.setActiveHost(null);
    st.setSelection({ distro: d.id, tool: d.defaultTool, version: '' });
    st.setPage('rules');
    st.toast('Your starting ruleset is ready. Review it, then open Build.');
    done();
  };
  if (!open) return null;
  return (
    <Modal open onClose={done} wide title="Welcome to Emberwall"
      footer={<>
        <button className="btn btn-ghost" onClick={done}>Skip, I'll explore</button>
        {step > 0 && <button className="btn" onClick={() => setStep(step - 1)}>Back</button>}
        {step < 2 ? <button className="btn btn-primary" onClick={() => setStep(step + 1)}>Next <ArrowRight size={14} /></button> : <button className="btn btn-primary" disabled={!adminOk} onClick={finish}><Check size={14} /> Create ruleset</button>}
      </>}>
      <div className="mb-4 flex gap-1.5">{[0, 1, 2].map((i) => <span key={i} className="h-1 flex-1 rounded-full" style={{ background: i <= step ? '#ff6b35' : 'var(--line-strong)' }} />)}</div>
      {step === 0 && (
        <>
          <p className="mb-3 text-[13px] text-mute">Three questions and you have a reviewed starting point. What is this machine?</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {[...TEMPLATES, { id: 'blank', name: 'Something else', summary: 'Start from an empty default-deny ruleset.' }].map((t) => (
              <button key={t.id} onClick={() => setRole(t.id)} aria-pressed={role === t.id} className="tile px-3 py-2.5 text-left" style={role === t.id ? { borderColor: '#ff8f5c', background: 'rgba(255,107,53,0.1)' } : undefined}>
                <div className="text-[13.5px] font-semibold">{t.name}</div>
                <div className="text-[12px] leading-snug text-mute">{t.summary}</div>
              </button>
            ))}
          </div>
        </>
      )}
      {step === 1 && (
        <>
          <p className="mb-3 text-[13px] text-mute">Which system does it run? Emberwall picks that distribution's default firewall and exact version; you can change both at any time.</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {DISTROS.map((d) => (
              <button key={d.id} onClick={() => setDistro(d.id)} aria-pressed={distro === d.id} className="tile flex items-center justify-between px-3 py-2 text-left" style={distro === d.id ? { borderColor: '#ff8f5c', background: 'rgba(255,107,53,0.1)' } : undefined}>
                <span className="text-[13px] font-medium">{d.name}</span>
                <span className="font-mono text-[11.5px] text-mute">{d.defaultTool} {d.tools[d.defaultTool]}</span>
              </button>
            ))}
          </div>
        </>
      )}
      {step === 2 && (
        <>
          <Field label="Where do you administer it from? (optional)" hint="Addresses or networks allowed to use SSH. Leave empty to keep the template's choice.">
            <input className="field font-mono" placeholder="203.0.113.0/24, 2001:db8:10::/48" value={admin} onChange={(e) => setAdmin(e.target.value)} />
          </Field>
          {!adminOk && <p className="mt-1 text-[12px]" style={{ color: 'var(--bad)' }}>One of these is not a valid address or CIDR.</p>}
          <label className="mt-4 flex items-start gap-2.5 text-[13px]">
            <input type="checkbox" className="mt-1" checked={harden} onChange={(e) => setHarden(e.target.checked)} />
            <span>Enable recommended kernel hardening<span className="block text-[12px] text-mute">Reverse-path filter, SYN cookies, no redirects or source routing. Written to a sysctl file in the build.</span></span>
          </label>
          <p className="mt-4 text-[12.5px] text-mute">This replaces the ruleset currently open (undo brings it back).</p>
        </>
      )}
    </Modal>
  );
}
