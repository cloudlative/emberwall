import { X } from 'lucide-react';
import { useEffect, useState, type KeyboardEvent, type ReactNode } from 'react';
import type { Action } from '../../core/model';
import type { Severity } from '../../core/lint';

export function Panel({ title, hint, actions, children, className = '', pad = true }: { title?: ReactNode; hint?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`glass flex flex-col ${className}`}>
      {(title || actions) && (
        <header className="flex flex-none items-center justify-between gap-3 px-4 pb-2 pt-3.5">
          <div className="min-w-0">
            <h2 className="truncate text-[13px] font-semibold tracking-wide">{title}</h2>
            {hint && <p className="mt-0.5 truncate text-[12px] text-mute">{hint}</p>}
          </div>
          {actions && <div className="flex flex-none items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={`min-h-0 flex-1 ${pad ? 'px-4 pb-4' : ''}`}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, sub, children }: { title: string; sub: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
        <p className="mt-0.5 text-[13px] text-mute">{sub}</p>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  );
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} className="switch" onClick={() => onChange(!checked)} />;
}

export function Field({ label, children, hint, className = '' }: { label: string; children: ReactNode; hint?: string; className?: string }) {
  return (
    <label className={`block ${className}`}>
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[11.5px] text-mute">{hint}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange, size = 'md' }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; size?: 'sm' | 'md' }) {
  return (
    <div className="inline-flex rounded-xl p-0.5" style={{ background: 'var(--field)', border: '1px solid var(--line)' }}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={`rounded-[10px] font-medium transition ${size === 'sm' ? 'px-2 py-0.5 text-[12px]' : 'px-3 py-1 text-[13px]'} ${value === o.value ? 'text-ink shadow' : 'text-mute hover:text-ink'}`}
          style={value === o.value ? { background: 'var(--glass-hover)', border: '1px solid var(--line-strong)' } : { border: '1px solid transparent' }}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Free-text list input: Enter, comma or space commits an entry. */
export function TagInput({ value, onChange, placeholder, suggestions = [], render, validate }: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  suggestions?: { value: string; label: string }[];
  render?: (v: string) => string;
  validate?: (v: string) => boolean;
}) {
  const [draft, setDraft] = useState('');
  const commit = (text: string) => {
    const items = text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
    if (items.length === 0) return;
    onChange([...new Set([...value, ...items])]);
    setDraft('');
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
      if (draft.trim()) {
        e.preventDefault();
        commit(draft);
      }
    } else if (e.key === 'Backspace' && !draft && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };
  const open = suggestions.filter((s) => !value.includes(s.value));
  return (
    <div>
      <div className="field flex flex-wrap items-center gap-1 !py-1">
        {value.map((v) => {
          const bad = !v.startsWith('@') && validate && !validate(v);
          return (
            <span key={v} className="chip" style={bad ? { borderColor: 'var(--bad)', color: 'var(--bad)' } : undefined} title={bad ? 'Not valid' : undefined}>
              {render ? render(v) : v}
              <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(value.filter((x) => x !== v))} className="opacity-60 hover:opacity-100">
                <X size={11} />
              </button>
            </span>
          );
        })}
        <input
          className="min-w-[90px] flex-1 bg-transparent py-0.5 font-mono text-[12px] outline-none placeholder:font-sans placeholder:text-mute/70"
          value={draft}
          placeholder={value.length === 0 ? placeholder : ''}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKey}
          onBlur={() => commit(draft)}
        />
      </div>
      {open.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {open.map((s) => (
            <button key={s.value} type="button" className="chip opacity-70 hover:opacity-100" onClick={() => onChange([...value, s.value])}>
              + {s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function ActionBadge({ action }: { action: Action }) {
  const cls = action === 'accept' ? 'badge-ok' : action === 'drop' ? 'badge-bad' : 'badge-warn';
  return <span className={`badge ${cls}`}>{action}</span>;
}

const SEV_CLASS: Record<Severity, string> = { critical: 'badge-bad', high: 'badge-bad', medium: 'badge-warn', low: 'badge-info', info: 'badge-mute' };
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${SEV_CLASS[severity]}`}>{severity}</span>;
}

export function Modal({ open, onClose, title, children, wide = false, footer }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean; footer?: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: globalThis.KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-[7vh]" style={{ background: 'rgba(3,5,10,0.55)', backdropFilter: 'blur(6px)' }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-modal="true" aria-label={title} className={`glass-strong pop-in flex max-h-[84vh] w-full flex-col ${wide ? 'max-w-3xl' : 'max-w-lg'}`}>
        <header className="flex flex-none items-center justify-between px-5 pb-3 pt-4">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 pb-5">{children}</div>
        {footer && <footer className="flex flex-none justify-end gap-2 border-t px-5 py-3" style={{ borderColor: 'var(--line)' }}>{footer}</footer>}
      </div>
    </div>
  );
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="mb-1 grid h-12 w-12 place-items-center rounded-2xl text-ember-400" style={{ background: 'var(--glass-hover)', border: '1px solid var(--line)' }}>{icon}</div>
      <div className="text-[14px] font-semibold">{title}</div>
      {children && <div className="max-w-sm text-[13px] text-mute">{children}</div>}
    </div>
  );
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: 'ok' | 'bad' | 'warn' }) {
  const color = tone === 'ok' ? 'var(--ok)' : tone === 'bad' ? 'var(--bad)' : tone === 'warn' ? 'var(--warn)' : 'rgb(var(--mute))';
  return (
    <div className="glass px-4 py-3.5">
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-mute">
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
        {label}
      </div>
      <div className="mt-1 text-[26px] font-semibold leading-none tracking-tight">{value}</div>
      {sub && <div className="mt-1.5 text-[12px] text-mute">{sub}</div>}
    </div>
  );
}
