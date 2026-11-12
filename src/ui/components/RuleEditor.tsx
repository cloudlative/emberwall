import { ChevronDown } from 'lucide-react';
import { useEffect, useState } from 'react';
import { ICMP_TYPES, WEEKDAYS, newRule, type Action, type ConnState, type Direction, type Family, type Proto, type Rule } from '../../core/model';
import { parseCidr, parsePort, portLabel } from '../../core/net';
import { useStore } from '../../store/useStore';
import { Field, Modal, Segmented, Switch, TagInput } from './ui';

const COMMON_PORTS = ['22', '53', '80', '443', '3306', '5432', '8080', '51820'];
const STATES: ConnState[] = ['new', 'established', 'related', 'invalid'];

/** Modal editor. `editingRuleId` is a rule id, or "new:<direction>" for a rule not yet in the project. */
export function RuleEditor() {
  const editing = useStore((s) => s.editingRuleId);
  const project = useStore((s) => s.project);
  const update = useStore((s) => s.update);
  const editRule = useStore((s) => s.editRule);
  const [draft, setDraft] = useState<Rule | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const isNew = !!editing && editing.startsWith('new:');

  useEffect(() => {
    if (!editing) setDraft(null);
    else if (editing.startsWith('new:')) setDraft(newRule({ name: '', direction: editing.slice(4) as Direction }));
    else {
      const found = project.rules.find((r) => r.id === editing) ?? null;
      setDraft(found);
      setAdvanced(!!found && !!(found.srcPorts?.length || found.srcMac || found.connLimit || found.schedule || found.mark || found.srcZone || found.dstZone || found.hosts?.length));
    }
    // Only re-seed when a different rule is opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editing]);

  if (!draft) return null;
  const set = (patch: Partial<Rule>) => setDraft({ ...draft, ...patch });
  const hasPorts = draft.proto === 'tcp' || draft.proto === 'udp' || draft.proto === 'tcpudp';
  const groupName = (v: string) => (v.startsWith('@') ? `@${project.addressGroups.find((g) => g.id === v.slice(1))?.name ?? v.slice(1)}` : v);
  const portName = (v: string) => {
    if (v.startsWith('@')) return `@${project.portGroups.find((g) => g.id === v.slice(1))?.name ?? v.slice(1)}`;
    const l = portLabel(v);
    return l ? `${v} · ${l}` : v;
  };
  const addrSuggestions = project.addressGroups.map((g) => ({ value: `@${g.id}`, label: g.name }));
  const close = () => editRule(null);
  const save = () => {
    const rule: Rule = { ...draft, name: draft.name.trim() || 'Unnamed rule', ports: hasPorts ? draft.ports : [], icmpType: draft.proto === 'icmp' ? draft.icmpType : undefined };
    update((p) => ({ ...p, rules: isNew ? [...p.rules, rule] : p.rules.map((r) => (r.id === rule.id ? rule : r)) }));
    useStore.setState({ editingRuleId: null, selectedRuleId: rule.id });
  };

  return (
    <Modal
      open
      onClose={close}
      wide
      title={isNew ? 'New rule' : 'Edit rule'}
      footer={
        <>
          <button className="btn" onClick={close}>Cancel</button>
          <button className="btn btn-primary" onClick={save}>{isNew ? 'Add rule' : 'Save changes'}</button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" className="sm:col-span-2">
          <input autoFocus className="field" value={draft.name} placeholder="e.g. HTTPS from anywhere" onChange={(e) => set({ name: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && save()} />
        </Field>
        <Field label="Direction">
          <Segmented<Direction> value={draft.direction} onChange={(direction) => set({ direction })} options={[{ value: 'in', label: 'Inbound' }, { value: 'out', label: 'Outbound' }, { value: 'forward', label: 'Forward' }]} />
        </Field>
        <Field label="Action">
          <Segmented<Action> value={draft.action} onChange={(action) => set({ action })} options={[{ value: 'accept', label: 'Accept' }, { value: 'drop', label: 'Drop' }, { value: 'reject', label: 'Reject' }]} />
        </Field>
        <Field label="Protocol">
          <select className="field" value={draft.proto} onChange={(e) => set({ proto: e.target.value as Proto })}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="tcpudp">TCP + UDP</option>
            <option value="icmp">ICMP / ICMPv6</option>
            <option value="any">Any protocol</option>
          </select>
        </Field>
        <Field label="Address family">
          <Segmented<Family> value={draft.family} onChange={(family) => set({ family })} options={[{ value: 'both', label: 'IPv4 + IPv6' }, { value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }]} />
        </Field>
        {hasPorts && (
          <Field label="Destination ports" hint="Single ports or ranges (8000:8100). Empty means every port." className="sm:col-span-2">
            <TagInput
              value={draft.ports}
              onChange={(ports) => set({ ports })}
              placeholder="22, 443, 8000:8100"
              render={portName}
              validate={(v) => !!parsePort(v)}
              suggestions={[...project.portGroups.map((g) => ({ value: `@${g.id}`, label: g.name })), ...COMMON_PORTS.map((p) => ({ value: p, label: `${p} ${portLabel(p)}` }))]}
            />
          </Field>
        )}
        {draft.proto === 'icmp' && (
          <Field label="ICMP type" className="sm:col-span-2">
            <select className="field" value={draft.icmpType ?? ''} onChange={(e) => set({ icmpType: e.target.value || undefined })}>
              <option value="">Every type</option>
              {ICMP_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
        )}
        <Field label="Source" hint="Addresses, CIDRs or groups. Empty means anywhere.">
          <TagInput value={draft.src} onChange={(src) => set({ src })} placeholder="anywhere" render={groupName} validate={(v) => !!parseCidr(v)} suggestions={addrSuggestions} />
        </Field>
        <Field label="Destination" hint="Empty means any address.">
          <TagInput value={draft.dst} onChange={(dst) => set({ dst })} placeholder="anywhere" render={groupName} validate={(v) => !!parseCidr(v)} suggestions={addrSuggestions} />
        </Field>
        {draft.direction !== 'out' && (
          <Field label="Inbound interface">
            <input className="field font-mono" value={draft.inIface ?? ''} placeholder="any (e.g. eth0)" onChange={(e) => set({ inIface: e.target.value.trim() || undefined })} />
          </Field>
        )}
        {draft.direction !== 'in' && (
          <Field label="Outbound interface">
            <input className="field font-mono" value={draft.outIface ?? ''} placeholder="any (e.g. eth0)" onChange={(e) => set({ outIface: e.target.value.trim() || undefined })} />
          </Field>
        )}
        <Field label="Connection state" hint="Leave empty to match every state." className="sm:col-span-2">
          <div className="flex flex-wrap gap-1.5">
            {STATES.map((st) => {
              const on = draft.states?.includes(st) ?? false;
              return (
                <button key={st} type="button" aria-pressed={on} className={`chip !py-1 ${on ? '!border-ember-400/70 text-ink' : 'text-mute'}`} onClick={() => {
                  const next = on ? (draft.states ?? []).filter((x) => x !== st) : [...(draft.states ?? []), st];
                  set({ states: next.length > 0 ? next : undefined });
                }}>
                  {st}
                </button>
              );
            })}
          </div>
        </Field>
        <div className="tile flex items-center justify-between gap-3 px-3 py-2.5">
          <div>
            <div className="text-[13px] font-medium">Log matches</div>
            <div className="text-[12px] text-mute">Write a kernel log line per match</div>
          </div>
          <Switch label="Log matches" checked={!!draft.log} onChange={(log) => set({ log: log || undefined })} />
        </div>
        <div className="tile px-3 py-2.5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-[13px] font-medium">Rate limit</div>
              <div className="text-[12px] text-mute">Accept only up to a rate; excess falls through</div>
            </div>
            <Switch label="Rate limit" checked={!!draft.rateLimit} onChange={(on) => set({ rateLimit: on ? { rate: 10, per: 'minute', burst: 20 } : undefined })} />
          </div>
          {draft.rateLimit && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[12px] text-mute">
              <input type="number" min={1} aria-label="Rate" className="field !w-16 !px-2 font-mono" value={draft.rateLimit.rate} onChange={(e) => set({ rateLimit: { ...draft.rateLimit!, rate: Math.max(1, Number(e.target.value) || 1) } })} />
              per
              <select aria-label="Per" className="field !w-auto" value={draft.rateLimit.per} onChange={(e) => set({ rateLimit: { ...draft.rateLimit!, per: e.target.value as 'second' | 'minute' | 'hour' } })}>
                <option value="second">second</option>
                <option value="minute">minute</option>
                <option value="hour">hour</option>
              </select>
              burst
              <input type="number" min={1} aria-label="Burst" className="field !w-16 !px-2 font-mono" value={draft.rateLimit.burst} onChange={(e) => set({ rateLimit: { ...draft.rateLimit!, burst: Math.max(1, Number(e.target.value) || 1) } })} />
              <label className="ml-1 flex items-center gap-1.5 text-ink" title="Count each client address separately; clients over the rate are dropped">
                <Switch label="Per client" checked={!!draft.rateLimit.perSource} onChange={(v) => set({ rateLimit: { ...draft.rateLimit!, perSource: v || undefined } })} /> per client
              </label>
            </div>
          )}
        </div>
        <button type="button" className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute hover:text-ink sm:col-span-2" onClick={() => setAdvanced((v) => !v)} aria-expanded={advanced}>
          <ChevronDown size={14} style={{ transform: advanced ? 'none' : 'rotate(-90deg)', transition: '0.15s' }} /> Advanced matches
        </button>
        {advanced && (
          <>
            {project.zones.length > 0 && draft.direction !== 'out' && (
              <Field label="Source zone">
                <select className="field" value={draft.srcZone ?? ''} onChange={(e) => set({ srcZone: e.target.value || undefined })}>
                  <option value="">Any zone</option>
                  {project.zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
                </select>
              </Field>
            )}
            {project.zones.length > 0 && draft.direction !== 'in' && (
              <Field label="Destination zone">
                <select className="field" value={draft.dstZone ?? ''} onChange={(e) => set({ dstZone: e.target.value || undefined })}>
                  <option value="">Any zone</option>
                  {project.zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
                </select>
              </Field>
            )}
            {hasPorts && (
              <Field label="Source ports" hint="Rarely needed; replies usually match by connection state.">
                <TagInput value={draft.srcPorts ?? []} onChange={(v) => set({ srcPorts: v.length ? v : undefined })} placeholder="any" validate={(v) => !!parsePort(v)} />
              </Field>
            )}
            <Field label="Connections per client" hint="Clients holding more are rejected. Empty = no limit.">
              <input type="number" min={1} className="field font-mono" value={draft.connLimit ?? ''} placeholder="unlimited" onChange={(e) => set({ connLimit: e.target.value ? Math.max(1, Number(e.target.value)) : undefined })} />
            </Field>
            {draft.direction !== 'out' && (
              <Field label="Source MAC address">
                <input className="field font-mono" value={draft.srcMac ?? ''} placeholder="aa:bb:cc:dd:ee:ff" onChange={(e) => set({ srcMac: e.target.value.trim() || undefined })} />
              </Field>
            )}
            {project.hosts.length > 0 && (
              <Field label="Hosts" hint="Leave all unselected to apply the rule to every host." className="sm:col-span-2">
                <div className="flex flex-wrap gap-1.5">
                  {project.hosts.map((h) => {
                    const on = draft.hosts?.includes(h.id) ?? false;
                    return (
                      <button key={h.id} type="button" aria-pressed={on} className={`chip !py-1 ${on ? '!border-ember-400/70 text-ink' : 'text-mute'}`} onClick={() => {
                        const next = on ? (draft.hosts ?? []).filter((x) => x !== h.id) : [...(draft.hosts ?? []), h.id];
                        set({ hosts: next.length > 0 ? next : undefined });
                      }}>{h.name}</button>
                    );
                  })}
                </div>
              </Field>
            )}
            <Field label="Packet mark">
              <input className="field font-mono" value={draft.mark ?? ''} placeholder="0x1" onChange={(e) => set({ mark: e.target.value.trim() || undefined })} />
            </Field>
            <div className="tile px-3 py-2.5 sm:col-span-2">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-[13px] font-medium">Schedule</div>
                  <div className="text-[12px] text-mute">Rule is active only in this window (firewall host clock, UTC unless configured)</div>
                </div>
                <Switch label="Schedule" checked={!!draft.schedule} onChange={(on) => set({ schedule: on ? { days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], from: '08:00', to: '18:00' } : undefined })} />
              </div>
              {draft.schedule && (
                <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[12px] text-mute">
                  {WEEKDAYS.map((d) => {
                    const on = draft.schedule!.days.includes(d);
                    return (
                      <button key={d} type="button" aria-pressed={on} className={`chip !py-1 ${on ? '!border-ember-400/70 text-ink' : 'text-mute'}`} onClick={() => set({ schedule: { ...draft.schedule!, days: on ? draft.schedule!.days.filter((x) => x !== d) : WEEKDAYS.filter((x) => x === d || draft.schedule!.days.includes(x)) } })}>{d}</button>
                    );
                  })}
                  <input type="time" aria-label="From" className="field !w-auto font-mono" value={draft.schedule.from} onChange={(e) => set({ schedule: { ...draft.schedule!, from: e.target.value } })} />
                  to
                  <input type="time" aria-label="To" className="field !w-auto font-mono" value={draft.schedule.to} onChange={(e) => set({ schedule: { ...draft.schedule!, to: e.target.value } })} />
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
