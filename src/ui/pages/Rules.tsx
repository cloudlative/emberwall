import { ArrowDown, ArrowUp, Clock, Copy, FileText, Gauge, GripVertical, ListPlus, Pencil, Plus, Trash2, Users } from 'lucide-react';
import { useState } from 'react';
import { DIRECTION_LABEL, uid, type Direction, type Policy, type Project, type Rule } from '../../core/model';
import { portLabel } from '../../core/net';
import { useStore } from '../../store/useStore';
import { OutputPanel } from '../components/OutputPanel';
import { ActionBadge, Empty, PageHeader, Segmented, Switch } from '../components/ui';

const PROTO_LABEL = { tcp: 'TCP', udp: 'UDP', tcpudp: 'TCP+UDP', icmp: 'ICMP', any: 'any' } as const;

export function ruleSummary(r: Rule, p: Project) {
  const addr = (list: string[]) =>
    list.length === 0 ? 'anywhere' : list.map((v) => (v.startsWith('@') ? p.addressGroups.find((g) => g.id === v.slice(1))?.name ?? v : v)).join(', ');
  const ports = r.ports.map((v) => (v.startsWith('@') ? p.portGroups.find((g) => g.id === v.slice(1))?.name ?? v : v));
  return { src: addr(r.src), dst: addr(r.dst), ports };
}

function OptionToggle({ k, label, hint }: { k: keyof Project['options']; label: string; hint: string }) {
  const value = useStore((s) => s.project.options[k]);
  const update = useStore((s) => s.update);
  return (
    <div className="tile flex items-center justify-between gap-3 px-3 py-2" title={hint}>
      <div className="min-w-0">
        <div className="truncate text-[12.5px] font-medium">{label}</div>
        <div className="truncate text-[11.5px] text-mute">{hint}</div>
      </div>
      <Switch label={label} checked={value} onChange={(v) => update((p) => ({ ...p, options: { ...p.options, [k]: v } }))} />
    </div>
  );
}

function RuleRow({ rule, index, count, onDropOn }: { rule: Rule; index: number; count: number; onDropOn: (draggedId: string) => void }) {
  const project = useStore((s) => s.project);
  const selected = useStore((s) => s.selectedRuleId === rule.id);
  const { update, selectRule, editRule } = useStore.getState();
  const [over, setOver] = useState(false);
  const s = ruleSummary(rule, project);
  const move = (delta: number) =>
    update((p) => {
      const same = p.rules.filter((r) => r.direction === rule.direction);
      const other = same[index + delta];
      if (!other) return p;
      const rules = [...p.rules];
      const a = rules.indexOf(rule);
      const b = rules.indexOf(other);
      [rules[a], rules[b]] = [rules[b], rules[a]];
      return { ...p, rules };
    });
  return (
    <div
      draggable
      onDragStart={(e) => e.dataTransfer.setData('text/rule', rule.id)}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        setOver(false);
        const id = e.dataTransfer.getData('text/rule');
        if (id && id !== rule.id) onDropOn(id);
      }}
      onClick={() => selectRule(rule.id)}
      onDoubleClick={() => editRule(rule.id)}
      className={`tile group flex cursor-pointer items-center gap-2.5 px-2.5 py-2 transition ${rule.enabled ? '' : 'opacity-50'}`}
      style={{
        borderColor: over ? '#ff8f5c' : selected ? 'rgba(255,143,92,0.6)' : undefined,
        background: selected ? 'rgba(255,107,53,0.1)' : undefined,
      }}
    >
      <GripVertical size={14} className="flex-none cursor-grab text-mute/60" />
      <span className="w-5 flex-none text-center font-mono text-[11px] text-mute">{index + 1}</span>
      <Switch label={`Enable ${rule.name}`} checked={rule.enabled} onChange={(enabled) => update((p) => ({ ...p, rules: p.rules.map((r) => (r.id === rule.id ? { ...r, enabled } : r)) }))} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-[13px] font-medium">{rule.name}</span>
          {rule.log && <span title="Logged"><FileText size={12} className="text-mute" /></span>}
          {rule.rateLimit && <span title={`Rate limit ${rule.rateLimit.rate}/${rule.rateLimit.per}${rule.rateLimit.perSource ? ' per client' : ''}`}><Gauge size={12} className="text-mute" /></span>}
          {rule.connLimit && <span title={`At most ${rule.connLimit} connections per client`}><Users size={12} className="text-mute" /></span>}
          {rule.schedule && <span title={`Active ${rule.schedule.days.join(' ')} ${rule.schedule.from}-${rule.schedule.to}`}><Clock size={12} className="text-mute" /></span>}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-1 text-[11.5px] text-mute">
          <span className="chip">{PROTO_LABEL[rule.proto]}{rule.proto === 'icmp' && rule.icmpType ? ` ${rule.icmpType}` : ''}</span>
          {s.ports.map((pt) => (
            <span key={pt} className="chip" title={portLabel(pt)}>{pt}</span>
          ))}
          <span className="max-w-full truncate px-0.5">{s.src} → {s.dst}</span>
          {rule.srcZone && <span className="chip">from zone {project.zones.find((z) => z.id === rule.srcZone)?.name ?? '?'}</span>}
          {rule.dstZone && <span className="chip">to zone {project.zones.find((z) => z.id === rule.dstZone)?.name ?? '?'}</span>}
          {rule.srcMac && <span className="chip">{rule.srcMac}</span>}
          {rule.inIface && <span className="chip">in {rule.inIface}</span>}
          {rule.outIface && <span className="chip">out {rule.outIface}</span>}
          {rule.family !== 'both' && <span className="chip">{rule.family === 'ipv4' ? 'IPv4' : 'IPv6'}</span>}
          {rule.states?.map((st) => <span key={st} className="chip">{st}</span>)}
        </div>
      </div>
      <ActionBadge action={rule.action} />
      <div className="flex flex-none items-center opacity-60 transition group-hover:opacity-100" onClick={(e) => e.stopPropagation()}>
        <button className="btn btn-ghost btn-icon" aria-label="Move up" disabled={index === 0} onClick={() => move(-1)}><ArrowUp size={14} /></button>
        <button className="btn btn-ghost btn-icon" aria-label="Move down" disabled={index === count - 1} onClick={() => move(1)}><ArrowDown size={14} /></button>
        <button className="btn btn-ghost btn-icon" aria-label="Edit" onClick={() => editRule(rule.id)}><Pencil size={14} /></button>
        <button className="btn btn-ghost btn-icon" aria-label="Duplicate" onClick={() => update((p) => {
          const i = p.rules.indexOf(rule);
          const copy = { ...rule, id: uid('r'), name: `${rule.name} (copy)` };
          return { ...p, rules: [...p.rules.slice(0, i + 1), copy, ...p.rules.slice(i + 1)] };
        })}><Copy size={14} /></button>
        <button className="btn btn-ghost btn-icon" aria-label="Delete" onClick={() => update((p) => ({ ...p, rules: p.rules.filter((r) => r.id !== rule.id) }))}><Trash2 size={14} /></button>
      </div>
    </div>
  );
}

function ProtectionsPanel() {
  const pr = useStore((s) => s.project.protections ?? {});
  const update = useStore((s) => s.update);
  const set = (patch: Partial<Project['protections']>) => update((p) => ({ ...p, protections: { ...p.protections, ...patch } }));
  const num = (value: number, onChange: (n: number) => void, label: string) => (
    <input type="number" min={1} aria-label={label} className="field !w-[72px] !px-2 !py-1 font-mono" value={value} onChange={(e) => onChange(Math.max(1, Number(e.target.value) || 1))} />
  );
  return (
    <section className="glass flex-none px-4 py-3.5">
      <div className="mb-2.5 text-[13px] font-semibold">Attack protection <span className="ml-1 font-normal text-mute">nftables and iptables; ufw via fragment</span></div>
      <div className="grid gap-2 2xl:grid-cols-3">
        <div className="tile px-3 py-2">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0"><div className="text-[12.5px] font-medium">SYN flood guard</div><div className="truncate text-[11.5px] text-mute">Drop clients opening connections too fast</div></div>
            <Switch label="SYN flood guard" checked={!!pr.synFlood} onChange={(v) => set({ synFlood: v ? { rate: 25, burst: 50 } : undefined })} />
          </div>
          {pr.synFlood && <div className="mt-2 flex items-center gap-1.5 text-[12px] text-mute">{num(pr.synFlood.rate, (rate) => set({ synFlood: { ...pr.synFlood!, rate } }), 'SYN rate')} /s per client, burst {num(pr.synFlood.burst, (burst) => set({ synFlood: { ...pr.synFlood!, burst } }), 'SYN burst')}</div>}
        </div>
        <div className="tile flex items-center justify-between gap-3 px-3 py-2">
          <div className="min-w-0"><div className="text-[12.5px] font-medium">Port-scan filter</div><div className="truncate text-[11.5px] text-mute">Drop TCP flag combinations only scanners send</div></div>
          <Switch label="Port-scan filter" checked={!!pr.portScan} onChange={(v) => set({ portScan: v || undefined })} />
        </div>
        <div className="tile px-3 py-2">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0"><div className="text-[12.5px] font-medium">Auto-ban</div><div className="truncate text-[11.5px] text-mute">Ban clients that touch a trap port</div></div>
            <Switch label="Auto-ban" checked={!!pr.autoBan} onChange={(v) => set({ autoBan: v ? { ports: ['23', '3389', '5900'], seconds: 3600 } : undefined })} />
          </div>
          {pr.autoBan && (
            <div className="mt-2 space-y-1.5 text-[12px] text-mute">
              <input aria-label="Trap ports" className="field !py-1 font-mono" value={pr.autoBan.ports.join(', ')} onChange={(e) => set({ autoBan: { ...pr.autoBan!, ports: e.target.value.split(/[\s,]+/).filter(Boolean) } })} />
              <div className="flex items-center gap-1.5">ban for {num(pr.autoBan.seconds, (seconds) => set({ autoBan: { ...pr.autoBan!, seconds } }), 'Ban seconds')} seconds</div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

export function RulesPage() {
  const project = useStore((s) => s.project);
  const update = useStore((s) => s.update);
  const editRule = useStore((s) => s.editRule);
  const [dir, setDir] = useState<Direction>('in');
  const rules = project.rules.filter((r) => r.direction === dir);
  const count = (d: Direction) => project.rules.filter((r) => r.direction === d).length;

  const dropOn = (targetRule: Rule) => (draggedId: string) =>
    update((p) => {
      const dragged = p.rules.find((r) => r.id === draggedId);
      if (!dragged || dragged.direction !== targetRule.direction) return p;
      const from = p.rules.indexOf(dragged);
      const to = p.rules.findIndex((r) => r.id === targetRule.id);
      const rest = p.rules.filter((r) => r.id !== draggedId);
      const at = rest.findIndex((r) => r.id === targetRule.id) + (from < to ? 1 : 0);
      return { ...p, rules: [...rest.slice(0, at), dragged, ...rest.slice(at)] };
    });

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Rules" sub="Rules are checked top to bottom; the first match decides. Click a rule to see the lines it generates.">
        <button className="btn btn-primary" onClick={() => editRule(`new:${dir}`)}><Plus size={15} /> Add rule</button>
      </PageHeader>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto xl:overflow-visible xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4 pr-1 xl:min-h-0 xl:overflow-y-auto">
          <section className="glass flex-none px-4 py-3.5">
            <div className="mb-2.5 text-[13px] font-semibold">Default policies and baseline</div>
            <div className="mb-3 grid gap-2 sm:grid-cols-3">
              {(['in', 'out', 'forward'] as Direction[]).map((d) => (
                <div key={d} className="tile flex items-center justify-between gap-2 px-3 py-2">
                  <span className="text-[12.5px] font-medium">{DIRECTION_LABEL[d]}</span>
                  <Segmented<Policy> size="sm" value={project.policies[d]} onChange={(v) => update((p) => ({ ...p, policies: { ...p.policies, [d]: v } }))} options={[{ value: 'drop', label: 'Drop' }, { value: 'accept', label: 'Accept' }]} />
                </div>
              ))}
            </div>
            <div className="grid gap-2 sm:grid-cols-2 2xl:grid-cols-3">
              <OptionToggle k="allowEstablished" label="Established connections" hint="Accept replies to allowed traffic" />
              <OptionToggle k="allowLoopback" label="Loopback" hint="Accept traffic on lo" />
              <OptionToggle k="dropInvalid" label="Drop invalid" hint="Drop packets with no valid state" />
              <OptionToggle k="allowIcmp" label="Essential ICMP" hint="Ping and IPv6 neighbour discovery" />
              <OptionToggle k="ipv6" label="IPv6" hint="Off blocks all IPv6 traffic" />
              <OptionToggle k="forwarding" label="Routing" hint="Host forwards between interfaces" />
              <OptionToggle k="logDropped" label="Log dropped" hint="Rate-limited log of policy drops" />
            </div>
          </section>

          <ProtectionsPanel />

          <section className="glass flex min-h-[240px] flex-1 flex-col px-4 py-3.5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <Segmented<Direction> value={dir} onChange={setDir} options={(['in', 'out', 'forward'] as Direction[]).map((d) => ({ value: d, label: <>{DIRECTION_LABEL[d]} <span className="ml-1 font-mono text-[11px] text-mute">{count(d)}</span></> }))} />
              <span className="text-[12px] text-mute">Then: <b className="font-semibold text-ink">{project.policies[dir]}</b> everything else</span>
            </div>
            {rules.length === 0 ? (
              <Empty icon={<ListPlus size={22} />} title={`No ${DIRECTION_LABEL[dir].toLowerCase()} rules`}>
                Everything {dir === 'in' ? 'arriving' : dir === 'out' ? 'leaving' : 'passing through'} is handled by the default policy ({project.policies[dir]}).
              </Empty>
            ) : (
              <div className="space-y-1.5">
                {rules.map((r, i) => (
                  <RuleRow key={r.id} rule={r} index={i} count={rules.length} onDropOn={dropOn(r)} />
                ))}
              </div>
            )}
          </section>
        </div>
        <OutputPanel className="h-[620px] xl:h-auto xl:min-h-0" />
      </div>
    </div>
  );
}
