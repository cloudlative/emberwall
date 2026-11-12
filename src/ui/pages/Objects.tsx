import { Network, Plus, Trash2 } from 'lucide-react';
import { uid } from '../../core/model';
import { parseCidr, parsePort, portLabel } from '../../core/net';
import { useStore } from '../../store/useStore';
import { Empty, PageHeader, Panel, TagInput } from '../components/ui';

export function ObjectsPage() {
  const project = useStore((s) => s.project);
  const update = useStore((s) => s.update);
  const uses = (ref: string) => project.rules.filter((r) => [...r.src, ...r.dst, ...r.ports].includes(ref)).length;
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Objects" sub="Name a set of addresses or ports once and reuse it across rules. nftables output turns address groups into named sets." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Address groups" actions={<button className="btn" onClick={() => update((p) => ({ ...p, addressGroups: [...p.addressGroups, { id: uid('ag'), name: 'New group', members: [] }] }))}><Plus size={14} /> Group</button>}>
          {project.addressGroups.length === 0 ? (
            <Empty icon={<Network size={22} />} title="No address groups">Example: an “Admin networks” group used by every management rule.</Empty>
          ) : (
            <div className="space-y-3">
              {project.addressGroups.map((g) => (
                <div key={g.id} className="tile p-3">
                  <div className="mb-2 flex items-center gap-2">
                    <input aria-label="Group name" className="field font-medium" value={g.name} onChange={(e) => update((p) => ({ ...p, addressGroups: p.addressGroups.map((x) => (x.id === g.id ? { ...x, name: e.target.value } : x)) }))} />
                    <span className="badge badge-mute whitespace-nowrap">{uses(`@${g.id}`)} use{uses(`@${g.id}`) === 1 ? '' : 's'}</span>
                    <button className="btn btn-ghost btn-icon" aria-label="Delete group" onClick={() => update((p) => ({
                      ...p,
                      addressGroups: p.addressGroups.filter((x) => x.id !== g.id),
                      rules: p.rules.map((r) => ({ ...r, src: r.src.filter((v) => v !== `@${g.id}`), dst: r.dst.filter((v) => v !== `@${g.id}`) })),
                    }))}><Trash2 size={14} /></button>
                  </div>
                  <TagInput value={g.members} placeholder="10.0.0.0/8, 2001:db8::/32" validate={(v) => !!parseCidr(v)} onChange={(members) => update((p) => ({ ...p, addressGroups: p.addressGroups.map((x) => (x.id === g.id ? { ...x, members } : x)) }))} />
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Port groups" actions={<button className="btn" onClick={() => update((p) => ({ ...p, portGroups: [...p.portGroups, { id: uid('pg'), name: 'New port group', ports: [] }] }))}><Plus size={14} /> Group</button>}>
          {project.portGroups.length === 0 ? (
            <Empty icon={<Network size={22} />} title="No port groups">Example: “Web” = 80, 443, 8080.</Empty>
          ) : (
            <div className="space-y-3">
              {project.portGroups.map((g) => (
                <div key={g.id} className="tile p-3">
                  <div className="mb-2 flex items-center gap-2">
                    <input aria-label="Group name" className="field font-medium" value={g.name} onChange={(e) => update((p) => ({ ...p, portGroups: p.portGroups.map((x) => (x.id === g.id ? { ...x, name: e.target.value } : x)) }))} />
                    <span className="badge badge-mute whitespace-nowrap">{uses(`@${g.id}`)} use{uses(`@${g.id}`) === 1 ? '' : 's'}</span>
                    <button className="btn btn-ghost btn-icon" aria-label="Delete group" onClick={() => update((p) => ({
                      ...p,
                      portGroups: p.portGroups.filter((x) => x.id !== g.id),
                      rules: p.rules.map((r) => ({ ...r, ports: r.ports.filter((v) => v !== `@${g.id}`) })),
                    }))}><Trash2 size={14} /></button>
                  </div>
                  <TagInput value={g.ports} placeholder="80, 443, 8000:8100" validate={(v) => !!parsePort(v)} render={(v) => (portLabel(v) ? `${v} · ${portLabel(v)}` : v)} onChange={(ports) => update((p) => ({ ...p, portGroups: p.portGroups.map((x) => (x.id === g.id ? { ...x, ports } : x)) }))} />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
