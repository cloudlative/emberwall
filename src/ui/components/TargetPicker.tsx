import { DISTROS, TOOL_LABEL, VERSIONS, latestVersion, toolsFor, type Tool } from '../../core/targets';
import { useStore, useTarget } from '../../store/useStore';
import { Segmented } from './ui';

/** Distro preset or hand-picked tool + version. Drives every compiled output in the app. */
export function TargetPicker({ compact = false }: { compact?: boolean }) {
  const selection = useStore((s) => s.selection);
  const setSelection = useStore((s) => s.setSelection);
  const target = useTarget();
  const tools = toolsFor(selection);
  return (
    <div className={`flex flex-wrap items-center gap-2 ${compact ? '' : 'gap-y-2'}`}>
      <select
        aria-label="Target system"
        className="field !w-auto"
        value={selection.distro}
        onChange={(e) => {
          const distro = e.target.value;
          const d = DISTROS.find((x) => x.id === distro);
          setSelection({ distro, tool: d && d.tools[target.tool] === undefined ? d.defaultTool : target.tool, version: target.version });
        }}
      >
        <optgroup label="Distribution presets">
          {DISTROS.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </optgroup>
        <option value="custom">Custom tool version…</option>
      </select>
      <Segmented<Tool>
        value={target.tool}
        options={tools.map((t) => ({ value: t, label: TOOL_LABEL[t] }))}
        onChange={(tool) => setSelection({ tool, version: selection.distro === 'custom' ? latestVersion(tool) : selection.version })}
      />
      {selection.distro === 'custom' ? (
        <select aria-label="Tool version" className="field !w-auto font-mono" value={target.version} onChange={(e) => setSelection({ version: e.target.value })}>
          {VERSIONS[target.tool].map((v) => (
            <option key={v} value={v}>v{v}</option>
          ))}
        </select>
      ) : (
        <span className="badge badge-mute font-mono normal-case" title="Version this distribution ships">v{target.version}</span>
      )}
    </div>
  );
}
