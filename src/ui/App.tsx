import {
  ArrowLeftRight, Camera, Check, ClipboardCheck, Columns2, Command, FlaskConical, FolderInput, Gauge, Grid3x3, Hammer, Info, Layers, LayoutDashboard, LayoutTemplate,
  ListChecks, Moon, Network, Plus, Redo2, Search, ShieldAlert, Sun, Table2, Undo2, Waypoints, XCircle,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { score } from '../core/lint';
import { runTests } from '../core/reach';
import { DISTROS, TOOL_LABEL, type Tool } from '../core/targets';
import { TEMPLATES } from '../core/templates';
import { readShare, useFindings, useStore, type PageId } from '../store/useStore';
import { RuleEditor } from './components/RuleEditor';
import { TargetPicker } from './components/TargetPicker';
import { AuditPage } from './pages/Audit';
import { BuildPage, ComparePage } from './pages/Build';
import { DashboardPage } from './pages/Dashboard';
import { FlowPage } from './pages/Flow';
import { SnapshotsPage, TemplatesPage, TransferPage, VersionsPage } from './pages/Library';
import { NatPage } from './pages/Nat';
import { ObjectsPage } from './pages/Objects';
import { ReachabilityPage, TestsPage, ZonesPage } from './pages/Policy';
import { RulesPage } from './pages/Rules';
import { SimulatorPage } from './pages/Simulator';

interface NavItem {
  id: PageId;
  label: string;
  icon: ReactNode;
  group: string;
}

const NAV: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} />, group: 'Design' },
  { id: 'rules', label: 'Rules', icon: <ListChecks size={16} />, group: 'Design' },
  { id: 'nat', label: 'NAT', icon: <ArrowLeftRight size={16} />, group: 'Design' },
  { id: 'objects', label: 'Objects', icon: <Network size={16} />, group: 'Design' },
  { id: 'zones', label: 'Zones', icon: <Layers size={16} />, group: 'Design' },
  { id: 'build', label: 'Build', icon: <Hammer size={16} />, group: 'Ship' },
  { id: 'compare', label: 'Compare', icon: <Columns2 size={16} />, group: 'Ship' },
  { id: 'versions', label: 'Version matrix', icon: <Table2 size={16} />, group: 'Ship' },
  { id: 'simulator', label: 'Simulator', icon: <FlaskConical size={16} />, group: 'Verify' },
  { id: 'reach', label: 'Reachability', icon: <Grid3x3 size={16} />, group: 'Verify' },
  { id: 'tests', label: 'Policy tests', icon: <ClipboardCheck size={16} />, group: 'Verify' },
  { id: 'audit', label: 'Audit', icon: <ShieldAlert size={16} />, group: 'Verify' },
  { id: 'flow', label: 'Packet flow', icon: <Waypoints size={16} />, group: 'Verify' },
  { id: 'templates', label: 'Templates', icon: <LayoutTemplate size={16} />, group: 'Library' },
  { id: 'snapshots', label: 'Snapshots', icon: <Camera size={16} />, group: 'Library' },
  { id: 'transfer', label: 'Import / export', icon: <FolderInput size={16} />, group: 'Library' },
];

const PAGES: Record<PageId, () => JSX.Element> = {
  dashboard: DashboardPage, rules: RulesPage, nat: NatPage, objects: ObjectsPage, build: BuildPage, compare: ComparePage,
  versions: VersionsPage, simulator: SimulatorPage, audit: AuditPage, flow: FlowPage, templates: TemplatesPage,
  snapshots: SnapshotsPage, transfer: TransferPage, zones: ZonesPage, reach: ReachabilityPage, tests: TestsPage,
};

function Logo() {
  return (
    <div className="flex items-center gap-2.5 px-2">
      <svg viewBox="0 0 32 32" className="h-8 w-8 flex-none" aria-hidden>
        <defs>
          <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#ffb38a" /><stop offset="1" stopColor="#ec4f17" /></linearGradient>
        </defs>
        <path d="M16 2l11 4.200v8.800c0 6.800-4.600 11.800-11 14-6.400-2.200-11-7.200-11-14v-8.800z" fill="url(#lg)" />
        <path d="M16 9.500c2.400 3 4.200 4.600 4.200 7.300a4.200 4.200 0 01-8.400 0c0-1.500.6-2.500 1.600-3.400.2 1.200.9 1.800 1.600 1.800.4-2 .3-3.800 1-5.700z" fill="#12141c" />
      </svg>
      <div className="hidden leading-tight lg:block">
        <div className="text-[15px] font-semibold tracking-tight">Emberwall</div>
        <div className="text-[10.5px] uppercase tracking-[0.18em] text-mute">Firewall builder</div>
      </div>
    </div>
  );
}

interface Cmd {
  id: string;
  label: string;
  hint: string;
  icon: ReactNode;
  run: () => void;
}

function Palette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const project = useStore((s) => s.project);
  const cmds = useMemo<Cmd[]>(() => {
    const st = useStore.getState();
    const list: Cmd[] = [
      { id: 'new', label: 'Add rule', hint: 'Action', icon: <Plus size={15} />, run: () => { st.setPage('rules'); st.editRule('new:in'); } },
      ...NAV.map((n) => ({ id: `go:${n.id}`, label: `Go to ${n.label}`, hint: 'Page', icon: n.icon, run: () => st.setPage(n.id) })),
      { id: 'undo', label: 'Undo', hint: 'Ctrl+Z', icon: <Undo2 size={15} />, run: st.undo },
      { id: 'redo', label: 'Redo', hint: 'Ctrl+Shift+Z', icon: <Redo2 size={15} />, run: st.redo },
      { id: 'theme', label: 'Toggle light / dark theme', hint: 'Action', icon: <Sun size={15} />, run: () => st.setTheme(useStore.getState().theme === 'dark' ? 'light' : 'dark') },
      { id: 'snap', label: 'Save snapshot', hint: 'Action', icon: <Camera size={15} />, run: () => { st.addSnapshot(''); st.toast('Snapshot saved'); } },
      ...DISTROS.flatMap((d) => (Object.keys(d.tools) as Tool[]).map((t) => ({
        id: `t:${d.id}:${t}`, label: `Target: ${d.name} · ${TOOL_LABEL[t]} ${d.tools[t]}`, hint: 'Target', icon: <Gauge size={15} />, run: () => st.setSelection({ distro: d.id, tool: t }),
      }))),
      ...TEMPLATES.map((t) => ({ id: `tpl:${t.id}`, label: `Load template: ${t.name}`, hint: 'Template', icon: <LayoutTemplate size={15} />, run: () => { st.replaceProject(t.build()); st.setPage('rules'); } })),
      ...project.rules.map((r) => ({ id: `r:${r.id}`, label: `Edit rule: ${r.name}`, hint: 'Rule', icon: <ListChecks size={15} />, run: () => { st.setPage('rules'); st.editRule(r.id); } })),
    ];
    return list;
  }, [project.rules]);
  const shown = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    return cmds.filter((c) => words.every((w) => c.label.toLowerCase().includes(w))).slice(0, 12);
  }, [cmds, q]);
  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
    }
  }, [open]);
  useEffect(() => setIdx(0), [q]);
  if (!open) return null;
  const run = (c?: Cmd) => {
    if (!c) return;
    onClose();
    c.run();
  };
  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center p-4 pt-[14vh]" style={{ background: 'rgba(3,5,10,0.5)', backdropFilter: 'blur(6px)' }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-label="Command palette" className="glass-strong pop-in w-full max-w-xl overflow-hidden">
        <div className="flex items-center gap-2.5 border-b px-4 py-3" style={{ borderColor: 'var(--line)' }}>
          <Search size={16} className="text-mute" />
          <input
            ref={input}
            autoFocus
            className="flex-1 bg-transparent text-[14px] outline-none placeholder:text-mute/70"
            placeholder="Search pages, rules, targets, templates…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(i + 1, shown.length - 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)); }
              else if (e.key === 'Enter') run(shown[idx]);
              else if (e.key === 'Escape') onClose();
            }}
          />
          <kbd className="chip">Esc</kbd>
        </div>
        <ul className="max-h-[50vh] overflow-y-auto p-1.5">
          {shown.length === 0 && <li className="px-3 py-6 text-center text-[13px] text-mute">Nothing matches “{q}”.</li>}
          {shown.map((c, i) => (
            <li key={c.id}>
              <button onMouseEnter={() => setIdx(i)} onClick={() => run(c)} className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-left text-[13px]" style={i === idx ? { background: 'var(--glass-hover)' } : undefined}>
                <span className="text-mute">{c.icon}</span>
                <span className="flex-1 truncate">{c.label}</span>
                <span className="text-[11px] text-mute">{c.hint}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed bottom-5 left-1/2 z-[70] flex -translate-x-1/2 flex-col items-center gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className="glass-strong pop-in flex items-center gap-2 !rounded-full px-4 py-2 text-[13px]">
          {t.tone === 'bad' ? <XCircle size={15} style={{ color: 'var(--bad)' }} /> : t.tone === 'info' ? <Info size={15} style={{ color: 'var(--info)' }} /> : <Check size={15} style={{ color: 'var(--ok)' }} />}
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function App() {
  const page = useStore((s) => s.page);
  const theme = useStore((s) => s.theme);
  const name = useStore((s) => s.project.name);
  const canUndo = useStore((s) => s.past.length > 0);
  const canRedo = useStore((s) => s.future.length > 0);
  const findings = useFindings();
  const { setPage, undo, redo, setTheme, update } = useStore.getState();
  const [palette, setPalette] = useState(false);
  const urgent = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const project = useStore((st) => st.project);
  const failingTests = useMemo(() => runTests(project).filter((t) => !t.pass).length, [project]);
  const s = score(findings);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // A share link carries a whole project in the URL fragment.
  useEffect(() => {
    const shared = readShare(location.hash);
    if (!shared) return;
    const st = useStore.getState();
    st.replaceProject(shared.project);
    if (shared.selection) st.setSelection(shared.selection);
    st.toast(`Opened shared ruleset "${shared.project.name}"`, 'info');
    history.replaceState(null, '', location.pathname + location.search);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement).tagName);
      if (mod && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPalette((v) => !v);
      } else if (mod && e.key.toLowerCase() === 'z' && !typing) {
        e.preventDefault();
        if (e.shiftKey) redo();
        else undo();
      } else if (mod && e.key.toLowerCase() === 'y' && !typing) {
        e.preventDefault();
        redo();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [redo, undo]);

  const Page = PAGES[page] ?? DashboardPage;
  const groups = [...new Set(NAV.map((n) => n.group))];

  return (
    <>
      <div className="backdrop"><b /><i /></div>
      <div className="relative z-10 flex h-full gap-4 p-4">
        <aside className="glass flex w-[60px] flex-none flex-col py-4 lg:w-[218px]">
          <Logo />
          <nav className="mt-5 flex-1 space-y-4 overflow-y-auto px-2" aria-label="Main">
            {groups.map((g) => (
              <div key={g}>
                <div className="mb-1 hidden px-3 text-[10.5px] font-semibold uppercase tracking-[0.16em] text-mute/70 lg:block">{g}</div>
                <div className="space-y-0.5">
                  {NAV.filter((n) => n.group === g).map((n) => (
                    <button key={n.id} className="nav-item justify-center lg:justify-start" aria-current={page === n.id ? 'page' : undefined} onClick={() => setPage(n.id)} title={n.label}>
                      {n.icon}
                      <span className="hidden flex-1 text-left lg:inline">{n.label}</span>
                      {n.id === 'audit' && urgent > 0 && <span className="badge badge-bad hidden lg:inline-flex">{urgent}</span>}
                      {n.id === 'tests' && failingTests > 0 && <span className="badge badge-bad hidden lg:inline-flex">{failingTests}</span>}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>
          <div className="mt-3 hidden px-4 text-[11px] leading-snug text-mute lg:block">Runs entirely in your browser. Rulesets are never uploaded.</div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col gap-4">
          <header className="glass relative z-20 flex flex-none flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
            <input aria-label="Project name" className="min-w-[120px] max-w-[260px] flex-1 truncate rounded-lg bg-transparent px-1.5 py-1 text-[15px] font-semibold outline-none hover:bg-white/5 focus:bg-white/5" value={name} onChange={(e) => update((p) => ({ ...p, name: e.target.value }))} />
            <button className="badge badge-mute normal-case" onClick={() => setPage('audit')} title="Posture score from the audit">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: s >= 75 ? 'var(--ok)' : s >= 50 ? 'var(--warn)' : 'var(--bad)' }} /> Score {s}
            </button>
            {failingTests > 0 && (
              <button className="badge badge-bad normal-case" onClick={() => setPage('tests')}>{failingTests} test{failingTests > 1 ? 's' : ''} failing</button>
            )}
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <TargetPicker compact />
              <span className="mx-1 hidden h-6 w-px xl:block" style={{ background: 'var(--line)' }} />
              <button className="btn btn-icon" onClick={undo} disabled={!canUndo} aria-label="Undo" title="Undo (Ctrl+Z)"><Undo2 size={15} /></button>
              <button className="btn btn-icon" onClick={redo} disabled={!canRedo} aria-label="Redo" title="Redo (Ctrl+Shift+Z)"><Redo2 size={15} /></button>
              <button className="btn" onClick={() => setPalette(true)} title="Command palette"><Command size={14} /><span className="hidden sm:inline">Search</span><kbd className="ml-1 hidden font-mono text-[10.5px] text-mute sm:inline">Ctrl K</kbd></button>
              <button className="btn btn-icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle theme" title="Toggle theme">{theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}</button>
            </div>
          </header>
          <main key={page} className="fade-in min-h-0 flex-1">
            <Page />
          </main>
        </div>
      </div>
      <RuleEditor />
      <Palette open={palette} onClose={() => setPalette(false)} />
      <Toasts />
    </>
  );
}
