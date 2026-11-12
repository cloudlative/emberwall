import { useMemo } from 'react';
import LZString from 'lz-string';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { compile, type CompileResult } from '../core/compile';
import { lint, type Finding } from '../core/lint';
import { coerceProject, uid, type Project } from '../core/model';
import { DEFAULT_SELECTION, resolveTarget, type Target, type TargetSelection } from '../core/targets';
import { TEMPLATES } from '../core/templates';

export type PageId =
  | 'dashboard' | 'rules' | 'nat' | 'objects' | 'build' | 'compare' | 'simulator'
  | 'audit' | 'flow' | 'versions' | 'templates' | 'snapshots' | 'transfer' | 'zones' | 'reach' | 'tests'
  | 'blocklists' | 'hardening' | 'compliance';

export interface Snapshot {
  id: string;
  name: string;
  at: number;
  project: Project;
  selection: TargetSelection;
}

export interface Toast {
  id: string;
  text: string;
  tone: 'ok' | 'bad' | 'info';
}

interface State {
  project: Project;
  selection: TargetSelection;
  snapshots: Snapshot[];
  theme: 'dark' | 'light';
  past: Project[];
  future: Project[];
  page: PageId;
  selectedRuleId: string | null;
  editingRuleId: string | null;
  toasts: Toast[];
  /** Applies a change to the project and records it for undo. */
  update: (fn: (p: Project) => Project) => void;
  replaceProject: (p: Project) => void;
  undo: () => void;
  redo: () => void;
  setSelection: (s: Partial<TargetSelection>) => void;
  setTheme: (t: 'dark' | 'light') => void;
  setPage: (p: PageId) => void;
  selectRule: (id: string | null) => void;
  editRule: (id: string | null) => void;
  addSnapshot: (name: string) => void;
  restoreSnapshot: (id: string) => void;
  deleteSnapshot: (id: string) => void;
  toast: (text: string, tone?: Toast['tone']) => void;
  dismissToast: (id: string) => void;
}

const HISTORY = 60;

export const useStore = create<State>()(
  persist(
    (set, get) => ({
      project: TEMPLATES[0].build(),
      selection: DEFAULT_SELECTION,
      snapshots: [],
      theme: 'dark',
      past: [],
      future: [],
      page: 'dashboard',
      selectedRuleId: null,
      editingRuleId: null,
      toasts: [],
      update: (fn) =>
        set((s) => {
          const next = fn(s.project);
          if (next === s.project) return s;
          return { project: next, past: [...s.past.slice(-HISTORY), s.project], future: [] };
        }),
      replaceProject: (p) => set((s) => ({ project: p, past: [...s.past.slice(-HISTORY), s.project], future: [], selectedRuleId: null, editingRuleId: null })),
      undo: () =>
        set((s) => {
          if (s.past.length === 0) return s;
          return { project: s.past[s.past.length - 1], past: s.past.slice(0, -1), future: [s.project, ...s.future] };
        }),
      redo: () =>
        set((s) => {
          if (s.future.length === 0) return s;
          return { project: s.future[0], past: [...s.past, s.project], future: s.future.slice(1) };
        }),
      setSelection: (sel) => set((s) => ({ selection: { ...s.selection, ...sel } })),
      setTheme: (theme) => set({ theme }),
      setPage: (page) => set({ page }),
      selectRule: (selectedRuleId) => set({ selectedRuleId }),
      editRule: (editingRuleId) => set({ editingRuleId, selectedRuleId: editingRuleId ?? get().selectedRuleId }),
      addSnapshot: (name) =>
        set((s) => ({
          snapshots: [{ id: uid('s'), name: name || `Snapshot ${s.snapshots.length + 1}`, at: Date.now(), project: s.project, selection: s.selection }, ...s.snapshots],
        })),
      restoreSnapshot: (id) => {
        const snap = get().snapshots.find((x) => x.id === id);
        if (snap) get().replaceProject(snap.project);
      },
      deleteSnapshot: (id) => set((s) => ({ snapshots: s.snapshots.filter((x) => x.id !== id) })),
      toast: (text, tone = 'ok') => {
        const id = uid('t');
        set((s) => ({ toasts: [...s.toasts, { id, text, tone }] }));
        setTimeout(() => get().dismissToast(id), 3200);
      },
      dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
    }),
    {
      name: 'emberwall',
      version: 2,
      // Projects saved by earlier versions lack newer fields: pass them through coerceProject.
      migrate: (state: any) => {
        try {
          if (state?.project) state.project = coerceProject(state.project);
          if (Array.isArray(state?.snapshots)) state.snapshots = state.snapshots.map((x: any) => ({ ...x, project: coerceProject(x.project) }));
        } catch {
          delete state.project;
        }
        return state;
      },
      partialize: (s) => ({ project: s.project, selection: s.selection, snapshots: s.snapshots, theme: s.theme, page: s.page }),
    },
  ),
);

export function useTarget(): Target {
  const selection = useStore((s) => s.selection);
  return useMemo(() => resolveTarget(selection), [selection]);
}

export function useCompiled(): CompileResult {
  const project = useStore((s) => s.project);
  const target = useTarget();
  return useMemo(() => compile(project, target), [project, target]);
}

export function useFindings(): Finding[] {
  const project = useStore((s) => s.project);
  return useMemo(() => lint(project), [project]);
}

// ---- share links: the whole project lives in the URL fragment, nothing is uploaded ----

export function shareUrl(project: Project, selection: TargetSelection): string {
  const payload = LZString.compressToEncodedURIComponent(JSON.stringify({ project, selection }));
  return `${location.origin}${location.pathname}#s=${payload}`;
}

export function readShare(hash: string): { project: Project; selection?: TargetSelection } | null {
  const m = /[#&]s=([^&]+)/.exec(hash);
  if (!m) return null;
  try {
    const raw = JSON.parse(LZString.decompressFromEncodedURIComponent(m[1]) ?? '');
    return { project: coerceProject(raw.project), selection: raw.selection };
  } catch {
    return null;
  }
}

export function download(name: string, text: string, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}
