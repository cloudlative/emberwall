import { create } from 'zustand';
import { api, type Health, type ProjectMeta, type Role, type SessionUser } from '../api/client';

interface SessionState {
  /** 'checking' until the first health call returns; 'static' when there is no server. */
  mode: 'checking' | 'static' | 'server';
  health: Health | null;
  user: SessionUser | null;
  /** The server-saved project currently open, if any. */
  openProject: ProjectMeta | null;
  /** Server whose live view is open. */
  liveServerId: number | null;
  refresh: () => Promise<void>;
  setUser: (u: SessionUser | null) => void;
  setOpenProject: (p: ProjectMeta | null) => void;
  setLiveServer: (id: number | null) => void;
}

export const useSession = create<SessionState>((set) => ({
  mode: 'checking',
  health: null,
  user: null,
  openProject: null,
  liveServerId: null,
  refresh: async () => {
    const health = await api.health();
    set(health ? { mode: 'server', health, user: health.user } : { mode: 'static', health: null, user: null });
  },
  setUser: (user) => set((s) => ({ user, health: s.health ? { ...s.health, user, setupNeeded: false } : s.health })),
  setOpenProject: (openProject) => set({ openProject }),
  setLiveServer: (liveServerId) => set({ liveServerId }),
}));

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
export const can = (user: SessionUser | null, role: Role) => !!user && RANK[user.role] >= RANK[role];
