// Typed client for the optional Emberwall server. In the static (browser-only) app there is no
// server; `health()` returns null and the server-mode screens stay hidden.
import type { ProbeOutput } from '../core/live';
import type { Project } from '../core/model';
import type { TargetSelection, Tool } from '../core/targets';

export type Role = 'admin' | 'operator' | 'viewer';
export interface SessionUser { username: string; role: Role }
export interface Health { ok: boolean; setupNeeded: boolean; vault: boolean; user: SessionUser | null }
export interface ServerInfo {
  id: number; name: string; host: string; port: number; username: string; authKind: 'key' | 'password'; hasSecret: boolean;
  hostKeyFingerprint: string | null; tags: string; notes: string; lastTool: Tool | null; lastVersion: string | null; lastOs: string | null; lastFetchAt: number | null;
}
export interface ServerInput { name: string; host: string; port: number; username: string; authKind: 'key' | 'password'; secret?: string; passphrase?: string; tags?: string; notes?: string; forgetHostKey?: boolean }
export interface Snapshot { server: ServerInfo; output: ProbeOutput | null; fetchedAt?: number; by?: string }
export interface Deployment { id: number; serverId: number; server: string; project: string; tool: string; startedAt: number; deadline: number | null; by: string; status: 'running' | 'pending' | 'confirmed' | 'expired' | 'failed'; log: string }
export interface DeployResult { id: number; status: 'pending' | 'failed'; log: string; deadline?: number; timeoutSeconds?: number; manual: string[] }
export interface UserInfo { id: number; username: string; role: Role; disabled: number; createdAt: number }
export interface ProjectMeta { id: number; name: string; updatedAt: number; updatedBy: string }
export interface Activity { id: number; at: number; username: string; action: string; detail: string }

export class ApiError extends Error {
  constructor(public status: number, message: string, public data: Record<string, any> = {}) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Emberwall': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'The Emberwall server did not answer.');
  }
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(res.status, 'The server sent an unexpected answer.');
  }
  if (!res.ok) throw new ApiError(res.status, data?.error ?? `Request failed (${res.status}).`, data ?? {});
  return data as T;
}

export const api = {
  /** null when the app is not being served by an Emberwall server. */
  async health(): Promise<Health | null> {
    try {
      const res = await fetch('/api/health', { credentials: 'same-origin' });
      if (!res.ok || !/json/.test(res.headers.get('content-type') ?? '')) return null;
      const h = await res.json();
      return h && h.ok === true && typeof h.setupNeeded === 'boolean' ? (h as Health) : null;
    } catch {
      return null;
    }
  },
  setup: (username: string, password: string) => call<SessionUser>('POST', '/api/setup', { username, password }),
  login: (username: string, password: string) => call<SessionUser>('POST', '/api/login', { username, password }),
  logout: () => call<{ ok: true }>('POST', '/api/logout', {}),
  changePassword: (current: string, password: string) => call<{ ok: true }>('POST', '/api/me/password', { current, password }),

  users: () => call<UserInfo[]>('GET', '/api/users'),
  createUser: (username: string, password: string, role: Role) => call<{ id: number }>('POST', '/api/users', { username, password, role }),
  updateUser: (id: number, patch: { role?: Role; disabled?: boolean; password?: string }) => call<{ ok: true }>('PATCH', `/api/users/${id}`, patch),
  deleteUser: (id: number) => call<{ ok: true }>('DELETE', `/api/users/${id}`),

  servers: () => call<ServerInfo[]>('GET', '/api/servers'),
  createServer: (s: ServerInput) => call<ServerInfo>('POST', '/api/servers', s),
  updateServer: (id: number, s: Partial<ServerInput>) => call<ServerInfo>('PATCH', `/api/servers/${id}`, s),
  deleteServer: (id: number) => call<{ ok: true }>('DELETE', `/api/servers/${id}`),
  probe: (id: number, trustFingerprint?: string) => call<Snapshot>('POST', `/api/servers/${id}/probe`, { trustFingerprint }),
  snapshot: (id: number) => call<Snapshot>('GET', `/api/servers/${id}/snapshot`),

  deploy: (id: number, body: { project: Project; selection: TargetSelection; confirmName: string; timeoutSeconds: number }) => call<DeployResult>('POST', `/api/servers/${id}/deploy`, body),
  confirm: (id: number) => call<{ id: number; status: 'confirmed' | 'expired' }>('POST', `/api/deployments/${id}/confirm`, {}),
  deployments: (serverId?: number) => call<Deployment[]>('GET', `/api/deployments${serverId ? `?server=${serverId}` : ''}`),

  projects: () => call<ProjectMeta[]>('GET', '/api/projects'),
  project: (id: number) => call<ProjectMeta & { data: Project }>('GET', `/api/projects/${id}`),
  saveProject: (project: Project, id?: number, baseUpdatedAt?: number) =>
    id ? call<ProjectMeta>('PUT', `/api/projects/${id}`, { project, baseUpdatedAt }) : call<ProjectMeta>('POST', '/api/projects', { project }),
  deleteProject: (id: number) => call<{ ok: true }>('DELETE', `/api/projects/${id}`),

  activity: () => call<Activity[]>('GET', '/api/activity'),
};
