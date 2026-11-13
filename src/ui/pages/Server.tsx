import { AlertTriangle, ArrowRight, Check, KeyRound, Loader2, LogIn, Pencil, Plus, RefreshCw, Server as ServerIcon, ShieldCheck, Trash2, Upload, UserPlus, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError, type Activity, type Deployment, type DeployResult, type ProjectMeta, type Role, type ServerInfo, type ServerInput, type Snapshot, type UserInfo } from '../../api/client';
import { compile, fileText } from '../../core/compile';
import { assess } from '../../core/compliance';
import { diffLines, diffStats } from '../../core/diff';
import { grade, lint, score } from '../../core/lint';
import { filterTables } from '../../core/import/nft';
import { detect, readLiveConfig } from '../../core/live';
import { semanticDiff } from '../../core/reach';
import { resolveTarget, TOOL_LABEL } from '../../core/targets';
import { can, useSession } from '../../store/useSession';
import { useEffectiveProject, useSelection, useStore } from '../../store/useStore';
import { CodeView, DiffView } from '../components/CodeView';
import { ruleSummary } from './Rules';
import { ActionBadge, Empty, Field, Modal, PageHeader, Panel, Segmented, SeverityBadge, Stat } from '../components/ui';

const when = (t: number | null | undefined) => (t ? new Date(t).toLocaleString() : 'never');
const errText = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong.');

function useLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const reload = useCallback(() => {
    load().then((d) => { setData(d); setError(''); }).catch((e) => setError(errText(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(reload, [reload]);
  return { data, error, reload };
}

// ---------- sign in / first-run setup ----------

export function LoginGate() {
  const health = useSession((s) => s.health);
  const setUser = useSession((s) => s.setUser);
  const setup = !!health?.setupNeeded;
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (setup && password !== again) return setError('The two passwords are different.');
    setBusy(true);
    setError('');
    try {
      setUser(setup ? await api.setup(username.trim(), password) : await api.login(username.trim(), password));
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="relative z-10 grid h-full place-items-center overflow-y-auto p-4">
      <form onSubmit={submit} className="glass-strong w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="h-10 w-10" aria-hidden>
            <defs><linearGradient id="lg2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#ffb38a" /><stop offset="1" stopColor="#ec4f17" /></linearGradient></defs>
            <path d="M16 2l11 4.200v8.800c0 6.800-4.600 11.800-11 14-6.400-2.200-11-7.200-11-14v-8.800z" fill="url(#lg2)" />
          </svg>
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight">{setup ? 'Set up Emberwall' : 'Sign in to Emberwall'}</h1>
            <p className="text-[12.5px] text-mute">{setup ? 'Create the first administrator account.' : 'Use your team account.'}</p>
          </div>
        </div>
        <Field label="User name"><input autoFocus className="field" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="Password" className="mt-3" hint={setup ? 'At least 10 characters.' : undefined}><input type="password" className="field" autoComplete={setup ? 'new-password' : 'current-password'} value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        {setup && <Field label="Repeat password" className="mt-3"><input type="password" className="field" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></Field>}
        {error && <p role="alert" className="mt-3 text-[12.5px]" style={{ color: 'var(--bad)' }}>{error}</p>}
        <button className="btn btn-primary mt-5 w-full !py-2" disabled={busy || !username.trim() || !password}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <LogIn size={15} />} {setup ? 'Create administrator' : 'Sign in'}
        </button>
        {setup && health && !health.vault && (
          <p className="mt-4 flex gap-2 text-[12px] leading-snug text-mute"><AlertTriangle size={14} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />The server was started without EMBERWALL_SECRET, so SSH credentials cannot be saved until it is set.</p>
        )}
      </form>
    </div>
  );
}

// ---------- inventory ----------

const EMPTY: ServerInput = { name: '', host: '', port: 22, username: 'root', authKind: 'key', secret: '', passphrase: '', tags: '', notes: '' };

function ServerForm({ initial, onClose, onSaved }: { initial: ServerInfo | null; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<ServerInput>(initial ? { name: initial.name, host: initial.host, port: initial.port, username: initial.username, authKind: initial.authKind, secret: '', passphrase: '', tags: initial.tags, notes: initial.notes } : EMPTY);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const vault = useSession((s) => s.health?.vault);
  const set = (p: Partial<ServerInput>) => setF({ ...f, ...p });
  const save = async () => {
    setBusy(true);
    setError('');
    try {
      const body = { ...f, secret: f.secret || undefined, passphrase: f.passphrase || undefined };
      if (initial) await api.updateServer(initial.id, body);
      else await api.createServer(body);
      onSaved();
      onClose();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open onClose={onClose} wide title={initial ? `Edit ${initial.name}` : 'Add a server'} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy || !f.name || !f.host || !f.username} onClick={save}>{initial ? 'Save' : 'Add server'}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><input autoFocus className="field" placeholder="web-1" value={f.name} onChange={(e) => set({ name: e.target.value })} /></Field>
        <Field label="Tags"><input className="field" placeholder="prod, web" value={f.tags} onChange={(e) => set({ tags: e.target.value })} /></Field>
        <Field label="Address"><input className="field font-mono" placeholder="203.0.113.10 or host name" value={f.host} onChange={(e) => set({ host: e.target.value.trim() })} /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="SSH port"><input type="number" className="field font-mono" value={f.port} onChange={(e) => set({ port: Number(e.target.value) })} /></Field>
          <Field label="SSH user"><input className="field font-mono" value={f.username} onChange={(e) => set({ username: e.target.value.trim() })} /></Field>
        </div>
        <Field label="Sign in with" className="sm:col-span-2">
          <Segmented value={f.authKind} onChange={(authKind) => set({ authKind, secret: '' })} options={[{ value: 'key', label: 'Private key' }, { value: 'password', label: 'Password' }]} />
        </Field>
        {f.authKind === 'key' ? (
          <>
            <Field label={initial?.hasSecret ? 'Replace private key (leave empty to keep the stored one)' : 'Private key'} className="sm:col-span-2" hint="OpenSSH or PEM format. A key used only by Emberwall is best.">
              <textarea className="field h-28 resize-y font-mono text-[11.5px]" spellCheck={false} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={f.secret} onChange={(e) => set({ secret: e.target.value })} />
            </Field>
            <Field label="Key passphrase (if it has one)"><input type="password" autoComplete="off" className="field" value={f.passphrase} onChange={(e) => set({ passphrase: e.target.value })} /></Field>
          </>
        ) : (
          <Field label={initial?.hasSecret ? 'Replace password (leave empty to keep)' : 'Password'}><input type="password" autoComplete="off" className="field" value={f.secret} onChange={(e) => set({ secret: e.target.value })} /></Field>
        )}
        <Field label="Notes" className="sm:col-span-2"><input className="field" value={f.notes} onChange={(e) => set({ notes: e.target.value })} /></Field>
      </div>
      <p className="mt-4 flex gap-2 text-[12px] leading-snug text-mute">
        <KeyRound size={14} className="mt-0.5 flex-none" />
        <span>The credential is encrypted on the Emberwall server and is never sent back to a browser. The SSH user needs root, or passwordless sudo for the firewall commands.{vault === false && <b style={{ color: 'var(--warn)' }}> This server has no master key, so saving a credential will fail.</b>}</span>
      </p>
      {error && <p role="alert" className="mt-3 text-[12.5px]" style={{ color: 'var(--bad)' }}>{error}</p>}
    </Modal>
  );
}

export function ServersPage() {
  const user = useSession((s) => s.user);
  const setLive = useSession((s) => s.setLiveServer);
  const { setPage, toast } = useStore.getState();
  const { data, error, reload } = useLoad(api.servers);
  const [editing, setEditing] = useState<ServerInfo | 'new' | null>(null);
  const edit = can(user, 'operator');
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Servers" sub="The machines Emberwall can reach over SSH. Open one to read its running firewall, audit it, compare it with the project, or push a build.">
        {edit && <button className="btn btn-primary" onClick={() => setEditing('new')}><Plus size={15} /> Add server</button>}
      </PageHeader>
      {error && <p className="mb-3 text-[13px]" style={{ color: 'var(--bad)' }}>{error}</p>}
      {data && data.length === 0 ? (
        <div className="glass"><Empty icon={<ServerIcon size={22} />} title="No servers yet">{edit ? 'Add a server with its address and an SSH credential.' : 'An operator or administrator can add servers.'}</Empty></div>
      ) : (
        <div className="space-y-3">
          {(data ?? []).map((s) => (
            <section key={s.id} className="glass flex flex-wrap items-center gap-3 px-4 py-3">
              <ServerIcon size={18} className="flex-none text-ember-400" />
              <div className="min-w-[200px] flex-1">
                <div className="flex flex-wrap items-center gap-2 text-[14px] font-semibold">{s.name}{s.tags.split(/[\s,]+/).filter(Boolean).map((t) => <span key={t} className="chip">{t}</span>)}</div>
                <div className="font-mono text-[12px] text-mute">{s.username}@{s.host}:{s.port}</div>
              </div>
              <div className="min-w-[220px] text-[12px] text-mute">
                <div>{s.lastTool ? <><b className="font-semibold text-ink">{TOOL_LABEL[s.lastTool]} {s.lastVersion}</b> · {s.lastOs}</> : 'Not read yet'}</div>
                <div>Last read: {when(s.lastFetchAt)}</div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {!s.hasSecret && <span className="badge badge-warn">no credential</span>}
                <span className={`badge ${s.hostKeyFingerprint ? 'badge-ok' : 'badge-mute'}`} title={s.hostKeyFingerprint ?? 'The host key is approved on first connection'}>{s.hostKeyFingerprint ? 'host key pinned' : 'host key not yet seen'}</span>
                <button className="btn btn-primary" onClick={() => { setLive(s.id); setPage('live'); }}>Open <ArrowRight size={14} /></button>
                {edit && <button className="btn btn-icon" aria-label={`Edit ${s.name}`} onClick={() => setEditing(s)}><Pencil size={14} /></button>}
                {edit && <button className="btn btn-ghost btn-icon" aria-label={`Delete ${s.name}`} onClick={async () => {
                  if (!window.confirm(`Remove ${s.name} from the inventory? Its stored credential and history are deleted. Nothing changes on the server itself.`)) return;
                  try { await api.deleteServer(s.id); toast(`${s.name} removed`); reload(); } catch (e) { toast(errText(e), 'bad'); }
                }}><Trash2 size={14} /></button>}
              </div>
            </section>
          ))}
        </div>
      )}
      {editing && <ServerForm initial={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={reload} />}
    </div>
  );
}

// ---------- live view ----------

type LiveTab = 'rules' | 'raw' | 'audit' | 'drift' | 'push' | 'history';

function PushPanel({ server, snapshot, onDone }: { server: ServerInfo; snapshot: Snapshot; onDone: () => void }) {
  const project = useEffectiveProject();
  const selection = useSelection();
  const { setSelection, toast } = useStore.getState();
  const d = useMemo(() => detect(snapshot.output!), [snapshot]);
  const target = useMemo(() => resolveTarget(selection), [selection]);
  const result = useMemo(() => compile(project, target), [project, target]);
  const errors = result.diagnostics.filter((x) => x.level === 'error');
  const adapted = result.diagnostics.filter((x) => x.kind === 'fallback' || x.kind === 'unsupported');
  const [name, setName] = useState('');
  const [timeout, setTimeoutS] = useState(60);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [run, setRun] = useState<DeployResult | null>(null);
  const [state, setState] = useState<'pending' | 'confirmed' | 'expired' | 'failed' | null>(null);
  const [left, setLeft] = useState(0);
  const others = useMemo(() => (snapshot.output?.nftRuleset?.code === 0 ? filterTables(snapshot.output.nftRuleset.stdout).filter((t) => t !== 'inet emberwall') : []), [snapshot]);
  const toolMismatch = !!d.activeTool && d.activeTool !== target.tool;
  const versionMismatch = !toolMismatch && !!d.activeTool && d.versions[d.activeTool] !== undefined && d.selection !== null && resolveTarget(d.selection).version !== target.version;

  useEffect(() => {
    if (state !== 'pending' || !run?.deadline) return;
    const tick = () => {
      const s = Math.max(0, Math.round((run.deadline! - Date.now()) / 1000));
      setLeft(s);
      if (s === 0) setState('expired');
    };
    tick();
    const t = setInterval(tick, 500);
    return () => clearInterval(t);
  }, [state, run]);

  const push = async () => {
    setBusy(true);
    setError('');
    setRun(null);
    try {
      const r = await api.deploy(server.id, { project, selection, confirmName: name, timeoutSeconds: timeout });
      setRun(r);
      setState(r.status);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async () => {
    setBusy(true);
    setError('');
    try {
      const r = await api.confirm(run!.id);
      setState(r.status);
      if (r.status === 'confirmed') {
        toast(`New rules are live on ${server.name}`);
        onDone();
      }
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="1 · Check" hint={`Pushing "${project.name}" built for ${target.label}`}>
        <ul className="space-y-2 text-[12.5px]">
          <Line ok={!toolMismatch} good={`The build is for ${TOOL_LABEL[target.tool]}, which is what this server runs.`} bad={`This server runs ${d.activeTool ? TOOL_LABEL[d.activeTool] : 'no known firewall'}, but the build is for ${TOOL_LABEL[target.tool]}.`} />
          {!toolMismatch && <Line ok={!versionMismatch} warn good={`Build version matches the server (${target.version}).`} bad={`The server has ${d.activeTool ? d.versions[d.activeTool] : '?'}, the build targets ${target.version}.`} />}
          <Line ok={errors.length === 0} good="The build has no errors." bad={`The build has ${errors.length} error${errors.length === 1 ? '' : 's'}: ${errors[0]?.message ?? ''}`} />
          <Line ok={adapted.length === 0} warn good="Every rule maps cleanly onto this target." bad={`${adapted.length} thing${adapted.length === 1 ? ' is' : 's are'} adapted or left out for this target (see Build).`} />
          {target.tool === 'nftables' && others.length > 0 && <Line ok={false} warn good="" bad={`Emberwall replaces only its own table. ${others.join(', ')} will keep filtering traffic alongside it; remove ${others.length === 1 ? 'it' : 'them'} on the server if the new ruleset should be the only one.`} />}
          <Line ok={!d.needsPrivilege} good="The SSH user can manage the firewall." bad="The SSH user cannot manage the firewall (needs root or passwordless sudo)." />
        </ul>
        {(toolMismatch || versionMismatch) && d.selection && <button className="btn mt-3" onClick={() => setSelection(d.selection!)}>Build for this server ({TOOL_LABEL[d.selection.tool]} {resolveTarget(d.selection).version})</button>}
      </Panel>
      <Panel title="2 · Push with automatic rollback" hint="The server reverts by itself unless Emberwall can reconnect and you confirm">
        {!run || state === 'failed' ? (
          <>
            <ol className="mb-3 list-decimal space-y-1 pl-4 text-[12.5px] leading-relaxed text-ink/90">
              <li>The running rules are backed up on the server and the new ones are checked.</li>
              <li>A rollback timer is started on the server, then the new rules are applied.</li>
              <li>You confirm. Emberwall opens a <b>new</b> SSH connection for that, so a ruleset that locks it out can never be confirmed.</li>
            </ol>
            <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
              <Field label={`Type the server name (${server.name}) to enable the push`}><input className="field font-mono" value={name} onChange={(e) => setName(e.target.value)} /></Field>
              <Field label="Roll back after"><select className="field" value={timeout} onChange={(e) => setTimeoutS(Number(e.target.value))}>{[30, 60, 120, 300].map((s) => <option key={s} value={s}>{s} seconds</option>)}</select></Field>
            </div>
            <button className="btn btn-primary mt-3" disabled={busy || name !== server.name || toolMismatch || errors.length > 0 || d.needsPrivilege} onClick={push}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Upload size={15} />} {busy ? 'Pushing…' : `Push to ${server.name}`}
            </button>
          </>
        ) : state === 'pending' ? (
          <div>
            <div className="flex items-center gap-3">
              <div className="grid h-16 w-16 flex-none place-items-center rounded-2xl text-[22px] font-semibold" style={{ background: 'color-mix(in srgb, var(--warn) 16%, transparent)', color: 'var(--warn)' }}>{left}</div>
              <div><div className="text-[15px] font-semibold">Applied. Confirm to keep the new rules.</div><div className="text-[12.5px] text-mute">Without confirmation the server restores its previous rules in {left} seconds.</div></div>
            </div>
            <button className="btn btn-primary mt-4 !py-2" disabled={busy} onClick={confirm}>{busy ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />} Confirm: keep the new rules</button>
            <span className="ml-3 text-[12px] text-mute">Do nothing to roll back.</span>
          </div>
        ) : state === 'confirmed' ? (
          <div className="flex items-center gap-3"><ShieldCheck size={28} style={{ color: 'var(--ok)' }} /><div><div className="text-[15px] font-semibold">Confirmed. The new rules are live.</div><div className="text-[12.5px] text-mute">Emberwall reconnected over a new SSH session before confirming.</div></div></div>
        ) : (
          <div className="flex items-center gap-3"><X size={28} style={{ color: 'var(--bad)' }} /><div><div className="text-[15px] font-semibold">Not confirmed in time.</div><div className="text-[12.5px] text-mute">The server restored its previous rules on its own. Read it again to verify.</div></div></div>
        )}
        {error && <p role="alert" className="mt-3 text-[12.5px]" style={{ color: 'var(--bad)' }}>{error}</p>}
        {run && run.manual.length > 0 && state !== 'failed' && <p className="mt-3 text-[12px] text-mute">Not installed by this push (install by hand if you need them): <span className="font-mono">{run.manual.join(', ')}</span></p>}
        {run && <pre className="code mt-3 max-h-56 overflow-auto p-3 text-[11.5px]">{run.log}</pre>}
        {(state === 'confirmed' || state === 'expired') && <button className="btn mt-3" onClick={() => { setRun(null); setState(null); setName(''); }}>New push</button>}
      </Panel>
    </div>
  );
}

function Line({ ok, good, bad, warn = false }: { ok: boolean; good: string; bad: string; warn?: boolean }) {
  return (
    <li className="flex gap-2">
      {ok ? <Check size={15} className="mt-0.5 flex-none" style={{ color: 'var(--ok)' }} /> : warn ? <AlertTriangle size={15} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} /> : <X size={15} className="mt-0.5 flex-none" style={{ color: 'var(--bad)' }} />}
      <span>{ok ? good : bad}</span>
    </li>
  );
}

export function LivePage() {
  const user = useSession((s) => s.user);
  const serverId = useSession((s) => s.liveServerId);
  const setLive = useSession((s) => s.setLiveServer);
  const project = useEffectiveProject();
  const selection = useSelection();
  const { replaceProject, setSelection, setActiveHost, setPage, toast } = useStore.getState();
  const servers = useLoad(api.servers);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [hostKey, setHostKey] = useState<{ kind: 'unknown' | 'changed'; fingerprint: string; pinned: string | null } | null>(null);
  const [tab, setTab] = useState<LiveTab>('rules');
  const [history, setHistory] = useState<Deployment[]>([]);
  const operator = can(user, 'operator');

  const loadHistory = useCallback(() => { if (serverId) api.deployments(serverId).then(setHistory).catch(() => undefined); }, [serverId]);
  useEffect(() => {
    setSnap(null);
    setError('');
    if (!serverId) return;
    api.snapshot(serverId).then(setSnap).catch((e) => setError(errText(e)));
    loadHistory();
  }, [serverId, loadHistory]);

  const fetchLive = async (trust?: string) => {
    if (!serverId) return;
    setBusy(true);
    setError('');
    try {
      setSnap(await api.probe(serverId, trust));
      setHostKey(null);
      servers.reload();
      toast('Read the running configuration');
    } catch (e) {
      if (e instanceof ApiError && e.data.code === 'host_key') setHostKey({ kind: e.data.kind, fingerprint: e.data.fingerprint, pinned: e.data.pinned });
      else setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const d = useMemo(() => (snap?.output ? detect(snap.output) : null), [snap]);
  const live = useMemo(() => (snap?.output && d?.activeTool ? readLiveConfig(snap.output, d.activeTool) : null), [snap, d]);
  const findings = useMemo(() => (live ? lint(live.report.project) : []), [live]);
  const liveScore = score(findings);
  const comp = useMemo(() => (live ? assess(live.report.project, 'internet') : null), [live]);
  const drift = useMemo(() => {
    if (!live || !d) return null;
    const access = semanticDiff(live.report.project, project);
    const sameTool = resolveTarget(selection).tool === live.tool;
    const built = sameTool ? fileText(compile(project, resolveTarget(selection)).files[0]).trimEnd() : null;
    const lines = built !== null ? diffLines(live.raw[0].text.trimEnd(), built) : null;
    return { access, lines, sameTool };
  }, [live, d, project, selection]);

  const server = servers.data?.find((s) => s.id === serverId) ?? snap?.server ?? null;

  if (!serverId || !server) {
    return (
      <div className="h-full overflow-y-auto pr-1">
        <PageHeader title="Live server" sub="Pick a server to read its running firewall." />
        <div className="glass p-4">
          {(servers.data ?? []).length === 0 ? <Empty icon={<ServerIcon size={22} />} title="No servers in the inventory"><button className="btn mt-2" onClick={() => setPage('servers')}>Open Servers</button></Empty> : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {servers.data!.map((s) => <button key={s.id} className="tile px-3 py-2.5 text-left" onClick={() => setLive(s.id)}><div className="text-[13.5px] font-semibold">{s.name}</div><div className="font-mono text-[12px] text-mute">{s.username}@{s.host}</div></button>)}
            </div>
          )}
        </div>
      </div>
    );
  }

  const tabs: { value: LiveTab; label: ReactNode }[] = [
    { value: 'rules', label: <>Rules {live && <span className="ml-1 font-mono text-[11px] text-mute">{live.report.project.rules.length}</span>}</> },
    { value: 'raw', label: 'Raw config' },
    { value: 'audit', label: <>Audit {live && <span className="ml-1 font-mono text-[11px] text-mute">{liveScore}</span>}</> },
    { value: 'drift', label: <>Drift {drift && drift.access.length > 0 && <span className="badge badge-warn ml-1">{drift.access.length}</span>}</> },
    ...(operator ? [{ value: 'push' as LiveTab, label: 'Push' }] : []),
    { value: 'history', label: 'History' },
  ];

  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title={server.name} sub={`${server.username}@${server.host}:${server.port} · last read ${when(snap?.fetchedAt)}${snap?.by ? ` by ${snap.by}` : ''}`}>
        <select aria-label="Server" className="field !w-auto" value={serverId} onChange={(e) => setLive(Number(e.target.value))}>
          {(servers.data ?? [server]).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        {operator && <button className="btn btn-primary" disabled={busy} onClick={() => fetchLive()}>{busy ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />} {busy ? 'Reading…' : 'Read live config'}</button>}
      </PageHeader>
      {error && <div role="alert" className="glass mb-4 flex gap-2 px-4 py-3 text-[13px]" style={{ borderColor: 'color-mix(in srgb, var(--bad) 50%, transparent)' }}><AlertTriangle size={16} className="mt-0.5 flex-none" style={{ color: 'var(--bad)' }} />{error}</div>}

      {!snap?.output || !d ? (
        <div className="glass"><Empty icon={<RefreshCw size={22} />} title="Nothing read yet">{operator ? 'Press “Read live config” to connect over SSH. Only read-only commands are run.' : 'An operator has not read this server yet.'}</Empty></div>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="System" value={<span className="text-[16px]">{d.os}</span>} sub={`kernel ${d.kernel}`} />
            <Stat label="Firewall in charge" value={<span className="text-[18px]">{d.activeTool ? `${TOOL_LABEL[d.activeTool]} ${d.versions[d.activeTool] ?? ''}` : 'none found'}</span>} sub={d.reason} tone={d.activeTool ? 'ok' : 'warn'} />
            <Stat label="Live audit score" value={live ? liveScore : '—'} sub={live ? `Grade ${grade(liveScore)} · ${findings.filter((f) => f.severity !== 'info').length} findings` : undefined} tone={!live ? undefined : liveScore >= 75 ? 'ok' : liveScore >= 50 ? 'warn' : 'bad'} />
            <Stat label="Differs from project" value={drift ? drift.access.length : '—'} sub={drift ? (drift.access.length === 0 ? 'same access as the project' : 'paths with different access') : undefined} tone={drift && drift.access.length === 0 ? 'ok' : 'warn'} />
          </div>
          {live?.report.notes?.map((n) => <div key={n} className="glass mb-4 flex gap-2 px-4 py-3 text-[13px]"><AlertTriangle size={16} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />{n}</div>)}
          {d.needsPrivilege && <div className="glass mb-4 flex gap-2 px-4 py-3 text-[13px]"><AlertTriangle size={16} className="mt-0.5 flex-none" style={{ color: 'var(--warn)' }} />The SSH user could not read the ruleset. Connect as root, or give this user passwordless sudo for the firewall commands.</div>}
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <Segmented value={tab} onChange={setTab} options={tabs} />
            <div className="flex flex-wrap gap-2">
              {d.selection && <button className="btn" onClick={() => { setActiveHost(null); setSelection(d.selection!); toast(`Build target set to ${TOOL_LABEL[d.selection!.tool]} ${resolveTarget(d.selection!).version}`); }}>Use as build target</button>}
              {live && operator && <button className="btn" onClick={() => { if (window.confirm('Replace the project that is open with this server\'s running rules? Undo brings it back.')) { replaceProject({ ...live.report.project, name: `${server.name} (live)` }); if (d.selection) { setActiveHost(null); setSelection(d.selection); } setPage('rules'); toast('Live rules opened as the project'); } }}>Adopt as project</button>}
            </div>
          </div>

          {!live ? <div className="glass"><Empty icon={<AlertTriangle size={22} />} title="No ruleset to show">{d.reason}</Empty></div> : tab === 'rules' ? (
            <Panel title="Rules read from the server" hint={`${live.report.project.rules.length} rules · ${live.report.project.nat.length} NAT · inbound policy ${live.report.project.policies.in}${live.report.skipped.length ? ` · ${live.report.skipped.length} lines not understood` : ''}`}>
              {live.report.project.rules.length === 0 ? <p className="py-6 text-center text-[13px] text-mute">No rules beyond the default policies.</p> : (
                <ul className="space-y-1.5">
                  {live.report.project.rules.map((r, i) => {
                    const s = ruleSummary(r, live.report.project);
                    return (
                      <li key={r.id} className="tile flex items-center gap-3 px-3 py-2">
                        <span className="w-6 flex-none text-center font-mono text-[11px] text-mute">{i + 1}</span>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-[13px] font-medium">{r.name}</div>
                          <div className="flex flex-wrap items-center gap-1 text-[11.5px] text-mute"><span className="chip">{r.direction}</span><span className="chip">{r.proto}</span>{s.ports.map((p) => <span key={p} className="chip">{p}</span>)}<span>{s.src} → {s.dst}</span>{r.inIface && <span className="chip">in {r.inIface}</span>}</div>
                        </div>
                        <ActionBadge action={r.action} />
                      </li>
                    );
                  })}
                </ul>
              )}
              {live.report.skipped.length > 0 && (
                <div className="mt-4">
                  <div className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--warn)' }}>Not understood ({live.report.skipped.length}) — these lines are on the server but not in the view above</div>
                  <div className="code max-h-48 overflow-auto p-3 text-[11.5px]">{live.report.skipped.map((s, i) => <div key={i} className="mb-1.5"><span style={{ color: 'var(--warn)' }}>{s.reason}</span><br /><span className="text-mute">{s.line}</span></div>)}</div>
                </div>
              )}
            </Panel>
          ) : tab === 'raw' ? (
            <div className="space-y-4">{live.raw.map((f) => <Panel key={f.name} title={f.name} hint={`${f.text.split('\n').length} lines, exactly as the server returned it`}><CodeView lines={(f.text || '(empty)').trimEnd().split('\n').map((text) => ({ text }))} lang={live.tool === 'nftables' ? 'nft' : live.tool === 'firewalld' ? 'xml' : live.tool === 'ufw' ? 'shell' : 'iptables'} className="max-h-[60vh]" /></Panel>)}</div>
          ) : tab === 'audit' ? (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
              <Panel title="Findings on the running ruleset" hint="The same checks as the Audit page, applied to what the server actually runs">
                {findings.length === 0 ? <p className="py-6 text-center text-[13px] text-mute">Nothing to report.</p> : (
                  <ul className="space-y-2">{findings.map((f) => <li key={f.id} className="tile flex items-start gap-3 px-3 py-2.5"><div className="w-[76px] flex-none pt-0.5"><SeverityBadge severity={f.severity} /></div><div><div className="text-[13px] font-semibold">{f.title}</div><div className="text-[12.5px] leading-snug text-mute">{f.detail}</div></div></li>)}</ul>
                )}
              </Panel>
              {comp && (
                <Panel title={`${comp.profile.name}: ${comp.percent}%`} hint={`${comp.passed} passed, ${comp.failed} failed`}>
                  <ul className="space-y-1.5">{comp.results.map((r) => <li key={r.id} className="flex items-start gap-2 text-[12.5px]">{r.status === 'pass' ? <Check size={14} className="mt-0.5 flex-none" style={{ color: 'var(--ok)' }} /> : r.status === 'fail' ? <X size={14} className="mt-0.5 flex-none" style={{ color: 'var(--bad)' }} /> : <span className="w-[14px] flex-none text-center text-mute">–</span>}<span><b className="font-semibold">{r.title}.</b> <span className="text-mute">{r.evidence}</span></span></li>)}</ul>
                  <p className="mt-3 text-[12px] text-mute">Kernel hardening and policy tests are project settings; the server's own sysctl values are not read.</p>
                </Panel>
              )}
            </div>
          ) : tab === 'drift' && drift ? (
            <div className="space-y-4">
              <Panel title="Access that differs" hint={`Live server compared with the project "${project.name}"`}>
                {drift.access.length === 0 ? <p className="flex items-center gap-2 py-3 text-[13px]"><Check size={16} style={{ color: 'var(--ok)' }} /> The server allows and blocks the same traffic as the project, for the sources and services the rules mention.</p> : (
                  <ul className="space-y-1.5 text-[12.5px]">{drift.access.map((c, i) => (
                    <li key={i} className="tile flex flex-wrap items-center gap-2 px-3 py-2">
                      <span className={`badge ${c.kind === 'opened' ? 'badge-warn' : 'badge-info'}`}>{c.kind === 'opened' ? 'project opens' : 'project closes'}</span>
                      <span>{c.source.label} → {c.target.label}, {c.service.label}{c.family === 'ipv6' && <span className="badge badge-mute ml-1.5">IPv6</span>}</span>
                      <span className="text-mute">live: {c.before}, project: {c.after}</span>
                    </li>
                  ))}</ul>
                )}
              </Panel>
              {drift.lines ? (
                <Panel title="Configuration diff" hint={`Red: only on the server. Green: only in the project's build. +${diffStats(drift.lines).added} / −${diffStats(drift.lines).removed} lines`}>
                  <DiffView lines={drift.lines} lang={live.tool === 'nftables' ? 'nft' : live.tool === 'firewalld' ? 'shell' : live.tool === 'ufw' ? 'shell' : 'iptables'} className="max-h-[56vh]" />
                </Panel>
              ) : <p className="text-[12.5px] text-mute">The project is being built for a different tool than this server runs, so a line-by-line diff would not mean anything. Use “Use as build target”.</p>}
            </div>
          ) : tab === 'push' && operator ? (
            <PushPanel server={server} snapshot={snap} onDone={() => { loadHistory(); void fetchLive(); }} />
          ) : (
            <Panel title="Push history" actions={<button className="btn btn-ghost" onClick={loadHistory}><RefreshCw size={13} /> Refresh</button>}>
              {history.length === 0 ? <p className="py-6 text-center text-[13px] text-mute">Nothing has been pushed to this server from Emberwall.</p> : (
                <ul className="space-y-2">{history.map((h) => (
                  <li key={h.id} className="tile px-3 py-2.5">
                    <details>
                      <summary className="flex cursor-pointer flex-wrap items-center gap-2 text-[13px]">
                        <span className={`badge ${h.status === 'confirmed' ? 'badge-ok' : h.status === 'pending' ? 'badge-warn' : 'badge-bad'}`}>{h.status === 'expired' ? 'rolled back' : h.status}</span>
                        <b className="font-semibold">#{h.id} {h.project}</b><span className="text-mute">{h.tool} · {h.by} · {when(h.startedAt)}</span>
                      </summary>
                      <pre className="code mt-2 max-h-56 overflow-auto p-3 text-[11.5px]">{h.log}</pre>
                    </details>
                  </li>
                ))}</ul>
              )}
            </Panel>
          )}
        </>
      )}

      <Modal open={!!hostKey} onClose={() => setHostKey(null)} title={hostKey?.kind === 'changed' ? 'Host key has changed' : 'Approve this server\'s host key'}
        footer={hostKey?.kind === 'unknown' ? <><button className="btn" onClick={() => setHostKey(null)}>Cancel</button><button className="btn btn-primary" disabled={busy} onClick={() => fetchLive(hostKey.fingerprint)}>It matches, trust it</button></> : <button className="btn" onClick={() => setHostKey(null)}>Close</button>}>
        {hostKey?.kind === 'unknown' ? (
          <>
            <p className="text-[13px] leading-relaxed">Emberwall has not connected to <b>{server.name}</b> before. Compare this fingerprint with the server's own (run <code className="chip">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on its console) before trusting it.</p>
            <pre className="code mt-3 overflow-x-auto p-3 text-[12px]">{hostKey.fingerprint}</pre>
            <p className="mt-3 text-[12px] text-mute">After this, a different key will block the connection.</p>
          </>
        ) : hostKey ? (
          <>
            <p className="flex gap-2 text-[13px] leading-relaxed"><AlertTriangle size={18} className="mt-0.5 flex-none" style={{ color: 'var(--bad)' }} /><span>The machine answering at {server.host} presented a different host key from the one approved earlier. The connection was refused. This happens after a reinstall, or when something is intercepting the connection.</span></p>
            <div className="mt-3 text-[12px] text-mute">Approved earlier</div><pre className="code overflow-x-auto p-2 text-[12px]">{hostKey.pinned}</pre>
            <div className="mt-2 text-[12px] text-mute">Presented now</div><pre className="code overflow-x-auto p-2 text-[12px]">{hostKey.fingerprint}</pre>
            {operator && <button className="btn mt-4" onClick={async () => { if (!window.confirm('Only do this if you know why the key changed (for example, the server was reinstalled). Forget the approved key?')) return; await api.updateServer(server.id, { forgetHostKey: true }); setHostKey(null); servers.reload(); toast('Approved key forgotten; read again to review the new one'); }}>The server was reinstalled: forget the old key</button>}
          </>
        ) : null}
      </Modal>
    </div>
  );
}

// ---------- team projects ----------

export function ProjectsPage() {
  const user = useSession((s) => s.user);
  const open = useSession((s) => s.openProject);
  const setOpen = useSession((s) => s.setOpenProject);
  const project = useStore((s) => s.project);
  const { replaceProject, toast, setPage } = useStore.getState();
  const { data, error, reload } = useLoad(api.projects);
  const edit = can(user, 'operator');
  const save = async (asNew: boolean) => {
    try {
      const meta = await api.saveProject(project, asNew ? undefined : open?.id, asNew ? undefined : open?.updatedAt);
      setOpen(meta);
      toast(`Saved "${meta.name}" for the team`);
      reload();
    } catch (e) {
      toast(errText(e), 'bad');
    }
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Team projects" sub="Rulesets saved on the Emberwall server and shared by everyone who signs in. The project you edit still lives in your browser until you save it here.">
        {edit && open && <button className="btn btn-primary" onClick={() => save(false)}><Upload size={15} /> Save “{open.name}”</button>}
        {edit && <button className={open ? 'btn' : 'btn btn-primary'} onClick={() => save(true)}><Plus size={15} /> Save current as new</button>}
      </PageHeader>
      {error && <p className="mb-3 text-[13px]" style={{ color: 'var(--bad)' }}>{error}</p>}
      <Panel title={`${data?.length ?? 0} saved`} hint={open ? `Open now: ${open.name}` : `Editing a local project: ${project.name}`}>
        {(data ?? []).length === 0 ? <Empty icon={<Upload size={22} />} title="Nothing saved yet">Save the ruleset you are working on to share it.</Empty> : (
          <ul className="space-y-2">{data!.map((p: ProjectMeta) => (
            <li key={p.id} className="tile flex flex-wrap items-center gap-3 px-3.5 py-2.5" style={open?.id === p.id ? { borderColor: 'rgba(255,143,92,0.6)' } : undefined}>
              <div className="min-w-[200px] flex-1"><div className="text-[13.5px] font-semibold">{p.name}</div><div className="text-[12px] text-mute">saved {when(p.updatedAt)} by {p.updatedBy}</div></div>
              <button className="btn" onClick={async () => { try { const full = await api.project(p.id); replaceProject(full.data); setOpen({ id: full.id, name: full.name, updatedAt: full.updatedAt, updatedBy: full.updatedBy }); toast(`Opened "${full.name}"`); setPage('rules'); } catch (e) { toast(errText(e), 'bad'); } }}>Open</button>
              {edit && <button className="btn btn-ghost btn-icon" aria-label={`Delete ${p.name}`} onClick={async () => { if (!window.confirm(`Delete "${p.name}" for everyone?`)) return; try { await api.deleteProject(p.id); if (open?.id === p.id) setOpen(null); reload(); } catch (e) { toast(errText(e), 'bad'); } }}><Trash2 size={14} /></button>}
            </li>
          ))}</ul>
        )}
      </Panel>
    </div>
  );
}

// ---------- users and activity ----------

const ROLE_HELP: Record<Role, string> = { admin: 'Everything, including users', operator: 'Edit, connect to servers, push', viewer: 'Read only' };

export function UsersPage() {
  const me = useSession((s) => s.user);
  const toast = useStore((s) => s.toast);
  const { data, error, reload } = useLoad(api.users);
  const [f, setF] = useState({ username: '', password: '', role: 'operator' as Role });
  const [formError, setFormError] = useState('');
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); toast(ok); reload(); } catch (e) { toast(errText(e), 'bad'); }
  };
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Users" sub="Who can sign in, and what they may do." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Panel title="Accounts">
          {error && <p className="text-[13px]" style={{ color: 'var(--bad)' }}>{error}</p>}
          <ul className="space-y-2">{(data ?? []).map((u: UserInfo) => (
            <li key={u.id} className={`tile flex flex-wrap items-center gap-3 px-3.5 py-2.5 ${u.disabled ? 'opacity-60' : ''}`}>
              <div className="min-w-[140px] flex-1"><div className="text-[13.5px] font-semibold">{u.username}{u.username === me?.username && <span className="badge badge-info ml-2">you</span>}</div><div className="text-[12px] text-mute">{ROLE_HELP[u.role]}{u.disabled ? ' · disabled' : ''}</div></div>
              <select aria-label={`Role of ${u.username}`} className="field !w-auto" value={u.role} onChange={(e) => act(() => api.updateUser(u.id, { role: e.target.value as Role }), `${u.username} is now ${e.target.value}`)}>
                <option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option>
              </select>
              <button className="btn" onClick={() => { const p = window.prompt(`New password for ${u.username} (at least 10 characters). Their sessions are ended.`); if (p) void act(() => api.updateUser(u.id, { password: p }), 'Password reset'); }}>Reset password</button>
              <button className="btn" onClick={() => act(() => api.updateUser(u.id, { disabled: !u.disabled }), u.disabled ? `${u.username} enabled` : `${u.username} disabled`)}>{u.disabled ? 'Enable' : 'Disable'}</button>
              <button className="btn btn-ghost btn-icon" aria-label={`Delete ${u.username}`} disabled={u.username === me?.username} onClick={() => { if (window.confirm(`Delete the account ${u.username}?`)) void act(() => api.deleteUser(u.id), `${u.username} deleted`); }}><Trash2 size={14} /></button>
            </li>
          ))}</ul>
        </Panel>
        <Panel title="Add a user">
          <Field label="User name"><input className="field" autoComplete="off" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
          <Field label="Initial password" className="mt-3" hint="At least 10 characters. Ask them to change it after signing in."><input type="password" autoComplete="new-password" className="field" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
          <Field label="Role" className="mt-3"><Segmented value={f.role} onChange={(role) => setF({ ...f, role })} options={[{ value: 'viewer', label: 'Viewer' }, { value: 'operator', label: 'Operator' }, { value: 'admin', label: 'Admin' }]} /></Field>
          <p className="mt-2 text-[12px] text-mute">{ROLE_HELP[f.role]}.</p>
          {formError && <p role="alert" className="mt-2 text-[12.5px]" style={{ color: 'var(--bad)' }}>{formError}</p>}
          <button className="btn btn-primary mt-3" disabled={!f.username || !f.password} onClick={async () => { setFormError(''); try { await api.createUser(f.username.trim(), f.password, f.role); setF({ username: '', password: '', role: 'operator' }); toast('User added'); reload(); } catch (e) { setFormError(errText(e)); } }}><UserPlus size={15} /> Add user</button>
        </Panel>
      </div>
    </div>
  );
}

export function ActivityPage() {
  const { data, error, reload } = useLoad(api.activity);
  return (
    <div className="h-full overflow-y-auto pr-1">
      <PageHeader title="Activity" sub="Sign-ins, server connections, pushes and changes to accounts and inventory, newest first.">
        <button className="btn" onClick={reload}><RefreshCw size={14} /> Refresh</button>
      </PageHeader>
      <Panel title="Audit log" hint="Last 300 entries">
        {error && <p className="text-[13px]" style={{ color: 'var(--bad)' }}>{error}</p>}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-[12.5px]">
            <thead className="text-[11px] uppercase tracking-wider text-mute"><tr><th className="pb-2 font-semibold">When</th><th className="pb-2 font-semibold">Who</th><th className="pb-2 font-semibold">What</th><th className="pb-2 font-semibold">Detail</th></tr></thead>
            <tbody>{(data ?? []).map((a: Activity) => (
              <tr key={a.id} className="border-t" style={{ borderColor: 'var(--line)' }}>
                <td className="whitespace-nowrap py-1.5 pr-3 text-mute">{when(a.at)}</td><td className="py-1.5 pr-3 font-medium">{a.username}</td>
                <td className="py-1.5 pr-3"><span className={`chip ${/failed|delete/.test(a.action) ? '!border-[color:var(--bad)]' : ''}`}>{a.action}</span></td><td className="py-1.5 text-mute">{a.detail}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

/** Top-bar account menu: who is signed in, change password, sign out. */
export function AccountChip() {
  const user = useSession((s) => s.user);
  const setUser = useSession((s) => s.setUser);
  const toast = useStore((s) => s.toast);
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  if (!user) return null;
  return (
    <>
      <button className="badge badge-mute normal-case" title="Account" onClick={() => setOpen(true)}>{user.username} · {user.role}</button>
      <Modal open={open} onClose={() => setOpen(false)} title={`Signed in as ${user.username}`} footer={<button className="btn" onClick={async () => { await api.logout().catch(() => undefined); setUser(null); setOpen(false); }}>Sign out</button>}>
        <p className="mb-3 text-[12.5px] text-mute">Role: {user.role} — {ROLE_HELP[user.role].toLowerCase()}.</p>
        <Field label="Current password"><input type="password" className="field" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
        <Field label="New password" className="mt-3" hint="At least 10 characters. Your other sessions are signed out."><input type="password" className="field" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
        {error && <p role="alert" className="mt-2 text-[12.5px]" style={{ color: 'var(--bad)' }}>{error}</p>}
        <button className="btn btn-primary mt-3" disabled={!cur || !next} onClick={async () => { setError(''); try { await api.changePassword(cur, next); setCur(''); setNext(''); toast('Password changed'); setOpen(false); } catch (e) { setError(errText(e)); } }}>Change password</button>
      </Modal>
    </>
  );
}
