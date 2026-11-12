import type { Project, Rule } from '../model';

export interface ImportReport {
  project: Project;
  imported: number;
  skipped: { line: string; reason: string }[];
}

/** Rules that only restate the baseline (loopback, established, invalid, essential ICMP) become options. */
export function foldBaseline(p: Project, r: Rule, extra: { iif?: string } = {}): boolean {
  const bare = r.src.length === 0 && r.dst.length === 0 && r.ports.length === 0 && !r.rateLimit;
  if (!bare) return false;
  const iface = extra.iif ?? r.inIface ?? r.outIface;
  if (r.proto === 'any' && iface === 'lo' && r.action === 'accept' && !r.states) {
    p.options.allowLoopback = true;
    return true;
  }
  if (r.proto === 'any' && !iface && r.action === 'accept' && r.states && r.states.length > 0 && r.states.every((s) => s === 'established' || s === 'related')) {
    p.options.allowEstablished = true;
    return true;
  }
  if (r.proto === 'any' && !iface && r.action === 'drop' && r.states?.join() === 'invalid') {
    p.options.dropInvalid = true;
    return true;
  }
  return false;
}

export function baselineOff(p: Project): Project {
  p.options = { ...p.options, allowLoopback: false, allowEstablished: false, dropInvalid: false, allowIcmp: false, logDropped: false };
  return p;
}
