// SSH access to inventory servers. Host keys are pinned (trust on first use); commands are
// supplied by server code only.
import { createHash } from 'node:crypto';
import { Client } from 'ssh2';
import type { CommandResult } from '../src/core/live';

export interface SshTarget {
  host: string;
  port: number;
  username: string;
  privateKey?: string;
  passphrase?: string;
  password?: string;
  /** Fingerprint stored for this server, if it has been trusted before. */
  pinned?: string | null;
  /** Fingerprint the user has just approved (first connection only). */
  trust?: string | null;
}

export class HostKeyError extends Error {
  constructor(public kind: 'unknown' | 'changed', public fingerprint: string, public pinned?: string | null) {
    super(kind === 'unknown' ? 'The server\'s host key has not been approved yet.' : 'The server\'s host key is different from the one approved earlier.');
  }
}

export class SshError extends Error {}

export const fingerprintOf = (key: Buffer) => `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;

const MAX_OUTPUT = 4 * 1024 * 1024;

export interface Session {
  fingerprint: string;
  exec(command: string, opts?: { stdin?: string; timeoutMs?: number }): Promise<CommandResult>;
  close(): void;
}

export function connect(t: SshTarget, timeoutMs = 15000): Promise<Session> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let seen = '';
    let hostKeyProblem: HostKeyError | null = null;
    let settled = false;
    const done = (fn: () => void) => {
      if (!settled) {
        settled = true;
        fn();
      }
    };
    client.on('ready', () => {
      done(() =>
        resolve({
          fingerprint: seen,
          close: () => client.end(),
          exec: (command, opts = {}) =>
            new Promise<CommandResult>((res, rej) => {
              const timer = setTimeout(() => rej(new SshError(`Command timed out: ${command.slice(0, 60)}`)), opts.timeoutMs ?? 30000);
              client.exec(command, (err, stream) => {
                if (err) {
                  clearTimeout(timer);
                  rej(new SshError(err.message));
                  return;
                }
                let stdout = '';
                let stderr = '';
                stream.on('data', (d: Buffer) => { if (stdout.length < MAX_OUTPUT) stdout += d.toString('utf8'); });
                stream.stderr.on('data', (d: Buffer) => { if (stderr.length < MAX_OUTPUT) stderr += d.toString('utf8'); });
                stream.on('close', (code: number | null) => {
                  clearTimeout(timer);
                  res({ code, stdout, stderr });
                });
                if (opts.stdin !== undefined) stream.end(opts.stdin);
                else stream.end();
              });
            }),
        }),
      );
    });
    // Send each SSH packet at once. Without ssh2's optional native crypto (it does not build on
    // every Node release) a packet goes out in several small writes, and TCP's default batching
    // then holds each one back for about 40 ms, which adds up over a probe's many commands.
    client.on('connect', () => client.setNoDelay(true));
    client.on('error', (err) => {
      done(() => {
        if (hostKeyProblem) reject(hostKeyProblem);
        else if (/authentication/i.test(err.message)) reject(new SshError('Authentication failed: the server rejected the key or password.'));
        else reject(new SshError(`Could not connect to ${t.host}:${t.port} (${err.message}).`));
      });
    });
    client.on('close', () => done(() => reject(hostKeyProblem ?? new SshError('The connection was closed before it was ready.'))));
    try {
      client.connect({
        host: t.host,
        port: t.port,
        username: t.username,
        privateKey: t.privateKey,
        passphrase: t.passphrase || undefined,
        password: t.password,
        readyTimeout: timeoutMs,
        tryKeyboard: false,
        hostVerifier: (key: Buffer) => {
          seen = fingerprintOf(key);
          if (t.pinned) {
            if (t.pinned === seen) return true;
            hostKeyProblem = new HostKeyError('changed', seen, t.pinned);
            return false;
          }
          if (t.trust && t.trust === seen) return true;
          hostKeyProblem = new HostKeyError('unknown', seen);
          return false;
        },
      });
    } catch (e) {
      done(() => reject(new SshError(/privateKey|parse|key format/i.test((e as Error).message) ? 'The private key could not be read (wrong format or passphrase).' : (e as Error).message)));
    }
  });
}
