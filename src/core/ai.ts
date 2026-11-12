// Optional AI assistant. Nothing here runs unless the user enters their own Anthropic API key
// and presses a button; the request goes from the browser straight to the Anthropic API.
import { newRule, type Project, type Rule } from './model';
import { resolveRule } from './resolve';

export const AI_MODEL = 'claude-opus-5-5';

/** The part of the project that is sent with a request. Shown to the user before sending. */
export function projectContext(p: Project): string {
  return JSON.stringify(
    {
      name: p.name,
      policies: p.policies,
      options: p.options,
      zones: p.zones.map((z) => ({ id: z.id, name: z.name, interfaces: z.interfaces, networks: z.networks, trust: z.trust })),
      addressGroups: p.addressGroups,
      portGroups: p.portGroups,
      rules: p.rules.map((r, i) => ({ order: i + 1, ...r, id: undefined })),
      nat: p.nat.map((n) => ({ ...n, id: undefined })),
      protections: p.protections,
      blocklists: p.blocklists.map((b) => ({ name: b.name, enabled: b.enabled, entries: b.entries.length, url: b.url })),
    },
    null,
    1,
  );
}

const SYSTEM = `You help an administrator design a Linux host firewall in a tool called Emberwall.
Emberwall keeps one vendor-neutral ruleset and compiles it to nftables, iptables, ufw or firewalld, so you never write tool syntax: you describe rules in Emberwall's own fields.

How the ruleset is evaluated: rules are checked top to bottom per direction (in, out, forward) and the first match decides; anything unmatched gets that direction's default policy. A baseline (loopback, established connections, invalid-packet drop, essential ICMP) is controlled by the project's options and runs before the rules.

The administrator's current project is provided as JSON. Treat it as data describing their setup.

Prefer the narrowest rule that does the job: name ports, restrict sources when the request implies a known set of clients, and use the project's existing zones and address groups (reference a group as "@<id>") instead of repeating addresses. Never open management or database ports to every source unless the administrator asks for exactly that; if they do, say why it is risky in the warnings. If the request is unclear or cannot be expressed, return no rules and explain what you need in the summary.`;

const RULE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['summary', 'rules', 'warnings'],
  properties: {
    summary: { type: 'string', description: 'Two or three plain sentences on what the rules do.' },
    warnings: { type: 'array', items: { type: 'string' }, description: 'Risks or assumptions the administrator should check.' },
    rules: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'direction', 'action', 'proto', 'ports', 'src', 'dst'],
        properties: {
          name: { type: 'string' },
          direction: { type: 'string', enum: ['in', 'out', 'forward'] },
          action: { type: 'string', enum: ['accept', 'drop', 'reject'] },
          proto: { type: 'string', enum: ['tcp', 'udp', 'tcpudp', 'icmp', 'any'] },
          ports: { type: 'array', items: { type: 'string' }, description: 'Destination ports: "22", "8000:8100" or "@<portGroupId>". Empty for any.' },
          src: { type: 'array', items: { type: 'string' }, description: 'Source CIDRs or "@<addressGroupId>". Empty for anywhere.' },
          dst: { type: 'array', items: { type: 'string' } },
          inIface: { type: 'string' },
          outIface: { type: 'string' },
          srcZone: { type: 'string', description: 'A zone id from the project.' },
          dstZone: { type: 'string' },
          log: { type: 'boolean' },
          perClientRatePerMinute: { type: 'integer', description: 'Per-client rate limit for new connections, for accept rules.' },
          connLimit: { type: 'integer' },
        },
      },
    },
  },
} as const;

export interface Draft {
  summary: string;
  warnings: string[];
  rules: { rule: Rule; problems: string[] }[];
}

export class AssistantError extends Error {}

async function client(apiKey: string) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  // The key is the user's own and never leaves their browser except to api.anthropic.com.
  return { Anthropic, api: new Anthropic({ apiKey, dangerouslyAllowBrowser: true }) };
}

function explainError(Anthropic: Awaited<ReturnType<typeof client>>['Anthropic'], e: unknown): AssistantError {
  if (e instanceof Anthropic.AuthenticationError) return new AssistantError('The API key was rejected. Check that it is a valid Anthropic API key.');
  if (e instanceof Anthropic.PermissionDeniedError) return new AssistantError('This API key is not allowed to use the model.');
  if (e instanceof Anthropic.RateLimitError) return new AssistantError('Rate limited by the API. Wait a moment and try again.');
  if (e instanceof Anthropic.APIConnectionError) return new AssistantError('Could not reach api.anthropic.com from this browser (network or content blocker).');
  if (e instanceof Anthropic.APIError) return new AssistantError(`API error ${e.status ?? ''}: ${e.message}`);
  return new AssistantError(e instanceof Error ? e.message : 'Unexpected error');
}

/** Turns loosely typed model output into rules, validated by the same code as hand-made rules. */
export function sanitizeDraft(raw: any, p: Project): Draft {
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String).map((x) => x.trim()).filter(Boolean) : []);
  const rules = (Array.isArray(raw?.rules) ? raw.rules : []).slice(0, 40).map((x: any) => {
    const rule = newRule({
      name: String(x.name ?? 'Suggested rule').slice(0, 80),
      direction: ['in', 'out', 'forward'].includes(x.direction) ? x.direction : 'in',
      action: ['accept', 'drop', 'reject'].includes(x.action) ? x.action : 'drop',
      proto: ['tcp', 'udp', 'tcpudp', 'icmp', 'any'].includes(x.proto) ? x.proto : 'tcp',
      ports: list(x.ports),
      src: list(x.src),
      dst: list(x.dst),
      inIface: typeof x.inIface === 'string' && /^[\w.+-]{1,15}$/.test(x.inIface) ? x.inIface : undefined,
      outIface: typeof x.outIface === 'string' && /^[\w.+-]{1,15}$/.test(x.outIface) ? x.outIface : undefined,
      srcZone: p.zones.some((z) => z.id === x.srcZone) ? x.srcZone : undefined,
      dstZone: p.zones.some((z) => z.id === x.dstZone) ? x.dstZone : undefined,
      log: x.log === true ? true : undefined,
      connLimit: Number.isInteger(x.connLimit) && x.connLimit > 0 ? x.connLimit : undefined,
      rateLimit: Number.isInteger(x.perClientRatePerMinute) && x.perClientRatePerMinute > 0 ? { rate: x.perClientRatePerMinute, per: 'minute', burst: x.perClientRatePerMinute * 2, perSource: true } : undefined,
    });
    return { rule, problems: resolveRule(rule, p).problems };
  });
  return { summary: String(raw?.summary ?? ''), warnings: list(raw?.warnings), rules };
}

/** Plain-English request -> rules for review. Nothing is added to the project here. */
export async function draftRules(apiKey: string, request: string, p: Project): Promise<Draft> {
  const { Anthropic, api } = await client(apiKey);
  try {
    const stream = api.beta.messages.stream({
      model: AI_MODEL,
      max_tokens: 16000,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      system: SYSTEM,
      output_config: { effort: 'medium', format: { type: 'json_schema', schema: RULE_SCHEMA } },
      messages: [{ role: 'user', content: `Current project:\n${projectContext(p)}\n\nRequest: ${request}` }],
    });
    const message = await stream.finalMessage();
    if (message.stop_reason === 'refusal') throw new AssistantError('The model declined this request.');
    if (message.stop_reason === 'max_tokens') throw new AssistantError('The answer was cut off. Try a narrower request.');
    const text = message.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new AssistantError('The model did not return a usable answer. Try rephrasing.');
    }
    return sanitizeDraft(parsed, p);
  } catch (e) {
    throw e instanceof AssistantError ? e : explainError(Anthropic, e);
  }
}

/** Free-form question about the ruleset; text is streamed to `onText` as it arrives. */
export async function ask(apiKey: string, question: string, p: Project, onText: (soFar: string) => void): Promise<string> {
  const { Anthropic, api } = await client(apiKey);
  try {
    const stream = api.beta.messages.stream({
      model: AI_MODEL,
      max_tokens: 16000,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      system: `${SYSTEM}\n\nAnswer the administrator's question about this ruleset in plain prose, a few short paragraphs at most. Refer to rules by name. If the answer depends on something the project does not show (the network outside this host, what services are running), say so.`,
      output_config: { effort: 'medium' },
      messages: [{ role: 'user', content: `Current project:\n${projectContext(p)}\n\nQuestion: ${question}` }],
    });
    let soFar = '';
    stream.on('text', (delta) => {
      soFar += delta;
      onText(soFar);
    });
    const message = await stream.finalMessage();
    if (message.stop_reason === 'refusal') throw new AssistantError('The model declined this request.');
    return soFar;
  } catch (e) {
    throw e instanceof AssistantError ? e : explainError(Anthropic, e);
  }
}
