import { Fragment, type ReactNode } from 'react';
import type { OutLang, OutLine } from '../../core/compile';
import type { DiffLine } from '../../core/diff';

const KEYWORDS = /^(table|chain|set|type|hook|priority|policy|elements|flags|comment|counter|log|prefix|limit|rate|burst|ufw|firewall-cmd|iptables|ip6tables|iptables-restore|ip6tables-restore|nft|sysctl|rule|zone|port|source|destination|family|masquerade|dnat|snat|COMMIT|destroy|add|delete|flush|set|echo|if|then|else|fi|sed|cp|rm|install|kill|sleep|read|printf|trap)$/;
const GOOD = /^(accept|ACCEPT|allow|CONTINUE)$/;
const BAD = /^(drop|DROP|reject|REJECT|deny|limit-drop)$/;

/** Small tokenizer shared by all four output languages: good enough to make rulesets scannable. */
function highlight(text: string, lang: OutLang): ReactNode {
  if (lang === 'xml') {
    const parts = text.split(/(<!--.*?-->|"[^"]*"|<\/?[\w-]+|\/?>)/g);
    return parts.map((p, i) => {
      if (!p) return null;
      if (p.startsWith('<!--')) return <span key={i} className="tok-comment">{p}</span>;
      if (p.startsWith('"')) return <span key={i} className="tok-string">{p}</span>;
      if (p.startsWith('<') || p.endsWith('>')) return <span key={i} className="tok-key">{p}</span>;
      return <span key={i} className="tok-flag">{p}</span>;
    });
  }
  const trimmed = text.trimStart();
  if (trimmed.startsWith('#')) return <span className="tok-comment">{text}</span>;
  const parts = text.split(/("[^"]*"|'[^']*'|\s+|[{},;])/g);
  return parts.map((p, i) => {
    if (!p) return null;
    if (/^\s+$/.test(p) || /^[{},;]$/.test(p)) return <Fragment key={i}>{p}</Fragment>;
    if (p.startsWith('"') || p.startsWith("'")) return <span key={i} className="tok-string">{p}</span>;
    if (GOOD.test(p)) return <span key={i} className="tok-ok">{p}</span>;
    if (BAD.test(p)) return <span key={i} className="tok-bad">{p}</span>;
    if (/^--?[A-Za-z]/.test(p) || p.startsWith('*') || p.startsWith(':')) return <span key={i} className="tok-flag">{p}</span>;
    if (/^@?[\d[]/.test(p) || (/^[0-9a-f:]+(\/\d+)?$/i.test(p) && p.includes(':'))) return <span key={i} className="tok-num">{p}</span>;
    if (KEYWORDS.test(p)) return <span key={i} className="tok-key">{p}</span>;
    return <Fragment key={i}>{p}</Fragment>;
  });
}

export function CodeView({ lines, lang, activeRuleId, onPick, className = '' }: {
  lines: OutLine[];
  lang: OutLang;
  activeRuleId?: string | null;
  onPick?: (ruleId: string) => void;
  className?: string;
}) {
  return (
    <div className={`code overflow-auto py-2 ${className}`}>
      {lines.map((l, i) => {
        const linked = !!l.ruleId && !!onPick;
        return (
          <div
            key={i}
            className={`code-line ${linked ? 'linked' : ''} ${l.ruleId && l.ruleId === activeRuleId ? 'active' : ''}`}
            onClick={linked ? () => onPick!(l.ruleId!) : undefined}
            title={linked ? 'Click to select the rule that produced this line' : undefined}
          >
            <span className="ln">{i + 1}</span>
            <span className="tx">{highlight(l.text, lang) || ' '}</span>
          </div>
        );
      })}
    </div>
  );
}

export function DiffView({ lines, lang, className = '' }: { lines: DiffLine[]; lang: OutLang; className?: string }) {
  return (
    <div className={`code overflow-auto py-2 ${className}`}>
      {lines.map((l, i) => (
        <div key={i} className={`code-line ${l.kind === 'add' ? 'add' : l.kind === 'del' ? 'del' : ''}`}>
          <span className="ln">{l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ''}</span>
          <span className="tx">{highlight(l.text, lang) || ' '}</span>
        </div>
      ))}
    </div>
  );
}
