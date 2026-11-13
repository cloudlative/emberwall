// A small, dependency-free highlighter for the languages Emberwall emits and the docs use.
// It only colours tokens; it never changes the text, so copied code is exactly what was shown.

export const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const KEYWORDS: Record<string, string[]> = {
  nft: ['table', 'chain', 'type', 'hook', 'priority', 'policy', 'accept', 'drop', 'reject', 'counter', 'log', 'prefix', 'ct', 'state', 'established', 'related', 'invalid', 'new', 'iif', 'oif', 'iifname', 'oifname', 'ip', 'ip6', 'saddr', 'daddr', 'tcp', 'udp', 'th', 'dport', 'sport', 'meta', 'l4proto', 'icmp', 'icmpv6', 'set', 'elements', 'flags', 'interval', 'timeout', 'limit', 'rate', 'burst', 'over', 'masquerade', 'snat', 'dnat', 'to', 'add', 'delete', 'destroy', 'flush', 'ruleset', 'define', 'inet', 'filter', 'nat', 'input', 'output', 'forward', 'prerouting', 'postrouting', 'comment', 'jump', 'return', 'update', 'counter', 'packets', 'bytes'],
  iptables: ['ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN', 'MASQUERADE', 'SNAT', 'DNAT', 'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING', 'COMMIT', 'filter', 'nat', 'mangle', 'raw'],
  sh: ['if', 'then', 'else', 'elif', 'fi', 'for', 'in', 'do', 'done', 'case', 'esac', 'while', 'until', 'function', 'return', 'exit', 'set', 'export', 'local', 'readonly', 'echo', 'printf', 'read', 'trap', 'kill', 'sleep', 'cd', 'sudo', 'curl', 'chmod', 'mkdir', 'install', 'systemctl', 'nft', 'iptables', 'iptables-restore', 'ip6tables-restore', 'ufw', 'firewall-cmd', 'npm', 'npx', 'node', 'git', 'emberwall', 'sha256sum', 'shasum'],
  yaml: ['true', 'false', 'null', 'yes', 'no'],
  json: ['true', 'false', 'null'],
  hcl: ['resource', 'variable', 'provider', 'terraform', 'locals', 'output', 'data', 'module', 'true', 'false', 'null', 'for_each', 'dynamic', 'content'],
  powershell: ['New-NetFirewallRule', 'Remove-NetFirewallRule', 'Get-NetFirewallRule', 'Set-NetFirewallProfile', 'if', 'else', 'foreach', 'param', 'function', 'return', '$true', '$false', '$null'],
  ini: [],
  xml: [],
  text: [],
};

const ALIAS: Record<string, string> = { shell: 'sh', bash: 'sh', console: 'sh', zsh: 'sh', conf: 'ini', toml: 'ini', yml: 'yaml', ps1: 'powershell', pf: 'nft', tf: 'hcl' };

/** Highlights one block of code and returns HTML (already escaped). */
export function highlight(code: string, langIn = 'text'): string {
  const lang = ALIAS[langIn] ?? langIn;
  if (lang === 'xml') return highlightXml(code);
  const kw = new Set(KEYWORDS[lang] ?? []);
  const commentRe = lang === 'json' ? null : lang === 'hcl' ? /^(#|\/\/).*/ : lang === 'powershell' ? /^#.*/ : /^#.*/;
  const out: string[] = [];
  for (const line of code.split('\n')) {
    let html = '';
    let i = 0;
    // A comment only starts at the beginning of a line or after whitespace (so "#s=" in URLs is safe).
    while (i < line.length) {
      const rest = line.slice(i);
      const prev = i === 0 ? ' ' : line[i - 1];
      let m: RegExpExecArray | null;
      if (commentRe && /\s/.test(prev) && (m = commentRe.exec(rest))) {
        html += `<span class="tk-c">${esc(m[0])}</span>`;
        break;
      }
      if (lang === 'yaml' && i === line.search(/\S/) && (m = /^(- )?([A-Za-z0-9_.\-/ ]+)(:)(?=\s|$)/.exec(rest))) {
        html += (m[1] ? `<span class="tk-p">-</span> ` : '') + `<span class="tk-k">${esc(m[2])}</span><span class="tk-p">:</span>`;
        i += m[0].length;
        continue;
      }
      if (lang === 'json' && (m = /^"(?:[^"\\]|\\.)*"(?=\s*:)/.exec(rest))) {
        html += `<span class="tk-k">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if (lang === 'ini' && i === 0 && (m = /^\[[^\]]*\]/.exec(rest))) {
        html += `<span class="tk-k">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if (lang === 'ini' && i === line.search(/\S/) && (m = /^[A-Za-z0-9_.-]+(?=\s*=)/.exec(rest))) {
        html += `<span class="tk-k">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if ((m = /^"(?:[^"\\]|\\.)*"|^'[^']*'/.exec(rest))) {
        html += `<span class="tk-s">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if (lang === 'sh' && (m = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|^\$\(/.exec(rest))) {
        html += `<span class="tk-v">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if (/[\s(=]/.test(prev) && (m = /^--?[A-Za-z][A-Za-z0-9-]*/.exec(rest)) && lang !== 'yaml' && lang !== 'json' && lang !== 'hcl') {
        html += `<span class="tk-f">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if (lang === 'iptables' && i === 0 && (m = /^[*:][A-Za-z0-9_-]+/.exec(rest))) {
        html += `<span class="tk-k">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      // Addresses, CIDRs, ports, ranges, versions and plain numbers.
      if (!/[A-Za-z0-9_]/.test(prev) && (m = /^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/\d+)?(?![\w:])|^\d+(?:\.\d+){1,3}(?:\/\d+)?|^0x[0-9a-f]+|^\d+(?:[:-]\d+)?(?![A-Za-z_])/i.exec(rest))) {
        html += `<span class="tk-n">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      if ((m = /^[A-Za-z_$][A-Za-z0-9_\-$.]*/.exec(rest))) {
        const word = m[0];
        html += kw.has(word) ? `<span class="tk-w">${esc(word)}</span>` : esc(word);
        i += word.length;
        continue;
      }
      if ((m = /^[{}[\]();,|&<>]+/.exec(rest))) {
        html += `<span class="tk-p">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
      html += esc(line[i]);
      i += 1;
    }
    out.push(html);
  }
  return out.join('\n');
}

function highlightXml(code: string): string {
  return esc(code)
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="tk-c">$1</span>')
    .replace(/(&lt;\/?)([A-Za-z0-9_:-]+)/g, '$1<span class="tk-w">$2</span>')
    .replace(/([A-Za-z0-9_:-]+)=(&quot;[^&]*?&quot;)/g, '<span class="tk-k">$1</span>=<span class="tk-s">$2</span>');
}
