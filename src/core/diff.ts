export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
}

/** Line diff by longest common subsequence. Fine for ruleset-sized inputs. */
export function diffLines(a: string, b: string): DiffLine[] {
  const x = a.split('\n');
  const y = b.split('\n');
  const n = x.length;
  const m = y.length;
  const w = m + 1;
  const lcs = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i * w + j] = x[i] === y[j] ? lcs[(i + 1) * w + j + 1] + 1 : Math.max(lcs[(i + 1) * w + j], lcs[i * w + j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ kind: 'same', text: x[i] });
      i += 1;
      j += 1;
    } else if (lcs[(i + 1) * w + j] >= lcs[i * w + j + 1]) {
      out.push({ kind: 'del', text: x[i] });
      i += 1;
    } else {
      out.push({ kind: 'add', text: y[j] });
      j += 1;
    }
  }
  while (i < n) out.push({ kind: 'del', text: x[i++] });
  while (j < m) out.push({ kind: 'add', text: y[j++] });
  return out;
}

export function diffStats(d: DiffLine[]): { added: number; removed: number } {
  return { added: d.filter((l) => l.kind === 'add').length, removed: d.filter((l) => l.kind === 'del').length };
}
