// Country lists: the URLs, the migration away from ipdeny.com, and the updater's parsing of the
// real list format (comment header, then one CIDR per line).
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { activeLists, blocklistUpdater } from '../src/core/compile/blocklists';
import { fileText } from '../src/core/compile/types';
import { countryLists, migrateCountryUrl } from '../src/core/geo';
import { coerceProject, emptyProject } from '../src/core/model';

const root = mkdtempSync(join(tmpdir(), 'ew-geo-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('country lists', () => {
  it('adds an IPv4 and an IPv6 list, both over HTTPS', () => {
    const lists = countryLists('Pk');
    expect(lists.map((l) => l.name)).toEqual(['Country PK (IPv4)', 'Country PK (IPv6)']);
    expect(lists.map((l) => l.url)).toEqual([
      'https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/pk/ipv4-aggregated.txt',
      'https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/pk/ipv6-aggregated.txt',
    ]);
    expect(() => countryLists('PAK')).toThrow();
    expect(() => countryLists('p1')).toThrow();
  });

  it('moves saved ipdeny country URLs to the HTTPS source, and leaves other URLs alone', () => {
    expect(migrateCountryUrl('https://www.ipdeny.com/ipblocks/data/aggregated/pk-aggregated.zone')).toBe(countryLists('pk')[0].url);
    expect(migrateCountryUrl('http://ipdeny.com/ipblocks/data/countries/KP.zone')).toBe(countryLists('kp')[0].url);
    expect(migrateCountryUrl('https://example.org/ipdeny.com/pk-aggregated.zone')).toBe('https://example.org/ipdeny.com/pk-aggregated.zone');
    const p = emptyProject('Old');
    p.blocklists = [{ id: 'b', name: 'Country PK', enabled: true, entries: [], url: 'https://www.ipdeny.com/ipblocks/data/aggregated/pk-aggregated.zone' }];
    expect(coerceProject(JSON.parse(JSON.stringify(p))).blocklists[0].url).toBe(countryLists('pk')[0].url);
  });

  it('the updater keeps the addresses and skips the comment header', () => {
    // A stand-in curl "downloads" a file in the real format.
    const bin = join(root, 'bin');
    mkdirSync(bin);
    writeFileSync(join(root, 'v4.txt'), '# Country: Pakistan (PK)\n# Address family: IPv4\n#\n14.1.104.0/22\n14.192.128.0/19\n');
    writeFileSync(join(root, 'v6.txt'), '# Country: Pakistan (PK)\n# Address family: IPv6\n#\n2001:dd8:1c::/48\n2001:dec:8000::/48\n');
    // Called as: curl <flags> <url> -o <file>; picks the fixture by URL and writes it to <file>.
    writeFileSync(join(bin, 'curl'), `#!/bin/sh\ncase "$*" in *ipv4*) f=v4 ;; *) f=v6 ;; esac\nfor a; do out=$a; done\ncp "${root}/$f.txt" "$out"\n`);
    chmodSync(join(bin, 'curl'), 0o755);
    const p = emptyProject('Geo');
    p.blocklists = countryLists('pk').map((l, i) => ({ id: `b${i}`, enabled: true, entries: [], ...l }));
    const script = fileText(blocklistUpdater(activeLists(p), 'nftables', true).find((f) => f.name.endsWith('.sh'))!);
    const fetchFn = /fetch\(\) \{[\s\S]*?\n\}/.exec(script)![0];
    const run = (url: string, out: string) =>
      execFileSync('sh', ['-c', `${fetchFn}\nfetch "$1" "$2" && cat "$2.v4" "$2.v6"`, '_', url, join(root, out)], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
    expect(run(p.blocklists[0].url!, 'a').trim().split('\n')).toEqual(['14.1.104.0/22', '14.192.128.0/19']);
    expect(run(p.blocklists[1].url!, 'b').trim().split('\n')).toEqual(['2001:dd8:1c::/48', '2001:dec:8000::/48']);
    expect(readFileSync(join(root, 'a.v6'), 'utf8')).toBe('');
  });
});
