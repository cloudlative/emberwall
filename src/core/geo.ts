// Country address lists for geo-blocking. The data is ipverse/country-ip-blocks: built daily from
// the regional internet registries' delegation files, public domain (CC0), served over HTTPS.
// The server fetches these itself (see compile/blocklists.ts); Emberwall does not bundle them.

export const COUNTRY_SOURCE = 'https://github.com/ipverse/country-ip-blocks';
const BASE = 'https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country';

/** The IPv4 and IPv6 lists for a two-letter country code, as blocklists to add. */
export function countryLists(code: string): { name: string; url: string }[] {
  const cc = code.trim().toLowerCase();
  if (!/^[a-z]{2}$/.test(cc)) throw new Error(`"${code}" is not a two-letter country code`);
  const up = cc.toUpperCase();
  return [
    { name: `Country ${up} (IPv4)`, url: `${BASE}/${cc}/ipv4-aggregated.txt` },
    { name: `Country ${up} (IPv6)`, url: `${BASE}/${cc}/ipv6-aggregated.txt` },
  ];
}

/**
 * Earlier versions pointed country lists at ipdeny.com, whose HTTPS stopped answering (only plain
 * HTTP works, which a firewall must not trust). Maps those URLs to the same country's IPv4 list
 * here; any other URL is returned unchanged.
 */
export function migrateCountryUrl(url: string): string {
  const m = /^https?:\/\/(?:www\.)?ipdeny\.com\/ipblocks\/data\/(?:aggregated|countries)\/([a-z]{2})(?:-aggregated)?\.zone$/i.exec(url.trim());
  return m ? `${BASE}/${m[1].toLowerCase()}/ipv4-aggregated.txt` : url;
}
