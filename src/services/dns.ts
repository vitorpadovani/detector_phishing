import { parse } from 'tldts';

export const DYNAMIC_DNS_SUFFIXES = new Set([
  'no-ip.org','zapto.org','ddns.net','duckdns.org','dynu.net','hopto.org','sytes.net','dynserv.org','dyndns.org','servebeer.com','servegame.com','myftp.biz','myftp.org','gotdns.com'
]);

export function extractDomain(urlOrHost: string): string {
  const info = parse(urlOrHost);
  if (info.domain) return info.domain; // registrable domain
  return info.hostname || urlOrHost;
}

export function hasExcessiveSubdomains(url: string, limit = 3): { excessive: boolean; count: number } {
  const info = parse(url);
  const subs = (info.subdomain || '').split('.').filter(Boolean);
  const count = subs.length;
  return { excessive: count > limit, count };
}

export function isDynamicDNS(domain: string): boolean {
  for (const suf of DYNAMIC_DNS_SUFFIXES) {
    if (domain.endsWith(suf)) return true;
  }
  return false;
}

export function looksLikeLeet(domain: string): Array<[string,string]> {
  const map: Record<string,string> = { '0': 'o', '1': 'l/i', '3': 'e', '5': 's', '7': 't' };
  const ret: Array<[string,string]> = [];
  for (const k of Object.keys(map)) if (domain.includes(k)) ret.push([k, map[k]]);
  return ret;
}

export function hasSuspiciousChars(url: string): string[] {
  const chars = ['@','%',';','"','\'','`','|','\\',' ','<','>'];
  return chars.filter((c) => url.includes(c));
}

export function isShortener(domain: string): boolean {
  return new Set(['bit.ly','tinyurl.com','goo.gl','t.co','is.gd','ow.ly','buff.ly','rebrand.ly','cutt.ly','rb.gy','lnkd.in']).has(domain);
}
