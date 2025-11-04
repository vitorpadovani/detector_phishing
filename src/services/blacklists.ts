import { request } from 'undici';
import { CONFIG } from '../config';
import { getCache, setCache } from '../util/cache';

export async function checkOpenPhish(url: string): Promise<boolean | null> {
  const key = 'openphish';
  const cached = getCache<Set<string>>(key);
  if (!cached) {
    try {
      const r = await request('https://openphish.com/feed.txt', { method: 'GET' });
      const text = await r.body.text();
      const set = new Set(text.split(/\n+/).map((l) => l.trim()).filter(Boolean));
      setCache(key, set, CONFIG.FEED_TTL_HOURS * 3600);
      return set.has(url);
    } catch { return null; }
  }
  return cached.has(url);
}

export async function checkPhishTank(url: string): Promise<boolean | null> {
  const key = 'phishtank';
  const cached = getCache<Set<string>>(key);
  if (!cached) {
    try {
      const r = await request('https://data.phishtank.com/data/online-valid.json', { method: 'GET' });
      const data = JSON.parse(await r.body.text());
      const set = new Set<string>();
      for (const e of data) if (e?.url && e?.online) set.add(e.url);
      setCache(key, set, CONFIG.FEED_TTL_HOURS * 3600);
      return set.has(url);
    } catch { return null; }
  }
  return cached.has(url);
}

export async function checkGoogleSafeBrowsing(url: string): Promise<boolean | null> {
  if (!CONFIG.GSB_KEY) return null;
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.GSB_KEY}`;
    const payload = {
      client: { clientId: 'insper-detector', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };
    const r = await request(endpoint, { method: 'POST', body: JSON.stringify(payload), headers: { 'content-type': 'application/json' } });
    const data = JSON.parse(await r.body.text());
    return Boolean(data?.matches && data.matches.length);
  } catch { return null; }
}
