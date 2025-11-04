interface CacheEntry<T> { value: T; expiresAt: number; }
const store = new Map<string, CacheEntry<any>>();

export function setCache<T>(key: string, value: T, ttlSeconds: number) {
  store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}
export function getCache<T>(key: string): T | undefined {
  const e = store.get(key);
  if (!e) return undefined;
  if (Date.now() > e.expiresAt) { store.delete(key); return undefined; }
  return e.value as T;
}
