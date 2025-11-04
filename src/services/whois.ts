import whoiser from 'whoiser';

export async function whoisAgeDays(domain: string): Promise<number | null> {
  try {
    const data: any = await whoiser(domain, { follow: 1 });
    const node = data?.[domain] || data;
    const creation = node?.creationDate || node?.['Creation Date'] || node?.creationDate;
    if (!creation) return null;
    const created = new Date(Array.isArray(creation) ? creation[0] : creation);
    const diff = Date.now() - created.getTime();
    return Math.floor(diff / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}
