import { distance } from 'fastest-levenshtein';
import { parse } from 'tldts';

export const BRAND_DOMAINS: Record<string,string[]> = {
  google: ['google.com','google.com.br'],
  facebook: ['facebook.com'],
  microsoft: ['microsoft.com','live.com','office.com'],
  apple: ['apple.com','icloud.com'],
  paypal: ['paypal.com'],
  amazon: ['amazon.com','amazon.com.br'],
  netflix: ['netflix.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  bb: ['bb.com.br','bancobrasil.com.br'],
  itau: ['itau.com.br'],
  caixa: ['caixa.gov.br'],
  bradesco: ['bradesco.com.br'],
  nubank: ['nubank.com.br']
};

export function brandSimilarity(domain: string): Array<[string, number, string]> {
  const info = parse(domain);
  const registrable = (info.domain || info.hostname || domain).split('.')[0];
  const results: Array<[string, number, string]> = [];
  for (const brand of Object.keys(BRAND_DOMAINS)) {
    const d = distance(registrable.toLowerCase(), brand.toLowerCase());
    const maxLen = Math.max(registrable.length, brand.length) || 1;
    const ratio = Math.round(100 * (1 - d / maxLen));
    if (ratio >= 80 && registrable.toLowerCase() !== brand.toLowerCase()) {
      results.push([brand, ratio, BRAND_DOMAINS[brand].join(', ')]);
    }
  }
  results.sort((a, b) => b[1] - a[1]);
  return results;
}
