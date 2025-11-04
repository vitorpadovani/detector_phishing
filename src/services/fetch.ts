import { request } from 'undici';
import * as cheerio from 'cheerio';
import { extractDomain } from './dns';

export async function headExpand(url: string): Promise<{ finalUrl: string; chain: string[] }>{ 
  const chain: string[] = [];
  let current = url;
  for (let i = 0; i < 10; i++) {
    const res = await request(current, { method: 'HEAD', maxRedirections: 0, headers: { 'User-Agent': ua() } }).catch(() => null);
    if (!res) break;
    const loc = res.headers['location'] as string | undefined;
    if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && loc) {
      chain.push(loc);
      if (/^https?:\/\//i.test(loc)) current = loc; else current = new URL(loc, current).toString();
    } else {
      break;
    }
  }
  return { finalUrl: current, chain };
}

export async function fetchHTML(url: string): Promise<{ html: string; finalUrl: string; redirects: number }>{ 
  const res = await request(url, { method: 'GET', headers: { 'User-Agent': ua() }, maxRedirections: 5 });
  const body = await res.body.text();
  const finalUrl = (res.headers['content-location'] as string) || url;
  const redirects = 0;
  return { html: body, finalUrl, redirects };
}

export function detectMetaRefresh(html: string, baseUrl: string): string | null {
  try {
    const $ = cheerio.load(html);
    const metas = $('meta[http-equiv]');
    let to: string | null = null;
    metas.each((_, el) => {
      const v = ($(el).attr('http-equiv') || '').toLowerCase();
      if (v.includes('refresh')) {
        const content = $(el).attr('content') || '';
        const m = /url=([^;]+)/i.exec(content);
        if (m) {
          const loc = m[1].trim();
          to = new URL(loc, baseUrl).toString();
        }
      }
    });
    return to;
  } catch { return null; }
}

export function analyzeContent(html: string, baseUrl: string) {
  const $ = cheerio.load(html);
  const forms = $('form');
  const hasPassword = $('input[type="password"]').length > 0;
  const inputs = $('input').toArray().map((el) => ($(el).attr('name') || '').toLowerCase());
  const text = $('body').text().toLowerCase();

  const SUSPICIOUS = new Set(['senha','cpf','cartao','cartão','cvv','token','codigo','código','verificação','atualização','urgente','bloqueio','desbloqueio','pix','2fa','otp','login','acesso','fatura','premio','prêmio']);
  const keywordsFound = Array.from(SUSPICIOUS).filter((k) => text.includes(k));

  const loginLike = text.includes('login') || text.includes('sign in') || text.includes('acesso');
  const sensitiveForm = hasPassword || inputs.some((n) => ['cpf','cvv','token','otp','2fa','senha'].some((k) => n.includes(k)));

  const crossDomainForms: string[] = [];
  const baseDomain = extractDomain(baseUrl);
  forms.each((_, f) => {
    const action = $(f).attr('action') || '';
    if (action) {
      const abs = new URL(action, baseUrl).toString();
      const d = extractDomain(abs);
      if (d && d !== baseDomain) crossDomainForms.push(abs);
    }
  });

  const tricks: string[] = [];
  const htmlStr = $.html();
  if (htmlStr.includes('oncontextmenu')) tricks.push('Bloqueio de clique direito');
  if (/setTimeout\(.*?\)/.test(htmlStr)) tricks.push('Uso de temporizadores (potencial urgência)');

  return {
    forms: forms.length,
    hasPassword,
    loginLike,
    sensitiveForm,
    keywordsFound,
    crossDomainForms,
    tricks
  };
}

function ua() {
  return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
}
