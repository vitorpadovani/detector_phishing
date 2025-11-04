import express from 'express';
import path from 'path';
import cors from 'cors';
import morgan from 'morgan';
import fs from 'fs';
import { CONFIG } from './config';
import { extractDomain, hasExcessiveSubdomains, hasSuspiciousChars, isDynamicDNS, isShortener, looksLikeLeet } from './services/dns';
import { headExpand, fetchHTML, detectMetaRefresh, analyzeContent } from './services/fetch';
import { whoisAgeDays } from './services/whois';
import { sslCertificateInfo } from './services/ssl';
import { brandSimilarity } from './services/brand';
import { checkGoogleSafeBrowsing, checkOpenPhish, checkPhishTank } from './services/blacklists';
import { totalScore, verdictFromScore } from './services/score';
import type { AnalysisResult, Signal } from './types';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

// Persistência simples (JSON) — produção: troque por DB
const DATA_DIR = path.join(__dirname, '..', 'data');
const HISTORY_PATH = path.join(DATA_DIR, 'history.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(HISTORY_PATH)) fs.writeFileSync(HISTORY_PATH, '[]', 'utf-8');

function appendHistory(row: AnalysisResult) {
  const arr: AnalysisResult[] = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf-8'));
  arr.push(row);
  fs.writeFileSync(HISTORY_PATH, JSON.stringify(arr, null, 2), 'utf-8');
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.get('/api/history', (_req, res) => {
  const arr: AnalysisResult[] = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf-8'));
  res.json(arr.slice(-500).reverse());
});

app.get('/api/stats', (_req, res) => {
  const arr: AnalysisResult[] = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf-8'));
  const bins = { seguro: 0, suspeita: 0, malicioso: 0 };
  for (const r of arr) {
    if (r.riskScore <= 34) bins.seguro++; else if (r.riskScore <= 64) bins.suspeita++; else bins.malicioso++;
  }
  res.json(bins);
});

app.post('/api/analyze', async (req, res) => {
  try {
    const urlInput = String(req.body?.url || '').trim();
    if (!urlInput) return res.status(400).json({ error: 'URL é obrigatória' });

    const normalized = /^https?:\/\//i.test(urlInput) ? urlInput : `http://${urlInput}`;
    const domain0 = extractDomain(normalized);

    const signals: Signal[] = [];

    // 1) Encurtadores + expansão
    const { finalUrl: headFinal, chain } = await headExpand(normalized);
    let finalUrl = headFinal;
    const finalDomain = extractDomain(finalUrl);
    if (isShortener(domain0) && chain.length) {
      signals.push({ name: 'URL encurtada (expandida)', weight: 8, detail: `Redirecionamentos: ${chain.length}` });
    }

    // 2) Heurísticas básicas (Conceito C)
    const sub = hasExcessiveSubdomains(finalUrl);
    if (sub.excessive) signals.push({ name: 'Excesso de subdomínios', weight: 7, detail: `${sub.count} subdomínios` });

    const chars = hasSuspiciousChars(finalUrl);
    if (chars.length) signals.push({ name: 'Caracteres suspeitos na URL', weight: 5, detail: `Encontrados: ${chars.join(' ')}` });

    const leet = looksLikeLeet(finalDomain);
    if (leet.length) signals.push({ name: 'Semelhança visual (leet)', weight: 6, detail: `Substituições: ${JSON.stringify(leet)}` });

    // 3) Blacklists
    const [openPhish, phishTank, gsb] = await Promise.all([
      checkOpenPhish(finalUrl),
      checkPhishTank(finalUrl),
      checkGoogleSafeBrowsing(finalUrl)
    ]);
    if (openPhish === true) signals.push({ name: 'Listas: OpenPhish', weight: 35, detail: 'Consta como phishing ativo' });
    if (phishTank === true) signals.push({ name: 'Listas: PhishTank', weight: 35, detail: 'Consta como phishing ativo' });
    if (gsb === true) signals.push({ name: 'Google Safe Browsing', weight: 30, detail: 'Identificado como ameaça' });

    // 4) WHOIS
    const age = await whoisAgeDays(finalDomain);
    if (age !== null) {
      if (age < 30) signals.push({ name: 'Domínio muito recente', weight: 15, detail: `${age} dias` });
      else if (age < 180) signals.push({ name: 'Domínio jovem', weight: 8, detail: `${age} dias` });
    } else {
      signals.push({ name: 'WHOIS indisponível', weight: 3, detail: 'Não foi possível obter a idade' });
    }

    // 5) DNS dinâmico
    if (isDynamicDNS(finalDomain)) signals.push({ name: 'DNS dinâmico', weight: 10, detail: `${finalDomain} em provedor de DDNS` });

    // 6) SSL/TLS
    const ssl = await sslCertificateInfo(finalDomain);
    if (ssl.present) {
      if (ssl.hostnameMatches === false) signals.push({ name: 'Certificado SSL não corresponde', weight: 18, detail: 'Hostname mismatch' });
      if (typeof ssl.daysToExpire === 'number') {
        if (ssl.daysToExpire < 0) signals.push({ name: 'Certificado expirado', weight: 15, detail: `${ssl.daysToExpire} dias para expirar (negativo)` });
        else if (ssl.daysToExpire < 14) signals.push({ name: 'Certificado prestes a expirar', weight: 4, detail: `expira em ${ssl.daysToExpire} dias` });
      }
    } else {
      if (finalUrl.toLowerCase().startsWith('https://')) signals.push({ name: 'Falha ao inspecionar SSL', weight: 2, detail: 'Não foi possível ler o certificado' });
      else signals.push({ name: 'Sem HTTPS', weight: 8, detail: 'Conexão não segura' });
    }

    // 7) Conteúdo & redirecionamentos
    let contentMeta: any = {};
    try {
      const page = await fetchHTML(finalUrl);
      finalUrl = page.finalUrl || finalUrl;
      const metaTo = detectMetaRefresh(page.html, finalUrl);
      if (metaTo) signals.push({ name: 'Meta refresh', weight: 5, detail: `Redireciona para ${metaTo}` });
      contentMeta = analyzeContent(page.html, finalUrl);
      if (contentMeta.sensitiveForm) signals.push({ name: 'Formulário sensível', weight: 16, detail: 'Coleta senha/CPF/CVV/etc' });
      if (contentMeta.loginLike && contentMeta.forms > 0) signals.push({ name: 'Página de login', weight: 10, detail: 'Formulário de autenticação detectado' });
      if (contentMeta.keywordsFound?.length) signals.push({ name: 'Palavras de pressão/financeiras', weight: 6, detail: contentMeta.keywordsFound.slice(0,8).join(', ') });
      if (contentMeta.crossDomainForms?.length) signals.push({ name: 'Form envia para outro domínio', weight: 10, detail: `${contentMeta.crossDomainForms.length} ação(ões) externas` });
      for (const t of contentMeta.tricks || []) signals.push({ name: 'Comportamento suspeito', weight: 5, detail: t });
    } catch (e: any) {
      signals.push({ name: 'Falha ao baixar página', weight: 5, detail: `${e?.name || 'Erro'}: ${e?.message || e}` });
    }

    // 8) Similaridade com marcas
    const sim = brandSimilarity(finalDomain);
    if (sim.length) {
      const [brand, ratio, legit] = sim[0];
      signals.push({ name: 'Possível typosquatting', weight: 14, detail: `${brand} (~${ratio}%) — legítimos: ${legit}` });
    }

    // Agregação de score
    const riskScore = totalScore(signals);
    const verdict = verdictFromScore(riskScore);

    const result: AnalysisResult = {
      urlInput,
      finalUrl,
      domain: finalDomain,
      createdAt: new Date().toISOString(),
      riskScore,
      verdict,
      signals,
      meta: {
        expandedChainLen: chain.length,
        whoisAgeDays: age,
        ssl,
        content: contentMeta,
        brandSimilarity: sim
      }
    };

    appendHistory(result);
    return res.json(result);
  } catch (e: any) {
    return res.status(500).json({ error: e?.message || 'Erro interno' });
  }
});

// UI estática
app.use(express.static(path.join(__dirname, '..', 'public')));

app.listen(CONFIG.PORT, () => {
  console.log(`Servidor rodando em http://localhost:${CONFIG.PORT}`);
});
