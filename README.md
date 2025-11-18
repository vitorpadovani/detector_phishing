# Detector de Phishing
Prova FInal Tecnologias Hacker - 7° Semestre Engenharia da Computação

Link do funcionamento: https://youtu.be/Z2xgmKnYmKE



Uma ferramenta **web** e **API** em Node.js + TypeScript que analisa URLs e páginas para detectar possíveis **phishing**.


## Como funciona
1. **Normaliza a URL** (adiciona `http://` se necessário).
2. **HEAD expand** para encurtadores → registra a cadeia de redirects.
3. **Heurísticas** de URL/domínio (subdomínios, caracteres, leet, DDNS).
4. **Listas**: consulta aos feeds (OpenPhish/PhishTank, com cache) e ao **GSB** se configurado.
5. **WHOIS**: extrai data de criação e calcula idade em dias.
6. **SSL**: obtém o certificado via `tls.connect()` e verifica SAN/expiração.
7. **GET** da página final: analisa HTML (forms, palavras, `meta refresh`, *cross-domain form actions*).
8. **Similaridade** com marcas (Levenshtein percentual).
9. **Score 0–100**: soma ponderada dos sinais (cap em 100) → **veredito**:
   - 0–34: *Provavelmente segura*
   - 35–64: *Suspeita*
   - 65–100: *Maliciosa*


## Instalação & Execução
No diretório do projeto:
```bash
npm install              
cp .env.example .env 
npm run dev                  # modo desenvolvimento (ts-node-dev)
# ou
npm run build && npm start   # build para dist/ e executa JS compilado
```

> **npm moderno** pode omitir devDependencies se você usar `--omit=dev`.  
> Para garantir instalação das devDeps (onde está o `ts-node-dev`), use:
> ```bash
> npm install --omit=dev=false
> ```

Abra o navegador em **http://localhost:3000**.

## Endpoints da API
- `GET /api/health` → `{ ok: true }`
- `POST /api/analyze` → analisa uma URL  
  **Body**:
  ```json
  { "url": "https://exemplo.com" }
  ```
  **Resposta (resumo)**:
  ```json
  {
    "finalUrl": "https://...",
    "domain": "exemplo.com",
    "riskScore": 42,
    "verdict": "SUSPEITA",
    "signals": [{ "name": "...", "weight": 10, "detail": "..." }],
    "meta": { "whoisAgeDays": 123, "ssl": { ... }, "content": { ... } }
  }
  ```
- `GET /api/history` → histórico (mais recente primeiro)
- `GET /api/stats` → contagem por classe (seguro/suspeita/malicioso)
- *(Opcional, se você aplicou o patch do botão “Limpar histórico”)*  
  `DELETE /api/history` → limpa `data/history.json`

### Exemplos `curl`
```bash
curl -s http://localhost:3000/api/health
curl -s -X POST http://localhost:3000/api/analyze -H 'content-type: application/json'   -d '{"url":"https://example.com"}' | jq
curl -s http://localhost:3000/api/history | jq '.[:3]'
curl -s http://localhost:3000/api/stats | jq
```

## Interface Web
- Campo para colar a URL (encurtadas são expandidas).
- Cartão de **resultado** com **score** e **veredito**.
- Tabela de **sinais** (indicador, peso, detalhes) e **Detalhes técnicos** (WHOIS/SSL/Conteúdo).
- **Histórico** com filtro e **gráfico** de distribuição (Chart.js).
- Botão **“Limpar histórico”** se você adicionou a rota `DELETE /api/history`.

## Dicas de teste
- **Typosquatting**: `https://g00gle-security-check.example` (leet).
- **DDNS**: `http://exemplo.no-ip.org/login`.
- **Sem HTTPS**: `http://example.com`.
- **Form de login**: uma página com `<input type="password">`.
- **Redirecionamentos**: use um encurtador (bit.ly) para ver a expansão.

## Aviso
Ferramenta educacional. Pode gerar **falsos positivos/negativos**. Não substitui soluções comerciais, sandboxing ou análise humana.
