async function clearHistory() {
  const ok = confirm('Tem certeza que deseja limpar todo o histórico?');
  if (!ok) return;
  const res = await fetch('/api/history', { method: 'DELETE' });
  if (!res.ok) throw new Error('Falha ao limpar histórico');
  await refresh();
}

// no topo, após selecionar elementos:
const clearBtn = document.getElementById('clear');

// depois dos outros listeners:
clearBtn.addEventListener('click', async () => {
  try {
    await clearHistory();
  } catch (e) {
    alert(String(e));
  }
});


async function analyze(url) {
  const res = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
  if (!res.ok) throw new Error('Falha na análise');
  return res.json();
}
async function loadHistory() {
  const res = await fetch('/api/history');
  return res.json();
}
async function loadStats() {
  const res = await fetch('/api/stats');
  return res.json();
}

const form = document.getElementById('form');
const urlInput = document.getElementById('url');
const result = document.getElementById('result');
const filter = document.getElementById('filter');
const refreshBtn = document.getElementById('refresh');
const tbody = document.querySelector('#history tbody');

let chart;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;
  result.classList.remove('hidden');
  result.innerHTML = '<div class="muted">Analisando...</div>';
  try {
    const data = await analyze(url);
    const color = data.verdict === 'MALICIOSA' ? 'red' : (data.verdict === 'SUSPEITA' ? 'orange' : 'green');
    const signalsRows = data.signals.map((s) => `<tr><td>${escapeHtml(s.name)}</td><td>${s.weight}</td><td>${escapeHtml(s.detail)}</td></tr>`).join('');
    result.innerHTML = `
      <div class="card">
        <h2>Resultado: <span class="badge ${color}">${data.verdict}</span> — Score ${data.riskScore}/100</h2>
        <p><b>URL final:</b> ${escapeHtml(data.finalUrl)}<br/><b>Domínio:</b> ${escapeHtml(data.domain)}</p>
        <details open>
          <summary><b>Sinais detectados</b></summary>
          <table><thead><tr><th>Indicador</th><th>Peso</th><th>Detalhes</th></tr></thead><tbody>${signalsRows}</tbody></table>
        </details>
        <details>
          <summary><b>Detalhes técnicos</b></summary>
          <pre>${escapeHtml(JSON.stringify(data.meta, null, 2))}</pre>
        </details>
      </div>
    `;
    await refresh();
  } catch (err) {
    result.innerHTML = `<div class="card">Erro: ${escapeHtml(String(err))}</div>`;
  }
});

refreshBtn.addEventListener('click', refresh);
filter.addEventListener('input', renderHistory);

async function refresh() {
  const [hist, stats] = await Promise.all([loadHistory(), loadStats()]);
  window.__hist = hist;
  renderHistory();
  renderChart(stats);
}

function renderHistory() {
  const hist = window.__hist || [];
  const q = (filter.value || '').toLowerCase();
  const rows = hist.filter((r) => !q || r.finalUrl.toLowerCase().includes(q) || r.domain.toLowerCase().includes(q))
    .map((r) => `<tr><td>${new Date(r.createdAt).toLocaleString()}</td><td>${escapeHtml(r.finalUrl)}</td><td>${escapeHtml(r.domain)}</td><td>${r.riskScore}</td><td>${r.verdict}</td></tr>`)
    .join('');
  tbody.innerHTML = rows || '<tr><td colspan="5" class="muted">sem dados</td></tr>';
}

function renderChart(stats) {
  const ctx = document.getElementById('chart');
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: 'bar',
    data: { labels: ['Seguro','Suspeita','Malicioso'], datasets: [{ label: 'Contagem', data: [stats.seguro, stats.suspeita, stats.malicioso] }] },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

function escapeHtml(s) { return s.replace(/[&<>"]+/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// inicial
refresh();
