const LEVEL_COLORS = {
  safe: '#10b981', low: '#84cc16', medium: '#f59e0b',
  high: '#ef4444', critical: '#dc2626', unknown: '#64748b'
};

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return showError('No active tab found.');

  chrome.runtime.sendMessage({ type: 'GET_SCAN', tabId: tab.id }, (result) => {
    if (result) {
      renderResult(result, tab.url);
    } else {
      // Trigger a fresh scan
      fetchScan(tab.url);
    }
  });
}

async function fetchScan(url) {
  try {
    const resp = await fetch('http://localhost:8000/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input_value: url, input_type: 'url' })
    });
    if (!resp.ok) throw new Error('API error');
    const data = await resp.json();
    renderResult(data, url);
  } catch (e) {
    showError('Backend not reachable. Start the Phishara server.');
  }
}

function renderResult(data, url) {
  const level = data.risk_level || 'unknown';
  const score = Math.round(data.risk_score || 0);
  const color = LEVEL_COLORS[level];

  const findings = (data.explanation || []).slice(0, 4)
    .map(e => `<div class="finding">${e}</div>`).join('');

  document.getElementById('content').innerHTML = `
    <div class="url-text">${(url || '').substring(0, 60)}${url?.length > 60 ? '...' : ''}</div>
    <div class="status-card">
      <div class="score-row">
        <div>
          <div style="font-size:10px;color:#64748b;margin-bottom:4px;text-transform:uppercase">Risk Score</div>
          <div class="score-num" style="color:${color}">${score}</div>
        </div>
        <span class="badge ${level}">${level.toUpperCase()}</span>
      </div>
      <div class="bar-wrap">
        <div class="bar" style="width:${score}%;background:${color}"></div>
      </div>
    </div>
    <div class="findings">${findings || '<div class="finding" style="border-color:var(--safe)">No threats detected</div>'}</div>
    <div style="margin-top:12px">
      <button class="open-btn" onclick="chrome.tabs.create({url:'http://localhost:3000'})">
        Open Phishara Dashboard →
      </button>
    </div>
  `;
}

function showError(msg) {
  document.getElementById('content').innerHTML = `
    <div style="text-align:center;padding:20px;color:#64748b">
      <div style="font-size:32px;margin-bottom:10px">⚠️</div>
      <div style="font-size:12px">${msg}</div>
    </div>
  `;
}

init();
