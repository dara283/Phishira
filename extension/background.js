const API_BASE = 'http://localhost:8000';
const cache = new Map(); // url -> result

chrome.webNavigation.onCompleted.addListener(async ({ tabId, url, frameId }) => {
  if (frameId !== 0) return;
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  // Check cache
  if (cache.has(url)) {
    const cached = cache.get(url);
    updateBadge(tabId, cached.risk_level);
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input_value: url, input_type: 'url' })
    });

    if (!resp.ok) return;
    const data = await resp.json();
    cache.set(url, data);

    // Store result for popup
    await chrome.storage.local.set({ [`scan_${tabId}`]: data });

    updateBadge(tabId, data.risk_level);

    // Inject warning for high/critical
    if (data.risk_level === 'high' || data.risk_level === 'critical') {
      chrome.scripting.executeScript({
        target: { tabId },
        func: showWarningBanner,
        args: [data.risk_score, data.risk_level, data.explanation]
      });
    }
  } catch (e) {
    console.error('Phishara scan error:', e);
  }
});

function updateBadge(tabId, level) {
  const colors = {
    safe: '#10b981',
    low: '#84cc16',
    medium: '#f59e0b',
    high: '#ef4444',
    critical: '#dc2626',
    unknown: '#64748b'
  };
  const labels = { safe: 'OK', low: 'LOW', medium: 'MED', high: 'HIGH', critical: '!!!', unknown: '?' };

  chrome.action.setBadgeText({ tabId, text: labels[level] || '?' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[level] || '#64748b' });
}

function showWarningBanner(score, level, explanation) {
  if (document.getElementById('phishara-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishara-warning';
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${level === 'critical' ? '#dc2626' : '#ef4444'};
    color: white; padding: 12px 20px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px; display: flex; align-items: center; gap: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  `;

  const reasons = (explanation || []).slice(0, 2).join(' • ');
  banner.innerHTML = `
    <span style="font-size:20px">🚨</span>
    <div style="flex:1">
      <strong>Phishara Warning — Risk Score: ${Math.round(score)}/100 (${level.toUpperCase()})</strong>
      <div style="font-size:12px;opacity:0.9;margin-top:2px">${reasons}</div>
    </div>
    <button onclick="this.parentElement.remove()" style="
      background:rgba(255,255,255,0.2); border:none; color:white;
      padding:6px 12px; border-radius:6px; cursor:pointer; font-size:12px
    ">Dismiss</button>
  `;

  document.body.prepend(banner);
}

// Listen for popup requests
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_SCAN') {
    chrome.storage.local.get([`scan_${msg.tabId}`], (result) => {
      sendResponse(result[`scan_${msg.tabId}`] || null);
    });
    return true;
  }
});
