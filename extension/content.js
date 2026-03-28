// Content script: intercept form submissions on high-risk pages
(function () {
  chrome.storage.local.get(null, (items) => {
    // Find scan for current tab — handled by background
  });

  // Listen for warning injection from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'BLOCK_FORMS') {
      blockPasswordForms();
    }
  });

  function blockPasswordForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const hasPassword = form.querySelector('input[type="password"]');
      if (!hasPassword) return;

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();

        const overlay = document.createElement('div');
        overlay.style.cssText = `
          position: fixed; inset: 0; z-index: 2147483647;
          background: rgba(0,0,0,0.85); display: flex;
          align-items: center; justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        `;
        overlay.innerHTML = `
          <div style="background:#1a1a2e; border:1px solid rgba(239,68,68,0.5);
            border-radius:16px; padding:32px; max-width:420px; text-align:center; color:white;">
            <div style="font-size:48px;margin-bottom:16px">🛡️</div>
            <h2 style="color:#ef4444;margin-bottom:8px">Phishara Blocked This Submission</h2>
            <p style="color:#94a3b8;font-size:14px;margin-bottom:20px">
              This page has been flagged as potentially dangerous.
              Submitting your credentials here could compromise your account.
            </p>
            <div style="display:flex;gap:10px;justify-content:center">
              <button onclick="this.closest('div[style]').remove()" style="
                background:#ef4444;color:white;border:none;padding:10px 20px;
                border-radius:8px;cursor:pointer;font-size:14px">
                Go Back (Recommended)
              </button>
              <button onclick="this.closest('div[style]').parentElement.remove()" style="
                background:rgba(255,255,255,0.1);color:white;border:1px solid rgba(255,255,255,0.2);
                padding:10px 20px;border-radius:8px;cursor:pointer;font-size:14px">
                Proceed Anyway
              </button>
            </div>
          </div>
        `;
        document.body.appendChild(overlay);
      }, true);
    });
  }
})();
