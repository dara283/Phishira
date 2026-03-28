import React, { useState } from 'react';
import { headlessScan } from '../api';
import './BehaviourScanPage.css';

const VERDICT_CONFIG = {
  Safe:      { color: 'var(--safe)',   bg: 'var(--safe-dim)',     icon: <CheckIcon /> },
  Suspicious:{ color: 'var(--medium)', bg: 'var(--medium-dim)',   icon: <WarnIcon /> },
  Dangerous: { color: 'var(--high)',   bg: 'var(--high-dim)',     icon: <DangerIcon /> },
};

const CHECKS = [
  { key: 'has_password_field', label: 'Asks for your password',         invert: true },
  { key: 'has_login_form',     label: 'Contains a login form',          invert: true },
  { key: 'hidden_iframes',     label: 'Has hidden sections (iframes)',  invert: true, isArray: true },
  { key: 'suspicious_scripts', label: 'Runs suspicious hidden code',    invert: true, isArray: true },
  { key: 'popups_attempted',   label: 'Tried to open popups',           invert: true, isNum: true },
];

export default function BehaviourScanPage() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [step, setStep] = useState('');

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);

    // Show progress steps so user knows it's working
    setStep('Opening page in hidden browser...');
    setTimeout(() => setStep('Checking for login forms and password fields...'), 3000);
    setTimeout(() => setStep('Looking for hidden iframes and suspicious scripts...'), 7000);
    setTimeout(() => setStep('Watching for automatic redirects...'), 11000);

    try {
      const data = await headlessScan(url.trim());
      setResult(data);
    } catch {
      setError('Could not run the behaviour scan. Make sure the backend is running.');
    } finally {
      setLoading(false);
      setStep('');
    }
  };

  const cfg = result ? (VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.Safe) : null;

  return (
    <div className="behaviour-page">
      <div className="page-header">
        <h1 className="page-title">Behaviour scan</h1>
        <p className="page-subtitle">
          Opens the website in a hidden browser and watches what it actually does —
          not just what the link looks like
        </p>
      </div>

      {/* How it works strip */}
      <div className="how-strip">
        {[
          { n: '1', text: 'Opens the URL in a real hidden browser' },
          { n: '2', text: 'Checks for login forms, password fields, hidden iframes' },
          { n: '3', text: 'Watches for suspicious scripts and auto-redirects' },
          { n: '4', text: 'Returns Safe, Suspicious, or Dangerous' },
        ].map(s => (
          <div key={s.n} className="how-step-chip">
            <span className="how-step-n">{s.n}</span>
            <span className="how-step-text">{s.text}</span>
          </div>
        ))}
      </div>

      {/* Input */}
      <div className="card behaviour-input-card">
        <form onSubmit={handleScan}>
          <div className="scan-input-row">
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="Paste a website link to analyse its behaviour..."
              disabled={loading}
              autoFocus
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading || !url.trim()}
              style={{ minWidth: 130 }}
            >
              {loading ? <><span className="spinner" /> Scanning</> : 'Run scan'}
            </button>
          </div>
        </form>

        {loading && step && (
          <div className="scan-progress">
            <span className="spinner" style={{ width: 14, height: 14 }} />
            {step}
          </div>
        )}
      </div>

      {error && (
        <div className="scan-error" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="behaviour-result">

          {/* Verdict banner */}
          <div className="verdict-banner card" style={{ borderColor: cfg.color, background: cfg.bg }}>
            <div className="verdict-icon" style={{ color: cfg.color }}>{cfg.icon}</div>
            <div>
              <div className="verdict-label" style={{ color: cfg.color }}>
                {result.verdict}
              </div>
              <div className="verdict-score">Behaviour score: {result.score} / 100</div>
              {result.details?.page_title && (
                <div className="verdict-title">"{result.details.page_title}"</div>
              )}
            </div>
          </div>

          {/* What we found */}
          <div className="card">
            <div className="behaviour-section-title">What we found</div>
            <div className="signals-list">
              {result.signals?.map((s, i) => (
                <div key={i} className={`signal-row ${result.verdict.toLowerCase()}`}>
                  <span className="signal-dot" />
                  {s}
                </div>
              ))}
            </div>
          </div>

          {/* Checklist */}
          <div className="card">
            <div className="behaviour-section-title">Checks performed</div>
            <div className="checks-list">
              {CHECKS.map(c => {
                const val = result.details?.[c.key];
                const triggered = c.isArray ? val?.length > 0 : c.isNum ? val > 0 : val === true;
                const ok = c.invert ? !triggered : triggered;
                return (
                  <div key={c.key} className="check-row">
                    <span className={`check-icon ${ok ? 'pass' : 'fail'}`}>
                      {ok
                        ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                      }
                    </span>
                    <span className="check-label">{c.label}</span>
                    {c.isArray && val?.length > 0 && (
                      <span className="check-count">{val.length} found</span>
                    )}
                    {c.isNum && val > 0 && (
                      <span className="check-count">{val}</span>
                    )}
                  </div>
                );
              })}

              {/* Redirects */}
              <div className="check-row">
                <span className={`check-icon ${(result.details?.auto_redirects?.length || 0) <= 1 ? 'pass' : 'fail'}`}>
                  {(result.details?.auto_redirects?.length || 0) <= 1
                    ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                  }
                </span>
                <span className="check-label">Automatic redirects</span>
                <span className="check-count">
                  {result.details?.auto_redirects?.length || 0} detected
                </span>
              </div>
            </div>
          </div>

          {/* Final URL if different */}
          {result.details?.final_url && result.details.final_url !== url && (
            <div className="card">
              <div className="behaviour-section-title">Final destination</div>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
                The link took you to a different address than the one you entered:
              </p>
              <code className="final-url">{result.details.final_url}</code>
            </div>
          )}

          {/* External requests */}
          {result.details?.external_requests?.length > 0 && (
            <div className="card">
              <div className="behaviour-section-title">
                Background requests ({result.details.external_requests.length})
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 10 }}>
                Other websites this page contacted without you knowing:
              </p>
              <div className="ext-req-list">
                {result.details.external_requests.slice(0, 10).map((r, i) => (
                  <div key={i} className="ext-req-row">{r}</div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

const CheckIcon  = () => <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>;
const WarnIcon   = () => <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const DangerIcon = () => <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>;
