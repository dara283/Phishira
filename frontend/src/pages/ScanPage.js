import React, { useState } from 'react';
import { scan } from '../api';
import ScanResult from '../components/ScanResult';
import EmailResult from '../components/EmailResult';
import './ScanPage.css';

const MODES = [
  { key: 'url',   label: 'Analyse a link',   placeholder: 'Paste a website link here...' },
  { key: 'email', label: 'Analyse an email', placeholder: 'Paste the full email text here — we\'ll extract and check every link inside it...' },
];

const URL_EXAMPLES = [
  { label: 'Suspicious link', value: 'http://paypal-secure-login.tk/verify' },
  { label: 'Normal site',     value: 'https://www.bbc.co.uk' },
];

const EMAIL_EXAMPLE = `Dear Customer,

Your account has been suspended due to unusual activity. 
Please verify your details immediately to avoid permanent closure.

Click here to verify: http://paypal-secure-login.tk/verify
Or visit: http://amaz0n-account-update.xyz/login

This is urgent. Act within 24 hours.

Support Team`;

export default function ScanPage() {
  const [mode, setMode] = useState('url');
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!input.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await scan(input.trim(), mode);
      setResult(data);
    } catch (err) {
      setError('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const currentMode = MODES.find(m => m.key === mode);

  return (
    <div className="scan-page">
      <div className="page-header">
        <h1 className="page-title">Threat analysis</h1>
        <p className="page-subtitle">Submit a link or email to receive an instant security assessment</p>
      </div>

      <div className="scan-card card">
        {/* Mode tabs */}
        <div className="type-tabs">
          {MODES.map(m => (
            <button
              key={m.key}
              className={`type-tab${mode === m.key ? ' active' : ''}`}
              onClick={() => { setMode(m.key); setResult(null); setInput(''); }}
            >
              {m.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleScan} className="scan-form">
          {mode === 'email' ? (
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={currentMode.placeholder}
              disabled={loading}
              rows={7}
              style={{ resize: 'vertical', fontFamily: 'inherit', lineHeight: 1.6 }}
            />
          ) : (
            <div className="scan-input-row">
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder={currentMode.placeholder}
                disabled={loading}
                autoFocus
              />
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary scan-btn"
            disabled={loading || !input.trim()}
            style={{ marginTop: 12, width: mode === 'email' ? '100%' : 'auto' }}
          >
            {loading ? <><span className="spinner" /> Analysing...</> : 'Run analysis'}
          </button>
        </form>

        {/* Examples */}
        <div className="scan-examples">
          <span className="examples-label">Sample inputs</span>
          {mode === 'url'
            ? URL_EXAMPLES.map(ex => (
                <button key={ex.label} className="example-chip" onClick={() => setInput(ex.value)}>
                  {ex.label}
                </button>
              ))
            : (
              <button className="example-chip" onClick={() => setInput(EMAIL_EXAMPLE)}>
                Phishing email example
              </button>
            )
          }
        </div>
      </div>

      {error && <div className="scan-error"><AlertIcon />{error}</div>}

      {result && result.input_type === 'email'
        ? <EmailResult result={result} />
        : result && <ScanResult result={result} />
      }
    </div>
  );
}

const AlertIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);
