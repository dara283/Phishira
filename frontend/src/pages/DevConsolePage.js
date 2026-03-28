import React, { useState } from 'react';
import { scan } from '../api';
import RedirectChain from '../components/RedirectChain';
import RiskMeter from '../components/RiskMeter';

export default function DevConsolePage() {
  const [input, setInput] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [activePanel, setActivePanel] = useState('overview');

  const handleScan = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await scan(input.trim(), 'auto');
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const d = result?.details || {};
  const panels = ['overview', 'redirects', 'forms', 'network', 'threat-intel', 'raw'];

  return (
    <div>
      <div className="page-title">⚙️ Developer Console</div>
      <div className="page-subtitle">Deep threat analysis for security researchers</div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginBottom: 20 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="Enter URL, email, or phone for deep analysis..."
          style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13 }}
        />
        <button className="btn btn-primary" onClick={handleScan} disabled={loading}>
          {loading ? <span className="spinner" /> : '▶ Analyze'}
        </button>
      </div>

      {error && (
        <div style={{
          padding: '10px 14px', background: 'rgba(239,68,68,0.1)',
          border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8,
          color: 'var(--high)', fontSize: 13, marginBottom: 16
        }}>⚠️ {error}</div>
      )}

      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px', gap: 20 }}>
          {/* Main panel */}
          <div>
            {/* Panel tabs */}
            <div style={{ display: 'flex', gap: 2, marginBottom: 16, flexWrap: 'wrap' }}>
              {panels.map(p => (
                <button key={p} onClick={() => setActivePanel(p)} style={{
                  background: activePanel === p ? 'var(--accent-glow)' : 'var(--bg-secondary)',
                  border: `1px solid ${activePanel === p ? 'rgba(0,212,255,0.3)' : 'var(--border)'}`,
                  color: activePanel === p ? 'var(--accent)' : 'var(--text-secondary)',
                  padding: '6px 12px', borderRadius: 6, cursor: 'pointer',
                  fontSize: 12, fontWeight: 500, textTransform: 'capitalize'
                }}>{p.replace('-', ' ')}</button>
              ))}
            </div>

            <div className="card">
              {activePanel === 'overview' && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>
                    ANALYSIS SUMMARY
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
                    {[
                      ['URL', d.url || result.input_value],
                      ['Domain', d.domain || '—'],
                      ['TLD', d.tld || '—'],
                      ['Subdomain', d.subdomain || 'none'],
                      ['IP Address', d.ip_address || 'unknown'],
                      ['Country', d.country || 'unknown'],
                      ['Registrar', d.registrar || 'unknown'],
                      ['Domain Age', d.domain_age_days != null ? `${d.domain_age_days} days` : 'unknown'],
                      ['HTTPS', d.is_https ? '✅ Yes' : '❌ No'],
                      ['SSL Valid', d.ssl_valid ? '✅ Yes' : '❌ No'],
                      ['Login Form', d.has_login_form ? '⚠️ Yes' : 'No'],
                      ['URL Length', d.url_length || '—'],
                    ].map(([k, v]) => (
                      <div key={k} style={{ background: 'var(--bg-secondary)', borderRadius: 8, padding: '8px 12px' }}>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: 0.5 }}>{k}</div>
                        <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>

                  {d.suspicious_keywords?.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>SUSPICIOUS KEYWORDS</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {d.suspicious_keywords.map(kw => (
                          <span key={kw} className="badge badge-high">{kw}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activePanel === 'redirects' && <RedirectChain chain={d.redirect_chain || []} />}

              {activePanel === 'forms' && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>
                    DETECTED FORMS ({(d.forms || []).length})
                  </div>
                  {(d.forms || []).length === 0
                    ? <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No forms detected on this page.</p>
                    : (d.forms || []).map((form, i) => (
                      <div key={i} style={{ background: 'var(--bg-secondary)', borderRadius: 8, padding: 14, marginBottom: 10 }}>
                        <div style={{ display: 'flex', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Method:</span>
                          <code style={{ fontSize: 11 }}>{form.method?.toUpperCase()}</code>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Action:</span>
                          <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{form.action || '(none)'}</code>
                          {form.has_password_field && <span className="badge badge-critical">⚠️ Password Field</span>}
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {(form.inputs || []).map((inp, j) => (
                            <span key={j} style={{
                              background: inp.type === 'password' ? 'rgba(239,68,68,0.15)' : 'var(--bg-card)',
                              color: inp.type === 'password' ? 'var(--high)' : 'var(--text-secondary)',
                              padding: '3px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace'
                            }}>{inp.type}:{inp.name}</span>
                          ))}
                        </div>
                      </div>
                    ))
                  }
                </div>
              )}

              {activePanel === 'network' && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>
                    EXTERNAL REQUESTS ({(d.external_requests || []).length})
                  </div>
                  {(d.external_requests || []).length === 0
                    ? <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No external requests detected.</p>
                    : (d.external_requests || []).map((req, i) => (
                      <div key={i} style={{
                        padding: '8px 12px', background: 'var(--bg-secondary)',
                        borderRadius: 6, marginBottom: 6, fontSize: 12,
                        fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all',
                        color: 'var(--text-secondary)'
                      }}>
                        <span style={{ color: 'var(--medium)', marginRight: 8 }}>→</span>{req}
                      </div>
                    ))
                  }
                </div>
              )}

              {activePanel === 'threat-intel' && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>
                    THREAT INTELLIGENCE
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <ThreatCard
                      title="VirusTotal"
                      data={d.virustotal}
                      render={vt => vt?.available
                        ? `${vt.positives} / ${vt.total} engines flagged`
                        : 'API key not configured'}
                      flagged={d.virustotal?.positives > 0}
                    />
                    <ThreatCard
                      title="Google Safe Browsing"
                      data={d.google_safe_browsing}
                      render={gsb => gsb ? '⚠️ URL flagged as unsafe' : '✅ Not flagged'}
                      flagged={d.google_safe_browsing === true}
                    />
                  </div>
                </div>
              )}

              {activePanel === 'raw' && (
                <pre style={{
                  fontSize: 11, color: 'var(--text-secondary)', overflow: 'auto',
                  maxHeight: 500, fontFamily: 'JetBrains Mono, monospace'
                }}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              )}
            </div>
          </div>

          {/* Side risk panel */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="card" style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>Risk Score</div>
              <RiskMeter score={result.risk_score} level={result.risk_level} />
            </div>
            {result.input_type === 'url' && (
              <div className="card">
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase' }}>Score Breakdown</div>
                {[
                  ['Domain', d.domain_risk || 0],
                  ['Content', d.content_risk || 0],
                  ['API', d.api_behavior_risk || 0],
                ].map(([label, val]) => (
                  <div key={label} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                      <span style={{ fontWeight: 600 }}>{Math.round(val)}</span>
                    </div>
                    <div className="risk-bar-wrap">
                      <div className="risk-bar" style={{
                        width: `${val}%`,
                        background: val > 60 ? 'var(--high)' : val > 30 ? 'var(--medium)' : 'var(--safe)'
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatCard({ title, data, render, flagged }) {
  return (
    <div style={{
      padding: '12px 16px', background: 'var(--bg-secondary)', borderRadius: 8,
      border: `1px solid ${flagged ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
      display: 'flex', justifyContent: 'space-between', alignItems: 'center'
    }}>
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{title}</div>
        <div style={{ fontSize: 12, color: flagged ? 'var(--high)' : 'var(--safe)' }}>
          {render(data)}
        </div>
      </div>
      <span style={{ fontSize: 20 }}>{flagged ? '🚨' : '✅'}</span>
    </div>
  );
}
