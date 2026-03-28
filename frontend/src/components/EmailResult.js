import React, { useState } from 'react';
import RiskMeter from './RiskMeter';
import './EmailResult.css';

const RISK_MESSAGES = {
  safe:     { headline: 'Email looks safe',        sub: 'No dangerous links were found.' },
  low:      { headline: 'Mostly safe',             sub: 'A couple of minor things to be aware of.' },
  medium:   { headline: 'Treat with caution',      sub: 'Some suspicious links or language found.' },
  high:     { headline: 'Likely a scam email',     sub: 'Dangerous links detected — do not click anything.' },
  critical: { headline: 'This is a scam email',    sub: 'Confirmed dangerous links. Delete this email immediately.' },
  unknown:  { headline: 'Could not fully check',   sub: 'We were unable to analyse all links.' },
};

const LEVEL_COLOR = {
  safe: 'var(--safe)', low: 'var(--low)', medium: 'var(--medium)',
  high: 'var(--high)', critical: 'var(--critical)', unknown: 'var(--text-muted)'
};

export default function EmailResult({ result }) {
  const [expanded, setExpanded] = useState(null);
  const d = result.details || {};
  const msg = RISK_MESSAGES[result.risk_level] || RISK_MESSAGES.unknown;
  const linkResults = d.link_scan_results || [];

  return (
    <div className="email-result-wrap">

      {/* Header */}
      <div className="email-summary card">
        <div className="email-summary-left">
          <div className="email-verdict" style={{ color: LEVEL_COLOR[result.risk_level] }}>
            {msg.headline}
          </div>
          <div className="email-verdict-sub">{msg.sub}</div>

          <div className="email-findings">
            {result.explanation?.map((exp, i) => (
              <div key={i} className={`finding-row ${result.risk_level}`}>
                <span className="finding-dot" />
                {exp}
              </div>
            ))}
          </div>
        </div>
        <RiskMeter score={result.risk_score} level={result.risk_level} />
      </div>

      {/* Stats row */}
      <div className="email-stats">
        <div className="email-stat card">
          <div className="email-stat-num">{d.link_count || 0}</div>
          <div className="email-stat-label">Links found</div>
        </div>
        <div className="email-stat card">
          <div className="email-stat-num" style={{ color: 'var(--high)' }}>
            {linkResults.filter(l => ['high','critical'].includes(l.risk_level)).length}
          </div>
          <div className="email-stat-label">Dangerous links</div>
        </div>
        <div className="email-stat card">
          <div className="email-stat-num" style={{ color: 'var(--medium)' }}>
            {(d.urgency_words_found || []).length}
          </div>
          <div className="email-stat-label">Pressure words</div>
        </div>
      </div>

      {/* Link results */}
      {linkResults.length > 0 && (
        <div className="card">
          <div className="email-section-title">Links found in this email</div>
          <div className="link-list">
            {linkResults.map((lr, i) => (
              <div key={i} className={`link-row ${lr.risk_level}`}>
                <div className="link-row-top">
                  <span className={`badge badge-${lr.risk_level}`}>
                    {lr.risk_level === 'safe' ? 'Safe' :
                     lr.risk_level === 'low' ? 'Low risk' :
                     lr.risk_level === 'medium' ? 'Suspicious' :
                     lr.risk_level === 'high' ? 'Dangerous' :
                     lr.risk_level === 'critical' ? 'Very dangerous' : lr.risk_level}
                  </span>
                  {lr.malware_db_hit && (
                    <span className="badge badge-critical" style={{ fontSize: 10 }}>Malware DB</span>
                  )}
                  <span className="link-url">{lr.url}</span>
                  <span className="link-score">{Math.round(lr.risk_score)}/100</span>
                  {lr.findings?.length > 0 && (
                    <button
                      className="link-expand-btn"
                      onClick={() => setExpanded(expanded === i ? null : i)}
                    >
                      {expanded === i ? 'Hide' : 'Details'}
                    </button>
                  )}
                </div>
                {lr.sources_flagged?.length > 0 && (
                  <div className="link-db-sources">
                    Found in: {lr.sources_flagged.join(' · ')}
                  </div>
                )}
                {expanded === i && lr.findings?.length > 0 && (
                  <div className="link-findings">
                    {lr.findings.map((f, j) => (
                      <div key={j} className="link-finding">{f}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Urgency words */}
      {(d.urgency_words_found || []).length > 0 && (
        <div className="card">
          <div className="email-section-title">Pressure language detected</div>
          <p className="email-section-sub">
            Scammers use these words to make you panic and act without thinking.
          </p>
          <div className="urgency-chips">
            {d.urgency_words_found.map(w => (
              <span key={w} className="urgency-chip">{w}</span>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
