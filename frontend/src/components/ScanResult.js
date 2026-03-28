import React, { useState } from 'react';
import RiskMeter from './RiskMeter';
import RedirectChain from './RedirectChain';
import { headlessScan } from '../api';
import './ScanResult.css';

const TABS = ['What we checked', 'Behaviour scan', 'Redirects'];

const RISK_MESSAGES = {
  safe:     { headline: 'No threats detected',       sub: 'This appears to be safe based on our analysis.' },
  low:      { headline: 'Low risk',                  sub: 'A few minor indicators were noted — generally safe to proceed.' },
  medium:   { headline: 'Exercise caution',          sub: 'Several warning signs were identified. Verify before proceeding.' },
  high:     { headline: 'Likely malicious',          sub: 'Multiple indicators of a phishing or scam attempt were detected.' },
  critical: { headline: 'Do not proceed',            sub: 'Strong evidence of a scam. Do not click or submit any information.' },
  unknown:  { headline: 'Analysis incomplete',       sub: 'We were unable to fully assess this item.' },
};

const VERDICT_COLOR = {
  Safe:       'var(--safe)',
  Suspicious: 'var(--medium)',
  Dangerous:  'var(--high)',
};
const VERDICT_BG = {
  Safe:       'var(--safe-dim)',
  Suspicious: 'var(--medium-dim)',
  Dangerous:  'var(--high-dim)',
};

const BEHAVIOUR_CHECKS = [
  { key: 'has_password_field', label: 'Requests password input',                    invert: true },
  { key: 'has_login_form',     label: 'Contains a login or authentication form',    invert: true },
  { key: 'hidden_iframes',     label: 'Hidden frames loading external content',     invert: true, isArray: true },
  { key: 'suspicious_scripts', label: 'Obfuscated or encoded scripts detected',     invert: true, isArray: true },
  { key: 'popups_attempted',   label: 'Attempted to open popup windows',            invert: true, isNum: true },
];

export default function ScanResult({ result }) {
  const [tab, setTab] = useState('What we checked');
  const [headless, setHeadless] = useState(null);
  const [headlessLoading, setHeadlessLoading] = useState(false);
  const [headlessStep, setHeadlessStep] = useState('');
  const d = result.details || {};
  const msg = RISK_MESSAGES[result.risk_level] || RISK_MESSAGES.unknown;
  const scoreColor = (v) => v > 60 ? 'var(--high)' : v > 30 ? 'var(--medium)' : 'var(--safe)';

  const runHeadless = async () => {    setHeadlessLoading(true);
    setHeadless(null);
    setHeadlessStep('Opening page in hidden browser...');
    const t1 = setTimeout(() => setHeadlessStep('Checking for login forms and password fields...'), 3500);
    const t2 = setTimeout(() => setHeadlessStep('Looking for hidden iframes and suspicious scripts...'), 7000);
    const t3 = setTimeout(() => setHeadlessStep('Watching for automatic redirects and popups...'), 11000);
    try {
      const data = await headlessScan(result.input_value);
      setHeadless(data);
    } catch {
      setHeadless({ verdict: 'Error', score: 0, signals: ['Could not run the behaviour scan.'], details: {} });
    } finally {
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      setHeadlessLoading(false);
      setHeadlessStep('');
    }
  };

  return (
    <div className="result-wrap">

      {/* ── Top summary card ── */}
      <div className="result-summary card">
        <div className="result-summary-left">
          <div className="result-verdict-headline" style={{ color: scoreColor(result.risk_score) }}>
            {msg.headline}
          </div>
          <div className="result-verdict-sub">{msg.sub}</div>
          <div className="result-value">{result.input_value}</div>
          <div className="result-findings">
            {result.explanation?.map((exp, i) => (
              <div key={i} className={`finding-row ${result.risk_level}`}>
                <span className="finding-dot" />
                {exp}
              </div>
            ))}
          </div>
        </div>
        <div className="result-summary-right">
          <RiskMeter score={result.risk_score} level={result.risk_level} />
        </div>
      </div>

      {/* ── Score breakdown ── */}
      {result.input_type === 'url' && (
        <div className="score-breakdown">
          {[
            { label: 'Website trustworthiness', value: d.domain_risk || 0 },
            { label: 'Page content safety',     value: d.content_risk || 0 },
            { label: 'Hidden activity',         value: d.api_behavior_risk || 0 },
          ].map(({ label, value }) => (
            <div key={label} className="score-item card">
              <div className="score-item-header">
                <span className="score-item-label">{label}</span>
                <span className="score-item-value" style={{ color: scoreColor(value) }}>
                  {Math.round(value)}
                </span>
              </div>
              <div className="risk-bar-track">
                <div className="risk-bar-fill" style={{ width: `${value}%`, background: scoreColor(value) }} />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Tabs ── */}
      <div className="result-tabs-wrap">
        <div className="result-tabs">
          {TABS.map(t => (
            <button key={t} className={`result-tab${tab === t ? ' active' : ''}`} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </div>

        <div className="result-tab-content card">

          {/* ── WHAT WE CHECKED ── */}
          {tab === 'What we checked' && (
            <div>
              <div className="checks-list">
                <CheckRow label="Secure connection (HTTPS)" ok={d.is_https} />
                <CheckRow label="Valid security certificate" ok={d.ssl_valid} />
                <CheckRow
                  label="Website is established (over 6 months old)"
                  ok={d.domain_age_days != null && d.domain_age_days > 180}
                  detail={d.domain_age_days != null ? `${d.domain_age_days} days old` : null}
                />
                <CheckRow label="No hidden login or password form" ok={!d.has_login_form} />
                <CheckRow
                  label="Goes directly to destination without multiple redirects"
                  ok={(d.redirect_chain?.length || 0) <= 2}
                  detail={(d.redirect_chain?.length || 0) > 2 ? `${d.redirect_chain.length} redirects` : null}
                />
                <CheckRow label="Uses a proper domain name, not a raw IP address" ok={!d.ip_in_url} />
                <CheckRow label="No look-alike letters in the web address" ok={!d.homoglyph_detected} />
                <CheckRow label="Not impersonating a known brand" ok={!d.brand_impersonation}
                  detail={d.brand_impersonation ? `Impersonating ${d.brand_impersonation}` : null}
                />
                <CheckRow
                  label="No suspicious words in the link"
                  ok={!d.suspicious_keywords?.length}
                  detail={d.suspicious_keywords?.length ? d.suspicious_keywords.slice(0,4).join(', ') : null}
                />
              </div>
            </div>
          )}

          {/* ── BEHAVIOUR SCAN ── */}
          {tab === 'Behaviour scan' && (
            <div>
              <p className="tab-intro">
                Loads the URL in an isolated headless browser and monitors its behaviour in real time —
                independent of how the link appears. Effective against phishing sites that pass URL-based checks.
              </p>

              {/* How it works chips */}
              <div className="behaviour-how-strip">
                {[
                  'Opens URL in real hidden browser',
                  'Checks for login forms & password fields',
                  'Looks for hidden iframes & suspicious scripts',
                  'Watches for auto-redirects & popups',
                ].map((s, i) => (
                  <div key={i} className="behaviour-how-chip">
                    <span className="behaviour-how-n">{i + 1}</span>
                    <span className="behaviour-how-text">{s}</span>
                  </div>
                ))}
              </div>

              {!headless && !headlessLoading && (
                <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={runHeadless}>
                  Run behaviour scan
                </button>
              )}

              {headlessLoading && (
                <div className="behaviour-progress">
                  <span className="spinner" style={{ width: 15, height: 15 }} />
                  {headlessStep}
                </div>
              )}

              {headless && headless.verdict !== 'Error' && (
                <div className="behaviour-result-wrap">

                  {/* Verdict banner */}
                  <div className="behaviour-verdict-banner"
                    style={{ borderColor: VERDICT_COLOR[headless.verdict], background: VERDICT_BG[headless.verdict] }}>
                    <div className="behaviour-verdict-icon" style={{ color: VERDICT_COLOR[headless.verdict] }}>
                      {headless.verdict === 'Safe' ? <CheckCircleIcon /> :
                       headless.verdict === 'Suspicious' ? <WarnCircleIcon /> : <DangerCircleIcon />}
                    </div>
                    <div>
                      <div className="behaviour-verdict-label" style={{ color: VERDICT_COLOR[headless.verdict] }}>
                        {headless.verdict}
                      </div>
                      <div className="behaviour-verdict-score">Behaviour score: {headless.score} / 100</div>
                      {headless.details?.page_title && (
                        <div className="behaviour-verdict-title">"{headless.details.page_title}"</div>
                      )}
                    </div>
                  </div>

                  {/* Signals */}
                  {headless.signals?.length > 0 && (
                    <div className="behaviour-signals">
                      <div className="tab-section-label">What we found</div>
                      {headless.signals.map((s, i) => (
                        <div key={i} className={`signal-row ${headless.verdict.toLowerCase()}`}>
                          <span className="signal-dot" />
                          {s}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Checklist */}
                  <div style={{ marginTop: 16 }}>
                    <div className="tab-section-label">Checks performed</div>
                    <div className="checks-list">
                      {BEHAVIOUR_CHECKS.map(c => {
                        const val = headless.details?.[c.key];
                        const triggered = c.isArray ? val?.length > 0 : c.isNum ? val > 0 : val === true;
                        const ok = c.invert ? !triggered : triggered;
                        return (
                          <CheckRow
                            key={c.key}
                            label={c.label}
                            ok={ok}
                            detail={
                              c.isArray && val?.length > 0 ? `${val.length} found` :
                              c.isNum && val > 0 ? `${val} detected` : null
                            }
                          />
                        );
                      })}
                      <CheckRow
                        label="No automatic redirects"
                        ok={(headless.details?.auto_redirects?.length || 0) <= 1}
                        detail={`${headless.details?.auto_redirects?.length || 0} detected`}
                      />
                    </div>
                  </div>

                  {/* Final URL if different */}
                  {headless.details?.final_url && headless.details.final_url !== result.input_value && (
                    <div style={{ marginTop: 16 }}>
                      <div className="tab-section-label">Final destination</div>
                      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
                        The link took you to a different address than the one you entered:
                      </p>
                      <code className="final-url-code">{headless.details.final_url}</code>
                    </div>
                  )}

                  {/* External requests */}
                  {headless.details?.external_requests?.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                      <div className="tab-section-label">
                        Background requests ({headless.details.external_requests.length})
                      </div>
                      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
                        Other websites this page contacted without you knowing:
                      </p>
                      <div className="ext-req-list">
                        {headless.details.external_requests.slice(0, 10).map((r, i) => (
                          <div key={i} className="ext-req-row">{r}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  <button className="btn btn-ghost btn-sm" style={{ marginTop: 16 }} onClick={runHeadless}>
                    Run again
                  </button>
                </div>
              )}

              {headless?.verdict === 'Error' && (
                <div className="behaviour-error">
                  {headless.signals?.[0] || 'Scan failed.'}
                </div>
              )}
            </div>
          )}

          {/* ── REDIRECTS ── */}
          {tab === 'Redirects' && (
            <div>
              <p className="tab-intro">
                Some links route through multiple intermediate sites before reaching their destination.
                This technique is commonly used to obscure the true origin or purpose of a link.
              </p>
              <RedirectChain chain={d.redirect_chain || []} />
            </div>
          )}

        </div>
      </div>

    </div>
  );
}

/* ── Shared CheckRow ── */
function CheckRow({ label, ok, detail = null }) {
  return (
    <div className="check-row">
      <span className={`check-icon ${ok ? 'pass' : 'fail'}`}>
        {ok
          ? <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          : <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        }
      </span>
      <span className="check-label">{label}</span>
      {detail && <span className="check-detail">{detail}</span>}
    </div>
  );
}

/* ── Verdict icons ── */
const CheckCircleIcon  = () => <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>;
const WarnCircleIcon   = () => <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const DangerCircleIcon = () => <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>;
