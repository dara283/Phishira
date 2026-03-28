import React from 'react';
import { useNavigate } from 'react-router-dom';
import './LandingPage.css';

/* ── Icons ── */
const ShieldLogoLanding = () => (
  <svg width="30" height="30" viewBox="0 0 24 24" fill="none" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(124,58,237,0.2)" stroke="var(--purple-light)" strokeWidth="1.8" />
    <polyline points="9 12 11 14 15 10" stroke="var(--purple-light)" strokeWidth="2.2" />
  </svg>
);
const LinkIcon   = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>;
const MailIcon   = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>;
const ShieldIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const ChartIcon  = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>;
const EyeIcon    = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
const CodeIcon   = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>;

/* ── Feature data ── */
const FEATURES = [
  { icon: <LinkIcon />,   title: 'Link analysis',              desc: 'Paste any website link and we\'ll verify whether it\'s safe to visit before you click.' },
  { icon: <MailIcon />,   title: 'Email verification',         desc: 'Unsure about an email? We\'ll examine the sender, extract every link, and flag anything suspicious.' },
  { icon: <ShieldIcon />, title: 'Cross-referenced threat data', desc: 'Every scan is checked against global databases of confirmed phishing and malware sites.' },
  { icon: <ChartIcon />,  title: 'Clear risk scoring',         desc: 'A 0–100 risk score with a plain-language breakdown — no technical knowledge required.' },
  { icon: <EyeIcon />,    title: 'Transparent analysis',       desc: 'We show you exactly where a link leads, what it requests, and whether anything is being concealed.' },
  { icon: <CodeIcon />,   title: 'Built for security teams',   desc: 'Enable Developer mode for a full technical breakdown — redirect chains, form inspection, network requests, and more.' },
];

const HOW_STEPS = [
  { n: '01', title: 'Submit what you want to check', desc: 'Copy a link from an email, message, or website and paste it in. You can also paste the full text of a suspicious email.' },
  { n: '02', title: 'We analyse it immediately',     desc: 'Phishara examines the destination, ownership, age, and reputation of the link against multiple threat databases.' },
  { n: '03', title: 'Receive a clear verdict',       desc: 'A risk score from 0 to 100, with a plain-language explanation of every finding — no technical background needed.' },
];

const EXT_STEPS = [
  { n: '1', text: <><strong>Open</strong> the <code>phishara/extension/</code> folder in your file explorer</> },
  { n: '2', text: <><strong>Go to</strong> <code>chrome://extensions</code> in Chrome</> },
  { n: '3', text: <><strong>Enable</strong> Developer mode using the toggle top-right</> },
  { n: '4', text: <><strong>Click "Load unpacked"</strong> and select the extension folder</> },
];

/* ── Component ── */
export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="landing">

      {/* Nav */}
      <nav className="landing-nav">
        <div className="landing-nav-inner">
          <div className="landing-logo">
            <span style={{
              fontFamily: "'Syne', sans-serif",
              fontSize: 22,
              fontWeight: 800,
              letterSpacing: '0.5px',
              color: '#ffffff',
            }}>Phishara</span>
          </div>
          <div className="landing-nav-links">
            <button className="landing-nav-link" onClick={() => navigate('/dashboard')}>Dashboard</button>
            <button className="landing-nav-link" onClick={() => navigate('/history')}>History</button>
            <button className="btn btn-primary btn-sm" onClick={() => {
              alert(
                "Install Phishara Extension:\n\n" +
                "1. Go to chrome://extensions in Chrome\n" +
                "2. Enable Developer mode (top right)\n" +
                "3. Click 'Load unpacked'\n" +
                "4. Select the phishara/extension folder"
              );
            }}>
              Download Extension
            </button>
          </div>
        </div>
      </nav>

      {/* ── HERO (dark) ── */}
      <section className="hero">
        <div className="hero-eyebrow">
          <span className="hero-eyebrow-dot" />
          Real-time phishing detection
        </div>
        <h1 className="hero-title">
          Is that link safe?<br />
          <span className="hero-title-accent">Find out in <em style={{ fontStyle: 'italic' }}>seconds.</em></span>
        </h1>
        <p className="hero-subtitle">
          Received a suspicious email or an unfamiliar link?
          Paste it into Phishara and get an instant, plain-English verdict.
        </p>
        <div className="hero-actions">
          <button className="btn btn-primary hero-cta" onClick={() => navigate('/scan')}>Start scanning</button>
          <button className="btn btn-ghost hero-cta" onClick={() => navigate('/dashboard')}>View dashboard</button>
        </div>
      </section>

      {/* ── LIGHT SECTION: features + extension + how + footer ── */}
      <div className="light-body">

        {/* Features */}
        <section className="features-section">
          <div className="section-inner">
            <div className="section-eyebrow">What Phishara checks</div>
            <h2 className="section-title">Comprehensive protection in one place</h2>
            <p className="section-subtitle">
              Whether it's a link in a text message or an email asking you to "verify your account" —
              Phishara analyses it thoroughly and tells you what it found.
            </p>
            <div className="features-grid">
              {FEATURES.map(f => (
                <div className="feature-card" key={f.title}>
                  <div className="feature-icon">{f.icon}</div>
                  <h3 className="feature-title">{f.title}</h3>
                  <p className="feature-desc">{f.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Extension */}
        <section className="extension-section">
          <div className="section-inner extension-inner">
            <div className="extension-content">
              <div className="section-eyebrow purple">Chrome Extension</div>
              <h2 className="section-title">Browser protection, always on</h2>
              <p className="section-subtitle">
                Install the Phishara extension and every website you visit is quietly assessed in the background.
                If a threat is detected, you'll be alerted before entering any information.
              </p>
              <div className="extension-steps">
                {EXT_STEPS.map(s => (
                  <div key={s.n} className="ext-step">
                    <div className="ext-step-num">{s.n}</div>
                    <div className="ext-step-text">{s.text}</div>
                  </div>
                ))}
              </div>
              <button className="btn btn-primary" onClick={() => {
                // Guide user through loading the unpacked extension
                alert(
                  "To install the Phishara extension:\n\n" +
                  "1. Open Chrome and go to: chrome://extensions\n" +
                  "2. Turn on 'Developer mode' (top right toggle)\n" +
                  "3. Click 'Load unpacked'\n" +
                  "4. Select the 'phishara/extension' folder\n\n" +
                  "The Phishara shield icon will appear in your toolbar."
                );
              }}>
                Install extension
              </button>
            </div>

            {/* Popup mockup */}
            <div className="ext-mockup-wrap">
              <div className="ext-popup-mock">
                <div className="ext-popup-header">
                  <div className="ext-popup-logo">P</div>
                  <span className="ext-popup-name">Phishara</span>
                  <span className="badge badge-high" style={{ marginLeft: 'auto' }}>High</span>
                </div>
                <div className="ext-popup-body">
                  <div className="ext-popup-url">http://paypal-secure-login.tk/verify</div>
                  <div className="ext-popup-score">72 <span>/100</span></div>
                  <div className="ext-popup-bar"><div className="ext-popup-bar-fill" /></div>
                  <div className="ext-popup-finding">Suspicious TLD commonly used in phishing</div>
                  <div className="ext-popup-finding">Page contains a login / password form</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* How it works */}
        <section className="how-section">
          <div className="section-inner">
            <div className="section-eyebrow">How it works</div>
            <h2 className="section-title">How it works</h2>
            <div className="how-grid">
              {HOW_STEPS.map(s => (
                <div key={s.n} className="how-step">
                  <div className="how-step-num">{s.n}</div>
                  <h3 className="how-step-title">{s.title}</h3>
                  <p className="how-step-desc">{s.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cta-section">
          <div className="section-inner cta-inner">
            <h2 className="cta-title">Have something to check?</h2>
            <p className="cta-subtitle">
              No account required. Paste a link or email and receive your results in seconds.
            </p>
            <div className="cta-actions">
              <button className="btn btn-primary hero-cta" onClick={() => navigate('/scan')}>Start scanning</button>
              <button className="btn btn-ghost-dark hero-cta" onClick={() => navigate('/dashboard')}>View dashboard</button>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="landing-footer">
          <div className="section-inner landing-footer-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="footer-brand" style={{
                fontFamily: "'Syne', sans-serif",
                letterSpacing: '0.5px',
                fontSize: 16,
                fontWeight: 800,
                color: '#ffffff',
              }}>Phishara</span>
            </div>
            <span className="footer-copy">
              Built for security professionals and everyday users &copy; {new Date().getFullYear()}
            </span>
          </div>
        </footer>

      </div>{/* end .light-body */}
    </div>
  );
}
