import React from 'react';
import './RedirectChain.css';

const statusColor = (code) => {
  if (code >= 200 && code < 300) return 'var(--safe)';
  if (code >= 300 && code < 400) return 'var(--medium)';
  return 'var(--high)';
};

export default function RedirectChain({ chain = [] }) {
  if (!chain.length) return <p className="empty-state">No redirect data available.</p>;

  return (
    <div className="redirect-chain">
      {chain.map((hop, i) => (
        <div key={i} className="hop-row">
          <div className="hop-left">
            <div className="hop-dot" style={{ background: statusColor(hop.status_code) }} />
            {i < chain.length - 1 && <div className="hop-line" />}
          </div>
          <div className="hop-card">
            <div className="hop-header">
              <span className="hop-status" style={{ color: statusColor(hop.status_code), background: `${statusColor(hop.status_code)}18` }}>
                {hop.status_code}
              </span>
              <span className="hop-label">
                {hop.status_code >= 300 && hop.status_code < 400 ? 'Redirect' :
                 hop.status_code >= 200 && hop.status_code < 300 ? 'Final destination' : 'Error'}
              </span>
            </div>
            <div className="hop-url">{hop.url}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
