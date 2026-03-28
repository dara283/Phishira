import React from 'react';

export default function Toggle({ on, onChange, label }) {
  return (
    <label className="toggle-wrap" onClick={() => onChange(!on)}>
      <span className={`dev-toggle-label${on ? ' active' : ''}`}>{label}</span>
      <div className={`toggle-track${on ? ' on' : ''}`}>
        <div className="toggle-thumb" />
      </div>
    </label>
  );
}
