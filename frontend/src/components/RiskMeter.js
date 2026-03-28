import React from 'react';
import './RiskMeter.css';

const COLORS = {
  safe: '#34d399',
  low: '#a3e635',
  medium: '#fbbf24',
  high: '#f87171',
  critical: '#ef4444',
  unknown: '#5c5a6e'
};

export default function RiskMeter({ score, level }) {
  const color = COLORS[level] || COLORS.unknown;
  const pct = Math.min(score, 100);
  const circumference = 2 * Math.PI * 44;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="risk-meter">
      <svg width="110" height="110" viewBox="0 0 110 110">
        <circle cx="55" cy="55" r="44" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle
          cx="55" cy="55" r="44"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 55 55)"
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 8px ${color}60)` }}
        />
        <text x="55" y="50" textAnchor="middle" fill={color} fontSize="22" fontWeight="700" fontFamily="Inter, sans-serif">
          {Math.round(score)}
        </text>
        <text x="55" y="66" textAnchor="middle" fill="#5c5a6e" fontSize="10" fontFamily="Inter, sans-serif">
          / 100
        </text>
      </svg>
      <span className={`badge badge-${level}`}>{level}</span>
    </div>
  );
}
