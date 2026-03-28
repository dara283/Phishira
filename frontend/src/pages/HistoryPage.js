import React, { useEffect, useState } from 'react';
import { getHistory, downloadReport } from '../api';
import './HistoryPage.css';

export default function HistoryPage() {
  const [records, setRecords] = useState([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getHistory({ limit: 100, input_type: filter || undefined })
      .then(setRecords)
      .finally(() => setLoading(false));
  }, [filter]);

  return (
    <div className="history-page">
      <div className="page-header">
        <h1 className="page-title">Check history</h1>
        <p className="page-subtitle">Everything you've checked, and what we found</p>
      </div>

      <div className="history-filters">
        {[
          { key: '',      label: 'All' },
          { key: 'url',   label: 'Links' },
          { key: 'email', label: 'Emails' },
        ].map(t => (
          <button
            key={t.key}
            className={`type-tab${filter === t.key ? ' active' : ''}`}
            onClick={() => setFilter(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="card history-table-wrap">
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)', padding: 24 }}>
            <span className="spinner" /> Loading...
          </div>
        ) : (
          <table className="history-table">
            <thead>
              <tr>
                {['#', 'What was checked', 'Type', 'Result', 'Score', 'Date', ''].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {records.length === 0 && (
                <tr><td colSpan={7} className="empty-cell">No records found.</td></tr>
              )}
              {records.map(r => (
                <tr key={r.id}>
                  <td className="col-id">#{r.id}</td>
                  <td className="col-value">{r.input_value}</td>
                  <td className="col-type">{r.input_type === 'url' ? 'Link' : 'Email'}</td>
                  <td><span className={`badge badge-${r.risk_level}`}>{
                    r.risk_level === 'safe' ? 'Safe' :
                    r.risk_level === 'low' ? 'Mostly safe' :
                    r.risk_level === 'medium' ? 'Caution' :
                    r.risk_level === 'high' ? 'Dangerous' :
                    r.risk_level === 'critical' ? 'Very dangerous' : r.risk_level
                  }</span></td>
                  <td className="col-score">{r.risk_score}</td>
                  <td className="col-date">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="col-actions">
                    <a href={downloadReport(r.id, 'json')} target="_blank" rel="noreferrer">
                      <button className="btn btn-ghost btn-sm">JSON</button>
                    </a>
                    <a href={downloadReport(r.id, 'pdf')} target="_blank" rel="noreferrer">
                      <button className="btn btn-ghost btn-sm">PDF</button>
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
