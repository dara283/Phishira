import React, { useEffect, useState } from 'react';
import { getStats, getHistory } from '../api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import './DashboardPage.css';

const LEVEL_COLORS = { safe: '#34d399', low: '#a3e635', medium: '#fbbf24', high: '#f87171', critical: '#ef4444' };
const TYPE_COLORS = ['#8a5cf6', '#22d3ee', '#fbbf24'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 14px', fontSize: 12 }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
      <div style={{ color: 'var(--text)', fontWeight: 600 }}>{payload[0].value}</div>
    </div>
  );
};

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    getStats().then(setStats).catch(() => {});
    getHistory({ limit: 8 }).then(setRecent).catch(() => {});
  }, []);

  if (!stats) return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)', paddingTop: 40 }}>
      <span className="spinner" /> Loading...
    </div>
  );

  const levelData = Object.entries(stats.by_level).map(([name, value]) => ({ name, value }));
  const typeData = Object.entries(stats.by_type).map(([name, value]) => ({ name, value }));

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <h1 className="page-title">Overview</h1>
        <p className="page-subtitle">A summary of your scan activity and threat trends</p>
      </div>

      {/* KPIs */}
      <div className="kpi-row">
        <div className="kpi-card card">
          <div className="kpi-value" style={{ color: 'var(--purple-light)' }}>{stats.total}</div>
          <div className="kpi-label">Total checks</div>
        </div>
        {Object.entries(stats.by_level).map(([level, count]) => (
          <div key={level} className="kpi-card card">
            <div className="kpi-value" style={{ color: LEVEL_COLORS[level] }}>{count}</div>
            <div className="kpi-label">{
              level === 'safe' ? 'Safe' :
              level === 'low' ? 'Mostly safe' :
              level === 'medium' ? 'Caution' :
              level === 'high' ? 'Dangerous' : 'Critical'
            }</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="charts-row">
        <div className="card chart-card">
          <div className="chart-title">Results breakdown</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={levelData} barSize={28}>
              <XAxis dataKey="name" tick={{ fill: '#9896a8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#9896a8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="value" radius={[5, 5, 0, 0]}>
                {levelData.map(e => <Cell key={e.name} fill={LEVEL_COLORS[e.name] || '#5c5a6e'} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card chart-card">
          <div className="chart-title">What was checked</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={typeData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={72} innerRadius={36} paddingAngle={3}>
                {typeData.map((e, i) => <Cell key={e.name} fill={TYPE_COLORS[i % TYPE_COLORS.length]} />)}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pie-legend">
            {typeData.map((e, i) => (
              <div key={e.name} className="pie-legend-item">
                <span className="pie-dot" style={{ background: TYPE_COLORS[i] }} />
                <span>{e.name}</span>
                <span className="pie-count">{e.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent */}
      <div className="card">
        <div className="chart-title" style={{ marginBottom: 16 }}>Recent checks</div>
        {recent.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No scans yet.</p>
        ) : (
          <div className="recent-list">
            {recent.map(item => (
              <div key={item.id} className="recent-row">
                <span className="recent-id">#{item.id}</span>
                <span className="recent-value">{item.input_value}</span>
                <span className="recent-type">{item.input_type}</span>
                <span className={`badge badge-${item.risk_level}`}>{item.risk_level}</span>
                <span className="recent-date">{new Date(item.created_at).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
