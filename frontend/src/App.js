import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useLocation, useNavigate } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import ScanPage from './pages/ScanPage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import DevConsolePage from './pages/DevConsolePage';
import Toggle from './components/Toggle';
import './styles/App.css';

const ScanIcon     = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>;
const DashIcon     = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>;
const HistIcon     = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>;
const DevIcon      = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>;

const ShieldLogo = () => (
  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--purple-light)' }}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(124,58,237,0.18)" stroke="var(--purple-light)" />
    <polyline points="9 12 11 14 15 10" strokeWidth="2" />
  </svg>
);

function AppNav({ devMode, setDevMode }) {
  const navigate = useNavigate();
  return (
    <nav className="topnav">
      <div className="topnav-logo" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>
        <span className="logo-name">Phishara</span>
      </div>

      <div className="topnav-links">
        <NavLink to="/scan" className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
          <ScanIcon /><span>Scan</span>
        </NavLink>
        <NavLink to="/dashboard" className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
          <DashIcon /><span>Dashboard</span>
        </NavLink>
        <NavLink to="/history" className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
          <HistIcon /><span>History</span>
        </NavLink>
        {devMode && (
          <NavLink to="/dev" className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
            <DevIcon /><span>Dev Console</span>
          </NavLink>
        )}
      </div>

      <div className="topnav-right">
        <Toggle on={devMode} onChange={setDevMode} label="Developer" />
        <button className="btn btn-primary btn-sm" onClick={() => alert('To be available soon')}>
          Download Extension
        </button>
      </div>
    </nav>
  );
}

function AppShell() {
  const [devMode, setDevMode] = useState(false);
  const location = useLocation();
  const isLanding = location.pathname === '/';

  if (isLanding) return <LandingPage />;

  return (
    <div className="app-shell">
      <AppNav devMode={devMode} setDevMode={setDevMode} />
      <main className="main-content">
        <Routes>
          <Route path="/scan"      element={<ScanPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/history"   element={<HistoryPage />} />
          <Route path="/dev"       element={devMode ? <DevConsolePage /> : <ScanPage />} />
          <Route path="*"          element={<ScanPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
