import { useEffect, useState } from 'react';
import './App.css';
import VaultUnlock, { type VaultSession } from './features/VaultUnlock/VaultUnlock';
import TextVault from './features/TextVault/TextVault';
import FileLocker from './features/FileLocker/FileLocker';
import Vault from './features/Vault/Vault';
import B2BPortal from './features/B2BPortal/B2BPortal';
import SOCDashboard from './features/SOCDashboard/SOCDashboard';
import Settings from './features/Settings/Settings';
import Connect from './features/Connect/Connect';
import { pruneLedger } from './lib/ephemeral';

type View = 'text' | 'files' | 'vault' | 'b2b' | 'soc' | 'connect' | 'settings';

const NAV: { id: View; label: string }[] = [
  { id: 'text', label: 'Text Vault' },
  { id: 'files', label: 'File Locker' },
  { id: 'vault', label: 'My Vault' },
  { id: 'b2b', label: 'B2B Portal' },
  { id: 'soc', label: 'SOC Monitor' },
  { id: 'connect', label: 'Connect' },
  { id: 'settings', label: 'Settings' },
];

export default function App() {
  const [session, setSession] = useState<VaultSession | null>(null);
  const [view, setView] = useState<View>('text');

  useEffect(() => {
    pruneLedger();
  }, []);

  if (!session) {
    return <VaultUnlock onUnlock={setSession} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">PV</div>
          <div>
            <div className="brand-name">PhantomVault</div>
            <div className="brand-sub">local-first privacy</div>
          </div>
        </div>

        {NAV.map((n) => (
          <button key={n.id} className={`nav-item ${view === n.id ? 'active' : ''}`} onClick={() => setView(n.id)}>
            <span className="dot" />
            {n.label}
          </button>
        ))}

        <div className="sidebar-footer">
          <div className={`vault-mode-pill ${session.collection}`}>
            {session.collection === 'decoy' ? '⚠ Decoy vault active' : '● Real vault unlocked'}
          </div>
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <span style={{ fontSize: 13, color: 'var(--text-dim)', fontWeight: 500 }}>{NAV.find((n) => n.id === view)?.label}</span>
          <button className="btn" onClick={() => setSession(null)}>Lock</button>
        </div>
        <div className="content">
          {view === 'text' && <TextVault />}
          {view === 'files' && <FileLocker />}
          {view === 'vault' && <Vault collection={session.collection} password={session.password} />}
          {view === 'b2b' && <B2BPortal />}
          {view === 'soc' && <SOCDashboard />}
          {view === 'connect' && <Connect />}
          {view === 'settings' && (
            <Settings
              collection={session.collection}
              onPasswordChanged={(newPassword) => setSession({ ...session, password: newPassword })}
              onLock={() => setSession(null)}
            />
          )}
        </div>
      </div>
    </div>
  );
}
