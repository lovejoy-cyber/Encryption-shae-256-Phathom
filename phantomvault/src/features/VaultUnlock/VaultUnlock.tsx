import { useEffect, useState } from 'react';
import { isVaultConfigured, setupVault, unlockVault, type VaultCollection } from '../../lib/vault';

export interface VaultSession {
  collection: VaultCollection;
  password: string;
}

export default function VaultUnlock({ onUnlock }: { onUnlock: (session: VaultSession) => void }) {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // setup fields
  const [realPw, setRealPw] = useState('');
  const [realPw2, setRealPw2] = useState('');
  const [duressPw, setDuressPw] = useState('');
  const [duressPw2, setDuressPw2] = useState('');

  // unlock field
  const [password, setPassword] = useState('');

  useEffect(() => {
    isVaultConfigured().then(setConfigured);
  }, []);

  async function handleSetup(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (realPw.length < 8) return setError('Real password must be at least 8 characters.');
    if (realPw !== realPw2) return setError("Real passwords don't match.");
    if (duressPw.length < 8) return setError('Duress password must be at least 8 characters.');
    if (duressPw !== duressPw2) return setError("Duress passwords don't match.");
    if (realPw === duressPw) return setError('Real and duress passwords must be different.');

    setBusy(true);
    try {
      await setupVault(realPw, duressPw);
      onUnlock({ collection: 'true', password: realPw });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const result = await unlockVault(password);
      onUnlock({ collection: result.collection, password });
    } catch {
      setError('Incorrect password.');
    } finally {
      setBusy(false);
    }
  }

  if (configured === null) return null;

  if (!configured) {
    return (
      <div className="unlock-screen">
        <div className="card unlock-card">
          <h1>Set up PhantomVault</h1>
          <p className="section-desc">
            Choose two <em>different</em> passwords. The real one opens your actual vault. The duress
            password opens an empty decoy vault that looks completely normal — use it if you're ever
            forced to unlock the app under pressure.
          </p>
          <form onSubmit={handleSetup} className="stack">
            <div className="field-group">
              <label>Real password</label>
              <input type="password" value={realPw} onChange={(e) => setRealPw(e.target.value)} autoComplete="new-password" />
            </div>
            <div className="field-group">
              <label>Confirm real password</label>
              <input type="password" value={realPw2} onChange={(e) => setRealPw2(e.target.value)} autoComplete="new-password" />
            </div>
            <div className="field-group">
              <label>Duress (decoy) password</label>
              <input type="password" value={duressPw} onChange={(e) => setDuressPw(e.target.value)} autoComplete="new-password" />
            </div>
            <div className="field-group">
              <label>Confirm duress password</label>
              <input type="password" value={duressPw2} onChange={(e) => setDuressPw2(e.target.value)} autoComplete="new-password" />
            </div>
            {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Setting up…' : 'Create vault'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="unlock-screen">
      <div className="card unlock-card">
        <h1>PhantomVault</h1>
        <p className="section-desc">Enter your password to unlock.</p>
        <form onSubmit={handleUnlock} className="stack">
          <div className="field-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              autoComplete="current-password"
            />
          </div>
          {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
          <button type="submit" className="btn btn-primary" disabled={busy || !password}>
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </form>
      </div>
    </div>
  );
}
