import { useEffect, useState } from 'react';
import * as backend from '../../lib/backendClient';

export default function Connect() {
  const [connected, setConnected] = useState(backend.isConnected());
  const [email, setEmail] = useState('');
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [totp, setTotp] = useState<{ pendingToken: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');

  useEffect(() => backend.onConnectionChange(() => setConnected(backend.isConnected())), []);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await backend.register(email);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const result = await backend.login(email || undefined);
      if (result.totpRequired && result.pendingToken) {
        setTotp({ pendingToken: result.pendingToken });
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleTotp(e: React.FormEvent) {
    e.preventDefault();
    if (!totp) return;
    setError('');
    setBusy(true);
    try {
      await backend.completeTotpLogin(email, totp.pendingToken, totpCode);
      setTotp(null);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  if (connected) {
    return (
      <div className="stack">
        <div>
          <h1>Capability Mode</h1>
          <p className="section-desc">Connected to the PhantomVault backend. This unlocks server-enforced expiry and revocation in Text Vault and File Locker — see the "Capability Mode" toggle in each.</p>
        </div>
        <div className="card">
          <div className="row-between">
            <div>
              <div className="name">{backend.getCurrentEmail() ?? 'Connected'}</div>
              <div className="meta">Signed in with a passkey</div>
            </div>
            <button className="btn btn-danger" onClick={() => backend.logout()}>Disconnect</button>
          </div>
        </div>
      </div>
    );
  }

  if (totp) {
    return (
      <div className="unlock-screen">
        <div className="card unlock-card">
          <h1>Enter your MFA code</h1>
          <form onSubmit={handleTotp} className="stack">
            <div className="field-group">
              <label>6-digit code</label>
              <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} maxLength={6} autoFocus />
            </div>
            {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
            <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Verifying…' : 'Verify'}</button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      <div>
        <h1>Connect to PhantomVault Backend</h1>
        <p className="section-desc">
          Optional. Everything else in this app works fully offline with no account. Connecting adds
          <strong> Capability Mode</strong>: a server-mediated messaging/sharing path where access can be
          revoked or set to expire server-side — a real property Offline Mode can't offer, since there's no
          server in that path at all. See docs/THREAT_MODEL.md for exactly what this does and doesn't guarantee.
        </p>
      </div>
      <div className="card">
        <div className="row" style={{ marginBottom: 16 }}>
          <button className={`btn ${mode === 'login' ? 'btn-primary' : ''}`} onClick={() => setMode('login')}>Sign in</button>
          <button className={`btn ${mode === 'register' ? 'btn-primary' : ''}`} onClick={() => setMode('register')}>Create account</button>
        </div>
        <form onSubmit={mode === 'login' ? handleLogin : handleRegister} className="stack">
          <div className="field-group">
            <label>Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required={mode === 'register'} placeholder={mode === 'login' ? 'optional if using autofill' : ''} />
          </div>
          {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Waiting for passkey…' : mode === 'login' ? 'Sign in with passkey' : 'Create account with passkey'}
          </button>
        </form>
      </div>
    </div>
  );
}

function describeError(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === 'NotAllowedError') return 'Passkey prompt was cancelled or timed out.';
    return err.message;
  }
  return 'Something went wrong.';
}
