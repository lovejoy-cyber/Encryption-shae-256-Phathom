import { useEffect, useRef, useState } from 'react';
import {
  createShare,
  listShares,
  registerBiometric,
  accessShare,
  isBiometricAvailable,
  type ShareMeta,
} from '../../lib/b2bPortal';
import { getEvents, type SecurityEvent } from '../../lib/soc';

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export default function B2BPortal() {
  const [shares, setShares] = useState<ShareMeta[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [password, setPassword] = useState('');
  const [requireBio, setRequireBio] = useState(false);
  const [logTick, setLogTick] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const bioSupported = isBiometricAvailable();

  async function refresh() {
    setShares(await listShares());
    setLogTick((t) => t + 1);
  }
  useEffect(() => {
    refresh();
  }, []);

  async function handleCreate(file: File) {
    setError('');
    if (!password) return setError('Set a client password first.');
    setBusy(true);
    try {
      const meta = await createShare(file, password, requireBio && bioSupported);
      if (requireBio && bioSupported) {
        try {
          await registerBiometric(meta.id);
        } catch (err) {
          setError(`Share created, but biometric registration failed: ${err instanceof Error ? err.message : 'cancelled'}`);
        }
      }
      setPassword('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create share');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div>
        <h1>B2B Client Portal</h1>
        <p className="section-desc">
          Share a sensitive document with a client. They need the password — and, optionally, their own
          device biometric — to decrypt it. Every access is timestamped in the SOC log below.
        </p>
      </div>

      <div className="card stack">
        <h2>New share</h2>
        <div className="field-group">
          <label>Client password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <label className="row" style={{ fontSize: 13, color: bioSupported ? 'var(--text-dim)' : 'var(--text-dim)', opacity: bioSupported ? 1 : 0.5 }}>
          <input
            type="checkbox"
            checked={requireBio}
            onChange={(e) => setRequireBio(e.target.checked)}
            disabled={!bioSupported}
            style={{ width: 'auto' }}
          />
          Also require this device's biometric (WebAuthn) {bioSupported ? '' : '— not supported in this browser'}
        </label>
        <input ref={inputRef} type="file" style={{ display: 'none' }} onChange={(e) => e.target.files?.[0] && handleCreate(e.target.files[0])} />
        <button className="btn btn-primary" onClick={() => inputRef.current?.click()} disabled={busy}>
          {busy ? 'Encrypting…' : '+ Upload & share document'}
        </button>
        {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
      </div>

      <div>
        <h2 style={{ marginBottom: 10 }}>Active shares</h2>
        {shares.length === 0 ? (
          <div className="empty-state">No shares yet.</div>
        ) : (
          shares.map((s) => <ShareRow key={s.id} share={s} onAccessed={refresh} />)
        )}
      </div>

      <AccessLogPanel refreshKey={logTick} />
    </div>
  );
}

function ShareRow({ share, onAccessed }: { share: ShareMeta; onAccessed: () => void }) {
  const [opening, setOpening] = useState(false);
  const [pw, setPw] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleAccess() {
    setError('');
    setBusy(true);
    try {
      const { meta, bytes } = await accessShare(share.id, pw);
      const blob = new Blob([bytes as BlobPart], { type: meta.type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = meta.name;
      a.click();
      URL.revokeObjectURL(url);
      setOpening(false);
      setPw('');
      onAccessed();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Access denied');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
      <div className="row-between">
        <div>
          <div className="name">{share.name}</div>
          <div className="meta">
            {formatBytes(share.size)} · shared {new Date(share.createdAt).toLocaleString()}
            {share.requireBiometric && ' · 🔒 biometric required'}
          </div>
        </div>
        <button className="btn" onClick={() => setOpening((o) => !o)}>{opening ? 'Cancel' : 'Open as client'}</button>
      </div>
      {opening && (
        <div className="row">
          <input type="password" placeholder="Client password" value={pw} onChange={(e) => setPw(e.target.value)} style={{ flex: 1 }} />
          <button className="btn btn-primary" onClick={handleAccess} disabled={busy || !pw}>{busy ? 'Verifying…' : 'Decrypt & download'}</button>
        </div>
      )}
      {error && <p style={{ color: 'var(--danger)', fontSize: 12.5 }}>{error}</p>}
    </div>
  );
}

function AccessLogPanel({ refreshKey }: { refreshKey: number }) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  useEffect(() => {
    getEvents(50).then((all) => setEvents(all.filter((e) => e.type.startsWith('b2b_'))));
  }, [refreshKey]);
  if (events.length === 0) return null;
  return (
    <div className="card">
      <h2>Access log</h2>
      <div style={{ marginTop: 10 }}>
        {events.map((e) => (
          <div key={e.id} className="row-between" style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12.5 }}>
            <span>{e.type === 'b2b_file_shared' ? 'Shared' : 'Accessed'}: {e.detail}</span>
            <span style={{ color: 'var(--text-dim)' }}>{new Date(e.timestamp).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
