import { useEffect, useState } from 'react';
import {
  createEphemeralMessage,
  openEphemeralMessage,
  TIMER_PRESETS_MINUTES,
  ExpiredMessageError,
  AlreadyOpenedError,
} from '../../lib/ephemeral';
import { DecryptionError, encryptWithPassword, decryptWithPassword } from '@phantomvault/crypto-core';
import { logEvent } from '../../lib/soc';
import { isConnected, onConnectionChange, createCapability, releaseCapability } from '../../lib/backendClient';

export default function TextVault() {
  const [mode, setMode] = useState<'compose' | 'open'>('compose');

  return (
    <div className="stack">
      <div>
        <h1>Text Vault</h1>
        <p className="section-desc">
          <strong>Offline Mode</strong> — encrypt here, paste the ciphertext into WhatsApp or any chat app; works
          with zero infrastructure, but expiry/burn-after-reading are enforced only on-device (see
          docs/THREAT_MODEL.md §6). <strong>Capability Mode</strong> — sends through your PhantomVault account
          instead; the server holds a revocable key it never uses to read your message, but <em>can</em> refuse
          to release it once expired/revoked — real server-enforced access control, at the cost of needing an
          account and connectivity.
        </p>
      </div>

      <div className="row">
        <button className={`btn ${mode === 'compose' ? 'btn-primary' : ''}`} onClick={() => setMode('compose')}>
          Compose
        </button>
        <button className={`btn ${mode === 'open' ? 'btn-primary' : ''}`} onClick={() => setMode('open')}>
          Open a message
        </button>
      </div>

      {mode === 'compose' ? <Compose /> : <Open />}
    </div>
  );
}

function ModeToggle({ mode, onChange }: { mode: 'offline' | 'capability'; onChange: (m: 'offline' | 'capability') => void }) {
  const [, forceUpdate] = useState(0);
  useEffect(() => onConnectionChange(() => forceUpdate((n) => n + 1)), []);
  const connected = isConnected();

  return (
    <div className="row">
      <button className={`btn ${mode === 'offline' ? 'btn-primary' : ''}`} onClick={() => onChange('offline')}>Offline Mode</button>
      <button
        className={`btn ${mode === 'capability' ? 'btn-primary' : ''}`}
        onClick={() => connected && onChange('capability')}
        disabled={!connected}
        title={connected ? '' : 'Connect a PhantomVault account first (see the Connect tab)'}
      >
        Capability Mode {!connected && '(connect first)'}
      </button>
    </div>
  );
}

function Compose() {
  const [subMode, setSubMode] = useState<'offline' | 'capability'>('offline');
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [minutes, setMinutes] = useState<number | null>(12);
  const [burn, setBurn] = useState(true);
  const [maxOpens, setMaxOpens] = useState<string>('1');
  const [ciphertext, setCiphertext] = useState('');
  const [shareCode, setShareCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleEncryptOffline() {
    setError('');
    if (!message.trim()) return setError('Write a message first.');
    if (!password) return setError('Set a password the recipient also knows.');
    setBusy(true);
    try {
      const payload = await createEphemeralMessage(message, password, {
        expiresAt: minutes ? Date.now() + minutes * 60_000 : null,
        burnAfterReading: burn,
      });
      setCiphertext(payload);
      setShareCode('');
      await logEvent({ type: 'message_encrypted', severity: 'info' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleSendCapability() {
    setError('');
    if (!message.trim()) return setError('Write a message first.');
    if (!password) return setError('Set a password the recipient also knows.');
    setBusy(true);
    try {
      const ciphertextInner = await encryptWithPassword(new TextEncoder().encode(message), password);
      const capability = await createCapability({
        ciphertextInner,
        expiresAt: minutes ? new Date(Date.now() + minutes * 60_000) : null,
        maxOpens: maxOpens ? Number(maxOpens) : null,
      });
      setShareCode(capability.id);
      setCiphertext('');
      await logEvent({ type: 'message_encrypted', severity: 'info', detail: 'capability mode' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Send failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleCopy(text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="card stack">
      <ModeToggle mode={subMode} onChange={setSubMode} />
      <div className="field-group">
        <label>Message</label>
        <textarea rows={4} value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Type your message…" />
      </div>
      <div className="field-group">
        <label>Password (share this with the recipient separately)</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
        <button className={`btn ${minutes === null ? 'btn-primary' : ''}`} onClick={() => setMinutes(null)}>
          No timer
        </button>
        {TIMER_PRESETS_MINUTES.map((m) => (
          <button key={m} className={`btn ${minutes === m ? 'btn-primary' : ''}`} onClick={() => setMinutes(m)}>
            {m}m
          </button>
        ))}
      </div>

      {subMode === 'offline' ? (
        <label className="row" style={{ fontSize: 13, color: 'var(--text-dim)', cursor: 'pointer' }}>
          <input type="checkbox" checked={burn} onChange={(e) => setBurn(e.target.checked)} style={{ width: 'auto' }} />
          Burn after reading (blocks a second open on the recipient's device — device-local only)
        </label>
      ) : (
        <div className="field-group">
          <label>Max opens (blank = unlimited) — enforced server-side</label>
          <input type="number" min="1" value={maxOpens} onChange={(e) => setMaxOpens(e.target.value)} />
        </div>
      )}

      <button className="btn btn-primary" onClick={subMode === 'offline' ? handleEncryptOffline : handleSendCapability} disabled={busy}>
        {busy ? 'Encrypting…' : subMode === 'offline' ? 'Encrypt message' : 'Send via Capability Mode'}
      </button>
      {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}

      {ciphertext && (
        <div className="stack">
          <div className="row-between">
            <label style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 500 }}>Ciphertext — copy this into WhatsApp</label>
            <button className="btn" onClick={() => handleCopy(ciphertext)}>{copied ? 'Copied ✓' : 'Copy'}</button>
          </div>
          <div className="mono-block">{ciphertext}</div>
        </div>
      )}
      {shareCode && (
        <div className="stack">
          <div className="row-between">
            <label style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 500 }}>Share code — send this (and the password, separately) to the recipient</label>
            <button className="btn" onClick={() => handleCopy(shareCode)}>{copied ? 'Copied ✓' : 'Copy'}</button>
          </div>
          <div className="mono-block">{shareCode}</div>
          <p style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>The recipient needs their own PhantomVault account to open this.</p>
        </div>
      )}
    </div>
  );
}

function Open() {
  const [subMode, setSubMode] = useState<'offline' | 'capability'>('offline');
  const [payload, setPayload] = useState('');
  const [shareCode, setShareCode] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleDecryptOffline() {
    setError('');
    setResult(null);
    setBusy(true);
    try {
      const plaintext = await openEphemeralMessage(payload, password);
      setResult(plaintext);
      await logEvent({ type: 'message_decrypted', severity: 'info' });
    } catch (err) {
      if (err instanceof ExpiredMessageError || err instanceof AlreadyOpenedError) {
        setError(err.message);
        await logEvent({ type: 'message_blocked', severity: 'warning', detail: err.message });
      } else if (err instanceof DecryptionError) {
        setError('Wrong password, or this is not a PhantomVault message.');
      } else {
        setError(err instanceof Error ? err.message : 'Decryption failed');
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleOpenCapability() {
    setError('');
    setResult(null);
    setBusy(true);
    try {
      const ciphertextInner = await releaseCapability(shareCode.trim());
      const plaintext = await decryptWithPassword(ciphertextInner, password);
      setResult(new TextDecoder().decode(plaintext));
      await logEvent({ type: 'message_decrypted', severity: 'info', detail: 'capability mode' });
    } catch (err) {
      if (err instanceof DecryptionError) setError('Wrong password.');
      else setError(err instanceof Error ? err.message : 'Could not open this capability.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card stack">
      <ModeToggle mode={subMode} onChange={setSubMode} />
      {subMode === 'offline' ? (
        <div className="field-group">
          <label>Pasted ciphertext</label>
          <textarea rows={4} value={payload} onChange={(e) => setPayload(e.target.value)} placeholder="PV1:…" />
        </div>
      ) : (
        <div className="field-group">
          <label>Share code</label>
          <input value={shareCode} onChange={(e) => setShareCode(e.target.value)} placeholder="capability id" />
        </div>
      )}
      <div className="field-group">
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <button
        className="btn btn-primary"
        onClick={subMode === 'offline' ? handleDecryptOffline : handleOpenCapability}
        disabled={busy || !password || (subMode === 'offline' ? !payload : !shareCode)}
      >
        {busy ? 'Decrypting…' : 'Decrypt'}
      </button>
      {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
      {result !== null && (
        <div className="stack">
          <label style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 500 }}>Message</label>
          <div className="mono-block" style={{ color: 'var(--text-h)' }}>{result}</div>
        </div>
      )}
    </div>
  );
}
