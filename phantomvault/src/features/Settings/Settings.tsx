import { useState } from 'react';
import { rotateVaultPassword, type VaultCollection } from '../../lib/vault';

const VT_KEY_STORAGE = 'pv-virustotal-key';

export default function Settings({
  collection,
  onPasswordChanged,
  onLock,
}: {
  collection: VaultCollection;
  onPasswordChanged: (newPassword: string) => void;
  onLock: () => void;
}) {
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [newPw2, setNewPw2] = useState('');
  const [rotateError, setRotateError] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateDone, setRotateDone] = useState(false);

  const [vtKey, setVtKey] = useState(() => localStorage.getItem(VT_KEY_STORAGE) ?? '');
  const [vtSaved, setVtSaved] = useState(false);

  async function handleRotate(e: React.FormEvent) {
    e.preventDefault();
    setRotateError('');
    setRotateDone(false);
    if (newPw.length < 8) return setRotateError('New password must be at least 8 characters.');
    if (newPw !== newPw2) return setRotateError("New passwords don't match.");
    setRotateBusy(true);
    try {
      await rotateVaultPassword(collection, oldPw, newPw);
      setRotateDone(true);
      setOldPw('');
      setNewPw('');
      setNewPw2('');
      onPasswordChanged(newPw);
    } catch {
      setRotateError('Current password is incorrect.');
    } finally {
      setRotateBusy(false);
    }
  }

  function saveVtKey() {
    if (vtKey) localStorage.setItem(VT_KEY_STORAGE, vtKey);
    else localStorage.removeItem(VT_KEY_STORAGE);
    setVtSaved(true);
    setTimeout(() => setVtSaved(false), 1500);
  }

  return (
    <div className="stack">
      <div>
        <h1>Settings</h1>
        <p className="section-desc">Key management, integrations, and session controls.</p>
      </div>

      <div className="card stack">
        <h2>Rotate {collection === 'decoy' ? 'decoy' : 'vault'} password</h2>
        <p className="section-desc">Re-encrypts your canary and every stored item under a new password.</p>
        <form onSubmit={handleRotate} className="stack">
          <div className="field-group">
            <label>Current password</label>
            <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
          </div>
          <div className="field-group">
            <label>New password</label>
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          </div>
          <div className="field-group">
            <label>Confirm new password</label>
            <input type="password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} />
          </div>
          {rotateError && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{rotateError}</p>}
          {rotateDone && <p style={{ color: 'var(--accent)', fontSize: 13 }}>Password rotated successfully.</p>}
          <button type="submit" className="btn btn-primary" disabled={rotateBusy}>
            {rotateBusy ? 'Rotating…' : 'Rotate password'}
          </button>
        </form>
      </div>

      <div className="card stack">
        <h2>VirusTotal integration (optional)</h2>
        <p className="section-desc">
          If set, the file scanner can look up a file's SHA-256 hash on VirusTotal for reputation data.
          Only the hash is ever sent — never file contents. Your key is stored locally in this browser only.
        </p>
        <div className="row">
          <input type="password" placeholder="VirusTotal API key" value={vtKey} onChange={(e) => setVtKey(e.target.value)} style={{ flex: 1 }} />
          <button className="btn" onClick={saveVtKey}>{vtSaved ? 'Saved ✓' : 'Save'}</button>
        </div>
      </div>

      <div className="card">
        <h2>Session</h2>
        <p className="section-desc" style={{ marginBottom: 12 }}>Lock the app and return to the password screen.</p>
        <button className="btn btn-danger" onClick={onLock}>Lock vault</button>
      </div>
    </div>
  );
}
