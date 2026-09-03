import { useEffect, useRef, useState, type DragEvent } from 'react';
import { encryptWithPassword, decryptWithPassword, DecryptionError } from '@phantomvault/crypto-core';
import { packFile, unpackFile } from '../../lib/filePayload';
import { scanFile, type ScanReport } from '../../lib/fileScanner';
import { stripImageMetadata, detectLikelyMetadataFields } from '../../lib/metadata';
import { logEvent } from '../../lib/soc';
import { isConnected, onConnectionChange } from '../../lib/backendClient';
import {
  ALL_ADAPTERS,
  setCarrierImage,
  setRelayPolicy,
  receiveFromManualFile,
  receiveFromConcealedImage,
  receiveFromRelay,
  type TransportAdapter,
  type TransportSendResult,
} from '../../lib/transport';

function DropZone({
  label,
  hint,
  accept,
  onFile,
  fileName,
}: {
  label: string;
  hint: string;
  accept?: string;
  onFile: (f: File) => void;
  fileName?: string;
}) {
  const [active, setActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  }

  return (
    <div
      className={`dropzone ${active ? 'active' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setActive(true);
      }}
      onDragLeave={() => setActive(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
      />
      <div style={{ fontWeight: 600, color: fileName ? 'var(--accent)' : 'var(--text-h)', fontSize: 13.5 }}>
        {fileName ?? label}
      </div>
      <div style={{ fontSize: 12, marginTop: 4 }}>{fileName ? 'Click to change' : hint}</div>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export default function FileLocker() {
  const [tab, setTab] = useState<'send' | 'receive' | 'clean'>('send');
  return (
    <div className="stack">
      <div>
        <h1>Encrypted File & Media Sharing</h1>
        <p className="section-desc">
          Encryption always happens here, before anything reaches a transport. How the encrypted bytes actually
          get to the recipient is a separate, explicit choice — see the transport options below.
        </p>
      </div>
      <div className="row">
        <button className={`btn ${tab === 'send' ? 'btn-primary' : ''}`} onClick={() => setTab('send')}>Send</button>
        <button className={`btn ${tab === 'receive' ? 'btn-primary' : ''}`} onClick={() => setTab('receive')}>Receive</button>
        <button className={`btn ${tab === 'clean' ? 'btn-primary' : ''}`} onClick={() => setTab('clean')}>Clean metadata</button>
      </div>
      {tab === 'send' && <Send />}
      {tab === 'receive' && <Receive />}
      {tab === 'clean' && <Clean />}
    </div>
  );
}

function AdapterPicker({ selected, onSelect }: { selected: TransportAdapter; onSelect: (a: TransportAdapter) => void }) {
  const [, forceUpdate] = useState(0);
  useEffect(() => onConnectionChange(() => forceUpdate((n) => n + 1)), []);

  return (
    <div className="stack">
      <label style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 500 }}>Transport</label>
      {ALL_ADAPTERS.map((a) => {
        const available = a.isAvailable();
        return (
          <label
            key={a.id}
            className="item-row"
            style={{
              cursor: available ? 'pointer' : 'not-allowed',
              opacity: available ? 1 : 0.5,
              borderColor: selected.id === a.id ? 'var(--accent-border)' : undefined,
              alignItems: 'flex-start',
            }}
          >
            <div className="row" style={{ alignItems: 'flex-start' }}>
              <input type="radio" checked={selected.id === a.id} disabled={!available} onChange={() => onSelect(a)} style={{ width: 'auto', marginTop: 3 }} />
              <div>
                <div className="name">
                  {a.name}{' '}
                  <span className={`badge ${a.reliability === 'bit-perfect' ? 'badge-ok' : 'badge-warn'}`} style={{ marginLeft: 6 }}>
                    {a.reliability === 'bit-perfect' ? 'bit-perfect' : 'fragile'}
                  </span>
                </div>
                <div className="meta">{a.description}{!available && a.id === 'phantom-relay' ? ' (connect an account first — see Connect tab)' : ''}</div>
              </div>
            </div>
          </label>
        );
      })}
    </div>
  );
}

function Send() {
  const [file, setFile] = useState<File | null>(null);
  const [scan, setScan] = useState<ScanReport | null>(null);
  const [password, setPassword] = useState('');
  const [adapter, setAdapter] = useState<TransportAdapter>(ALL_ADAPTERS[0]);
  const [carrier, setCarrier] = useState<File | null>(null);
  const [stripMeta, setStripMeta] = useState(true);
  const [maxOpens, setMaxOpens] = useState<string>('');
  const [expiryMinutes, setExpiryMinutes] = useState<string>('');
  const [result, setResult] = useState<(TransportSendResult & { resultUrl?: string }) | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleFile(f: File) {
    setFile(f);
    setResult(null);
    setScan(await scanFile(f));
  }

  async function handleSend() {
    setError('');
    setResult(null);
    if (!file) return setError('Choose a file to send.');
    if (!password) return setError('Set a password.');
    if (adapter.id === 'concealed-image' && !carrier) return setError('Choose a carrier image for steganography.');
    setBusy(true);
    try {
      let bytes = new Uint8Array(await file.arrayBuffer());
      let type = file.type;
      if (adapter.id === 'concealed-image' && stripMeta && file.type.startsWith('image/')) {
        const outType = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
        const stripped = await stripImageMetadata(file, outType);
        bytes = new Uint8Array(await stripped.blob.arrayBuffer());
        type = outType;
      }
      const packed = packFile(file.name, type, bytes);
      const ciphertext = await encryptWithPassword(packed, password);

      if (adapter.id === 'concealed-image') setCarrierImage(carrier);
      if (adapter.id === 'phantom-relay') {
        setRelayPolicy({
          maxOpens: maxOpens ? Number(maxOpens) : null,
          expiresAt: expiryMinutes ? new Date(Date.now() + Number(expiryMinutes) * 60_000) : null,
        });
      }

      const sendResult = await adapter.send({ ciphertext, filename: 'encrypted-file.phantom', mimeType: 'application/octet-stream' });
      const resultUrl = sendResult.blob ? URL.createObjectURL(sendResult.blob) : undefined;
      setResult({ ...sendResult, resultUrl });
      await logEvent({ type: 'stego_locked', severity: 'info', detail: `${file.name} via ${adapter.id}` });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Send failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card stack">
      <DropZone label="File to send" hint="Any file — photo, document, anything" onFile={handleFile} fileName={file?.name} />
      {file && <p style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{formatBytes(file.size)}</p>}

      {scan && scan.warnings.length > 0 && (
        <div className="warn-banner">
          {scan.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
        </div>
      )}

      <AdapterPicker selected={adapter} onSelect={setAdapter} />

      {adapter.id === 'concealed-image' && (
        <div className="stack">
          <DropZone label="Carrier image" hint="PNG/JPEG — drop or click" accept="image/*" onFile={setCarrier} fileName={carrier?.name} />
          {file?.type.startsWith('image/') && (
            <label className="row" style={{ fontSize: 13, color: 'var(--text-dim)', cursor: 'pointer' }}>
              <input type="checkbox" checked={stripMeta} onChange={(e) => setStripMeta(e.target.checked)} style={{ width: 'auto' }} />
              Strip EXIF/metadata from the file before encrypting
            </label>
          )}
        </div>
      )}

      {adapter.id === 'phantom-relay' && (
        <div className="row">
          <div className="field-group" style={{ flex: 1 }}>
            <label>Expires after (minutes, blank = never)</label>
            <input type="number" min="1" value={expiryMinutes} onChange={(e) => setExpiryMinutes(e.target.value)} />
          </div>
          <div className="field-group" style={{ flex: 1 }}>
            <label>Max opens (blank = unlimited)</label>
            <input type="number" min="1" value={maxOpens} onChange={(e) => setMaxOpens(e.target.value)} />
          </div>
        </div>
      )}

      <div className="field-group">
        <label>Password (share this with the recipient separately)</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>

      <button className="btn btn-primary" onClick={handleSend} disabled={busy}>
        {busy ? 'Encrypting…' : `Send via ${adapter.name}`}
      </button>
      {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}

      {result && (
        <div className="stack">
          {result.warning && (
            <div className="warn-banner">⚠ {result.warning}</div>
          )}
          {result.kind === 'image' && result.resultUrl && (
            <img src={result.resultUrl} alt="Result carrier" style={{ maxWidth: '100%', borderRadius: 10, border: '1px solid var(--border)' }} />
          )}
          {result.resultUrl && (
            <a href={result.resultUrl} download={result.downloadFilename} className="btn btn-primary" style={{ textDecoration: 'none' }}>
              Download {result.downloadFilename}
            </a>
          )}
          {result.shareCode && (
            <div className="stack">
              <label style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 500 }}>Share code</label>
              <div className="mono-block">{result.shareCode}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

type ReceiveSource = 'manual-file' | 'phantom-relay' | 'concealed-image';

function Receive() {
  const [source, setSource] = useState<ReceiveSource>('manual-file');
  const [file, setFile] = useState<File | null>(null);
  const [shareCode, setShareCode] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<{ name: string; type: string; url: string; size: number } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [, forceUpdate] = useState(0);
  useEffect(() => onConnectionChange(() => forceUpdate((n) => n + 1)), []);

  async function handleReceive() {
    setError('');
    setResult(null);
    if (!password) return setError('Enter the password.');
    setBusy(true);
    try {
      let ciphertext: Uint8Array;
      if (source === 'manual-file') {
        if (!file) return setError('Choose the .phantom file.');
        ciphertext = await receiveFromManualFile(file);
      } else if (source === 'concealed-image') {
        if (!file) return setError('Choose the image.');
        ciphertext = await receiveFromConcealedImage(file);
      } else {
        if (!shareCode) return setError('Enter the share code.');
        if (!isConnected()) return setError('Connect a PhantomVault account first (see the Connect tab).');
        ciphertext = await receiveFromRelay(shareCode);
      }

      const packed = await decryptWithPassword(ciphertext, password);
      const { name, type, bytes } = unpackFile(packed);
      const blob = new Blob([bytes as BlobPart], { type });
      setResult({ name, type, url: URL.createObjectURL(blob), size: bytes.length });
      await logEvent({ type: 'stego_extracted', severity: 'info', detail: `${name} via ${source}` });
    } catch (err) {
      setError(err instanceof DecryptionError ? 'Wrong password, or no valid payload found.' : err instanceof Error ? err.message : 'Receive failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card stack">
      <div className="row">
        <button className={`btn ${source === 'manual-file' ? 'btn-primary' : ''}`} onClick={() => setSource('manual-file')}>Encrypted file</button>
        <button className={`btn ${source === 'phantom-relay' ? 'btn-primary' : ''}`} onClick={() => setSource('phantom-relay')}>Relay code</button>
        <button className={`btn ${source === 'concealed-image' ? 'btn-primary' : ''}`} onClick={() => setSource('concealed-image')}>Concealed image</button>
      </div>

      {source === 'manual-file' && <DropZone label="Encrypted (.phantom) file" hint="Drop or click" onFile={setFile} fileName={file?.name} />}
      {source === 'concealed-image' && <DropZone label="Image with hidden data" hint="Drop or click" accept="image/*" onFile={setFile} fileName={file?.name} />}
      {source === 'phantom-relay' && (
        <div className="field-group">
          <label>Share code</label>
          <input value={shareCode} onChange={(e) => setShareCode(e.target.value)} placeholder="capability id" />
          {!isConnected() && <p style={{ fontSize: 11.5, color: 'var(--warn)', marginTop: 4 }}>Not connected — see the Connect tab.</p>}
        </div>
      )}

      <div className="field-group">
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>

      <button className="btn btn-primary" onClick={handleReceive} disabled={busy}>
        {busy ? 'Opening…' : 'Decrypt & open'}
      </button>
      {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
      {result && (
        <div className="item-row">
          <div>
            <div className="name">{result.name}</div>
            <div className="meta">{formatBytes(result.size)} · {result.type || 'unknown type'}</div>
          </div>
          <a href={result.url} download={result.name} className="btn">Download</a>
        </div>
      )}
    </div>
  );
}

function Clean() {
  const [file, setFile] = useState<File | null>(null);
  const [detected, setDetected] = useState<string[]>([]);
  const [result, setResult] = useState<{ url: string; before: number; after: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  function handleFile(f: File) {
    setFile(f);
    setResult(null);
    setDetected(detectLikelyMetadataFields(f));
  }

  async function handleClean() {
    if (!file) return;
    setError('');
    setBusy(true);
    try {
      const outType = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
      const { blob, originalBytes, cleanedBytes } = await stripImageMetadata(file, outType);
      setResult({ url: URL.createObjectURL(blob), before: originalBytes, after: cleanedBytes });
      await logEvent({ type: 'metadata_stripped', severity: 'info', detail: file.name });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cleaning failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card stack">
      <p className="section-desc">
        Strips EXIF/GPS/device metadata from a photo before you post or send it — useful for OSINT-aware
        sharing where you don't want to leak where or on what device a photo was taken.
      </p>
      <DropZone label="Photo to clean" hint="Drop or click" accept="image/*" onFile={handleFile} fileName={file?.name} />
      {detected.length > 0 && (
        <div className="warn-banner">
          {detected.map((d, i) => <div key={i}>ⓘ Likely present: {d}</div>)}
        </div>
      )}
      <button className="btn btn-primary" onClick={handleClean} disabled={busy || !file}>
        {busy ? 'Cleaning…' : 'Strip metadata'}
      </button>
      {error && <p style={{ color: 'var(--danger)', fontSize: 13 }}>{error}</p>}
      {result && (
        <div className="stack">
          <img src={result.url} alt="Cleaned" style={{ maxWidth: '100%', borderRadius: 10, border: '1px solid var(--border)' }} />
          <p style={{ fontSize: 12, color: 'var(--text-dim)' }}>{formatBytes(result.before)} → {formatBytes(result.after)}</p>
          <a href={result.url} download={`cleaned-${file?.name}`} className="btn btn-primary" style={{ textDecoration: 'none' }}>Download cleaned photo</a>
        </div>
      )}
    </div>
  );
}
