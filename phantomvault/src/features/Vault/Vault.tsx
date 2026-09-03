import { useEffect, useRef, useState } from 'react';
import { addItem, deleteItem, getItemBytes, listItems, type VaultCollection, type VaultItemMeta } from '../../lib/vault';
import { scanFile } from '../../lib/fileScanner';

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export default function Vault({ collection, password }: { collection: VaultCollection; password: string }) {
  const [items, setItems] = useState<VaultItemMeta[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  async function refresh() {
    setItems(await listItems(collection));
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collection]);

  async function handleAdd(file: File) {
    setError('');
    setBusy(true);
    try {
      const report = await scanFile(file);
      if (report.executableWarning && !confirm(`${file.name} looks like an executable (${report.detectedType}). Add it to the vault anyway?`)) {
        return;
      }
      await addItem(collection, password, file);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add file');
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(item: VaultItemMeta) {
    setError('');
    try {
      const { bytes } = await getItemBytes(collection, password, item.id);
      const blob = new Blob([bytes as BlobPart], { type: item.type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = item.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError('Could not decrypt this item.');
    }
  }

  async function handleDelete(item: VaultItemMeta) {
    if (!confirm(`Permanently delete "${item.name}" from the vault?`)) return;
    await deleteItem(collection, item.id);
    await refresh();
  }

  return (
    <div className="stack">
      <div>
        <h1>{collection === 'decoy' ? 'Decoy Vault' : 'Your Vault'}</h1>
        <p className="section-desc">
          {collection === 'decoy'
            ? 'You unlocked with the duress password. Anything added here is only in the decoy — your real vault is untouched.'
            : 'Files here are encrypted at rest with AES-256-GCM, individually, using your vault password.'}
        </p>
      </div>

      <div className="card">
        <input
          ref={inputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={(e) => e.target.files?.[0] && handleAdd(e.target.files[0])}
        />
        <button className="btn btn-primary" onClick={() => inputRef.current?.click()} disabled={busy}>
          {busy ? 'Encrypting…' : '+ Add file to vault'}
        </button>
        {error && <p style={{ color: 'var(--danger)', fontSize: 13, marginTop: 10 }}>{error}</p>}
      </div>

      {items.length === 0 ? (
        <div className="empty-state">No files yet.</div>
      ) : (
        <div>
          {items.map((item) => (
            <div className="item-row" key={item.id}>
              <div>
                <div className="name">{item.name}</div>
                <div className="meta">{formatBytes(item.size)} · added {new Date(item.createdAt).toLocaleString()}</div>
              </div>
              <div className="row">
                <button className="btn" onClick={() => handleDownload(item)}>Download</button>
                <button className="btn btn-danger" onClick={() => handleDelete(item)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
