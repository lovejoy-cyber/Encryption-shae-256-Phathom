import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import {
  setupVault,
  unlockVault,
  addItem,
  listItems,
  getItemBytes,
  rotateVaultPassword,
  isVaultConfigured,
} from '../src/lib/vault';
import { DecryptionError } from '../src/lib/crypto';

function makeFile(name: string, contents: string, type = 'text/plain'): File {
  return new File([contents], name, { type });
}

beforeEach(() => {
  // fresh IndexedDB per test so vault state doesn't leak across tests
  // @ts-expect-error test-only reset of the fake IDB factory
  globalThis.indexedDB = new IDBFactory();
});

describe('vault duress/decoy behaviour', () => {
  it('is unconfigured until setupVault runs', async () => {
    expect(await isVaultConfigured()).toBe(false);
    await setupVault('real-pw', 'duress-pw');
    expect(await isVaultConfigured()).toBe(true);
  });

  it('rejects setup with identical real and duress passwords', async () => {
    await expect(setupVault('same', 'same')).rejects.toThrow();
  });

  it('unlocks the true vault with the real password', async () => {
    await setupVault('real-pw', 'duress-pw');
    const result = await unlockVault('real-pw');
    expect(result.collection).toBe('true');
  });

  it('unlocks the decoy vault with the duress password', async () => {
    await setupVault('real-pw', 'duress-pw');
    const result = await unlockVault('duress-pw');
    expect(result.collection).toBe('decoy');
  });

  it('rejects a completely wrong password', async () => {
    await setupVault('real-pw', 'duress-pw');
    await expect(unlockVault('nope')).rejects.toThrow(DecryptionError);
  });

  it('keeps true and decoy vault contents fully separate', async () => {
    await setupVault('real-pw', 'duress-pw');
    await addItem('true', 'real-pw', makeFile('real-secret.txt', 'the actual plan'));
    await addItem('decoy', 'duress-pw', makeFile('grocery-list.txt', 'milk, eggs'));

    const trueItems = await listItems('true');
    const decoyItems = await listItems('decoy');
    expect(trueItems.map((i) => i.name)).toEqual(['real-secret.txt']);
    expect(decoyItems.map((i) => i.name)).toEqual(['grocery-list.txt']);

    const { bytes } = await getItemBytes('true', 'real-pw', trueItems[0].id);
    expect(new TextDecoder().decode(bytes)).toBe('the actual plan');
  });

  it('rotates the vault password and re-encrypts existing items', async () => {
    await setupVault('real-pw', 'duress-pw');
    const meta = await addItem('true', 'real-pw', makeFile('doc.txt', 'payload'));

    await rotateVaultPassword('true', 'real-pw', 'new-real-pw');

    // old password no longer works
    await expect(unlockVault('real-pw')).rejects.toThrow();
    // new password does, and existing item is still readable under it
    const result = await unlockVault('new-real-pw');
    expect(result.collection).toBe('true');
    const { bytes } = await getItemBytes('true', 'new-real-pw', meta.id);
    expect(new TextDecoder().decode(bytes)).toBe('payload');
  });
});
