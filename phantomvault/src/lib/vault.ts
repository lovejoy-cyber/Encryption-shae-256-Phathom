/**
 * The file/media vault, with duress (decoy) password support à la VeraCrypt
 * hidden volumes. Two independent collections — "true" and "decoy" — each
 * gated by their own password. unlockVault() tries both and returns which
 * one matched; callers MUST render an identical UI regardless of which
 * collection unlocked, or the whole point of a decoy is defeated.
 *
 * Threat-model note: PBKDF2's ~100ms+ cost dominates any timing signal
 * from trying "true" before "decoy" sequentially, but this has not been
 * hardened against a sophisticated local timing side-channel attacker.
 */

import { get, set, del } from "idb-keyval";
import { encryptBytes, decryptBytes, DecryptionError } from "./crypto";
import { logEvent } from "./soc";

export type VaultCollection = "true" | "decoy";

export interface VaultItemMeta {
  id: string;
  name: string;
  type: string;
  size: number;
  createdAt: number;
}

interface StoredItem extends VaultItemMeta {
  envelope: Uint8Array;
}

const CANARY_PLAINTEXT = "PHANTOMVAULT-CANARY-v1";

const canaryKey = (c: VaultCollection) => `pv-vault:${c}:canary`;
const indexKey = (c: VaultCollection) => `pv-vault:${c}:index`;
const itemKey = (c: VaultCollection, id: string) => `pv-vault:${c}:item:${id}`;

export async function isVaultConfigured(): Promise<boolean> {
  return (await get(canaryKey("true"))) !== undefined;
}

export async function setupVault(truePassword: string, decoyPassword: string): Promise<void> {
  if (!truePassword || !decoyPassword) throw new Error("Both passwords are required");
  if (truePassword === decoyPassword) {
    throw new Error("The real password and the duress password must be different.");
  }
  const enc = new TextEncoder();
  await set(canaryKey("true"), await encryptBytes(enc.encode(CANARY_PLAINTEXT), truePassword));
  await set(canaryKey("decoy"), await encryptBytes(enc.encode(CANARY_PLAINTEXT), decoyPassword));
  await set(indexKey("true"), []);
  await set(indexKey("decoy"), []);
}

export interface UnlockResult {
  collection: VaultCollection;
}

export async function unlockVault(password: string): Promise<UnlockResult> {
  for (const collection of ["true", "decoy"] as VaultCollection[]) {
    const canaryEnvelope = await get(canaryKey(collection));
    if (!canaryEnvelope) continue;
    try {
      const plaintext = await decryptBytes(canaryEnvelope, password);
      if (new TextDecoder().decode(plaintext) === CANARY_PLAINTEXT) {
        await logEvent({
          type: collection === "decoy" ? "duress_unlock" : "vault_unlock",
          severity: collection === "decoy" ? "critical" : "info",
        });
        return { collection };
      }
    } catch {
      // wrong password for this collection — fall through and try the other
    }
  }
  await logEvent({ type: "failed_unlock", severity: "warning" });
  throw new DecryptionError("Incorrect password");
}

export async function listItems(collection: VaultCollection): Promise<VaultItemMeta[]> {
  const index: string[] = (await get(indexKey(collection))) ?? [];
  const metas: VaultItemMeta[] = [];
  for (const id of index) {
    const item = (await get(itemKey(collection, id))) as StoredItem | undefined;
    if (item) {
      const { envelope: _envelope, ...meta } = item;
      metas.push(meta);
    }
  }
  return metas.sort((a, b) => b.createdAt - a.createdAt);
}

export async function addItem(collection: VaultCollection, password: string, file: File): Promise<VaultItemMeta> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const envelope = await encryptBytes(bytes, password);
  const id = crypto.randomUUID();
  const meta: VaultItemMeta = { id, name: file.name, type: file.type, size: file.size, createdAt: Date.now() };
  await set(itemKey(collection, id), { ...meta, envelope });

  const index: string[] = (await get(indexKey(collection))) ?? [];
  index.push(id);
  await set(indexKey(collection), index);
  await logEvent({ type: "vault_item_added", severity: "info", detail: meta.name });
  return meta;
}

export async function getItemBytes(
  collection: VaultCollection,
  password: string,
  id: string
): Promise<{ meta: VaultItemMeta; bytes: Uint8Array }> {
  const stored = (await get(itemKey(collection, id))) as StoredItem | undefined;
  if (!stored) throw new Error("Item not found");
  const bytes = await decryptBytes(stored.envelope, password);
  const { envelope: _envelope, ...meta } = stored;
  await logEvent({ type: "vault_item_accessed", severity: "info", detail: meta.name });
  return { meta, bytes };
}

export async function deleteItem(collection: VaultCollection, id: string): Promise<void> {
  await del(itemKey(collection, id));
  const index: string[] = (await get(indexKey(collection))) ?? [];
  await set(indexKey(collection), index.filter((x) => x !== id));
}

/** Re-encrypts the canary and every item under a new password. Run periodically or after a suspected compromise. */
export async function rotateVaultPassword(
  collection: VaultCollection,
  oldPassword: string,
  newPassword: string
): Promise<void> {
  const canaryEnvelope = await get(canaryKey(collection));
  if (!canaryEnvelope) throw new Error("Vault not configured");
  const plaintext = await decryptBytes(canaryEnvelope, oldPassword);
  if (new TextDecoder().decode(plaintext) !== CANARY_PLAINTEXT) throw new DecryptionError();

  await set(canaryKey(collection), await encryptBytes(plaintext, newPassword));

  const index: string[] = (await get(indexKey(collection))) ?? [];
  for (const id of index) {
    const stored = (await get(itemKey(collection, id))) as StoredItem | undefined;
    if (!stored) continue;
    const itemPlain = await decryptBytes(stored.envelope, oldPassword);
    const newEnvelope = await encryptBytes(itemPlain, newPassword);
    await set(itemKey(collection, id), { ...stored, envelope: newEnvelope });
  }
  await logEvent({ type: "key_rotated", severity: "info", detail: collection });
}
