/**
 * At-rest encryption for server-side secrets that must never be stored in
 * cleartext: TOTP seeds and K_cap values (docs/ARCHITECTURE.md §5.4/§5.2).
 *
 * The master key is provided via environment/secret store in this
 * reference deployment. In a real production system this function's job
 * (encrypt/decrypt under a master key) is exactly what a KMS/HSM does —
 * swapping the implementation to call out to one is the intended upgrade
 * path and requires no change to callers.
 */
import { encryptWithKey, decryptWithKey, b64ToBytes, bytesToB64 } from '@phantomvault/crypto-core';
import { env } from './env.js';

const masterKey = b64ToBytes(env.MASTER_KEY_B64);

export async function encryptAtRest(plaintext: Uint8Array, aad?: Uint8Array): Promise<string> {
  const envelope = await encryptWithKey(plaintext, masterKey, aad);
  return bytesToB64(envelope);
}

export async function decryptAtRest(ciphertextB64: string, aad?: Uint8Array): Promise<Uint8Array> {
  const envelope = b64ToBytes(ciphertextB64);
  return decryptWithKey(envelope, masterKey, aad);
}
