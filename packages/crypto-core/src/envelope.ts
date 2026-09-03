/**
 * Versioned binary framing around the raw AES-GCM primitives.
 *
 * PASSWORD envelope (version 1): [1B version][16B salt][12B iv][ciphertext+tag]
 *   Self-contained — carries its own salt so the derivation is repeatable.
 *   Used for the Offline Mode vault/messaging (password known by both parties).
 *
 * KEY envelope (version 2): [1B version][12B iv][ciphertext+tag]
 *   No salt — used where the key is already a raw 32-byte secret (a CEK,
 *   or K_cap in the capability double-envelope design). See
 *   docs/ARCHITECTURE.md §5.2 for how the two envelope layers compose.
 */

import { aesGcmEncrypt, aesGcmDecrypt, deriveKeyPBKDF2, DecryptionError, IV_LENGTH, KEY_LENGTH } from './primitives.js';

const SALT_LENGTH = 16;
const VERSION_PASSWORD = 1;
const VERSION_KEY = 2;

export { DecryptionError };

export async function encryptWithPassword(plaintext: Uint8Array, password: string, iterations = 600_000): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await deriveKeyPBKDF2(password, salt, iterations);
  const { iv, ciphertext } = await aesGcmEncrypt(plaintext, key);

  const out = new Uint8Array(1 + SALT_LENGTH + IV_LENGTH + ciphertext.length);
  out[0] = VERSION_PASSWORD;
  out.set(salt, 1);
  out.set(iv, 1 + SALT_LENGTH);
  out.set(ciphertext, 1 + SALT_LENGTH + IV_LENGTH);
  return out;
}

export async function decryptWithPassword(envelope: Uint8Array, password: string, iterations = 600_000): Promise<Uint8Array> {
  if (envelope.length < 1 + SALT_LENGTH + IV_LENGTH + 16 || envelope[0] !== VERSION_PASSWORD) {
    throw new DecryptionError('Not a valid password envelope');
  }
  const salt = envelope.slice(1, 1 + SALT_LENGTH);
  const iv = envelope.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH);
  const ciphertext = envelope.slice(1 + SALT_LENGTH + IV_LENGTH);
  const key = await deriveKeyPBKDF2(password, salt, iterations);
  return aesGcmDecrypt(ciphertext, key, iv);
}

export async function encryptWithKey(plaintext: Uint8Array, rawKey: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  if (rawKey.length !== KEY_LENGTH) throw new Error(`Key envelope requires a ${KEY_LENGTH}-byte key`);
  const { iv, ciphertext } = await aesGcmEncrypt(plaintext, rawKey, aad);
  const out = new Uint8Array(1 + IV_LENGTH + ciphertext.length);
  out[0] = VERSION_KEY;
  out.set(iv, 1);
  out.set(ciphertext, 1 + IV_LENGTH);
  return out;
}

export async function decryptWithKey(envelope: Uint8Array, rawKey: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  if (envelope.length < 1 + IV_LENGTH + 16 || envelope[0] !== VERSION_KEY) {
    throw new DecryptionError('Not a valid key envelope');
  }
  const iv = envelope.slice(1, 1 + IV_LENGTH);
  const ciphertext = envelope.slice(1 + IV_LENGTH);
  return aesGcmDecrypt(ciphertext, rawKey, iv, aad);
}
