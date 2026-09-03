/**
 * Thin wrappers over the platform's native WebCrypto (SubtleCrypto) engine —
 * identical API in browsers and Node 20+. We deliberately do NOT reimplement
 * AES-GCM, PBKDF2, or SHA-256 in pure JS: the native implementations are
 * backed by audited, typically FIPS-validated native code (BoringSSL/OpenSSL
 * under the hood), and using one implementation on both client and server
 * means there is exactly one place these primitives can go wrong, not two.
 */

export const IV_LENGTH = 12;
export const KEY_LENGTH = 32;
export const GCM_TAG_LENGTH = 16;

export async function generateKey(): Promise<Uint8Array> {
  return crypto.getRandomValues(new Uint8Array(KEY_LENGTH));
}

async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length !== KEY_LENGTH) {
    throw new Error(`AES-256 key must be ${KEY_LENGTH} bytes, got ${rawKey.length}`);
  }
  return crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export class DecryptionError extends Error {
  constructor(message = 'Decryption failed: wrong key or corrupted/tampered ciphertext') {
    super(message);
    this.name = 'DecryptionError';
  }
}

export interface AesGcmResult {
  iv: Uint8Array;
  ciphertext: Uint8Array; // includes the 16-byte GCM authentication tag
}

/**
 * Node's WebCrypto tolerates `additionalData: undefined` in the AES-GCM
 * params object; Chrome's does not (throws "AeadParams: additionalData:
 * Not a BufferSource"). Building the params object conditionally — instead
 * of always including the key with a possibly-undefined value — keeps this
 * working identically in both, which matters since this exact function
 * runs in both the browser client and the Node backend.
 */
function gcmParams(iv: Uint8Array, aad?: Uint8Array): AesGcmParams {
  return aad ? { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource } : { name: 'AES-GCM', iv: iv as BufferSource };
}

export async function aesGcmEncrypt(plaintext: Uint8Array, rawKey: Uint8Array, aad?: Uint8Array): Promise<AesGcmResult> {
  const key = await importAesKey(rawKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(gcmParams(iv, aad), key, plaintext as BufferSource));
  return { iv, ciphertext };
}

export async function aesGcmDecrypt(ciphertext: Uint8Array, rawKey: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await importAesKey(rawKey);
  try {
    const plaintext = await crypto.subtle.decrypt(gcmParams(iv, aad), key, ciphertext as BufferSource);
    return new Uint8Array(plaintext);
  } catch {
    throw new DecryptionError();
  }
}

/** PBKDF2-HMAC-SHA256. 600k iterations follows OWASP's 2023 minimum for password-derived AES-256 keys. */
export async function deriveKeyPBKDF2(password: string, salt: Uint8Array, iterations = 600_000): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password) as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    baseKey,
    KEY_LENGTH * 8
  );
  return new Uint8Array(bits);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await sha256(data);
  return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time byte comparison — use for comparing MACs/hashes, never `===`. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
