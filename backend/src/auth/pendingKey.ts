/**
 * Symmetric signing key for short-lived, single-purpose "pending TOTP"
 * tokens (routes/auth.ts) — deliberately separate from the ES256 session
 * keys in sessions.ts so a leaked pending-token secret can't be used to
 * forge full access tokens, and vice versa.
 */
import { hkdfSha256, b64ToBytes } from '@phantomvault/crypto-core';
import { importJWK, type CryptoKey as JoseCryptoKey } from 'jose';
import { env } from '../lib/env.js';

let keyPromise: Promise<JoseCryptoKey> | null = null;

export async function getPendingSigningKey(): Promise<JoseCryptoKey> {
  if (!keyPromise) {
    keyPromise = (async () => {
      const masterKey = b64ToBytes(env.MASTER_KEY_B64);
      const derived = hkdfSha256(masterKey, new Uint8Array(0), new TextEncoder().encode('phantomvault-pending-totp-key'), 32);
      const jwk = { kty: 'oct', k: Buffer.from(derived).toString('base64url') };
      return (await importJWK(jwk, 'HS256')) as JoseCryptoKey;
    })();
  }
  return keyPromise;
}
