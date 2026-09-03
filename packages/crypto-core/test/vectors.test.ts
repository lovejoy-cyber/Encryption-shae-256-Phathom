/**
 * Validates our primitives against reference vectors computed independently
 * by Python's `cryptography` library (see generate_vectors.py) — a
 * separate implementation from the Node/WebCrypto + @noble/* code under
 * test here. The first two AES-256-GCM cases (all-zero key) also happen to
 * match the well-known published GCM specification test cases 13/14
 * (McGrew & Viega), which is an independent confirmation the reference
 * generator itself is correct.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { aesGcmEncrypt, aesGcmDecrypt, deriveKeyPBKDF2 } from '../src/primitives.js';
import { hkdfSha256 } from '../src/kdf.js';
import { hexToBytes, bytesToHex } from '../src/encoding.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(__dirname, 'vectors', 'vectors.json'), 'utf8'));

describe('AES-256-GCM against independent reference vectors', () => {
  for (const [i, v] of vectors.aes256gcm.entries()) {
    it(`case ${i}: ciphertext+tag match reference`, async () => {
      const key = hexToBytes(v.key);
      const iv = hexToBytes(v.iv);
      const plaintext = hexToBytes(v.plaintext);
      const aad = v.aad ? hexToBytes(v.aad) : undefined;

      // Our aesGcmEncrypt generates a random IV internally; to test against a
      // fixed-IV reference vector we exercise the underlying subtle.encrypt
      // call directly with the vector's IV rather than through the
      // randomized wrapper.
      const cryptoKey = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
      const ctWithTag = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource | undefined }, cryptoKey, plaintext as BufferSource)
      );
      expect(bytesToHex(ctWithTag)).toBe(v.ciphertext_with_tag);

      const decrypted = await aesGcmDecrypt(ctWithTag, key, iv, aad);
      expect(bytesToHex(decrypted)).toBe(v.plaintext);
    });
  }

  it('our own aesGcmEncrypt/aesGcmDecrypt round-trips (random IV path)', async () => {
    const v = vectors.aes256gcm[2];
    const key = hexToBytes(v.key);
    const plaintext = hexToBytes(v.plaintext);
    const { iv, ciphertext } = await aesGcmEncrypt(plaintext, key);
    const decrypted = await aesGcmDecrypt(ciphertext, key, iv);
    expect(bytesToHex(decrypted)).toBe(v.plaintext);
  });
});

describe('PBKDF2-HMAC-SHA256 against independent reference vectors', () => {
  for (const [i, v] of vectors.pbkdf2_sha256.entries()) {
    it(`case ${i}: derived key matches reference`, async () => {
      const salt = hexToBytes(v.salt);
      const derived = await deriveKeyPBKDF2(v.password, salt, v.iterations);
      expect(bytesToHex(derived)).toBe(v.derived);
    });
  }
});

describe('HKDF-SHA256 against independent reference vectors', () => {
  for (const [i, v] of vectors.hkdf_sha256.entries()) {
    it(`case ${i}: OKM matches reference`, () => {
      const ikm = hexToBytes(v.ikm);
      const salt = hexToBytes(v.salt);
      const info = hexToBytes(v.info);
      const okm = hkdfSha256(ikm, salt, info, v.length);
      expect(bytesToHex(okm)).toBe(v.okm);
    });
  }
});
