import { describe, it, expect } from 'vitest';
import { encryptWithKey, decryptWithKey } from '../src/envelope.js';
import { generateKey, DecryptionError } from '../src/primitives.js';
import { sealedBoxEncrypt, sealedBoxDecrypt, generateX25519KeyPair } from '../src/publicKey.js';

function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

describe('fuzz: key envelope survives arbitrary-length random plaintexts', () => {
  it('round-trips across random lengths (20 iterations)', async () => {
    const key = await generateKey();
    for (let i = 0; i < 20; i++) {
      const plaintext = randomBytes(Math.floor(Math.random() * 8192));
      const envelope = await encryptWithKey(plaintext, key);
      const decrypted = await decryptWithKey(envelope, key);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    }
  });

  it('single-bit flips anywhere in the envelope always fail authentication (15 iterations)', async () => {
    const key = await generateKey();
    for (let i = 0; i < 15; i++) {
      const plaintext = randomBytes(1 + Math.floor(Math.random() * 512));
      const envelope = await encryptWithKey(plaintext, key);
      const tampered = new Uint8Array(envelope);
      const idx = Math.floor(Math.random() * tampered.length);
      tampered[idx] ^= 1 << Math.floor(Math.random() * 8);
      await expect(decryptWithKey(tampered, key)).rejects.toThrow(DecryptionError);
    }
  });
});

describe('fuzz: sealed box survives arbitrary-length random plaintexts', () => {
  it('round-trips across random lengths (10 iterations)', async () => {
    const recipient = generateX25519KeyPair();
    for (let i = 0; i < 10; i++) {
      const plaintext = randomBytes(Math.floor(Math.random() * 4096));
      const sealed = await sealedBoxEncrypt(plaintext, recipient.publicKey);
      const decrypted = await sealedBoxDecrypt(sealed, recipient.secretKey);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    }
  });
});
