import { describe, it, expect } from 'vitest';
import { encryptBytes, decryptBytes } from '../src/lib/crypto';
import { packFile, unpackFile } from '../src/lib/filePayload';

function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

function randomString(len: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?/~`';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

describe('fuzz: crypto round-trips survive arbitrary-ish inputs', () => {
  it('encrypt/decrypt round-trips across random lengths and passwords (10 iterations)', async () => {
    // PBKDF2 runs at 600k iterations by design (src/lib/crypto.ts) — kept low
    // here since each round-trip pays that cost twice (encrypt + decrypt).
    for (let i = 0; i < 10; i++) {
      const plaintext = randomBytes(Math.floor(Math.random() * 4096));
      const password = randomString(1 + Math.floor(Math.random() * 40));
      const envelope = await encryptBytes(plaintext, password);
      const decrypted = await decryptBytes(envelope, password);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    }
  });

  it('never decrypts with a mutated envelope (auth tag must reject tampering)', async () => {
    for (let i = 0; i < 8; i++) {
      const plaintext = randomBytes(1 + Math.floor(Math.random() * 512));
      const password = randomString(10);
      const envelope = await encryptBytes(plaintext, password);
      const tampered = new Uint8Array(envelope);
      const flipIndex = Math.floor(Math.random() * tampered.length);
      tampered[flipIndex] ^= 1 << Math.floor(Math.random() * 8);
      await expect(decryptBytes(tampered, password)).rejects.toThrow();
    }
  });
});

describe('fuzz: file payload packing survives arbitrary names/types/bytes', () => {
  it('packFile/unpackFile round-trips (30 iterations)', () => {
    for (let i = 0; i < 30; i++) {
      const name = randomString(Math.floor(Math.random() * 60));
      const type = randomString(Math.floor(Math.random() * 30));
      const bytes = randomBytes(Math.floor(Math.random() * 2048));
      const packed = packFile(name, type, bytes);
      const unpacked = unpackFile(packed);
      expect(unpacked.name).toBe(name);
      expect(unpacked.type).toBe(type);
      expect(Array.from(unpacked.bytes)).toEqual(Array.from(bytes));
    }
  });
});
