import { describe, it, expect } from 'vitest';
import { encryptBytes, decryptBytes, encryptText, decryptText, DecryptionError, sha256Hex } from '../src/lib/crypto';

describe('crypto core', () => {
  it('round-trips bytes with the correct password', async () => {
    const plaintext = new TextEncoder().encode('The launch codes are hidden in the fern.');
    const envelope = await encryptBytes(plaintext, 'correct-horse-battery-staple');
    const decrypted = await decryptBytes(envelope, 'correct-horse-battery-staple');
    expect(new TextDecoder().decode(decrypted)).toBe('The launch codes are hidden in the fern.');
  });

  it('rejects the wrong password', async () => {
    const envelope = await encryptBytes(new TextEncoder().encode('secret'), 'right-password');
    await expect(decryptBytes(envelope, 'wrong-password')).rejects.toThrow(DecryptionError);
  });

  it('detects tampering (GCM auth tag fails)', async () => {
    const envelope = await encryptBytes(new TextEncoder().encode('secret'), 'pw');
    const tampered = new Uint8Array(envelope);
    tampered[tampered.length - 1] ^= 0xff; // flip a bit in the ciphertext/tag
    await expect(decryptBytes(tampered, 'pw')).rejects.toThrow(DecryptionError);
  });

  it('produces different ciphertext for the same plaintext (random salt/iv)', async () => {
    const a = await encryptBytes(new TextEncoder().encode('same message'), 'pw');
    const b = await encryptBytes(new TextEncoder().encode('same message'), 'pw');
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('encryptText/decryptText round-trip through a base64 string', async () => {
    const payload = await encryptText('Meet at the usual place, 9pm.', 'shared-secret');
    expect(payload.startsWith('PV1:')).toBe(true);
    const decrypted = await decryptText(payload, 'shared-secret');
    expect(decrypted).toBe('Meet at the usual place, 9pm.');
  });

  it('rejects text payloads without the PV1: prefix', async () => {
    await expect(decryptText('not-a-real-payload', 'pw')).rejects.toThrow(DecryptionError);
  });

  it('sha256Hex is deterministic, 64 hex chars, and input-sensitive', async () => {
    const a = await sha256Hex(new TextEncoder().encode('hello'));
    const b = await sha256Hex(new TextEncoder().encode('hello'));
    const c = await sha256Hex(new TextEncoder().encode('hellp'));
    expect(a).toHaveLength(64);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});
