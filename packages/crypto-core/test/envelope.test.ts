import { describe, it, expect } from 'vitest';
import { encryptWithPassword, decryptWithPassword, encryptWithKey, decryptWithKey } from '../src/envelope.js';
import { generateKey, DecryptionError } from '../src/primitives.js';

const LOW_ITERATIONS = 1000; // keep tests fast; production uses 600k (see primitives.ts)

describe('password envelope', () => {
  it('round-trips with the correct password', async () => {
    const plaintext = new TextEncoder().encode('the launch codes are hidden in the fern');
    const envelope = await encryptWithPassword(plaintext, 'correct-horse', LOW_ITERATIONS);
    const decrypted = await decryptWithPassword(envelope, 'correct-horse', LOW_ITERATIONS);
    expect(new TextDecoder().decode(decrypted)).toBe('the launch codes are hidden in the fern');
  });

  it('rejects the wrong password', async () => {
    const envelope = await encryptWithPassword(new TextEncoder().encode('secret'), 'right', LOW_ITERATIONS);
    await expect(decryptWithPassword(envelope, 'wrong', LOW_ITERATIONS)).rejects.toThrow(DecryptionError);
  });

  it('detects tampering via the GCM auth tag', async () => {
    const envelope = await encryptWithPassword(new TextEncoder().encode('secret'), 'pw', LOW_ITERATIONS);
    const tampered = new Uint8Array(envelope);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(decryptWithPassword(tampered, 'pw', LOW_ITERATIONS)).rejects.toThrow(DecryptionError);
  });

  it('produces different ciphertext for identical plaintext (random salt+iv)', async () => {
    const a = await encryptWithPassword(new TextEncoder().encode('same'), 'pw', LOW_ITERATIONS);
    const b = await encryptWithPassword(new TextEncoder().encode('same'), 'pw', LOW_ITERATIONS);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('rejects a truncated/malformed envelope', async () => {
    await expect(decryptWithPassword(new Uint8Array([1, 2, 3]), 'pw', LOW_ITERATIONS)).rejects.toThrow(DecryptionError);
  });
});

describe('key envelope (raw 32-byte key, no KDF) — used for CEK/K_cap layers', () => {
  it('round-trips with the correct key', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('inner ciphertext blob');
    const envelope = await encryptWithKey(plaintext, key);
    const decrypted = await decryptWithKey(envelope, key);
    expect(new TextDecoder().decode(decrypted)).toBe('inner ciphertext blob');
  });

  it('rejects the wrong key', async () => {
    const key = await generateKey();
    const wrongKey = await generateKey();
    const envelope = await encryptWithKey(new TextEncoder().encode('x'), key);
    await expect(decryptWithKey(envelope, wrongKey)).rejects.toThrow(DecryptionError);
  });

  it('supports AAD binding — decrypting with different AAD fails', async () => {
    const key = await generateKey();
    const envelope = await encryptWithKey(new TextEncoder().encode('bound'), key, new TextEncoder().encode('capability-id-123'));
    await expect(decryptWithKey(envelope, key, new TextEncoder().encode('capability-id-456'))).rejects.toThrow(DecryptionError);
    await expect(decryptWithKey(envelope, key, new TextEncoder().encode('capability-id-123'))).resolves.toBeTruthy();
  });

  it('rejects a key of the wrong length', async () => {
    await expect(encryptWithKey(new TextEncoder().encode('x'), new Uint8Array(16))).rejects.toThrow();
  });

  it('double-envelope composition: outer(inner(plaintext, CEK), K_cap) round-trips and each layer is independently required', async () => {
    // Mirrors the capability-released content design in docs/ARCHITECTURE.md §5.2:
    // inner layer = sender/recipient shared CEK, outer layer = server-held K_cap.
    const cek = await generateKey();
    const kCap = await generateKey();
    const plaintext = new TextEncoder().encode('capability-protected content');

    const inner = await encryptWithKey(plaintext, cek);
    const outer = await encryptWithKey(inner, kCap);

    // Recipient flow: unwrap outer with server-released K_cap, then inner with CEK.
    const unwrappedInner = await decryptWithKey(outer, kCap);
    const recovered = await decryptWithKey(unwrappedInner, cek);
    expect(new TextDecoder().decode(recovered)).toBe('capability-protected content');

    // Having the CEK alone (no K_cap) must NOT be enough to reach the plaintext:
    // the outer layer is still there and requires K_cap.
    await expect(decryptWithKey(outer, cek)).rejects.toThrow(DecryptionError);
  });
});
