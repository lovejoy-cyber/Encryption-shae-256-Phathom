import { describe, it, expect } from 'vitest';
import { generateX25519KeyPair, sealedBoxEncrypt, sealedBoxDecrypt } from '../src/publicKey.js';
import { DecryptionError } from '../src/primitives.js';

describe('X25519 sealed box', () => {
  it('round-trips: recipient decrypts with their secret key', async () => {
    const recipient = generateX25519KeyPair();
    const plaintext = new TextEncoder().encode('anonymous ECIES-style message');
    const sealed = await sealedBoxEncrypt(plaintext, recipient.publicKey);
    const decrypted = await sealedBoxDecrypt(sealed, recipient.secretKey);
    expect(new TextDecoder().decode(decrypted)).toBe('anonymous ECIES-style message');
  });

  it('a different recipient keypair cannot decrypt', async () => {
    const recipient = generateX25519KeyPair();
    const attacker = generateX25519KeyPair();
    const sealed = await sealedBoxEncrypt(new TextEncoder().encode('secret'), recipient.publicKey);
    await expect(sealedBoxDecrypt(sealed, attacker.secretKey)).rejects.toThrow(DecryptionError);
  });

  it('produces different ciphertext each time (fresh ephemeral key per call)', async () => {
    const recipient = generateX25519KeyPair();
    const a = await sealedBoxEncrypt(new TextEncoder().encode('same'), recipient.publicKey);
    const b = await sealedBoxEncrypt(new TextEncoder().encode('same'), recipient.publicKey);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('rejects an invalid recipient public key length', async () => {
    await expect(sealedBoxEncrypt(new TextEncoder().encode('x'), new Uint8Array(16))).rejects.toThrow();
  });

  it('rejects a truncated sealed box', async () => {
    const recipient = generateX25519KeyPair();
    await expect(sealedBoxDecrypt(new Uint8Array(10), recipient.secretKey)).rejects.toThrow(DecryptionError);
  });
});
